import csv
import io
import os
import secrets
from pathlib import Path
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    make_response,
    jsonify,
)
from flask_login import (
    LoginManager,
    login_required,
    current_user,
)
from werkzeug.utils import secure_filename

from analyzer import analyze_logs
from database import init_db, save_analysis, get_history
from auth import auth, get_user_by_id
from live_monitor import (
    initialize_live_log,
    read_live_logs,
    get_live_log_status,
    append_live_log,
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MONITORED_LOGS_DIR = (BASE_DIR / "monitored_logs").resolve()
UPLOAD_DIR = (BASE_DIR / "uploads").resolve()

MAX_FILE_SIZE = 1 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".log", ".csv"}

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

# Stable secret key for sessions.
secret_key_file = BASE_DIR / ".logsec_secret"

if os.environ.get("LOGSEC_SECRET_KEY"):
    app.config["SECRET_KEY"] = os.environ["LOGSEC_SECRET_KEY"]

elif secret_key_file.exists():
    app.config["SECRET_KEY"] = secret_key_file.read_text(
        encoding="utf-8"
    ).strip()

else:
    generated_secret = secrets.token_hex(32)
    secret_key_file.write_text(
        generated_secret,
        encoding="utf-8",
    )
    app.config["SECRET_KEY"] = generated_secret

# Create folders without deleting existing files.
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MONITORED_LOGS_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# LOGIN CONFIGURATION
# --------------------------------------------------

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access LogSec."
login_manager.login_message_category = "error"
login_manager.init_app(app)

app.register_blueprint(auth)

init_db()
initialize_live_log()


@login_manager.user_loader
def load_user(user_id):
    try:
        return get_user_by_id(int(user_id))
    except (TypeError, ValueError):
        return None


def get_current_user_id():
    return int(current_user.get_id())


# --------------------------------------------------
# ANALYSIS AND DATABASE
# --------------------------------------------------

def analyze_and_save(log_lines, filename):
    """Analyze log entries and save the report for the logged-in user."""
    report = analyze_logs(log_lines)

    save_analysis(
        filename=filename,
        report=report,
        user_id=get_current_user_id(),
    )

    return report


# --------------------------------------------------
# MONITORED FILE HELPERS
# --------------------------------------------------

def get_monitored_files():
    """List supported log files inside monitored_logs."""
    files = []

    try:
        for path in MONITORED_LOGS_DIR.iterdir():
            if (
                path.is_file()
                and path.suffix.lower() in ALLOWED_EXTENSIONS
            ):
                files.append(path.name)

    except OSError:
        app.logger.exception("Could not list monitored log files.")

    return sorted(files, key=str.lower)


def read_selected_log_file(filename):
    """Safely read a selected file from monitored_logs."""
    if not filename or not isinstance(filename, str):
        raise ValueError("Please select a log file.")

    safe_name = secure_filename(filename)

    if not safe_name or safe_name != filename:
        raise ValueError("Invalid filename.")

    if Path(safe_name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .txt, .log and .csv files are supported.")

    path = (MONITORED_LOGS_DIR / safe_name).resolve()

    if path.parent != MONITORED_LOGS_DIR:
        raise ValueError("Invalid file location.")

    if not path.is_file():
        raise ValueError(
            "The selected file was not found in monitored_logs."
        )

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("The selected log file exceeds 1 MB.")

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            lines = [
                line.strip()
                for line in file
                if line.strip()
            ]

    except OSError as exc:
        raise ValueError(
            "Could not read the selected log file."
        ) from exc

    if not lines:
        raise ValueError("The selected log file is empty.")

    return lines, safe_name


def get_file_status(filename):
    """Return status information for a monitored file."""
    path = (MONITORED_LOGS_DIR / filename).resolve()
    stat = path.stat()

    return {
        "monitoring": True,
        "source": filename,
        "file_exists": True,
        "file_size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(
            stat.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    report = None
    error = None
    filename = None

    if request.method == "POST":
        input_mode = request.form.get("input_mode", "upload")

        try:
            if input_mode == "paste":
                pasted_logs = request.form.get(
                    "pasted_logs", ""
                ).strip()

                if not pasted_logs:
                    raise ValueError("Please paste some log entries.")

                if len(pasted_logs.encode("utf-8")) > MAX_FILE_SIZE:
                    raise ValueError(
                        "Pasted logs cannot exceed 1 MB."
                    )

                log_lines = pasted_logs.splitlines()
                filename = "Pasted Logs"

            elif input_mode == "sample":
                sample_file = BASE_DIR / "sample_logs.txt"

                if not sample_file.is_file():
                    raise ValueError(
                        "sample_logs.txt was not found in the project folder."
                    )

                log_lines = sample_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                ).splitlines()

                if not any(line.strip() for line in log_lines):
                    raise ValueError("The sample log file is empty.")

                filename = "Sample Logs"

            elif input_mode == "live":
                log_lines = read_live_logs()
                filename = "Live Logs"

                if not log_lines:
                    raise ValueError(
                        "No live log entries found. Add entries to "
                        "live_logs.txt and try again."
                    )

            elif input_mode == "monitored":
                selected_file = request.form.get(
                    "monitored_file", ""
                )
                log_lines, filename = read_selected_log_file(
                    selected_file
                )

            else:
                uploaded_file = request.files.get("log_file")

                if (
                    uploaded_file is None
                    or not uploaded_file.filename
                ):
                    raise ValueError(
                        "Please select a log file to upload."
                    )

                filename = secure_filename(
                    uploaded_file.filename
                )

                if not filename:
                    raise ValueError(
                        "The uploaded filename is invalid."
                    )

                if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
                    raise ValueError(
                        "Only .txt, .log and .csv files are supported."
                    )

                content = uploaded_file.read(MAX_FILE_SIZE + 1)

                if len(content) > MAX_FILE_SIZE:
                    raise ValueError(
                        "The uploaded file cannot exceed 1 MB."
                    )

                text_content = content.decode(
                    "utf-8",
                    errors="replace",
                )
                log_lines = text_content.splitlines()

                if not any(line.strip() for line in log_lines):
                    raise ValueError("The uploaded file is empty.")

            report = analyze_and_save(log_lines, filename)

        except ValueError as exc:
            error = str(exc)

        except OSError:
            app.logger.exception("File processing failed.")
            error = "Could not read the selected file."

        except Exception:
            app.logger.exception("Dashboard analysis failed.")
            error = "Analysis failed. Please check the server logs."

    return render_template(
        "index.html",
        report=report,
        error=error,
        filename=filename,
        username=current_user.username,
        full_name=current_user.full_name,
        monitored_files=get_monitored_files(),
    )


# --------------------------------------------------
# ANALYSIS HISTORY
# --------------------------------------------------

@app.route("/history")
@login_required
def history():
    records = get_history(get_current_user_id())

    return render_template(
        "history.html",
        records=records,
        username=current_user.username,
    )


# --------------------------------------------------
# CSV EXPORT
# --------------------------------------------------

@app.route("/download-csv")
@login_required
def download_csv():
    records = get_history(get_current_user_id())

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Filename",
        "Analyzed At",
        "Total Entries",
        "Successful Logins",
        "Failed Logins",
        "Alert Count",
    ])

    for record in records:
        writer.writerow([
            record.get("id", ""),
            record.get("filename", ""),
            record.get("analyzed_at", ""),
            record.get("total_entries", 0),
            record.get("successful_logins", 0),
            record.get("failed_logins", 0),
            record.get("alert_count", 0),
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=logsec_report.csv"
    )

    return response


# --------------------------------------------------
# API: MONITORED FILE LIST
# --------------------------------------------------

@app.route("/api/monitored-files")
@login_required
def monitored_files_api():
    return jsonify({
        "success": True,
        "files": get_monitored_files(),
    })


# --------------------------------------------------
# API: ANALYZE SELECTED MONITORED FILE
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze_selected_file_api():
    """Analyze a selected monitored file and return JSON."""
    filename = request.form.get("file", "").strip()

    try:
        log_lines, safe_name = read_selected_log_file(filename)

        report = analyze_and_save(log_lines, safe_name)

        return jsonify({
            "success": True,
            "message": f"{safe_name} analyzed successfully.",
            "source": safe_name,
            "report": report,
            "logs": log_lines[-100:],
            "status": get_file_status(safe_name),
        })

    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:
        app.logger.exception("Selected log analysis failed.")

        return jsonify({
            "success": False,
            "message": "An internal error occurred during log analysis.",
        }), 500


# --------------------------------------------------
# API: MONITORED FILE CONTENT AND REPORT
# --------------------------------------------------

@app.route("/api/monitored-logs")
@login_required
def monitored_logs_api():
    filename = request.args.get("file", "").strip()

    try:
        log_lines, safe_name = read_selected_log_file(filename)
        report = analyze_logs(log_lines)

        return jsonify({
            "success": True,
            "source": safe_name,
            "report": report,
            "logs": log_lines[-100:],
            "status": get_file_status(safe_name),
        })

    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except OSError:
        app.logger.exception("Could not monitor selected log file.")

        return jsonify({
            "success": False,
            "message": "Could not read the selected log file.",
        }), 500


# --------------------------------------------------
# API: LIVE STATUS AND LOGS
# --------------------------------------------------

@app.route("/api/live-status")
@login_required
def live_status():
    return jsonify(get_live_log_status())


@app.route("/api/live-logs")
@login_required
def live_logs():
    log_lines = read_live_logs()
    report = analyze_logs(log_lines)

    return jsonify({
        "status": get_live_log_status(),
        "report": report,
        "logs": log_lines[-100:],
    })


# --------------------------------------------------
# API: ANALYZE LIVE LOGS
# --------------------------------------------------

@app.route("/api/live-analyze", methods=["POST"])
@login_required
def live_analyze():
    log_lines = read_live_logs()

    if not log_lines:
        return jsonify({
            "success": False,
            "message": "No live logs are available yet.",
        }), 400

    report = analyze_and_save(log_lines, "Live Logs")

    return jsonify({
        "success": True,
        "report": report,
        "message": "Live logs analyzed successfully.",
    })


# --------------------------------------------------
# API: ADD A DEMO LIVE LOG ENTRY
# --------------------------------------------------

@app.route("/api/live-log", methods=["POST"])
@login_required
def add_demo_live_log():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str) or not message.strip():
        return jsonify({
            "success": False,
            "message": "Provide a non-empty log message.",
        }), 400

    if len(message) > 2000:
        return jsonify({
            "success": False,
            "message": "The log message is too long.",
        }), 400

    try:
        entry = append_live_log(message)

        return jsonify({
            "success": True,
            "message": "Demo log entry added.",
            "entry": entry,
        }), 201

    except (OSError, ValueError):
        app.logger.exception("Could not add demo live log.")

        return jsonify({
            "success": False,
            "message": "Could not write the log entry.",
        }), 500


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def request_too_large(error):
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "message": "The submitted data exceeds the 1 MB limit.",
        }), 413

    return "The submitted data exceeds the 1 MB limit.", 413


@app.errorhandler(404)
def page_not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "message": "API endpoint not found.",
        }), 404

    return "Page not found.", 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception("An internal server error occurred.")

    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "message": "Internal server error. Check the Flask terminal.",
        }), 500

    return "An internal server error occurred.", 500


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )

