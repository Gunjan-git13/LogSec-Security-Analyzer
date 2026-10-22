from pathlib import Path
from datetime import datetime
from threading import Lock

BASE_DIR = Path(__file__).resolve().parent
LIVE_LOG_FILE = BASE_DIR / "live_logs.txt"

_file_lock = Lock()


def initialize_live_log():
    """Create the default live log file without deleting existing data."""
    with _file_lock:
        LIVE_LOG_FILE.touch(exist_ok=True)

    return str(LIVE_LOG_FILE)


def get_log_file(file_path=None):
    """
    Return a validated path for a log file.

    If no path is supplied, use the default live_logs.txt file.
    """
    if not file_path:
        return LIVE_LOG_FILE

    path = Path(file_path).expanduser()

    if not path.is_absolute():
        path = (BASE_DIR / path).resolve()
    else:
        path = path.resolve()

    if path.suffix.lower() not in {".log", ".txt", ".csv"}:
        raise ValueError("Only .log, .txt and .csv files are supported.")

    if not path.is_file():
        raise ValueError("The selected log file does not exist.")

    return path


def read_live_logs(file_path=None):
    """Read non-empty entries from the selected log file."""
    try:
        path = get_log_file(file_path)

        with _file_lock:
            with path.open(
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:
                return [
                    line.strip()
                    for line in file
                    if line.strip()
                ]

    except (OSError, ValueError):
        return []


def get_live_log_status(file_path=None):
    """Return the selected log file's status."""
    try:
        if file_path is None:
            initialize_live_log()
            path = LIVE_LOG_FILE
        else:
            path = get_log_file(file_path)

        with _file_lock:
            stat = path.stat()

        return {
            "monitoring": True,
            "source": path.name,
            "file_path": str(path),
            "file_exists": True,
            "file_size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(
                stat.st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "checked_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

    except (OSError, ValueError):
        return {
            "monitoring": False,
            "source": (
                Path(file_path).name
                if file_path
                else LIVE_LOG_FILE.name
            ),
            "file_exists": False,
            "file_size_bytes": 0,
            "checked_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }


def append_live_log(message):
    """Append a timestamped log entry to the default test log."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Log message cannot be empty.")

    message = message.replace("\r", " ").replace("\n", " ")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} {message}"

    initialize_live_log()

    with _file_lock:
        with LIVE_LOG_FILE.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(log_entry + "\n")

    return log_entry

