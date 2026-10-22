import re
import sqlite3

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_login import (
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database import get_connection


auth = Blueprint("auth", __name__)


class User(UserMixin):
    def __init__(self, user_id, full_name, email, username):
        self.id = str(user_id)
        self.full_name = full_name
        self.email = email
        self.username = username


def get_user_by_id(user_id):
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, full_name, email, username
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

    if row is None:
        return None

    return User(
        row["id"],
        row["full_name"],
        row["email"],
        row["username"]
    )


@auth.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not username:
            flash("Please fill in all required fields.", "error")

        elif len(full_name) > 100:
            flash("Full name must be under 100 characters.", "error")

        elif not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email
        ):
            flash("Please enter a valid email address.", "error")

        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash(
                "Username must be 3–30 characters and contain only "
                "letters, numbers, dots, underscores or hyphens.",
                "error"
            )

        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")

        elif len(password) > 128:
            flash("Password is too long.", "error")

        elif password != confirm_password:
            flash("Passwords do not match.", "error")

        else:
            password_hash = generate_password_hash(password)

            try:
                with get_connection() as connection:
                    connection.execute(
                        """
                        INSERT INTO users (
                            full_name, email, username, password_hash
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (full_name, email, username, password_hash)
                    )

                flash(
                    "Account created successfully. Please log in.",
                    "success"
                )
                return redirect(url_for("auth.login"))

            except sqlite3.IntegrityError:
                flash(
                    "This email or username is already registered.",
                    "error"
                )

    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        if not identity or not password:
            flash("Enter your username/email and password.", "error")

        else:
            with get_connection() as connection:
                row = connection.execute(
                    """
                    SELECT id, full_name, email, username, password_hash
                    FROM users
                    WHERE username = ? COLLATE NOCASE
                       OR email = ? COLLATE NOCASE
                    """,
                    (identity, identity)
                ).fetchone()

            if row and check_password_hash(
                row["password_hash"], password
            ):
                user = User(
                    row["id"],
                    row["full_name"],
                    row["email"],
                    row["username"]
                )

                login_user(user)

                next_page = request.args.get("next", "")

                if (
                    next_page.startswith("/")
                    and not next_page.startswith("//")
                    and "\\" not in next_page
                ):
                    return redirect(next_page)

                return redirect(url_for("index"))

            flash("Invalid username/email or password.", "error")

    return render_template("login.html")


@auth.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))

