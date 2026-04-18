import hmac
import os
import sqlite3
import secrets
from urllib.parse import urlsplit
from flask import Flask, flash, redirect, render_template, request, session, url_for
from services.auth_service import authenticate_user, create_user, validate_signup_form
from services.captcha_service import generate_captcha
from services.db_service import append_log, delete_user_by_username, ensure_storage, list_users, load_logs


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true"
app.config["SESSION_COOKIE_NAME"] = "py_login_session"
app.config["PREFERRED_URL_SCHEME"] = "https" if app.config["SESSION_COOKIE_SECURE"] else "http"
MAX_AUTH_FAILURES = 5
TRUSTED_HOSTS = {
    host.strip().lower()
    for host in os.environ.get("TRUSTED_HOSTS", "localhost,127.0.0.1,10.0.0.101").split(",")
    if host.strip()
}


ensure_storage()


@app.before_request
def configure_session():
    session.permanent = False
    host = request.host.split(":", 1)[0].lower()
    if host not in TRUSTED_HOSTS:
        return render_template("error.html", title="400", message="허용되지 않은 호스트입니다."), 400


def set_captcha(target):
    session[f"{target}_captcha"] = generate_captcha()


def set_form_token(target):
    session[f"{target}_form_token"] = secrets.token_urlsafe(32)


def get_form_token(target):
    token_key = f"{target}_form_token"
    if token_key not in session:
        set_form_token(target)
    return session[token_key]


def is_valid_form_token(target, submitted_token):
    expected_token = session.get(f"{target}_form_token", "")
    return bool(submitted_token) and bool(expected_token) and hmac.compare_digest(submitted_token, expected_token)


def is_safe_redirect(target):
    if not target:
        return False
    parsed = urlsplit(target)
    return parsed.scheme == "" and parsed.netloc == "" and target.startswith("/")


def reset_login_captcha():
    set_captcha("login")


def reset_signup_captcha():
    set_captcha("signup")


def increase_auth_failures():
    session["auth_failures"] = session.get("auth_failures", 0) + 1
    return session["auth_failures"]


def reset_auth_failures():
    session["auth_failures"] = 0


def handle_auth_failure(message, username=""):
    failures = increase_auth_failures()
    append_log(f"LOGIN_FAIL username={username or 'unknown'} reason={message} count={failures}")
    if failures >= MAX_AUTH_FAILURES:
        for key in ["auth_failures", "login_captcha", "login_form_token"]:
            session.pop(key, None)
        flash("로그인 시도가 5회 실패했습니다. 메인 페이지로 이동합니다.")
        return redirect(url_for("index"))
    reset_login_captcha()
    set_form_token("login")
    flash(f"{message} 현재 실패 횟수: {failures}회")
    return render_template(
        "login.html",
        captcha=session.get("login_captcha"),
        form_token=get_form_token("login"),
        username=username,
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "auth_failures" not in session:
        reset_auth_failures()

    if request.method == "GET":
        reset_login_captcha()
        set_form_token("login")
        return render_template(
            "login.html",
            captcha=session.get("login_captcha"),
            form_token=get_form_token("login"),
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    captcha_input = request.form.get("captcha", "").strip()
    expected_captcha = session.get("login_captcha", "")
    form_token = request.form.get("form_token", "")

    if not is_valid_form_token("login", form_token):
        reset_login_captcha()
        set_form_token("login")
        flash("잘못된 요청입니다. 다시 시도해 주세요.")
        return render_template(
            "login.html",
            captcha=session.get("login_captcha"),
            form_token=get_form_token("login"),
            username=username,
        )

    if captcha_input != expected_captcha:
        return handle_auth_failure("캡차가 올바르지 않습니다.", username=username)

    user = authenticate_user(username, password)
    reset_login_captcha()
    set_form_token("login")

    if not user:
        return handle_auth_failure("계정이 없거나 비밀번호가 틀렸습니다.", username=username)

    session.clear()
    reset_auth_failures()
    session["username"] = user["username"]
    session["user_name"] = user["name"]
    session["is_admin"] = user.get("role") == "admin"
    append_log(f"LOGIN_SUCCESS username={user['username']} role={'admin' if session['is_admin'] else 'user'}")
    if session["is_admin"]:
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("secret"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        reset_signup_captcha()
        set_form_token("signup")
        return render_template(
            "signup.html",
            captcha=session.get("signup_captcha"),
            form_token=get_form_token("signup"),
        )

    form_data = {
        "name": request.form.get("name", "").strip(),
        "username": request.form.get("username", "").strip(),
        "birthdate": request.form.get("birthdate", "").strip(),
        "email": request.form.get("email", "").strip(),
        "password": request.form.get("password", ""),
        "confirm_password": request.form.get("confirm_password", ""),
        "path": request.form.get("path", "").strip(),
        "captcha": request.form.get("captcha", "").strip(),
    }
    expected_captcha = session.get("signup_captcha", "")
    form_token = request.form.get("form_token", "")

    if not is_valid_form_token("signup", form_token):
        reset_signup_captcha()
        set_form_token("signup")
        flash("잘못된 요청입니다. 다시 시도해 주세요.")
        return render_template(
            "signup.html",
            captcha=session.get("signup_captcha"),
            form_token=get_form_token("signup"),
            values=form_data,
        )

    error = validate_signup_form(form_data, expected_captcha)
    if error:
        reset_signup_captcha()
        set_form_token("signup")
        flash(error)
        return render_template(
            "signup.html",
            captcha=session.get("signup_captcha"),
            form_token=get_form_token("signup"),
            values=form_data,
        )

    try:
        create_user(form_data)
    except sqlite3.IntegrityError:
        reset_signup_captcha()
        set_form_token("signup")
        flash("이미 사용 중인 아이디 또는 이메일입니다.")
        return render_template(
            "signup.html",
            captcha=session.get("signup_captcha"),
            form_token=get_form_token("signup"),
            values=form_data,
        )
    except sqlite3.Error:
        reset_signup_captcha()
        set_form_token("signup")
        flash("회원가입 처리 중 오류가 발생했습니다. 다시 시도해 주세요.")
        return render_template(
            "signup.html",
            captcha=session.get("signup_captcha"),
            form_token=get_form_token("signup"),
            values=form_data,
        )
    append_log(f"SIGNUP_SUCCESS username={form_data['username']} email={form_data['email']}")
    for key in ["signup_captcha", "signup_form_token"]:
        session.pop(key, None)
    flash("회원가입이 완료되었습니다. 로그인해 주세요.")
    return redirect(url_for("login"))


@app.route("/secret")
def secret():
    if "username" not in session:
        flash("로그인 후 접근할 수 있습니다.")
        return redirect(url_for("login"))
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    return render_template("secret.html")


def require_admin():
    if "username" not in session:
        flash("로그인 후 접근할 수 있습니다.")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for("secret"))
    return None


@app.route("/admin")
def admin_dashboard():
    denied = require_admin()
    if denied:
        return denied
    set_form_token("admin")
    return render_template(
        "admin.html",
        name=session.get("user_name"),
        users=list_users(),
        logs=load_logs(),
        form_token=get_form_token("admin"),
    )


@app.route("/admin/users/delete", methods=["POST"])
def admin_delete_user():
    denied = require_admin()
    if denied:
        return denied

    form_token = request.form.get("form_token", "")
    if not is_valid_form_token("admin", form_token):
        flash("잘못된 요청입니다. 다시 시도해 주세요.")
        return redirect(url_for("admin_dashboard"))

    username = request.form.get("username", "").strip()
    if not username:
        flash("삭제할 사용자 아이디가 필요합니다.")
        return redirect(url_for("admin_dashboard"))

    try:
        if delete_user_by_username(username):
            append_log(f"ADMIN_DELETE_USER admin={session.get('username')} target={username}")
            flash(f"{username} 사용자를 삭제했습니다.")
        else:
            flash("해당 사용자를 찾을 수 없습니다.")
    except sqlite3.Error:
        flash("사용자 삭제 중 오류가 발생했습니다.")
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    if session.get("username"):
        append_log(f"LOGOUT username={session.get('username')}")
    for key in ["username", "user_name", "is_admin", "auth_failures", "login_captcha", "login_form_token", "admin_form_token"]:
        session.pop(key, None)
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", title="404", message="페이지를 찾을 수 없습니다."), 404


@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", title="400", message="잘못된 요청입니다."), 400


@app.errorhandler(500)
def internal_error(_error):
    return render_template("error.html", title="500", message="서버 오류가 발생했습니다."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
