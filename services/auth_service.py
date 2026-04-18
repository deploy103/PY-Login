import os
import re
import hmac
from werkzeug.security import check_password_hash, generate_password_hash
from services.db_service import create_user_record, get_user_by_email, get_user_by_username


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
MAX_NAME_LENGTH = 50
MAX_EMAIL_LENGTH = 120
MAX_PATH_LENGTH = 120


def authenticate_user(username, password):
    if ADMIN_PASSWORD and username == ADMIN_USERNAME:
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            return {
                "username": ADMIN_USERNAME,
                "name": "Administrator",
                "role": "admin",
            }
        return None

    user = get_user_by_username(username)
    if not user:
        return None
    if not check_password_hash(user["password"], password):
        return None
    return user


def validate_signup_form(form_data, expected_captcha):
    required_fields = ["name", "username", "birthdate", "email", "password", "confirm_password", "path", "captcha"]
    for field in required_fields:
        if not form_data.get(field, "").strip():
            return "모든 항목을 입력해야 합니다."

    if len(form_data["name"]) > MAX_NAME_LENGTH:
        return "이름이 너무 깁니다."

    if not USERNAME_PATTERN.match(form_data["username"]):
        return "아이디는 3~20자의 영문, 숫자, 밑줄, 하이픈만 사용할 수 있습니다."

    if len(form_data["email"]) > MAX_EMAIL_LENGTH:
        return "이메일이 너무 깁니다."

    if not EMAIL_PATTERN.match(form_data["email"]):
        return "이메일 형식이 올바르지 않습니다."

    if len(form_data["password"]) < 8:
        return "비밀번호는 8자 이상이어야 합니다."

    if form_data["password"] != form_data["confirm_password"]:
        return "비밀번호 확인이 일치하지 않습니다."

    if len(form_data["path"]) > MAX_PATH_LENGTH:
        return "가입 경로 입력값이 너무 깁니다."

    if form_data["captcha"] != expected_captcha:
        return "캡차가 일치하지 않습니다."

    if form_data["username"].lower() == ADMIN_USERNAME.lower():
        return "사용할 수 없는 아이디입니다."

    if get_user_by_username(form_data["username"]):
        return "이미 사용 중인 아이디입니다."

    if get_user_by_email(form_data["email"]):
        return "이미 가입된 이메일입니다."

    return None


def create_user(form_data):
    user = {
        "name": form_data["name"],
        "username": form_data["username"],
        "birthdate": form_data["birthdate"],
        "email": form_data["email"],
        "path": form_data["path"],
        "password": generate_password_hash(form_data["password"]),
    }
    create_user_record(user)
    return user
