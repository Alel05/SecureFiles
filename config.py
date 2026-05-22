import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "file-sharing"),
    "charset": "utf8mb4",
}

_AES_KEY_ENV = os.environ.get("FILE_ENCRYPTION_KEY", "dev-key-32-bytes-length-1234567890")


def get_aes_key() -> bytes:
    key = _AES_KEY_ENV.encode("utf-8")
    if len(key) < 32:
        key = key.ljust(32, b"0")
    return key[:32]
