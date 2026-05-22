import os
import uuid
import hashlib
from datetime import datetime
from io import BytesIO

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from werkzeug.utils import secure_filename
import mysql.connector
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from config import DB_CONFIG, UPLOAD_FOLDER, SECRET_KEY

ALLOWED_EXTENSIONS = None

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def user_can_access_file(user_id: int, file_record: dict) -> bool:
    if file_record["user_id"] == user_id:
        return True

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM file_shares WHERE file_id = %s AND user_id = %s LIMIT 1",
        (file_record["id"], user_id),
    )
    allowed = cursor.fetchone() is not None
    cursor.close()
    conn.close()
    return allowed


def encrypt_payload(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv, encrypted


def decrypt_payload(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def allowed_file(filename: str) -> bool:
    return bool(filename)


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    # Renders the application introduction landing page
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not password or not confirm_password:
            flash("Please complete all registration fields.", "warning")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("register"))

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (full_name, username, password_hash, created_at) VALUES (%s, %s, %s, %s)",
                (full_name, username, password_hash, datetime.utcnow()),
            )
            conn.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except mysql.connector.Error as err:
            if err.errno == 1062:
                flash("Username already exists. Choose a different username.", "danger")
            else:
                flash(f"Database error: {err}", "danger")
            return redirect(url_for("register"))
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please enter username and password.", "warning")
            return redirect(url_for("login"))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.id, f.original_filename, u.username AS owner, "
        "(SELECT COUNT(*) FROM file_shares s2 WHERE s2.file_id = f.id AND s2.user_id <> f.user_id) AS shared_count "
        "FROM files f JOIN users u ON f.user_id = u.id "
        "WHERE f.user_id = %s OR f.id IN (SELECT file_id FROM file_shares WHERE user_id = %s) "
        "ORDER BY f.upload_timestamp DESC",
        (user_id, user_id),
    )
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if not uploaded_file or uploaded_file.filename == "":
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("upload"))

        filename = secure_filename(uploaded_file.filename)
        file_password = request.form.get("file_password", "")
        if not allowed_file(filename) or not file_password:
            flash("Please provide a valid file and password.", "danger")
            return redirect(url_for("upload"))

        raw_data = uploaded_file.read()
        salt = os.urandom(16)
        key = derive_key(file_password, salt)
        iv, encrypted_data = encrypt_payload(raw_data, key)
        file_hash = calculate_sha256(encrypted_data)
        plaintext_hash = calculate_sha256(raw_data)
        stored_filename = f"{uuid.uuid4().hex}_{filename}"
        destination_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)

        with open(destination_path, "wb") as storage:
            storage.write(encrypted_data)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (user_id, original_filename, stored_filename, upload_timestamp, sha256_hash, plaintext_sha256, iv, password_salt) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                session["user_id"],
                filename,
                stored_filename,
                datetime.utcnow(),
                file_hash,
                plaintext_hash,
                iv.hex(),
                salt.hex(),
            ),
        )
        conn.commit()
        cursor.close()
        conn.close()

        # Custom explicit upload confirmation string
        flash("File uploaded successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


@app.route("/download/<int:file_id>")
def download(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id = %s", (file_id,))
    file_record = cursor.fetchone()
    cursor.close()
    conn.close()

    if not file_record or not user_can_access_file(session["user_id"], file_record):
        flash("File not found or access denied.", "danger")
        return redirect(url_for("dashboard"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["stored_filename"])
    if not os.path.exists(file_path):
        flash("Encrypted file is missing from storage.", "danger")
        return redirect(url_for("dashboard"))

    with open(file_path, "rb") as encrypted_file:
        ciphertext = encrypted_file.read()

    current_hash = calculate_sha256(ciphertext)
    if current_hash != file_record["sha256_hash"]:
        flash("File integrity check failed. Download cancelled.", "danger")
        return redirect(url_for("dashboard"))

    attachment_name = f"{file_record['original_filename']}.enc"
    return send_file(
        BytesIO(ciphertext),
        download_name=attachment_name,
        as_attachment=True,
    )


@app.route("/decrypt/<int:file_id>", methods=["GET", "POST"])
def decrypt_file(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id = %s", (file_id,))
    file_record = cursor.fetchone()
    cursor.close()
    conn.close()

    if not file_record:
        flash("Action denied.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        file_password = request.form.get("file_password", "")
        if not file_password:
            flash("Please enter the file password.", "warning")
            return redirect(url_for("decrypt_file", file_id=file_id))

        if not user_can_access_file(session["user_id"], file_record):
            flash("Action denied.", "danger")
            return redirect(url_for("dashboard"))

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["stored_filename"])
        if not os.path.exists(file_path):
            flash("Encrypted file is missing from storage.", "danger")
            return redirect(url_for("dashboard"))

        with open(file_path, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()

        current_hash = calculate_sha256(ciphertext)
        if current_hash != file_record["sha256_hash"]:
            flash("File integrity check failed. Download cancelled.", "danger")
            return redirect(url_for("dashboard"))

        salt = bytes.fromhex(file_record["password_salt"])
        key = derive_key(file_password, salt)
        iv = bytes.fromhex(file_record["iv"])

        try:
            plaintext = decrypt_payload(iv, ciphertext, key)
        except Exception:
            flash("Invalid password.", "danger")
            return redirect(url_for("decrypt_file", file_id=file_id))

        plain_hash = calculate_sha256(plaintext)
        if plain_hash != file_record["plaintext_sha256"]:
            flash("Invalid password.", "danger")
            return redirect(url_for("decrypt_file", file_id=file_id))

        return send_file(
            BytesIO(plaintext),
            download_name=file_record["original_filename"],
            as_attachment=True,
        )

    return render_template("decrypt.html", file=file_record)


@app.route("/share/<int:file_id>", methods=["GET", "POST"])
def share_file(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session["user_id"]))
    file_record = cursor.fetchone()

    if not file_record:
        cursor.close()
        conn.close()
        flash("Action denied.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        recipient_username = request.form.get("recipient_username", "").strip()
        if not recipient_username:
            flash("Please enter a username to share with.", "warning")
            return redirect(url_for("share_file", file_id=file_id))

        cursor.execute("SELECT id FROM users WHERE username = %s", (recipient_username,))
        recipient = cursor.fetchone()
        if not recipient:
            cursor.close()
            conn.close()
            flash("User not found.", "danger")
            return redirect(url_for("share_file", file_id=file_id))

        recipient_id = recipient["id"]
        if recipient_id == session["user_id"]:
            cursor.close()
            conn.close()
            flash("You already own this file.", "warning")
            return redirect(url_for("share_file", file_id=file_id))

        try:
            cursor.execute(
                "INSERT INTO file_shares (file_id, user_id, shared_at) VALUES (%s, %s, %s)",
                (file_id, recipient_id, datetime.utcnow()),
            )
            conn.commit()
            flash(f"File shared successfully with {recipient_username}!", "success")
        except mysql.connector.Error as err:
            if err.errno == 1062:
                flash(f"{recipient_username} already has access.", "info")
            else:
                flash(f"Database error: {err}", "danger")
        
        # Cleanly channels workflow progression straight back onto the workspace data rows
        cursor.close()
        conn.close()
        return redirect(url_for("dashboard"))

    cursor.execute(
        "SELECT u.id, u.username, s.shared_at FROM file_shares s JOIN users u ON s.user_id = u.id WHERE s.file_id = %s",
        (file_id,),
    )
    shared_users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("share.html", file=file_record, shared_users=shared_users)


@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, user_id))
    file_record = cursor.fetchone()

    if not file_record:
        cursor.close()
        conn.close()
        flash("Action denied.", "danger")
        return redirect(url_for("dashboard"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record["stored_filename"])
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            flash("Could not remove file from storage.", "warning")

    cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("File deleted successfully.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)