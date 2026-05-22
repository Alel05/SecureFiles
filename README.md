# Secure File Upload System

A Flask-based file upload system with:
- User registration and login
- Password hashing with bcrypt
- AES-256 file encryption
- SHA-256 integrity checking
- MySQL metadata storage
- Local file storage in `uploads/`

## Setup

1. Create a Python virtual environment and install dependencies:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2. Create the MySQL schema:

```sql
source schema.sql
```

If you already created the database from an earlier version, apply the schema upgrade:

```sql
source upgrade.sql
```

3. Configure environment variables in `.env` or your shell:

```env
FLASK_SECRET_KEY=your-flask-secret
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=file-sharing
FILE_ENCRYPTION_KEY=32-character-key-for-aes
```

If your MySQL root user has no password, leave `DB_PASSWORD` blank.

4. Run the app:

```bash
python app.py
```

5. Open http://127.0.0.1:5000

## Notes

- The system encrypts uploaded files before saving them using a password set during upload.
- SHA-256 hashes are stored in the database and verified before download.
- Encrypted files can be downloaded only by users with explicit access.
- File owners can share access with other registered users.
- Decryption requires the owner-set file password and authentication through the system.
