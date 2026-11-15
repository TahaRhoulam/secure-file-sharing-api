import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

app = FastAPI(title="Secure File Sharing API", version="1.0.0")
DB_PATH = Path(os.environ.get("FILE_API_DB", "files.db"))
MAX_BYTES = 2 * 1024 * 1024


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript("""
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            filename TEXT NOT NULL, content_type TEXT NOT NULL,
            content BLOB NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shares (
            token_hash TEXT PRIMARY KEY, file_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        """)
        yield connection
        connection.commit()
    finally:
        connection.close()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=10, max_length=128)


def current_user(authorization: str | None = Header(default=None)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    with db() as connection:
        row = connection.execute(
            "SELECT user_id FROM sessions WHERE token_hash=?",
            (digest(authorization[7:]),),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "Invalid token")
    return row["user_id"]


@app.post("/register", status_code=201)
def register(data: Credentials):
    salt = secrets.token_bytes(16)
    with db() as connection:
        try:
            connection.execute(
                "INSERT INTO users(username,salt,password_hash) VALUES(?,?,?)",
                (data.username, salt.hex(), hash_password(data.password, salt)),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already exists")
    return {"message": "Registered"}


@app.post("/login")
def login(data: Credentials):
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username=?", (data.username,)
        ).fetchone()
        if row is None or not secrets.compare_digest(
            row["password_hash"], hash_password(data.password, bytes.fromhex(row["salt"]))
        ):
            raise HTTPException(401, "Invalid credentials")
        token = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id) VALUES(?,?)",
            (digest(token), row["id"]),
        )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/files", status_code=201)
async def upload(file: UploadFile = File(...), user_id: int = Depends(current_user)):
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 2 MiB limit")
    filename = Path(file.filename or "upload.bin").name
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO files(user_id,filename,content_type,content) VALUES(?,?,?,?)",
            (user_id, filename, file.content_type or "application/octet-stream", content),
        )
        file_id = cursor.lastrowid
    return {"id": file_id, "filename": filename, "size": len(content)}


@app.get("/files")
def list_files(user_id: int = Depends(current_user)):
    with db() as connection:
        rows = connection.execute(
            "SELECT id,filename,length(content) AS size FROM files WHERE user_id=? ORDER BY id",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def owned_file(connection, file_id: int, user_id: int):
    row = connection.execute(
        "SELECT * FROM files WHERE id=? AND user_id=?", (file_id, user_id)
    ).fetchone()
    if row is None:
        raise HTTPException(404, "File not found")
    return row


def file_response(row):
    safe_name = row["filename"].replace('"', "").replace("\r", "").replace("\n", "")
    return Response(
        content=row["content"], media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"',
                 "X-Content-Type-Options": "nosniff"},
    )


@app.get("/files/{file_id}")
def download(file_id: int, user_id: int = Depends(current_user)):
    with db() as connection:
        row = owned_file(connection, file_id, user_id)
        return file_response(row)


class ShareRequest(BaseModel):
    expires_in_seconds: int = Field(ge=60, le=86400)


@app.post("/files/{file_id}/share")
def share(file_id: int, data: ShareRequest, user_id: int = Depends(current_user)):
    with db() as connection:
        owned_file(connection, file_id, user_id)
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + data.expires_in_seconds
        connection.execute(
            "INSERT INTO shares(token_hash,file_id,expires_at) VALUES(?,?,?)",
            (digest(token), file_id, expires),
        )
    return {"share_token": token, "expires_at": expires,
            "download_path": f"/shared/{token}"}


@app.get("/shared/{token}")
def shared_download(token: str):
    with db() as connection:
        row = connection.execute(
            """SELECT files.* FROM shares
               JOIN files ON files.id=shares.file_id
               WHERE shares.token_hash=? AND shares.expires_at>?""",
            (digest(token), int(time.time())),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Link invalid or expired")
        return file_response(row)


@app.delete("/files/{file_id}", status_code=204)
def delete_file(file_id: int, user_id: int = Depends(current_user)):
    with db() as connection:
        owned_file(connection, file_id, user_id)
        connection.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
        connection.execute("DELETE FROM files WHERE id=?", (file_id,))
    return Response(status_code=204)
