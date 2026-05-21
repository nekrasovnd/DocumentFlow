"""
Модуль базы данных (SQLite).
Хранение пользователей, документов, подписей и сертификатов.
"""

import sqlite3
import os
import hashlib
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documentflow.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Инициализация базы данных — создание таблиц."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            private_key_pem BLOB,
            public_key_pem BLOB,
            certificate_pem BLOB,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            checksum TEXT NOT NULL,
            upload_date TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            signature_b64 TEXT NOT NULL,
            signed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# ---- Users ----

def create_user(username, password_hash, private_key_pem, public_key_pem, certificate_pem):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash, private_key_pem, public_key_pem, certificate_pem) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, private_key_pem, public_key_pem, certificate_pem)
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id


def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


# ---- Documents ----

def insert_document(filename, filepath, author_id, checksum):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (filename, filepath, author_id, checksum) VALUES (?, ?, ?, ?)",
        (filename, filepath, author_id, checksum)
    )
    conn.commit()
    doc_id = cursor.lastrowid
    conn.close()
    return doc_id


def get_all_documents():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*, u.username as author_name
        FROM documents d
        JOIN users u ON d.author_id = u.id
        ORDER BY d.upload_date DESC
    """)
    docs = cursor.fetchall()
    conn.close()
    return docs


def get_document_by_id(doc_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()
    conn.close()
    return doc


# ---- Signatures ----

def save_signature(document_id, user_id, signature_b64):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO signatures (document_id, user_id, signature_b64) VALUES (?, ?, ?)",
        (document_id, user_id, signature_b64)
    )
    conn.commit()
    conn.close()


def get_signature_for_document(document_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, u.username as signer_name
        FROM signatures s
        JOIN users u ON s.user_id = u.id
        WHERE s.document_id = ?
        ORDER BY s.signed_at DESC
        LIMIT 1
    """, (document_id,))
    sig = cursor.fetchone()
    conn.close()
    return sig


def compute_checksum(file_data: bytes) -> str:
    """Вычисление контрольной суммы SHA-256."""
    return hashlib.sha256(file_data).hexdigest()
