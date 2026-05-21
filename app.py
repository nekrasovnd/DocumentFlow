"""
DocumentFlow — система документооборота с электронной подписью.
Основной файл приложения (Flask).
"""

import os
import sys
import hashlib
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import database as db
import signature as sig

app = Flask(__name__)
app.secret_key = "documentflow-secret-key-2026"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "txt", "png", "jpg", "doc"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Необходимо войти в систему.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---- Аутентификация ----

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            flash("Заполните все поля.", "danger")
            return redirect(url_for("register"))

        if db.get_user_by_username(username):
            flash("Пользователь с таким именем уже существует.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        # Генерация ключевой пары и сертификата
        private_key = sig.generate_key_pair()
        private_pem = sig.serialize_private_key(private_key)
        public_pem = sig.serialize_public_key(private_key)
        cert = sig.generate_certificate(private_key, username)
        cert_pem = sig.serialize_certificate(cert)

        user_id = db.create_user(username, password_hash, private_pem, public_pem, cert_pem)

        session["user_id"] = user_id
        session["username"] = username
        flash(f"Регистрация успешна. Ключевая пара RSA-2048 и сертификат X.509 сгенерированы.", "success")
        return redirect(url_for("documents_list"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        user = db.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Вход выполнен.", "success")
            return redirect(url_for("documents_list"))
        else:
            flash("Неверное имя пользователя или пароль.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


# ---- Документы ----

@app.route("/")
@login_required
def documents_list():
    docs = db.get_all_documents()
    documents = []
    for doc in docs:
        sig_info = db.get_signature_for_document(doc["id"])
        documents.append({
            "id": doc["id"],
            "filename": doc["filename"],
            "upload_date": doc["upload_date"],
            "author_name": doc["author_name"],
            "checksum": doc["checksum"][:16] + "...",
            "is_signed": sig_info is not None,
            "signer_name": sig_info["signer_name"] if sig_info else None,
            "signed_at": sig_info["signed_at"] if sig_info else None,
        })
    return render_template("documents.html", documents=documents, username=session["username"])


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        if "document" not in request.files:
            flash("Файл не выбран.", "danger")
            return redirect(url_for("upload_document"))

        file = request.files["document"]
        if file.filename == "":
            flash("Файл не выбран.", "danger")
            return redirect(url_for("upload_document"))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Ensure unique filename
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], filename)):
                filename = f"{base}_{counter}{ext}"
                counter += 1

            file_data = file.read()
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            with open(filepath, "wb") as f:
                f.write(file_data)

            checksum = db.compute_checksum(file_data)
            db.insert_document(filename, filepath, session["user_id"], checksum)
            flash(f"Документ «{filename}» загружен. SHA-256: {checksum[:32]}...", "success")
            return redirect(url_for("documents_list"))
        else:
            flash(f"Недопустимый формат файла. Разрешены: {', '.join(ALLOWED_EXTENSIONS)}", "danger")

    return render_template("upload.html", username=session["username"])


@app.route("/download/<int:doc_id>")
@login_required
def download_document(doc_id):
    doc = db.get_document_by_id(doc_id)
    if not doc:
        flash("Документ не найден.", "danger")
        return redirect(url_for("documents_list"))
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        doc["filename"],
        as_attachment=True
    )


# ---- Подписание и верификация ----

@app.route("/sign/<int:doc_id>", methods=["POST"])
@login_required
def sign_doc(doc_id):
    doc = db.get_document_by_id(doc_id)
    if not doc:
        flash("Документ не найден.", "danger")
        return redirect(url_for("documents_list"))

    # Проверка наличия подписи
    existing_sig = db.get_signature_for_document(doc_id)
    if existing_sig:
        flash("Документ уже подписан.", "warning")
        return redirect(url_for("documents_list"))

    # Чтение файла
    with open(doc["filepath"], "rb") as f:
        file_data = f.read()

    # Загрузка закрытого ключа пользователя
    user = db.get_user_by_id(session["user_id"])
    private_key = sig.load_private_key(user["private_key_pem"])

    # Формирование подписи
    signature = sig.sign_document(file_data, private_key)
    sig_b64 = sig.encode_signature_b64(signature)

    # Сохранение подписи
    db.save_signature(doc_id, session["user_id"], sig_b64)
    flash(f"Документ «{doc['filename']}» успешно подписан (RSA-PSS, SHA-256).", "success")
    return redirect(url_for("documents_list"))


@app.route("/verify/<int:doc_id>")
@login_required
def verify_doc(doc_id):
    doc = db.get_document_by_id(doc_id)
    if not doc:
        flash("Документ не найден.", "danger")
        return redirect(url_for("documents_list"))

    sig_info = db.get_signature_for_document(doc_id)
    if not sig_info:
        flash("Документ не подписан.", "warning")
        return redirect(url_for("documents_list"))

    # Чтение файла
    with open(doc["filepath"], "rb") as f:
        file_data = f.read()

    # Загрузка открытого ключа подписавшего
    signer = db.get_user_by_id(sig_info["user_id"])
    public_key = sig.load_public_key(signer["public_key_pem"])

    # Верификация
    signature = sig.decode_signature_b64(sig_info["signature_b64"])
    is_valid = sig.verify_signature(file_data, signature, public_key)

    # Текущая контрольная сумма
    current_checksum = db.compute_checksum(file_data)
    checksum_match = current_checksum == doc["checksum"]

    return render_template("verify.html",
                           doc=doc,
                           sig_info=sig_info,
                           is_valid=is_valid,
                           checksum_match=checksum_match,
                           current_checksum=current_checksum,
                           original_checksum=doc["checksum"],
                           username=session["username"])


@app.route("/keys")
@login_required
def my_keys():
    user = db.get_user_by_id(session["user_id"])
    public_key_pem = user["public_key_pem"].decode("utf-8") if isinstance(user["public_key_pem"], bytes) else user["public_key_pem"]
    cert_pem = user["certificate_pem"].decode("utf-8") if isinstance(user["certificate_pem"], bytes) else user["certificate_pem"]
    return render_template("keys.html",
                           public_key=public_key_pem,
                           certificate=cert_pem,
                           username=session["username"])


if __name__ == "__main__":
    db.init_db()
    print("DocumentFlow запущен: http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
