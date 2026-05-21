"""Тест всех модулей DocumentFlow."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import signature as sig
import database as db

# 1. Test signature module
print("=== Тест модуля электронной подписи ===")

key = sig.generate_key_pair()
print("  Генерация ключевой пары RSA-2048: OK")

priv_pem = sig.serialize_private_key(key)
pub_pem = sig.serialize_public_key(key)
print(f"  Сериализация ключей: private={len(priv_pem)}B, public={len(pub_pem)}B")

cert = sig.generate_certificate(key, "TestUser")
cert_pem = sig.serialize_certificate(cert)
print(f"  Генерация сертификата X.509: {len(cert_pem)}B")

data = b"This is a test document content for signing."
signature = sig.sign_document(data, key)
print(f"  Подписание документа (RSA-PSS, SHA-256): signature={len(signature)}B")

pub_key = sig.load_public_key(pub_pem)
result = sig.verify_signature(data, signature, pub_key)
assert result is True, "Verification should be True for valid signature"
print(f"  Верификация (корректная подпись): {result}")

result_tampered = sig.verify_signature(data + b"X", signature, pub_key)
assert result_tampered is False, "Verification should be False for tampered data"
print(f"  Верификация (изменённый документ): {result_tampered}")

sig_b64 = sig.encode_signature_b64(signature)
sig_decoded = sig.decode_signature_b64(sig_b64)
assert sig_decoded == signature
print(f"  Base64 кодирование/декодирование: OK")

# 2. Test database module
print("\n=== Тест модуля базы данных ===")

# Use temp db
db.DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_db.db")
if os.path.exists(db.DB_PATH):
    os.remove(db.DB_PATH)

db.init_db()
print("  Инициализация БД: OK")

user_id = db.create_user("testuser", "hash123", priv_pem, pub_pem, cert_pem)
print(f"  Создание пользователя: id={user_id}")

user = db.get_user_by_username("testuser")
assert user is not None
assert user["username"] == "testuser"
print(f"  Поиск пользователя по имени: OK")

user2 = db.get_user_by_id(user_id)
assert user2 is not None
print(f"  Поиск пользователя по ID: OK")

# Create a test file
test_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "test.txt")
with open(test_file, "w") as f:
    f.write("Test document content")

checksum = db.compute_checksum(b"Test document content")
doc_id = db.insert_document("test.txt", test_file, user_id, checksum)
print(f"  Сохранение документа: id={doc_id}, checksum={checksum[:16]}...")

docs = db.get_all_documents()
assert len(docs) == 1
print(f"  Получение списка документов: count={len(docs)}")

doc = db.get_document_by_id(doc_id)
assert doc is not None
print(f"  Получение документа по ID: OK")

db.save_signature(doc_id, user_id, sig_b64)
print(f"  Сохранение подписи: OK")

sig_info = db.get_signature_for_document(doc_id)
assert sig_info is not None
assert sig_info["signer_name"] == "testuser"
print(f"  Получение подписи документа: signer={sig_info['signer_name']}")

# Cleanup
os.remove(db.DB_PATH)
os.remove(test_file)
print("\n=== ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО ===")
