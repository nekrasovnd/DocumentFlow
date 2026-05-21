"""
Модуль электронной подписи.
Генерация ключей RSA, подписание и верификация документов,
генерация самоподписанных сертификатов X.509.
"""

import datetime
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_key_pair():
    """Генерация ключевой пары RSA-2048."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key


def serialize_private_key(private_key):
    """Сериализация закрытого ключа в формат PEM."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(private_key):
    """Сериализация открытого ключа в формат PEM."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_data):
    """Загрузка закрытого ключа из PEM."""
    return serialization.load_pem_private_key(pem_data, password=None)


def load_public_key(pem_data):
    """Загрузка открытого ключа из PEM."""
    return serialization.load_pem_public_key(pem_data)


def sign_document(file_data: bytes, private_key) -> bytes:
    """
    Подписание документа.
    Используется схема RSA-PSS с хэш-функцией SHA-256.
    """
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(file_data: bytes, signature: bytes, public_key) -> bool:
    """
    Верификация электронной подписи.
    Возвращает True, если подпись корректна, иначе False.
    """
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def generate_certificate(private_key, username: str):
    """Генерация самоподписанного сертификата X.509."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocumentFlow System"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


def serialize_certificate(cert):
    """Сериализация сертификата в PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def encode_signature_b64(signature: bytes) -> str:
    """Кодирование подписи в Base64."""
    return base64.b64encode(signature).decode("utf-8")


def decode_signature_b64(sig_b64: str) -> bytes:
    """Декодирование подписи из Base64."""
    return base64.b64decode(sig_b64)
