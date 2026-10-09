"""敏感字段加密存储（面板令牌、Reality 私钥、SS 密钥）。"""
import base64
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .config import get_config

_fernet = None


def _get():
    global _fernet
    if _fernet is None:
        path = os.path.join(get_config().data_dir, "secret.key")
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(Fernet.generate_key())
            os.chmod(path, 0o600)
        with open(path, "rb") as f:
            _fernet = Fernet(f.read().strip())
    return _fernet


def reset():
    global _fernet
    _fernet = None


def enc(value):
    if value in (None, ""):
        return value
    return "enc:" + _get().encrypt(value.encode()).decode()


def dec(value):
    if not value or not str(value).startswith("enc:"):
        return value
    try:
        return _get().decrypt(value[4:].encode()).decode()
    except InvalidToken:
        return None


def mask(value, keep=8):
    if not value:
        return ""
    return value[:keep] + "…"


# ---------- 代理相关密钥 ----------

SS2022_KEY_LEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


def gen_ss2022_key(method):
    n = SS2022_KEY_LEN[method]
    return base64.b64encode(secrets.token_bytes(n)).decode()


def ss2022_key_ok(method, key):
    """SS 2022 密钥必须是 base64，且解码后长度匹配加密方式。"""
    n = SS2022_KEY_LEN.get(method)
    if n is None:
        return True  # 非 2022 方法不校验长度
    try:
        raw = base64.b64decode(key, validate=True)
    except Exception:
        return False
    return len(raw) == n


def gen_x25519():
    """Reality 密钥对（base64url，无填充，与 xray x25519 输出一致）。"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pb = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    b = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
    return b(pb), b(pub)


def gen_short_id():
    return secrets.token_hex(8)


def gen_token(n=16):
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))
