"""认证工具：管理员密码 / JWT / SIP Digest 鉴权。"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import get_settings

settings = get_settings()
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- 管理员密码 ----------

def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return _pwd.verify(password, hashed)


# ---------- JWT ----------

def create_access_token(sub: str, expires_minutes: int = 60 * 12) -> str:
    payload = {
        "sub": sub,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        return data.get("sub")
    except JWTError:
        return None


# ---------- SIP Digest (RFC 2617) ----------

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def compute_ha1(username: str, realm: str, password: str) -> str:
    return md5_hex(f"{username}:{realm}:{password}")


def gen_nonce() -> str:
    return md5_hex(f"{time.time()}:{secrets.token_hex(8)}")


def verify_digest(
    *,
    method: str,
    uri: str,
    realm: str,
    nonce: str,
    response: str,
    ha1: str,
    qop: Optional[str] = None,
    nc: Optional[str] = None,
    cnonce: Optional[str] = None,
) -> bool:
    """校验 SIP Digest response。"""
    ha2 = md5_hex(f"{method}:{uri}")
    if qop in ("auth", "auth-int") and nc and cnonce:
        expected = md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        expected = md5_hex(f"{ha1}:{nonce}:{ha2}")
    return hmac.compare_digest(expected, response.lower())
