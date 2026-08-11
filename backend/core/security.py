import os
import ctypes
import secrets
import time
import base64
import hashlib
from typing import Optional
from fastapi import Header, HTTPException, Query, status


_token_cache: dict = {"token": None, "ts": 0.0}
_TOKEN_CACHE_TTL = 15.0

_rust_lib = None
_rust_lib_path = os.path.join(os.path.dirname(__file__), "..", "rust_crypto", "target", "release", "sentinel_crypto.dll")
if not os.path.exists(_rust_lib_path):
    _rust_lib_path = os.path.join(os.path.dirname(__file__), "..", "rust_crypto", "target", "release", "libsentinel_crypto.so")

if os.path.exists(_rust_lib_path):
    try:
        _rust_lib = ctypes.CDLL(_rust_lib_path)
        _rust_lib.encrypt_payload.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _rust_lib.encrypt_payload.restype = ctypes.c_char_p
        _rust_lib.decrypt_payload.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _rust_lib.decrypt_payload.restype = ctypes.c_char_p
        _rust_lib.free_string.argtypes = [ctypes.c_char_p]
        _rust_lib.free_string.restype = None
    except Exception:
        _rust_lib = None


def sanitize_file_path(filename: str) -> str:
    if not filename:
        return ""
    clean = os.path.basename(filename).replace("..", "").replace("/", "").replace("\\", "")
    return clean


def sanitize_input_string(text: str, max_len: int = 5000) -> str:
    if not text:
        return ""
    clean = text.strip()[:max_len]
    return clean


def _get_default_secret_key() -> str:
    return os.getenv("SENTINEL_SECRET_KEY", "sentinel_default_rust_key_32b")


def encrypt_with_rust(data: str, secret_key: str = None) -> str:
    if not data:
        return ""
    if not secret_key:
        secret_key = _get_default_secret_key()
    if _rust_lib:
        try:
            res_ptr = _rust_lib.encrypt_payload(data.encode("utf-8"), secret_key.encode("utf-8"))
            if res_ptr:
                result = ctypes.string_at(res_ptr).decode("utf-8")
                _rust_lib.free_string(res_ptr)
                return result
        except Exception:
            pass
    try:
        salt = hashlib.sha256(secret_key.encode("utf-8")).digest()[:16]
        key_bytes = hashlib.pbkdf2_hmac("sha256", secret_key.encode("utf-8"), salt, 100000, 32)
        data_bytes = data.encode("utf-8")
        xor_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])
        return base64.b64encode(salt + xor_bytes).decode("utf-8")
    except Exception:
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def decrypt_with_rust(encrypted_data: str, secret_key: str = None) -> str:
    if not secret_key:
        secret_key = _get_default_secret_key()
    if not encrypted_data:
        return ""
    if _rust_lib:
        try:
            res_ptr = _rust_lib.decrypt_payload(encrypted_data.encode("utf-8"), secret_key.encode("utf-8"))
            if res_ptr:
                result = ctypes.string_at(res_ptr).decode("utf-8")
                _rust_lib.free_string(res_ptr)
                return result
        except Exception:
            pass
    try:
        raw_bytes = base64.b64decode(encrypted_data)
        if len(raw_bytes) > 16:
            salt = raw_bytes[:16]
            payload = raw_bytes[16:]
            key_bytes = hashlib.pbkdf2_hmac("sha256", secret_key.encode("utf-8"), salt, 100000, 32)
            data_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(payload)])
            return data_bytes.decode("utf-8")
        key_bytes = hashlib.sha256(secret_key.encode("utf-8")).digest()
        data_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw_bytes)])
        return data_bytes.decode("utf-8")
    except Exception:
        try:
            return base64.b64decode(encrypted_data).decode("utf-8")
        except Exception:
            return ""


def _get_api_token() -> str:
    now = time.monotonic()
    if _token_cache["token"] is None or (now - _token_cache["ts"]) > _TOKEN_CACHE_TTL:
        from backend.db.database import SessionLocal, get_settings_db
        db = SessionLocal()
        try:
            s = get_settings_db(db)
            _token_cache["token"] = (s.api_key or "").strip()
            _token_cache["ts"] = now
        finally:
            db.close()
    return _token_cache["token"] or ""


def invalidate_token_cache():
    _token_cache["token"] = None
    _token_cache["ts"] = 0.0


def _assert_token_match(provided: str, stored: str):
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key not configured on server.",
        )
    if not provided or not secrets.compare_digest(provided, stored):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication token.",
        )


async def verify_agent_token(
    token: Optional[str] = Header(None, alias="token"),
    token_query: Optional[str] = Query(None, alias="token"),
) -> str:
    provided = (token or token_query or "").strip()
    stored = _get_api_token()
    _assert_token_match(provided, stored)
    return provided


async def verify_api_agent_mode(
    token: Optional[str] = Header(None, alias="token"),
) -> str:
    stored_key = _get_api_token()
    if not stored_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Server is not in API Agent mode. Configure an API token in settings.",
        )
    provided = (token or "").strip()
    _assert_token_match(provided, stored_key)
    return provided
