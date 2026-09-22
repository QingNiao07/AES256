# -*- coding: utf-8 -*-
"""
app/core/cipher.py
==================
AES-256-GCM 基础加解密（内存态）。

设计要点
--------
- 12 字节随机 nonce，GCM 下绝不复用；
- 支持 AAD（附加认证数据），用于把文件头/块序号绑进认证范围；
- 返回 blob = nonce || ciphertext || tag。
"""
from __future__ import annotations

from Crypto.Cipher import AES

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32


class IntegrityError(ValueError):
    """认证失败：密文被篡改或密码错误。"""


def _check_key(key: bytes) -> None:
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256 需要 32 字节密钥，当前 {len(key)} 字节")


def encrypt_bytes(data: bytes, key: bytes, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
    _check_key(key)
    import os

    nonce = nonce or os.urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce 必须为 12 字节")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag


def decrypt_bytes(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    _check_key(key)
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise IntegrityError("密文长度不足，文件可能被截断")
    nonce, ct, tag = blob[:NONCE_LEN], blob[NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError as exc:
        raise IntegrityError("完整性校验失败：密码错误或文件已被篡改") from exc


def encrypt_with_nonce_ct_tag(data: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """分块流式用：只返回 (ciphertext, tag)，nonce 由调用方按序号构造。"""
    _check_key(key)
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce 必须为 12 字节")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def decrypt_with_nonce_ct_tag(ct: bytes, tag: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    _check_key(key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError as exc:
        raise IntegrityError("分块完整性校验失败：密码错误或文件已被篡改") from exc
