# -*- coding: utf-8 -*-
"""tests/test_multicipher.py
容器 v4（算法链叠加、单一总密钥）端到端验证。
"""
import os

import pytest

from app.core import algorithms as alg
from app.core import multicipher as mc


def _write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def test_v4_password_roundtrip(tmp_path):
    src = tmp_path / "secret.bin"
    payload = os.urandom(200_000)
    _write(src, payload)
    enc = tmp_path / "secret.aes256"
    dec = tmp_path / "secret.out"
    chain = ["aes-256-gcm", "chacha20-poly1305"]

    ok, r = mc.encrypt_file_password(str(src), str(enc), "Str0ng-Pass!2025",
                                     chain, chunk_size=32 * 1024)
    assert ok, r
    assert mc.is_v4(str(enc))
    meta = mc.read_meta(str(enc))
    assert meta["chain"] == chain
    assert meta["version"] == 4

    ok2, r2 = mc.decrypt_file_password(str(enc), str(dec), "Str0ng-Pass!2025")
    assert ok2, r2
    assert dec.read_bytes() == payload


def test_v4_wrong_password_fails(tmp_path):
    src = tmp_path / "s.bin"
    _write(src, b"x" * 4096)
    enc = tmp_path / "s.aes256"
    dec = tmp_path / "s.out"
    assert mc.encrypt_file_password(str(src), str(enc), "right-pass-1",
                                    ["aes-256-gcm"])[0]
    ok, _ = mc.decrypt_file_password(str(enc), str(dec), "wrong-pass-9")
    assert not ok
    assert not dec.exists()


def test_v4_tamper_detected(tmp_path):
    src = tmp_path / "t.bin"
    _write(src, os.urandom(20_000))
    enc = tmp_path / "t.aes256"
    dec = tmp_path / "t.out"
    assert mc.encrypt_file_password(str(src), str(enc), "pw-abcdef-12345",
                                    ["aes-256-gcm"], chunk_size=4096)[0]
    raw = bytearray(enc.read_bytes())
    # 翻转文件末尾之前的某个数据字节，破坏尾部 HMAC
    raw[-64] ^= 0x01
    enc.write_bytes(bytes(raw))
    ok, _ = mc.decrypt_file_password(str(enc), str(dec), "pw-abcdef-12345")
    assert not ok


def test_v4_empty_file(tmp_path):
    src = tmp_path / "empty.bin"
    _write(src, b"")
    enc = tmp_path / "empty.aes256"
    dec = tmp_path / "empty.out"
    assert mc.encrypt_file_password(str(src), str(enc), "pw-empty-123456",
                                    ["aes-256-gcm"])[0]
    assert mc.decrypt_file_password(str(enc), str(dec), "pw-empty-123456")[0]
    assert dec.read_bytes() == b""


def test_v4_multi_layer_file(tmp_path):
    chain = [c for c in ("aes-256-gcm", "chacha20-poly1305", "aes-256-cbc-hmac",
                         "camellia-256-cfb-hmac") if alg.is_available(c)]
    src = tmp_path / "m.bin"
    payload = os.urandom(300_000)
    _write(src, payload)
    enc = tmp_path / "m.aes256"
    dec = tmp_path / "m.out"
    assert mc.encrypt_file_password(str(src), str(enc), "multi-layer-Pass-9",
                                    chain, chunk_size=16 * 1024)[0]
    assert mc.decrypt_file_password(str(enc), str(dec), "multi-layer-Pass-9")[0]
    assert dec.read_bytes() == payload


def test_v4_bytes_helpers():
    import app.core as core

    master = core.derive_master("pw", salt=core.new_salt())
    blob = core.encrypt_bytes_chain(b"hello" * 1000, master,
                                    ["aes-256-gcm", "blowfish-cfb-hmac"]
                                    if alg.is_available("blowfish-cfb-hmac")
                                    else ["aes-256-gcm"])
    assert core.is_v4_bytes(blob) if hasattr(core, "is_v4_bytes") else blob[:8] == b"AES256v4"
    assert core.decrypt_bytes_chain(blob, master) == b"hello" * 1000
