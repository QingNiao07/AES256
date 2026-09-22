# -*- coding: utf-8 -*-
"""tests/test_core.py · 核心逻辑单测"""
import os

import pytest

from app.core import (IntegrityError, check_password_policy, decrypt_bytes,
                      decode_recovery_code, derive_file_key, derive_master,
                      encrypt_bytes, export_keyfile, import_keyfile,
                      make_recovery_code, new_salt, password_strength,
                      verify_challenge)


# ---- KDF ----
def test_kdf_deterministic_with_same_salt():
    salt = new_salt()
    assert derive_master("pw", salt=salt) == derive_master("pw", salt=salt)
    assert len(derive_master("pw", salt=salt)) == 32


def test_kdf_random_salt_differs():
    # 默认随机盐，两次结果必须不同（修正原文档的固定盐缺陷）
    assert derive_master("pw") != derive_master("pw")


def test_kdf_salt_changes_key():
    assert derive_master("pw", salt=b"\x01" * 16) != derive_master("pw", salt=b"\x02" * 16)


def test_backup_master_differs_from_master():
    salt = new_salt()
    assert derive_master("pw", salt=salt) != derive_master("pw")


def test_file_key_depends_on_salt():
    m = derive_master("pw", salt=new_salt())
    assert derive_file_key(m, b"a" * 16) != derive_file_key(m, b"b" * 16)


# ---- 内存加解密 ----
def test_encrypt_decrypt_roundtrip():
    m = derive_master("pw", salt=new_salt())
    data = b"Hello, AES-256!" * 100
    assert decrypt_bytes(encrypt_bytes(data, m), m) == data


def test_wrong_password_fails():
    m1 = derive_master("correct", salt=new_salt())
    m2 = derive_master("wrong", salt=new_salt())
    blob = encrypt_bytes(b"secret", m1)
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob, m2)


def test_tampered_blob_fails():
    m = derive_master("pw", salt=new_salt())
    blob = bytearray(encrypt_bytes(b"secret data here", m))
    blob[-1] ^= 0x01
    with pytest.raises(IntegrityError):
        decrypt_bytes(bytes(blob), m)


# ---- 密码策略 ----
def test_password_strength_levels():
    assert password_strength("123456")[0] == 0
    assert password_strength("Abc@12345678xyz!")[0] >= 2


def test_policy_rejects_short():
    ok, _ = check_password_policy("Short1!")
    assert not ok


def test_policy_accepts_strong():
    ok, msg = check_password_policy("Str0ng#Passw0rd!2025")
    assert ok, msg


# ---- 密钥文件 ----
def test_keyfile_roundtrip(tmp_path):
    m = derive_master("pw", salt=new_salt())
    p = export_keyfile(m, tmp_path / "b.key", "backup-pw")
    assert import_keyfile(p, "backup-pw") == m


def test_keyfile_wrong_passphrase(tmp_path):
    m = derive_master("pw", salt=new_salt())
    p = export_keyfile(m, tmp_path / "b.key", "backup-pw")
    with pytest.raises(Exception):
        import_keyfile(p, "wrong-pw")


# ---- 恢复码 ----
def test_recovery_code_roundtrip():
    m = derive_master("pw", salt=new_salt())
    code = make_recovery_code(m)
    assert decode_recovery_code(code) == m


def test_recovery_code_challenge():
    m = derive_master("pw", salt=new_salt())
    groups = make_recovery_code(m).split("-")
    assert verify_challenge(m, {1: groups[0], 5: groups[4]})
    assert not verify_challenge(m, {1: "WRONG"})
