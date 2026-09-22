# -*- coding: utf-8 -*-
"""tests/test_security.py · 可配置安全参数 + 密码级往返（图片来源第 5 项）"""
import os

import pytest

from app.core import container, kdf, security, vault


# ---- 预设与校验 ----
def test_all_presets_valid():
    for name in security.preset_names():
        p = security.preset(name)
        assert p.validate() == [], f"{name} 预设不合法"


def test_validate_catches_weak_params():
    p = security.SecurityParams(argon2_memory_cost=1024)   # 1 MiB 太弱
    assert p.validate()
    p2 = security.SecurityParams(salt_len=4)               # 盐太短
    assert p2.validate()
    p3 = security.SecurityParams(kdf="rot13")
    assert p3.validate()


def test_describe_mentions_algorithm():
    assert "Argon2id" in security.preset("hardened").describe()
    assert "PBKDF2" in security.SecurityParams(kdf="pbkdf2").describe()


def test_from_dict_ignores_unknown_and_fills_defaults():
    p = security.SecurityParams.from_dict({"argon2_time_cost": 5, "bogus": 1})
    assert p.argon2_time_cost == 5
    assert p.kdf == "argon2id"


# ---- 本机性能校准 ----
def test_calibrate_returns_valid_params():
    p, dt = security.calibrate(max_memory_kib=64 * 1024)
    assert p.validate() == []
    assert dt >= 0.0


def test_config_roundtrip():
    p = security.preset("fast")
    cfg = security.to_config(p, {})
    back = security.from_config(cfg)
    assert back.to_dict() == p.to_dict()


# ---- 关键修复：密码级往返（自描述头部 v3）----
PW = "Passw0rd!12345"


def test_password_roundtrip_small(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(5000))
    enc = tmp_path / "a.aes256"
    dec = tmp_path / "out.bin"
    ok, r = container.encrypt_file_password(str(src), str(enc), PW)
    assert ok, r
    ok2, r2 = container.decrypt_file_password(str(enc), str(dec), PW)
    assert ok2, r2
    assert dec.read_bytes() == src.read_bytes()


def test_password_roundtrip_multichunk(tmp_path):
    # 跨多个块（默认 4 MiB 块），验证块序号 nonce 与尾部 HMAC
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(4 * 1024 * 1024 + 12345))
    enc = tmp_path / "big.aes256"
    dec = tmp_path / "big.out"
    assert container.encrypt_file_password(str(src), str(enc), PW)[0]
    assert container.decrypt_file_password(str(enc), str(dec), PW)[0]
    assert dec.read_bytes() == src.read_bytes()


def test_password_roundtrip_empty_file(tmp_path):
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")
    enc = tmp_path / "empty.aes256"
    dec = tmp_path / "empty.out"
    assert container.encrypt_file_password(str(src), str(enc), PW)[0]
    assert container.decrypt_file_password(str(enc), str(dec), PW)[0]
    assert dec.read_bytes() == b""


def test_wrong_password_rejected(tmp_path):
    src = tmp_path / "b.bin"
    src.write_bytes(b"x" * 256)
    enc = tmp_path / "b.aes256"
    assert container.encrypt_file_password(str(src), str(enc), "correct-pass-1")[0]
    ok, _ = container.decrypt_file_password(str(enc), str(tmp_path / "o"), "wrong-pass-9")
    assert not ok


def test_tamper_detected(tmp_path):
    src = tmp_path / "c.bin"
    src.write_bytes(b"y" * 8192)
    enc = tmp_path / "c.aes256"
    assert container.encrypt_file_password(str(src), str(enc), PW)[0]
    data = bytearray(enc.read_bytes())
    data[len(data) // 2] ^= 0xFF               # 翻转密文中部一个字节
    enc.write_bytes(data)
    ok, _ = container.decrypt_file_password(str(enc), str(tmp_path / "o2"), PW)
    assert not ok


def test_truncation_detected(tmp_path):
    src = tmp_path / "d.bin"
    src.write_bytes(os.urandom(40000))
    enc = tmp_path / "d.aes256"
    assert container.encrypt_file_password(str(src), str(enc), PW)[0]
    enc.write_bytes(enc.read_bytes()[:-16])    # 砍掉尾部 HMAC
    ok, _ = container.decrypt_file_password(str(enc), str(tmp_path / "o3"), PW)
    assert not ok


# ---- 保险库盐持久化 ----
def test_vault_salt_persists(tmp_path):
    s1 = vault.get_salt(tmp_path)
    s2 = vault.get_salt(tmp_path)
    assert s1 == s2
    assert len(s1) == 16


def test_recipe_reflects_active_params():
    orig = kdf.active_params()
    try:
        p = security.preset("fast")
        kdf.set_active_params(p)
        r = kdf.recipe()
        assert r["time_cost"] == p.argon2_time_cost
        assert r["iterations"] == p.pbkdf2_iterations
        assert len(r["salt"]) == p.salt_len
    finally:
        kdf.set_active_params(orig)
