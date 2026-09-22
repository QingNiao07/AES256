# -*- coding: utf-8 -*-
"""tests/test_container.py · 分块容器加解密与完整性"""
import os
from pathlib import Path

import pytest

from app.core import container
from app.core import derive_master, new_salt


@pytest.fixture()
def master():
    return derive_master("Container#Test!2025", salt=new_salt())


def test_file_roundtrip(tmp_path, master):
    src = tmp_path / "data.bin"
    src.write_bytes(os.urandom(1_000_000))
    enc = tmp_path / "data.bin.aes256"
    dec = tmp_path / "out.bin"
    r = container.encrypt_stream(src, enc, master, chunk_size=64 * 1024)
    assert r["ok"] and enc.exists()
    container.decrypt_stream(enc, dec, master)
    assert dec.read_bytes() == src.read_bytes()


def test_empty_file(tmp_path, master):
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")
    enc = tmp_path / "empty.aes256"
    dec = tmp_path / "empty.out"
    container.encrypt_stream(src, enc, master)
    container.decrypt_stream(enc, dec, master)
    assert dec.read_bytes() == b""


def test_wrong_password_file(tmp_path, master):
    src = tmp_path / "d.bin"
    src.write_bytes(b"payload" * 1000)
    enc = tmp_path / "d.aes256"
    container.encrypt_stream(src, enc, master)
    with pytest.raises(container.IntegrityError):
        container.decrypt_stream(enc, tmp_path / "o.bin",
                                 derive_master("wrong", salt=new_salt()))


def test_truncated_file_detected(tmp_path, master):
    src = tmp_path / "d.bin"
    src.write_bytes(os.urandom(200_000))
    enc = tmp_path / "d.aes256"
    container.encrypt_stream(src, enc, master, chunk_size=32 * 1024)
    data = enc.read_bytes()
    enc.write_bytes(data[:-40])              # 砍掉尾部 HMAC
    with pytest.raises(Exception):
        container.decrypt_stream(enc, tmp_path / "o.bin", master)


def test_no_partial_output_on_failure(tmp_path, master):
    src = tmp_path / "d.bin"
    src.write_bytes(b"x" * 1000)
    enc = tmp_path / "d.aes256"
    container.encrypt_stream(src, enc, master)
    out = tmp_path / "o.bin"
    with pytest.raises(container.IntegrityError):
        container.decrypt_stream(enc, out, derive_master("bad", salt=new_salt()))
    assert not out.exists()                  # 解密失败不得残留半成品


def test_cancel(tmp_path, master):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(400_000))
    enc = tmp_path / "big.aes256"
    state = {"n": 0}

    def cancel():
        state["n"] += 1
        return state["n"] > 1

    with pytest.raises(container.CancelledError):
        container.encrypt_stream(src, enc, master, chunk_size=16 * 1024, cancel=cancel)
    assert not enc.exists()
