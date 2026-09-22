# -*- coding: utf-8 -*-
"""tests/test_algorithms.py
多加密算法注册表 + 按算法/叠加算法往返验证。
"""
import os

import pytest

from app.core import algorithms as alg
from app.core.cipher import IntegrityError


def _key(algo_id):
    a = alg.get_algorithm(algo_id)
    need = a.key_size + a.mac_key_len
    import hashlib

    seed = hashlib.sha256(b"k::" + algo_id.encode()).digest()
    return (seed * (need // len(seed) + 1))[:need]


@pytest.mark.parametrize("algo_id", alg.available_ids())
def test_single_algorithm_roundtrip(algo_id):
    a = alg.get_algorithm(algo_id)
    key = _key(algo_id)
    nonce = b"\x07" * a.nonce_size
    msg = os.urandom(5000)
    ct, tag = a.encrypt(key, msg, nonce, b"aad")
    assert ct != msg
    assert a.decrypt(key, ct, nonce, tag, b"aad") == msg


@pytest.mark.parametrize("algo_id", alg.available_ids())
def test_tamper_detected(algo_id):
    a = alg.get_algorithm(algo_id)
    key = _key(algo_id)
    nonce = b"\x07" * a.nonce_size
    ct, tag = a.encrypt(key, b"payload-data", nonce, b"aad")
    bad = bytearray(ct)
    bad[0] ^= 0x01
    with pytest.raises(IntegrityError):
        a.decrypt(key, bytes(bad), nonce, tag, b"aad")


def test_registry_metadata():
    metas = alg.list_algorithms()
    assert len(metas) == len(alg.algorithm_ids())
    assert metas[0]["id"] == "aes-256-gcm"        # 优先级最高
    for m in metas:
        assert m["name"]["zh_CN"] and m["name"]["en_US"]
        assert m["tag_size"] == 16


def test_normalize_chain_validation():
    assert alg.normalize_chain(None) == [alg.DEFAULT_ALGORITHM]
    assert alg.normalize_chain(["aes-256-gcm"]) == ["aes-256-gcm"]
    with pytest.raises(alg.AlgorithmError):
        alg.normalize_chain(["nope-cipher"])
    with pytest.raises(alg.AlgorithmError):
        alg.normalize_chain(["aes-256-gcm"] * (alg.MAX_CHAIN + 1))


def test_stacked_roundtrip():
    chain = [c for c in ("aes-256-gcm", "chacha20-poly1305", "aes-256-cbc-hmac")
             if alg.is_available(c)]
    master = os.urandom(32)
    salt = os.urandom(16)
    st = alg.CipherStack(chain, master, salt)
    for idx in (0, 1, 7):
        msg = os.urandom(3000)
        aad = b"hdr" + idx.to_bytes(4, "big")
        ct, tags = st.encrypt_block(msg, idx, aad)
        assert st.decrypt_block(ct, tags, idx, aad) == msg


def test_stacked_wrong_key_fails():
    chain = ["aes-256-gcm", "aes-256-cbc-hmac"]
    st1 = alg.CipherStack(chain, os.urandom(32), b"\x00" * 16)
    st2 = alg.CipherStack(chain, os.urandom(32), b"\x00" * 16)
    ct, tags = st1.encrypt_block(b"hello", 0, b"h" + b"\x00\x00\x00\x00")
    with pytest.raises(IntegrityError):
        st2.decrypt_block(ct, tags, 0, b"h" + b"\x00\x00\x00\x00")


def test_single_master_key_subkeys_differ():
    """单一总密钥约束：各层子密钥必须不同（HKDF 域分离）。"""
    chain = ["aes-256-gcm", "chacha20-poly1305"]
    master = os.urandom(32)
    salt = os.urandom(16)
    k0 = alg.derive_layer_key(master, salt, chain[0], 0)
    k1 = alg.derive_layer_key(master, salt, chain[1], 1)
    assert k0 != k1
    assert len(k0) == 32 and len(k1) == 32
