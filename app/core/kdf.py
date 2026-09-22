# -*- coding: utf-8 -*-
"""
app/core/kdf.py
===============
密钥派生：
- 主密钥：Argon2id 优先，argon2-cffi 缺失时自动回退 PBKDF2-HMAC-SHA256；
- 备份主密钥：不同 salt 域，避免与主密钥互相推导；
- 文件子密钥：HKDF（RFC 5869）从主密钥 + 每文件随机 salt 派生。

重要修正（相对原文档）
----------------------
原文档测试写了 `derive_master("x") == derive_master("x")`，这隐含「全局固定盐」，
等于所有用户共用一个派生参数，彩虹表可跨用户复用，是严重缺陷。
本实现要求随机盐；确定性只在显式传入同一 salt 时成立。
"""
from __future__ import annotations

import hashlib
import hmac
import os

try:
    from argon2.low_level import Type, hash_secret_raw

    ARGON2_AVAILABLE = True
except Exception:                      # pragma: no cover
    ARGON2_AVAILABLE = False

# ---- 参数（默认值；可经 security.SecurityParams 动态覆盖）----
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536             # KiB = 64 MiB
ARGON2_PARALLELISM = 2
PBKDF2_ITERATIONS = 600_000

SALT_LEN = 16
KEY_LEN = 32
NONCE_LEN = 12

# 运行期生效的安全参数（由 set_active_params / load_active_params 设置）。
# 为 None 时回退上面的模块常量，保证旧调用零改动。
_ACTIVE = None


def set_active_params(params) -> None:
    """安装一组 SecurityParams，使后续 derive_master 采用其强度。"""
    global _ACTIVE
    _ACTIVE = params


def active_params():
    return _ACTIVE


def load_active_params(root=None):
    """从 config.json 读取安全参数并安装。失败时保持 None（用默认值）。"""
    try:
        from .settings import load_params

        p = load_params(root)
    except Exception:
        return None
    set_active_params(p)
    return p

BACKUP_SALT_DOMAIN = b"aes256-tool::backup-master::v1"
FILE_KEY_INFO = b"aes256-tool::file-key::v2"
AI_SECRET_SALT = b"aes256-tool::ai-secret::v1"


def new_salt(n: int = SALT_LEN) -> bytes:
    return os.urandom(n)


def new_nonce(n: int = NONCE_LEN) -> bytes:
    return os.urandom(n)


def hkdf(master: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """RFC 5869 HKDF-SHA256（extract + expand）。"""
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_master(password: str, salt: bytes | None = None, salt_len: int | None = None) -> bytes:
    """由密码派生 32 字节主密钥。salt=None 时使用随机盐（推荐）。

    强度取自 active_params()（若已安装），否则用模块常量。
    """
    p = _ACTIVE
    if salt_len is None:
        salt_len = p.salt_len if p is not None else SALT_LEN
    if salt is None:
        salt = new_salt(salt_len)
    pwd = password.encode("utf-8")
    want_argon2 = ARGON2_AVAILABLE and (p is None or p.kdf == "argon2id")
    if want_argon2:
        return hash_secret_raw(
            secret=pwd, salt=salt,
            time_cost=p.argon2_time_cost if p else ARGON2_TIME_COST,
            memory_cost=p.argon2_memory_cost if p else ARGON2_MEMORY_COST,
            parallelism=p.argon2_parallelism if p else ARGON2_PARALLELISM,
            hash_len=KEY_LEN, type=Type.ID,
        )
    iters = p.pbkdf2_iterations if p else PBKDF2_ITERATIONS
    return hashlib.pbkdf2_hmac("sha256", pwd, salt, iters, dklen=KEY_LEN)


_ACTIVE_SALT: bytes | None = None


def set_active_salt(salt: bytes | None) -> None:
    """安装当前保险库的 KDF 盐（字节）。"""
    global _ACTIVE_SALT
    _ACTIVE_SALT = bytes(salt) if salt else None


def get_active_salt() -> bytes | None:
    return _ACTIVE_SALT


def recipe() -> dict:
    """返回当前应使用的 KDF 配方（盐 + 参数），供容器头部自描述使用。"""
    p = _ACTIVE
    salt = _ACTIVE_SALT
    if salt is None:
        salt = new_salt(p.salt_len if p is not None else SALT_LEN)
    if p is None:
        return {
            "salt": salt,
            "kdf_name": "argon2id" if ARGON2_AVAILABLE else "pbkdf2",
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "iterations": PBKDF2_ITERATIONS,
        }
    return {
        "salt": salt,
        "kdf_name": p.kdf,
        "time_cost": p.argon2_time_cost,
        "memory_cost": p.argon2_memory_cost,
        "parallelism": p.argon2_parallelism,
        "iterations": p.pbkdf2_iterations,
    }


def derive_master_custom(password: str, salt: bytes, *, kdf_name: str = "argon2id",
                         time_cost: int = ARGON2_TIME_COST,
                         memory_cost: int = ARGON2_MEMORY_COST,
                         parallelism: int = ARGON2_PARALLELISM,
                         iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """用显式参数派生主密钥——解密方从容器头部读回盐与参数后调用，保证可复现。"""
    pwd = password.encode("utf-8")
    if kdf_name == "argon2id" and ARGON2_AVAILABLE:
        return hash_secret_raw(
            secret=pwd, salt=salt,
            time_cost=int(time_cost), memory_cost=int(memory_cost),
            parallelism=int(parallelism), hash_len=KEY_LEN, type=Type.ID,
        )
    return hashlib.pbkdf2_hmac("sha256", pwd, salt, int(iterations), dklen=KEY_LEN)


def derive_backup_master(password: str) -> bytes:
    """备份密钥使用独立盐域，不能由主密钥推出，反之亦然。"""
    return derive_master(password, salt=BACKUP_SALT_DOMAIN)


def derive_file_key(master: bytes, salt: bytes) -> bytes:
    """每个文件独立的加密子密钥（HKDF），主密钥不直接参与分块加密。"""
    if len(salt) < 8:
        raise ValueError("file salt 至少 8 字节")
    return hkdf(master, salt, FILE_KEY_INFO, KEY_LEN)


def kdf_name() -> str:
    return "Argon2id" if ARGON2_AVAILABLE else "PBKDF2-HMAC-SHA256"
