# -*- coding: utf-8 -*-
"""
app/core/__init__.py
====================
对外统一门面。函数签名与 DEVELOPMENT.md 中声明的一致，
旧代码 `import aes256_core as core` 可无改动迁移。

关键设计（相对原文档的修正）
----------------------------
1. derive_master 默认使用随机盐；确定性只在显式传 salt 时成立。
2. derive_file_key / encrypt_bytes / decrypt_bytes 签名保持文档一致。
3. load_policy / save_policy / check_password_policy / db_init / db_query
   全部按文档提供。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import (algorithms, archive, audit, cipher, container, keystore, kdf,
               multicipher, netguard, policy, recent,
               riskcheck, securemem, security, settings, share, split, state, store,
               vault)
from .cipher import IntegrityError
from .container import (CancelledError, ContainerError, decrypt_file_password,
                        decrypt_stream, decrypt_stream_password, encrypt_file_password,
                        encrypt_stream, encrypt_stream_password, header_params)
from .kdf import (derive_backup_master, derive_file_key, derive_master,
                  derive_master_custom, hkdf, new_nonce, new_salt, recipe)
from .security import PRESETS, SecurityParams, calibrate, preset, preset_names
from .state import (
    check_timeout, clear as clear_keys, get_backup, get_master,
    has_master, set_backup, set_master, set_timeout,
)

__version__ = "1.0.0"

__all__ = [
    # 密钥派生
    "derive_master", "derive_backup_master", "derive_file_key", "hkdf",
    "new_salt", "new_nonce",
    # 加解密
    "encrypt_bytes", "decrypt_bytes", "encrypt_file", "decrypt_file",
    "encrypt_stream", "decrypt_stream", "read_meta",
    # 策略
    "load_policy", "save_policy", "check_password_policy", "password_strength",
    "entropy_bits", "crack_seconds", "humanize_seconds", "suggest_password",
    # 密钥备份
    "export_keyfile", "import_keyfile", "make_recovery_code", "decode_recovery_code",
    "verify_challenge", "challenge_positions",
    # 数据库
    "db_init", "db_query", "db_record", "db_stats",
    # 状态
    "set_master", "get_master", "set_backup", "get_backup", "has_master",
    "clear_keys", "set_timeout", "check_timeout",
    # 审计
    "audit", "verify_audit", "audit_report",
    # 扩展功能
    "encrypt_folder", "decrypt_folder",
    "split_blob", "merge_parts", "list_parts",
    "make_share_page", "write_share_page",
    "check_same_volume", "find_secret_files",
    "recent_add", "recent_list", "toggle_favorite", "favorites",
    # 异常
    "IntegrityError", "ContainerError", "CancelledError",
    # 安全参数 / 保险库
    "SecurityParams", "PRESETS", "preset", "preset_names", "calibrate",
    "derive_master_custom", "recipe", "vault",
    "encrypt_stream_password", "decrypt_stream_password",
    "encrypt_file_password", "decrypt_file_password", "header_params",
    # 多算法 / 叠加加密（v4）
    "list_ciphers", "cipher_meta", "cipher_name", "available_ciphers",
    "describe_chain", "CipherStack", "DEFAULT_ALGORITHM", "MAX_CHAIN",
    "encrypt_stream_chain", "decrypt_stream_chain",
    "encrypt_file_chain", "decrypt_file_chain",
    "encrypt_bytes_chain", "decrypt_bytes_chain",
    "read_meta_v4", "is_v4",
    # 离线守卫
    "netguard",
    # 子模块
    "algorithms", "multicipher",
    "archive", "cipher", "container", "kdf", "keystore", "policy",
    "recent", "riskcheck", "securemem", "security", "settings", "share",
    "split", "state", "store", "vault",
]


# ============================================================
# 多算法注册表（薄封装，便于 CLI / UI 统一调用）
# ============================================================
DEFAULT_ALGORITHM = algorithms.DEFAULT_ALGORITHM
MAX_CHAIN = algorithms.MAX_CHAIN
CipherStack = algorithms.CipherStack


def list_ciphers(lang: str = "zh_CN") -> list[dict]:
    """返回全部算法元数据（含中英文名称、可用性、优先级）。"""
    from .. import i18n

    out = algorithms.list_algorithms()
    for m in out:
        m["display_name"] = i18n.describe(m.get("name"), lang)
        m["display_desc"] = i18n.describe(m.get("desc"), lang)
    return out


def cipher_meta(algo_id: str) -> dict:
    return algorithms.algorithm_meta(algo_id)


def cipher_name(algo_id: str, lang: str = "zh_CN") -> str:
    return algorithms.name_of(algo_id, lang)


def available_ciphers() -> list[str]:
    return algorithms.available_ids()


def describe_chain(chain, lang: str = "zh_CN") -> str:
    return algorithms.describe_chain(chain, lang)


# ============================================================
# 叠加加密（容器 v4）便捷入口
# ============================================================
def encrypt_stream_chain(src, dst, master, chain, **kw) -> dict:
    return multicipher.encrypt_stream(src, dst, master, chain, **kw)


def decrypt_stream_chain(src, dst, master, **kw) -> dict:
    return multicipher.decrypt_stream(src, dst, master, **kw)


def encrypt_file_chain(src, dst, master, chain, **kw) -> tuple:
    try:
        return True, multicipher.encrypt_stream(src, dst, master, chain, **kw)
    except Exception as exc:
        return False, str(exc)


def decrypt_file_chain(src, dst, master, **kw) -> tuple:
    try:
        return True, multicipher.decrypt_stream(src, dst, master, **kw)
    except Exception as exc:
        return False, str(exc)


def encrypt_bytes_chain(data: bytes, master: bytes, chain) -> bytes:
    """内存态叠加加密（含自描述头部，可用于分享页/小数据）。"""
    import io

    src = io.BytesIO(data)
    dst = io.BytesIO()
    multicipher.encrypt_stream_io(src, dst, master, chain)
    return dst.getvalue()


def decrypt_bytes_chain(blob: bytes, master: bytes) -> bytes:
    import io

    src = io.BytesIO(blob)
    dst = io.BytesIO()
    multicipher.decrypt_stream_io(src, dst, master)
    return dst.getvalue()


def read_meta_v4(src) -> dict:
    return multicipher.read_meta(src)


def is_v4(src) -> bool:
    return multicipher.is_v4(src)


# ============================================================
# 加解密（文档签名）
# ============================================================
def encrypt_bytes(data: bytes, master: bytes) -> bytes:
    """内存态加密：自动生成文件盐并派生文件子密钥。"""
    salt = new_salt(16)
    fk = derive_file_key(master, salt)
    blob = cipher.encrypt_bytes(data, fk, aad=salt)
    return salt + blob


def decrypt_bytes(blob: bytes, master: bytes) -> bytes:
    if len(blob) < 16 + 12 + 16:
        raise IntegrityError("密文长度不足")
    salt, body = blob[:16], blob[16:]
    fk = derive_file_key(master, salt)
    return cipher.decrypt_bytes(body, fk, aad=salt)


def encrypt_file(src, dst, master, **kw) -> tuple:
    return container.encrypt_file(src, dst, master, **kw)


def decrypt_file(src, dst, master, **kw) -> tuple:
    return container.decrypt_file(src, dst, master, **kw)


def read_meta(src) -> dict:
    return container.read_meta(src)


# ============================================================
# 策略
# ============================================================
def load_policy(root: Path | None = None) -> dict:
    from ..config import load as _load

    return _load(root)


def save_policy(p: dict, root: Path | None = None) -> Path:
    from ..config import save as _save

    return _save(p, root)


def check_password_policy(password: str, min_len: int = 12,
                          require_classes: int = 3) -> tuple[bool, str]:
    return policy.check_password_policy(password, min_len, require_classes)


def password_strength(password: str) -> tuple[int, str]:
    return policy.password_strength(password)


def entropy_bits(password: str) -> float:
    return policy.entropy_bits(password)


def crack_seconds(password: str, guesses_per_sec: float = 1e10) -> float:
    return policy.crack_seconds(password, guesses_per_sec)


def humanize_seconds(sec: float) -> str:
    return policy.humanize_seconds(sec)


def suggest_password(min_len: int = 16) -> str:
    return policy.suggest(min_len)


# ============================================================
# 密钥备份
# ============================================================
def export_keyfile(master, dst, passphrase, note: str = "") -> Path:
    return keystore.export_keyfile(master, dst, passphrase, note)


def import_keyfile(src, passphrase) -> bytes:
    return keystore.import_keyfile(src, passphrase)


def make_recovery_code(master: bytes) -> str:
    return keystore.make_recovery_code(master)


def decode_recovery_code(code: str) -> bytes:
    return keystore.decode_recovery_code(code)


def verify_challenge(master: bytes, answers: dict) -> bool:
    return keystore.verify_challenge(master, answers)


def challenge_positions(n: int = 3, total: int = keystore.NUM_GROUPS) -> list[int]:
    return keystore.challenge_positions(n, total)


# ============================================================
# 数据库
# ============================================================
def db_init(root: Path | None = None) -> None:
    store.init(root)


def db_query(sql: str, params: tuple = (), root: Path | None = None) -> list[dict]:
    with store.connect(root) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def db_record(action: str, **kw) -> int:
    return store.record(action, **kw)


def db_stats(root: Path | None = None) -> dict:
    return store.stats(root)


# ============================================================
# 审计
# ============================================================
def verify_audit() -> tuple[bool, str]:
    return audit.verify()


def audit_report(dst=None) -> Path:
    return audit.write_html_report(dst)


# ============================================================
# 扩展功能（推荐落地的低成本高收益项）
# ============================================================
def encrypt_folder(folder, dst, master, **kw) -> dict:
    return archive.encrypt_folder(folder, dst, master, **kw)


def decrypt_folder(src, out_dir, master, **kw) -> dict:
    return archive.decrypt_folder(src, out_dir, master, **kw)


def split_blob(src, volume_size: int = split.DEFAULT_VOLUME, **kw) -> dict:
    return split.split_blob(src, volume_size, **kw)


def merge_parts(src, dst=None, **kw) -> dict:
    return split.merge_parts(src, dst, **kw)


def list_parts(src) -> list:
    return split.list_parts(src)


def make_share_page(data: bytes, password: str, title: str = "AES-256 加密分享") -> str:
    return share.build_share_page(data, password, title)


def write_share_page(data: bytes, password: str, dst, title: str = "AES-256 加密分享"):
    return share.write_share_page(data, password, dst, title)


def check_same_volume(cipher_path, key_paths=None) -> dict:
    return riskcheck.check_pair(cipher_path, key_paths)


def find_secret_files(search_dirs=None) -> list:
    return riskcheck.find_secret_files(search_dirs)


def recent_add(path: str, action: str = "") -> None:
    recent.add(path, action)


def recent_list(limit: int = 10) -> list:
    return recent.list_recent(limit)


def toggle_favorite(path: str) -> bool:
    return recent.toggle_favorite(path)


def favorites() -> list:
    return recent.favorites()


# ============================================================
# 自检
# ============================================================
def selftest() -> int:
    """最小可用性自检：加解密往返 + 密钥文件 + 恢复码。"""
    import os

    print(f"[core] KDF = {kdf.kdf_name()}")
    master = derive_master("Selftest#Passw0rd!2025", salt=new_salt())
    data = os.urandom(300_000)
    blob = encrypt_bytes(data, master)
    assert decrypt_bytes(blob, master) == data, "内存加解密往返失败"
    print("[core] 内存加解密往返 OK")

    bad = False
    try:
        decrypt_bytes(blob, derive_master("wrong", salt=new_salt()))
    except IntegrityError:
        bad = True
    assert bad, "错误密钥未触发完整性错误"
    print("[core] 错误密钥拒绝 OK")

    code = make_recovery_code(master)
    assert decode_recovery_code(code) == master, "恢复码往返失败"
    print(f"[core] 恢复码 OK（{len(code.split('-'))} 组）")

    ok, msg = check_password_policy("Selftest#Passw0rd!2025")
    print(f"[core] 密码策略：{msg}")
    print("[core] 自检完成")
    return 0
