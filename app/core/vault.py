# -*- coding: utf-8 -*-
"""
app/core/vault.py
=================
保险库元数据：持久化 KDF 盐与安全参数，使「密码 → 主密钥」可复现。

为什么需要它
------------
安全要求每次加密使用随机盐；但若盐不落盘，同一密码每次派生出的主密钥都不同，
解密必然失败。折中方案：盐是「每次安装一次性生成」的随机值（per-vault），
而不是 per-file；它本身不是秘密，写入 vault.json，与密文一同管理即可。
容器头部同时冗余记录盐与参数，因此即使 vault.json 丢失，只要记得密码，
单文件仍可自描述解密。

vault.json 字段：
    kdf_salt   : 16 字节盐（hex）
    created_at : 创建时间戳
    （KDF 参数来自 config.json 的 security 段，避免两处真源）
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .. import config as cfgmod
from ..paths import log_dir
from . import kdf
from .security import SecurityParams, from_config, preset, to_config

VAULT_NAME = "vault.json"


def vault_path(root: Path | str | None = None) -> Path:
    base = Path(root) if root else log_dir()
    base.mkdir(parents=True, exist_ok=True)
    return base / VAULT_NAME


def load_raw(root: Path | str | None = None) -> dict:
    p = vault_path(root)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_raw(data: dict, root: Path | str | None = None) -> Path:
    p = vault_path(root)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def get_salt(root: Path | str | None = None) -> bytes:
    """取得（必要时创建）保险库 KDF 盐。"""
    d = load_raw(root)
    salt_hex = d.get("kdf_salt")
    if not salt_hex:
        salt_hex = os.urandom(16).hex()
        d["kdf_salt"] = salt_hex
        d.setdefault("created_at", __import__("time").time())
        save_raw(d, root)
    return bytes.fromhex(salt_hex)


def get_params(root: Path | str | None = None) -> SecurityParams:
    return from_config(cfgmod.load(root))


def set_params(params: SecurityParams, root: Path | str | None = None) -> Path:
    errs = params.validate()
    if errs:
        raise ValueError("安全参数不合法: " + "; ".join(errs))
    cfg = cfgmod.load(root)
    saved = cfgmod.save(to_config(params, cfg), root)
    kdf.set_active_params(params)
    return saved


def apply_preset(name: str, root: Path | str | None = None) -> SecurityParams:
    p = preset(name)
    set_params(p, root)
    return p


def derive_master(password: str, root: Path | str | None = None) -> bytes:
    """安装当前参数与盐，然后由密码派生可复现的主密钥。"""
    params = get_params(root)
    salt = get_salt(root)
    kdf.set_active_params(params)
    kdf.set_active_salt(salt)
    return kdf.derive_master(password, salt=salt)


def init(root: Path | str | None = None) -> dict:
    """确保 vault.json 与安全参数存在，返回概览 dict。"""
    salt = get_salt(root)
    params = get_params(root)
    kdf.set_active_salt(salt)
    kdf.set_active_params(params)
    return {"salt_hex": salt.hex(), "params": params.describe(),
            "vault": str(vault_path(root))}
