# -*- coding: utf-8 -*-
"""
app/core/riskcheck.py
=====================
同盘风险检测：密文与密钥文件位于同一磁盘/分区时主动警告。

这条比加十个功能都实用 —— 用户最常犯的致命错误就是把密钥文件放在
密文旁边，等于没加密。
"""
from __future__ import annotations

import os
from pathlib import Path

from ..paths import is_same_volume

KEY_SUFFIXES = {".key", ".aes256key", ".keystore", ".recovery"}
SECRET_NAMES = {"ai_secret.bin", "recent.json", "backup.db"}


def find_secret_files(search_dirs: list[str | Path] | None = None) -> list[str]:
    """在给定目录（默认程序目录 + aes_log）中查找密钥类文件。"""
    from ..paths import base_dir, log_dir

    roots = [Path(d) for d in (search_dirs or [base_dir(), log_dir()])]
    found: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() in KEY_SUFFIXES or p.name in SECRET_NAMES:
                found.append(str(p))
    return found


def check_pair(cipher_path: str | Path, key_paths: list[str | Path] | None = None) -> dict:
    """检查单个密文与若干密钥文件是否同盘/同目录。

    返回 {safe: bool, same_dir: [...], same_volume: [...], warnings: [str]}
    """
    cipher = Path(cipher_path).resolve()
    keys = [Path(k).resolve() for k in (key_paths or find_secret_files())]

    same_dir, same_vol, warnings = [], [], []
    for k in keys:
        if k == cipher:
            continue
        if k.parent == cipher.parent:
            same_dir.append(str(k))
            warnings.append(f"密钥文件与密文在同一目录：{k}")
        elif is_same_volume(k, cipher):
            same_vol.append(str(k))
            warnings.append(f"密钥文件与密文在同一磁盘：{k}")

    return {
        "safe": not (same_dir or same_vol),
        "same_dir": same_dir,
        "same_volume": same_vol,
        "warnings": warnings,
    }


def check_any(paths: list[str | Path]) -> dict:
    """批量检查多个目标。"""
    keys = find_secret_files()
    out, all_warn = {}, []
    for p in paths:
        if str(p).endswith(".aes256"):
            r = check_pair(p, keys)
            out[str(p)] = r
            all_warn.extend(r["warnings"])
    return {"safe": not all_warn, "detail": out, "warnings": all_warn}
