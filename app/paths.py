# -*- coding: utf-8 -*-
"""
app/paths.py
============
统一的路径解析。

开发态与 PyInstaller 打包态的可写目录不同：
- 开发态：项目根目录（app/ 的上一级）
- 打包态：exe 所在目录（不能用 __file__，那会指向临时解包目录 _MEIPASS）
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

LOG_DIRNAME = "aes_log"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def base_dir() -> Path:
    """可写根目录。"""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_dir() -> Path:
    """只读资源目录（打包后为 _MEIPASS）。"""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", base_dir()))
    return base_dir()


def log_dir(create: bool = True) -> Path:
    d = base_dir() / LOG_DIRNAME
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_dirs(*names: str) -> list[Path]:
    out = []
    for n in names:
        p = base_dir() / n
        p.mkdir(parents=True, exist_ok=True)
        out.append(p)
    return out


def is_same_volume(a: str | os.PathLike, b: str | os.PathLike) -> bool:
    """判断两个路径是否位于同一卷/盘符（用于同盘风险检测）。"""
    try:
        pa, pb = Path(a).resolve(), Path(b).resolve()
    except OSError:
        return False
    if os.name == "nt":
        return pa.drive.lower() == pb.drive.lower()
    # POSIX：比较挂载点前缀的粗略方式
    def root(p: Path) -> str:
        parts = p.parts
        return "/" + (parts[1] if len(parts) > 1 else "")
    return root(pa) == root(pb)
