# -*- coding: utf-8 -*-
"""
app/core/archive.py
===================
文件夹整体加密为单容器（目录树 + 元数据打包）。

用途：整项目归档。把一棵目录树打成 tar，再走 container 的分块流式加密，
不把明文落盘（tar 流直接进加密器）。
"""
from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Callable, Optional

from . import container

MANIFEST_NAME = ".aes256_manifest.json"


def _iter_files(folder: Path, follow_symlinks: bool = False):
    for root, dirs, files in os.walk(folder, followlinks=follow_symlinks):
        rootp = Path(root)
        # 跳过运行数据目录与密钥文件，避免把密钥也打进去
        dirs[:] = [d for d in dirs if d not in ("aes_log", "__pycache__", ".git")]
        for name in files:
            p = rootp / name
            if p.suffix.lower() in (".key",) or name.endswith(".aes256"):
                continue
            yield p


def _make_tar(folder: Path, tar_path: Path, follow_symlinks: bool = False) -> int:
    """把目录树打成 tar（未压缩，压缩由外层完成）。返回文件数。"""
    n = 0
    with tarfile.open(tar_path, "w") as tar:
        for p in _iter_files(folder, follow_symlinks):
            arc = p.relative_to(folder)
            tar.add(str(p), arcname=str(arc))
            n += 1
    return n


def encrypt_folder(folder: str | Path, dst: str | Path, master: bytes,
                   chunk_size: int = container.DEFAULT_CHUNK,
                   progress: Optional[Callable[[int, int], None]] = None,
                   cancel: Optional[Callable[[], bool]] = None,
                   work_dir: Path | None = None) -> dict:
    """把文件夹加密成单个 .aes256 容器。

    中间 tar 写入临时目录，加密完成后删除；全程无明文外泄。
    """
    folder, dst = Path(folder), Path(dst)
    if not folder.is_dir():
        raise NotADirectoryError(f"不是目录：{folder}")
    import tempfile

    tmpdir = Path(tempfile.mkdtemp(dir=str(work_dir) if work_dir else None))
    tar_path = tmpdir / "payload.tar"
    try:
        n = _make_tar(folder, tar_path)
        r = container.encrypt_stream(tar_path, dst, master, chunk_size=chunk_size,
                                     progress=progress, cancel=cancel)
        r.update({"files": n, "folder": str(folder), "kind": "folder"})
        return r
    finally:
        try:
            tar_path.unlink(missing_ok=True)
            tmpdir.rmdir()
        except OSError:
            pass


def decrypt_folder(src: str | Path, out_dir: str | Path, master: bytes,
                   progress=None, cancel=None, work_dir: Path | None = None) -> dict:
    """解密 .aes256 文件夹容器并解包到 out_dir。"""
    src, out_dir = Path(src), Path(out_dir)
    import tempfile

    tmpdir = Path(tempfile.mkdtemp(dir=str(work_dir) if work_dir else None))
    tar_path = tmpdir / "payload.tar"
    try:
        r = container.decrypt_stream(src, tar_path, master,
                                     progress=progress, cancel=cancel)
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        with tarfile.open(tar_path, "r") as tar:
            for member in tar.getmembers():
                # 防目录穿越：拒绝绝对路径与 ../
                if member.name.startswith(("/", "\\")) or ".." in Path(member.name).parts:
                    continue
                tar.extract(member, path=str(out_dir))
                count += 1
        r.update({"out_dir": str(out_dir), "files": count, "kind": "folder"})
        return r
    finally:
        try:
            tar_path.unlink(missing_ok=True)
            tmpdir.rmdir()
        except OSError:
            pass


def peek_kind(src: str | Path) -> str:
    """判断容器里装的是单文件还是文件夹（读头部记录的原始文件名）。"""
    meta = container.read_meta(src)
    name = meta.get("name", "")
    return "folder" if name.endswith(".tar") else "file"
