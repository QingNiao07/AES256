#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/build_exe.py — PyInstaller 一键打包。

生成两个可执行文件：GUI（aes256-qt）与 CLI（aes256-cli）。
未安装 PyInstaller 时给出安装提示而不报错。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _have_pyinstaller() -> bool:
    return shutil.which("pyinstaller") is not None


def main() -> int:
    ap = argparse.ArgumentParser(description="打包 exe")
    ap.add_argument("--cli-only", action="store_true", help="只打包命令行版本")
    ap.add_argument("--gui-only", action="store_true", help="只打包 GUI 版本")
    args = ap.parse_args()

    if not _have_pyinstaller():
        print("未检测到 PyInstaller。请先安装：pip install pyinstaller")
        return 2

    dist = ROOT / "dist"
    jobs = []
    if not args.cli_only:
        jobs.append(["pyinstaller", "--noconfirm", "--noconsole", "--onefile",
                     "--name", "aes256-qt", str(ROOT / "aes256_qt.py")])
    if not args.gui_only:
        jobs.append(["pyinstaller", "--noconfirm", "--onefile",
                     "--name", "aes256-cli", str(ROOT / "cli.py")])

    rc = 0
    for cmd in jobs:
        print("$", " ".join(cmd))
        r = subprocess.run(cmd, cwd=str(ROOT))
        rc |= r.returncode
    print(f"产物目录: {dist}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
