#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/run_tests.py — 一键跑全部测试 + 语法编译检查。"""
from __future__ import annotations

import argparse
import compileall
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser(description="运行测试与编译检查")
    ap.add_argument("--no-tests", action="store_true")
    ap.add_argument("--no-compile", action="store_true")
    args = ap.parse_args()

    rc = 0
    if not args.no_compile:
        print("=== compileall ===")
        ok = compileall.compile_dir(str(ROOT / "app"), quiet=1)
        ok = compileall.compile_file(str(ROOT / "cli.py"), quiet=1) and ok
        print("编译:", "通过" if ok else "失败")
        rc |= 0 if ok else 1

    if not args.no_tests:
        print("=== pytest ===")
        r = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=str(ROOT))
        rc |= r.returncode
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
