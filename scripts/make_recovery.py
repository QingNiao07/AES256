#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/make_recovery.py — 生成密钥恢复码。

恢复码用于主密码遗忘时的补救：34 字节熵编码为 55 个 base32 字符，
按 11 组 × 5 字符展示，便于人工抄写。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import make_recovery_code, vault  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="生成密钥恢复码")
    ap.add_argument("--password", help="主密码（省略则交互输入）")
    ap.add_argument("--out", help="同时写入该文件")
    args = ap.parse_args()

    pw = args.password
    if pw is None:
        from getpass import getpass
        pw = getpass("主密码: ")
    master = vault.derive_master(pw)
    code = make_recovery_code(master)

    groups = [code[i:i + 5] for i in range(0, len(code), 5)]
    print("=== 恢复码（请离线抄写并妥善保管）===")
    for i in range(0, len(groups), 5):
        print("  " + "  ".join(groups[i:i + 5]))
    print(f"\n共 {len(code)} 字符 / {len(groups)} 组")

    if args.out:
        Path(args.out).write_text(code, encoding="utf-8")
        print(f"已写入 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
