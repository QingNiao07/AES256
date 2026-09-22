#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/verify_all.py — 批量密文完整性校验。

扫描目录内所有 .aes256，用给定密码解密并校验 GCM 认证标签与容器尾部 HMAC；
报告每个文件是「完好」「密码错误」还是「被篡改」。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import container  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="批量校验密文完整性")
    ap.add_argument("directory", help="包含密文的目录")
    ap.add_argument("--suffix", default=".aes256")
    ap.add_argument("--password", help="密码（省略则交互输入）")
    args = ap.parse_args()

    d = Path(args.directory).expanduser().resolve()
    if not d.is_dir():
        print(f"目录不存在: {d}")
        return 2
    files = sorted(p for p in d.rglob(f"*{args.suffix}") if p.is_file())
    print(f"发现 {len(files)} 个密文")

    pw = args.password
    if pw is None:
        from getpass import getpass
        pw = getpass("密码: ")

    ok = bad = 0
    for p in files:
        try:
            meta = container.read_meta(str(p))
            # dst=None：仅校验，不落盘明文
            container.decrypt_stream_password(str(p), None, pw)
            ok += 1
            print(f"  [OK]     {p.name}  ({meta.get('orig_size', '?')} B)")
        except Exception as e:
            bad += 1
            print(f"  [BAD]    {p.name}: {e}")
    print(f"\n完好 {ok} / 异常 {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
