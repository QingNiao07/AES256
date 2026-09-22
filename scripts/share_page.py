#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/share_page.py — 生成自解密分享页（HTML）。

把密文嵌入单个 HTML，接收方在浏览器输入密码即可本地解密下载，
明文不经过任何服务器。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import share  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="生成自解密分享页")
    ap.add_argument("input", help="待加密的源文件")
    ap.add_argument("output", help="输出的 .html 路径")
    ap.add_argument("--password", help="密码（省略则交互输入）")
    ap.add_argument("--title", default="加密分享", help="页面标题")
    args = ap.parse_args()

    pw = args.password
    if pw is None:
        from getpass import getpass
        pw = getpass("密码: ")

    src = Path(args.input).expanduser().resolve()
    if not src.is_file():
        print(f"文件不存在: {src}")
        return 2

    out = Path(args.output).expanduser().resolve()
    share.write_share_page(src.read_bytes(), pw, out, title=args.title)
    print(f"已生成分享页: {out}  ({out.stat().st_size} B)")
    print("把该 HTML 发给接收方，对方在浏览器输入密码即可解密。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
