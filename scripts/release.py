#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/release.py — 发版：打标签并生成校验清单。

不做任何网络推送；只在本地创建 git tag（可选）并写出 SHA256SUMS
与版本信息，供人工上传发布。
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="生成发布校验清单")
    ap.add_argument("--tag", help="git 标签名（如 v1.1.0）；给出则创建本地 tag")
    ap.add_argument("--dir", default="dist", help="产物目录")
    args = ap.parse_args()

    d = ROOT / args.dir
    files = sorted(p for p in d.glob("*") if p.is_file()) if d.is_dir() else []
    lines = []
    for p in files:
        lines.append(f"{sha256(p)}  {p.name}")
    sums = ROOT / "SHA256SUMS"
    sums.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    print(f"已写入 {sums}（{len(files)} 个文件）")

    if args.tag:
        r = subprocess.run(["git", "tag", "-a", args.tag, "-m", f"release {args.tag}"],
                           cwd=str(ROOT))
        print("git tag:", "OK" if r.returncode == 0 else "失败（可能已存在或非 git 仓库）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
