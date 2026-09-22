#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/rotate_password.py — 批量更换密码（重加密）。

遍历目录内的 .aes256 密文，用旧密码解密后以新密码重新加密，支持 --dry-run
预演与断点续跑（已处理成功的文件写入 .rotate_done 清单后跳过）。
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import container  # noqa: E402

DONE_FILE = ".rotate_done"


def main() -> int:
    ap = argparse.ArgumentParser(description="批量更换加密密码")
    ap.add_argument("directory", help="包含密文的目录")
    ap.add_argument("--suffix", default=".aes256", help="密文后缀")
    ap.add_argument("--dry-run", action="store_true", help="只列出将处理的文件")
    args = ap.parse_args()

    from getpass import getpass
    d = Path(args.directory).expanduser().resolve()
    if not d.is_dir():
        print(f"目录不存在: {d}")
        return 2

    targets = sorted(p for p in d.rglob(f"*{args.suffix}") if p.is_file())
    print(f"发现 {len(targets)} 个密文")
    if args.dry_run:
        for p in targets:
            print("  将处理:", p.relative_to(d))
        return 0
    if not targets:
        return 0

    old_pw = getpass("旧密码: ")
    new_pw = getpass("新密码: ")
    again = getpass("确认新密码: ")
    if new_pw != again:
        print("两次新密码不一致")
        return 2

    done_path = d / DONE_FILE
    done = set(done_path.read_text(encoding="utf-8").splitlines()) if done_path.exists() else set()

    ok = fail = skip = 0
    for p in targets:
        rel = str(p.relative_to(d))
        if rel in done:
            skip += 1
            continue
        fd, tmp_name = tempfile.mkstemp(dir=str(p.parent), suffix=".plain")
        import os
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            container.decrypt_stream_password(str(p), str(tmp), old_pw)
            container.encrypt_stream_password(str(tmp), str(p), new_pw)
            done.add(rel)
            done_path.write_text("\n".join(sorted(done)), encoding="utf-8")
            ok += 1
            print(f"  [OK] {rel}")
        except Exception as e:
            fail += 1
            print(f"  [FAIL] {rel}: {e}")
        finally:
            tmp.unlink(missing_ok=True)
    print(f"\n完成: 成功 {ok} / 跳过 {skip} / 失败 {fail}")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
