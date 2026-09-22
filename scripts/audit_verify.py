#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/audit_verify.py — 审计日志哈希链校验。

operation.log 每条记录含 prev_hash 与 hash，形成链式结构。
本脚本重算整条链，一旦发现断点即定位到具体行，用于发现篡改或删除。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import audit  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="审计日志哈希链校验")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    ok, msg = audit.verify()
    if args.json:
        import json
        print(json.dumps({"ok": ok, "message": msg}, ensure_ascii=False))
    else:
        print("[OK]  " + msg if ok else "[FAIL] " + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
