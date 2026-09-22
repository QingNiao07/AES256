#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/benchmark.py — 密钥派生性能基准。

实测本机各档安全参数的派生耗时，并给出推荐参数（落在 0.3~1.0 秒）。
用户可据此在「速度」与「抗暴力破解强度」之间取舍。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core.security import PRESETS, calibrate, preset_names  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="KDF 性能基准与参数推荐")
    ap.add_argument("--measure", action="store_true", help="实测各预设耗时")
    ap.add_argument("--calibrate", action="store_true", help="按本机性能推荐参数")
    ap.add_argument("--max-memory-mib", type=int, default=256, help="校准内存上限")
    ap.add_argument("--save", action="store_true", help="把校准结果写入 config.json")
    args = ap.parse_args()

    if not args.measure and not args.calibrate:
        args.measure = args.calibrate = True

    if args.measure:
        from app.core.security import _measure
        print("=== 各预设实测耗时 ===")
        for name in preset_names():
            p = PRESETS[name]
            dt = _measure(p)
            print(f"  {name:<9} {p.describe():<40} {dt*1000:7.1f} ms")

    if args.calibrate:
        print("\n=== 本机推荐参数 ===")
        p, dt = calibrate(max_memory_kib=args.max_memory_mib * 1024)
        print(f"  推荐: {p.describe()}  实测 {dt*1000:.1f} ms")
        if args.save:
            from app.core.settings import save_params
            save_params(p, ROOT)
            print("  已写入 config.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
