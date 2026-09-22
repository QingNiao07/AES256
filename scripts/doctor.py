#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/doctor.py — 环境自检 / 一键诊断。

检查 Python 版本、依赖可用性、Argon2 是否启用、配置是否合法、
安全参数是否可接受，并给出修复建议。
"""
from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:  # pragma: no cover
        ok, detail = False, f"{type(e).__name__}: {e}"
    mark = "OK  " if ok else "WARN"
    print(f"[{mark}] {name:<28} {detail}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="AES-256 工具箱环境自检")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    results = {}

    def py_ver():
        v = sys.version_info
        return v >= (3, 9), f"{platform.python_version()}"

    def dep(mod, label):
        def f():
            try:
                __import__(mod)
                return True, "已安装"
            except Exception:
                return False, "缺失（可选）"
        return f

    def argon2_on():
        from app.core import kdf
        return kdf.ARGON2_AVAILABLE, kdf.kdf_name()

    def cfg_ok():
        from app import config
        cfg = config.load(ROOT)
        return True, f"version={cfg.get('version')}"

    def sec_ok():
        from app.core.settings import load_params
        p = load_params(ROOT)
        errs = p.validate()
        return (not errs), (p.describe() if not errs else "; ".join(errs))

    print("=== AES-256 工具箱 · 环境自检 ===")
    results["python"] = _check("Python >= 3.9", py_ver)
    results["cryptography"] = _check("cryptography", dep("cryptography", ""))
    results["argon2"] = _check("Argon2id 可用", argon2_on)
    results["requests"] = _check("requests", dep("requests", ""))
    results["pyside6"] = _check("PySide6", dep("PySide6", ""))
    results["config"] = _check("config.json 可读", cfg_ok)
    results["security"] = _check("安全参数合法", sec_ok)

    if args.json:
        import json
        print(json.dumps(results, ensure_ascii=False, indent=2))

    hard_fail = not results["python"] or not results["config"] or not results["security"]
    print("\n结论:", "存在必须修复项" if hard_fail else "环境可用")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
