#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scripts/gen_docs.py — 从 app/core 的 docstring 生成 API 参考片段。

轻量级：遍历模块，抽取公共函数签名与其 docstring 首行，输出 markdown。
无需 sphinx，保证离线可用。
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 API 文档")
    ap.add_argument("--out", default="docs/API_GENERATED.md")
    args = ap.parse_args()

    import app.core as core

    lines = ["# app.core API（自动生成）", ""]
    for modinfo in pkgutil.iter_modules(core.__path__):
        name = f"app.core.{modinfo.name}"
        try:
            mod = importlib.import_module(name)
        except Exception as e:                      # pragma: no cover
            lines.append(f"## {name}\n\n（导入失败: {e}）\n")
            continue
        lines.append(f"## {name}")
        lines.append("")
        for fname, obj in sorted(vars(mod).items()):
            if fname.startswith("_"):
                continue
            if inspect.isfunction(obj) and obj.__module__ == name:
                try:
                    sig = str(inspect.signature(obj))
                except (TypeError, ValueError):
                    sig = "(...)"
                doc = (inspect.getdoc(obj) or "").split("\n")[0]
                lines.append(f"- `{fname}{sig}` — {doc}")
        lines.append("")

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"已生成: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
