# -*- coding: utf-8 -*-
"""
aes256_tool.py
==============
Tkinter 版本入口（主程序）。

保留原路径。无第三方 GUI 依赖即可启动，便于在受限环境分发。
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("[错误] 当前 Python 未包含 tkinter。", file=sys.stderr)
        print("        Windows 请重装 Python 并勾选 tcl/tk；Linux 安装 python3-tk。",
              file=sys.stderr)
        return 2

    from app import config as cfgmod
    from app import i18n, legal
    from app.core import audit, db_init, netguard

    db_init()
    cfg = cfgmod.load()
    i18n.set_language(cfgmod.get_language())

    # 首次运行闸门：必须本人勾选「我接受」才能继续使用
    if legal.needs_acceptance():
        from app.ui.tk.legal_tk import ask_legal

        if ask_legal(install=False):
            legal.accept()
            audit.append("legal", "accept", "首次运行接受法务条款")
        else:
            print("未接受法律声明与免责协议，程序退出。", file=sys.stderr)
            return 4

    if cfg.get("ai", {}).get("offline", True):
        netguard.enable(allow_loopback=True)
        audit.append("info", "netguard", "离线守卫已启用")
    from app.ui.tk.main_tk import TkApp

    audit.append("info", "start", "Tkinter 版本启动")
    TkApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
