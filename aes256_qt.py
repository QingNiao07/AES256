# -*- coding: utf-8 -*-
"""
aes256_qt.py
============
PySide6 版本入口（主程序）。

保留原路径，方便打包脚本与文档不改动。
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("[错误] 未安装 PySide6。请执行：pip install PySide6", file=sys.stderr)
        print("        或改用 Tkinter 版本：python aes256_tool.py", file=sys.stderr)
        return 2

    from app import config as cfgmod
    from app import i18n, legal
    from app.core import audit, db_init, netguard

    db_init()
    cfg = cfgmod.load()
    theme = cfg["ui"]["theme"]

    # 中英双语：按配置初始化
    i18n.set_language(cfgmod.get_language())

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("AES256Tool")
    app.setOrganizationName("AES256Tool")

    # 首次运行闸门：必须本人勾选「我接受」才能继续使用
    if legal.needs_acceptance():
        from app.ui.qt.legal_dialog import LegalDialog

        if LegalDialog.ask(install=False):
            legal.accept()
            audit.append("legal", "accept", "首次运行接受法务条款")
        else:
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.warning(None, i18n.tr("legal.title"),
                                i18n.tr("legal.decline") + "\n程序即将退出。")
            return 4

    # 离线安全：默认开启网络守卫，拦截一切外发连接
    if cfg.get("ai", {}).get("offline", True):
        netguard.enable(allow_loopback=True)
        audit.append("info", "netguard", "离线守卫已启用")

    # 允许在创建控件前预置主题
    if theme in ("light", "dark"):
        from PySide6.QtWidgets import QApplication as _QApp  # noqa: F401

    from app.ui.qt.main_window import MainWindow

    win = MainWindow()
    if theme in ("light", "dark"):
        win.theme.set_mode(theme)
    win.show()

    audit.append("info", "start", "PySide6 版本启动")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
