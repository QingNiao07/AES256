# -*- coding: utf-8 -*-
"""
app/ui/theme.py
===============
主题键位表 + 调色板 + QSS + 系统深色探测。

这是原文档第 3 项被截断处的完整补全：
LIGHT 补上 status_bg 之后的所有键，DARK 完整给出，
apply() 只在主题真正变化时重设样式表（避免 auto 模式每 2.5s 重刷卡顿），
并实现 Windows 注册表 / macOS defaults 的系统主题探测。
"""
from __future__ import annotations

import sys

LIGHT = {
    "bg": "#f5f7fa", "fg": "#1a1a1a",
    "panel_bg": "#ffffff", "panel_fg": "#333333",
    "accent": "#1976d2", "accent_fg": "#ffffff",
    "success": "#2e7d32", "warning": "#ed6c02", "danger": "#c62828",
    "status_bg": "#e8eef7", "status_fg": "#33506f",
    "border": "#d8dee9", "entry_bg": "#ffffff", "entry_fg": "#1a1a1a",
    "selection": "#cfe3ff", "log_bg": "#fbfcfe", "reason_bg": "#f3f6fb",
}

DARK = {
    "bg": "#1e2228", "fg": "#e6e6e6",
    "panel_bg": "#262b33", "panel_fg": "#d5d8dd",
    "accent": "#4d9fff", "accent_fg": "#0b1220",
    "success": "#81c995", "warning": "#ffb74d", "danger": "#ef6c6c",
    "status_bg": "#2c333d", "status_fg": "#c2cad6",
    "border": "#3a424d", "entry_bg": "#2b3138", "entry_fg": "#eaeaea",
    "selection": "#2f4a6f", "log_bg": "#20242a", "reason_bg": "#232830",
}

PALETTES = {"light": LIGHT, "dark": DARK}
MODES = ("light", "dark", "auto")


def palette(name: str) -> dict:
    return dict(PALETTES.get(name, LIGHT))


# ============================================================
# 系统主题探测
# ============================================================
def detect_system() -> str:
    if sys.platform.startswith("win"):
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            ) as key:
                light, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return "light" if light else "dark"
        except Exception:
            return "light"
    if sys.platform == "darwin":
        try:
            import subprocess

            out = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                                 capture_output=True, text=True, timeout=2)
            return "dark" if "Dark" in out.stdout else "light"
        except Exception:
            return "light"
    # Linux：优先 GTK/环境变量提示
    import os

    if os.environ.get("AES256_THEME") in ("light", "dark"):
        return os.environ["AES256_THEME"]
    return "light"


def build_qss(name: str) -> str:
    c = palette(name)
    return f"""
QWidget {{ background: {c['bg']}; color: {c['fg']};
           font-family: "Microsoft YaHei UI", "Microsoft YaHei", sans-serif; }}
QMainWindow, QDialog {{ background: {c['bg']}; }}
QGroupBox {{ background: {c['panel_bg']}; border: 1px solid {c['border']};
             border-radius: 8px; margin-top: 12px; padding: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px;
                    color: {c['accent']}; }}
QPushButton {{ background: {c['panel_bg']}; color: {c['panel_fg']};
               border: 1px solid {c['border']}; border-radius: 6px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {c['accent']}; color: {c['accent']}; }}
QPushButton:pressed {{ background: {c['accent']}; color: {c['accent_fg']}; }}
QPushButton:disabled {{ color: {c['border']}; }}
QPushButton#primary {{ background: {c['accent']}; color: {c['accent_fg']};
                       border: none; font-weight: 600; }}
QPushButton#primary:disabled {{ background: {c['border']}; }}
QLineEdit, QPlainTextEdit, QTextEdit, QTextBrowser, QListWidget, QTableWidget {{
    background: {c['entry_bg']}; color: {c['entry_fg']};
    border: 1px solid {c['border']}; border-radius: 6px;
    selection-background-color: {c['selection']}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {c['accent']}; }}
QStatusBar {{ background: {c['status_bg']}; color: {c['status_fg']}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 5px;
                               min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {c['accent']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QTabBar::tab {{ background: {c['panel_bg']}; color: {c['panel_fg']};
                padding: 6px 14px; border: 1px solid {c['border']}; border-bottom: none;
                border-top-left-radius: 6px; border-top-right-radius: 6px; }}
QTabBar::tab:selected {{ color: {c['accent']}; border-bottom: 2px solid {c['accent']}; }}
QCheckBox, QRadioButton, QLabel {{ background: transparent; }}
QToolTip {{ background: {c['panel_bg']}; color: {c['panel_fg']};
            border: 1px solid {c['border']}; }}
QProgressBar {{ border: 1px solid {c['border']}; border-radius: 6px; text-align: center;
                background: {c['panel_bg']}; color: {c['fg']}; }}
QProgressBar::chunk {{ background: {c['accent']}; border-radius: 5px; }}
QMenuBar, QMenu {{ background: {c['panel_bg']}; color: {c['panel_fg']}; }}
QMenu::item:selected {{ background: {c['accent']}; color: {c['accent_fg']}; }}

/* ---------- 现代化卡片与控件（v1.1） ---------- */
QLabel#hint {{ color: {c['status_fg']}; padding: 2px 4px; }}
QLabel#card, QFrame#card, QGroupBox#card {{
    background: {c['panel_bg']}; border: 1px solid {c['border']};
    border-radius: 10px; padding: 10px 12px; }}
QLabel#hint_card {{
    background: {c['reason_bg']}; border: 1px dashed {c['border']};
    border-radius: 10px; padding: 10px 12px; color: {c['status_fg']}; }}
QFrame#card:hover {{ border-color: {c['accent']}; }}
QListWidget {{ padding: 4px; outline: none; }}
QListWidget::item {{ border-radius: 6px; padding: 6px 8px; }}
QListWidget::item:selected {{ background: {c['selection']}; color: {c['fg']}; }}
QListWidget::item:hover {{ background: {c['reason_bg']}; }}
QPushButton {{ padding: 7px 16px; }}
QPushButton#pill {{
    border-radius: 14px; padding: 5px 14px; background: {c['reason_bg']}; }}
QPushButton#pill:hover {{ background: {c['accent']}; color: {c['accent_fg']}; }}
QPushButton#ghost {{ background: transparent; border: none; color: {c['accent']}; }}
QPushButton#ghost:hover {{ text-decoration: underline; }}
QToolButton {{ border: none; border-radius: 6px; padding: 4px; }}
QToolButton:hover {{ background: {c['reason_bg']}; }}
QHeaderView::section {{
    background: {c['panel_bg']}; color: {c['panel_fg']};
    border: none; border-bottom: 1px solid {c['border']}; padding: 6px; }}
QTableWidget {{ gridline-color: {c['border']}; }}
QDialogButtonBox QPushButton {{ min-width: 76px; }}
QProgressBar {{ height: 8px; }}
QSplitter::handle {{ background: {c['border']}; }}
QDockWidget::title {{ background: {c['status_bg']}; color: {c['status_fg']};
                       padding: 6px; }}
"""


# ============================================================
# Qt 主题管理器
# ============================================================
try:
    from PySide6.QtCore import QObject, QSettings, QTimer, Signal
    from PySide6.QtGui import QColor, QPalette

    _QT = True
except Exception:                          # pragma: no cover
    _QT = False


if _QT:

    class ThemeManager(QObject):
        theme_changed = Signal(str)        # 实际生效："light" | "dark"

        def __init__(self, app, parent=None, poll_ms: int = 2500):
            super().__init__(parent)
            self._app = app
            self._settings = QSettings("AES256Tool", "AES256Tool")
            mode = self._settings.value("ui/theme", "auto")
            self._mode = mode if mode in MODES else "auto"
            self._last = ""
            self._watch = QTimer(self)
            self._watch.setInterval(poll_ms)
            self._watch.timeout.connect(self._poll_system)
            self._watch.start()

        # ---------- 查询 ----------
        @property
        def mode(self) -> str:
            return self._mode

        def current(self) -> str:
            return detect_system() if self._mode == "auto" else self._mode

        def palette(self, name: str | None = None) -> dict:
            return palette(name or self.current())

        def color(self, key: str) -> "QColor":
            return QColor(self.palette()[key])

        # ---------- 切换 ----------
        def set_mode(self, mode: str, persist: bool = True) -> None:
            if mode not in MODES:
                return
            self._mode = mode
            if persist:
                self._settings.setValue("ui/theme", mode)
            self.apply(force=True)

        def toggle(self) -> None:
            self.set_mode("light" if self.current() == "dark" else "dark")

        def _poll_system(self) -> None:
            if self._mode == "auto":
                self.apply()

        # ---------- 应用 ----------
        def apply(self, force: bool = False) -> None:
            name = self.current()
            if name == self._last and not force:
                return
            self._last = name
            self._app.setPalette(self._build_palette(name))
            self._app.setStyleSheet(build_qss(name))
            self.theme_changed.emit(name)

        def _build_palette(self, name: str) -> "QPalette":
            c = palette(name)
            p = QPalette()
            p.setColor(QPalette.Window, QColor(c["bg"]))
            p.setColor(QPalette.WindowText, QColor(c["fg"]))
            p.setColor(QPalette.Base, QColor(c["entry_bg"]))
            p.setColor(QPalette.AlternateBase, QColor(c["panel_bg"]))
            p.setColor(QPalette.Text, QColor(c["entry_fg"]))
            p.setColor(QPalette.Button, QColor(c["panel_bg"]))
            p.setColor(QPalette.ButtonText, QColor(c["panel_fg"]))
            p.setColor(QPalette.Highlight, QColor(c["accent"]))
            p.setColor(QPalette.HighlightedText, QColor(c["accent_fg"]))
            p.setColor(QPalette.ToolTipBase, QColor(c["panel_bg"]))
            p.setColor(QPalette.ToolTipText, QColor(c["panel_fg"]))
            p.setColor(QPalette.Link, QColor(c["accent"]))
            p.setColor(QPalette.Disabled, QPalette.Text, QColor(c["border"]))
            p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(c["border"]))
            return p

else:                                       # 无 PySide6 时提供哑元，保证可 import

    class ThemeManager:                     # type: ignore
        def __init__(self, *a, **k):
            self._mode = "auto"

        @property
        def mode(self):
            return self._mode

        def current(self):
            return detect_system()

        def palette(self, name=None):
            return palette(name)

        def set_mode(self, mode, persist=True):
            self._mode = mode

        def toggle(self):
            pass

        def apply(self, force=False):
            pass
