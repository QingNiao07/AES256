# -*- coding: utf-8 -*-
"""
app/ui/qt/help_viewer.py
========================
帮助查看器（F1）：渲染 使用说明书.md，附快捷键表与安全提示。

这是原文档第 4 项缺失内容的另一部分。
"""
from __future__ import annotations

from PySide6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

from ...paths import resource_dir

MANUAL_CANDIDATES = ("使用说明书.md", "README.txt", "一分钟上手指南.md")

SHORTCUTS = """
## 快捷键

| 快捷键 | 功能 |
|---|---|
| F1 | 打开本使用说明 |
| Ctrl+Shift+P | 命令面板 |
| Ctrl+Shift+A | AI 助手面板 |
| Ctrl+Shift+T | 切换深色 / 浅色主题 |
| Ctrl+O | 选择文件加密 |
| Ctrl+Shift+O | 选择文件解密 |
| Ctrl+L | 立即锁定（清空内存密钥） |
| Esc | 关闭当前对话框 |
"""

SAFETY = """
## 安全要点

- 密码与密钥文件同时丢失 → 数据永久无法恢复，本工具**不提供**任何后门。
- 首次使用请**不要**勾选「加密后删除原文件」，先验证能解密再考虑开启。
- 密钥文件不要与密文放在同一磁盘、同一目录。
- 建议导出密钥文件后同时抄写一份**恢复码**，抗介质损坏。
- 开启 AI 助手联网前，请确认你接受把脱敏后的提问发送到云端。
"""


class HelpViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("使用说明")
        lay = QVBoxLayout(self)
        self.view = QTextBrowser()
        self.view.setOpenExternalLinks(True)
        lay.addWidget(self.view)
        self.reload()

    def reload(self):
        parts = [self._read_manual(), SHORTCUTS, SAFETY]
        self.view.setMarkdown("\n\n".join(p for p in parts if p))

    def _read_manual(self) -> str:
        for name in MANUAL_CANDIDATES:
            p = resource_dir() / name
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8")
                    return f"# {name}\n\n{text}" if name.endswith(".txt") else text
                except Exception:
                    continue
        return "# 使用说明\n\n（未找到说明书文件，请确认 使用说明书.md 与程序在同一目录）"
