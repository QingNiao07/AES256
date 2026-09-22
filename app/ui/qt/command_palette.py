# -*- coding: utf-8 -*-
"""
app/ui/qt/command_palette.py
============================
命令面板（Ctrl+Shift+P）：模糊搜索并执行注册的命令。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QVBoxLayout)


@dataclass
class Command:
    title: str
    shortcut: str
    handler: Callable[[], None]
    keywords: str = ""


class CommandPalette(QDialog):
    def __init__(self, commands: list[Command], parent=None):
        super().__init__(parent)
        self.setWindowTitle("命令面板")
        self.setModal(True)
        self.resize(520, 380)
        self._commands = commands

        lay = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("输入命令名称…（↑↓ 选择，Enter 执行，Esc 关闭）")
        self.search.textChanged.connect(self._refilter)
        self.search.returnPressed.connect(self._run_current)
        lay.addWidget(self.search)

        self.list = QListWidget()
        self.list.itemActivated.connect(lambda _: self._run_current())
        lay.addWidget(self.list)

        tip = QLabel(f"共 {len(commands)} 条命令")
        tip.setStyleSheet("color: #888;")
        lay.addWidget(tip)

        self._refilter("")
        self.search.setFocus()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Down, Qt.Key_Up):
            self.list.keyPressEvent(event)
            return
        if event.key() == Qt.Key_Escape:
            self.reject()
            return
        super().keyPressEvent(event)

    def _refilter(self, text: str):
        text = text.strip().lower()
        self.list.clear()
        for cmd in self._commands:
            hay = f"{cmd.title} {cmd.keywords} {cmd.shortcut}".lower()
            if not text or self._fuzzy(text, hay):
                label = f"{cmd.title}"
                if cmd.shortcut:
                    label += f"    [{cmd.shortcut}]"
                item = QListWidgetItem(label)
                item.setData(Qt.UserRole, cmd)
                self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    @staticmethod
    def _fuzzy(needle: str, hay: str) -> bool:
        if needle in hay:
            return True
        it = iter(hay)
        return all(ch in it for ch in needle)

    def _run_current(self):
        item = self.list.currentItem()
        if not item:
            return
        cmd: Command = item.data(Qt.UserRole)
        self.accept()
        try:
            cmd.handler()
        except Exception:
            pass
