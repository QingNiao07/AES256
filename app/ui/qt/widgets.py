# -*- coding: utf-8 -*-
"""
app/ui/qt/widgets.py
====================
可复用小部件：密码输入框（带强度条）、拖拽区、任务表格。
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QProgressBar, QPushButton, QVBoxLayout, QWidget)

from ...core import policy
from ..theme import palette

LEVEL_COLORS = {0: "#c62828", 1: "#ed6c02", 2: "#f9a825", 3: "#2e7d32", 4: "#1b5e20"}
LEVEL_LABELS = {0: "极弱", 1: "弱", 2: "中等", 3: "强", 4: "极强"}


class PasswordField(QWidget):
    """密码框 + 强度条 + 破解时间估算。"""

    changed = Signal(str)

    def __init__(self, placeholder: str = "请输入密码", show_meter: bool = True, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        row = QHBoxLayout()
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.textChanged.connect(self._on_change)
        row.addWidget(self.edit, 1)

        self.eye = QPushButton("👁")
        self.eye.setCheckable(True)
        self.eye.setFixedWidth(36)
        self.eye.setToolTip("显示/隐藏密码")
        self.eye.toggled.connect(
            lambda on: self.edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        row.addWidget(self.eye)
        lay.addLayout(row)

        self.meter = QProgressBar()
        self.meter.setRange(0, 100)
        self.meter.setTextVisible(False)
        self.meter.setFixedHeight(6)
        self.label = QLabel("")
        self.label.setFont(QFont(self.font().family(), 8))
        if show_meter:
            lay.addWidget(self.meter)
            lay.addWidget(self.label)
        else:
            self.meter.hide()
            self.label.hide()

    def _on_change(self, text: str):
        self.changed.emit(text)
        if not self.meter.isVisible():
            return
        level, desc = policy.password_strength(text)
        bits = policy.entropy_bits(text)
        self.meter.setValue(min(100, int(bits * 100 / 100)))
        color = LEVEL_COLORS.get(level, "#888")
        self.meter.setStyleSheet(
            f"QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}")
        if text:
            secs = policy.crack_seconds(text)
            self.label.setText(f"{LEVEL_LABELS.get(level, '?')} · {bits:.0f} bits · "
                               f"离线破解约 {policy.humanize_seconds(secs)}")
        else:
            self.label.setText("")

    def text(self) -> str:
        return self.edit.text()

    def clear(self):
        self.edit.clear()


class DropArea(QPlainTextEdit):
    """接受文件拖拽的文本域。"""

    files_dropped = Signal(list)

    def __init__(self, hint: str = "把文件拖到这里，或点击下方按钮选择", parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText(hint)
        self.setAcceptDrops(True)
        self.setMaximumHeight(90)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class JobRowWidget(QWidget):
    """单条任务行：名称 + 进度 + 取消。"""

    cancel_requested = Signal(str)

    def __init__(self, job_id: str, name: str, parent=None):
        super().__init__(parent)
        self.job_id = job_id
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 2, 4, 2)
        self.name = QLabel(name)
        self.name.setMinimumWidth(280)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setFixedHeight(14)
        self.state = QLabel("等待")
        self.state.setFixedWidth(64)
        self.btn = QPushButton("取消")
        self.btn.setFixedWidth(56)
        self.btn.clicked.connect(lambda: self.cancel_requested.emit(self.job_id))
        lay.addWidget(self.name, 1)
        lay.addWidget(self.bar, 2)
        lay.addWidget(self.state)
        lay.addWidget(self.btn)

    def update_state(self, state: str, percent: int | None = None):
        self.state.setText({
            "pending": "等待", "running": "进行中", "done": "完成",
            "failed": "失败", "cancelled": "已取消",
        }.get(state, state))
        if percent is not None:
            self.bar.setValue(percent)
        if state in ("done", "failed", "cancelled"):
            self.btn.setEnabled(False)
        if state == "done":
            self.bar.setValue(100)
