# -*- coding: utf-8 -*-
"""
app/ui/qt/ai_panel.py
=====================
AI 助手面板：离线闸门 + 流式输出 + 思考过程折叠 + 脱敏提示。
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QPlainTextEdit,
                               QPushButton, QTextBrowser, QVBoxLayout, QWidget)

from ...services.ai import ChatResult, DeepSeekClient
from ...services.ai.prompts import log_analysis_prompt, system_prompt
from ...services.ai.sanitize import diff_summary


class _AskWorker(QThread):
    chunk_reasoning = Signal(str)
    chunk_content = Signal(str)
    ok = Signal(object)
    failed = Signal(str)

    def __init__(self, client: DeepSeekClient, messages: list, thinking: bool, parent=None):
        super().__init__(parent)
        self.client, self.messages, self.thinking = client, messages, thinking

    def run(self):
        try:
            result = self.client.chat(
                self.messages, thinking=self.thinking,
                on_reasoning=self.chunk_reasoning.emit,
                on_content=self.chunk_content.emit)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.ok.emit(result)


class AIPanel(QWidget):
    """右侧可停靠的 AI 助手面板。"""

    def __init__(self, client: DeepSeekClient, pricing: dict | None = None, parent=None):
        super().__init__(parent)
        self.client = client
        self.pricing = pricing or {}
        self.history: list = []                # 只存 content，不存 reasoning_content
        self._worker = None
        self._buf_r = ""
        self._buf_c = ""
        self._prefix = ""
        self._dirty = False
        self.online_box = None
        self._build_ui()

        self._paint = QTimer(self)
        self._paint.setInterval(100)           # 节流重绘，避免逐字 setMarkdown 卡死界面
        self._paint.timeout.connect(self._flush)
        self._paint.start()

    # ---------- UI ----------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        bar = QHBoxLayout()
        self.online_box = QCheckBox("允许联网")
        self.online_box.setToolTip("默认关闭。开启后提问内容将发送到 DeepSeek 服务器。")
        self.online_box.setChecked(not self.client.offline)
        self.online_box.toggled.connect(self._on_toggle_online)
        self.think_box = QCheckBox("思考模式")
        self.think_box.setChecked(True)
        self.model_label = QLabel(self.client.model)
        self.model_label.setToolTip("DeepSeek V4.1 Flash")
        self.clear_btn = QPushButton("清空")
        self.clear_btn.clicked.connect(self.clear)
        bar.addWidget(self.online_box)
        bar.addWidget(self.think_box)
        bar.addStretch(1)
        bar.addWidget(self.model_label)
        bar.addWidget(self.clear_btn)
        root.addLayout(bar)

        self.hint = QLabel("离线模式：不会向任何服务器发送数据。"
                           "加密工具建议长期保持离线，仅在需要时临时开启。")
        self.hint.setWordWrap(True)
        root.addWidget(self.hint)

        self.reason_btn = QPushButton("思考过程 ▾")
        self.reason_btn.setCheckable(True)
        self.reason_btn.toggled.connect(self._toggle_reason)
        root.addWidget(self.reason_btn)

        self.reason_view = QPlainTextEdit(readOnly=True)
        self.reason_view.setMaximumHeight(150)
        self.reason_view.hide()
        root.addWidget(self.reason_view)

        self.output = QTextBrowser()
        self.output.setOpenExternalLinks(True)
        root.addWidget(self.output, 1)

        self.input = QPlainTextEdit()
        self.input.setPlaceholderText("问点什么…（Ctrl+Enter 发送）")
        self.input.setMaximumHeight(96)
        root.addWidget(self.input)

        row = QHBoxLayout()
        self.cost_label = QLabel("")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        self.send_btn = QPushButton("发送")
        self.send_btn.setObjectName("primary")
        self.send_btn.clicked.connect(self._on_send)
        row.addWidget(self.cost_label)
        row.addStretch(1)
        row.addWidget(self.stop_btn)
        row.addWidget(self.send_btn)
        root.addLayout(row)

        QShortcut(QKeySequence("Ctrl+Return"), self.input, activated=self._on_send)

    # ---------- 交互 ----------
    def _on_toggle_online(self, checked: bool):
        self.client.set_offline(not checked)
        self.hint.setVisible(not checked)
        if checked:
            self.hint.setText("已开启联网：提问内容将发送到 DeepSeek 服务器（已做脱敏）。")
            self.hint.setVisible(True)

    def _toggle_reason(self, on: bool):
        self.reason_view.setVisible(on)
        self.reason_btn.setText("思考过程 ▴" if on else "思考过程 ▾")

    def _notice(self, text: str, color: str = "#ed6c02"):
        self.output.append(f'<p style="color:{color}">⚠ {text}</p>')

    def _on_send(self):
        if self._worker and self._worker.isRunning():
            return
        text = self.input.toPlainText().strip()
        if not text:
            return
        if self.client.offline:
            self._notice("离线模式：请先勾选「允许联网」。")
            return
        if not self.client.api_key:
            self._notice("未配置 DeepSeek API Key。")
            return

        info = diff_summary(text)
        if info.get("changed"):
            self._notice("已对本次消息脱敏：路径 / 文件名 / 密文块已替换。")

        self.input.clear()
        self._prefix = f"<p><b>我：</b>{text}</p><p><b>AI：</b></p>"
        self.output.append(self._prefix)
        self._buf_c = ""
        self._buf_r = ""
        self.reason_view.clear()

        messages = ([{"role": "system", "content": system_prompt()}]
                    + self.history + [{"role": "user", "content": text}])
        self._worker = _AskWorker(self.client, messages, self.think_box.isChecked(), self)
        self._worker.chunk_reasoning.connect(self._on_reasoning)
        self._worker.chunk_content.connect(self._on_content)
        self._worker.ok.connect(self._on_ok)
        self._worker.failed.connect(lambda m: self._notice(m, "#c62828"))
        self._worker.finished.connect(self._reset_buttons)
        self.send_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._worker.start()

    def _on_stop(self):
        self.client.cancel()

    def _on_reasoning(self, piece: str):
        self._buf_r += piece
        self._dirty = True

    def _on_content(self, piece: str):
        self._buf_c += piece
        self._dirty = True

    def _flush(self):
        if not self._dirty:
            return
        self._dirty = False
        if self._buf_r:
            self.reason_view.setPlainText(self._buf_r)
        if self._buf_c:
            self.output.setMarkdown(self._prefix + self._buf_c)

    def _on_ok(self, result: ChatResult):
        self._buf_c = result.content or self._buf_c
        self._buf_r = result.reasoning or self._buf_r
        self.output.setMarkdown(self._prefix + self._buf_c)
        self.reason_view.setPlainText(self._buf_r)
        self.history.append({"role": "assistant", "content": self._buf_c})
        if len(self.history) > 8:
            self.history = self.history[-8:]
        if result.usage:
            cost = self.client.estimate_cost(result, self.pricing)
            unit = self.pricing.get("unit", "")
            self.cost_label.setText(
                f"in {result.usage.get('prompt_tokens', 0)} / out "
                f"{result.usage.get('completion_tokens', 0)} tok · "
                f"缓存命中 {result.cache_hit} · 约 {cost} {unit}")

    def _reset_buttons(self):
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def clear(self):
        self.output.clear()
        self.reason_view.clear()
        self.history.clear()
        self._buf_c = self._buf_r = ""

    # ---------- 供主窗口调用 ----------
    def ask_log(self, log_tail: str):
        self.input.setPlainText(log_analysis_prompt(log_tail))
        self.input.setFocus()

    def set_pricing(self, pricing: dict):
        self.pricing = pricing or {}
