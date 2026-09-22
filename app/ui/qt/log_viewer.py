# -*- coding: utf-8 -*-
"""
app/ui/qt/log_viewer.py
=======================
日志查看器：审计链、操作日志、AI 元数据日志，附链校验与 HTML 报告导出。

这是原文档第 4 项缺失内容的一部分（F1 使用说明体系里的「遇到问题看日志」落到实际界面）。
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit,
                               QPushButton, QTabWidget, QVBoxLayout, QWidget)

from ...core import audit, store
from ...paths import log_dir


class LogViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("日志与审计")
        lay = QVBoxLayout(self)

        bar = QHBoxLayout()
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.reload)
        self.verify_btn = QPushButton("校验审计链")
        self.verify_btn.clicked.connect(self._verify)
        self.report_btn = QPushButton("导出 HTML 报告")
        self.report_btn.clicked.connect(self._report)
        self.status = QLabel("")
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.verify_btn)
        bar.addWidget(self.report_btn)
        bar.addStretch(1)
        bar.addWidget(self.status)
        lay.addLayout(bar)

        self.tabs = QTabWidget()
        self.txt_chain = QPlainTextEdit(readOnly=True)
        self.txt_ops = QPlainTextEdit(readOnly=True)
        self.txt_ai = QPlainTextEdit(readOnly=True)
        self.txt_db = QPlainTextEdit(readOnly=True)
        self.tabs.addTab(self.txt_chain, "审计链")
        self.tabs.addTab(self.txt_ops, "操作日志")
        self.tabs.addTab(self.txt_ai, "AI 调用元数据")
        self.tabs.addTab(self.txt_db, "操作历史库")
        lay.addWidget(self.tabs)

        self.reload()

    # ---------- 加载 ----------
    def reload(self):
        self.txt_chain.setPlainText(self._render_chain())
        self.txt_ops.setPlainText(self._read(log_dir() / "operation.log"))
        self.txt_ai.setPlainText(self._read(log_dir() / "ai_audit.log"))
        self.txt_db.setPlainText(self._render_db())
        ok, msg = audit.verify()
        self.status.setText(("✔ " if ok else "✘ ") + msg)

    def _read(self, path) -> str:
        try:
            return path.read_text(encoding="utf-8") if path.exists() else "（暂无记录）"
        except Exception as exc:
            return f"读取失败：{exc}"

    def _render_chain(self) -> str:
        rows = audit.read_all(500)
        if not rows:
            return "（暂无审计记录）"
        import time

        lines = []
        for r in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0)))
            lines.append(f"{ts} [{r.get('level','')}] {r.get('event','')} | "
                         f"{r.get('detail','')}  #{str(r.get('hash',''))[:12]}")
        return "\n".join(lines)

    def _render_db(self) -> str:
        rows = store.recent(200)
        if not rows:
            return "（暂无操作历史）"
        import time

        lines = [f"{'时间':<20}{'动作':<10}{'大小':>12}  结果  文件"]
        for r in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0)))
            lines.append(f"{ts:<20}{r.get('action',''):<10}{r.get('size',0):>12}  "
                         f"{'OK' if r.get('ok') else 'FAIL'}  {r.get('src','')}")
        return "\n".join(lines)

    # ---------- 操作 ----------
    def _verify(self):
        ok, msg = audit.verify()
        self.status.setText(("✔ " if ok else "✘ ") + msg)
        QMessageBox.information(self, "审计链校验",
                                ("审计链完整，未被篡改。\n" if ok else "审计链校验失败！\n") + msg)

    def _report(self):
        try:
            p = audit.write_html_report()
            QMessageBox.information(self, "导出成功", f"报告已生成：\n{p}")
        except Exception as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
