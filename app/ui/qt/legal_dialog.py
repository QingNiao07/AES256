# -*- coding: utf-8 -*-
"""app/ui/qt/legal_dialog.py
===========================
法务条款展示 + 「我接受」确认对话框（PySide6）。

安装与首次运行使用同一对话框：
- 顶部为《法律声明与免责协议》全文（可滚动、可复制）；
- 底部复选框「我接受上述声明与条款」，**必须勾选**才能点击「同意并继续」；
- 未勾选时按钮禁用，且点击会提示。

返回 ``True`` 表示用户本人已勾选接受。
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout,
                               QLabel, QPushButton, QTextEdit, QVBoxLayout)

from ... import i18n, legal
from ... import meta


class LegalDialog(QDialog):
    def __init__(self, parent=None, install: bool = False):
        super().__init__(parent)
        self._install = install
        self.setWindowTitle(i18n.tr("legal.title"))
        self.resize(760, 620)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        lang = i18n.current_language()

        title = QLabel(legal.HEADER)
        title.setObjectName("h1")
        root.addWidget(title)
        sub = QLabel(f"{i18n.tr('app.version')} v{legal.DOC_VERSION}   ·   "
                     f"{meta.author_line(lang)}")
        sub.setObjectName("hint")
        root.addWidget(sub)

        body = QTextEdit()
        body.setReadOnly(True)
        body.setPlainText(legal.full_text(lang))
        root.addWidget(body, 1)

        # 安装声明强调
        decl = QLabel((i18n.tr("legal.install_gate") if self._install
                       else i18n.tr("legal.firstrun_gate")))
        decl.setWordWrap(True)
        decl.setObjectName("card")
        root.addWidget(decl)

        self.cb = QCheckBox(legal.short_accept_line(lang))
        self.cb.setChecked(False)
        self.cb.stateChanged.connect(self._sync)
        root.addWidget(self.cb)

        box = QDialogButtonBox()
        self.accept_btn = box.addButton(i18n.tr("legal.accept"),
                                        QDialogButtonBox.AcceptRole)
        self.decline_btn = box.addButton(i18n.tr("legal.decline"),
                                         QDialogButtonBox.RejectRole)
        self.accept_btn.setObjectName("primary")
        self.accept_btn.clicked.connect(self._on_accept)
        self.decline_btn.clicked.connect(self.reject)
        root.addWidget(box)
        self._sync()

    def _sync(self):
        # 必须本人勾选才能同意
        self.accept_btn.setEnabled(self.cb.isChecked())

    def _on_accept(self):
        if not self.cb.isChecked():
            return
        self.accept()

    @property
    def accepted(self) -> bool:
        return self.cb.isChecked()

    @staticmethod
    def ask(parent=None, install: bool = False) -> bool:
        dlg = LegalDialog(parent, install=install)
        return dlg.exec() == QDialog.Accepted and dlg.accepted


# ---- i18n keys used here (registered in catalog) ----
# legal.title/legal.accept/legal.decline/legal.install_gate/legal.firstrun_gate
