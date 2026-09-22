# -*- coding: utf-8 -*-
"""app/ui/qt/cipher_dialog.py
============================
加密方式选择对话框：可单选，也可多选叠加成「算法链」。

要点
----
- 左侧列出全部可用算法（按推荐度排序，标注 AEAD / 传统算法 / 依赖缺失）；
- 右侧为已选算法链，支持上移 / 下移调整加密顺序（自上而下依次加密）；
- 顶部固定提示：无论叠加几种算法，始终只使用一个总密钥；
- 依赖缺失的算法置灰且不可添加，避免用户选了却跑不起来；
- 文案全部走 i18n，随中英切换。

返回：``chain`` 属性为最终算法 id 列表（至少一项）。
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox,
                               QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
                               QPushButton, QVBoxLayout)

from ... import i18n
from ...core import algorithms


class CipherDialog(QDialog):
    def __init__(self, chain=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("cipher.title"))
        self.resize(720, 460)
        self._chain = list(chain or [algorithms.DEFAULT_ALGORITHM])
        self._meta = {m["id"]: m for m in algorithms.list_algorithms()}
        self._build()
        self._refresh()

    # ---------- 构建 ----------
    def _build(self):
        root = QVBoxLayout(self)

        intro = QLabel(i18n.tr("cipher.intro"))
        intro.setWordWrap(True)
        intro.setObjectName("hint")
        root.addWidget(intro)

        single = QLabel("🔑 " + i18n.tr("cipher.single_key_hint"))
        single.setWordWrap(True)
        single.setObjectName("card")
        root.addWidget(single)

        cols = QHBoxLayout()

        # 左：可用算法
        left = QVBoxLayout()
        left.addWidget(QLabel(i18n.tr("cipher.available")))
        self.avail = QListWidget()
        self.avail.setSelectionMode(QAbstractItemView.SingleSelection)
        self.avail.itemDoubleClicked.connect(lambda _i: self._add())
        left.addWidget(self.avail)
        self.add_btn = QPushButton(i18n.tr("cipher.add") + " →")
        self.add_btn.setObjectName("primary")
        self.add_btn.clicked.connect(self._add)
        left.addWidget(self.add_btn)
        cols.addLayout(left, 1)

        # 右：算法链
        right = QVBoxLayout()
        right.addWidget(QLabel(i18n.tr("cipher.chain_order")))
        self.chain = QListWidget()
        self.chain.setSelectionMode(QAbstractItemView.SingleSelection)
        self.chain.itemDoubleClicked.connect(lambda _i: self._remove())
        right.addWidget(self.chain)
        row = QHBoxLayout()
        self.up_btn = QPushButton("↑ " + i18n.tr("cipher.move_up"))
        self.up_btn.clicked.connect(lambda: self._move(-1))
        self.down_btn = QPushButton("↓ " + i18n.tr("cipher.move_down"))
        self.down_btn.clicked.connect(lambda: self._move(1))
        self.rm_btn = QPushButton("← " + i18n.tr("cipher.remove"))
        self.rm_btn.clicked.connect(self._remove)
        self.clr_btn = QPushButton(i18n.tr("cipher.clear"))
        self.clr_btn.clicked.connect(self._clear)
        for b in (self.up_btn, self.down_btn, self.rm_btn, self.clr_btn):
            row.addWidget(b)
        right.addLayout(row)
        cols.addLayout(right, 1)

        root.addLayout(cols)

        self.hint = QLabel()
        self.hint.setObjectName("hint")
        root.addWidget(self.hint)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.button(QDialogButtonBox.Ok).setText(i18n.tr("common.ok"))
        box.button(QDialogButtonBox.Cancel).setText(i18n.tr("common.cancel"))
        box.accepted.connect(self._accept)
        box.rejected.connect(self.reject)
        root.addWidget(box)

    # ---------- 刷新 ----------
    def _label(self, algo_id: str) -> str:
        m = self._meta.get(algo_id, {})
        name = m.get("display_name") or algorithms.name_of(algo_id)
        tags = []
        tags.append(i18n.tr("cipher.aead") if m.get("aead") else i18n.tr("cipher.etm"))
        if m.get("legacy"):
            tags.append(i18n.tr("cipher.legacy"))
        if not m.get("available", True):
            tags.append(i18n.tr("cipher.unavailable"))
        return f"{name}  ·  {' / '.join(tags)}"

    def _refresh(self):
        self.avail.clear()
        for m in algorithms.list_algorithms():
            algo_id = m["id"]
            item = QListWidgetItem(self._label(algo_id))
            item.setData(Qt.UserRole, algo_id)
            if not m.get("available", True):
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            if algo_id not in self._chain:
                self.avail.addItem(item)

        self.chain.clear()
        for algo_id in self._chain:
            item = QListWidgetItem(self._label(algo_id))
            item.setData(Qt.UserRole, algo_id)
            self.chain.addItem(item)

        self.add_btn.setEnabled(self.avail.count() > 0
                                and len(self._chain) < algorithms.MAX_CHAIN)
        self.hint.setText(i18n.tr("cipher.max_layers", n=algorithms.MAX_CHAIN)
                          + "   " + " → ".join(
                              algorithms.name_of(a) for a in self._chain))

    # ---------- 操作 ----------
    def _add(self):
        item = self.avail.currentItem()
        if not item or len(self._chain) >= algorithms.MAX_CHAIN:
            return
        algo_id = item.data(Qt.UserRole)
        if algo_id and algo_id not in self._chain:
            self._chain.append(algo_id)
        self._refresh()

    def _remove(self):
        row = self.chain.currentRow()
        if 0 <= row < len(self._chain):
            self._chain.pop(row)
        self._refresh()

    def _move(self, delta: int):
        row = self.chain.currentRow()
        new = row + delta
        if 0 <= row < len(self._chain) and 0 <= new < len(self._chain):
            self._chain[row], self._chain[new] = self._chain[new], self._chain[row]
        self._refresh()
        self.chain.setCurrentRow(new)

    def _clear(self):
        self._chain = []
        self._refresh()

    def _accept(self):
        if not self._chain:
            self.hint.setText("⚠ " + i18n.tr("cipher.need_one"))
            return
        self.accept()

    # ---------- 结果 ----------
    @property
    def chain(self) -> list[str]:
        return list(self._chain)

    @staticmethod
    def select(parent=None, chain=None) -> list[str] | None:
        dlg = CipherDialog(chain=chain, parent=parent)
        if dlg.exec() == QDialog.Accepted:
            return dlg.chain
        return None
