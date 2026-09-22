# -*- coding: utf-8 -*-
"""
app/ui/qt/tools_panel.py
========================
扩展工具面板：文件夹容器 / 分卷 / 分享页 / 同盘风险检测 / 最近文件。
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (QCheckBox, QFileDialog, QGroupBox, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QListWidget,
                               QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget)

from ...core import (archive, get_master, recent, riskcheck, share, split)
from ...core import audit


class ToolsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("扩展工具")
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # 文件夹容器
        g1 = QGroupBox("文件夹容器（整目录加密为单文件）")
        l1 = QHBoxLayout(g1)
        b1 = QPushButton("加密文件夹…")
        b1.clicked.connect(self.folder_encrypt)
        b2 = QPushButton("解密文件夹容器…")
        b2.clicked.connect(self.folder_decrypt)
        l1.addWidget(b1)
        l1.addWidget(b2)
        l1.addStretch(1)
        root.addWidget(g1)

        # 分卷
        g2 = QGroupBox("分卷加密（单卷泄露无意义）")
        l2 = QHBoxLayout(g2)
        self.vol_spin = QSpinBox()
        self.vol_spin.setRange(1, 8192)
        self.vol_spin.setValue(100)
        self.vol_spin.setSuffix(" MB/卷")
        b3 = QPushButton("切分为多卷…")
        b3.clicked.connect(self.do_split)
        b4 = QPushButton("合并分卷…")
        b4.clicked.connect(self.do_merge)
        l2.addWidget(QLabel("卷大小"))
        l2.addWidget(self.vol_spin)
        l2.addWidget(b3)
        l2.addWidget(b4)
        l2.addStretch(1)
        root.addWidget(g2)

        # 分享页
        g3 = QGroupBox("自解密分享页（接收方无需装软件）")
        l3 = QHBoxLayout(g3)
        b5 = QPushButton("生成分享页 HTML…")
        b5.clicked.connect(self.make_share)
        l3.addWidget(b5)
        tip = QLabel("密码不会写入页面，请另行安全告知接收方")
        tip.setStyleSheet("color:#888;")
        l3.addWidget(tip)
        l3.addStretch(1)
        root.addWidget(g3)

        # 风险检测
        g4 = QGroupBox("同盘风险检测（密文与密钥同盘会警告）")
        l4 = QHBoxLayout(g4)
        b6 = QPushButton("选择密文并检测…")
        b6.clicked.connect(self.check_risk)
        self.risk_label = QLabel("")
        self.risk_label.setWordWrap(True)
        l4.addWidget(b6)
        l4.addWidget(self.risk_label, 1)
        root.addWidget(g4)

        # 最近文件
        g5 = QGroupBox("最近文件 / 收藏夹")
        l5 = QVBoxLayout(g5)
        self.recent_list = QListWidget()
        l5.addWidget(self.recent_list)
        row = QHBoxLayout()
        b7 = QPushButton("刷新")
        b7.clicked.connect(self.reload_recent)
        b8 = QPushButton("收藏/取消收藏")
        b8.clicked.connect(self.toggle_fav)
        b9 = QPushButton("清空记录")
        b9.clicked.connect(self.clear_recent)
        row.addWidget(b7)
        row.addWidget(b8)
        row.addWidget(b9)
        row.addStretch(1)
        l5.addLayout(row)
        root.addWidget(g5)

        self.reload_recent()

    # ---------- 文件夹 ----------
    def _need_master(self):
        m = get_master()
        if not m:
            QMessageBox.warning(self, "未解锁", "请先在主窗口缓存密码。")
        return m

    def folder_encrypt(self):
        m = self._need_master()
        if not m:
            return
        folder = QFileDialog.getExistingDirectory(self, "选择要加密的文件夹")
        if not folder:
            return
        out, _ = QFileDialog.getSaveFileName(self, "保存为", folder.rstrip("/\\") + ".aes256")
        if not out:
            return
        try:
            r = archive.encrypt_folder(folder, out, m)
            audit.append("info", "folder_encrypt", f"{folder} → {out}")
            QMessageBox.information(self, "完成",
                                    f"已打包 {r['files']} 个文件\n密文：{out}")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))

    def folder_decrypt(self):
        m = self._need_master()
        if not m:
            return
        f, _ = QFileDialog.getOpenFileName(self, "选择文件夹容器", filter="*.aes256")
        if not f:
            return
        out = QFileDialog.getExistingDirectory(self, "选择解包目标目录")
        if not out:
            return
        try:
            r = archive.decrypt_folder(f, out, m)
            QMessageBox.information(self, "完成", f"已解出 {r['files']} 个文件到 {out}")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))

    # ---------- 分卷 ----------
    def do_split(self):
        f, _ = QFileDialog.getOpenFileName(self, "选择已加密的 .aes256", filter="*.aes256")
        if not f:
            return
        try:
            r = split.split_blob(f, self.vol_spin.value() * 1024 * 1024)
            QMessageBox.information(self, "完成",
                                    f"已切成 {r['parts']} 卷\n清单：{r['manifest']}\n"
                                    "请把各卷分存不同介质。")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))

    def do_merge(self):
        f, _ = QFileDialog.getOpenFileName(self, "选择分卷清单", filter="*.json")
        if not f:
            return
        try:
            r = split.merge_parts(f)
            QMessageBox.information(self, "完成", f"合并完成：{r['out']}")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))

    # ---------- 分享页 ----------
    def make_share(self):
        f, _ = QFileDialog.getOpenFileName(self, "选择要分享的文件")
        if not f:
            return
        pwd, ok = QInputDialog.getText(self, "分享密码", "为分享页设置密码：",
                                       QLineEdit.Password)
        if not ok or not pwd:
            return
        out, _ = QFileDialog.getSaveFileName(self, "保存分享页", f + ".share.html",
                                             filter="*.html")
        if not out:
            return
        try:
            share.write_share_page(Path(f).read_bytes(), pwd, out)
            QMessageBox.information(self, "完成",
                                    f"分享页已生成：{out}\n\n"
                                    "密码不会写入该文件，请通过安全渠道单独告知接收方。")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))

    # ---------- 风险检测 ----------
    def check_risk(self):
        f, _ = QFileDialog.getOpenFileName(self, "选择密文", filter="*.aes256")
        if not f:
            return
        r = riskcheck.check_pair(f)
        if r["safe"]:
            self.risk_label.setText("✔ 未发现密钥文件与密文同盘/同目录")
            self.risk_label.setStyleSheet("color:#2e7d32;")
        else:
            self.risk_label.setText("⚠ " + "；".join(r["warnings"]))
            self.risk_label.setStyleSheet("color:#c62828;")

    # ---------- 最近 ----------
    def reload_recent(self):
        self.recent_list.clear()
        import time

        for it in recent.list_recent(20):
            ts = time.strftime("%m-%d %H:%M", time.localtime(it.get("ts", 0)))
            star = "★ " if recent.is_favorite(it.get("path", "")) else "  "
            self.recent_list.addItem(f"{star}{ts}  [{it.get('action','')}]  {it.get('path','')}")

    def toggle_fav(self):
        item = self.recent_list.currentItem()
        if not item:
            return
        text = item.text()
        path = text.split("  ")[-1].strip()
        recent.toggle_favorite(path)
        self.reload_recent()

    def clear_recent(self):
        recent.clear()
        self.reload_recent()
