# -*- coding: utf-8 -*-
"""
app/ui/qt/main_window.py
========================
PySide6 主窗口：加密/解密/密码/任务/审计/AI/主题/命令面板。

启动流程
--------
1. 先建 ThemeManager，但 apply 放到控件建好之后；
2. 建 UI → 建 AI 面板（默认隐藏）→ 应用主题；
3. 缓存密码后调用 unlock_ai()，用主密钥解出 API Key；
4. closeEvent 时清空内存密钥与 API Key。
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QDockWidget, QFileDialog,
                               QGroupBox, QHBoxLayout, QLabel, QListWidget,
                               QListWidgetItem, QMainWindow, QMessageBox, QProgressBar,
                               QPushButton, QSplitter, QStatusBar, QVBoxLayout, QWidget)

from ... import config as cfgmod
from ... import i18n
from ...core import (IntegrityError, check_password_policy, decrypt_stream,
                     derive_master, encrypt_stream, export_keyfile, get_master,
                     import_keyfile, make_recovery_code, multicipher, new_salt, set_master,
                     store, verify_challenge)
from ...core import algorithms
from ...paths import is_same_volume
from ...services import JobQueue
from ...services.ai import DeepSeekClient
from ...services.ai.client import load_api_key
from ..theme import ThemeManager
from .ai_panel import AIPanel
from .cipher_dialog import CipherDialog
from .command_palette import Command, CommandPalette
from .help_viewer import HelpViewer
from .log_viewer import LogViewer
from .widgets import DropArea, PasswordField


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = cfgmod.load()
        self.setWindowTitle(i18n.tr("app.title"))
        # 当前加密算法链（可叠加；始终只使用一个总密钥）
        self.chain = cfgmod.get_default_chain()
        w = self.cfg["ui"]["window"]
        self.resize(w.get("w", 1080), w.get("h", 720))

        # 主题管理器先建，apply 稍后
        self.theme = ThemeManager(QApplication.instance())

        # AI 客户端（默认离线）
        ai = self.cfg["ai"]
        self.client = DeepSeekClient(
            model=ai["model"], base_url=ai["base_url"], offline=ai["offline"],
            timeout=(ai["timeout"]["connect"], ai["timeout"]["read"]),
            max_retry=ai["max_retry"])

        # 任务队列
        self.jobs = JobQueue()
        self.jobs.start()
        self._job_rows: dict[str, object] = {}

        self._build_central()
        self._build_ai_dock()
        self._build_menus()
        self._build_statusbar()
        self._build_shortcuts()

        self.theme.theme_changed.connect(self._on_theme_changed)
        self.theme.apply(force=True)

        # 会话超时检测
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self._poll = QTimer(self)
        self._poll.setInterval(150)
        self._poll.timeout.connect(self._drain_jobs)
        self._poll.start()

    # ========================================================
    # 界面
    # ========================================================
    def _build_central(self):
        central = QWidget()
        root = QHBoxLayout(central)

        left = QVBoxLayout()

        # 密码区
        pw_box = QGroupBox("1 · 密码")
        pw_lay = QVBoxLayout(pw_box)
        self.pw = PasswordField("输入密码（至少 12 位）")
        pw_lay.addWidget(self.pw)
        row = QHBoxLayout()
        self.cache_btn = QPushButton("缓存密码")
        self.cache_btn.setObjectName("primary")
        self.cache_btn.clicked.connect(self.on_cache_password)
        self.suggest_btn = QPushButton("建议密码")
        self.suggest_btn.clicked.connect(self.on_suggest)
        self.lock_btn = QPushButton("立即锁定")
        self.lock_btn.clicked.connect(self.on_lock)
        row.addWidget(self.cache_btn)
        row.addWidget(self.suggest_btn)
        row.addWidget(self.lock_btn)
        row.addStretch(1)
        pw_lay.addLayout(row)
        left.addWidget(pw_box)

        # 加解密区
        op_box = QGroupBox("2 · 加解密")
        op_lay = QVBoxLayout(op_box)
        self.drop = DropArea()
        self.drop.files_dropped.connect(self.on_files_dropped)
        op_lay.addWidget(self.drop)
        row2 = QHBoxLayout()
        self.enc_btn = QPushButton("选择文件加密")
        self.enc_btn.clicked.connect(self.on_pick_encrypt)
        self.dec_btn = QPushButton("选择文件解密")
        self.dec_btn.clicked.connect(self.on_pick_decrypt)
        row2.addWidget(self.enc_btn)
        row2.addWidget(self.dec_btn)
        row2.addStretch(1)
        op_lay.addLayout(row2)

        self.del_src = QCheckBox("加密后删除原文件（先校验解密可读）")
        self.del_src.setChecked(self.cfg["delete_source_after_encrypt"])
        self.del_src.toggled.connect(
            lambda v: cfgmod.set_value("delete_source_after_encrypt", v))
        op_lay.addWidget(self.del_src)

        self.warn_same = QCheckBox("同盘风险检测（密文与密钥同盘时警告）")
        self.warn_same.setChecked(self.cfg["warn_same_volume"])
        self.warn_same.toggled.connect(lambda v: cfgmod.set_value("warn_same_volume", v))
        op_lay.addWidget(self.warn_same)
        left.addWidget(op_box)

        # 任务区
        task_box = QGroupBox("3 · 任务队列")
        task_lay = QVBoxLayout(task_box)
        self.task_list = QListWidget()
        self.task_list.setMaximumHeight(160)
        task_lay.addWidget(self.task_list)
        row3 = QHBoxLayout()
        self.cancel_all_btn = QPushButton("全部取消")
        self.cancel_all_btn.clicked.connect(self.jobs.cancel_all)
        self.clear_done_btn = QPushButton("清除已完成")
        self.clear_done_btn.clicked.connect(self._clear_done)
        row3.addWidget(self.cancel_all_btn)
        row3.addWidget(self.clear_done_btn)
        row3.addStretch(1)
        task_lay.addLayout(row3)
        left.addWidget(task_box)

        # 密钥备份区
        key_box = QGroupBox("4 · 密钥备份（强烈推荐）")
        key_lay = QVBoxLayout(key_box)
        row4 = QHBoxLayout()
        self.export_btn = QPushButton("导出密钥文件")
        self.export_btn.clicked.connect(self.on_export_keyfile)
        self.recovery_btn = QPushButton("生成恢复码")
        self.recovery_btn.clicked.connect(self.on_recovery_code)
        self.import_btn = QPushButton("导入密钥文件")
        self.import_btn.clicked.connect(self.on_import_keyfile)
        row4.addWidget(self.export_btn)
        row4.addWidget(self.recovery_btn)
        row4.addWidget(self.import_btn)
        row4.addStretch(1)
        key_lay.addLayout(row4)
        left.addWidget(key_box)

        left.addStretch(1)
        root.addLayout(left, 3)

        self.setCentralWidget(central)

    def _build_ai_dock(self):
        self.ai_panel = AIPanel(self.client, pricing=self.cfg["ai"]["pricing"], parent=self)
        self.ai_dock = QDockWidget("AI 助手（DeepSeek V4.1 Flash）", self)
        self.ai_dock.setWidget(self.ai_panel)
        self.ai_dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        self.addDockWidget(Qt.RightDockWidgetArea, self.ai_dock)
        self.ai_dock.hide()          # 默认不显示，避免误触联网

    def _build_menus(self):
        mb = self.menuBar()

        m_file = mb.addMenu(i18n.tr("menu.file"))
        self._act(m_file, i18n.tr("cipher.title") + "…", "Ctrl+Shift+C", self.choose_cipher)
        self._act(m_file, "加密文件…", "Ctrl+O", self.on_pick_encrypt)
        self._act(m_file, "解密文件…", "Ctrl+Shift+O", self.on_pick_decrypt)
        m_file.addSeparator()
        self._act(m_file, i18n.tr("action.quit"), "Ctrl+Q", self.close)

        m_tool = mb.addMenu(i18n.tr("menu.tools"))
        self._act(m_tool, i18n.tr("tools.title") + "…", "Ctrl+Shift+E", self.open_tools)
        self._act(m_tool, i18n.tr("ai.title"), "Ctrl+Shift+A", self.toggle_ai)
        self._act(m_tool, i18n.tr("menu.theme") + " / 切换主题", "Ctrl+Shift+T", self.theme.toggle)
        self._act(m_tool, i18n.tr("sec.params") + "…", None, self.open_security)
        self._act(m_tool, "日志与审计", None, self.open_logs)
        self._act(m_tool, i18n.tr("action.lock_now"), "Ctrl+L", self.on_lock)

        # 语言菜单（运行时中英切换）
        m_lang = mb.addMenu(i18n.tr("menu.language"))
        self._act(m_lang, i18n.tr("action.language_zh"), None,
                  lambda: self._switch_language("zh_CN"))
        self._act(m_lang, i18n.tr("action.language_en"), None,
                  lambda: self._switch_language("en_US"))

        m_help = mb.addMenu(i18n.tr("menu.help"))
        self._act(m_help, "使用说明", "F1", self.open_help)
        self._act(m_help, i18n.tr("legal.menu"), None, self.open_legal)
        self._act(m_help, i18n.tr("app.about"), None, self.on_about)

    def _switch_language(self, lang: str):
        """运行时切换语言：更新 i18n、持久化到 config，并提示重启以全面刷新。"""
        i18n.set_language(lang)
        cfgmod.set_language(lang)
        self.statusBar().showMessage(
            i18n.tr("action.settings") if False else "Language: " + i18n.label(lang, lang), 4000)
        QMessageBox.information(
            self, i18n.tr("menu.language"),
            "语言已切换为 " + i18n.label(lang) + "。\n"
            "Language switched. Restart the app to fully apply.")
        self._retranslate()

    def _retranslate(self):
        """就地刷新主要可见文案（标题 / 菜单重建）。"""
        self.setWindowTitle(i18n.tr("app.title"))
        self.menuBar().clear()
        self._build_menus()

    def choose_cipher(self):
        """打开加密方式选择对话框：单选或叠加，写入 self.chain 并持久化默认值。"""
        chosen = CipherDialog.select(self, chain=self.chain)
        if chosen:
            self.chain = chosen
            cfgmod.set_default_chain(chosen)
            self.statusBar().showMessage(
                "算法链：" + algorithms.describe_chain(chosen), 5000)

        m_help = mb.addMenu("帮助(&H)")
        self._act(m_help, "使用说明", "F1", self.open_help)
        self._act(m_help, i18n.tr("legal.menu"), None, self.open_legal)
        self._act(m_help, "关于", None, self.on_about)

    def _act(self, menu, text, shortcut, handler):
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        a.triggered.connect(handler)
        menu.addAction(a)
        return a

    def open_security(self):
        """打开安全参数对话框（可配置安全参数，按机器性能调优）。"""
        from .security_dialog import SecurityDialog

        dlg = SecurityDialog(self)
        if dlg.exec():
            QMessageBox.information(self, "提示", "安全参数已更新，新参数将在下次加密时生效。")

    def _build_statusbar(self):
        self.setStatusBar(QStatusBar(self))
        self.kdf_label = QLabel("KDF: -")
        self.session_label = QLabel("未解锁")
        self.statusBar().addPermanentWidget(self.kdf_label)
        self.statusBar().addPermanentWidget(self.session_label)

    def _build_shortcuts(self):
        QShortcut(QKeySequence("F1"), self, activated=self.open_help)
        QShortcut(QKeySequence("Ctrl+Shift+P"), self, activated=self.open_palette)
        QShortcut(QKeySequence("Ctrl+Shift+A"), self, activated=self.toggle_ai)

    # ========================================================
    # 密码
    # ========================================================
    def on_cache_password(self):
        pwd = self.pw.text()
        ok, msg = check_password_policy(pwd, self.cfg["min_password_len"],
                                        self.cfg["require_classes"])
        if not ok:
            if QMessageBox.question(self, "密码强度提示",
                                    f"{msg}\n\n仍要继续吗？") != QMessageBox.Yes:
                return
        try:
            from ...core import vault

            master = vault.derive_master(pwd)
        except Exception as exc:
            QMessageBox.critical(self, "派生失败", str(exc))
            return
        set_master(master)
        self.kdf_label.setText(f"KDF: {'Argon2id' if self._argon() else 'PBKDF2'}")
        self.session_label.setText("已解锁（密钥在内存）")
        self.unlock_ai()
        from ...core import audit

        audit.append("info", "cache_password", "主密钥已缓存")
        QMessageBox.information(self, "已缓存",
                                "主密钥已派生并缓存到内存。\n请尽快导出密钥文件。")

    @staticmethod
    def _argon() -> bool:
        from ...core import kdf

        return kdf.ARGON2_AVAILABLE

    def on_suggest(self):
        from ...core import suggest_password

        pwd = suggest_password(18)
        self.pw.edit.setText(pwd)
        self.pw.edit.setEchoMode(self.pw.edit.Normal)

    def on_lock(self):
        from ...core import audit, clear_keys

        clear_keys()
        self.client.clear_api_key()
        self.session_label.setText("未解锁")
        audit.append("security", "lock", "用户手动锁定")
        self.statusBar().showMessage("已清空内存密钥", 4000)

    # ========================================================
    # 加解密
    # ========================================================
    def on_files_dropped(self, paths: list):
        if not paths:
            return
        if not get_master():
            QMessageBox.warning(self, "未解锁", "请先输入密码并点击「缓存密码」。")
            return
        for p in paths:
            if p.endswith(".aes256"):
                self._decrypt(p)
            else:
                self._encrypt(p)

    def on_pick_encrypt(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择要加密的文件")
        for p in paths:
            self._encrypt(p)

    def on_pick_decrypt(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择要解密的文件", filter="*.aes256")
        for p in paths:
            self._decrypt(p)

    def _encrypt(self, src: str):
        master = get_master()
        if not master:
            QMessageBox.warning(self, "未解锁", "请先缓存密码。")
            return
        dst = src + self.cfg["suffix"]
        delete_src = self.del_src.isChecked()
        chain = list(self.chain)

        def task(progress=None, cancel=None):
            # 容器 v4：自选算法链叠加加密，单一总密钥
            r = multicipher.encrypt_stream(src, dst, master, chain,
                                           chunk_size=self.cfg["chunk_size"],
                                           progress=progress, cancel=cancel)
            # 删除原文件前必须做一次解密回读校验
            if delete_src:
                import hashlib
                import os
                import tempfile

                fd, tmp = tempfile.mkstemp()
                os.close(fd)
                try:
                    multicipher.decrypt_stream(dst, tmp, master)
                    a = hashlib.sha256(Path(src).read_bytes()).digest()
                    b = hashlib.sha256(Path(tmp).read_bytes()).digest()
                    if a != b:
                        raise IntegrityError("回读校验不一致，已阻止删除原文件")
                    os.remove(src)
                    r["source_deleted"] = True
                finally:
                    Path(tmp).unlink(missing_ok=True)
            store.record("encrypt", src, dst, r.get("size", 0), True,
                         sha256=r.get("sha256", ""))
            return r

        job = self.jobs.submit(task, name=f"加密 {Path(src).name}")
        self._register_job_row(job)

    def _decrypt(self, src: str):
        master = get_master()
        if not master:
            QMessageBox.warning(self, "未解锁", "请先缓存密码。")
            return
        dst = src[:-len(self.cfg["suffix"])] if src.endswith(self.cfg["suffix"]) else src + ".dec"

        def task(progress=None, cancel=None):
            # 自动识别容器版本：v4 叠加容器按自描述头部还原算法链
            if multicipher.is_v4(src):
                r = multicipher.decrypt_stream(src, dst, master,
                                               progress=progress, cancel=cancel)
            else:
                r = decrypt_stream(src, dst, master, progress=progress, cancel=cancel)
            store.record("decrypt", src, dst, r.get("size", 0), True)
            return r

        job = self.jobs.submit(task, name=f"解密 {Path(src).name}")
        self._register_job_row(job)

    def _register_job_row(self, job):
        item = QListWidgetItem()
        from .widgets import JobRowWidget

        row = JobRowWidget(job.id, job.name)
        row.cancel_requested.connect(self.jobs.cancel)
        item.setSizeHint(row.sizeHint())
        self.task_list.addItem(item)
        self.task_list.setItemWidget(item, row)
        self._job_rows[job.id] = (row, item)

    def _drain_jobs(self):
        for ev in self.jobs.events():
            pair = self._job_rows.get(ev.job_id)
            if not pair:
                continue
            row, _item = pair
            job = self.jobs.get(ev.job_id)
            if ev.kind == "progress":
                pct = job.percent if job else 0
                row.update_state("running", pct)
            elif ev.kind == "done":
                row.update_state("done")
                self.statusBar().showMessage("任务完成", 4000)
            elif ev.kind == "failed":
                row.update_state("failed")
                err = (ev.payload or {}).get("error", "")
                from ...core import audit

                audit.append("error", "job_failed", err)
                QMessageBox.warning(self, "任务失败", err)
            elif ev.kind == "cancelled":
                row.update_state("cancelled")

    def _clear_done(self):
        self.jobs.clear_finished()
        done_ids = {j.id for j in self.jobs.all_jobs()
                    if j.state.value in ("done", "failed", "cancelled")}
        for jid in list(self._job_rows):
            if jid in done_ids:
                row, item = self._job_rows.pop(jid)
                self.task_list.takeItem(self.task_list.row(item))

    # ========================================================
    # 密钥备份
    # ========================================================
    def on_export_keyfile(self):
        master = get_master()
        if not master:
            QMessageBox.warning(self, "未解锁", "请先缓存密码。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存密钥文件", "aes256_backup.key")
        if not path:
            return
        from PySide6.QtWidgets import QInputDialog

        pwd, ok = QInputDialog.getText(self, "备份口令", "为密钥文件设置备份口令：",
                                       QLineEditNormal())
        if not ok or not pwd:
            return
        try:
            p = export_keyfile(master, path, pwd, note="导出于工具箱")
            from ...core import audit

            audit.append("security", "export_keyfile", str(p))
            QMessageBox.information(self, "导出成功", f"密钥文件已保存：\n{p}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    def on_recovery_code(self):
        master = get_master()
        if not master:
            QMessageBox.warning(self, "未解锁", "请先缓存密码。")
            return
        code = make_recovery_code(master)
        QMessageBox.information(
            self, "恢复码（请抄写到纸上）",
            "恢复码是密码与密钥文件同时丢失时的最后挽救手段。\n"
            "请抄写并妥善保管，不要截图、不要存手机相册。\n\n" + code)

    def on_import_keyfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", filter="*.key")
        if not path:
            return
        from PySide6.QtWidgets import QInputDialog

        pwd, ok = QInputDialog.getText(self, "备份口令", "输入密钥文件的备份口令：",
                                       QLineEditNormal())
        if not ok:
            return
        try:
            master = import_keyfile(path, pwd)
        except Exception as exc:
            QMessageBox.critical(self, "导入失败", str(exc))
            return
        set_master(master)
        self.session_label.setText("已解锁（由密钥文件恢复）")
        self.unlock_ai()
        QMessageBox.information(self, "导入成功", "主密钥已从密钥文件恢复并缓存。")

    # ========================================================
    # AI / 主题 / 面板
    # ========================================================
    def unlock_ai(self):
        master = get_master()
        if not master:
            return
        try:
            self.client.set_api_key(load_api_key(master))
        except Exception:
            self.client.set_api_key("")

    def toggle_ai(self):
        self.ai_dock.setVisible(not self.ai_dock.isVisible())

    def open_logs(self):
        dlg = LogViewer(self)
        dlg.resize(900, 620)
        dlg.show()

    def open_tools(self):
        from .tools_panel import ToolsPanel

        if not getattr(self, "_tools_win", None) or not self._tools_win.isVisible():
            self._tools_win = ToolsPanel(self)
            self._tools_win.resize(760, 720)
        self._tools_win.show()
        self._tools_win.raise_()
        self._tools_win.reload_recent()

    def open_help(self):
        dlg = HelpViewer(self)
        dlg.resize(860, 680)
        dlg.show()

    def open_legal(self):
        """查看《法律声明与免责协议》（只读展示 + 可重新确认）。"""
        from .legal_dialog import LegalDialog

        LegalDialog(self, install=False).exec()

    def open_palette(self):
        cmds = [
            Command("加密文件…", "Ctrl+O", self.on_pick_encrypt, "encrypt"),
            Command("解密文件…", "Ctrl+Shift+O", self.on_pick_decrypt, "decrypt"),
            Command("缓存密码", "", self.on_cache_password, "password"),
            Command("建议密码", "", self.on_suggest, "password"),
            Command("立即锁定", "Ctrl+L", self.on_lock, "lock"),
            Command("导出密钥文件", "", self.on_export_keyfile, "keyfile"),
            Command("生成恢复码", "", self.on_recovery_code, "recovery"),
            Command("导入密钥文件", "", self.on_import_keyfile, "keyfile"),
            Command("切换主题", "Ctrl+Shift+T", self.theme.toggle, "theme dark light"),
            Command("扩展工具（文件夹/分卷/分享页/风险检测）", "Ctrl+Shift+E",
                    self.open_tools, "tools folder split share risk"),
            Command("显示/隐藏 AI 助手", "Ctrl+Shift+A", self.toggle_ai, "ai"),
            Command("日志与审计", "", self.open_logs, "log audit"),
            Command("使用说明", "F1", self.open_help, "help f1"),
            Command("退出", "Ctrl+Q", self.close, "quit exit"),
        ]
        CommandPalette(cmds, self).exec()

    def _on_theme_changed(self, name: str):
        self.statusBar().showMessage(f"主题：{'深色' if name == 'dark' else '浅色'}", 3000)

    # ========================================================
    # 会话
    # ========================================================
    def _tick(self):
        from ...core import check_timeout

        if check_timeout():
            self.client.clear_api_key()
            self.session_label.setText("未解锁")
            self.statusBar().showMessage("会话超时，已自动清空内存密钥", 5000)

    def closeEvent(self, event):
        from ...core import audit, clear_keys

        audit.append("info", "exit", "程序退出")
        self.jobs.stop()
        self.client.close()
        self.client.clear_api_key()
        clear_keys()
        super().closeEvent(event)

    def on_about(self):
        from ... import __version__
        from ... import meta
        from ...core import kdf

        QMessageBox.about(
            self, i18n.tr("app.about"),
            f"{meta.APP_NAME} v{__version__}\n\n"
            f"{i18n.tr('app.author')}：{meta.author_line(i18n.current_language())}\n"
            f"{i18n.tr('app.email')}：{meta.AUTHOR_EMAIL}\n\n"
            f"加密算法链：{algorithms.describe_chain(self.chain)}\n"
            f"密钥派生：{kdf.kdf_name()}（一次派生，总密钥唯一）\n"
            f"子密钥：HKDF-SHA256 域分离（每层独立）\n"
            f"完整性：每层 tag + 尾部 HMAC-SHA256 + 明文 SHA-256\n"
            f"AI 助手：DeepSeek（默认离线，出网需显式同意）\n"
            f"离线守卫：{'已启用' if _netguard_on() else '未启用'}")


def _netguard_on() -> bool:
    try:
        from ...core import netguard

        return netguard.is_enforced()
    except Exception:
        return False


def QLineEditNormal():
    from PySide6.QtWidgets import QLineEdit

    return QLineEdit.Password
