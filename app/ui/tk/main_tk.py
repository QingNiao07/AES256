# -*- coding: utf-8 -*-
"""
app/ui/tk/main_tk.py
====================
Tkinter 界面：与 PySide6 版本共用同一套 core / services。

本实现不依赖 tkinterdnd2 也能启动；若安装了 tkinterdnd2 则自动启用拖拽。
AI 请求走后台线程 + ui_queue，主线程只轮询渲染，避免界面假死。
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from ... import __version__, config as cfgmod, i18n
from ...core import (algorithms, check_password_policy, decrypt_stream, derive_master,
                     encrypt_stream, export_keyfile, get_master, import_keyfile,
                     make_recovery_code, multicipher, new_salt, set_master, store,
                     suggest_password)
from ...core import audit, check_timeout, clear_keys, kdf
from ...services import JobQueue
from ...services.ai import DeepSeekClient
from ...services.ai.client import load_api_key
from ...services.ai.prompts import log_analysis_prompt, system_prompt
from ...services.ai.sanitize import diff_summary
from ..theme import DARK, LIGHT, detect_system

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    _HAS_DND = True
except Exception:
    _HAS_DND = False


class TkApp:
    def __init__(self):
        self.cfg = cfgmod.load()
        i18n.set_language(cfgmod.get_language())
        self.chain = cfgmod.get_default_chain()
        self.root = TkinterDnD.Tk() if _HAS_DND else tk.Tk()
        self.root.title(f"{i18n.tr('app.title')} v{__version__} (Tkinter)")
        self.root.geometry("1040x720")

        self.ui_queue: queue.Queue = queue.Queue()
        self.jobs = JobQueue(on_event=lambda ev: self.ui_queue.put(("job", ev)))
        self.jobs.start()

        self.client = DeepSeekClient(offline=self.cfg["ai"]["offline"],
                                     model=self.cfg["ai"]["model"],
                                     base_url=self.cfg["ai"]["base_url"])
        self.theme_mode = self.cfg.get("ui", {}).get("theme", "auto")
        if self.theme_mode not in ("light", "dark", "auto"):
            self.theme_mode = "auto"
        self.current_theme = detect_system() if self.theme_mode == "auto" else self.theme_mode

        self._build_style()
        self._build_widgets()
        self._bind_shortcuts()
        self._poll_queue()
        self._tick()
        self.root.after(2000, self._poll_system_theme)

    # ========================================================
    # 样式
    # ========================================================
    def _palette(self) -> dict:
        return DARK if self.current_theme == "dark" else LIGHT

    def _build_style(self):
        c = self._palette()
        self.style = ttk.Style(self.root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg=c["bg"])
        self.style.configure("TFrame", background=c["bg"])
        self.style.configure("TLabel", background=c["bg"], foreground=c["fg"])
        self.style.configure("TLabelframe", background=c["panel_bg"],
                             foreground=c["accent"], borderwidth=1)
        self.style.configure("TLabelframe.Label", background=c["panel_bg"],
                             foreground=c["accent"])
        self.style.configure("TButton", padding=6)
        self.style.configure("Primary.TButton", padding=6)
        self.style.map("Primary.TButton",
                       background=[("!disabled", c["accent"])],
                       foreground=[("!disabled", c["accent_fg"])])

    def toggle_theme(self):
        order = ["auto", "light", "dark"]
        self.theme_mode = order[(order.index(self.theme_mode) + 1) % len(order)]
        cfgmod.set_value("ui.theme", self.theme_mode)
        self.apply_theme()

    def _resolve_theme(self) -> str:
        return detect_system() if self.theme_mode == "auto" else self.theme_mode

    def apply_theme(self):
        """按当前模式重建样式（auto 时跟随系统）。"""
        self.current_theme = self._resolve_theme()
        self._build_style()
        c = self._palette()
        self.root.configure(bg=c["bg"])
        for child in self.root.winfo_children():
            try:
                child.configure(background=c["bg"])
            except Exception:
                pass
        try:
            self._log(f"主题：{self.theme_mode}（当前 {self.current_theme}）")
        except Exception:
            pass

    def _poll_system_theme(self):
        """auto 模式下轮询系统主题，实时跟随。"""
        if self.theme_mode == "auto":
            now = detect_system()
            if now != self.current_theme:
                self.apply_theme()
                try:
                    self.status.config(
                        text=f"已随系统切换主题：{self.current_theme}")
                except Exception:
                    pass
        self.root.after(2000, self._poll_system_theme)

    # ========================================================
    # 控件
    # ========================================================
    def _build_widgets(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        # 密码
        pw = ttk.Labelframe(outer, text="1 · 密码", padding=8)
        pw.pack(fill="x", pady=4)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw, textvariable=self.pw_var, show="*", width=40)
        self.pw_entry.grid(row=0, column=0, sticky="we", padx=4, pady=4)
        self.pw_var.trace_add("write", lambda *a: self._update_strength())
        self.strength_label = ttk.Label(pw, text="")
        self.strength_label.grid(row=1, column=0, sticky="w", padx=4)
        ttk.Button(pw, text="缓存密码", style="Primary.TButton",
                   command=self.on_cache_password).grid(row=0, column=1, padx=4)
        ttk.Button(pw, text="建议密码", command=self.on_suggest).grid(row=0, column=2, padx=4)
        ttk.Button(pw, text="立即锁定", command=self.on_lock).grid(row=0, column=3, padx=4)
        pw.columnconfigure(0, weight=1)

        # 加解密
        op = ttk.Labelframe(outer, text="2 · 加解密", padding=8)
        op.pack(fill="x", pady=4)
        self.drop_label = ttk.Label(op, text="把文件拖到这里（未安装 tkinterdnd2 时请用下方按钮）",
                                    anchor="center")
        self.drop_label.pack(fill="x", pady=6)
        if _HAS_DND:
            self.drop_label.drop_target_register(DND_FILES)
            self.drop_label.dnd_bind("<<Drop>>", self._on_drop)
        btns = ttk.Frame(op)
        btns.pack(fill="x")
        ttk.Button(btns, text="选择文件加密", command=self.on_pick_encrypt).pack(side="left", padx=4)
        ttk.Button(btns, text="选择文件解密", command=self.on_pick_decrypt).pack(side="left", padx=4)
        self.del_src = tk.BooleanVar(value=self.cfg["delete_source_after_encrypt"])
        ttk.Checkbutton(btns, text="加密后删除原文件（先校验解密可读）",
                        variable=self.del_src).pack(side="left", padx=12)
        ttk.Button(btns, text="加密方式…", command=self.on_choose_cipher).pack(side="left", padx=8)
        ttk.Button(btns, text="语言/Language", command=self.on_toggle_language).pack(side="left", padx=8)
        ttk.Button(btns, text=i18n.tr("legal.menu"), command=self.on_show_legal).pack(side="left", padx=8)
        self.chain_label = ttk.Label(op, text="算法链：" + algorithms.describe_chain(self.chain))
        self.chain_label.pack(fill="x", pady=2)

        # 任务
        task = ttk.Labelframe(outer, text="3 · 任务队列", padding=8)
        task.pack(fill="both", expand=True, pady=4)
        self.task_tree = ttk.Treeview(task, columns=("state", "progress", "name"),
                                      show="headings", height=6)
        self.task_tree.heading("state", text="状态")
        self.task_tree.heading("progress", text="进度")
        self.task_tree.heading("name", text="任务")
        self.task_tree.column("state", width=80, anchor="center")
        self.task_tree.column("progress", width=100, anchor="center")
        self.task_tree.column("name", width=520, anchor="w")
        self.task_tree.pack(fill="both", expand=True)
        row = ttk.Frame(task)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="全部取消", command=self.jobs.cancel_all).pack(side="left", padx=4)
        ttk.Button(row, text="清除已完成", command=self._clear_done).pack(side="left", padx=4)

        # 密钥备份
        key = ttk.Labelframe(outer, text="4 · 密钥备份（强烈推荐）", padding=8)
        key.pack(fill="x", pady=4)
        ttk.Button(key, text="导出密钥文件", command=self.on_export_keyfile).pack(side="left", padx=4)
        ttk.Button(key, text="生成恢复码", command=self.on_recovery_code).pack(side="left", padx=4)
        ttk.Button(key, text="导入密钥文件", command=self.on_import_keyfile).pack(side="left", padx=4)

        # 扩展工具
        ext = ttk.Labelframe(outer, text="5 · 扩展工具", padding=8)
        ext.pack(fill="x", pady=4)
        ttk.Button(ext, text="加密文件夹", command=self.on_folder_encrypt).pack(side="left", padx=4)
        ttk.Button(ext, text="解密文件夹", command=self.on_folder_decrypt).pack(side="left", padx=4)
        ttk.Button(ext, text="切分卷", command=self.on_split).pack(side="left", padx=4)
        ttk.Button(ext, text="合并分卷", command=self.on_merge).pack(side="left", padx=4)
        ttk.Button(ext, text="生成分享页", command=self.on_share).pack(side="left", padx=4)
        ttk.Button(ext, text="同盘风险检测", command=self.on_risk).pack(side="left", padx=4)

        # 日志
        logf = ttk.Labelframe(outer, text="日志", padding=8)
        logf.pack(fill="both", expand=True, pady=4)
        self.log_text = tk.Text(logf, height=7, wrap="word")
        self.log_text.pack(fill="both", expand=True)
        self._log("就绪。请先输入密码并点击「缓存密码」。")

        self.status = ttk.Label(outer, text="未解锁 | 主题: light")
        self.status.pack(fill="x", pady=2)

        # AI
        self._build_ai(outer)

    def _build_ai(self, parent):
        ai = ttk.Labelframe(parent, text="AI 助手（DeepSeek V4.1 Flash）", padding=8)
        ai.pack(fill="both", expand=True, pady=4)
        bar = ttk.Frame(ai)
        bar.pack(fill="x")
        self.online_var = tk.BooleanVar(value=not self.client.offline)
        ttk.Checkbutton(bar, text="允许联网", variable=self.online_var,
                        command=self._on_toggle_online).pack(side="left")
        self.think_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="思考模式", variable=self.think_var).pack(side="left", padx=10)
        ttk.Button(bar, text="清空", command=self._ai_clear).pack(side="right")

        self.ai_out = tk.Text(ai, height=8, wrap="word")
        self.ai_out.pack(fill="both", expand=True, pady=4)
        self.ai_reason = tk.Text(ai, height=4, wrap="word")
        self.ai_reason.pack(fill="both", expand=True)

        entry_row = ttk.Frame(ai)
        entry_row.pack(fill="x")
        self.ai_input = tk.Text(entry_row, height=3, wrap="word")
        self.ai_input.pack(side="left", fill="both", expand=True)
        self.ai_send_btn = ttk.Button(entry_row, text="发送", style="Primary.TButton",
                                      command=self._ai_send)
        self.ai_send_btn.pack(side="right", padx=4)
        self.ai_stop_btn = ttk.Button(entry_row, text="停止", state="disabled",
                                      command=self.client.cancel)
        self.ai_stop_btn.pack(side="right")

    # ========================================================
    # 快捷键
    # ========================================================
    def _bind_shortcuts(self):
        self.root.bind("<F1>", lambda e: self.show_help())
        self.root.bind("<Control-l>", lambda e: self.on_lock())
        self.root.bind("<Control-Shift-T>", lambda e: self.toggle_theme())
        self.root.bind("<Control-Shift-A>", lambda e: self.ai_input.focus_set())
        self.ai_input.bind("<Control-Return>", lambda e: (self._ai_send(), "break")[1])

    # ========================================================
    # 密码
    # ========================================================
    def _update_strength(self):
        from ...core import policy

        pwd = self.pw_var.get()
        level, desc = policy.password_strength(pwd)
        bits = policy.entropy_bits(pwd)
        if pwd:
            self.strength_label.config(
                text=f"{desc} · {bits:.0f} bits · 离线破解约 "
                     f"{policy.humanize_seconds(policy.crack_seconds(pwd))}")
        else:
            self.strength_label.config(text="")

    def on_cache_password(self):
        pwd = self.pw_var.get()
        ok, msg = check_password_policy(pwd, self.cfg["min_password_len"])
        if not ok and not messagebox.askyesno("密码强度提示", f"{msg}\n\n仍要继续吗？"):
            return
        from ...core import vault

        set_master(vault.derive_master(pwd))
        audit.append("info", "cache_password", "主密钥已缓存")
        self.unlock_ai()
        self.status.config(text=f"已解锁 | KDF: {kdf.kdf_name()} | 主题: {self.current_theme}")
        self._log("主密钥已缓存。请尽快导出密钥文件。")

    def on_suggest(self):
        self.pw_entry.config(show="")
        self.pw_var.set(suggest_password(18))

    def on_choose_cipher(self):
        """Tk 版加密方式选择：多选叠加成算法链（单一总密钥）。"""
        win = tk.Toplevel(self.root)
        win.title(i18n.tr("cipher.title"))
        win.transient(self.root)
        ttk.Label(win, text=i18n.tr("cipher.intro"), wraplength=520).pack(padx=10, pady=6)
        ttk.Label(win, text="🔑 " + i18n.tr("cipher.single_key_hint"),
                  wraplength=520).pack(padx=10, pady=2)
        vars_map = {}
        for m in algorithms.list_algorithms():
            var = tk.BooleanVar(value=m["id"] in self.chain)
            vars_map[m["id"]] = var
            label = m.get("display_name", m["id"])
            if not m["available"]:
                label += "（不可用）"
            cb = ttk.Checkbutton(win, text=label, variable=var)
            if not m["available"]:
                cb.state(["disabled"])
            cb.pack(anchor="w", padx=16)

        def _ok():
            chosen = [a for a in algorithms.algorithm_ids() if vars_map[a].get()]
            if not chosen:
                messagebox.showwarning(i18n.tr("cipher.title"), i18n.tr("cipher.need_one"))
                return
            try:
                self.chain = algorithms.normalize_chain(chosen)
            except algorithms.AlgorithmError as exc:
                messagebox.showerror(i18n.tr("cipher.title"), str(exc))
                return
            cfgmod.set_default_chain(self.chain)
            self.chain_label.config(text="算法链：" + algorithms.describe_chain(self.chain))
            win.destroy()

        ttk.Button(win, text=i18n.tr("common.ok"), command=_ok).pack(pady=8)

    def on_toggle_language(self):
        lang = "en_US" if i18n.current_language() == "zh_CN" else "zh_CN"
        i18n.set_language(lang)
        cfgmod.set_language(lang)
        messagebox.showinfo(i18n.tr("menu.language"), "语言已切换，重启后全面生效。")

    def on_show_legal(self):
        """查看《法律声明与免责协议》。"""
        from .legal_tk import ask_legal

        ask_legal(self.root, install=False)

    def on_lock(self):
        clear_keys()
        self.client.clear_api_key()
        audit.append("security", "lock", "用户手动锁定")
        self.status.config(text=f"未解锁 | 主题: {self.current_theme}")
        self._log("已清空内存密钥。")

    # ========================================================
    # 加解密
    # ========================================================
    def _on_drop(self, event):
        paths = self.root.tk.splitlist(event.data)
        self._handle_paths(paths)

    def _handle_paths(self, paths: list):
        if not get_master():
            messagebox.showwarning("未解锁", "请先输入密码并点击「缓存密码」。")
            return
        for p in paths:
            if p.endswith(".aes256"):
                self._decrypt(p)
            else:
                self._encrypt(p)

    def on_pick_encrypt(self):
        self._handle_paths(list(filedialog.askopenfilenames(title="选择要加密的文件")))

    def on_pick_decrypt(self):
        self._handle_paths(list(filedialog.askopenfilenames(
            title="选择要解密的文件", filetypes=[("AES256", "*.aes256"), ("全部", "*.*")])))

    def _encrypt(self, src: str):
        master, delete_src = get_master(), self.del_src.get()
        dst = src + self.cfg["suffix"]

        def task(progress=None, cancel=None):
            r = encrypt_stream(src, dst, master, chunk_size=self.cfg["chunk_size"],
                               progress=progress, cancel=cancel)
            if delete_src:
                import hashlib
                import os
                import tempfile

                fd, tmp = tempfile.mkstemp()
                os.close(fd)
                try:
                    decrypt_stream(dst, tmp, master)
                    if (hashlib.sha256(Path(src).read_bytes()).digest()
                            != hashlib.sha256(Path(tmp).read_bytes()).digest()):
                        raise ValueError("回读校验不一致，已阻止删除原文件")
                    os.remove(src)
                    r["source_deleted"] = True
                finally:
                    Path(tmp).unlink(missing_ok=True)
            store.record("encrypt", src, dst, r.get("size", 0), True)
            return r

        job = self.jobs.submit(task, name=f"加密 {Path(src).name}")
        self._add_task_row(job)

    def _decrypt(self, src: str):
        master = get_master()
        dst = src[:-7] if src.endswith(".aes256") else src + ".dec"

        def task(progress=None, cancel=None):
            r = decrypt_stream(src, dst, master, progress=progress, cancel=cancel)
            store.record("decrypt", src, dst, r.get("size", 0), True)
            return r

        job = self.jobs.submit(task, name=f"解密 {Path(src).name}")
        self._add_task_row(job)

    def _add_task_row(self, job):
        self.task_tree.insert("", "end", iid=job.id,
                              values=("等待", "0%", job.name))

    def _clear_done(self):
        self.jobs.clear_finished()
        for jid in list(self.task_tree.get_children()):
            job = self.jobs.get(jid)
            if job is None or job.state.value in ("done", "failed", "cancelled"):
                if job is not None and job.state.value in ("done", "failed", "cancelled"):
                    self.task_tree.delete(jid)
                elif job is None:
                    self.task_tree.delete(jid)

    # ========================================================
    # 密钥备份
    # ========================================================
    def on_export_keyfile(self):
        master = get_master()
        if not master:
            messagebox.showwarning("未解锁", "请先缓存密码。")
            return
        path = filedialog.asksaveasfilename(title="保存密钥文件", defaultextension=".key",
                                            initialfile="aes256_backup.key")
        if not path:
            return
        pwd = simpledialog.askstring("备份口令", "为密钥文件设置备份口令：", show="*")
        if not pwd:
            return
        try:
            p = export_keyfile(master, path, pwd, note="导出于工具箱")
            audit.append("security", "export_keyfile", str(p))
            messagebox.showinfo("导出成功", f"密钥文件已保存：\n{p}")
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))

    def on_recovery_code(self):
        master = get_master()
        if not master:
            messagebox.showwarning("未解锁", "请先缓存密码。")
            return
        code = make_recovery_code(master)
        messagebox.showinfo("恢复码（请抄写到纸上）",
                            "请抄写并妥善保管，不要截图。\n\n" + code)

    def on_import_keyfile(self):
        path = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("KEY", "*.key")])
        if not path:
            return
        pwd = simpledialog.askstring("备份口令", "输入密钥文件的备份口令：", show="*")
        if pwd is None:
            return
        try:
            set_master(import_keyfile(path, pwd))
            self.unlock_ai()
            messagebox.showinfo("导入成功", "主密钥已从密钥文件恢复并缓存。")
        except Exception as exc:
            messagebox.showerror("导入失败", str(exc))

    # ========================================================
    # AI
    # ========================================================
    def unlock_ai(self):
        master = get_master()
        if master:
            try:
                self.client.set_api_key(load_api_key(master))
            except Exception:
                self.client.set_api_key("")

    def _on_toggle_online(self):
        self.client.set_offline(not self.online_var.get())
        self._log("已开启联网（提问将被脱敏后发送到 DeepSeek）。"
                  if self.online_var.get() else "已回到离线模式。")

    def _ai_clear(self):
        self.ai_out.delete("1.0", "end")
        self.ai_reason.delete("1.0", "end")

    def _ai_send(self):
        text = self.ai_input.get("1.0", "end").strip()
        if not text:
            return
        if self.client.offline:
            self._log("离线模式：请先勾选「允许联网」。")
            return
        if not self.client.api_key:
            self._log("未配置 DeepSeek API Key。")
            return
        if diff_summary(text).get("changed"):
            self._log("已对本次消息脱敏。")
        self.ai_input.delete("1.0", "end")
        self._log(f"我：{text}")
        self.ai_out.insert("end", "\nAI：")
        self.ai_reason.delete("1.0", "end")
        self.ai_send_btn.config(state="disabled")
        self.ai_stop_btn.config(state="normal")
        threading.Thread(target=self._ask_ai, args=(text,), daemon=True).start()

    def _ask_ai(self, question: str):
        try:
            self.client.chat(
                [{"role": "system", "content": system_prompt()},
                 {"role": "user", "content": question}],
                thinking=self.think_var.get(),
                on_content=lambda s: self.ui_queue.put(("ai_chunk", s)),
                on_reasoning=lambda s: self.ui_queue.put(("ai_reason", s)))
        except Exception as exc:
            self.ui_queue.put(("ai_error", f"{type(exc).__name__}: {exc}"))
        finally:
            self.ui_queue.put(("ai_done", None))

    def ask_ai_log(self, log_tail: str):
        self.ai_input.delete("1.0", "end")
        self.ai_input.insert("1.0", log_analysis_prompt(log_tail))
        self.ai_input.focus_set()

    # ========================================================
    # 轮询与状态
    # ========================================================
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                self._handle_event(kind, payload)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    def _handle_event(self, kind: str, payload):
        if kind == "job":
            ev = payload
            job = self.jobs.get(ev.job_id)
            if not job or not self.task_tree.exists(ev.job_id):
                return
            if ev.kind == "progress":
                self.task_tree.item(ev.job_id,
                                    values=("进行中", f"{job.percent}%", job.name))
            elif ev.kind == "done":
                self.task_tree.item(ev.job_id, values=("完成", "100%", job.name))
                self._log(f"任务完成：{job.name}")
            elif ev.kind == "failed":
                self.task_tree.item(ev.job_id, values=("失败", "-", job.name))
                err = (ev.payload or {}).get("error", "")
                audit.append("error", "job_failed", err)
                self._log(f"任务失败：{job.name} → {err}")
            elif ev.kind == "cancelled":
                self.task_tree.item(ev.job_id, values=("已取消", "-", job.name))
        elif kind == "ai_chunk":
            self.ai_out.insert("end", payload)
            self.ai_out.see("end")
        elif kind == "ai_reason":
            self.ai_reason.insert("end", payload)
            self.ai_reason.see("end")
        elif kind == "ai_error":
            self._log(f"AI 错误：{payload}")
        elif kind == "ai_done":
            self.ai_send_btn.config(state="normal")
            self.ai_stop_btn.config(state="disabled")

    def _tick(self):
        if check_timeout():
            self.client.clear_api_key()
            self.status.config(text=f"未解锁（会话超时）| 主题: {self.current_theme}")
            self._log("会话超时，已自动清空内存密钥。")
        self.root.after(1000, self._tick)

    def _log(self, msg: str):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def show_help(self):
        try:
            p = Path(__file__).resolve().parents[3] / "使用说明书.md"
            text = p.read_text(encoding="utf-8") if p.exists() else "未找到 使用说明书.md"
        except Exception:
            text = "读取使用说明失败"
        win = tk.Toplevel(self.root)
        win.title("使用说明 (F1)")
        win.geometry("760x600")
        t = tk.Text(win, wrap="word")
        t.insert("1.0", text)
        t.pack(fill="both", expand=True)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        audit.append("info", "exit", "程序退出")
        self.jobs.stop()
        self.client.close()
        self.client.clear_api_key()
        clear_keys()
        self.root.destroy()


def main():
    TkApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
