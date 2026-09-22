# -*- coding: utf-8 -*-
"""app/ui/tk/legal_tk.py
=======================
Tk 版法务条款展示 + 「我接受」确认对话框（用于首次运行闸门）。

必须由使用者本人勾选复选框后才能点击「同意并继续」。
"""
from __future__ import annotations

from ... import i18n, legal


def ask_legal(root=None, install: bool = False) -> bool:
    """弹出法务对话框；返回 True 表示本人已勾选接受。"""
    import tkinter as tk
    from tkinter import ttk

    lang = i18n.current_language()
    own_root = root is None
    win = tk.Tk() if own_root else tk.Toplevel(root)
    win.title(i18n.tr("legal.title"))
    win.geometry("720x600")
    accepted = {"ok": False}

    ttk.Label(win, text=legal.HEADER, font=("", 13, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
    ttk.Label(win, text=f"v{legal.DOC_VERSION} · {legal.DOC_VERSION and ''}", foreground="#666").pack(anchor="w", padx=10)

    body = tk.Text(win, wrap="word")
    body.insert("1.0", legal.full_text(lang))
    body.config(state="disabled")
    body.pack(fill="both", expand=True, padx=10, pady=6)

    gate = i18n.tr("legal.install_gate") if install else i18n.tr("legal.firstrun_gate")
    ttk.Label(win, text=gate, wraplength=680, foreground="#a00").pack(anchor="w", padx=10)

    var = tk.BooleanVar(value=False)
    ttk.Checkbutton(win, text=legal.short_accept_line(lang), variable=var).pack(anchor="w", padx=10, pady=4)

    bar = ttk.Frame(win)
    bar.pack(fill="x", padx=10, pady=10)

    def on_accept():
        if not var.get():
            return
        accepted["ok"] = True
        win.destroy()

    def on_decline():
        accepted["ok"] = False
        win.destroy()

    acc = ttk.Button(bar, text=i18n.tr("legal.accept"), command=on_accept)
    acc.pack(side="right", padx=4)
    ttk.Button(bar, text=i18n.tr("legal.decline"), command=on_decline).pack(side="right", padx=4)

    def sync():
        acc.state(["!disabled"] if var.get() else ["disabled"])

    var.trace_add("write", lambda *_: sync())
    sync()

    if own_root:
        win.mainloop()
    else:
        win.grab_set()
        win.wait_window()
    return accepted["ok"]
