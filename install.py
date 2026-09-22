# -*- coding: utf-8 -*-
"""install.py —— AES-256 加密工具箱 安装程序
================================================
一个零依赖（仅标准库 Tkinter）的安装向导。核心目标：

**必须由使用者本人勾选「我接受」才能完成安装。**

流程
----
    欢迎 → 阅读《法律声明与免责协议》→ 勾选「我接受」→ 安装选项 → 完成

用法
----
    python install.py            # 图形安装向导（Tk，默认）
    python install.py --cli      # 命令行安装（需输入「我接受」确认）
    python install.py --check    # 仅检查依赖与法务状态，不安装
    python install.py --quiet    # 无界面安装（仍需 --accept 明确同意）

安装动作（就地安装，不写系统目录）
----------------------------------
1. 校验运行依赖（pycryptodome / cryptography / argon2-cffi，缺失给出提示）；
2. 初始化配置 config.json（若不存在）；
3. 写入法务接受记录（legal.accepted / version / accepted_at）；
4. 创建日志目录 aes_log/；
5. 可选：写入桌面/开始菜单快捷方式（--shortcut；失败不阻断）。

未勾选「我接受」时，安装会被终止，且不会写入任何接受记录。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import legal, meta  # noqa: E402


# ============================================================
# 依赖与安装动作
# ============================================================
REQUIRED = [
    ("pycryptodome", "Crypto", "核心加密算法（AES-GCM / ChaCha20 / 传统算法）"),
    ("cryptography", "cryptography", "Camellia 等国际标准算法"),
    ("argon2-cffi", "argon2", "强密码派生（缺失时回退 PBKDF2）"),
]
OPTIONAL = [
    ("PySide6", "PySide6", "图形界面（缺失时可用 Tkinter 版）"),
    ("requests", "requests", "AI 助手联网（默认离线可不装）"),
]


def _probe(module: str) -> bool:
    import importlib

    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def check_dependencies() -> tuple[list, list]:
    missing_req, missing_opt = [], []
    for pkg, mod, desc in REQUIRED:
        if not _probe(mod):
            missing_req.append((pkg, desc))
    for pkg, mod, desc in OPTIONAL:
        if not _probe(mod):
            missing_opt.append((pkg, desc))
    return missing_req, missing_opt


def perform_install(who: str = "", make_shortcut: bool = False,
                    progress=None) -> dict:
    """执行安装（假定已获得接受）。返回结果摘要。"""
    from app import config as cfgmod
    from app.paths import ensure_dirs, log_dir

    log: list[str] = []

    def step(msg: str, frac: float):
        log.append(msg)
        if progress:
            progress(msg, frac)

    step("初始化配置…", 0.2)
    cfg = cfgmod.load()
    cfgmod.save(cfg)

    step("创建日志目录…", 0.4)
    ensure_dirs("aes_log")

    step("写入法务接受记录…", 0.6)
    info = legal.accept(who=who)

    step("检查运行依赖…", 0.8)
    missing_req, missing_opt = check_dependencies()

    if make_shortcut:
        step("创建快捷方式…", 0.9)
        try:
            _make_shortcut()
        except Exception as exc:  # 快捷方式失败不阻断安装
            log.append(f"快捷方式创建失败（不影响使用）：{exc}")

    step("安装完成", 1.0)
    return {
        "ok": True,
        "legal": info,
        "missing_required": missing_req,
        "missing_optional": missing_opt,
        "log_dir": str(log_dir(create=False)),
        "log": log,
    }


def _make_shortcut() -> None:
    """尽力创建快捷方式：Windows 用 .lnk（需 pywin32），否则写一个启动脚本。"""
    if sys.platform.startswith("win"):
        try:
            import pythoncom  # noqa: F401
            from win32com.client import Dispatch

            desktop = Path.home() / "Desktop"
            lnk = desktop / "AES-256 加密工具箱.lnk"
            shell = Dispatch("WScript.Shell")
            sc = shell.CreateShortCut(str(lnk))
            sc.Targetpath = sys.executable
            sc.Arguments = f'"{ROOT / "aes256_qt.py"}"'
            sc.WorkingDirectory = str(ROOT)
            sc.save()
            return
        except Exception:
            pass
    # 跨平台回退：写一个 run.sh / run.bat
    if sys.platform.startswith("win"):
        (ROOT / "run.bat").write_text(
            f'@echo off\r\ncd /d "{ROOT}"\r\n"{sys.executable}" aes256_qt.py\r\n',
            encoding="utf-8")
    else:
        p = ROOT / "run.sh"
        p.write_text(f'#!/bin/sh\ncd "{ROOT}"\nexec "{sys.executable}" aes256_qt.py\n',
                     encoding="utf-8")
        p.chmod(0o755)


# ============================================================
# 图形安装向导（Tk）
# ============================================================
def run_gui() -> int:
    import tkinter as tk
    from tkinter import messagebox, ttk

    from app import i18n

    i18n.set_language("zh_CN")
    root = tk.Tk()
    root.title(i18n.tr("install.title"))
    root.geometry("760x640")
    root.minsize(680, 560)

    state = {"accepted": False, "who": ""}

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=10)

    # --- 欢迎页 ---
    f_welcome = ttk.Frame(nb)
    nb.add(f_welcome, text=i18n.tr("install.welcome"))
    ttk.Label(f_welcome, text=i18n.tr("app.title"),
              font=("", 16, "bold")).pack(pady=(40, 8))
    ttk.Label(f_welcome, text=i18n.tr("app.subtitle")).pack()
    ttk.Label(f_welcome, text=f"{meta.author_line('zh_CN')}",
              foreground="#666").pack(pady=4)
    ttk.Label(f_welcome, text=i18n.tr("install.welcome"),
              wraplength=620, justify="center").pack(pady=24)
    ttk.Label(f_welcome, text=i18n.tr("install.cancel_hint"),
              wraplength=620, foreground="#a00").pack(pady=8)

    # --- 法务页（必须勾选） ---
    f_legal = ttk.Frame(nb)
    nb.add(f_legal, text=i18n.tr("install.step_legal"))
    ttk.Label(f_legal, text=legal.HEADER, font=("", 12, "bold")).pack(anchor="w", padx=8, pady=(8, 2))
    ttk.Label(f_legal,
              text=f"{i18n.tr('app.version')} v{legal.DOC_VERSION}   ·   {meta.author_line('zh_CN')}",
              foreground="#666").pack(anchor="w", padx=8)
    body = tk.Text(f_legal, wrap="word", height=20)
    body.insert("1.0", legal.full_text("zh_CN"))
    body.config(state="disabled")
    body.pack(fill="both", expand=True, padx=8, pady=6)

    acc_var = tk.BooleanVar(value=False)
    chk = ttk.Checkbutton(f_legal, text=legal.short_accept_line("zh_CN"),
                          variable=acc_var)
    chk.pack(anchor="w", padx=8, pady=4)

    # --- 选项页 ---
    f_opt = ttk.Frame(nb)
    nb.add(f_opt, text=i18n.tr("install.step_options"))
    ttk.Label(f_opt, text=i18n.tr("install.dir")).grid(row=0, column=0, sticky="w", padx=8, pady=(16, 4))
    dir_var = tk.StringVar(value=str(ROOT))
    ttk.Entry(f_opt, textvariable=dir_var, width=64).grid(row=0, column=1, padx=8, pady=(16, 4))
    who_var = tk.StringVar(value="")
    ttk.Label(f_opt, text="使用者（可选，用于记录）").grid(row=1, column=0, sticky="w", padx=8, pady=4)
    ttk.Entry(f_opt, textvariable=who_var, width=32).grid(row=1, column=1, sticky="w", padx=8, pady=4)
    sc_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(f_opt, text="创建快捷方式", variable=sc_var).grid(
        row=2, column=1, sticky="w", padx=8, pady=4)
    prog = ttk.Progressbar(f_opt, length=520, maximum=1.0)
    prog.grid(row=3, column=0, columnspan=2, padx=8, pady=16)
    log_txt = tk.Text(f_opt, height=8, wrap="word")
    log_txt.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=8, pady=6)
    f_opt.rowconfigure(4, weight=1)
    f_opt.columnconfigure(1, weight=1)

    # --- 完成页 ---
    f_done = ttk.Frame(nb)
    nb.add(f_done, text=i18n.tr("install.step_done"))
    ttk.Label(f_done, text="✔ " + i18n.tr("install.finished"),
              font=("", 13, "bold")).pack(pady=40)
    ttk.Label(f_done, text=f"日志目录：{ROOT / 'aes_log'}", foreground="#666").pack()

    # --- 底部按钮 ---
    bar = ttk.Frame(root)
    bar.pack(fill="x", padx=10, pady=(0, 10))
    status = ttk.Label(bar, text="", foreground="#a00")
    status.pack(side="left")

    def sync_accept():
        state["accepted"] = bool(acc_var.get())

    acc_var.trace_add("write", lambda *_: sync_accept())

    def go_next():
        nb.select(f_legal)

    def do_install():
        # 关键闸门：未勾选「我接受」绝不安装
        if not acc_var.get():
            status.config(text=i18n.tr("install.accept_required"))
            messagebox.showwarning(i18n.tr("legal.title"), i18n.tr("install.accept_required"))
            nb.select(f_legal)
            return
        status.config(text="")
        nb.select(f_opt)
        root.update()

        def progress(msg, frac):
            prog["value"] = frac
            log_txt.insert("end", msg + "\n")
            log_txt.see("end")
            root.update()

        result = perform_install(who=who_var.get().strip(),
                                 make_shortcut=sc_var.get(),
                                 progress=progress)
        log_txt.insert("end", "\n依赖检查：\n")
        if result["missing_required"]:
            for pkg, desc in result["missing_required"]:
                log_txt.insert("end", f"  ✗ 缺少必需依赖 {pkg}（{desc}）→ pip install {pkg}\n")
        else:
            log_txt.insert("end", "  ✓ 必需依赖齐全\n")
        for pkg, desc in result["missing_optional"]:
            log_txt.insert("end", f"  · 可选依赖未安装 {pkg}（{desc}）\n")
        log_txt.see("end")
        root.after(600, lambda: nb.select(f_done))

    def do_cancel():
        if messagebox.askyesno(i18n.tr("legal.title"),
                               "确定不同意并退出吗？安装将被终止。"):
            root.destroy()

    ttk.Button(bar, text="← 上一步", command=lambda: nb.select(f_welcome)).pack(side="left", padx=4)
    ttk.Button(bar, text="下一步 →", command=go_next).pack(side="left", padx=4)
    ttk.Button(bar, text=i18n.tr("install.install"), command=do_install).pack(side="right", padx=4)
    ttk.Button(bar, text=i18n.tr("legal.decline"), command=do_cancel).pack(side="right", padx=4)

    root.mainloop()
    return 0 if legal.is_accepted() else 3


# ============================================================
# 命令行安装
# ============================================================
def run_cli(assume_accept: bool = False, who: str = "") -> int:
    print("=" * 70)
    print(f"  {legal.HEADER}  (v{legal.DOC_VERSION})")
    print(f"  {meta.APP_NAME} · {meta.author_line('zh_CN')}")
    print("=" * 70)
    print(legal.full_text("zh_CN"))
    print("=" * 70)
    if not assume_accept:
        print(legal.short_accept_line("zh_CN"))
        try:
            ans = input(">>> 请输入「我接受」以继续安装（其它输入将终止）：").strip()
        except EOFError:
            ans = ""
        if ans not in ("我接受", "接受", "I ACCEPT", "accept", "ACCEPT"):
            print("已取消安装：未获得本人确认。")
            return 3
    result = perform_install(
        who=who,
        progress=lambda m, f: print(f"  [{int(f * 100):>3}%] {m}"))
    print("\n安装结果：")
    if result["missing_required"]:
        for pkg, desc in result["missing_required"]:
            print(f"  ✗ 缺少必需依赖 {pkg}（{desc}）→ pip install {pkg}")
    else:
        print("  ✓ 必需依赖齐全")
    for pkg, desc in result["missing_optional"]:
        print(f"  · 可选依赖未安装 {pkg}（{desc}）")
    print(f"  ✓ 已记录法务接受：{result['legal'].get('accepted_at')}")
    print("\n安装完成。运行：python aes256_qt.py")
    return 0


def run_check() -> int:
    print(f"法务版本：{legal.DOC_VERSION}")
    print(f"是否已接受：{'是' if legal.is_accepted() else '否'}  {legal.accepted_info()}")
    missing_req, missing_opt = check_dependencies()
    print(f"必需依赖缺失：{missing_req or '无'}")
    print(f"可选依赖缺失：{missing_opt or '无'}")
    return 0 if not missing_req else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AES-256 加密工具箱 安装程序")
    ap.add_argument("--cli", action="store_true", help="命令行安装（默认图形向导）")
    ap.add_argument("--quiet", action="store_true", help="无界面（需配合 --accept）")
    ap.add_argument("--accept", action="store_true",
                    help="明确表示已阅读并接受条款（无界面安装必填）")
    ap.add_argument("--who", default="", help="使用者标识（可选，写入接受记录）")
    ap.add_argument("--check", action="store_true", help="仅检查依赖与法务状态")
    args = ap.parse_args(argv)

    if args.check:
        return run_check()
    if args.quiet:
        if not args.accept:
            print("错误：无界面安装必须显式传入 --accept 表示本人已接受条款。",
                  file=sys.stderr)
            return 2
        return run_cli(assume_accept=True, who=args.who)
    if args.cli:
        return run_cli(who=args.who)
    try:
        return run_gui()
    except Exception as exc:
        print(f"图形安装不可用（{exc}），切换为命令行安装。", file=sys.stderr)
        return run_cli(who=args.who)


if __name__ == "__main__":
    raise SystemExit(main())
