# -*- coding: utf-8 -*-
"""
cli.py
======
命令行入口：加解密 / 批量 / 文件夹 / 分卷 / 分享页 / 风险检测 / 密钥 / 审计。

为什么需要它：GUI 打不开、或需要把加密塞进备份脚本 / CI 时，
命令行是唯一兜底通道，也是应急恢复手段。

用法摘要
--------
    python cli.py enc FILE... [--out OUT]            # 支持多文件批量
    python cli.py enc-dir DIR [--out OUT] [--pattern *.log]
    python cli.py dec FILE... [--out OUT]
    python cli.py folder-enc DIR -o OUT.aes256
    python cli.py folder-dec FILE -o OUTDIR
    python cli.py split FILE [--volume-mb N]
    python cli.py merge MANIFEST [--out FILE]
    python cli.py share FILE -o OUT.html
    python cli.py risk PATH...
    python cli.py verify|info FILE
    python cli.py export-key KEYFILE | recovery | recent
    python cli.py audit | audit-report [--out R.html]
    python cli.py selftest | suggest

安全约定：密码永不作为命令行参数传递（会进入 shell 历史 / 进程列表），
只允许交互输入或从 stdin 读取。
"""
from __future__ import annotations

import argparse
import fnmatch
import getpass
import sys
from pathlib import Path

from app.core import (algorithms, archive, audit, check_password_policy, container,
                      db_init, decrypt_stream, derive_master, encrypt_stream,
                      export_keyfile, make_recovery_code,
                      multicipher, new_salt, read_meta, recent, riskcheck,
                      share, split, store, suggest_password)
from app.core import kdf, policy


# ============================================================
# 输入
# ============================================================
def _ask_password(confirm: bool = False) -> str:
    if not sys.stdin.isatty():
        line = sys.stdin.readline().strip()
        if line:
            return line
    pwd = getpass.getpass("请输入密码：")
    if confirm:
        again = getpass.getpass("请再次输入：")
        if pwd != again:
            print("[错误] 两次输入不一致", file=sys.stderr)
            raise SystemExit(2)
    return pwd


def _master(confirm: bool = False) -> bytes:
    pwd = _ask_password(confirm)
    ok, msg = check_password_policy(pwd, 12, 3)
    if not ok:
        print(f"[警告] 密码强度不足：{msg}", file=sys.stderr)
    # 经保险库派生：KDF 盐持久化于 vault.json，保证同一密码可复现主密钥
    from app.core import vault

    return vault.derive_master(pwd)


def _progress(done: int, total: int) -> None:
    if total <= 0:
        return
    pct = int(done * 100 / total)
    bar = "█" * (pct // 2) + "░" * (50 - pct // 2)
    sys.stderr.write(f"\r  [{bar}] {pct:>3}%  {done}/{total} B")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\n")


def _risk_warn(paths) -> None:
    """加密前做同盘风险检测，命中则提示（不阻断）。"""
    r = riskcheck.check_any([p for p in paths])
    for w in r.get("warnings", []):
        print(f"[风险] {w}", file=sys.stderr)
    if r.get("warnings"):
        print("[提示] 密钥文件与密文同盘/同目录会显著降低安全性，建议分开存放。",
              file=sys.stderr)


# ============================================================
# 加解密（含批量）
# ============================================================
def cmd_enc(args) -> int:
    # 叠加加密 / 移动互通模式：使用容器 v4，单一总密钥，自描述头部
    #   --chain          指定算法链（叠加）
    #   --kdf pbkdf2     强制 PBKDF2 派生（浏览器/PWA 移动端可解密）
    if getattr(args, "chain", None) or getattr(args, "kdf", None) == "pbkdf2":
        return _cmd_enc_chain(args)

    master = _master()
    files = list(args.files)
    if args.dir:
        d = Path(args.dir)
        for p in sorted(d.rglob("*")):
            if p.is_file() and fnmatch.fnmatch(p.name, args.pattern):
                files.append(str(p))
    if not files:
        print("[错误] 没有要加密的文件", file=sys.stderr)
        return 2

    _risk_warn(files)
    db_init()
    ok_n = fail_n = 0
    for src in files:
        out = args.out if (args.out and len(files) == 1) else src + ".aes256"
        print(f"加密：{src} → {out}")
        try:
            r = encrypt_stream(src, out, master, progress=_progress)
            store.record("encrypt", src, out, r["size"], True, sha256=r["sha256"])
            recent.add(src, "encrypt")
            ok_n += 1
        except Exception as exc:
            print(f"[失败] {src}：{type(exc).__name__}: {exc}", file=sys.stderr)
            fail_n += 1
    print(f"[完成] 成功 {ok_n}，失败 {fail_n}")
    return 0 if fail_n == 0 else 1


def cmd_dec(args) -> int:
    # v4 叠加容器：按自描述头部还原算法链
    files = list(args.files)
    if args.dir:
        d = Path(args.dir)
        for p in sorted(d.rglob("*")):
            if p.is_file() and fnmatch.fnmatch(p.name, args.pattern):
                files.append(str(p))
    v4_files = [f for f in files if multicipher.is_v4(f)]
    if v4_files:
        return _cmd_dec_chain(args, files)

    master = _master()
    if not files:
        print("[错误] 没有要解密的文件", file=sys.stderr)
        return 2

    db_init()
    ok_n = fail_n = 0
    for src in files:
        out = args.out if (args.out and len(files) == 1) else (
            src[:-7] if src.endswith(".aes256") else src + ".dec")
        print(f"解密：{src} → {out}")
        try:
            r = decrypt_stream(src, out, master, progress=_progress)
            store.record("decrypt", src, out, r["size"], True)
            recent.add(src, "decrypt")
            ok_n += 1
        except container.IntegrityError as exc:
            print(f"[失败] {src}：完整性校验不通过（密码错误或文件被篡改）", file=sys.stderr)
            fail_n += 1
        except Exception as exc:
            print(f"[失败] {src}：{type(exc).__name__}: {exc}", file=sys.stderr)
            fail_n += 1
    print(f"[完成] 成功 {ok_n}，失败 {fail_n}")
    return 0 if fail_n == 0 else 1


# ============================================================
# 叠加加密（容器 v4）：自选算法链，单一总密钥
# ============================================================
def _print_ciphers() -> None:
    print("可用加密算法（按推荐度排序，可叠加）：")
    for m in algorithms.list_algorithms():
        flag = "✔" if m["available"] else "�’"
        tag = " [AEAD]" if m["aead"] else " [EtM]"
        legacy = " (传统算法)" if m.get("legacy") else ""
        print(f"  {flag} {m['id']:<24}{tag}{legacy}  {algorithms.name_of(m['id'])}")


def _resolve_chain(chain_arg) -> list[str]:
    """把 --chain 参数拆成算法链并校验；为空时回退默认单算法链。"""
    if not chain_arg:
        return algorithms.normalize_chain(["aes-256-gcm"])
    chain = [c.strip() for c in chain_arg.split(",") if c.strip()]
    if not chain:
        raise SystemExit("[错误] --chain 未指定任何算法")
    try:
        return algorithms.normalize_chain(chain)
    except algorithms.AlgorithmError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        print("[提示] 用 `cli.py list-ciphers` 查看可用算法。", file=sys.stderr)
        raise SystemExit(2)


def _cmd_enc_chain(args) -> int:
    chain = _resolve_chain(args.chain)
    files = list(args.files)
    if args.dir:
        d = Path(args.dir)
        for p in sorted(d.rglob("*")):
            if p.is_file() and fnmatch.fnmatch(p.name, args.pattern):
                files.append(str(p))
    if not files:
        print("[错误] 没有要加密的文件", file=sys.stderr)
        return 2

    print(f"[算法链] {algorithms.describe_chain(chain)}")
    print("[说明] 无论叠加几种算法，都只使用一个总密钥。")

    # 移动互通：--kdf pbkdf2 时强制 PBKDF2-HMAC-SHA256（浏览器 WebCrypto 支持）
    use_pbkdf2 = getattr(args, "kdf", None) == "pbkdf2"
    if use_pbkdf2:
        if chain != ["aes-256-gcm"]:
            print("[提示] 移动网页版仅支持算法链 [aes-256-gcm]；"
                  "当前算法链可被桌面端解密，但浏览器端无法处理。", file=sys.stderr)
        print("[互通] KDF 已设为 PBKDF2-HMAC-SHA256（与移动网页版一致）。")

    iters = int(getattr(args, "kdf_iters", 0) or 0) or kdf.PBKDF2_ITERATIONS
    pwd = _ask_password(confirm=True)
    ok, msg = check_password_policy(pwd, 12, 3)
    if not ok:
        print(f"[警告] 密码强度不足：{msg}", file=sys.stderr)

    _risk_warn(files)
    db_init()
    ok_n = fail_n = 0
    for src in files:
        out = args.out if (args.out and len(files) == 1) else src + ".aes256"
        print(f"加密：{src} → {out}")
        try:
            if use_pbkdf2:
                salt = kdf.new_salt(16)
                recipe = {"salt": salt, "kdf_name": "pbkdf2", "time_cost": 0,
                          "memory_cost": 0, "parallelism": 0, "iterations": iters}
                master = kdf.derive_master_custom(
                    pwd, salt, kdf_name="pbkdf2", iterations=iters)
                r = multicipher.encrypt_stream(
                    src, out, master, chain, kdf_salt=salt,
                    kdf_recipe=recipe, progress=_progress)
            else:
                r = multicipher.encrypt_stream_password(src, out, pwd, chain,
                                                        progress=_progress)
            store.record("encrypt", src, out, r["size"], True, sha256=r["sha256"])
            recent.add(src, "encrypt")
            ok_n += 1
        except Exception as exc:
            print(f"[失败] {src}：{type(exc).__name__}: {exc}", file=sys.stderr)
            fail_n += 1
    print(f"[完成] 成功 {ok_n}，失败 {fail_n}")
    return 0 if fail_n == 0 else 1


def _cmd_dec_chain(args, files) -> int:
    db_init()
    ok_n = fail_n = 0
    for src in files:
        out = args.out if (args.out and len(files) == 1) else (
            src[:-7] if src.endswith(".aes256") else src + ".dec")
        try:
            if multicipher.is_v4(src):
                meta = multicipher.read_meta(src)
                print(f"[算法链] {algorithms.describe_chain(meta['chain'])}")
                pwd = _ask_password()
                r = multicipher.decrypt_stream_password(src, out, pwd, progress=_progress)
            else:
                print(f"解密：{src} → {out}")
                master = _master()
                r = decrypt_stream(src, out, master, progress=_progress)
            print(f"解密：{src} → {out}")
            store.record("decrypt", src, out, r["size"], True)
            recent.add(src, "decrypt")
            ok_n += 1
        except container.IntegrityError as exc:
            print(f"[失败] {src}：完整性校验不通过（密码错误或文件被篡改）", file=sys.stderr)
            fail_n += 1
        except Exception as exc:
            print(f"[失败] {src}：{type(exc).__name__}: {exc}", file=sys.stderr)
            fail_n += 1
    print(f"[完成] 成功 {ok_n}，失败 {fail_n}")
    return 0 if fail_n == 0 else 1


# ============================================================
# 文件夹容器
# ============================================================
def cmd_folder_enc(args) -> int:
    master = _master()
    out = args.out or (str(args.dir).rstrip("/\\") + ".aes256")
    db_init()
    print(f"打包并加密文件夹：{args.dir} → {out}")
    try:
        r = archive.encrypt_folder(args.dir, out, master, progress=_progress)
    except Exception as exc:
        print(f"[失败] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    store.record("encrypt", str(args.dir), out, r.get("size", 0), True)
    print(f"[完成] 打包 {r['files']} 个文件，密文 {r['size']} B")
    return 0


def cmd_folder_dec(args) -> int:
    master = _master()
    out = args.out or "unpacked"
    db_init()
    print(f"解密并解包：{args.file} → {out}")
    try:
        r = archive.decrypt_folder(args.file, out, master, progress=_progress)
    except Exception as exc:
        print(f"[失败] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    store.record("decrypt", args.file, out, r.get("size", 0), True)
    print(f"[完成] 解出 {r['files']} 个文件到 {out}")
    return 0


# ============================================================
# 分卷
# ============================================================
def cmd_split(args) -> int:
    try:
        r = split.split_blob(args.file, args.volume_mb * 1024 * 1024,
                             out_dir=args.out_dir, progress=_progress)
    except Exception as exc:
        print(f"[失败] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"[完成] 切成 {r['parts']} 卷，清单：{r['manifest']}")
    print("[提示] 请把各卷分存不同介质；合并需要全部卷齐全。")
    return 0


def cmd_merge(args) -> int:
    try:
        r = split.merge_parts(args.manifest, args.out, progress=_progress)
    except Exception as exc:
        print(f"[失败] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"[完成] 合并 {r['parts']} 卷 → {r['out']}")
    return 0


# ============================================================
# 分享页
# ============================================================
def cmd_share(args) -> int:
    pwd = getpass.getpass("为分享页设置密码：")
    if not pwd:
        print("[错误] 密码不能为空", file=sys.stderr)
        return 2
    out = args.out or (args.file + ".share.html")
    try:
        data = Path(args.file).read_bytes()
        share.write_share_page(data, pwd, out, title=args.title)
    except Exception as exc:
        print(f"[失败] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"[完成] 分享页：{out}")
    print("[提醒] 密码不会写入该文件；请通过安全渠道单独告知接收方。")
    return 0


# ============================================================
# 风险检测
# ============================================================
def cmd_risk(args) -> int:
    r = riskcheck.check_any(args.paths)
    if r["safe"]:
        print("[安全] 未发现密文与密钥同盘/同目录的情况。")
        return 0
    for w in r["warnings"]:
        print(f"[风险] {w}")
    return 1


# ============================================================
# 校验 / 信息
# ============================================================
def cmd_verify(args) -> int:
    try:
        meta = read_meta(args.file)
    except Exception as exc:
        print(f"[失败] {exc}", file=sys.stderr)
        return 1
    print(f"结构正常：容器 v{meta['version']}，块大小 {meta['chunk_size']}，"
          f"原始大小 {meta['orig_size']} B")
    return 0


def cmd_info(args) -> int:
    try:
        meta = read_meta(args.file)
    except Exception as exc:
        print(f"[失败] {exc}", file=sys.stderr)
        return 1
    kind = archive.peek_kind(args.file)
    print(f"文件：{args.file}")
    print(f"容器版本：{meta['version']}")
    print(f"原始类型：{'文件夹容器' if kind == 'folder' else '单文件'}")
    print(f"原始大小：{meta['orig_size']} B")
    print(f"原始文件名：{meta['name']}")
    print(f"块大小：{meta['chunk_size']} B")
    return 0


# ============================================================
# 密钥
# ============================================================
def cmd_export_key(args) -> int:
    master = _master(confirm=True)
    backup = getpass.getpass("为密钥文件设置备份口令：")
    p = export_keyfile(master, args.keyfile, backup, note="CLI 导出")
    audit.append("security", "export_keyfile", str(p))
    print(f"[完成] 密钥文件已保存：{p}")
    print("[提醒] 密钥文件不要与密文放在同一磁盘。")
    return 0


def cmd_recovery(args) -> int:
    master = _master(confirm=True)
    code = make_recovery_code(master)
    print("恢复码（请抄写到纸上，不要截图）：")
    print(code)
    return 0


# ============================================================
# 审计 / 最近
# ============================================================
def cmd_audit(args) -> int:
    ok, msg = audit.verify()
    print(("✔ " if ok else "✘ ") + msg)
    return 0 if ok else 1


def cmd_audit_report(args) -> int:
    p = audit.write_html_report(args.out)
    print(f"[完成] 报告：{p}")
    return 0


def cmd_recent(args) -> int:
    rows = recent.list_recent(args.limit)
    if not rows:
        print("（暂无最近记录）")
        return 0
    import time

    for it in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get("ts", 0)))
        print(f"{ts}  {it.get('action', ''):<8}  {it.get('path', '')}")
    favs = recent.favorites()
    if favs:
        print("\n收藏夹：")
        for f in favs:
            print(f"  ★ {f}")
    return 0


def cmd_selftest(args) -> int:
    from app import core

    return core.selftest()


def cmd_suggest(args) -> int:
    pwd = suggest_password(args.length)
    print(f"建议密码：{pwd}")
    level, desc = policy.password_strength(pwd)
    print(f"强度：{desc}，估算熵 {policy.entropy_bits(pwd)} bits")
    return 0


def cmd_list_ciphers(args) -> int:
    if getattr(args, "json", False):
        import json

        print(json.dumps(algorithms.list_algorithms(), ensure_ascii=False, indent=2))
        return 0
    _print_ciphers()
    print()
    print("示例：")
    print("  python cli.py enc secret.dat --chain aes-256-gcm")
    print("  python cli.py enc secret.dat --chain aes-256-gcm,chacha20-poly1305")
    print("  python cli.py dec secret.dat.aes256")
    return 0


# ============================================================
# 解析器
# ============================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cli.py", description="AES-256 工具箱命令行")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enc", help="加密文件（支持多文件批量 / --dir）")
    e.add_argument("files", nargs="*")
    e.add_argument("--dir", "-d", help="批量：递归加密该目录下匹配的文件")
    e.add_argument("--pattern", "-p", default="*", help="配合 --dir 的通配符，默认 *")
    e.add_argument("--out", "-o")
    e.add_argument("--chain", "-c", default=None,
                   help="叠加加密：逗号分隔的算法链，如 aes-256-gcm,chacha20-poly1305")
    e.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default=None,
                   help="密钥派生：argon2id（默认，桌面）或 pbkdf2（与移动网页版互通）")
    e.add_argument("--kdf-iters", type=int, default=0,
                   help="配合 --kdf pbkdf2 的迭代次数，默认 600000")
    e.set_defaults(func=cmd_enc)

    d = sub.add_parser("dec", help="解密文件（支持多文件批量 / --dir）")
    d.add_argument("files", nargs="*")
    d.add_argument("--dir", "-d", help="批量：递归解密该目录下的 .aes256")
    d.add_argument("--pattern", "-p", default="*.aes256")
    d.add_argument("--out", "-o")
    d.set_defaults(func=cmd_dec)

    fe = sub.add_parser("folder-enc", help="文件夹整体加密为单容器")
    fe.add_argument("dir")
    fe.add_argument("--out", "-o")
    fe.set_defaults(func=cmd_folder_enc)

    fd = sub.add_parser("folder-dec", help="解密文件夹容器并解包")
    fd.add_argument("file")
    fd.add_argument("--out", "-o")
    fd.set_defaults(func=cmd_folder_dec)

    sp = sub.add_parser("split", help="把 .aes256 切成多卷")
    sp.add_argument("file")
    sp.add_argument("--volume-mb", type=int, default=100)
    sp.add_argument("--out-dir")
    sp.set_defaults(func=cmd_split)

    mg = sub.add_parser("merge", help="合并分卷")
    mg.add_argument("manifest")
    mg.add_argument("--out", "-o")
    mg.set_defaults(func=cmd_merge)

    sh = sub.add_parser("share", help="生成自解密分享页 HTML")
    sh.add_argument("file")
    sh.add_argument("--out", "-o")
    sh.add_argument("--title", default="AES-256 加密分享")
    sh.set_defaults(func=cmd_share)

    rk = sub.add_parser("risk", help="同盘风险检测")
    rk.add_argument("paths", nargs="+")
    rk.set_defaults(func=cmd_risk)

    v = sub.add_parser("verify", help="校验容器结构")
    v.add_argument("file")
    v.set_defaults(func=cmd_verify)

    i = sub.add_parser("info", help="查看密文头部信息")
    i.add_argument("file")
    i.set_defaults(func=cmd_info)

    k = sub.add_parser("export-key", help="导出密钥文件")
    k.add_argument("keyfile")
    k.set_defaults(func=cmd_export_key)

    r = sub.add_parser("recovery", help="生成恢复码")
    r.set_defaults(func=cmd_recovery)

    a = sub.add_parser("audit", help="校验审计链")
    a.set_defaults(func=cmd_audit)

    ar = sub.add_parser("audit-report", help="导出 HTML 审计报告")
    ar.add_argument("--out", "-o")
    ar.set_defaults(func=cmd_audit_report)

    rc = sub.add_parser("recent", help="查看最近文件与收藏夹")
    rc.add_argument("--limit", "-l", type=int, default=10)
    rc.set_defaults(func=cmd_recent)

    s = sub.add_parser("selftest", help="运行自检")
    s.set_defaults(func=cmd_selftest)

    sg = sub.add_parser("suggest", help="生成建议密码")
    sg.add_argument("--length", "-l", type=int, default=18)
    sg.set_defaults(func=cmd_suggest)

    lc = sub.add_parser("list-ciphers", help="列出全部可用加密算法")
    lc.add_argument("--json", action="store_true", help="以 JSON 输出")
    lc.set_defaults(func=cmd_list_ciphers)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[中断] 已取消", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
