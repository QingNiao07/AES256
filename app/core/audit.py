# -*- coding: utf-8 -*-
"""
app/core/audit.py
=================
审计日志：哈希链 + HTML 报告。

哈希链
------
每条记录包含 prev_hash，自身 hash = HMAC(key, prev_hash || 本行内容)。
任何对历史行的修改都会导致其后所有行的链校验失败 —— 企业审计刚需。

只记元数据与事件，绝不记录密码、密钥、明文内容。
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..paths import log_dir

CHAIN_FILE = "audit_chain.jsonl"
SECURITY_FILE = "security.log"
OPERATION_FILE = "operation.log"
GENESIS = "0" * 64


def _chain_key() -> bytes:
    """链密钥：优先取环境变量注入的机器密钥，否则用固定域密钥（仅防误改，非抗强对抗）。"""
    env = os.environ.get("AES256_AUDIT_KEY", "")
    if env:
        return hashlib.sha256(env.encode("utf-8")).digest()
    return hashlib.sha256(b"aes256-tool::audit-chain::v1").digest()


@dataclass
class Record:
    ts: float
    level: str            # info | warn | error | security
    event: str
    detail: str = ""
    extra: dict = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hmac.new(_chain_key(), (prev + payload).encode("utf-8"), hashlib.sha256).hexdigest()


def append(level: str, event: str, detail: str = "", **extra) -> Record:
    path = log_dir() / CHAIN_FILE
    prev = GENESIS
    if path.exists():
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                back = min(size, 8192)
                f.seek(size - back)
                tail = f.read().decode("utf-8", "ignore").strip().splitlines()
            if tail:
                prev = json.loads(tail[-1]).get("hash", GENESIS)
        except Exception:
            prev = GENESIS

    rec = Record(ts=time.time(), level=level, event=event, detail=detail,
                 extra=extra or {}, prev_hash=prev)
    body = {"ts": rec.ts, "level": rec.level, "event": rec.event,
            "detail": rec.detail, "extra": rec.extra, "prev_hash": rec.prev_hash}
    rec.hash = _digest(prev, body)

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")

    _plain(level, event, detail)
    return rec


def _plain(level: str, event: str, detail: str) -> None:
    target = log_dir() / (SECURITY_FILE if level == "security" else OPERATION_FILE)
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level.upper()}] {event} | {detail}\n"
    try:
        target.write_text(
            (target.read_text(encoding="utf-8") if target.exists() else "") + line,
            encoding="utf-8")
    except Exception:
        pass


def verify() -> tuple[bool, str]:
    """校验整条链。返回 (是否完整, 说明)。"""
    path = log_dir() / CHAIN_FILE
    if not path.exists():
        return True, "暂无审计记录"
    prev = GENESIS
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, f"第 {lineno} 行不是合法 JSON"
            body = {"ts": rec.get("ts"), "level": rec.get("level"),
                    "event": rec.get("event"), "detail": rec.get("detail"),
                    "extra": rec.get("extra", {}), "prev_hash": rec.get("prev_hash")}
            if rec.get("prev_hash") != prev:
                return False, f"第 {lineno} 行 prev_hash 断裂"
            if _digest(prev, body) != rec.get("hash"):
                return False, f"第 {lineno} 行内容被篡改"
            prev = rec["hash"]
            n += 1
    return True, f"链完整，共 {n} 条记录"


def read_all(limit: int = 500) -> list[dict]:
    path = log_dir() / CHAIN_FILE
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out[-limit:]


def write_html_report(dst: str | Path | None = None) -> Path:
    """生成可打印的 HTML 审计报告。"""
    dst = Path(dst) if dst else (log_dir() / "audit_report.html")
    ok, msg = verify()
    rows = read_all(1000)
    tr = "\n".join(
        "<tr class='{lvl}'><td>{ts}</td><td>{lvl}</td><td>{ev}</td><td>{de}</td></tr>".format(
            lvl=html.escape(r.get("level", "")),
            ts=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0))),
            ev=html.escape(str(r.get("event", ""))),
            de=html.escape(str(r.get("detail", ""))),
        ) for r in rows)
    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>AES-256 审计报告</title>
<style>
@page {{ size: A4; margin: 18mm; }}
body {{ font-family: "Microsoft YaHei", sans-serif; line-height: 1.6; color: #222; }}
h1 {{ color: #1565c0; font-size: 20px; }}
.status {{ padding: 8px 12px; border-radius: 6px; font-weight: 600;
          background: {'#e8f5e9' if ok else '#ffebee'};
          color: {'#2e7d32' if ok else '#c62828'}; }}
table {{ border-collapse: collapse; width: 100%; font-size: 12px; margin-top: 12px; }}
th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left; }}
th {{ background: #f0f4f9; }}
tr.warn td {{ background: #fff8e1; }}
tr.error td, tr.security td {{ background: #ffebee; }}
</style></head><body>
<h1>AES-256 加密工具箱 · 审计报告</h1>
<p>生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p class="status">链校验：{html.escape(msg)}</p>
<table><thead><tr><th>时间</th><th>级别</th><th>事件</th><th>详情</th></tr></thead>
<tbody>{tr}</tbody></table>
</body></html>"""
    dst.write_text(doc, encoding="utf-8")
    return dst
