# -*- coding: utf-8 -*-
"""
app/core/store.py
=================
SQLite 元数据存储：加密历史、统计、策略快照。

注意：绝不存密码、密钥、明文。只存路径、大小、时间、结果、哈希。
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from ..paths import log_dir

DB_NAME = "backup.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    action    TEXT    NOT NULL,      -- encrypt | decrypt | verify | rotate
    src       TEXT,
    dst       TEXT,
    size      INTEGER DEFAULT 0,
    ok        INTEGER DEFAULT 1,
    detail    TEXT,
    sha256    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ops_ts ON operations(ts DESC);
CREATE INDEX IF NOT EXISTS idx_ops_action ON operations(action);
"""


def db_path(root: Path | None = None) -> Path:
    """返回数据库文件路径（不是目录）。"""
    if root is None:
        return log_dir() / DB_NAME
    return Path(root) / DB_NAME


def connect(root: Path | None = None) -> sqlite3.Connection:
    p = db_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def init(root: Path | None = None) -> None:
    with connect(root):
        pass


def record(action: str, src: str = "", dst: str = "", size: int = 0,
           ok: bool = True, detail: str = "", sha256: str = "",
           root: Path | None = None) -> int:
    with connect(root) as conn:
        cur = conn.execute(
            "INSERT INTO operations (ts, action, src, dst, size, ok, detail, sha256)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), action, src, dst, size, 1 if ok else 0, detail, sha256))
        return int(cur.lastrowid)


def recent(limit: int = 100, root: Path | None = None) -> list[dict]:
    with connect(root) as conn:
        rows = conn.execute(
            "SELECT * FROM operations ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def stats(root: Path | None = None) -> dict:
    with connect(root) as conn:
        row = conn.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(size),0) total,"
            " COALESCE(SUM(ok),0) ok FROM operations").fetchone()
        by = conn.execute(
            "SELECT action, COUNT(*) c FROM operations GROUP BY action").fetchall()
    return {"count": row["n"], "bytes": row["total"], "ok": row["ok"],
            "by_action": {r["action"]: r["c"] for r in by}}


def clear(root: Path | None = None) -> None:
    with connect(root) as conn:
        conn.execute("DELETE FROM operations")


def export_rows(rows: Iterable[dict] | None = None, root: Path | None = None) -> list[dict]:
    return list(rows) if rows is not None else recent(1000, root)
