# -*- coding: utf-8 -*-
"""
app/core/recent.py
==================
最近文件与收藏夹：快速回到高频路径。

只记路径与操作时间/次数，不记任何内容；路径本身属于用户本地信息，
因此该文件放在 aes_log/ 下并已加入 .gitignore。
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..paths import log_dir

FILE_NAME = "recent.json"
MAX_ITEMS = 30


def _path() -> Path:
    return log_dir() / FILE_NAME


def _load() -> dict:
    p = _path()
    if not p.exists():
        return {"items": [], "favorites": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        data.setdefault("items", [])
        data.setdefault("favorites", [])
        return data
    except Exception:
        return {"items": [], "favorites": []}


def _save(data: dict) -> None:
    _path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def add(path: str, action: str = "") -> None:
    data = _load()
    items = [it for it in data["items"] if it.get("path") != path]
    items.insert(0, {"path": path, "action": action, "ts": time.time()})
    data["items"] = items[:MAX_ITEMS]
    _save(data)


def list_recent(limit: int = 10) -> list[dict]:
    return _load()["items"][:limit]


def clear() -> None:
    data = _load()
    data["items"] = []
    _save(data)


# ---- 收藏夹 ----
def toggle_favorite(path: str) -> bool:
    data = _load()
    favs = data["favorites"]
    if path in favs:
        favs.remove(path)
        added = False
    else:
        favs.insert(0, path)
        added = True
    data["favorites"] = favs[:MAX_ITEMS]
    _save(data)
    return added


def favorites() -> list[str]:
    return _load()["favorites"]


def is_favorite(path: str) -> bool:
    return path in favorites()
