# -*- coding: utf-8 -*-
"""
app/core/state.py
=================
全局密钥状态：唯一真源。

原版把 cached_master / cached_backup_master / _state_lock 散在 core 里，
AI 层、UI 层各自读写，容易出现「一把锁漏判」。这里集中管理，并提供：
- 线程安全读写
- 会话超时自动清空
- 密钥内存擦除
"""
from __future__ import annotations

import threading
import time

from . import securemem

_lock = threading.RLock()
_cached_master: bytes | None = None
_cached_backup: bytes | None = None
_last_active: float = 0.0
_timeout_sec: int = 600


# ---- 兼容旧名字 ----
_state_lock = _lock

# ============================================================
# 主密钥
# ============================================================
def set_master(master: bytes | None, backup: bytes | None = None) -> None:
    global _cached_master, _cached_backup, _last_active
    with _lock:
        _cached_master = bytes(master) if master else None
        if backup is not None:
            _cached_backup = bytes(backup) if backup else None
        _last_active = time.time()


def get_master() -> bytes | None:
    with _lock:
        return _cached_master


def get_backup() -> bytes | None:
    with _lock:
        return _cached_backup


def set_backup(backup: bytes | None) -> None:
    global _cached_backup, _last_active
    with _lock:
        _cached_backup = bytes(backup) if backup else None
        _last_active = time.time()


def has_master() -> bool:
    with _lock:
        return _cached_master is not None


def touch() -> None:
    global _last_active
    with _lock:
        _last_active = time.time()


def clear(reason: str = "") -> None:
    """擦除内存中的密钥。返回前保证引用被清空。"""
    global _cached_master, _cached_backup
    with _lock:
        if _cached_master:
            securemem.wipe(bytearray(_cached_master))
        if _cached_backup:
            securemem.wipe(bytearray(_cached_backup))
        _cached_master = None
        _cached_backup = None


# ============================================================
# 会话超时
# ============================================================
def set_timeout(sec: int) -> None:
    global _timeout_sec
    _timeout_sec = max(0, int(sec))


def timeout() -> int:
    return _timeout_sec


def expired(now: float | None = None) -> bool:
    with _lock:
        if _cached_master is None or _timeout_sec <= 0:
            return False
        return ((now or time.time()) - _last_active) > _timeout_sec


def check_timeout() -> bool:
    """若超时则清空并返回 True。由 UI 定时器调用。"""
    if expired():
        clear("session timeout")
        return True
    return False


def idle_seconds() -> float:
    with _lock:
        return (time.time() - _last_active) if _last_active else 0.0


# 兼容旧代码的模块属性访问（只读快照）
def __getattr__(name: str):
    if name == "cached_master":
        return get_master()
    if name == "cached_backup_master":
        return get_backup()
    raise AttributeError(name)
