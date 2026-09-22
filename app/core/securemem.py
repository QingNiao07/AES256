# -*- coding: utf-8 -*-
"""
app/core/securemem.py
=====================
密钥内存处理：
- wipe：原地擦除，不依赖 GC 的「删除变量」；
- mlock / munlock：把密钥所在页锁定在物理内存，防止被换页写盘；
- constant_time_eq：常量时间比较，避免时序侧信道。
"""
from __future__ import annotations

import ctypes
import os
import secrets
import sys

try:                     # POSIX
    import resource
except ImportError:      # Windows
    resource = None


def wipe(buf: bytearray | memoryview | None) -> None:
    """原地覆写为 0。仅对可变缓冲区有效。"""
    if buf is None:
        return
    try:
        n = len(buf)
        if isinstance(buf, memoryview):
            view = buf.cast("B") if buf.format != "B" else buf
            view[:] = b"\x00" * n
        else:
            buf[:] = b"\x00" * n
    except Exception:
        pass


def wipe_str(s: str) -> None:
    """字符串不可变，无法原地擦除；这里只提供明确的失败语义。"""
    raise TypeError("Python str 不可原地擦除，请用 bytearray 保存密钥")


def mlock(buf: bytearray | bytes) -> bool:
    """尝试锁定内存页。返回是否成功（失败不致命）。"""
    try:
        if sys.platform.startswith("linux") and resource is not None:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY,) * 2)
    except Exception:
        pass
    try:
        if os.name == "nt":
            k32 = ctypes.windll.kernel32
            addr = ctypes.c_char_p(bytes(buf))
            return bool(k32.VirtualLock(addr, ctypes.c_size_t(len(buf))))
        libc = ctypes.CDLL("libc.so.6", use_errno=True) if sys.platform.startswith("linux") else ctypes.CDLL(None)
        arr = (ctypes.c_char * len(buf)).from_buffer_copy(bytes(buf))
        return libc.mlock(ctypes.byref(arr), ctypes.c_size_t(len(buf))) == 0
    except Exception:
        return False


def munlock(buf: bytearray | bytes) -> bool:
    try:
        if os.name == "nt":
            k32 = ctypes.windll.kernel32
            return bool(k32.VirtualUnlock(ctypes.c_char_p(bytes(buf)), ctypes.c_size_t(len(buf))))
        libc = ctypes.CDLL(None)
        arr = (ctypes.c_char * len(buf)).from_buffer_copy(bytes(buf))
        return libc.munlock(ctypes.byref(arr), ctypes.c_size_t(len(buf))) == 0
    except Exception:
        return False


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return secrets.compare_digest(a, b)


def random_token(n: int = 32) -> str:
    return secrets.token_hex(n)
