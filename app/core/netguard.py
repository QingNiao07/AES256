# -*- coding: utf-8 -*-
"""app/core/netguard.py
======================
离线安全守卫：在进程内拦截任何非回环（非本机）的外发网络连接。

动机
----
本工具的定位是「离线加密」。一旦误连外网，可能带来元数据泄露与远程控制风险。
本模块提供一层可插拔的 socket 拦截：

- 默认 **未启用**（import 不产生任何副作用，保证测试与正常导入不受影响）；
- 由程序入口在「离线模式」下显式 ``enable()``；
- 启用后，除回环地址（127.0.0.0/8、::1、localhost）外，所有 connect 都会抛
  ``NetworkBlocked``；
- 允许临时 ``guard()`` 上下文或 ``allow()`` 白名单放行特定主机（例如用户
  明确同意联网询问 AI 时，仅放行 API 域名）。

设计注意
--------
- 只拦截 socket 层的 connect，不改动 requests/urllib 逻辑；
- enable/disable 幂等，可嵌套计数；
- 不记录、不修改用户数据，只做「放行 / 阻断」判断。
"""
from __future__ import annotations

import socket
import threading
from contextlib import contextmanager

_LOOPBACK_V4 = "127."
_LOOPBACK_HOSTS = {"localhost", "::1", "", "0.0.0.0"}

_lock = threading.RLock()
_state = {
    "enabled": False,
    "allow_loopback": True,
    "allow_hosts": set(),        # 白名单主机名（精确匹配，忽略大小写）
}
_orig_connect = None
_orig_connect_ex = None


class NetworkBlocked(RuntimeError):
    """离线守卫拦截了一次外发连接。"""


def _is_loopback(host) -> bool:
    if host is None:
        return True
    h = str(host)
    if h in _LOOPBACK_HOSTS:
        return True
    if h.startswith(_LOOPBACK_V4):
        return True
    if h.startswith("::ffff:127."):
        return True
    return False


def _host_allowed(host) -> bool:
    h = str(host).strip().lower()
    return h in {x.lower() for x in _state["allow_hosts"]}


def is_enforced() -> bool:
    return bool(_state["enabled"])


def allow_host(host: str) -> None:
    with _lock:
        _state["allow_hosts"].add(str(host).strip())


def clear_allowlist() -> None:
    with _lock:
        _state["allow_hosts"].clear()


def _patched_connect(self, address):
    try:
        host = address[0] if isinstance(address, (tuple, list)) else address
    except Exception:
        host = None
    if _is_loopback(host) and _state["allow_loopback"]:
        return _orig_connect(self, address)
    if _host_allowed(host):
        return _orig_connect(self, address)
    raise NetworkBlocked(
        f"离线守卫已拦截对外连接：{host}。如需联网，请在设置中显式允许。"
    )


def _patched_connect_ex(self, address):
    try:
        _patched_connect(self, address)
    except NetworkBlocked:
        raise
    return 0


def enable(allow_loopback: bool = True) -> None:
    """启用离线守卫（幂等）。"""
    global _orig_connect, _orig_connect_ex
    with _lock:
        if _state["enabled"]:
            _state["allow_loopback"] = allow_loopback
            return
        if _orig_connect is None:
            _orig_connect = socket.socket.connect
            _orig_connect_ex = socket.socket.connect_ex
        socket.socket.connect = _patched_connect          # type: ignore[assignment]
        socket.socket.connect_ex = _patched_connect_ex    # type: ignore[assignment]
        _state["enabled"] = True
        _state["allow_loopback"] = allow_loopback


def disable() -> None:
    """关闭离线守卫，恢复原始 socket 行为（幂等）。"""
    global _orig_connect, _orig_connect_ex
    with _lock:
        if not _state["enabled"]:
            return
        if _orig_connect is not None:
            socket.socket.connect = _orig_connect         # type: ignore[assignment]
            socket.socket.connect_ex = _orig_connect_ex   # type: ignore[assignment]
        _state["enabled"] = False


def status() -> dict:
    return {
        "enforced": _state["enabled"],
        "allow_loopback": _state["allow_loopback"],
        "allow_hosts": sorted(_state["allow_hosts"]),
    }


@contextmanager
def allow(*hosts: str):
    """临时放行指定主机（用于用户显式同意的联网操作）。"""
    added = []
    with _lock:
        for h in hosts:
            if h not in _state["allow_hosts"]:
                _state["allow_hosts"].add(h)
                added.append(h)
    try:
        yield
    finally:
        with _lock:
            for h in added:
                _state["allow_hosts"].discard(h)


@contextmanager
def guard(allow_loopback: bool = True):
    """上下文管理器：临时启用守卫并在退出时恢复先前状态。"""
    was = _state["enabled"]
    enable(allow_loopback=allow_loopback)
    try:
        yield
    finally:
        if not was:
            disable()


def check_host(host: str, port: int | None = None) -> None:
    """显式检查一个主机是否被允许（供网络客户端出网前调用）。"""
    if not is_enforced():
        return
    if _is_loopback(host) and _state["allow_loopback"]:
        return
    if _host_allowed(host):
        return
    raise NetworkBlocked(
        f"离线守卫：目标主机 {host} 未在允许列表中，已阻止出网。"
    )
