# -*- coding: utf-8 -*-
"""
aes256_core.py
==============
兼容垫片：让旧代码与文档里的 `import aes256_core as core` 继续有效。

真实实现已迁移到 app/core/。cached_master / cached_backup_master / _state_lock
统一转发到 app.core.state（唯一状态源），避免多处各自维护导致漏判。
"""
from __future__ import annotations

import sys as _sys

from app.core import *                                  # noqa: F401,F403
from app.core import __all__ as _core_all
from app.core import state as _state
from app import core as _core


def __getattr__(name):
    try:
        return getattr(_state, name)
    except AttributeError:
        raise AttributeError(f"module 'aes256_core' has no attribute {name!r}") from None


def __dir__():
    return sorted(set(globals()) | set(dir(_state)))


if __name__ == "__main__":
    _sys.exit(_core.selftest())
