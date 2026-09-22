# -*- coding: utf-8 -*-
"""
app/core/settings.py
====================
安全参数的持久化门面：把 SecurityParams 落到 config.json。

放在 core 而非 config.py，是为了让 config.py 保持「通用 KV 配置」的职责，
而安全参数的业务语义集中在这里。
"""
from __future__ import annotations

from pathlib import Path

from .. import config as cfgmod
from .security import SecurityParams, calibrate, from_config, preset, to_config


def load_params(root: Path | None = None) -> SecurityParams:
    return from_config(cfgmod.load(root))


def save_params(params: SecurityParams, root: Path | None = None) -> Path:
    errs = params.validate()
    if errs:
        raise ValueError("安全参数不合法: " + "; ".join(errs))
    cfg = cfgmod.load(root)
    return cfgmod.save(to_config(params, cfg), root)


def apply_preset(name: str, root: Path | None = None) -> SecurityParams:
    p = preset(name)
    save_params(p, root)
    return p


def calibrate_and_save(
    max_memory_kib: int = 256 * 1024, root: Path | None = None
) -> tuple[SecurityParams, float]:
    params, dt = calibrate(max_memory_kib=max_memory_kib)
    save_params(params, root)
    return params, dt
