# -*- coding: utf-8 -*-
"""
app/config.py
=============
配置唯一真源：config.json。

设计要点（相对原版的重要修正）
------------------------------
原版让 QSettings 和 JSON 各存一份，容易出现「设置里显示深色、实际是浅色」
这类两处状态打架。这里规定：
- config.json 是唯一真源；
- QSettings 只做 UI 侧镜像，写之前必须先写 config.json。
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .paths import base_dir

CONFIG_NAME = "config.json"

DEFAULTS: dict[str, Any] = {
    "version": 2,
    "min_password_len": 12,
    "require_classes": 3,
    "session_timeout_sec": 600,
    "delete_source_after_encrypt": False,
    "delete_encrypted_after_decrypt": False,
    "chunk_size": 4 * 1024 * 1024,
    "max_password_attempts": 10,
    "warn_same_volume": True,
    "auto_lock_on_minimize": False,
    "suffix": ".aes256",
    # 默认加密算法链（容器 v4）：可单选，也可叠加；详见 app/core/algorithms.py
    "cipher_chain": ["aes-256-gcm"],
    # 可配置安全参数（图片来源第 5 项）；详见 app/core/security.py
    # kdf / argon2_time_cost / argon2_memory_cost / argon2_parallelism /
    # pbkdf2_iterations / salt_len / nonce_prefix_len / chunk_size /
    # session_timeout_sec / max_password_attempts
    "security": {
        "kdf": "argon2id",
        "argon2_time_cost": 3,
        "argon2_memory_cost": 65536,
        "argon2_parallelism": 2,
        "pbkdf2_iterations": 600000,
        "salt_len": 16,
        "nonce_prefix_len": 8,
        "chunk_size": 4 * 1024 * 1024,
        "session_timeout_sec": 600,
        "max_password_attempts": 10,
        "preset": "balanced",
    },
    "ui": {
        "theme": "auto",          # light | dark | auto
        "language": "zh_CN",
        "window": {"w": 1080, "h": 720},
    },
    # 法务条款接受状态（见 app/legal.py）
    "legal": {
        "accepted": False,
        "version": "",
        "accepted_at": "",
    },
    "ai": {
        "enabled": True,          # 是否允许存在 AI 功能入口
        "model": "deepseek-flash",
        "base_url": "https://api.deepseek.com",
        "thinking": True,
        "reasoning_effort": "high",
        "offline": True,          # 默认离线：不显式打开就不发请求
        "save_history": False,
        "max_history": 8,
        "timeout": {"connect": 10, "read": 180},
        "max_retry": 2,
        # 单价随官方调整，必须配置化，不要写死在代码里
        "pricing": {"in_hit": 0.0, "in_miss": 0.0, "out": 0.0, "unit": "CNY"},
    },
}


def config_path(root: Path | None = None) -> Path:
    return (root or base_dir()) / CONFIG_NAME


def _deep_merge(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(root: Path | None = None) -> dict:
    """读取配置；缺失字段用默认值补齐。损坏时回退默认值且不抛异常。"""
    p = config_path(root)
    if not p.exists():
        return copy.deepcopy(DEFAULTS)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return copy.deepcopy(DEFAULTS)
    except Exception:
        return copy.deepcopy(DEFAULTS)
    return _deep_merge(DEFAULTS, data)


def save(cfg: dict, root: Path | None = None) -> Path:
    p = config_path(root)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)          # 原子替换，避免写一半断电损坏配置
    return p


def get(path: str, default: Any = None, root: Path | None = None) -> Any:
    """点分路径读取，如 get("ai.model")。"""
    node: Any = load(root)
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def set_value(path: str, value: Any, root: Path | None = None) -> Path:
    cfg = load(root)
    node = cfg
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    return save(cfg, root)


# ============================================================
# 便捷访问器（语言 / 离线 / 加密算法链）
# ============================================================
def get_language(root: Path | None = None) -> str:
    lang = get("ui.language", "zh_CN", root)
    return lang if lang in ("zh_CN", "en_US") else "zh_CN"


def set_language(lang: str, root: Path | None = None) -> Path:
    return set_value("ui.language", lang, root)


def get_default_chain(root: Path | None = None) -> list:
    chain = get("security.default_chain", None, root)
    if not chain:
        chain = get("cipher_chain", ["aes-256-gcm"], root)
    return list(chain) if isinstance(chain, list) and chain else ["aes-256-gcm"]


def set_default_chain(chain: list, root: Path | None = None) -> Path:
    return set_value("cipher_chain", list(chain), root)


def is_offline(root: Path | None = None) -> bool:
    return bool(get("ai.offline", True, root))
