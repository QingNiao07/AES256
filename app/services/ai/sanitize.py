# -*- coding: utf-8 -*-
"""
app/services/ai/sanitize.py
===========================
出网脱敏：把本地绝对路径、密钥/密文文件名、长 Base64 密文块替换为占位符。

说明：脱敏是「降低误发敏感信息」的兜底，不等于 DLP。
真正的安全边界仍是默认离线的联网闸门。
"""
from __future__ import annotations

import re

# Windows 盘符路径 / POSIX 家目录与常见挂载点
_PATH_RE = re.compile(
    r"[A-Za-z]:\\\\[^\s\"'<>|]+"
    r"|[A-Za-z]:\\[^\s\"'<>|]+"
    r"|/(?:home|Users|mnt|Volumes|root|var|etc)/[^\s\"'<>|]+"
)
# 密钥 / 密文 / 备份类文件名
_FILE_RE = re.compile(
    r"[\w\u4e00-\u9fa5.\-]{1,120}\.(?:key|aes256|keystore|bak|db|part|zip\.enc)",
    re.I,
)
# 长 Base64 / hex 块（可能是密文或密钥材料）
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64,}(?![0-9a-fA-F])")
# 疑似凭据赋值
_CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|passphrase|api[_-]?key|secret|token)\b\s*[:=]\s*\S+"
)

PLACEHOLDERS = {
    "path": "<PATH>",
    "file": "<FILE>",
    "blob": "<BLOB>",
    "hex": "<HEX>",
    "cred": "<CREDENTIAL>",
}


def sanitize(text: str) -> str:
    if not text:
        return ""
    text = _CRED_RE.sub(lambda m: f"{m.group(1)}=<CREDENTIAL>", text)
    text = _PATH_RE.sub(PLACEHOLDERS["path"], text)
    text = _FILE_RE.sub(PLACEHOLDERS["file"], text)
    text = _B64_RE.sub(PLACEHOLDERS["blob"], text)
    text = _HEX_RE.sub(PLACEHOLDERS["hex"], text)
    return text


def changed(original: str, sanitized: str | None = None) -> bool:
    return (sanitize(original) if sanitized is None else sanitized) != original


def diff_summary(original: str) -> dict:
    """返回各占位符被替换的次数，用于在 UI 提示「已脱敏 N 处」。"""
    out = {}
    for key, ph in PLACEHOLDERS.items():
        out[key] = original.count(ph) if ph in original else 0
    s = sanitize(original)
    out["changed"] = s != original
    return out
