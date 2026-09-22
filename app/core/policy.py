# -*- coding: utf-8 -*-
"""
app/core/policy.py
==================
密码策略与强度评估。

强度 = 估算熵（bits）+ 常见弱口令黑名单 + 多样性惩罚，
并给出「离线暴力破解估算时间」，比「弱/中/强」三个字有说服力。
"""
from __future__ import annotations

import math
import re

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "admin",
    "111111", "abc123", "password1", "letmein", "welcome", "iloveyou",
    "666666", "888888", "a123456", "1234567890", "admin123", "root",
}

LOWER = set("abcdefghijklmnopqrstuvwxyz")
UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGIT = set("0123456789")
SYMBOL = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")


def classes_used(password: str) -> int:
    n = 0
    for s in (LOWER, UPPER, DIGIT, SYMBOL):
        if any(ch in s for ch in password):
            n += 1
    return n


def _pool_size(password: str) -> int:
    pool = 0
    if any(ch in LOWER for ch in password):
        pool += 26
    if any(ch in UPPER for ch in password):
        pool += 26
    if any(ch in DIGIT for ch in password):
        pool += 10
    if any(ch in SYMBOL for ch in password):
        pool += 33
    return max(pool, 2)


def entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    bits = len(password) * math.log2(_pool_size(password))
    # 重复字符惩罚（如 aaaaaa 或 123123）
    uniq = len(set(password))
    if uniq <= 2:
        bits *= 0.5
    if re.search(r"(.)\1{2,}", password):
        bits *= 0.8
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|qwe)", password.lower()):
        bits *= 0.85
    return round(bits, 1)


def guess_count(password: str) -> float:
    return 2 ** entropy_bits(password)


def crack_seconds(password: str, guesses_per_sec: float = 1e10) -> float:
    """离线暴力破解估算时间（秒）。默认 1e10 次/秒 ≈ 高端多卡 GPU。"""
    return guess_count(password) / guesses_per_sec


def humanize_seconds(sec: float) -> str:
    units = [("年", 31557600), ("天", 86400), ("小时", 3600), ("分钟", 60), ("秒", 1)]
    if sec < 1:
        return "瞬间"
    for name, mul in units:
        if sec >= mul:
            v = sec / mul
            if v > 1e6:
                return f"{v:.2e} {name}"
            return f"{v:,.1f} {name}"
    return "瞬间"


def password_strength(password: str) -> tuple[int, str]:
    """返回 (等级 0-4, 描述)。等级 0 最弱。"""
    if not password:
        return 0, "空"
    bits = entropy_bits(password)
    if password.lower() in COMMON or len(password) < 6:
        return 0, "极弱（常见/过短）"
    if bits < 40:
        return 1, "弱"
    if bits < 60:
        return 2, "中等"
    if bits < 80:
        return 3, "强"
    return 4, "极强"


def check_password_policy(password: str, min_len: int = 12,
                          require_classes: int = 3) -> tuple[bool, str]:
    """返回 (是否通过, 原因)。"""
    if len(password) < min_len:
        return False, f"长度不足：至少 {min_len} 位（当前 {len(password)} 位）"
    if password.lower() in COMMON:
        return False, "该密码在常见弱口令列表中"
    if classes_used(password) < require_classes:
        return False, f"字符种类不足：至少需要 {require_classes} 类（大写/小写/数字/符号）"
    level, desc = password_strength(password)
    if level < 2:
        return False, f"强度不足：{desc}（估算熵 {entropy_bits(password)} bits）"
    return True, "通过"


def suggest(min_len: int = 16) -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(min_len))
        if check_password_policy(pwd, min_len, 3)[0]:
            return pwd
