# -*- coding: utf-8 -*-
"""app/services/ai/policy.py
===========================
AI 助手安全限制（离线优先、最小暴露）。

约束目标
--------
1. 默认离线：AI 出网必须由用户在界面显式勾选同意；
2. 出网前脱敏：路径、文件名、密文块、密钥等替换为占位符（见 sanitize 模块）；
3. 提示注入防护：拦截「忽略上面的指令」等典型越狱话术；
4. 敏感内容防护：识别长 hex/base32、私钥块、疑似 API Key、绝对路径，避免误发；
5. 会话额度：限制单次会话的请求数 / 字符数 / 最小请求间隔，避免被当作免费代理；
6. 系统提示词硬约束：不索取/复述密码与密钥，不提供绕过加密、破解口令的指引；
7. 审计只记元数据，不记对话正文。

本模块不依赖网络库，可在任何前端复用。
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ... import meta


class PolicyViolation(Exception):
    """请求被安全策略拦截。"""

    def __init__(self, reason: str, kind: str = "blocked"):
        super().__init__(reason)
        self.reason = reason
        self.kind = kind


# ------------------------------------------------------------
# 系统提示词硬约束（随请求下发，约束模型行为）
# ------------------------------------------------------------
SYSTEM_GUARD = (
    "You are an assistant embedded in a LOCAL, OFFLINE-first encryption toolbox.\n"
    "STRICT RULES (never break these):\n"
    "1. Never ask for, request, echo, guess, or reconstruct the user's password, "
    "master key, key file, or recovery code.\n"
    "2. Never output encryption keys, salts, derived keys, or decrypted plaintext.\n"
    "3. Never provide instructions to bypass, crack, backdoor, or defeat encryption, "
    "or to recover data without the key file / password.\n"
    "4. If potential key exposure is suspected, advise rotating the password and "
    "re-exporting the key file.\n"
    "5. Do not invent features this tool does not have; say you are unsure when unclear.\n"
    "6. All cryptographic operations happen locally; you have no access to any key.\n"
)


# ------------------------------------------------------------
# 提示注入 / 越狱特征
# ------------------------------------------------------------
_INJECTION_PATTERNS = [
    r"忽略(上面|之前|以上|前面).{0,6}(指令|规则|设定|要求)",
    r"(无视|绕过|突破|破解).{0,6}(限制|规则|安全|审查|策略)",
    r"(进入|开启).{0,4}(开发者|上帝|越狱|DAN).{0,4}模式",
    r"(ignore|disregard|forget).{0,12}(previous|above|prior|earlier).{0,12}(instruction|rule|prompt)",
    r"(jailbreak|DAN mode|developer mode)",
    r"(reveal|show|print|repeat).{0,12}(system prompt|your instructions|hidden prompt)",
    r"(导出|输出|打印).{0,6}(系统提示|内部指令|隐藏指令)",
]

# ------------------------------------------------------------
# 敏感内容特征（疑似密钥 / 私钥 / 口令材料）
# ------------------------------------------------------------
_SENSITIVE_PATTERNS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "疑似私钥内容"),
    (r"\b(?:sk|pk)-[A-Za-z0-9]{16,}\b", "疑似 API Key"),
    (r"\b[A-Fa-f0-9]{64,}\b", "疑似长十六进制密钥/摘要"),
    (r"\b[A-Z2-7]{40,}\b", "疑似长 Base32 密钥"),
    (r"(?i)(password|passwd|密钥|口令)\s*[:=：]\s*\S{6,}", "疑似明文口令"),
]


@dataclass
class PolicyLimits:
    max_input_chars: int = 8000
    max_requests_per_session: int = 40
    max_chars_per_session: int = 120_000
    min_interval_seconds: float = 1.0
    block_injection: bool = True
    block_sensitive: bool = True
    max_history_turns: int = 8


class AIPolicy:
    """会话级安全策略执行器。"""

    def __init__(self, limits: PolicyLimits | None = None):
        self.limits = limits or PolicyLimits()
        self._requests = 0
        self._chars = 0
        self._last_ts = 0.0
        self._injection = [re.compile(p) for p in _INJECTION_PATTERNS]
        self._sensitive = [(re.compile(p), msg) for p, msg in _SENSITIVE_PATTERNS]

    # ---------- 状态 ----------
    def reset(self) -> None:
        self._requests = 0
        self._chars = 0
        self._last_ts = 0.0

    def usage(self) -> dict:
        return {
            "requests": self._requests,
            "chars": self._chars,
            "max_requests": self.limits.max_requests_per_session,
            "max_chars": self.limits.max_chars_per_session,
        }

    # ---------- 输入筛查 ----------
    def check_text(self, text: str) -> None:
        """对单条用户输入做注入与敏感内容筛查；不合格即抛 PolicyViolation。"""
        if text is None:
            return
        if len(text) > self.limits.max_input_chars:
            raise PolicyViolation(
                f"输入过长（{len(text)} > {self.limits.max_input_chars} 字符）", "too_long"
            )
        if self.limits.block_injection:
            for pat in self._injection:
                if pat.search(text):
                    raise PolicyViolation(
                        "检测到疑似提示注入（试图改变助手规则），已拦截。", "injection"
                    )
        if self.limits.block_sensitive:
            for pat, msg in self._sensitive:
                if pat.search(text):
                    raise PolicyViolation(
                        f"{msg}：出于安全考虑，请勿把密钥材料发送给 AI。", "sensitive"
                    )

    # ---------- 请求前额度 / 频率检查 ----------
    def before_request(self, text: str = "") -> None:
        if self._requests >= self.limits.max_requests_per_session:
            raise PolicyViolation("本次会话请求数已达上限，请重置会话。", "quota")
        if self._chars + len(text or "") > self.limits.max_chars_per_session:
            raise PolicyViolation("本次会话已发送字符数达上限，请重置会话。", "quota")
        now = time.time()
        wait = self.limits.min_interval_seconds - (now - self._last_ts)
        if wait > 0:
            raise PolicyViolation(f"请求过于频繁，请等待 {wait:.1f} 秒。", "rate")

    def record(self, text: str = "") -> None:
        self._requests += 1
        self._chars += len(text or "")
        self._last_ts = time.time()

    # ---------- 历史裁剪 ----------
    def trim_history(self, history: list) -> list:
        n = self.limits.max_history_turns * 2
        return history[-n:] if history and len(history) > n else (history or [])


# 默认单例
_DEFAULT = AIPolicy()


def get_policy() -> AIPolicy:
    return _DEFAULT


def system_guard() -> str:
    """系统提示词前缀（含作者标识，便于审计溯源）。"""
    return SYSTEM_GUARD + f"\n[embedded by {meta.AUTHOR_TAG}]\n"
