# -*- coding: utf-8 -*-
"""
app/services/ai/client.py
=========================
DeepSeek V4.1 Flash 客户端（OpenAI 兼容 Chat Completions）。

硬约束
------
1. 默认离线（offline=True），未显式关闭前不发起任何网络请求；
2. API Key 用主密钥派生子密钥加密落盘（见 save_api_key / load_api_key）；
3. 出网前脱敏（sanitize）；
4. 本模块不写 operation.log，只写 ai_audit.log 元数据。
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    import requests
except ImportError:                       # 无 requests 时仍可 import，仅离线可用
    requests = None

from ...core import cipher, kdf
from ...paths import log_dir
from . import policy as _policy
from .sanitize import sanitize

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-flash"          # = DeepSeek-V4.1-Flash
LEGACY_MODELS = ("deepseek-v4-flash", "deepseek-v4-flash-vision-exp")
CHAT_PATH = "/chat/completions"
SECRET_FILENAME = "ai_secret.bin"
AUDIT_FILE = "ai_audit.log"
SECRET_KDF_SALT = b"aes256-tool::ai-secret::v1"


# ============================================================
# 异常
# ============================================================
class AIError(RuntimeError):
    """AI 层统一异常基类。"""


class AIOfflineError(AIError):
    pass


class AIAuthError(AIError):
    pass


class AIRateLimitError(AIError):
    pass


class AICancelled(AIError):
    pass


class AISafetyError(AIError):
    """请求被本地 AI 安全策略拦截（注入 / 敏感 / 额度 / 离线守卫）。"""


# ============================================================
# 结果
# ============================================================
@dataclass
class ChatResult:
    content: str = ""
    reasoning: str = ""
    model: str = ""
    finish_reason: str = ""
    usage: dict = field(default_factory=dict)
    elapsed: float = 0.0

    @property
    def cache_hit(self) -> int:
        return int(self.usage.get("prompt_cache_hit_tokens", 0))

    @property
    def cache_miss(self) -> int:
        return int(self.usage.get("prompt_cache_miss_tokens", 0))

    @property
    def reasoning_tokens(self) -> int:
        return int(self.usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0))

    @property
    def total_tokens(self) -> int:
        return int(self.usage.get("total_tokens", 0))


# ============================================================
# 审计（只记元数据）
# ============================================================
def audit_meta(event: str, detail: str = "") -> None:
    try:
        p = log_dir() / AUDIT_FILE
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {event} | {detail}\n"
        with open(p, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


# ============================================================
# API Key 加密落盘
# ============================================================
def save_api_key(master: bytes, api_key: str) -> Path:
    sub = kdf.derive_file_key(master, SECRET_KDF_SALT)
    blob = cipher.encrypt_bytes(api_key.encode("utf-8"), sub, aad=b"ai-secret")
    p = log_dir() / SECRET_FILENAME
    p.write_bytes(blob)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    audit_meta("key_saved", "API Key 已加密落盘")
    return p


def load_api_key(master: bytes) -> str:
    p = log_dir() / SECRET_FILENAME
    if not p.exists():
        return ""
    sub = kdf.derive_file_key(master, SECRET_KDF_SALT)
    return cipher.decrypt_bytes(p.read_bytes(), sub, aad=b"ai-secret").decode("utf-8")


def has_saved_key() -> bool:
    return (log_dir() / SECRET_FILENAME).exists()


def delete_saved_key() -> None:
    (log_dir() / SECRET_FILENAME).unlink(missing_ok=True)
    audit_meta("key_deleted", "API Key 已删除")


# ============================================================
# 客户端
# ============================================================
class DeepSeekClient:
    """线程安全、可取消的 DeepSeek 客户端。"""

    def __init__(self, api_key: str = "", model: str = DEFAULT_MODEL,
                 base_url: str = DEFAULT_BASE_URL, offline: bool = True,
                 timeout: tuple = (10, 180), max_retry: int = 2):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.model = model or DEFAULT_MODEL
        self.offline = bool(offline)
        self.timeout = tuple(timeout)
        self.max_retry = int(max_retry)
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self._cancel = threading.Event()
        self._session = None
        self._policy = _policy.AIPolicy()

    # ---------- 状态 ----------
    @property
    def api_key(self) -> str:
        return self._api_key

    @property
    def ready(self) -> bool:
        return (not self.offline) and bool(self._api_key) and requests is not None

    def set_api_key(self, key: str) -> None:
        self._api_key = (key or "").strip()

    def clear_api_key(self) -> None:
        self._api_key = ""

    def set_offline(self, offline: bool) -> None:
        self.offline = bool(offline)

    def cancel(self) -> None:
        self._cancel.set()

    def _reset_cancel(self) -> None:
        self._cancel.clear()

    def close(self) -> None:
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    # ---------- 内部 ----------
    def _get_session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            })
        return self._session

    def _build_payload(self, messages, thinking, reasoning_effort, stream,
                       max_tokens, temperature, response_format, tools) -> dict:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": bool(stream),
            "thinking": {"type": "enabled" if thinking else "disabled"},
        }
        if thinking:
            payload["reasoning_effort"] = reasoning_effort or "high"
        elif temperature is not None:
            payload["temperature"] = float(temperature)
        if stream:
            payload["stream_options"] = {"include_usage": True}
        if max_tokens:
            payload["max_tokens"] = int(max_tokens)
        if response_format:
            payload["response_format"] = response_format
        if tools:
            payload["tools"] = tools
        return payload

    def _check_preconditions(self) -> None:
        if self.offline:
            raise AIOfflineError("AI 助手处于离线模式。请在界面中显式勾选「允许联网」后重试。")
        if requests is None:
            raise AIError("缺少依赖 requests：pip install requests")
        if not self._api_key:
            raise AIAuthError("未配置 DeepSeek API Key。")
        # 离线守卫：若已启用，出网前显式校验目标主机是否放行
        try:
            from ...core import netguard

            netguard.check_host(self.base_url.split("//")[-1].split("/")[0])
        except Exception as exc:
            from ...core.netguard import NetworkBlocked

            if isinstance(exc, NetworkBlocked):
                raise AISafetyError(str(exc)) from exc

    def _enforce_policy(self, messages: list, staged: list | None = None) -> None:
        """对用户输入做安全策略检查（注入 / 敏感 / 额度 / 频率）。"""
        text = "\n".join(m.get("content", "") for m in messages
                         if m.get("role") == "user" and isinstance(m.get("content"), str))
        self._policy.before_request(text)
        try:
            self._policy.check_text(text)
        except _policy.PolicyViolation as exc:
            audit_meta("policy_block", exc.kind)
            raise AISafetyError(exc.reason) from exc
        self._policy.record(text)

    def _raise_for_status(self, resp) -> None:
        code = resp.status_code
        if code == 200:
            return
        try:
            detail = resp.json().get("error", {}).get("message", resp.text[:300])
        except Exception:
            detail = resp.text[:300]
        if code in (401, 403):
            raise AIAuthError(f"鉴权失败（{code}）：{detail}")
        if code == 402:
            raise AIError(f"余额不足（402）：{detail}")
        if code == 429:
            raise AIRateLimitError(f"触发限流（429）：{detail}")
        if code >= 500:
            raise AIError(f"服务端错误（{code}）：{detail}")
        raise AIError(f"请求失败（{code}）：{detail}")

    # ---------- 主接口 ----------
    def chat(self, messages: list, *, thinking: bool = True, reasoning_effort: str = "high",
             stream: bool = True, max_tokens: Optional[int] = None,
             temperature: Optional[float] = None, response_format: Optional[dict] = None,
             tools: Optional[list] = None,
             on_reasoning: Optional[Callable[[str], None]] = None,
             on_content: Optional[Callable[[str], None]] = None,
             sanitize_out: bool = True) -> ChatResult:
        self._check_preconditions()
        self._reset_cancel()

        # 安全策略：注入 / 敏感内容 / 会话额度 / 频率
        self._enforce_policy(messages)

        # 对话历史裁剪，避免上下文无限增长
        messages = self._policy.trim_history(messages)

        if sanitize_out:
            messages = self._sanitize_messages(messages)

        payload = self._build_payload(messages, thinking, reasoning_effort, stream,
                                      max_tokens, temperature, response_format, tools)
        url = f"{self.base_url}{CHAT_PATH}"
        result = ChatResult(model=self.model)
        started = time.time()
        audit_meta("request", f"model={self.model} thinking={thinking} stream={stream}")

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retry + 1):
            if self._cancel.is_set():
                raise AICancelled("已取消")
            try:
                resp = self._get_session().post(url, json=payload, stream=stream,
                                                timeout=self.timeout)
                self._raise_for_status(resp)
                if stream:
                    self._consume_stream(resp, result, on_reasoning, on_content)
                else:
                    self._consume_once(resp, result)
                result.elapsed = time.time() - started
                audit_meta("response",
                           f"finish={result.finish_reason} tokens={result.total_tokens} "
                           f"elapsed={result.elapsed:.1f}s")
                return result
            except (AIAuthError, AIOfflineError, AICancelled):
                raise
            except (AIRateLimitError, AIError) as exc:
                last_err = exc
            except Exception as exc:
                last_err = AIError(f"网络异常：{type(exc).__name__}: {exc}")

            if attempt < self.max_retry:
                wait = 1.6 ** attempt
                for _ in range(int(wait * 10)):
                    if self._cancel.is_set():
                        raise AICancelled("已取消")
                    time.sleep(0.1)

        audit_meta("error", str(last_err))
        raise AIError(str(last_err) if last_err else "未知错误")

    def ask(self, question: str, *, system: Optional[str] = None,
            history: Optional[list] = None, **kwargs) -> str:
        from .prompts import system_prompt

        messages = [{"role": "system", "content": system or system_prompt()}]
        messages.extend(history or [])
        messages.append({"role": "user", "content": question})
        return self.chat(messages, **kwargs).content

    # ---------- 安全策略 ----------
    @property
    def policy(self) -> "_policy.AIPolicy":
        return self._policy

    def policy_usage(self) -> dict:
        return self._policy.usage()

    def reset_policy(self) -> None:
        self._policy.reset()

    # ---------- 解析 ----------
    def _consume_once(self, resp, result: ChatResult) -> None:
        data = resp.json()
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        result.content = msg.get("content") or ""
        result.reasoning = msg.get("reasoning_content") or ""
        result.finish_reason = choice.get("finish_reason", "")
        result.usage = data.get("usage", {}) or {}
        result.model = data.get("model", self.model)

    def _consume_stream(self, resp, result, on_reasoning, on_content) -> None:
        for raw in resp.iter_lines(decode_unicode=False):
            if self._cancel.is_set():
                resp.close()
                raise AICancelled("已取消")
            if not raw:
                continue
            line = raw.decode("utf-8", "ignore").strip()
            if not line.startswith("data:"):
                continue
            body = line[5:].strip()
            if body == "[DONE]":
                break
            try:
                chunk = json.loads(body)
            except json.JSONDecodeError:
                continue

            if chunk.get("usage"):
                result.usage = chunk["usage"]
            result.model = chunk.get("model", result.model)

            for choice in chunk.get("choices", []) or []:
                delta = choice.get("delta", {}) or {}
                piece_r = delta.get("reasoning_content")
                piece_c = delta.get("content")
                if piece_r:
                    result.reasoning += piece_r
                    if on_reasoning:
                        on_reasoning(piece_r)
                if piece_c:
                    result.content += piece_c
                    if on_content:
                        on_content(piece_c)
                if choice.get("finish_reason"):
                    result.finish_reason = choice["finish_reason"]

    # ---------- 脱敏 ----------
    @staticmethod
    def _sanitize_messages(messages: list) -> list:
        out = []
        for m in messages:
            m2 = dict(m)
            if isinstance(m2.get("content"), str):
                m2["content"] = sanitize(m2["content"])
            out.append(m2)
        return out

    # ---------- 成本估算 ----------
    def estimate_cost(self, result: ChatResult, pricing: Optional[dict] = None) -> float:
        p = pricing or {}
        hit = result.cache_hit / 1_000_000 * float(p.get("in_hit", 0) or 0)
        miss = result.cache_miss / 1_000_000 * float(p.get("in_miss", 0) or 0)
        out = int(result.usage.get("completion_tokens", 0)) / 1_000_000 * float(p.get("out", 0) or 0)
        return round(hit + miss + out, 6)
