# -*- coding: utf-8 -*-
"""
app/services/ai/prompts.py
==========================
系统提示词集中管理。

安全约束写进系统提示，但不依赖它做安全 —— 真正的边界是离线闸门 + 脱敏。
"""
from __future__ import annotations

BASE_GUARD = """你是 AES-256 加密工具箱的内置助手。

可以做：
1. 解释本工具的报错日志、退出码与常见故障原因；
2. 解释加密参数（KDF、GCM、chunk、salt/nonce、HKDF）的含义与取舍；
3. 生成操作步骤、检查清单、命令示例；
4. 起草文档、说明文字、更新日志。

绝对禁止：
- 索要、复述、推测用户的密码、主密钥、密钥文件内容或恢复码；
- 提供任何绕过加密、破解口令、逆向密文的建议；
- 声称本工具存在实际没有的功能；
- 帮用户判断"这个密码够不够用"以外的密码本身内容。

遇到疑似密钥泄露线索时：先提醒导出密钥文件、轮换密码，再谈其它。"""


def system_prompt(mode: str = "default") -> str:
    extra = {
        "default": "",
        "log": "\n\n当前场景：用户在排查报错日志。请先定位失败环节，再给排查顺序，最后给最小验证步骤。",
        "docs": "\n\n当前场景：用户在撰写项目文档。请使用 Markdown，标题层级清晰，避免空话。",
        "beginner": "\n\n当前场景：用户是新手。请用最简单的话解释，先说做什么，再说为什么。",
    }.get(mode, "")
    return BASE_GUARD + extra


LOG_TEMPLATE = """请帮我分析下面这段 AES-256 工具箱日志，指出：
1) 最可能的失败环节；
2) 按优先级排列的排查步骤；
3) 一个最小验证命令。

日志（已脱敏）：
{log}
"""


def log_analysis_prompt(log_tail: str, limit: int = 4000) -> str:
    from .sanitize import sanitize

    return LOG_TEMPLATE.format(log=sanitize(log_tail[-limit:]))
