# -*- coding: utf-8 -*-
"""app/meta.py
=============
应用元数据与作者信息（唯一真源）。

作者信息会写入加密容器头部、关于对话框、审计报告与生成的分享页，
便于溯源与联系作者。请勿在其它文件里硬编码这些字符串。
"""
from __future__ import annotations

APP_NAME = "AES-256 加密工具箱"
APP_NAME_EN = "AES-256 Encryption Toolbox"
APP_ID = "aes256-tool"
VERSION = "1.3.0"

AUTHOR = "Qingniao"
AUTHOR_ZH = "青鸟"
AUTHOR_EMAIL = "qingniao2007@126.com"

HOMEPAGE = ""
LICENSE = "MIT"

# 容器头部 / 分享页统一写入的短标识
AUTHOR_TAG = f"{AUTHOR} <{AUTHOR_EMAIL}>"


def author_line(lang: str = "zh_CN") -> str:
    name = AUTHOR_ZH if lang == "zh_CN" else AUTHOR
    return f"{name} <{AUTHOR_EMAIL}>"


def about_text(lang: str = "zh_CN") -> str:
    """关于页正文（中英双语）。"""
    if lang == "zh_CN":
        return (
            f"{APP_NAME}\n"
            f"版本：{VERSION}\n\n"
            f"作者：{AUTHOR_ZH}（{AUTHOR}）\n"
            f"邮箱：{AUTHOR_EMAIL}\n"
            f"许可：{LICENSE}\n\n"
            "本地离线加密工具箱：默认不联网，密钥与明文均不出本机。\n"
            "支持多种加密算法与叠加加密；无论叠加多少种，始终只使用一个总密钥。"
        )
    return (
        f"{APP_NAME_EN}\n"
        f"Version: {VERSION}\n\n"
        f"Author: {AUTHOR}\n"
        f"Email: {AUTHOR_EMAIL}\n"
        f"License: {LICENSE}\n\n"
        "Offline encryption toolbox: network is off by default; keys and "
        "plaintext never leave your machine.\n"
        "Supports multiple ciphers and stacked encryption; regardless of how "
        "many ciphers are stacked, only a single master key is used."
    )
