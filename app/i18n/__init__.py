# -*- coding: utf-8 -*-
"""app/i18n/__init__.py
=====================
运行时中英双语切换。

用法
----
    from app import i18n
    i18n.set_language("en_US")
    btn.setText(i18n.tr("cipher.title"))
    i18n.tr("cipher.max_layers", n=4)

语言状态可通过 config 持久化（见 app.config.get_language / set_language）。
本模块保持零依赖，Qt/Tk/CLI 均可直接使用。
"""
from __future__ import annotations

from .catalog import CATALOG, DEFAULT_LANG, SUPPORTED, LANG_LABELS

_lang = DEFAULT_LANG


def available() -> list[str]:
    return list(SUPPORTED)


def label(code: str, ui_lang: str | None = None) -> str:
    ui = ui_lang or _lang
    return LANG_LABELS.get(code, {}).get(ui, code)


def current_language() -> str:
    return _lang


def set_language(lang: str) -> str:
    global _lang
    if lang in SUPPORTED:
        _lang = lang
    return _lang


def tr(key: str, lang: str | None = None, **kwargs) -> str:
    """取文案；缺失时回退默认语言，再缺失则返回键名本身。"""
    active = lang or _lang
    table = CATALOG.get(active, {})
    text = table.get(key)
    if text is None:
        text = CATALOG.get(DEFAULT_LANG, {}).get(key)
    if text is None:
        text = key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text


def describe(field: dict | None, lang: str | None = None) -> str:
    """从 {zh_CN, en_US} 形式的字典里取当前语言的描述。"""
    if not field:
        return ""
    active = lang or _lang
    return field.get(active) or field.get(DEFAULT_LANG) or next(iter(field.values()), "")


# 常用别名
_ = tr
