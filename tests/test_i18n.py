# -*- coding: utf-8 -*-
"""tests/test_i18n.py
中英双语：目录完整性、回退、参数格式化。
"""
from app import i18n
from app.i18n.catalog import CATALOG


def test_supported_languages():
    assert set(i18n.available()) == {"zh_CN", "en_US"}


def test_set_and_current():
    original = i18n.current_language()
    try:
        i18n.set_language("en_US")
        assert i18n.current_language() == "en_US"
        i18n.set_language("zh_CN")
        assert i18n.current_language() == "zh_CN"
        # 非法语言不改变状态
        i18n.set_language("fr_FR")
        assert i18n.current_language() == "zh_CN"
    finally:
        i18n.set_language(original)


def test_catalog_keys_consistent():
    zh = set(CATALOG["zh_CN"].keys())
    en = set(CATALOG["en_US"].keys())
    assert zh == en, f"中英文案键不一致：{zh ^ en}"


def test_translation_values_differ_and_nonempty():
    for key in CATALOG["zh_CN"]:
        assert CATALOG["zh_CN"][key].strip()
        assert CATALOG["en_US"][key].strip()


def test_tr_formatting_and_fallback():
    original = i18n.current_language()
    try:
        i18n.set_language("en_US")
        assert "master key" in i18n.tr("cipher.single_key_hint").lower()
        assert "4" in i18n.tr("cipher.max_layers", n=4)
        assert i18n.tr("does.not.exist") == "does.not.exist"
    finally:
        i18n.set_language(original)


def test_describe_helper():
    field = {"zh_CN": "中文", "en_US": "English"}
    assert i18n.describe(field, "zh_CN") == "中文"
    assert i18n.describe(field, "en_US") == "English"
    assert i18n.describe(None) == ""
