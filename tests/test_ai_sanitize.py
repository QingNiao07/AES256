# -*- coding: utf-8 -*-
"""tests/test_ai_sanitize.py · AI 脱敏与离线闸门（不发起真实网络请求）"""
import pytest

from app.services.ai import AIOfflineError, DeepSeekClient
from app.services.ai.sanitize import diff_summary, sanitize


def test_sanitize_paths():
    s = sanitize(r"错误：D:\Users\bob\secret\data.bin 打开失败")
    assert "D:\\Users" not in s
    assert "<PATH>" in s or "<FILE>" in s


def test_sanitize_posix_path():
    s = sanitize("读取 /home/alice/private/key.aes256 失败")
    assert "/home/alice" not in s


def test_sanitize_blob():
    blob = "A" * 200
    assert "<BLOB>" in sanitize(f"密文：{blob}")


def test_sanitize_credential():
    s = sanitize("password=MyS3cret123!")
    assert "MyS3cret123" not in s
    assert "<CREDENTIAL>" in s


def test_sanitize_keeps_normal_text():
    text = "时间 2025-01-01，任务完成，共处理 3 个文件。"
    assert sanitize(text) == text


def test_diff_summary_flag():
    assert diff_summary("password=abc").get("changed") is True
    assert diff_summary("普通文本").get("changed") is False


def test_offline_gate_blocks_request():
    client = DeepSeekClient(api_key="dummy", offline=True)
    with pytest.raises(AIOfflineError):
        client.chat([{"role": "user", "content": "hi"}], stream=False)


def test_online_without_key_raises():
    client = DeepSeekClient(api_key="", offline=False)
    # requests 已安装；无 key 必须拒绝，且不得真正联网
    with pytest.raises(Exception):
        client.chat([{"role": "user", "content": "hi"}], stream=False)
