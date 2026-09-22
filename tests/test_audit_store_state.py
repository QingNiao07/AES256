# -*- coding: utf-8 -*-
"""tests/test_audit_store_state.py · 审计链 / SQLite / 状态"""
import time

from app.core import audit, store
from app.core import state as core_state


# ---- 审计链 ----
def test_audit_chain_intact():
    audit.append("info", "test_a", "1")
    audit.append("warn", "test_b", "2")
    ok, msg = audit.verify()
    assert ok, msg


def test_audit_chain_detects_tamper(tmp_path, monkeypatch):
    audit.append("info", "e1", "x")
    audit.append("info", "e2", "y")
    audit.append("info", "e3", "z")
    # 直接篡改链文件中间一行
    import json

    p = audit.log_dir() / audit.CHAIN_FILE
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["detail"] = "HACKED"
    lines[1] = json.dumps(rec, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = audit.verify()
    assert not ok
    assert "篡改" in msg


def test_audit_html_report(tmp_path):
    audit.append("info", "report_test", "内容")
    p = audit.write_html_report(tmp_path / "r.html")
    assert p.exists() and "审计报告" in p.read_text(encoding="utf-8")


# ---- SQLite ----
def test_store_record_and_stats():
    store.init()
    store.record("encrypt", "a.txt", "a.aes256", 100, True)
    store.record("decrypt", "a.aes256", "a.txt", 100, True)
    s = store.stats()
    assert s["count"] >= 2
    assert s["by_action"].get("encrypt", 0) >= 1
    rows = store.recent(10)
    assert rows and rows[0]["action"] in ("encrypt", "decrypt")


# ---- 状态 ----
def test_state_lifecycle(tmp_path):
    m = b"\x01" * 32
    core_state.set_master(m)
    assert core_state.has_master()
    assert core_state.get_master() == m
    core_state.clear()
    assert not core_state.has_master()


def test_state_timeout():
    core_state.set_master(b"\x02" * 32)
    core_state.set_timeout(1)
    core_state._last_active = time.time() - 10
    assert core_state.expired()
    assert core_state.check_timeout()
    assert not core_state.has_master()


def test_compat_shim_attribute():
    import aes256_core as core

    core.set_master(b"\x03" * 32)
    assert core.cached_master == b"\x03" * 32
    core.clear_keys()
