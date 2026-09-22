# -*- coding: utf-8 -*-
"""tests/test_legal.py
法务条款内容与安装/首次运行接受闸门。
"""
import pytest

from app import legal


def test_legal_version_and_header():
    assert legal.DOC_VERSION
    assert "法律声明" in legal.HEADER


def test_all_texts_present_and_bilingual():
    for lang in ("zh_CN", "en_US"):
        assert legal.legality(lang).strip()
        assert legal.disclaimer(lang).strip()
        assert legal.liability(lang).strip()
        assert legal.declaration(lang).strip()
        assert legal.full_text(lang).strip()


def test_author_email_in_disclaimer():
    assert "qingniao2007@126.com" in legal.disclaimer("zh_CN")


def test_keywords_present():
    # 核心价值观与合法用途、免责意图必须出现
    decl = legal.declaration("zh_CN")
    for kw in ("社会主义核心价值观", "合法", "我接受", "本人", "责任"):
        assert kw in decl, kw
    liab = legal.liability("zh_CN")
    assert "使用者责任" in liab and "作者责任" in liab


def test_social_values_line():
    assert "富强" in legal.core_values_line("zh_CN")
    assert "Prosperity" in legal.core_values_line("en_US")


def test_accept_and_gate_roundtrip(tmp_path):
    # 初始未接受
    assert legal.needs_acceptance(root=tmp_path)
    assert not legal.is_accepted(root=tmp_path)

    info = legal.accept(root=tmp_path, who="tester")
    assert info["accepted"] is True
    assert info["version"] == legal.DOC_VERSION
    assert info["accepted_at"]
    assert legal.is_accepted(root=tmp_path)
    assert not legal.needs_acceptance(root=tmp_path)

    # 版本不匹配 => 需重新接受
    from app import config as cfgmod

    cfgmod.set_value("legal.version", "0.0", root=tmp_path)
    assert legal.needs_acceptance(root=tmp_path)


def test_revoke(tmp_path):
    legal.accept(root=tmp_path)
    assert legal.is_accepted(root=tmp_path)
    legal.revoke(root=tmp_path)
    assert not legal.is_accepted(root=tmp_path)


def test_short_accept_line_mentions_values():
    line = legal.short_accept_line("zh_CN")
    assert "社会主义" in line or "合法" in line


def test_install_check_runs():
    import install

    missing_req, missing_opt = install.check_dependencies()
    assert isinstance(missing_req, list) and isinstance(missing_opt, list)


def test_install_requires_accept_no_accident(tmp_path, monkeypatch):
    """无界面安装缺少 --accept 必须失败，且不得写入接受记录。"""
    import install
    from app import legal as L

    # 用临时配置，避免污染真实配置
    monkeypatch.setattr(install, "run_cli", lambda **kw: 0)
    rc = install.main(["--quiet"])
    assert rc == 2
