# -*- coding: utf-8 -*-
"""tests/conftest.py · 隔离日志目录，避免污染真实 aes_log"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def isolated_base(tmp_path, monkeypatch):
    """把可写根目录重定向到临时目录，日志/DB 全部写进 tmp。"""
    import app.paths as paths

    monkeypatch.setattr(paths, "base_dir", lambda: tmp_path)
    import app.config as config

    monkeypatch.setattr(config, "base_dir", lambda: tmp_path)
    import app.services.ai.client as aiclient

    monkeypatch.setattr(aiclient, "log_dir", lambda: tmp_path / "aes_log")
    (tmp_path / "aes_log").mkdir(exist_ok=True)
    yield tmp_path
