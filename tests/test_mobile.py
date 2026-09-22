# -*- coding: utf-8 -*-
"""tests/test_mobile.py
======================
移动版互通能力测试。

覆盖：
1. 桌面端 `--kdf pbkdf2` 路径生成的 v4 容器可被同进程解密（自描述头部）。
2. 容器头部记录的 KDF 名为 pbkdf2、算法链为 [aes-256-gcm]（与移动端约定一致）。
3. 移动端 JS 核心的关键常量与桌面端一致（MAGIC、KDF 编号、迭代数）。
4. CLI 解析器包含 --kdf / --kdf-iters 选项，且 --kdf pbkdf2 会走 v4 分支。
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core import kdf, multicipher  # noqa: E402

JS_PATH = ROOT / "mobile" / "www" / "js" / "v4crypto.js"


def _encrypt_pbkdf2(tmp_path: Path, password: str = "interop-Pass-2026") -> Path:
    src = tmp_path / "hello.txt"
    src.write_text("移动互联互通测试" * 50, encoding="utf-8")
    dst = tmp_path / "hello.txt.aes256"
    salt = kdf.new_salt(16)
    iters = 120_000  # 测试用低迭代，加速
    recipe = {"salt": salt, "kdf_name": "pbkdf2", "time_cost": 0,
              "memory_cost": 0, "parallelism": 0, "iterations": iters}
    master = kdf.derive_master_custom(password, salt, kdf_name="pbkdf2", iterations=iters)
    multicipher.encrypt_stream(src, dst, master, ["aes-256-gcm"],
                               chunk_size=4096, kdf_salt=salt, kdf_recipe=recipe)
    return dst


def test_pbkdf2_v4_roundtrip(tmp_path):
    blob = _encrypt_pbkdf2(tmp_path)
    assert multicipher.is_v4(blob)
    out = tmp_path / "hello.out"
    src = tmp_path / "hello.txt"
    r = multicipher.decrypt_stream_password(blob, out, "interop-Pass-2026")
    assert out.read_bytes() == src.read_bytes()
    assert r["chain"] == ["aes-256-gcm"]


def test_pbkdf2_header_self_describes(tmp_path):
    blob = _encrypt_pbkdf2(tmp_path)
    meta = multicipher.read_meta(blob)
    assert meta["kdf_id"] == multicipher.KDF_PBKDF2
    assert meta["chain"] == ["aes-256-gcm"]
    assert meta["kdf_iters"] == 120_000


def test_wrong_password_rejected(tmp_path):
    blob = _encrypt_pbkdf2(tmp_path)
    ok, msg = multicipher.decrypt_file_password(blob, tmp_path / "x.out", "wrong")
    assert ok is False


@pytest.mark.skipif(not JS_PATH.exists(), reason="未找到移动端 JS 核心")
def test_js_constants_match_python(tmp_path):
    js = JS_PATH.read_text(encoding="utf-8")
    assert re.search(r'CONTAINER_MAGIC\s*=\s*"AES256v4"', js)
    assert re.search(r"KDF_PBKDF2\s*=\s*2", js)
    assert re.search(r"KDF_ARGON2\s*=\s*1", js)
    assert re.search(r"DEFAULT_ITERATIONS\s*=\s*600000", js)
    assert re.search(r"DEFAULT_CHUNK\s*=\s*4 \* 1024 \* 1024", js)
    assert re.search(r"TAG_LEN\s*=\s*16", js)
    assert re.search(r'SUPPORTED_CHAIN\s*=\s*\["aes-256-gcm"\]', js)
    # 域分离标签必须与 Python 端一致
    assert "aes256-tool::nonce::v1" in js
    assert "aes256-tool::stack-key::v1" in js
    assert "aes256-tool::integrity::v4" in js
    assert multicipher.INTEGRITY_INFO.decode() == "aes256-tool::integrity::v4"


def test_cli_has_kdf_option():
    spec = importlib.util.spec_from_file_location("cli_mod", ROOT / "cli.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    parser = cli.build_parser()
    args = parser.parse_args(["enc", "f.txt", "--kdf", "pbkdf2", "--kdf-iters", "600000"])
    assert args.kdf == "pbkdf2"
    assert args.kdf_iters == 600000
    # 无 --chain / --kdf 时走普通路径
    args2 = parser.parse_args(["enc", "f.txt"])
    assert args2.kdf is None
    assert args2.chain is None


def test_mobile_tree_present():
    base = ROOT / "mobile"
    for rel in ("serve.py", "kivy_app.py", "buildozer.spec",
                "www/index.html", "www/manifest.webmanifest", "www/sw.js",
                "www/js/v4crypto.js", "www/js/app.js", "www/js/legal.js"):
        assert (base / rel).exists(), f"缺少移动版文件：{rel}"
