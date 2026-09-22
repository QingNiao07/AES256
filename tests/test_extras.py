# -*- coding: utf-8 -*-
"""tests/test_extras.py · 新推荐功能：文件夹容器 / 分卷 / 分享页 / 风险检测 / 最近文件"""
import json
import os
from pathlib import Path

import pytest

from app.core import archive, recent, riskcheck, share, split
from app.core import derive_master, new_salt


@pytest.fixture()
def master():
    return derive_master("Extras#Test!2025", salt=new_salt())


# ---- 文件夹容器 ----
def test_folder_roundtrip(tmp_path, master):
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("hello 你好", encoding="utf-8")
    (src / "sub" / "b.bin").write_bytes(os.urandom(5000))
    enc = tmp_path / "proj.aes256"
    out = tmp_path / "restored"

    r = archive.encrypt_folder(src, enc, master)
    assert r["files"] == 2 and enc.exists()
    assert enc.name.endswith(".aes256")

    r2 = archive.decrypt_folder(enc, out, master)
    assert r2["files"] == 2
    assert (out / "a.txt").read_text(encoding="utf-8") == "hello 你好"
    assert (out / "sub" / "b.bin").read_bytes() == (src / "sub" / "b.bin").read_bytes()


def test_folder_skips_key_and_cipher(tmp_path, master):
    src = tmp_path / "proj2"
    src.mkdir()
    (src / "keep.txt").write_text("ok", encoding="utf-8")
    (src / "secret.key").write_text("KEY-MATERIAL", encoding="utf-8")
    (src / "old.aes256").write_bytes(b"cipher")
    enc = tmp_path / "proj2.aes256"
    r = archive.encrypt_folder(src, enc, master)
    assert r["files"] == 1                    # 密钥与密文均被排除


def test_folder_path_traversal_blocked(tmp_path, master):
    import tarfile

    # 造一个含 ../ 的恶意 tar，再加密，解密时应跳过越界成员
    mal = tmp_path / "mal.tar"
    with tarfile.open(mal, "w") as t:
        evil = tmp_path / "evil.txt"
        evil.write_text("evil", encoding="utf-8")
        t.add(str(evil), arcname="../escape.txt")
    enc = tmp_path / "mal.aes256"
    from app.core import container

    container.encrypt_stream(mal, enc, master)
    out = tmp_path / "unpack"
    archive.decrypt_folder(enc, out, master)
    assert not (tmp_path / "escape.txt").exists()


# ---- 分卷 ----
def test_split_merge_roundtrip(tmp_path, master):
    from app.core import container

    data = os.urandom(300_000)
    src = tmp_path / "big.bin"
    src.write_bytes(data)
    enc = tmp_path / "big.aes256"
    container.encrypt_stream(src, enc, master)

    r = split.split_blob(enc, volume_size=64 * 1024)
    assert r["parts"] >= 4
    # 删掉原密文，靠分卷合并恢复
    enc.unlink()
    r2 = split.merge_parts(r["manifest"])
    assert Path(r2["out"]).exists()

    dec = tmp_path / "out.bin"
    container.decrypt_stream(r2["out"], dec, master)
    assert dec.read_bytes() == data


def test_split_merge_detects_corrupt_part(tmp_path, master):
    from app.core import container

    src = tmp_path / "x.bin"
    src.write_bytes(os.urandom(200_000))
    enc = tmp_path / "x.aes256"
    container.encrypt_stream(src, enc, master)
    r = split.split_blob(enc, volume_size=50 * 1024)

    part = Path(r["manifest"]).parent / json.loads(
        Path(r["manifest"]).read_text(encoding="utf-8"))["parts"][0]["name"]
    part.write_bytes(part.read_bytes() + b"tamper")     # 破坏第一卷
    with pytest.raises(ValueError):
        split.merge_parts(r["manifest"])


def test_split_missing_part(tmp_path, master):
    from app.core import container

    src = tmp_path / "y.bin"
    src.write_bytes(os.urandom(200_000))
    enc = tmp_path / "y.aes256"
    container.encrypt_stream(src, enc, master)
    r = split.split_blob(enc, volume_size=50 * 1024)
    first = Path(split.list_parts(r["manifest"])[0])
    first.unlink()
    with pytest.raises(FileNotFoundError):
        split.merge_parts(r["manifest"])


# ---- 分享页 ----
def test_share_page_has_no_password(tmp_path):
    html = share.build_share_page(b"secret content", "P@ssw0rd#2025", title="测试分享")
    assert "P@ssw0rd#2025" not in html          # 密码绝不能出现在页面里
    assert "ssl" not in html.lower()
    assert "http://" not in html and "https://" not in html   # 不引外部资源
    assert "crypto.subtle" in html              # 浏览器本地解密
    assert "AES-GCM" in html


def test_share_page_written(tmp_path):
    p = share.write_share_page(b"data", "pw12345678", tmp_path / "s.html")
    assert p.exists() and p.stat().st_size > 500


# ---- 风险检测 ----
def test_risk_same_dir(tmp_path):
    cipher = tmp_path / "doc.aes256"
    cipher.write_bytes(b"x")
    key = tmp_path / "doc.key"
    key.write_text("k", encoding="utf-8")
    r = riskcheck.check_pair(cipher, [key])
    assert not r["safe"]
    assert r["same_dir"]


def test_risk_clean(tmp_path):
    cipher = tmp_path / "c" / "doc.aes256"
    cipher.parent.mkdir(parents=True)
    cipher.write_bytes(b"x")
    other = tmp_path / "keys" / "k.key"
    other.parent.mkdir(parents=True)
    other.write_text("k", encoding="utf-8")
    # 同一卷内但不同目录 —— 仍应报告同盘
    r = riskcheck.check_pair(cipher, [other])
    assert r["same_volume"] or r["same_dir"]


# ---- 最近文件 ----
def test_recent_and_favorites(tmp_path, monkeypatch):
    import app.paths as paths
    import app.core.recent as rec

    monkeypatch.setattr(paths, "base_dir", lambda: tmp_path)
    monkeypatch.setattr(rec, "log_dir", lambda: tmp_path / "aes_log")
    (tmp_path / "aes_log").mkdir(exist_ok=True)

    rec.add("/tmp/a.txt", "encrypt")
    rec.add("/tmp/b.txt", "decrypt")
    assert rec.list_recent(1)[0]["path"] == "/tmp/b.txt"

    assert rec.toggle_favorite("/tmp/a.txt") is True
    assert rec.is_favorite("/tmp/a.txt")
    assert rec.toggle_favorite("/tmp/a.txt") is False
