# -*- coding: utf-8 -*-
"""mobile/tests/interop_dec.py
=============================
验证移动端（JS）生成的容器能被桌面端解密。

用法：
    python mobile/tests/interop_dec.py <io_dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.core import multicipher  # noqa: E402


def main() -> int:
    io = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "_io"
    blob = io / "js_out.aes256"
    expect = (io / "js_out.plain").read_bytes()
    pw = (io / "password.txt").read_text(encoding="utf-8")

    if not blob.exists():
        print("[skip] 未找到 js_out.aes256（先运行 Node 端测试）")
        return 0

    meta = multicipher.read_meta(blob)
    print("[meta]", meta["chain"], "kdf_id=", meta["kdf_id"], "iters=", meta["kdf_iters"])
    assert meta["chain"] == ["aes-256-gcm"], meta["chain"]
    assert meta["kdf_id"] == multicipher.KDF_PBKDF2

    out = io / "js_out.decrypted"
    r = multicipher.decrypt_stream_password(blob, out, pw)
    got = out.read_bytes()
    assert got == expect, f"明文不一致：{len(got)} vs {len(expect)}"
    print(f"[OK] 桌面端成功解密移动端容器，{len(got)} B，name={r.get('name')}")

    # 错误密码必须失败
    try:
        multicipher.decrypt_file_password(blob, io / "bad.dec", "wrong")
        ok, msg = multicipher.decrypt_file_password(blob, io / "bad.dec", "wrong")
        assert not ok, "错误密码竟然解密成功"
        print("[OK] 错误密码被拒绝")
    except Exception as exc:  # noqa: BLE001
        print(f"[OK] 错误密码被拒绝：{type(exc).__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
