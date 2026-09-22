# -*- coding: utf-8 -*-
"""mobile/tests/interop_gen.py
=============================
桌面端 → 移动端互通数据生成器。

用桌面端 multicipher（容器 v4，PBKDF2-HMAC-SHA256，算法链 [aes-256-gcm]）
加密一段确定的明文，写出 .aes256 与期望明文，供 Node/浏览器端解密验证。

用法：
    python mobile/tests/interop_gen.py <out_dir> [iterations]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.core import kdf, multicipher  # noqa: E402

PW = "Correct-Horse-Battery-Staple-2026"
CHAIN = ["aes-256-gcm"]
ITER = 200_000


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "_io"
    iters = int(sys.argv[2]) if len(sys.argv) > 2 else ITER
    out.mkdir(parents=True, exist_ok=True)

    # 覆盖多块（> chunk_size）与空文件两种边界
    plain = ("AES-256 移动互通测试 payload — " * 400).encode("utf-8")
    empty = b""

    for tag, data in (("normal", plain), ("empty", empty)):
        salt = kdf.new_salt(16)
        recipe = {"salt": salt, "kdf_name": "pbkdf2", "time_cost": 0,
                  "memory_cost": 0, "parallelism": 0, "iterations": iters}
        master = kdf.derive_master_custom(PW, salt, kdf_name="pbkdf2", iterations=iters)
        dst = out / f"py_{tag}.aes256"
        multicipher.encrypt_stream(
            _as_src(out / f"py_{tag}.plain", data), dst, master, CHAIN,
            chunk_size=4096, kdf_salt=salt, kdf_recipe=recipe)
        print(f"[gen] {dst}  ({dst.stat().st_size} B, iters={iters})")

    (out / "password.txt").write_text(PW, encoding="utf-8")
    print(f"[gen] 密码与明文已写入 {out}")
    return 0


def _as_src(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
