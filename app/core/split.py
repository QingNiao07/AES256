# -*- coding: utf-8 -*-
"""
app/core/split.py
=================
分卷加密：把密文切成 N 份分存不同介质，单份泄露无意义。

设计
----
先把源文件加密成完整 .aes256，再按固定卷大小切分成
    name.aes256.part001 / .part002 / ...
并生成 name.aes256.parts.json 清单（含每卷 SHA-256、总数、原始大小）。

合并时必须全部卷齐全且逐卷哈希校验通过，避免「少一卷也能还原」的错觉。
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable, Optional

PART_SUFFIX = ".part%03d"
MANIFEST_SUFFIX = ".parts.json"
DEFAULT_VOLUME = 100 * 1024 * 1024       # 100 MiB


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blk)
    return h.hexdigest()


def split_blob(src: str | Path, volume_size: int = DEFAULT_VOLUME,
               out_dir: str | Path | None = None,
               progress: Optional[Callable[[int, int], None]] = None,
               cancel: Optional[Callable[[], bool]] = None) -> dict:
    """把已加密的 .aes256 切成多卷。"""
    src = Path(src)
    out_dir = Path(out_dir) if out_dir else src.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    if volume_size < 1024:
        raise ValueError("分卷大小至少 1 KiB")

    total = src.stat().st_size
    parts = []
    with open(src, "rb") as f:
        idx, done = 1, 0
        while True:
            if cancel and cancel():
                for p in parts:
                    Path(p["path"]).unlink(missing_ok=True)
                raise container_cancel()
            blk = f.read(volume_size)
            if not blk:
                break
            part_path = out_dir / (src.name + PART_SUFFIX % idx)
            with open(part_path, "wb") as out:
                out.write(blk)
            parts.append({"index": idx, "name": part_path.name,
                          "path": str(part_path), "size": len(blk),
                          "sha256": _sha256_file(part_path)})
            done += len(blk)
            if progress:
                progress(done, total)
            idx += 1

    manifest = {
        "magic": "AES256-PARTS",
        "version": 1,
        "source": src.name,
        "total_size": total,
        "volume_size": volume_size,
        "parts": parts,
    }
    mpath = out_dir / (src.name + MANIFEST_SUFFIX)
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "parts": len(parts), "manifest": str(mpath),
            "size": total}


def container_cancel():
    from .container import CancelledError

    return CancelledError("已取消")


def load_manifest(src: str | Path) -> dict:
    p = Path(src)
    if p.suffix == ".json":
        mpath = p
    else:
        mpath = p.parent / (p.name + MANIFEST_SUFFIX)
    if not mpath.exists():
        raise FileNotFoundError(f"找不到分卷清单：{mpath}")
    return json.loads(mpath.read_text(encoding="utf-8"))


def merge_parts(src: str | Path, dst: str | Path | None = None,
                progress: Optional[Callable[[int, int], None]] = None,
                verify: bool = True) -> dict:
    """按清单合并分卷，逐卷校验 SHA-256。"""
    manifest = load_manifest(src)
    base = Path(src)
    if base.suffix == ".json":
        base = base.parent / manifest["source"]
    out = Path(dst) if dst else base

    parts = manifest["parts"]
    total = manifest["total_size"]
    done = 0
    tmp = out.with_suffix(out.suffix + ".merging")
    try:
        with open(tmp, "wb") as w:
            for part in parts:
                pp = Path(part["path"])
                if not pp.exists():
                    pp = out.parent / part["name"]
                if not pp.exists():
                    raise FileNotFoundError(f"缺少分卷：{part['name']}")
                if verify and _sha256_file(pp) != part["sha256"]:
                    raise ValueError(f"分卷校验失败（可能损坏）：{part['name']}")
                with open(pp, "rb") as r:
                    w.write(r.read())
                done += part["size"]
                if progress:
                    progress(done, total)
        tmp.replace(out)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return {"ok": True, "out": str(out), "parts": len(parts), "size": total}


def list_parts(src: str | Path) -> list[str]:
    return [p["path"] for p in load_manifest(src)["parts"]]
