# -*- coding: utf-8 -*-
"""app/core/multicipher.py
=========================
容器格式 v4：**算法链叠加加密**，但只使用 **一个总密钥**。

格式（自描述头部）
------------------
    MAGIC(8)="AES256v4" | ver(1)=4 | kdf_id(1) | flags(1) | rsv(1)
    | kdf_salt(16) | file_salt(16)
    | n_chain(1) | [ id_len(1) | algo_id(id_len) ] × n_chain
    | kdf_time(4) | kdf_mem(4) | kdf_par(2) | kdf_iters(4)
    | chunk_size(4) | orig_size(8) | orig_sha256(32)
    | name_len(2) | name(name_len)
    | [ 块0..块N-1 ]   每块 = ct_len(4) | ciphertext | tag(16) × n_chain
    | tail_hmac(32)

单一总密钥
----------
密码只经过一次 Argon2id（或 PBKDF2 回退）派生主密钥；算法链各层子密钥由主密钥经
HKDF 以「算法名 + 层序号」做域分离得到。因此无论用户叠加几种算法，**始终只有一个
总密钥**，且各层密钥互不相关。

安全设计
--------
1. 头部进入 AAD，且算法链写入头部 → 篡改链顺序/算法会导致认证失败。
2. 每块每层独立 tag；块重排、删除、截断可被检出。
3. 尾部 HMAC-SHA256 覆盖全部块（密文 + 全部 tag），防止「截断到某个合法块」。
4. 每层 nonce 由 (file_salt, 块序号, 层序号) 确定性导出，不发生 nonce 复用。
5. 全程分块流式，不整文件进内存。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path
from typing import Callable, Optional

from . import algorithms as alg
from . import kdf
from .cipher import IntegrityError

MAGIC = b"AES256v4"
VERSION = 4
KDF_ARGON2, KDF_PBKDF2 = 1, 2
INTEGRITY_INFO = b"aes256-tool::integrity::v4"
DEFAULT_CHUNK = 4 * 1024 * 1024
MAX_NAME = 4096
AUTHOR = "qingniao2007@126.com"

ProgressCb = Optional[Callable[[int, int], None]]
CancelCb = Optional[Callable[[], bool]]


class MultiContainerError(ValueError):
    pass


class CancelledError(RuntimeError):
    pass


# ============================================================
# 头部
# ============================================================
def build_header(chain: list[str], kdf_salt: bytes, file_salt: bytes,
                 kdf_id: int, kdf_time: int, kdf_mem: int, kdf_par: int,
                 kdf_iters: int, chunk_size: int, orig_size: int,
                 orig_sha256: bytes, name: str = "") -> bytes:
    if len(kdf_salt) != 16 or len(file_salt) != 16:
        raise MultiContainerError("盐必须 16 字节")
    ids = [c.encode("ascii") for c in alg.normalize_chain(chain)]
    if not (1 <= len(ids) <= 255):
        raise MultiContainerError("算法链层数非法")
    name_b = (name or "").encode("utf-8")[:MAX_NAME]
    parts = [
        MAGIC,
        struct.pack(">BBBB", VERSION, kdf_id, 0x01, 0),
        kdf_salt, file_salt,
        struct.pack(">B", len(ids)),
    ]
    for i in ids:
        parts.append(struct.pack(">B", len(i)))
        parts.append(i)
    parts += [
        struct.pack(">I", int(kdf_time)),
        struct.pack(">I", int(kdf_mem)),
        struct.pack(">H", int(kdf_par)),
        struct.pack(">I", int(kdf_iters)),
        struct.pack(">I", int(chunk_size)),
        struct.pack(">Q", int(orig_size)),
        orig_sha256,
        struct.pack(">H", len(name_b)),
        name_b,
    ]
    return b"".join(parts)


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise MultiContainerError("文件被截断或损坏")
    return data


def parse_header(fh) -> dict:
    magic = fh.read(8)
    if magic != MAGIC:
        raise MultiContainerError("不是 v4 叠加加密容器（magic 不匹配）")
    ver, kdf_id, flags, _rsv = struct.unpack(">BBBB", _read_exact(fh, 4))
    if ver != VERSION:
        raise MultiContainerError(f"不支持的容器版本：{ver}")
    kdf_salt = _read_exact(fh, 16)
    file_salt = _read_exact(fh, 16)
    (n_chain,) = struct.unpack(">B", _read_exact(fh, 1))
    chain = []
    for _ in range(n_chain):
        (ln,) = struct.unpack(">B", _read_exact(fh, 1))
        chain.append(_read_exact(fh, ln).decode("ascii", "replace"))
    (kdf_time,) = struct.unpack(">I", _read_exact(fh, 4))
    (kdf_mem,) = struct.unpack(">I", _read_exact(fh, 4))
    (kdf_par,) = struct.unpack(">H", _read_exact(fh, 2))
    (kdf_iters,) = struct.unpack(">I", _read_exact(fh, 4))
    (chunk_size,) = struct.unpack(">I", _read_exact(fh, 4))
    (orig_size,) = struct.unpack(">Q", _read_exact(fh, 8))
    orig_sha256 = _read_exact(fh, 32)
    (name_len,) = struct.unpack(">H", _read_exact(fh, 2))
    name = _read_exact(fh, name_len).decode("utf-8", "replace") if name_len else ""
    header_len = (8 + 4 + 16 + 16 + 1
                  + sum(1 + len(c.encode("ascii")) for c in chain)
                  + 4 + 4 + 2 + 4 + 4 + 8 + 32 + 2 + name_len)
    return {
        "version": ver, "kdf_id": kdf_id, "flags": flags,
        "kdf_salt": kdf_salt, "file_salt": file_salt, "chain": chain,
        "kdf_time": kdf_time, "kdf_mem": kdf_mem, "kdf_par": kdf_par,
        "kdf_iters": kdf_iters, "chunk_size": chunk_size,
        "orig_size": orig_size, "orig_sha256": orig_sha256, "name": name,
        "header_len": header_len,
    }


def integrity_key(master: bytes, file_salt: bytes) -> bytes:
    return kdf.hkdf(master, file_salt, INTEGRITY_INFO, 32)


def header_params(info: dict) -> dict:
    return {
        "kdf_name": "argon2id" if info.get("kdf_id") == KDF_ARGON2 else "pbkdf2",
        "time_cost": info.get("kdf_time") or kdf.ARGON2_TIME_COST,
        "memory_cost": info.get("kdf_mem") or kdf.ARGON2_MEMORY_COST,
        "parallelism": info.get("kdf_par") or kdf.ARGON2_PARALLELISM,
        "iterations": info.get("kdf_iters") or kdf.PBKDF2_ITERATIONS,
    }


# ============================================================
# 主密钥版：流式加解密
# ============================================================
def encrypt_stream(src, dst, master: bytes, chain, *,
                   chunk_size: int | None = None,
                   progress: ProgressCb = None, cancel: CancelCb = None,
                   kdf_salt: bytes | None = None,
                   kdf_recipe: dict | None = None) -> dict:
    src, dst = Path(src), Path(dst)
    size = src.stat().st_size
    recipe = kdf_recipe or kdf.recipe()
    if chunk_size is None:
        p = kdf.active_params()
        chunk_size = p.chunk_size if p is not None else DEFAULT_CHUNK
    if kdf_salt is None:
        kdf_salt = kdf.get_active_salt() or recipe.get("salt") or kdf.new_salt(16)

    chain = alg.normalize_chain(chain)
    orig_hash = hashlib.sha256()
    with open(src, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            orig_hash.update(blk)

    file_salt = os.urandom(16)
    kdf_id = (KDF_ARGON2 if recipe.get("kdf_name") == "argon2id" and kdf.ARGON2_AVAILABLE
              else (KDF_PBKDF2 if recipe.get("kdf_name") == "pbkdf2"
                    else (KDF_ARGON2 if kdf.ARGON2_AVAILABLE else KDF_PBKDF2)))
    header = build_header(
        chain=chain, kdf_salt=kdf_salt, file_salt=file_salt, kdf_id=kdf_id,
        kdf_time=recipe.get("time_cost", 0), kdf_mem=recipe.get("memory_cost", 0),
        kdf_par=recipe.get("parallelism", 0), kdf_iters=recipe.get("iterations", 0),
        chunk_size=chunk_size, orig_size=size, orig_sha256=orig_hash.digest(),
        name=src.name)

    stack = alg.CipherStack(chain, master, file_salt)
    hkey = integrity_key(master, file_salt)
    tail = hmac.new(hkey, header, hashlib.sha256)

    written = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")
    try:
        with open(src, "rb") as f, open(tmp, "wb") as out:
            out.write(header)
            index = 0
            while True:
                if cancel and cancel():
                    raise CancelledError("已取消")
                block = f.read(chunk_size)
                if not block:
                    break
                aad_base = header + struct.pack(">I", index)
                ct, tags = stack.encrypt_block(block, index, aad_base)
                out.write(struct.pack(">I", len(ct)))
                out.write(ct)
                tail.update(ct)
                for t in tags:
                    out.write(t)
                    tail.update(t)
                written += len(block)
                if progress:
                    progress(written, size)
                index += 1
            if index == 0:                       # 空文件也写一个空块
                aad_base = header + struct.pack(">I", 0)
                ct, tags = stack.encrypt_block(b"", 0, aad_base)
                out.write(struct.pack(">I", len(ct)))
                out.write(ct)
                tail.update(ct)
                for t in tags:
                    out.write(t)
                    tail.update(t)
            out.write(tail.digest())
        tmp.replace(dst)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise
    return {"ok": True, "src": str(src), "dst": str(dst), "size": size,
            "chunks": max(index, 1), "sha256": orig_hash.hexdigest(),
            "chain": chain}


def decrypt_stream(src, dst, master: bytes, *,
                   progress: ProgressCb = None, cancel: CancelCb = None) -> dict:
    src = Path(src)
    dst = Path(dst) if dst is not None else None
    with open(src, "rb") as f:
        info = parse_header(f)
        f.seek(0)
        header_bytes = f.read(info["header_len"])
        chain = info["chain"]
        stack = alg.CipherStack(chain, master, info["file_salt"])
        hkey = integrity_key(master, info["file_salt"])
        tail = hmac.new(hkey, header_bytes, hashlib.sha256)
        out_hash = hashlib.sha256()

        chunk_size = info["chunk_size"] or DEFAULT_CHUNK
        n_blocks = max(1, (info["orig_size"] + chunk_size - 1) // chunk_size)
        n_tags = len(chain)

        tmp = None
        if dst is not None:
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_suffix(dst.suffix + ".part")

        def _cleanup():
            if tmp is not None:
                Path(tmp).unlink(missing_ok=True)

        done = 0
        try:
            out = open(tmp, "wb") if tmp is not None else None
            try:
                for index in range(n_blocks):
                    if cancel and cancel():
                        raise CancelledError("已取消")
                    (ct_len,) = struct.unpack(">I", _read_exact(f, 4))
                    ct = _read_exact(f, ct_len)
                    tags = [_read_exact(f, 16) for _ in range(n_tags)]
                    aad_base = header_bytes + struct.pack(">I", index)
                    plain = stack.decrypt_block(ct, tags, index, aad_base)
                    if out is not None:
                        out.write(plain)
                    tail.update(ct)
                    for t in tags:
                        tail.update(t)
                    out_hash.update(plain)
                    done += len(plain)
                    if progress:
                        progress(min(done, info["orig_size"]), info["orig_size"])
                stored_tail = f.read(32)
            finally:
                if out is not None:
                    out.close()
        except Exception:
            _cleanup()
            raise

    if len(stored_tail) != 32:
        _cleanup()
        raise MultiContainerError("缺少完整性校验尾部，文件可能被截断")
    if not hmac.compare_digest(stored_tail, tail.digest()):
        _cleanup()
        raise MultiContainerError("整体完整性校验失败：文件已被修改或截断")
    if info["orig_sha256"] != b"\x00" * 32 and \
            not hmac.compare_digest(info["orig_sha256"], out_hash.digest()):
        _cleanup()
        raise MultiContainerError("明文 SHA-256 与头部记录不一致：文件已损坏")
    if tmp is not None:
        tmp.replace(dst)
    return {"ok": True, "src": str(src), "dst": str(dst) if dst else None,
            "size": info["orig_size"], "name": info["name"], "chain": chain}


# ============================================================
# 密码级 API（自描述：盐与 KDF 参数写在头部）
# ============================================================
def encrypt_stream_password(src, dst, password: str, chain, **kw) -> dict:
    recipe = kdf.recipe()
    master = kdf.derive_master_custom(
        password, recipe["salt"], kdf_name=recipe["kdf_name"],
        time_cost=recipe["time_cost"], memory_cost=recipe["memory_cost"],
        parallelism=recipe["parallelism"], iterations=recipe["iterations"])
    return encrypt_stream(src, dst, master, chain,
                          kdf_salt=recipe["salt"], kdf_recipe=recipe, **kw)


def decrypt_stream_password(src, dst, password: str, **kw) -> dict:
    with open(src, "rb") as f:
        info = parse_header(f)
    master = kdf.derive_master_custom(password, info["kdf_salt"], **header_params(info))
    return decrypt_stream(src, dst, master, **kw)


def encrypt_file_password(src, dst, password: str, chain, **kw) -> tuple:
    try:
        return True, encrypt_stream_password(src, dst, password, chain, **kw)
    except Exception as exc:
        return False, str(exc)


def decrypt_file_password(src, dst, password: str, **kw) -> tuple:
    try:
        return True, decrypt_stream_password(src, dst, password, **kw)
    except Exception as exc:
        return False, str(exc)


def read_meta(src) -> dict:
    """只读头部（不解密），用于列表展示与算法链展示。"""
    with open(src, "rb") as f:
        info = parse_header(f)
    return {
        "version": info["version"], "chain": info["chain"],
        "chain_names": [alg.name_of(a) for a in info["chain"]],
        "chunk_size": info["chunk_size"], "orig_size": info["orig_size"],
        "name": info["name"], "kdf_id": info["kdf_id"],
        "kdf_time": info["kdf_time"], "kdf_mem": info["kdf_mem"],
        "kdf_par": info["kdf_par"], "kdf_iters": info["kdf_iters"],
    }


def is_v4(src) -> bool:
    try:
        with open(src, "rb") as f:
            return f.read(8) == MAGIC
    except Exception:
        return False


# ============================================================
# 内存态 IO（供分享页 / 小数据 / 测试使用）
# ============================================================
def encrypt_stream_io(src_io, dst_io, master: bytes, chain, *,
                      chunk_size: int = DEFAULT_CHUNK,
                      kdf_salt: bytes | None = None,
                      kdf_recipe: dict | None = None) -> None:
    """把 file-like 源加密写入 file-like 目标（不经过磁盘）。"""
    recipe = kdf_recipe or kdf.recipe()
    kdf_salt = kdf_salt or recipe.get("salt") or kdf.new_salt(16)
    chain = alg.normalize_chain(chain)

    data = src_io.read()
    orig_hash = hashlib.sha256(data)
    file_salt = os.urandom(16)
    kdf_id = (KDF_ARGON2 if recipe.get("kdf_name") == "argon2id" and kdf.ARGON2_AVAILABLE
              else (KDF_PBKDF2 if recipe.get("kdf_name") == "pbkdf2"
                    else (KDF_ARGON2 if kdf.ARGON2_AVAILABLE else KDF_PBKDF2)))
    header = build_header(
        chain=chain, kdf_salt=kdf_salt, file_salt=file_salt, kdf_id=kdf_id,
        kdf_time=recipe.get("time_cost", 0), kdf_mem=recipe.get("memory_cost", 0),
        kdf_par=recipe.get("parallelism", 0), kdf_iters=recipe.get("iterations", 0),
        chunk_size=chunk_size, orig_size=len(data), orig_sha256=orig_hash.digest(),
        name="")
    stack = alg.CipherStack(chain, master, file_salt)
    hkey = integrity_key(master, file_salt)
    tail = hmac.new(hkey, header, hashlib.sha256)

    dst_io.write(header)
    index = 0
    if not data:
        chunks = [b""]
    else:
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    for block in chunks:
        aad_base = header + struct.pack(">I", index)
        ct, tags = stack.encrypt_block(block, index, aad_base)
        dst_io.write(struct.pack(">I", len(ct)))
        dst_io.write(ct)
        tail.update(ct)
        for t in tags:
            dst_io.write(t)
            tail.update(t)
        index += 1
    dst_io.write(tail.digest())


def decrypt_stream_io(src_io, dst_io, master: bytes) -> bytes:
    """从 file-like 源解密写入 file-like 目标，并返回明文。"""
    info = parse_header(src_io)
    src_io.seek(0)
    header_bytes = src_io.read(info["header_len"])
    chain = info["chain"]
    stack = alg.CipherStack(chain, master, info["file_salt"])
    hkey = integrity_key(master, info["file_salt"])
    tail = hmac.new(hkey, header_bytes, hashlib.sha256)

    chunk_size = info["chunk_size"] or DEFAULT_CHUNK
    n_blocks = max(1, (info["orig_size"] + chunk_size - 1) // chunk_size)
    n_tags = len(chain)
    out = bytearray()
    out_hash = hashlib.sha256()
    for index in range(n_blocks):
        (ct_len,) = struct.unpack(">I", _read_exact(src_io, 4))
        ct = _read_exact(src_io, ct_len)
        tags = [_read_exact(src_io, 16) for _ in range(n_tags)]
        aad_base = header_bytes + struct.pack(">I", index)
        plain = stack.decrypt_block(ct, tags, index, aad_base)
        out += plain
        out_hash.update(plain)
        tail.update(ct)
        for t in tags:
            tail.update(t)
    stored_tail = src_io.read(32)
    if len(stored_tail) != 32 or not hmac.compare_digest(stored_tail, tail.digest()):
        raise MultiContainerError("整体完整性校验失败：文件已被修改或截断")
    if info["orig_sha256"] != b"\x00" * 32 and \
            not hmac.compare_digest(info["orig_sha256"], out_hash.digest()):
        raise MultiContainerError("明文 SHA-256 与头部记录不一致：文件已损坏")
    dst_io.write(bytes(out))
    return bytes(out)
