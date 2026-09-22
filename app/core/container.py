# -*- coding: utf-8 -*-
"""
app/core/container.py
=====================
.aes256 文件容器格式 v3（分块流式，自描述 KDF 参数）。

格式
----
    MAGIC(8)="AES256v3" | ver(1) | kdf_id(1) | flags(1) | rsv(1)
    | kdf_salt(16) | file_salt(16) | nonce_prefix(4)
    | kdf_time(4) | kdf_mem(4) | kdf_par(2) | kdf_iters(4)
    | chunk_size(4) | orig_size(8) | orig_sha256(32)
    | name_len(2) | name(name_len)
    | [ 块0..块N-1 ]   每块 = ct_len(4) | ciphertext | tag(16)
    | tail_hmac(32)

安全设计
--------
1. nonce 不复用：nonce = nonce_prefix(4) || chunk_index(8)，块序号进入 nonce 与 AAD。
2. 头部进入 AAD，篡改头部（如改块大小）会导致解密失败。
3. 每块独立 GCM tag，密文重排/删除可被检出。
4. 尾部 HMAC-SHA256 覆盖全部块，防止「截断到某个合法块」这类攻击。
5. 全程分块，不再整文件进内存。

重大修正（相对早期版本）
------------------------
早期版本用 `derive_master(pwd, salt=new_salt())` 派生主密钥，但随机盐**从未写入容器**，
导致「同一密码再次解密」必然失败（主密钥不可复现）。本版把 kdf_salt 与全部 KDF
参数写入头部，并提供 `*_password` 系列 API：解密方从头部读回盐与参数，重新派生
出同一主密钥，因此密码级往返成立。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path
from typing import Callable, Optional

from . import cipher, kdf
from .cipher import IntegrityError                     # noqa: F401  (对外统一异常)
from .kdf import derive_file_key, hkdf, new_nonce

MAGIC = b"AES256v3"
MAGIC_V2 = b"AES256v2"
VERSION = 3
VERSION_V2 = 2
KDF_ARGON2, KDF_PBKDF2 = 1, 2
FLAG_HAS_TAIL_HMAC = 0x01
INTEGRITY_INFO = b"aes256-tool::integrity::v2"
DEFAULT_CHUNK = 4 * 1024 * 1024
MAX_NAME = 4096

ProgressCb = Optional[Callable[[int, int], None]]
CancelCb = Optional[Callable[[], bool]]


class ContainerError(ValueError):
    pass


class CancelledError(RuntimeError):
    pass


# ============================================================
# 头部
# ============================================================
def build_header(kdf_salt: bytes, file_salt: bytes, nonce_prefix: bytes,
                 chunk_size: int, orig_size: int, orig_sha256: bytes,
                 name: str = "", *, kdf_id: int | None = None,
                 kdf_time: int = 0, kdf_mem: int = 0, kdf_par: int = 0,
                 kdf_iters: int = 0) -> bytes:
    if len(kdf_salt) != 16:
        raise ContainerError("kdf_salt 必须 16 字节")
    if len(file_salt) != 16:
        raise ContainerError("file_salt 必须 16 字节")
    if len(nonce_prefix) != 4:
        raise ContainerError("nonce_prefix 必须 4 字节")
    name_b = (name or "").encode("utf-8")[:MAX_NAME]
    if kdf_id is None:
        kdf_id = KDF_ARGON2 if kdf.ARGON2_AVAILABLE else KDF_PBKDF2
    return b"".join([
        MAGIC,
        struct.pack(">BBBB", VERSION, kdf_id, FLAG_HAS_TAIL_HMAC, 0),
        kdf_salt,
        file_salt,
        nonce_prefix,
        struct.pack(">I", int(kdf_time)),
        struct.pack(">I", int(kdf_mem)),
        struct.pack(">H", int(kdf_par)),
        struct.pack(">I", int(kdf_iters)),
        struct.pack(">I", chunk_size),
        struct.pack(">Q", orig_size),
        orig_sha256,
        struct.pack(">H", len(name_b)),
        name_b,
    ])


def parse_header(fh) -> dict:
    head = fh.read(8)
    if head not in (MAGIC, MAGIC_V2):
        raise ContainerError("不是有效的 .aes256 文件（magic 不匹配）")
    ver, kdf_id, flags, _rsv = struct.unpack(">BBBB", _read_exact(fh, 4))
    if ver not in (VERSION, VERSION_V2):
        raise ContainerError(f"不支持的容器版本：{ver}")
    kdf_salt = _read_exact(fh, 16)
    file_salt = _read_exact(fh, 16)
    nonce_prefix = _read_exact(fh, 4)
    kdf_time = kdf_mem = kdf_par = kdf_iters = 0
    if ver >= VERSION:
        (kdf_time,) = struct.unpack(">I", _read_exact(fh, 4))
        (kdf_mem,) = struct.unpack(">I", _read_exact(fh, 4))
        (kdf_par,) = struct.unpack(">H", _read_exact(fh, 2))
        (kdf_iters,) = struct.unpack(">I", _read_exact(fh, 4))
    (chunk_size,) = struct.unpack(">I", _read_exact(fh, 4))
    (orig_size,) = struct.unpack(">Q", _read_exact(fh, 8))
    orig_sha256 = _read_exact(fh, 32)
    (name_len,) = struct.unpack(">H", _read_exact(fh, 2))
    name = _read_exact(fh, name_len).decode("utf-8", "replace") if name_len else ""
    base = 8 + 4 + 16 + 16 + 4 + 4 + 8 + 32 + 2
    extra = 14 if ver >= VERSION else 0
    return {
        "version": ver, "kdf_id": kdf_id, "flags": flags,
        "kdf_salt": kdf_salt, "file_salt": file_salt, "nonce_prefix": nonce_prefix,
        "kdf_time": kdf_time, "kdf_mem": kdf_mem, "kdf_par": kdf_par,
        "kdf_iters": kdf_iters,
        "chunk_size": chunk_size, "orig_size": orig_size, "orig_sha256": orig_sha256,
        "name": name,
        "header_len": base + extra + name_len,
    }


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise ContainerError("文件被截断或损坏")
    return data


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def chunk_aad(header_bytes: bytes, index: int) -> bytes:
    return header_bytes + struct.pack(">I", index)


def integrity_key(master: bytes, file_salt: bytes) -> bytes:
    return hkdf(master, file_salt, INTEGRITY_INFO, 32)


# ============================================================
# 加密 / 解密（主密钥版）
# ============================================================
def encrypt_stream(src: str | Path, dst: str | Path, master: bytes,
                   chunk_size: int | None = None,
                   progress: ProgressCb = None, cancel: CancelCb = None,
                   kdf_salt: bytes | None = None,
                   kdf_recipe: dict | None = None) -> dict:
    src, dst = Path(src), Path(dst)
    size = src.stat().st_size
    if chunk_size is None:
        p = kdf.active_params()
        chunk_size = p.chunk_size if p is not None else DEFAULT_CHUNK

    recipe = kdf_recipe or kdf.recipe()
    if kdf_salt is None:
        kdf_salt = kdf.get_active_salt()
    if kdf_salt is None:
        kdf_salt = recipe.get("salt") or kdf.new_salt(16)

    orig_hash = hashlib.sha256()
    file_salt = os.urandom(16)
    nonce_prefix = new_nonce(4)
    file_key = derive_file_key(master, file_salt)
    hkey = integrity_key(master, file_salt)

    def _mk_header(sha: bytes) -> bytes:
        return build_header(
            kdf_salt=kdf_salt, file_salt=file_salt, nonce_prefix=nonce_prefix,
            chunk_size=chunk_size, orig_size=size, orig_sha256=sha, name=src.name,
            kdf_id=(KDF_ARGON2 if recipe.get("kdf_name") == "argon2id" and kdf.ARGON2_AVAILABLE
                    else (KDF_PBKDF2 if recipe.get("kdf_name") == "pbkdf2"
                          else (KDF_ARGON2 if kdf.ARGON2_AVAILABLE else KDF_PBKDF2))),
            kdf_time=recipe.get("time_cost", 0), kdf_mem=recipe.get("memory_cost", 0),
            kdf_par=recipe.get("parallelism", 0), kdf_iters=recipe.get("iterations", 0),
        )

    with open(src, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            orig_hash.update(blk)
    header = _mk_header(orig_hash.digest())

    written = 0
    tail = hmac.new(hkey, header, hashlib.sha256)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")

    with open(src, "rb") as f, open(tmp, "wb") as out:
        out.write(header)
        index = 0
        while True:
            if cancel and cancel():
                out.close()
                tmp.unlink(missing_ok=True)
                raise CancelledError("已取消")
            block = f.read(chunk_size)
            if not block:
                break
            nonce = chunk_nonce(nonce_prefix, index)
            ct, tag = cipher.encrypt_with_nonce_ct_tag(block, file_key, nonce,
                                                       chunk_aad(header, index))
            out.write(struct.pack(">I", len(ct)))
            out.write(ct)
            out.write(tag)
            tail.update(ct)
            tail.update(tag)
            written += len(block)
            if progress:
                progress(written, size)
            index += 1
        if index == 0:                      # 空文件也写一个空块，保证可解
            nonce = chunk_nonce(nonce_prefix, 0)
            ct, tag = cipher.encrypt_with_nonce_ct_tag(b"", file_key, nonce,
                                                       chunk_aad(header, 0))
            out.write(struct.pack(">I", len(ct)))
            out.write(ct)
            out.write(tag)
            tail.update(ct)
            tail.update(tag)
        out.write(tail.digest())

    tmp.replace(dst)
    return {"ok": True, "src": str(src), "dst": str(dst),
            "size": size, "chunks": max(index, 1), "sha256": orig_hash.hexdigest()}


def decrypt_stream(src: str | Path, dst: str | Path, master: bytes,
                   progress: ProgressCb = None, cancel: CancelCb = None) -> dict:
    src = Path(src)
    dst = Path(dst) if dst is not None else None
    total = src.stat().st_size

    with open(src, "rb") as f:
        info = parse_header(f)
        f.seek(0)
        header_bytes = f.read(info["header_len"])
        file_key = derive_file_key(master, info["file_salt"])
        hkey = integrity_key(master, info["file_salt"])
        tail = hmac.new(hkey, header_bytes, hashlib.sha256)
        out_hash = hashlib.sha256()

        chunk_size = info["chunk_size"] or DEFAULT_CHUNK
        n_blocks = max(1, (info["orig_size"] + chunk_size - 1) // chunk_size)

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
                    lenb = _read_exact(f, 4)
                    (ct_len,) = struct.unpack(">I", lenb)
                    ct = _read_exact(f, ct_len)
                    tag = _read_exact(f, 16)
                    nonce = chunk_nonce(info["nonce_prefix"], index)
                    plain = cipher.decrypt_with_nonce_ct_tag(
                        ct, tag, file_key, nonce, chunk_aad(header_bytes, index))
                    if out is not None:
                        out.write(plain)
                    tail.update(ct)
                    tail.update(tag)
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
        raise ContainerError("缺少完整性校验尾部，文件可能被截断")
    if not hmac.compare_digest(stored_tail, tail.digest()):
        _cleanup()
        raise ContainerError("整体完整性校验失败：文件已被修改或截断")
    if sha_check(info["orig_sha256"], out_hash.digest()) is False:
        _cleanup()
        raise ContainerError("明文 SHA-256 与头部记录不一致：文件已损坏")

    if tmp is not None:
        tmp.replace(dst)

    return {"ok": True, "src": str(src), "dst": str(dst) if dst else None,
            "size": info["orig_size"], "name": info["name"]}


def sha_check(expect: bytes, actual: bytes) -> bool:
    if expect == b"\x00" * 32:
        return True
    return hmac.compare_digest(expect, actual)


# ============================================================
# 密码级 API（自描述：salt 与 KDF 参数写在头部，可复现主密钥）
# ============================================================
def header_params(info: dict) -> dict:
    """把头部存档的 KDF 参数还原为 derive_master_custom 的实参。"""
    name = "argon2id" if info.get("kdf_id") == KDF_ARGON2 else "pbkdf2"
    return {
        "kdf_name": name,
        "time_cost": info.get("kdf_time") or kdf.ARGON2_TIME_COST,
        "memory_cost": info.get("kdf_mem") or kdf.ARGON2_MEMORY_COST,
        "parallelism": info.get("kdf_par") or kdf.ARGON2_PARALLELISM,
        "iterations": info.get("kdf_iters") or kdf.PBKDF2_ITERATIONS,
    }


def encrypt_stream_password(src, dst, password: str, *,
                            chunk_size: int | None = None,
                            progress: ProgressCb = None,
                            cancel: CancelCb = None) -> dict:
    recipe = kdf.recipe()
    master = kdf.derive_master_custom(
        password, recipe["salt"], kdf_name=recipe["kdf_name"],
        time_cost=recipe["time_cost"], memory_cost=recipe["memory_cost"],
        parallelism=recipe["parallelism"], iterations=recipe["iterations"])
    return encrypt_stream(src, dst, master, chunk_size=chunk_size,
                          progress=progress, cancel=cancel,
                          kdf_salt=recipe["salt"], kdf_recipe=recipe)


def decrypt_stream_password(src, dst, password: str, *,
                            progress: ProgressCb = None,
                            cancel: CancelCb = None) -> dict:
    with open(src, "rb") as f:
        info = parse_header(f)
    params = header_params(info)
    master = kdf.derive_master_custom(password, info["kdf_salt"], **params)
    return decrypt_stream(src, dst, master, progress=progress, cancel=cancel)


def encrypt_file_password(src, dst, password: str, **kw) -> tuple:
    try:
        return True, encrypt_stream_password(src, dst, password, **kw)
    except Exception as exc:
        return False, str(exc)


def decrypt_file_password(src, dst, password: str, **kw) -> tuple:
    try:
        return True, decrypt_stream_password(src, dst, password, **kw)
    except Exception as exc:
        return False, str(exc)


# ---- 兼容 API（主密钥版，返回 (ok, res)）----
def encrypt_file(src, dst, master, **kw) -> tuple:
    try:
        return True, encrypt_stream(src, dst, master, **kw)
    except Exception as exc:
        return False, str(exc)


def decrypt_file(src, dst, master, **kw) -> tuple:
    try:
        return True, decrypt_stream(src, dst, master, **kw)
    except Exception as exc:
        return False, str(exc)


# ---- 内存态 API ----
_BYTES_MAGIC = b"AES256B1"


def encrypt_bytes(data: bytes, master: bytes) -> bytes:
    file_salt = os.urandom(16)
    key = derive_file_key(master, file_salt)
    blob = cipher.encrypt_bytes(data, key, aad=file_salt)
    return _BYTES_MAGIC + file_salt + blob


def decrypt_bytes(blob: bytes, master: bytes) -> bytes:
    if blob[:8] != _BYTES_MAGIC:
        raise ContainerError("不是有效的内存密文")
    file_salt = blob[8:24]
    key = derive_file_key(master, file_salt)
    return cipher.decrypt_bytes(blob[24:], key, aad=file_salt)


def read_meta(src) -> dict:
    """只读头部，用于列表展示（不解密）。"""
    with open(src, "rb") as f:
        info = parse_header(f)
    return {k: info[k] for k in (
        "version", "chunk_size", "orig_size", "name",
        "kdf_id", "kdf_time", "kdf_mem", "kdf_par", "kdf_iters")}
