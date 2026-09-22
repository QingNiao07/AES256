# -*- coding: utf-8 -*-
"""
app/core/keystore.py
====================
密钥备份：
1. 密钥文件（.key）：用「备份口令」派生的备份主密钥加密真实主密钥后落盘；
2. 恢复码：把主密钥编码成 base32 分组码，可抄在纸上，抗介质损坏；
   并支持「查问式校验」——只要求用户报出其中几组，避免整码被肩窥抄走。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from . import cipher, kdf

KEYFILE_MAGIC = "AES256-KEYFILE"
KEYFILE_VERSION = 1
GROUP_SIZE = 5                 # 恢复码每组 5 个 base32 字符 = 25 bits
# 32 字节主密钥 + 2 字节校验 = 34 字节 = 272 bit；base32 需 ceil(272/5)=55 个字符，
# 故必须 11 组（11×5=55）。写成 10 组会丢字节，解码时长度不足。这是一处真实修正。
NUM_GROUPS = 11
RECOVERY_SALT = b"aes256-tool::recovery-code::v1"


class KeyFileError(ValueError):
    pass


# ============================================================
# 密钥文件
# ============================================================
def export_keyfile(master: bytes, dst: str | Path, passphrase: str,
                   note: str = "") -> Path:
    """导出密钥文件。passphrase 为空时拒绝（否则等于不加密）。"""
    if not passphrase:
        raise KeyFileError("备份口令不能为空：密钥文件必须加密保存")
    dst = Path(dst)
    bmaster = kdf.derive_backup_master(passphrase)
    blob = cipher.encrypt_bytes(master, bmaster, aad=b"keyfile")
    payload = {
        "magic": KEYFILE_MAGIC,
        "version": KEYFILE_VERSION,
        "created": int(time.time()),
        "note": note,
        "blob": base64.b64encode(blob).decode("ascii"),
        # 校验用的口令指纹，便于快速判断口令是否正确（不含密钥信息）
        "check": hmac.new(bmaster, b"keyfile-check", hashlib.sha256).hexdigest(),
    }
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        dst.chmod(0o600)
    except OSError:
        pass
    return dst


def import_keyfile(src: str | Path, passphrase: str) -> bytes:
    src = Path(src)
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except Exception as exc:
        raise KeyFileError(f"密钥文件无法解析：{exc}") from exc
    if payload.get("magic") != KEYFILE_MAGIC:
        raise KeyFileError("不是有效的密钥文件")
    bmaster = kdf.derive_backup_master(passphrase)
    expect = hmac.new(bmaster, b"keyfile-check", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, str(payload.get("check", ""))):
        raise KeyFileError("备份口令错误")
    try:
        return cipher.decrypt_bytes(base64.b64decode(payload["blob"]), bmaster, aad=b"keyfile")
    except Exception as exc:
        raise KeyFileError(f"密钥文件损坏或口令错误：{exc}") from exc


def inspect_keyfile(src: str | Path) -> dict:
    payload = json.loads(Path(src).read_text(encoding="utf-8"))
    return {"created": payload.get("created"), "note": payload.get("note", ""),
            "version": payload.get("version")}


# ============================================================
# 恢复码
# ============================================================
def _checksum(master: bytes) -> bytes:
    return hmac.new(RECOVERY_SALT, master, hashlib.sha256).digest()[:2]


def make_recovery_code(master: bytes) -> str:
    """生成分组恢复码，格式 A1B2C-... 共 10 组 + 1 组校验组。"""
    if len(master) != 32:
        raise KeyFileError("主密钥必须 32 字节")
    raw = master + _checksum(master)          # 34 字节
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [b32[i:i + GROUP_SIZE] for i in range(0, len(b32), GROUP_SIZE)]
    return "-".join(g for g in groups if g)


def parse_recovery_code(code: str) -> list[str]:
    clean = "".join(ch for ch in code.upper() if ch.isalnum())
    return [clean[i:i + GROUP_SIZE] for i in range(0, len(clean), GROUP_SIZE)]


def decode_recovery_code(code: str) -> bytes:
    groups = parse_recovery_code(code)
    if len(groups) < NUM_GROUPS:
        raise KeyFileError(f"恢复码组数不足：需要 {NUM_GROUPS} 组，收到 {len(groups)} 组")
    joined = "".join(groups[:NUM_GROUPS])
    pad = "=" * (-len(joined) % 8)
    try:
        raw = base64.b32decode(joined + pad)
    except Exception as exc:
        raise KeyFileError(f"恢复码字符非法：{exc}") from exc
    if len(raw) < 34:
        raise KeyFileError("恢复码长度不足")
    master, chk = raw[:32], raw[32:34]
    if not hmac.compare_digest(chk, _checksum(master)):
        raise KeyFileError("恢复码校验位不匹配，可能抄写有误")
    return master


def challenge_positions(n: int = 3, total: int = NUM_GROUPS) -> list[int]:
    """随机挑选要核验的组号（从 1 开始）。"""
    return sorted(secrets.Sample(range(1, total + 1), n) if hasattr(secrets, "Sample")
                  else secrets.sample(range(1, total + 1), n))


def verify_challenge(master: bytes, answers: dict[int, str]) -> bool:
    """查问式校验：answers 形如 {3: 'ABC12', 7: 'XY90Z'}。"""
    groups = parse_recovery_code(make_recovery_code(master))
    for pos, val in answers.items():
        idx = pos - 1
        if not (0 <= idx < len(groups)):
            return False
        if "".join(ch for ch in val.upper() if ch.isalnum()) != groups[idx]:
            return False
    return True


def random_master() -> bytes:
    """生成独立随机主密钥（用于「不用口令、只靠恢复码/密钥文件」的场景）。"""
    return os.urandom(32)
