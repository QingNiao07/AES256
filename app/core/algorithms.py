# -*- coding: utf-8 -*-
"""app/core/algorithms.py
=========================
多加密算法注册表 + 后端实现（供「自选 / 叠加加密」使用）。

设计
----
- 每个后端实现统一接口：
    encrypt(key, data, nonce, aad) -> (ciphertext, tag)
    decrypt(key, data, nonce, tag, aad) -> plaintext
- 密钥材料长度由算法决定：
    * AEAD：仅需加密密钥（key_size 字节）；
    * Encrypt-then-MAC：加密密钥 + 32 字节 HMAC 密钥。
- 所有算法 tag 统一 16 字节（AEAD 原生长度 / HMAC-SHA256 截断为 128 bit）。
- 注册表带中英文名称与描述、优先级、是否 AEAD、是否传统算法、可用性检测。

单一总密钥
----------
本模块不做密码派生；由调用方（multicipher）用 Argon2id 一次性派生主密钥，
再用 HKDF 以「算法名 + 层序号」做域分离，为每一层派生独立子密钥。
因此无论用户叠加多少种算法，始终只有一个总密钥。
"""
from __future__ import annotations

import hashlib
import hmac
import warnings

from .cipher import IntegrityError
from . import kdf

warnings.filterwarnings("ignore", category=DeprecationWarning)
try:  # cryptography 的自定义弃用告警类别
    from cryptography.utils import CryptographyDeprecationWarning as _CrWarn

    warnings.filterwarnings("ignore", category=_CrWarn)
except Exception:  # pragma: no cover
    pass

TAG_LEN = 16
MAC_KEY_LEN = 32
DEFAULT_ALGORITHM = "aes-256-gcm"
NONCE_INFO = b"aes256-tool::nonce::v1"
KEY_INFO = b"aes256-tool::stack-key::v1"
MAX_CHAIN = 4


class AlgorithmError(ValueError):
    """算法不可用或参数非法。"""


# ============================================================
# 填充（仅 CBC 这类需要块对齐的模式使用）
# ============================================================
def pad16(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def unpad16(data: bytes) -> bytes:
    if not data:
        raise IntegrityError("去填充失败：密文为空")
    n = data[-1]
    if n < 1 or n > 16 or len(data) < n:
        raise IntegrityError("去填充失败：PKCS7 校验不通过")
    if data[-n:] != bytes([n]) * n:
        raise IntegrityError("去填充失败：填充字节不一致")
    return data[:-n]


def _layer_nonce(file_salt: bytes, index: int, layer: int, size: int) -> bytes:
    """由 (文件盐, 块序号, 层序号) 确定性导出该层 nonce/IV，避免随块存储。"""
    msg = NONCE_INFO + index.to_bytes(8, "big") + bytes([layer])
    out = b""
    counter = 0
    while len(out) < size:
        out += hmac.new(file_salt, msg + bytes([counter]), hashlib.sha256).digest()
        counter += 1
    return out[:size]


def derive_layer_key(master: bytes, file_salt: bytes, algo_id: str, index: int) -> bytes:
    """对主密钥做 HKDF 域分离，得到该层子密钥。"""
    algo = get_algorithm(algo_id)
    info = KEY_INFO + algo_id.encode("ascii") + b"::" + str(index).encode("ascii")
    return kdf.hkdf(master, file_salt, info, algo.key_size + algo.mac_key_len)


# ============================================================
# 后端实现
# ============================================================
class _AEAD:
    """AEAD 基类（GCM / OCB / ChaCha20-Poly1305）。"""

    aead = True
    mac_key_len = 0
    tag_size = TAG_LEN

    def encrypt(self, key, data, nonce, aad):
        raise NotImplementedError

    def decrypt(self, key, data, nonce, tag, aad):
        raise NotImplementedError


class AESGCM(_AEAD):
    id = "aes-256-gcm"
    key_size = 32
    nonce_size = 12

    def encrypt(self, key, data, nonce, aad):
        from Crypto.Cipher import AES

        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        if aad:
            c.update(aad)
        return c.encrypt_and_digest(data)

    def decrypt(self, key, data, nonce, tag, aad):
        from Crypto.Cipher import AES

        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        if aad:
            c.update(aad)
        try:
            return c.decrypt_and_verify(data, tag)
        except ValueError as exc:
            raise IntegrityError("AES-256-GCM 认证失败：密码错误或数据被篡改") from exc


class AESOCB(_AEAD):
    id = "aes-256-ocb"
    key_size = 32
    nonce_size = 12

    def encrypt(self, key, data, nonce, aad):
        from Crypto.Cipher import AES

        c = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=TAG_LEN)
        if aad:
            c.update(aad)
        return c.encrypt_and_digest(data)

    def decrypt(self, key, data, nonce, tag, aad):
        from Crypto.Cipher import AES

        c = AES.new(key, AES.MODE_OCB, nonce=nonce, mac_len=TAG_LEN)
        if aad:
            c.update(aad)
        try:
            return c.decrypt_and_verify(data, tag)
        except ValueError as exc:
            raise IntegrityError("AES-OCB3 认证失败：密码错误或数据被篡改") from exc


class ChaCha20Poly1305(_AEAD):
    id = "chacha20-poly1305"
    key_size = 32
    nonce_size = 12

    def encrypt(self, key, data, nonce, aad):
        from Crypto.Cipher import ChaCha20_Poly1305

        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            c.update(aad)
        return c.encrypt_and_digest(data)

    def decrypt(self, key, data, nonce, tag, aad):
        from Crypto.Cipher import ChaCha20_Poly1305

        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            c.update(aad)
        try:
            return c.decrypt_and_verify(data, tag)
        except ValueError as exc:
            raise IntegrityError("ChaCha20-Poly1305 认证失败：密码错误或数据被篡改") from exc


class AESCBC_HMAC:
    """AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC，PKCS7 填充）。"""

    id = "aes-256-cbc-hmac"
    aead = False
    key_size = 32
    mac_key_len = MAC_KEY_LEN
    tag_size = TAG_LEN
    nonce_size = 16

    def encrypt(self, key, data, nonce, aad):
        from Crypto.Cipher import AES

        enc_key = key[: self.key_size]
        mac_key = key[self.key_size: self.key_size + MAC_KEY_LEN]
        ct = AES.new(enc_key, AES.MODE_CBC, iv=nonce).encrypt(pad16(data))
        tag = hmac.new(mac_key, aad + ct, hashlib.sha256).digest()[:TAG_LEN]
        return ct, tag

    def decrypt(self, key, data, nonce, tag, aad):
        from Crypto.Cipher import AES

        enc_key = key[: self.key_size]
        mac_key = key[self.key_size: self.key_size + MAC_KEY_LEN]
        expect = hmac.new(mac_key, aad + data, hashlib.sha256).digest()[:TAG_LEN]
        if not hmac.compare_digest(expect, tag):
            raise IntegrityError("AES-256-CBC-HMAC 认证失败：密码错误或数据被篡改")
        return unpad16(AES.new(enc_key, AES.MODE_CBC, iv=nonce).decrypt(data))


class _Stream:
    """把 cryptography 的 CipherContext(.update) 适配为 .encrypt/.decrypt。"""

    def __init__(self, ctx):
        self._c = ctx

    def encrypt(self, data):
        return self._c.update(data)

    def decrypt(self, data):
        return self._c.update(data)


class _Both:
    """pycryptodome 的 cipher 对象同时具备 encrypt/decrypt，包一层统一接口。"""

    def __init__(self, obj):
        self._o = obj

    def encrypt(self, data):
        return self._o.encrypt(data)

    def decrypt(self, data):
        return self._o.decrypt(data)


class _EtM:
    """Encrypt-then-MAC 基类：CFB 流式加密 + HMAC-SHA256 认证标签。

    非 128 bit 分组密码（CAST5/Blowfish/3DES）必须使用 8 字节 IV。
    """

    aead = False
    mac_key_len = MAC_KEY_LEN
    tag_size = TAG_LEN
    key_size = 32
    nonce_size = 8

    def _cipher(self, key, iv, encrypt: bool):
        raise NotImplementedError

    def _fix_key(self, key: bytes) -> bytes:
        """默认不改；子类可覆盖（如 3DES 禁止退化密钥）。"""
        return key

    def encrypt(self, key, data, nonce, aad):
        enc_key = self._fix_key(key[: self.key_size])
        mac_key = key[self.key_size: self.key_size + MAC_KEY_LEN]
        ct = self._cipher(enc_key, nonce, True).encrypt(data)
        tag = hmac.new(mac_key, aad + ct, hashlib.sha256).digest()[:TAG_LEN]
        return ct, tag

    def decrypt(self, key, data, nonce, tag, aad):
        enc_key = self._fix_key(key[: self.key_size])
        mac_key = key[self.key_size: self.key_size + MAC_KEY_LEN]
        expect = hmac.new(mac_key, aad + data, hashlib.sha256).digest()[:TAG_LEN]
        if not hmac.compare_digest(expect, tag):
            raise IntegrityError(f"{self.id} 认证失败：密码错误或数据被篡改")
        return self._cipher(enc_key, nonce, False).decrypt(data)


class CamelliaCFB(_EtM):
    """Camellia-256-CFB + HMAC-SHA256（128 bit 分组，16 字节 IV）。"""

    id = "camellia-256-cfb-hmac"
    key_size = 32
    nonce_size = 16

    def _cipher(self, key, iv, encrypt: bool):
        from cryptography.hazmat.primitives.ciphers import Cipher

        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except Exception:  # pragma: no cover - 旧版本路径
            from cryptography.hazmat.primitives.ciphers.modes import CFB  # type: ignore
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
        except Exception:  # pragma: no cover - 旧版本路径
            from cryptography.hazmat.primitives.ciphers.algorithms import Camellia  # type: ignore

        ctx = Cipher(Camellia(key), CFB(iv))
        return _Stream(ctx.encryptor() if encrypt else ctx.decryptor())


class CASTCFB(_EtM):
    """CAST5-CFB + HMAC-SHA256（64 bit 分组，16 字节密钥）。"""

    id = "cast5-cfb-hmac"
    key_size = 16
    nonce_size = 8

    def _cipher(self, key, iv, encrypt: bool):
        from Crypto.Cipher import CAST

        return _Both(CAST.new(key, CAST.MODE_CFB, iv=iv))


class BlowfishCFB(_EtM):
    """Blowfish-CFB + HMAC-SHA256（64 bit 分组，32 字节密钥）。"""

    id = "blowfish-cfb-hmac"
    key_size = 32
    nonce_size = 8

    def _cipher(self, key, iv, encrypt: bool):
        from Crypto.Cipher import Blowfish

        return _Both(Blowfish.new(key, Blowfish.MODE_CFB, iv=iv))


class TripleDESCFB(_EtM):
    """Triple-DES-CFB + HMAC-SHA256（64 bit 分组，24 字节密钥）。"""

    id = "tripledes-cfb-hmac"
    key_size = 24
    nonce_size = 8

    def _fix_key(self, key: bytes) -> bytes:
        # 3DES 禁止 K1==K2==K3（退化为单 DES）；派生密钥极偶发命中时修正 1 bit。
        k = bytearray(key)
        if len(k) == 24 and k[0:8] == k[8:16] == k[16:24]:
            k[0] ^= 0x01
        return bytes(k)

    def _cipher(self, key, iv, encrypt: bool):
        from Crypto.Cipher import DES3

        return _Both(DES3.new(key, DES3.MODE_CFB, iv=iv))


# ============================================================
# 注册表
# ============================================================
_BACKENDS = {
    cls.id: cls for cls in (
        AESGCM, AESOCB, ChaCha20Poly1305, AESCBC_HMAC,
        CamelliaCFB, CASTCFB, BlowfishCFB, TripleDESCFB,
    )
}

_META = {
    "aes-256-gcm": {
        "name": {"zh_CN": "AES-256-GCM", "en_US": "AES-256-GCM"},
        "desc": {"zh_CN": "AEAD 标准，硬件加速，速度与安全俱佳（推荐）",
                 "en_US": "AEAD standard, HW-accelerated (recommended)"},
        "component": "pycryptodome", "priority": 100, "legacy": False,
    },
    "aes-256-ocb": {
        "name": {"zh_CN": "AES-256-OCB3", "en_US": "AES-256-OCB3"},
        "desc": {"zh_CN": "AEAD，认证加密效率高，适合大文件",
                 "en_US": "AEAD, high-throughput authenticated encryption"},
        "component": "pycryptodome", "priority": 90, "legacy": False,
    },
    "chacha20-poly1305": {
        "name": {"zh_CN": "ChaCha20-Poly1305", "en_US": "ChaCha20-Poly1305"},
        "desc": {"zh_CN": "AEAD，移动端友好，无硬件依赖也快",
                 "en_US": "AEAD, mobile-friendly, fast without HW"},
        "component": "pycryptodome", "priority": 85, "legacy": False,
    },
    "aes-256-cbc-hmac": {
        "name": {"zh_CN": "AES-256-CBC + HMAC", "en_US": "AES-256-CBC + HMAC"},
        "desc": {"zh_CN": "Encrypt-then-MAC，兼容性最好的经典组合",
                 "en_US": "Encrypt-then-MAC, maximally compatible classic combo"},
        "component": "pycryptodome", "priority": 70, "legacy": False,
    },
    "camellia-256-cfb-hmac": {
        "name": {"zh_CN": "Camellia-256 + HMAC", "en_US": "Camellia-256 + HMAC"},
        "desc": {"zh_CN": "国际标准分组密码，与 AES 同级安全性",
                 "en_US": "ISO/IEC standard block cipher, AES-grade security"},
        "component": "cryptography", "priority": 60, "legacy": False,
    },
    "cast5-cfb-hmac": {
        "name": {"zh_CN": "CAST5 + HMAC", "en_US": "CAST5 + HMAC"},
        "desc": {"zh_CN": "传统算法（RFC 2144），仅用于兼容旧系统",
                 "en_US": "Legacy (RFC 2144), compatibility only"},
        "component": "pycryptodome", "priority": 30, "legacy": True,
    },
    "blowfish-cfb-hmac": {
        "name": {"zh_CN": "Blowfish + HMAC", "en_US": "Blowfish + HMAC"},
        "desc": {"zh_CN": "传统算法，64 bit 分组，仅用于兼容旧系统",
                 "en_US": "Legacy 64-bit block cipher, compatibility only"},
        "component": "pycryptodome", "priority": 20, "legacy": True,
    },
    "tripledes-cfb-hmac": {
        "name": {"zh_CN": "Triple-DES + HMAC", "en_US": "Triple-DES + HMAC"},
        "desc": {"zh_CN": "传统算法（3DES），仅用于兼容旧系统",
                 "en_US": "Legacy 3DES, compatibility only"},
        "component": "pycryptodome", "priority": 10, "legacy": True,
    },
}


def _probe(algo_id: str) -> bool:
    """探测后端依赖是否可用（真正跑一遍最小加解密，密钥用散列避免退化）。"""
    try:
        algo = get_algorithm(algo_id)
        need = algo.key_size + algo.mac_key_len
        seed = hashlib.sha256(b"probe::" + algo_id.encode()).digest()
        key = (seed * (need // len(seed) + 1))[:need]
        nseed = hashlib.sha256(b"nonce::" + algo_id.encode()).digest()
        nonce = (nseed * (algo.nonce_size // len(nseed) + 1))[:algo.nonce_size]
        ct, tag = algo.encrypt(key, b"probe-data", nonce, b"aad")
        pt = algo.decrypt(key, ct, nonce, tag, b"aad")
        return pt == b"probe-data"
    except Exception:
        return False


_AVAILABLE: dict[str, bool] = {}


def _ensure_probed() -> None:
    if not _AVAILABLE:
        for aid in _BACKENDS:
            _AVAILABLE[aid] = _probe(aid)


def is_available(algo_id: str) -> bool:
    _ensure_probed()
    return bool(_AVAILABLE.get(algo_id))


def algorithm_ids() -> list[str]:
    return list(_BACKENDS.keys())


def available_ids() -> list[str]:
    return [a for a in _BACKENDS if is_available(a)]


def get_algorithm(algo_id: str):
    """返回算法实例（无状态，可复用）。"""
    cls = _BACKENDS.get(algo_id)
    if cls is None:
        raise AlgorithmError(f"未知加密算法：{algo_id}")
    return cls()


def algorithm_meta(algo_id: str) -> dict:
    if algo_id not in _BACKENDS:
        raise AlgorithmError(f"未知加密算法：{algo_id}")
    inst = get_algorithm(algo_id)
    m = dict(_META.get(algo_id, {}))
    m["id"] = algo_id
    m["key_size"] = inst.key_size
    m["nonce_size"] = inst.nonce_size
    m["tag_size"] = TAG_LEN
    m["aead"] = inst.aead
    m["available"] = is_available(algo_id)
    return m


def list_algorithms() -> list[dict]:
    """按优先级返回全部算法元数据。"""
    out = [algorithm_meta(a) for a in _BACKENDS]
    return sorted(out, key=lambda m: m.get("priority", 0), reverse=True)


def name_of(algo_id: str, lang: str = "zh_CN") -> str:
    m = _META.get(algo_id, {}).get("name", {})
    return m.get(lang) or m.get("en_US") or algo_id


def normalize_chain(chain) -> list[str]:
    """校验算法链：非空、已知、依赖可用、层数受限。"""
    if not chain:
        return [DEFAULT_ALGORITHM]
    ids = [str(c) for c in chain]
    for aid in ids:
        if aid not in _BACKENDS:
            raise AlgorithmError(f"未知加密算法：{aid}")
        if not is_available(aid):
            raise AlgorithmError(f"加密算法不可用（缺少依赖）：{aid}")
    if len(ids) > MAX_CHAIN:
        raise AlgorithmError(f"叠加层数过多：最多 {MAX_CHAIN} 层（当前 {len(ids)}）")
    return ids


def describe_chain(chain, lang: str = "zh_CN") -> str:
    return " → ".join(name_of(a, lang) for a in normalize_chain(chain))


# ============================================================
# 算法链堆叠加解密
# ============================================================
class CipherStack:
    """按顺序对每个数据块叠加应用算法链；层子密钥由主密钥 HKDF 派生。"""

    def __init__(self, chain, master: bytes, file_salt: bytes):
        self.ids = normalize_chain(chain)
        self.file_salt = bytes(file_salt)
        self.algos = [get_algorithm(a) for a in self.ids]
        self.keys = [derive_layer_key(master, self.file_salt, a, i)
                     for i, a in enumerate(self.ids)]

    def __len__(self) -> int:
        return len(self.ids)

    def encrypt_block(self, data: bytes, index: int, aad_base: bytes):
        ct = data
        tags: list[bytes] = []
        for i, (algo, key) in enumerate(zip(self.algos, self.keys)):
            nonce = _layer_nonce(self.file_salt, index, i, algo.nonce_size)
            ct, tag = algo.encrypt(key, ct, nonce, aad_base + bytes([i]))
            tags.append(tag)
        return ct, tags

    def decrypt_block(self, ct: bytes, tags: list[bytes], index: int, aad_base: bytes) -> bytes:
        data = ct
        for i in range(len(self.algos) - 1, -1, -1):
            algo = self.algos[i]
            key = self.keys[i]
            nonce = _layer_nonce(self.file_salt, index, i, algo.nonce_size)
            data = algo.decrypt(key, data, nonce, tags[i], aad_base + bytes([i]))
        return data
