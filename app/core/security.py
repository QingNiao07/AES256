# -*- coding: utf-8 -*-
"""
app/core/security.py
====================
可配置的安全参数体系（图片第 5 项）。

设计动机
--------
原实现把 Argon2id 的 time_cost / memory_cost / parallelism 写死在 kdf.py，
等于强制所有人都用同一档强度：低配机器只能用偏弱参数，高配机器又浪费算力。
这里把全部安全敏感参数外置为 `SecurityParams`，并提供：

- 三档预设：fast / balanced / hardened；
- 本机性能校准 calibrate()：实测派生耗时，在内存上限内自动挑出落在
  目标耗时区间（默认 0.3~1.0 秒）的组合；
- 与 config.json 的读写（to_config / apply_to_config / from_config）。

注意
----
- 参数只影响新加密的派生强度；解密旧文件仍按容器头记录的参数（salt 等）工作。
- 强度越高，解锁越慢但抗暴力破解越强，用户需按机器性能权衡。
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any

# 目标解锁耗时区间（秒）：低于下限太弱，高于上限体验差
TARGET_MIN_SEC = 0.3
TARGET_MAX_SEC = 1.0

# 内存上限（KiB）：默认 256 MiB，避免在低配机器上触发 OOM
DEFAULT_MAX_MEMORY_KIB = 256 * 1024

PRESET_NAMES = ("fast", "balanced", "hardened")


@dataclass
class SecurityParams:
    """全部安全敏感参数的唯一载体。"""

    kdf: str = "argon2id"                 # argon2id | pbkdf2
    argon2_time_cost: int = 3             # Argon2 迭代次数（pass 数）
    argon2_memory_cost: int = 65536       # KiB，64 MiB
    argon2_parallelism: int = 2           # 并行度（线程数）
    pbkdf2_iterations: int = 600_000      # Argon2 不可用时的回退强度
    salt_len: int = 16                    # 盐长度（字节）
    nonce_prefix_len: int = 8             # 每文件 nonce 前缀长度（字节）
    chunk_size: int = 4 * 1024 * 1024     # 分块大小（字节）
    session_timeout_sec: int = 600        # 会话空闲超时（秒）
    max_password_attempts: int = 10       # 解锁尝试上限

    # ------------------------------------------------------------
    # 序列化
    # ------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SecurityParams":
        if not isinstance(data, dict):
            return cls()
        allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in allowed}
        return cls(**clean)

    # ------------------------------------------------------------
    # 校验
    # ------------------------------------------------------------
    def validate(self) -> list[str]:
        """返回问题列表；空列表表示合法。"""
        errs: list[str] = []
        if self.kdf not in ("argon2id", "pbkdf2"):
            errs.append(f"未知 kdf: {self.kdf}")
        if self.argon2_time_cost < 1:
            errs.append("argon2_time_cost 必须 >= 1")
        if self.argon2_memory_cost < 8 * 1024:
            errs.append("argon2_memory_cost 低于 8 MiB，太弱")
        if self.argon2_parallelism < 1:
            errs.append("argon2_parallelism 必须 >= 1")
        if self.pbkdf2_iterations < 100_000:
            errs.append("pbkdf2_iterations 低于 10 万，太弱")
        if self.salt_len < 16:
            errs.append("salt_len 至少 16 字节")
        if self.nonce_prefix_len < 4:
            errs.append("nonce_prefix_len 至少 4 字节（防 nonce 重用）")
        if self.chunk_size < 64 * 1024:
            errs.append("chunk_size 至少 64 KiB")
        if self.session_timeout_sec < 60:
            errs.append("session_timeout_sec 至少 60 秒")
        if self.max_password_attempts < 1:
            errs.append("max_password_attempts 必须 >= 1")
        return errs

    def describe(self) -> str:
        if self.kdf == "argon2id":
            return (f"Argon2id(t={self.argon2_time_cost}, "
                    f"m={self.argon2_memory_cost // 1024}MiB, "
                    f"p={self.argon2_parallelism})")
        return f"PBKDF2-SHA256({self.pbkdf2_iterations} 迭代)"


# ================================================================
# 三档预设
# ================================================================
PRESETS: dict[str, SecurityParams] = {
    # 低配 / 快速：树莓派、老旧笔记本
    "fast": SecurityParams(
        argon2_time_cost=2, argon2_memory_cost=32 * 1024, argon2_parallelism=1,
        pbkdf2_iterations=300_000, chunk_size=8 * 1024 * 1024,
        session_timeout_sec=1800, max_password_attempts=20,
    ),
    # 均衡 / 默认：普通台式与笔记本
    "balanced": SecurityParams(
        argon2_time_cost=3, argon2_memory_cost=64 * 1024, argon2_parallelism=2,
        pbkdf2_iterations=600_000, chunk_size=4 * 1024 * 1024,
        session_timeout_sec=600, max_password_attempts=10,
    ),
    # 加固 / 高价值数据：工作站
    "hardened": SecurityParams(
        argon2_time_cost=4, argon2_memory_cost=256 * 1024, argon2_parallelism=4,
        pbkdf2_iterations=1_200_000, chunk_size=2 * 1024 * 1024,
        session_timeout_sec=300, max_password_attempts=5,
    ),
}


def preset(name: str) -> SecurityParams:
    return replace(PRESETS.get(name, PRESETS["balanced"]))


def preset_names() -> tuple[str, ...]:
    return PRESET_NAMES


# ================================================================
# 本机性能校准
# ================================================================
def _measure(params: SecurityParams, password: str = "calibration-probe") -> float:
    """实测一次派生耗时（秒）。不依赖 kdf.py 的全局参数。"""
    import hashlib
    import os

    salt = os.urandom(max(16, params.salt_len))
    pwd = password.encode("utf-8")
    t0 = time.perf_counter()
    if params.kdf == "argon2id":
        try:
            from argon2.low_level import Type, hash_secret_raw

            hash_secret_raw(
                secret=pwd, salt=salt,
                time_cost=params.argon2_time_cost,
                memory_cost=params.argon2_memory_cost,
                parallelism=params.argon2_parallelism,
                hash_len=32, type=Type.ID,
            )
        except Exception:
            # Argon2 不可用：回退测量 PBKDF2
            hashlib.pbkdf2_hmac("sha256", pwd, salt,
                                params.pbkdf2_iterations, dklen=32)
    else:
        hashlib.pbkdf2_hmac("sha256", pwd, salt,
                            params.pbkdf2_iterations, dklen=32)
    return time.perf_counter() - t0


def calibrate(
    max_memory_kib: int = DEFAULT_MAX_MEMORY_KIB,
    target_min: float = TARGET_MIN_SEC,
    target_max: float = TARGET_MAX_SEC,
    base: SecurityParams | None = None,
) -> tuple[SecurityParams, float]:
    """
    按本机实际性能挑出一组参数，使单次派生耗时落入 [target_min, target_max]。

    策略：固定 parallelism=1 保证可比性，在内存上限内从低到高试 memory_cost，
    每次用单次测量估算，再按比例调整 time_cost，最后复测一次。

    返回 (params, 实测耗时秒)。
    """
    import os

    if not _argon2_ok():
        # 无 Argon2：只校准 PBKDF2 迭代数
        p = replace(base or PRESETS["balanced"], kdf="pbkdf2")
        lo, hi = 100_000, 4_000_000
        best = p
        for _ in range(8):
            mid = (lo + hi) // 2
            best = replace(p, pbkdf2_iterations=mid)
            dt = _measure(best)
            if dt < target_min:
                lo = mid
            elif dt > target_max:
                hi = mid
            else:
                break
        return best, _measure(best)

    max_mem = max(8 * 1024, min(max_memory_kib, 1024 * 1024))
    # 候选内存档位（KiB）
    ladder = [8, 16, 32, 64, 128, 192, 256, 384, 512, 768, 1024]
    ladder = [m * 1024 for m in ladder if m * 1024 <= max_mem]
    if not ladder:
        ladder = [max_mem]

    chosen = replace(base or PRESETS["balanced"], kdf="argon2id",
                     argon2_parallelism=1)
    for mem in ladder:
        p = replace(chosen, argon2_memory_cost=mem, argon2_time_cost=1)
        dt1 = _measure(p)
        # 估算需要的 time_cost
        if dt1 <= 0:
            continue
        est = max(1, round(target_min / dt1))
        p = replace(p, argon2_time_cost=min(est, 10))
        dt = _measure(p)
        if dt <= target_max and dt >= target_min:
            return p, dt
        chosen = p
        if dt > target_max:
            break
    # 兜底：返回最后一次测量结果
    return chosen, _measure(chosen)


def _argon2_ok() -> bool:
    try:
        import argon2  # noqa: F401

        return True
    except Exception:
        return False


# ================================================================
# 与 config.json 对接
# ================================================================
CONFIG_SECTION = "security"


def from_config(cfg: dict[str, Any] | None) -> SecurityParams:
    """从完整配置字典中取 security 段；缺失用 balanced 预设补。"""
    section = (cfg or {}).get(CONFIG_SECTION)
    if not isinstance(section, dict):
        # 兼容：老配置把 chunk_size 等放在顶层
        flat: dict[str, Any] = {}
        top = cfg or {}
        for k in ("chunk_size", "session_timeout_sec", "max_password_attempts"):
            if k in top:
                flat[k] = top[k]
        return SecurityParams.from_dict({**PRESETS["balanced"].to_dict(), **flat})
    return SecurityParams.from_dict({**PRESETS["balanced"].to_dict(), **section})


def to_config(params: SecurityParams, cfg: dict[str, Any]) -> dict[str, Any]:
    """把参数写回配置字典的 security 段，并同步旧顶层键（向后兼容）。"""
    out = dict(cfg)
    out[CONFIG_SECTION] = params.to_dict()
    # 向后兼容：保持在顶层也可见，老代码读取不受影响
    out["chunk_size"] = params.chunk_size
    out["session_timeout_sec"] = params.session_timeout_sec
    out["max_password_attempts"] = params.max_password_attempts
    return out
