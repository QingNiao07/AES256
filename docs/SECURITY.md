# 安全说明（SECURITY）

## 加密算法

| 环节 | 算法 | 参数 |
|------|------|------|
| 密钥派生 | Argon2id（回退 PBKDF2-HMAC-SHA256） | 可配置，默认 t=3 / m=64MiB / p=2 |
| 文件加密 | AES-256-GCM | 256 位密钥，12 字节随机 nonce（含块序号） |
| 子密钥派生 | HKDF-SHA256 | file_key / integrity_key 分离 |
| 完整性 | GCM tag（每块）+ HMAC-SHA256（整体） | 防篡改、防截断 |

## 可配置安全参数

安全参数集中在 `app/core/security.py` 的 `SecurityParams`，并提供三档预设：

| 预设 | 适用场景 | Argon2id | PBKDF2 |
|------|----------|----------|--------|
| `fast` | 低配机器 / 频繁解锁 | t=2, m=32MiB, p=1 | 30 万 |
| `balanced`（默认） | 普通台式 / 笔记本 | t=3, m=64MiB, p=2 | 60 万 |
| `hardened` | 高价值数据 / 工作站 | t=4, m=256MiB, p=4 | 120 万 |

用户可用 `scripts/benchmark.py --save` 让程序**实测本机性能**，自动挑选单次解锁
耗时落在 0.3\~1.0 秒区间的参数，兼顾安全与体验。

```python
from app.core import vault, SecurityParams

vault.apply_preset("hardened")          # 一键切到加固档
p, dt = vault.calibrate_and_save()      # 或按本机性能自动校准
```

## 密钥与盐

- **盐**：每个保险库一次性随机生成 16 字节，存入 `aes_log/vault.json`。盐不是秘密，
  但必须与密文一同保管。容器头部同时冗余记录盐与 KDF 参数。
- **自描述头部**：解密方从 `.aes256` 头部读回盐和 KDF 参数，重新派生出同一主密钥，
  因此**同一密码可稳定解密**。
- **密钥文件**：独立 `.keypack`，可与密文分离存放。
- **恢复码**：34 字节熵 → 55 个 base32 字符 → 11 组 × 5。

## 重要修正（v1.0 → v1.1）

> 早期版本用 `derive_master(pwd, salt=new_salt())` 派生主密钥，但随机盐**从未写入
> 容器**，导致「同一密码再次解密」必然失败——这是严重缺陷。v1.1 改用自描述头部
> v3 格式，将 KDF 盐与参数写入头部，密码级往返由此成立。

## 敏感操作

- 主密码、主密钥使用后经 `core/securemem.py` 擦除内存。
- 密码不入日志；`operation.log` 只记操作元数据。
- 默认离线：AI 助手需用户显式勾选「允许联网」，出网前经 `sanitize.py` 脱敏。

## 多加密方式与叠加加密（v1.1）

v1.1 起支持自选加密算法与叠加加密，但**始终只使用一个总密钥**：

| 环节 | 算法 | 说明 |
|------|------|------|
| 密钥派生 | Argon2id（一次） | 密码仅派生一次，得到唯一主密钥 |
| 各层子密钥 | HKDF-SHA256 | info = `stack-key::v1 | <算法id> | <层号>` 域分离 |
| 每层加密 | 用户选择的算法链 | AES-GCM / OCB3 / ChaCha20-Poly1305 / AES-CBC+HMAC / Camellia / CAST5 / Blowfish / 3DES |
| 完整性 | 每块每层 tag + 尾部 HMAC + 明文 SHA-256 | 防篡改、防截断、防重排 |

- 每层独立 nonce（由 文件盐 + 块序号 + 层序号 确定性导出），无 nonce 复用；
- 算法链写入头部并进入 AAD，篡改链顺序/算法会认证失败；
- 传统算法（CAST5 / Blowfish / 3DES）仅用于兼容旧系统，新数据不推荐；
- **叠加不能替代强密码**，只增加多算法冗余。详见 `docs/MULTI_CIPHER.md`。

## 离线与 AI 安全（v1.1）

- **网络守卫**（`app/core/netguard.py`）：默认启用时拦截一切非回环外发连接；
- **AI 安全策略**（`app/services/ai/policy.py`）：提示注入拦截、敏感内容拦截
  （私钥/长 hex/base32/API Key/明文口令）、输入长度上限、会话请求与字符额度、
  最小请求间隔、系统提示词硬约束（不索取/复述密码与密钥）；
- **出网脱敏**：路径、文件名、密文块等在发送前替换为占位符；
- **审计只记元数据**：对话正文不落盘，`ai_audit.log` 仅记录请求元数据。

## 作者与溯源

- 作者：青鸟（Qingniao） `<qingniao2007@126.com>`，见 `app/meta.py`；
- 关于页、分享页与审计报告均写入作者标识。

## 报告漏洞

请勿在公开 issue 中披露可利用细节；通过私有渠道联系维护者并附复现步骤。
