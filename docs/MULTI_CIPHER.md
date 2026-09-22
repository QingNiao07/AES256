# 多加密方式与叠加加密（容器 v4）

本文说明 v1.1 起引入的「自选加密算法 + 叠加加密 + 单一总密钥」能力。

## 1. 核心约束：一个总密钥

无论用户选择 1 种还是多种算法叠加，**密码只做一次密钥派生**：

```
用户密码 ──Argon2id(一次)──▶ 主密钥 Master Key (64B)
                                   │  HKDF-SHA256 域分离
        ┌──────────────┬───────────┼────────────┬──────────────┐
        ▼              ▼           ▼            ▼              ▼
   层0 子密钥      层1 子密钥    层2 子密钥   层3 子密钥     完整性密钥
   (算法0)        (算法1)       (算法2)      (算法3)       (HMAC 尾部)
```

- 子密钥派生信息：`aes256-tool::stack-key::v1 | <算法id> | <层序号>`；
- 每层子密钥相互独立，即使同一算法叠加两次，两层密钥也不同；
- 因此不存在「多个密码 / 多把钥匙」，始终只有**一把总密钥**。

## 2. 支持的算法

| 算法 id | 名称 | 类型 | 密钥 | 依赖 |
|---|---|---|---|---|
| `aes-256-gcm` | AES-256-GCM | AEAD（推荐） | 32B | pycryptodome |
| `aes-256-ocb` | AES-256-OCB3 | AEAD | 32B | pycryptodome |
| `chacha20-poly1305` | ChaCha20-Poly1305 | AEAD | 32B | pycryptodome |
| `aes-256-cbc-hmac` | AES-256-CBC + HMAC | EtM | 32B+32B | pycryptodome |
| `camellia-256-cfb-hmac` | Camellia-256 + HMAC | EtM | 32B+32B | cryptography |
| `cast5-cfb-hmac` | CAST5 + HMAC | EtM（传统） | 16B+32B | pycryptodome |
| `blowfish-cfb-hmac` | Blowfish + HMAC | EtM（传统） | 32B+32B | pycryptodome |
| `tripledes-cfb-hmac` | Triple-DES + HMAC | EtM（传统） | 24B+32B | pycryptodome |

> 传统算法仅用于兼容旧系统，新数据建议使用 AES-256-GCM 或叠加 AEAD 算法。
> 依赖缺失的算法会在界面中置灰，`cli.py list-ciphers` 会标注不可用。

## 3. 加密顺序与叠加语义

- 算法链**自上而下**依次加密：`明文 → 算法0 → 算法1 → … → 密文`；
- 解密时**逆序**逐层还原；
- 每层使用独立 nonce（由 文件盐 + 块序号 + 层序号 确定性导出），杜绝 nonce 复用；
- 每块每层都有 16 字节认证标签；层认证失败即整体失败。

## 4. 容器格式（v4）

```
MAGIC="AES256v4" | ver=4 | kdf_id | flags | rsv
| kdf_salt(16) | file_salt(16)
| n_chain(1) | [ len(1) | algo_id ] × n_chain
| kdf_time(4) | kdf_mem(4) | kdf_par(2) | kdf_iters(4)
| chunk_size(4) | orig_size(8) | orig_sha256(32)
| name_len(2) | name
| 块0..块N-1 : ct_len(4) | 密文 | tag(16) × n_chain
| tail_hmac(32)
```

校验层次：

1. 头部进入 AAD → 篡改算法链/KDF 参数会认证失败；
2. 每块每层 tag → 块内篡改可检出；
3. 尾部 HMAC-SHA256（覆盖头部 + 全部密文与标签）→ 截断、重排可检出；
4. 头部记录明文 SHA-256 → 解密后二次校验，防止逻辑层损坏。

## 5. 命令行用法

```bash
# 查看全部算法与可用性
python cli.py list-ciphers
python cli.py list-ciphers --json

# 单选
python cli.py enc secret.dat --chain aes-256-gcm

# 叠加（三层）
python cli.py enc secret.dat --chain aes-256-gcm,chacha20-poly1305,aes-256-cbc-hmac

# 解密：自动读取头部算法链，无需重复指定
python cli.py dec secret.dat.aes256
```

## 6. 程序内 API

```python
from app.core import multicipher, algorithms

chain = ["aes-256-gcm", "chacha20-poly1305"]
ok, r = multicipher.encrypt_file_password("in.bin", "out.aes256", "密码", chain)
ok, r = multicipher.decrypt_file_password("out.aes256", "restored.bin", "密码")
meta = multicipher.read_meta("out.aes256")      # 只读头部，展示算法链
```

## 7. 安全建议

- 新数据优先 `aes-256-gcm`；需要算法多样性时可叠加 `chacha20-poly1305`；
- 叠加不提升「密码强度」，只是增加多算法冗余，**不能替代强密码**；
- 无论叠加与否，都必须妥善保管密钥文件与恢复码。
