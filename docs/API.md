# API 参考（API）

`app.core` 为纯逻辑层，无 UI 依赖，可脱离显示环境单测。以下为常用公共 API。

## 容器容器（container）

### 主密钥版（底层）

```python
ok, info = container.encrypt_file(src, dst, master)   # -> (bool, dict|str)
ok, info = container.decrypt_file(src, dst, master)   # -> (bool, dict|str)
info = container.read_meta(src)                        # 只读头部元数据
```

### 密码版（推荐，自描述头部）

```python
container.encrypt_stream_password(src, dst, password, chunk_size=None,
                                  progress=cb, cancel=cb)
container.decrypt_stream_password(src, dst, password, dst=None,
                                  progress=cb, cancel=cb)
# 便利包装：返回 (ok, res)
ok, res = container.encrypt_file_password(src, dst, password)
ok, res = container.decrypt_file_password(src, dst, password)
```

`dst=None` 时只做完整性校验、不落盘明文。

### 内存态

```python
blob = container.encrypt_bytes(data, master)
data = container.decrypt_bytes(blob, master)
```

## 密钥派生（kdf）

```python
master = kdf.derive_master(password, salt=None)         # 用当前激活参数
master = kdf.derive_master_custom(password, salt, kdf_name="argon2id",
                                  time_cost=3, memory_cost=65536,
                                  parallelism=2, iterations=600000)
kdf.set_active_params(params); kdf.set_active_salt(salt)
recipe = kdf.recipe()                                   # 当前配方（盐+参数）
```

## 保险库（vault）

```python
master = vault.derive_master(password)     # 读取 vault.json + config，派生可复现主密钥
vault.init()                               # 确保 vault.json / 参数存在
params = vault.get_params(); vault.set_params(params)
vault.apply_preset("balanced")
```

## 安全参数（security）

```python
p = security.SecurityParams(kdf="argon2id", argon2_time_cost=3, ...)
p.validate()                # -> [问题列表]
p.describe()                # -> "Argon2id(t=3, m=64MiB, p=2)"
security.preset("hardened")
p, dt = security.calibrate(max_memory_kib=256*1024)
```

## 审计（audit）

```python
audit.log("encrypt", {"file": "a.txt"})     # 写入哈希链
ok, msg = audit.verify()                     # 校验哈希链
```

## 其他

- `keystore.make_recovery_code(master)` → 55 字符恢复码
- `share.write_share_page(plaintext, password, dst, title=...)` → 自解密 HTML
- `archive` / `split` / `riskcheck` / `recent`：文件夹容器 / 分卷 / 风险检测 / 最近文件

生成最新签名清单：`python scripts/gen_docs.py`
