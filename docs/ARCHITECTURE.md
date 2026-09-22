# 架构说明（ARCHITECTURE）

本项目是一个本地优先的 AES-256 文件加密工具箱，采用分层包结构，UI 与核心逻辑解耦，
命令行、PySide6、Tkinter 三种前端复用同一套 `app/core` 与 `app/services`。
自 v1.1 起支持多加密算法与叠加加密（容器 v4），但始终只使用一个总密钥；
并内置中英双语、离线网络守卫与 AI 安全限制。

## 分层结构

```
aes256-tool/
├─ aes256_qt.py        # PySide6 入口
├─ aes256_tool.py      # Tkinter 入口（无第三方依赖）
├─ cli.py              # 命令行入口（批量/文件夹/分卷/分享页/审计）
├─ aes256_core.py      # 兼容垫片：把 app.core 暴露为旧版单文件 API
├─ init_project.py     # 工程脚手架生成器
├─ app/
│  ├─ config.py, paths.py          # 配置与路径解析
│  ├─ core/                        # 【纯逻辑层】无 UI 依赖，可单测
│  │   ├─ kdf.py         Argon2id / PBKDF2 派生
│  │   ├─ cipher.py      AES-256-GCM 分块加解密
│  │   ├─ algorithms.py  多加密算法注册表 + CipherStack（8 种）
│  │   ├─ multicipher.py 容器 v4：算法链叠加、单一总密钥
│  │   ├─ netguard.py    离线网络守卫
│  │   ├─ container.py   v2 容器格式（头部/块/HMAC 尾部）
│  │   ├─ keystore.py    密钥文件 + 恢复码
│  │   ├─ policy.py      密码强度策略
│  │   ├─ audit.py       操作审计日志
│  │   ├─ store.py       SQLite 状态库
│  │   ├─ state.py       应用状态
│  │   ├─ securemem.py   安全内存擦除
│  │   ├─ archive.py     文件夹容器（整目录↔单文件）
│  │   ├─ split.py       分卷切分/合并
│  │   ├─ share.py       自解密分享页 HTML
│  │   ├─ riskcheck.py   同盘/同目录风险检测
│  │   └─ recent.py      最近文件 / 收藏夹
│  ├─ services/                    # 【服务层】
│  │   ├─ jobs.py        任务队列（进度/取消）
│  │   └─ ai/            DeepSeek 接入
│  │       ├─ client.py  OpenAI 兼容 HTTP 客户端
│  │       ├─ sanitize.py 出网脱敏
│  │       └─ prompts.py  提示词模板
│  └─ ui/                          # 【表现层】
│      ├─ theme.py       主题令牌 + QSS 生成
│      ├─ qt/            PySide6 组件
│      └─ tk/main_tk.py  Tkinter 单窗口
└─ tests/              111 个用例
```

## 数据流

```
用户操作 → UI(ui/) → 服务(services/jobs) → 核心(core/) → 磁盘
                                   ↘ AI(services/ai) → 脱敏 → HTTPS
```

## 容器格式 v2

```
[ magic(8) | ver(1) | flags(1) | salt(16) | chunk_size(4) | orig_size(8) ]
[ base_nonce(8) ]
[ 块0: len(4) | ciphertext | tag(16) ] ... [ 块N ]
[ hmac(32) ]
```
- 每块独立 12 字节 nonce（base_nonce 前缀 + 块序号），杜绝 nonce 重用。
- 尾部 HMAC-SHA256 覆盖头部与全部密文，防篡改。
- 解密按头部 `orig_size / chunk_size` 预计算块数，避免把尾部 HMAC 误读为块。

## 容器格式 v4（多算法叠加，单一总密钥）

```
[ magic(8)="AES256v4" | ver=4 | kdf_id(1) | flags(1) | rsv(1) ]
[ kdf_salt(16) | file_salt(16) ]
[ n_chain(1) | [ len(1) | algo_id ] × n_chain ]
[ kdf_time(4) | kdf_mem(4) | kdf_par(2) | kdf_iters(4) ]
[ chunk_size(4) | orig_size(8) | orig_sha256(32) | name_len(2) | name ]
[ 块0..块N-1: ct_len(4) | ciphertext | tag(16) × n_chain ]
[ tail_hmac(32) ]
```
- 密码只经一次 Argon2id 派生主密钥；各层子密钥由 HKDF 域分离得到 → 始终只有**一个总密钥**。
- 算法链自上而下依次加密，解密逆序；每层 nonce 由 (file_salt, 块号, 层号) 确定性导出。
- 头部进入 AAD；每块每层独立 tag；尾部 HMAC + 明文 SHA-256 双重校验。

## 密钥与安全

- KDF：Argon2id（缺失时回退 PBKDF2-HMAC-SHA256，600k 迭代）。
- 盐：每次加密随机生成，绝不复用固定盐；自描述头部记录盐与 KDF 参数。
- 密钥文件：独立 `.keypack`，可与密文分离存放。
- 恢复码：34 字节熵 → 55 个 base32 字符 → 11 组 × 5 字符。
- AI Key：用主密钥派生子密钥加密存储于 `ai_secret.bin`；默认离线。
- 离线守卫：`netguard.py` 启用后拦截一切非回环外发连接。
- AI 限制：`services/ai/policy.py` 负责注入拦截、敏感内容拦截、会话额度与频率。

## 扩展点

- 新增加密算法：在 `core/algorithms.py` 实现后端并登记 `_BACKENDS` / `_META`。
- 新增密文变换：在 `core/` 加模块，`cli.py` 与 `ui/` 各注册一个入口。
- 新增 AI 供应商：在 `services/ai/client.py` 增加适配器。
- 新增主题：在 `ui/theme.py` 增加令牌字典即可。
- 新增语言：在 `i18n/catalog.py` 的 `CATALOG` 增加语言表并加入 `SUPPORTED`。
