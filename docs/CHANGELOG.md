# 版本记录（CHANGELOG）

## v1.3.0

### 新增：移动版（桌面 / 移动双端）
- **移动网页版（PWA）**：`mobile/www/`
  - `mobile/www/js/v4crypto.js`：纯 WebCrypto 加密核心，与桌面端容器 v4
    **逐字节互通**（PBKDF2-HMAC-SHA256 + AES-256-GCM）；含 HKDF 域分离、
    确定性层 nonce、每块认证标签、尾部 HMAC 与明文 SHA-256 校验。
  - `mobile/www/index.html` + `js/app.js`：响应式触摸 UI，加密 / 解密 /
    关于三个标签页，中英双语切换，"添加到主屏幕"安装。
  - `mobile/www/sw.js`：Service Worker 离线缓存（首次加载后完全离线可用）。
  - `mobile/www/js/legal.js`：与桌面端一致的《法律声明与免责协议》与
    「我接受」首次运行闸门，状态存于 `localStorage`。
  - `mobile/serve.py`：零依赖本地静态服务器（仅监听本机/局域网，不出网）。
- **Kivy 原生移动版**：`mobile/kivy_app.py`
  - 复用桌面端核心（`app.core.multicipher` / `kdf` / `security`），支持全部
    8 种算法与叠加；触摸友好的标签页界面；同样带法务闸门与中英切换。
  - `mobile/buildozer.spec`：Android（APK）打包配置。
- **桌面端互通开关**：`cli.py enc` 新增 `--kdf pbkdf2` 与 `--kdf-iters`，
  生成浏览器可解密的容器；`--chain` 省略时回退为 `[aes-256-gcm]`。
- **文档**：新增 `docs/MOBILE.md`（移动版使用与互通说明）。
- **测试**：新增 `tests/test_mobile.py`（v4 PBKDF2 往返、头部自描述、
  错误密码拒绝、JS 常量一致性、CLI 选项、移动目录完整性）；
  `mobile/tests/` 提供 Python⇄JavaScript 双向互通验证脚本。
- 版本号 1.2.0 → 1.3.0。

## v1.2.0

### 新增：法律条款与免责协议
- `app/legal.py`：集中的法务文本（中英双语）
  - 软件合法性说明（`legality`）；
  - 安装与使用声明（`declaration`）：合法用途 + 符合社会主义核心价值观；
  - 作者免责声明（`disclaimer`）；
  - 免责协议条款（`liability`）：明确划分使用者责任与作者责任。
- `docs/LEGAL.md`：完整法律声明与免责协议文档。

### 新增：安装程序与「我接受」强制闸门
- `install.py`：零依赖安装向导（Tk 图形向导 + 命令行 + 无界面）。
  - **只有使用者本人勾选「我接受」后，才能完成安装**；
  - 无界面安装必须显式 `--accept`，否则拒绝安装（返回码 2）；
  - 命令行安装需输入「我接受」，否则终止（返回码 3）；
  - 支持 `--check` 仅检查依赖与法务状态。
- `app/ui/qt/legal_dialog.py` / `app/ui/tk/legal_tk.py`：安装与首次运行共用的
  条款展示 + 「我接受」确认对话框（未勾选则按钮禁用）。
- 图形版与 Tk 版**首次运行**均强制先确认条款（返回码 4 表示拒绝）。
- 接受状态写入 `config.json` 的 `legal` 段（`accepted` / `version` /
  `accepted_at`），并记入审计日志，可追溯。

### 优化：操作说明
- 重写 `README.txt`：以「安装 → 启动 → 三步使用」为主线的优化操作说明，并增加
  法律与免责章节。
- 新增根目录 `使用说明书.md`（Tk 版帮助 F1 直接读取）。
- 更新 `docs/LEGAL.md`；关于页显示作者与法务状态。

### 其他
- 版本号 1.1.0 → 1.2.0；i18n 新增法务与安装相关文案。
- 新增 `tests/test_legal.py`；测试总数 111 → 121，全部通过。

## v1.1.0

### 新增：多加密方式与叠加加密
- `app/core/algorithms.py`：8 种加密算法注册表
  （AES-256-GCM / AES-256-OCB3 / ChaCha20-Poly1305 / AES-256-CBC+HMAC /
   Camellia-256+HMAC / CAST5 / Blowfish / Triple-DES）。
- `app/core/multicipher.py`：容器格式 v4，支持算法链**叠加加密**。
- **单一总密钥约束**：密码仅经一次 Argon2id 派生主密钥，各层子密钥由
  HKDF-SHA256 域分离得到；无论叠加几种算法，始终只有一个总密钥。
- `app/ui/qt/cipher_dialog.py`：加密方式选择对话框（单选 / 叠加 / 排序）。
- CLI：新增 `--chain` 与 `list-ciphers` 子命令；`dec` 自动识别 v4 头部。

### 新增：中英双语（i18n）
- `app/i18n/`：`catalog.py` 文案表 + 运行时 `tr()` / `set_language()`。
- 配置持久化语言；Qt 菜单与 Tk 按钮可运行时切换。

### 新增：离线安全加固
- `app/core/netguard.py`：默认启用的网络守卫，拦截一切非回环外发连接。
- 入口文件初始化守卫；AI 出网前显式校验目标主机。

### 新增：AI 安全限制
- `app/services/ai/policy.py`：提示注入拦截、敏感内容拦截（私钥 / 长
  hex/base32 / API Key / 明文口令）、输入长度上限、会话额度、请求频率、
  系统提示词硬约束（不索取 / 不复述密码与密钥）。

### 新增：作者信息
- `app/meta.py`：作者 青鸟（Qingniao）`<qingniao2007@126.com>`；
  写入关于页、分享页与审计报告。

### 改进：界面现代化
- `app/ui/theme.py`：卡片式面板、圆角控件、悬停高亮、胶囊按钮等 QSS 升级。

### 修复
- 修正 v4 尾部 HMAC 的更新顺序（密文先于 tag），确保密码级往返可信。
- 修正 64 位分组密码（CAST5 / Blowfish / 3DES）使用 8 字节 IV。
- 修正 Camellia 迁移到 cryptography `decrepit` 命名空间后的 CFB 调用。
- 处理 3DES 退化密钥（K1==K2==K3）导致的构造异常。

### 测试
- 新增 `tests/test_algorithms.py`、`test_multicipher.py`、`test_i18n.py`、
  `test_hardening.py`；测试总数 51 → 111，全部通过。

## v1.0.0
- 首个工程化版本：分层包结构、DeepSeek AI 接入、11 项扩展工具、
  PySide6 / Tkinter 双前端、命令行、51 项测试。


### 新增：多加密方式与叠加加密
- `app/core/algorithms.py`：8 种加密算法注册表
  （AES-256-GCM / AES-256-OCB3 / ChaCha20-Poly1305 / AES-256-CBC+HMAC /
   Camellia-256+HMAC / CAST5 / Blowfish / Triple-DES）。
- `app/core/multicipher.py`：容器格式 v4，支持算法链**叠加加密**。
- **单一总密钥约束**：密码仅经一次 Argon2id 派生主密钥，各层子密钥由
  HKDF-SHA256 域分离得到；无论叠加几种算法，始终只有一个总密钥。
- `app/ui/qt/cipher_dialog.py`：加密方式选择对话框（单选 / 叠加 / 排序）。
- CLI：新增 `--chain` 与 `list-ciphers` 子命令；`dec` 自动识别 v4 头部。

### 新增：中英双语（i18n）
- `app/i18n/`：`catalog.py` 文案表 + 运行时 `tr()` / `set_language()`。
- 配置持久化语言；Qt 菜单与 Tk 按钮可运行时切换。

### 新增：离线安全加固
- `app/core/netguard.py`：默认启用的网络守卫，拦截一切非回环外发连接。
- 入口文件初始化守卫；AI 出网前显式校验目标主机。

### 新增：AI 安全限制
- `app/services/ai/policy.py`：提示注入拦截、敏感内容拦截（私钥 / 长
  hex/base32 / API Key / 明文口令）、输入长度上限、会话额度、请求频率、
  系统提示词硬约束（不索取 / 不复述密码与密钥）。

### 新增：作者信息
- `app/meta.py`：作者 青鸟（Qingniao）`<qingniao2007@126.com>`；
  写入关于页、分享页与审计报告。

### 改进：界面现代化
- `app/ui/theme.py`：卡片式面板、圆角控件、悬停高亮、胶囊按钮等 QSS 升级。

### 修复
- 修正 v4 尾部 HMAC 的更新顺序（密文先于 tag），确保密码级往返可信。
- 修正 64 位分组密码（CAST5 / Blowfish / 3DES）使用 8 字节 IV。
- 修正 Camellia 迁移到 cryptography `decrepit` 命名空间后的 CFB 调用。
- 处理 3DES 退化密钥（K1==K2==K3）导致的构造异常。

### 测试
- 新增 `tests/test_algorithms.py`、`test_multicipher.py`、`test_i18n.py`、
  `test_hardening.py`；测试总数 51 → 111，全部通过。

## v1.0.0
- 首个工程化版本：分层包结构、DeepSeek AI 接入、11 项扩展工具、
  PySide6 / Tkinter 双前端、命令行、51 项测试。
