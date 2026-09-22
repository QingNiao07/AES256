# 移动版使用说明（Mobile Edition）

AES-256 加密工具箱提供**三种**可互相配合的使用形态：

| 形态 | 入口 | 适用 | 依赖 |
|------|------|------|------|
| 桌面 GUI | `python aes256_qt.py` / `python aes256_tool.py` | Windows / macOS / Linux | PySide6 或 Tk |
| 命令行 | `python cli.py ...` | 脚本化 / 服务器 | Python 3.9+ |
| **移动网页版（PWA）** | `python mobile/serve.py` | 手机 / 平板浏览器 | 仅需浏览器 |
| **Kivy 原生移动版** | `python mobile/kivy_app.py` | Android / iOS | Kivy |

---

## 一、移动网页版（PWA，推荐）

手机浏览器即可使用，**完全离线**，可"添加到主屏幕"像 App 一样打开。

### 启动
```bash
python mobile/serve.py                 # 本机试用：http://127.0.0.1:8765/
python mobile/serve.py --host 0.0.0.0  # 手机同一 Wi-Fi 访问：http://<电脑IP>:8765/
```
电脑与手机连同一 Wi-Fi，手机浏览器打开提示的地址即可。

### 功能
- **加密**：选择文件 → 输入两次密码 → 生成 `文件名.aes256` 并下载。
- **解密**：选择 `.aes256` → 输入密码 → 下载还原文件；显示容器信息（算法链 / KDF / 迭代）。
- **离线**：首次加载后由 Service Worker 缓存，断网也能用。
- **法务闸门**：首次使用必须本人勾选"我接受"才能继续。
- **中英切换**：右上角 `EN / 中文`。

### 浏览器安全限制（重要）
WebCrypto 只提供 `AES-GCM`、`ChaCha20-Poly1305`、`AES-CBC`，且**不提供 Argon2id**。
因此移动网页版的支持范围是：

- 算法链：**仅 `[aes-256-gcm]`**（单层）
- 密钥派生：**仅 PBKDF2-HMAC-SHA256**

---

## 二、桌面 ⇄ 移动 互通

只要桌面端用 **PBKDF2 + AES-256-GCM** 生成容器，网页端即可解密，反之亦然。

### 桌面端生成（供手机解密）
```bash
python cli.py enc 文件 --kdf pbkdf2
# 可选自定义迭代次数（需与手机端一致才可解密，默认 600000）：
python cli.py enc 文件 --kdf pbkdf2 --kdf-iters 600000
```

### 手机端加密 → 桌面端解密
手机端生成的 `.aes256` 直接拷回电脑：
```bash
python cli.py dec 文件名.aes256      # 自动识别 v4 容器与算法链
```

> 说明：桌面端默认的 **Argon2id** 容器仍可用桌面端正常解密；只是浏览器无法处理 Argon2id，
> 所以跨端场景请统一使用 `--kdf pbkdf2`。

### 单一总密钥
无论桌面端叠加了几层算法，密码始终只派生**一个总密钥**；移动端解码时读取容器头部
自描述的算法链与参数，保持同样的语义。

---

## 三、Kivy 原生移动版

复用桌面端同一套核心（`app.core.multicipher` / `kdf` / `security`），支持**全部 8 种算法与叠加**。

### 运行
```bash
pip install kivy
python mobile/kivy_app.py
```

### 打包 Android（APK）
需要 Linux + Android SDK/NDK：
```bash
pip install buildozer cython
cp mobile/buildozer.spec buildozer.spec
buildozer -v android debug
```
> 构建产物为 `bin/*.apk`，可安装到 Android 设备。iOS 需在 macOS 上用 kivy-ios 工具链打包。

---

## 四、移动端安全性

- **不出网**：网页版无任何外部请求；Service Worker 仅缓存同源资源。
- **本地处理**：加解密全部在浏览器内存中进行，文件不上传服务器。
- **一致强度**：PBKDF2 默认 600,000 次迭代（可在加密界面调整，但两端需一致）。
- **完整性**：容器 v4 的每块认证标签 + 尾部 HMAC + 明文 SHA-256 三重校验，篡改必被检出。
- **法务闸门**：与桌面端一致的"我接受"声明，勾选后记录于浏览器 `localStorage`。

---

## 五、开发者：互通测试

`mobile/tests/` 提供双向互通验证：

```bash
# 1) 桌面端生成测试容器（PBKDF2 + AES-GCM）
python mobile/tests/interop_gen.py mobile/tests/_io 200000

# 2) 移动端（Node 环境）解密并回写容器
node mobile/tests/interop_test.mjs mobile/tests/_io

# 3) 桌面端解密移动端容器
python mobile/tests/interop_dec.py mobile/tests/_io
```
全部通过即表示容器格式**逐字节互通**。

作者：青鸟 / Qingniao · <qingniao2007@126.com> · MIT
