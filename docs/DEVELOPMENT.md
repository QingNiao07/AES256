# 开发指南（DEVELOPMENT）

## 环境准备

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

依赖：
- `argon2-cffi`（推荐，缺失时自动回退 PBKDF2）
- `cryptography`（AES-256-GCM）
- `PySide6`（可选，仅 Qt 前端）
- `tkinterdnd2`（可选，拖拽）
- `python-fido2`（可选，预留第二因子）

## 运行

```bash
python aes256_qt.py        # PySide6 图形界面
python aes256_tool.py      # Tkinter 图形界面（零第三方依赖）
python cli.py --help       # 命令行
```

## 测试

```bash
python -m pytest -q                       # 全量
python -m pytest tests/test_core.py -q    # 单文件
python -m compileall -q app cli.py        # 语法检查
```

## 项目脚手架

```bash
python init_project.py --out ./mydir      # 生成工程骨架
```

## 代码约定

- `app/core` 不得 import 任何 UI 库，保证可在无显示环境单测。
- 所有密钥/密码相关内存使用 `core/securemem.py` 擦除。
- 文件路径统一经 `app/paths.py` 解析。
- 新增功能务必补充 `tests/` 用例。

## 新增一个功能模块（示例：同盘风险检测）

1. 在 `app/core/riskcheck.py` 实现纯逻辑，返回结构化 dict。
2. 在 `cli.py` 注册子命令。
3. 在 `app/ui/qt/tools_panel.py` 加按钮，在 `app/ui/tk/main_tk.py` 加按钮。
4. 在 `tests/test_extras.py` 补断言。

## AI 助手

- 默认 `offline=True`，用户须显式勾选"允许联网"才出网。
- 出网前经 `services/ai/sanitize.py` 脱敏（路径/文件名/密文块替换为占位符）。
- 模型：`deepseek-flash`，`base_url=https://api.deepseek.com`（OpenAI 兼容）。
- 对话内容不写入 `operation.log`，仅记录元数据到 `ai_audit.log`。

## 打包

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --name aes256-qt aes256_qt.py
pyinstaller --onefile --name aes256-cli cli.py
```

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| F1 | 使用说明 |
| Ctrl+Shift+P | 命令面板 |
| Ctrl+Shift+A | AI 助手 |
| Ctrl+Shift+T | 切换主题 |
| Ctrl+Shift+E | 扩展工具 |
| Ctrl+L | 立即锁定 |
