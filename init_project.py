# -*- coding: utf-8 -*-
"""
init_project.py
================
一键生成 AES-256 工具箱的完整目录结构。
适合：从零开始搭建项目，或给协作者一个干净的起点。

用法：
    python init_project.py                       # 在当前目录生成
    python init_project.py --output D:\\MyProj    # 指定输出目录
    python init_project.py --force               # 覆盖已有文件
    python init_project.py --no-ai               # 不生成 AI 三件套（纯离线版）
    python init_project.py --min               # 只生成最小可运行子集

本版本修正了原稿的三个缺陷：
1. `if __name__ == "__main__"` 在 Markdown 中被吞成粗体；
2. gen_project() 里遍历 STRUCTURE 写文件的循环整段丢失（原稿只会打印不生成）；
3. 缩进全丢 + TEMPLATES.get(key, "") 在键写错时静默生成空文件，
   现改为键一致性校验，写错直接抛错。
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

# ============================================================
# 目录结构定义
# ============================================================
STRUCTURE: dict[str, str | None] = {
    # ---- 入口 ----
    "aes256_tool.py": "main_tk",
    "aes256_qt.py": "main_qt",
    "aes256_core.py": "core_shim",
    "cli.py": "cli",

    # ---- 文档 ----
    "README.txt": "readme",
    "使用说明书.md": "manual_md",
    "一分钟上手指南.md": "cheatsheet",
    "更新日志.md": "changelog",
    "安全说明.md": "security_doc",
    "FAQ.md": "faq",
    "LICENSE": "license",

    # ---- 构建 ----
    "build.bat": "build_bat",
    "build.sh": "build_sh",
    "生成手册.bat": "gen_manual_bat",
    "打包发布.bat": "pack_release_bat",
    "build_manual.py": "build_manual",
    "build_release.py": "build_release",
    "build_all_versions.ps1": "build_all_ps1",
    "init_project.py": None,          # 自己，不生成

    # ---- CI ----
    ".github/workflows/build.yml": "ci_workflow",
    ".gitignore": "gitignore",
    ".editorconfig": "editorconfig",

    # ---- 依赖 ----
    "requirements.txt": "requirements",

    # ---- 开发文档 ----
    "DEVELOPMENT.md": "dev_doc",
    "ARCHITECTURE.md": "arch_doc",
    "CHANGELOG.md": "changelog",
    "CONTRIBUTING.md": "contributing",

    # ---- 目录占位 ----
    "docs/.gitkeep": "empty",
    "tests/.gitkeep": "empty",
    "tools/.gitkeep": "empty",
    "assets/.gitkeep": "empty",
}

# AI 三件套（--no-ai 时剔除）
AI_MODULES = {
    "app/services/ai/client.py": "ai_client",
    "app/services/ai/sanitize.py": "ai_sanitize",
    "app/services/ai/prompts.py": "ai_prompts",
    "app/ui/qt/ai_panel.py": "ai_panel",
}


# ============================================================
# 文件内容（节选模板；完整实现见仓库内真实文件）
# ============================================================
TEMPLATES: dict[str, str] = {
    "main_tk": '''# -*- coding: utf-8 -*-
"""aes256_tool.py · Tkinter 入口"""
import sys

def main():
    from app.core import db_init
    db_init()
    from app.ui.tk.main_tk import TkApp
    TkApp().run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
''',

    "main_qt": '''# -*- coding: utf-8 -*-
"""aes256_qt.py · PySide6 入口"""
import sys

def main():
    from PySide6.QtWidgets import QApplication
    from app.core import db_init
    db_init()
    app = QApplication(sys.argv)
    from app.ui.qt.main_window import MainWindow
    win = MainWindow()
    win.show()
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
''',

    "core_shim": '''# -*- coding: utf-8 -*-
"""aes256_core.py · 兼容垫片，转发到 app.core"""
import sys
from app.core import *
from app.core import state as _state

def __getattr__(name):
    try:
        return getattr(_state, name)
    except AttributeError:
        raise AttributeError(f"module 'aes256_core' has no attribute {name!r}") from None

if __name__ == "__main__":
    from app import core
    sys.exit(core.selftest())
''',

    "cli": '''# -*- coding: utf-8 -*-
"""cli.py · 命令行入口（加密 / 解密 / 校验 / 报告 / 密钥管理）"""
# 完整实现见仓库内真实文件 cli.py

if __name__ == "__main__":
    print("请使用仓库内的完整 cli.py")
''',

    "architecture_note": "",

    "readme": '''AES-256 加密工具箱
====================

【如何启动】
· 图形版：双击 AES256Tool.exe（首次 5-15 秒属正常）
· 命令行：python cli.py --help

【三步开始使用】
1. 输入密码 → 点"缓存密码"
2. 把文件拖进窗口 → 自动加密
3. 把 .aes256 文件拖进窗口 → 自动解密

【两条铁律】
· 永远不要删除密钥文件
· 首次使用不要勾选"删除原文件"

【完整使用说明】
程序内按 F1

【遇到问题】
查看程序目录 aes_log/ 目录下的日志

【安全提醒】
· 密码丢失无法恢复，请务必保管好
· 建议立即导出密钥文件保存到 U 盘，并抄写一份恢复码
· AI 助手默认离线；开启联网前请确认你接受把脱敏后的提问发送到云端
''',

    "manual_md": '''# AES-256 加密工具箱 · 使用说明书

版本：1.0
适用系统：Windows 10 / 11、macOS 11+、Linux

---

## 一、重要声明

本工具采用 **AES-256-GCM** 加密，具备以下**不可逆**特性：

1. **密码与密钥文件同时丢失 = 数据永久无法恢复**
2. **本工具不负责备份你的数据**
3. **使用合法性由用户承担**

---

## 二、快速上手

1. 设置密码（建议 ≥ 12 位，含大小写 / 数字 / 符号）
2. 点击"缓存密码"，密钥在内存中派生
3. 拖拽文件到主窗口 → 加密；拖拽 `.aes256` → 解密
4. 点击"导出密钥文件"（强烈推荐），并抄写一份恢复码

---

## 三、操作守则

| 序号 | 规则 | 原因 |
|---|---|---|
| 1 | 永远不要删除密钥文件 | 密码丢失时唯一挽救方式之一 |
| 2 | 首次使用不要勾选"删除原文件" | 先测试解密 |
| 3 | 密文不要与密钥文件同盘 | 等同于没加密 |
| 4 | 抄写一份恢复码 | 抗介质损坏 |

---

## 四、AI 助手与隐私

AI 助手（DeepSeek V4.1 Flash）：

- **默认离线**，不勾选"允许联网"时不会发起任何网络请求；
- 开启联网后，提问内容会先**脱敏**（路径 / 文件名 / 密文块被替换）再发送；
- 对话内容**不会**写入操作日志，只记录调用元数据；
- API Key 用主密钥派生的子密钥加密存储，不落明文。

如需**彻底禁用 AI**，删除 `app/services/ai/` 目录并移除界面中的 AI 面板即可。
''',

    "cheatsheet": '''# AES-256 工具箱 · 一分钟上手

## 三步开始
1. 输入密码 → 【缓存密码】
2. 拖文件进窗口 → 自动加密
3. 拖 .aes256 → 自动解密

## 两条铁律
- 永远不要删除密钥文件
- 首次使用不要勾选"删除原文件"

## 立即做
点击【导出密钥文件】保存到 U 盘，并抄写恢复码

## 快捷键
- F1 → 使用说明
- Ctrl+Shift+P → 命令面板
- Ctrl+Shift+A → AI 助手
- Ctrl+Shift+T → 切换主题
- Ctrl+L → 立即锁定
''',

    "changelog": '''# 更新日志

## [Unreleased]

## [1.0.0] - 2025-01-01
### 新增
- 项目初始版本
- AES-256-GCM 分块流式加解密
- Argon2id / PBKDF2 密钥派生
- 密钥文件导出 / 恢复码
- 审计链日志 + HTML 报告
- DeepSeek V4.1 Flash AI 助手（默认离线）
''',

    "security_doc": '''# 安全说明

## 加密算法
- 加密：AES-256-GCM（分块流式，每块独立 tag）
- 密钥派生：Argon2id（PBKDF2-HMAC-SHA256 自动回退）
- 子密钥：HKDF-SHA256
- 完整性：GCM tag + 尾部 HMAC-SHA256 + 明文 SHA-256
- 恢复码校验：HMAC-SHA256 校验位

## 安全特性
- 主密钥仅存内存，会话超时 / 退出时擦除
- 每文件独立 salt + nonce 前缀 + 块序号，杜绝 nonce 复用
- 防篡改（GCM + 尾部 HMAC + 明文哈希）
- 密码尝试限制
- 密钥内存擦除
- 审计日志哈希链，篡改可检出

## AI 组件的数据边界
- AI 默认离线；只有用户在界面显式勾选"允许联网"后才联网
- 出网前脱敏：本地路径 / 密钥文件名 / 长密文块被替换
- API Key 加密存储（主密钥派生子密钥 + AES-256-GCM）
- 对话内容不进入 operation.log

## 威胁模型
- 针对静态数据保护
- 不防止键盘记录器
- 不防止已入侵系统
- AI 联网时，脱敏后的问题会离开本机
''',

    "faq": '''# 常见问题

## 忘记密码怎么办？
无法恢复。请使用密钥文件或恢复码；两者都没有则数据永久丢失。

## 程序在哪存数据？
`aes_log/` 目录（日志、审计链、SQLite 元数据）。

## 拖拽不工作？
需要 tkinterdnd2 库；未安装时请用"选择文件"按钮。

## 杀毒软件报毒？
PyInstaller 单文件 exe 常见误报，加白名单。

## AI 助手连不上？
1) 确认已勾选"允许联网"；2) 确认已配置 API Key；
3) 查看 aes_log/ai_audit.log 的元数据。
''',

    "license": '''MIT License

Copyright (c) 2025 AES-256 Tool

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
''',

    "build_bat": '''@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   AES-256 工具 · 一键打包
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Python
    pause
    exit /b 1
)

python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt pyinstaller --quiet

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

python -m PyInstaller --noconfirm --clean ^
    --name "AES256Tool" --windowed --onefile ^
    --collect-all tkinterdnd2 ^
    --collect-all pystray ^
    --collect-all PIL ^
    --collect-all Crypto ^
    --collect-all argon2 ^
    --add-data "使用说明书.md;." ^
    --add-data "README.txt;." ^
    aes256_tool.py

if exist "dist\\AES256Tool.exe" (
    echo [成功] dist\\AES256Tool.exe
    explorer "dist"
)
pause
''',

    "build_sh": '''#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

pip3 install -r requirements.txt pyinstaller
rm -rf build dist *.spec

pyinstaller --noconfirm --clean \\
    --name "AES256Tool" --windowed --onefile \\
    --collect-all tkinterdnd2 \\
    --collect-all pystray \\
    --collect-all PIL \\
    --collect-all Crypto \\
    --collect-all argon2 \\
    --add-data "使用说明书.md:." \\
    --add-data "README.txt:." \\
    aes256_tool.py

echo "输出：dist/AES256Tool"
''',

    "gen_manual_bat": '''@echo off
chcp 65001 >nul
cd /d "%~dp0"
python build_manual.py
pause
''',

    "pack_release_bat": '''@echo off
chcp 65001 >nul
cd /d "%~dp0"
python build_manual.py
call build.bat
python build_release.py
pause
''',

    "build_manual": '''# -*- coding: utf-8 -*-
"""build_manual.py · 由 使用说明书.md 生成 HTML / PDF 手册"""

if __name__ == "__main__":
    print("build_manual.py：可用 markdown 生成 HTML；PDF 需 reportlab/weasyprint")
''',

    "build_release": '''# -*- coding: utf-8 -*-
"""build_release.py · 打分发 ZIP（含 exe、文档、校验文件）"""

if __name__ == "__main__":
    print("build_release.py：打包 dist 为 ZIP 并生成 SHA-256 校验")
''',

    "build_all_ps1": '''# 本地双版本构建（需同时安装 Python 3.10 与 3.12）
# .\\build_all_versions.ps1
''',

    "ci_workflow": '''name: Build

on:
  push:
    tags: ['v*']
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt pytest ruff
      - run: ruff check .
      - run: pytest -q

  build:
    needs: test
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -r requirements.txt pyinstaller
      - run: python -m PyInstaller --noconfirm --clean --name AES256Tool --windowed --onefile aes256_tool.py
      - uses: actions/upload-artifact@v4
        with:
          name: AES256Tool
          path: dist/AES256Tool.exe
''',

    "gitignore": '''# Python
__pycache__/
*.py[cod]
*.egg-info/
venv/
.venv/
env/

# PyInstaller
build/
dist/
*.spec

# 运行数据
aes_log/
*.key
*.aes256
*.bak
*.bak.*
*.part
*.zip.enc

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# 测试
.pytest_cache/
.coverage
htmlcov/
.ruff_cache/

# 发布
release/
''',

    "editorconfig": '''root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{md,txt}]
trim_trailing_whitespace = false

[*.{bat,ps1}]
end_of_line = crlf
''',

    "requirements": '''# 必需
pycryptodome>=3.19.0
requests>=2.31.0

# 推荐（安全强化 + 拖拽 + 托盘）
argon2-cffi>=23.1.0
tkinterdnd2>=0.4.2
pystray>=0.19.5
Pillow>=10.0.0

# 可选（PySide6 版本 UI）
PySide6>=6.6.0

# 可选（扩展）
cryptography>=41.0.0
sqlcipher3-binary>=0.5.3
python-fido2>=1.1.0
pykeepass>=4.0.0
reportlab>=4.0.0

# 开发
pytest>=7.4.0
ruff>=0.3.0
''',

    "dev_doc": '''# 开发文档

> 面向贡献者与维护者。用户请见 `使用说明书.md`。

## 快速开始

```bash
python -m venv venv
venv\\Scripts\\activate        # Windows
source venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
python aes256_qt.py            # 或 python aes256_tool.py
```

## 目录结构

```
aes256-tool/
├─ aes256_tool.py      Tkinter 入口
├─ aes256_qt.py        PySide6 入口
├─ aes256_core.py      兼容垫片
├─ cli.py              命令行
├─ app/
│  ├─ config.py  paths.py
│  ├─ core/     kdf cipher container keystore policy audit store securemem state
│  ├─ services/ jobs.py  ai/{client,sanitize,prompts}.py
│  └─ ui/       theme.py  qt/  tk/
├─ tests/  docs/  tools/  assets/
└─ 文档与构建脚本
```

## 核心接口（app/core）

```python
derive_master(pwd, salt=None)      # salt=None 用随机盐（推荐）
derive_backup_master(pwd)
derive_file_key(master, salt)
encrypt_bytes(data, master) / decrypt_bytes(blob, master)
encrypt_file(src, dst, master) / decrypt_file(src, dst, master)
load_policy() / save_policy(p)
check_password_policy(pwd) / password_strength(pwd)
db_init() / db_query(sql, params)
```

全局状态统一在 `app/core/state.py`：`set_master` / `get_master` / `clear_keys`。
`aes256_core.cached_master` 经兼容垫片转发到这里。

## 测试

```bash
pytest -q
pytest --cov=app --cov-report=html
```

## 打包

```bash
build.bat          # Windows
./build.sh         # Linux/macOS
python build_manual.py
python build_release.py --version 1.0.0
```

## 提交规范

`feat/fix/docs/style/refactor/test/chore(scope): subject`

## 常见问题

- exe 无法启动：查杀毒隔离区；或改 `--onedir`。
- 依赖装不上：换镜像 `-i https://pypi.tuna.tsinghua.edu.cn/simple`。
- 回退 Argon2id：`app/core/kdf.py` 设 `ARGON2_AVAILABLE = False` 或卸载 argon2-cffi。
''',

    "arch_doc": '''# 架构说明

## 分层

```
┌────────────────────────────────────┐
│  表现层 UI                          │
│  ├─ app/ui/qt  (PySide6)           │
│  └─ app/ui/tk  (Tkinter)           │
├────────────────────────────────────┤
│  应用层 Services                    │
│  ├─ jobs.py    任务队列/进度/取消   │
│  └─ ai/        DeepSeek + 脱敏      │
├────────────────────────────────────┤
│  领域层 Core                        │
│  ├─ kdf / cipher / container       │
│  ├─ keystore / policy              │
│  ├─ audit / store / securemem      │
│  └─ state      全局密钥状态         │
├────────────────────────────────────┤
│  基础设施                            │
│  config / paths / 文件系统 / SQLite │
└────────────────────────────────────┘
```

## 数据流

```
用户操作 → UI 事件 → JobQueue → core 加解密 → 文件系统 + SQLite → 审计 + 报告
```

## AI 数据流

```
提问/日志 → sanitize 脱敏 → 离线闸门 →（显式联网）→ DeepSeek → 流式回显
```

## 扩展点

- 新增 UI：只依赖 `app/core` 接口，参照 `app/ui/qt` 或 `app/ui/tk`。
- 新增 KDF：在 `app/core/kdf.py` 的 `derive_master` 加分支。
- 新增存储后端：替换 `container.py` 的流式写盘实现。
- 新增审计输出：扩展 `audit.write_html_report`。
- 替换模型：改 `config.json` 的 `ai.model` / `ai.base_url`，无需改代码。
''',

    "contributing": '''# 贡献指南

## 报告 Bug
请提供：系统版本、Python 版本、复现步骤、aes_log/operation.log。

## 提交代码
1. Fork → 2. 分支 feature/xxx → 3. 代码 + 测试 → 4. PR

## 开发前自检
```bash
ruff check .
pytest -q
```

## Code Review
- 至少 1 人审查
- 所有 CI 通过
- 覆盖率不下降
- 不引入 hardcode 密钥/密码
''',

    "empty": "",
}


# ============================================================
# 写入
# ============================================================
def write_file(path: Path, content: str, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def _validate_templates(structure: dict[str, str | None]) -> None:
    """键一致性校验：STRUCTURE 引用的模板键必须存在，否则报错。

    原稿用 TEMPLATES.get(key, "") 会在键写错时静默生成空文件，是最难查的 bug 类型。
    """
    missing = sorted({k for k in structure.values()
                      if k is not None and k not in TEMPLATES})
    if missing:
        raise KeyError(f"STRUCTURE 引用了不存在的模板键：{missing}")


def gen_project(out_dir: Path, force: bool = False, with_ai: bool = True,
                preset_name: str = "balanced") -> int:
    out_dir = out_dir.resolve()
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    structure = dict(STRUCTURE)
    if not with_ai:
        structure = {k: v for k, v in structure.items() if v not in AI_MODULES.values()}
    _validate_templates(structure)

    print("=" * 56)
    print("  AES-256 项目初始化工具")
    print("=" * 56)
    print(f"输出目录：{out_dir}")
    print(f"生成时间：{stamp}")
    print(f"AI 模块：{'包含' if with_ai else '不包含（纯离线版）'}\n")

    created, skipped = [], []
    for rel_path, key in structure.items():
        if key is None:
            continue
        content = TEMPLATES[key]
        if write_file(out_dir / rel_path, content, force):
            created.append(rel_path)
        else:
            skipped.append(rel_path)

    for d in ("docs", "tests", "tools", "assets", "aes_log"):
        (out_dir / d).mkdir(parents=True, exist_ok=True)

    # 写入安全参数预设（可配置安全参数，图片来源第 5 项）
    import json
    _presets = {
        "fast": {"preset": "fast", "argon2_time_cost": 2, "argon2_memory_cost": 32768,
                 "argon2_parallelism": 1, "pbkdf2_iterations": 300000,
                 "chunk_size": 8 * 1024 * 1024},
        "balanced": {"preset": "balanced", "argon2_time_cost": 3, "argon2_memory_cost": 65536,
                     "argon2_parallelism": 2, "pbkdf2_iterations": 600000,
                     "chunk_size": 4 * 1024 * 1024},
        "hardened": {"preset": "hardened", "argon2_time_cost": 4, "argon2_memory_cost": 262144,
                     "argon2_parallelism": 4, "pbkdf2_iterations": 1200000,
                     "chunk_size": 2 * 1024 * 1024},
    }
    cfg_path = out_dir / "config.json"
    if force or not cfg_path.exists():
        cfg_path.write_text(json.dumps({
            "version": 2,
            "security": {"kdf": "argon2id", "salt_len": 16, "nonce_prefix_len": 8,
                         "session_timeout_sec": 600, "max_password_attempts": 10,
                         **_presets.get(preset_name, _presets["balanced"])},
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[配置] 安全参数预设：{preset_name}")

    print(f"[完成] 新建 {len(created)} 个，跳过 {len(skipped)} 个已存在文件")
    if skipped:
        head = "、".join(skipped[:8])
        print(f"       跳过：{head}{' ...' if len(skipped) > 8 else ''}")
    print(f"""
下一步：
  1. cd {out_dir}
  2. pip install -r requirements.txt
  3. 用仓库内真实实现替换同名占位文件
  4. python aes256_tool.py       # Tkinter 运行
     或 python aes256_qt.py      # PySide6 运行
  5. build.bat                   # 打包 exe
""")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 AES-256 工具项目结构")
    parser.add_argument("--output", "-o", default=".", help="输出目录（默认当前目录）")
    parser.add_argument("--force", "-f", action="store_true", help="覆盖已有文件")
    parser.add_argument("--no-ai", action="store_true", help="不生成 AI 模块（纯离线版）")
    parser.add_argument("--preset", default="balanced",
                        choices=["fast", "balanced", "hardened"],
                        help="安全参数预设（默认 balanced）")
    parser.add_argument("--doctor", action="store_true",
                        help="生成后立即执行环境自检")
    args = parser.parse_args()
    rc = gen_project(Path(args.output), args.force, with_ai=not args.no_ai,
                     preset_name=args.preset)
    if args.doctor and rc == 0:
        import subprocess
        print("\n=== 运行环境自检 ===")
        subprocess.run([sys.executable, str(Path(__file__).with_name("scripts") / "doctor.py")],
                       cwd=str(Path(args.output).resolve()))
    return rc


if __name__ == "__main__":
    sys.exit(main())
