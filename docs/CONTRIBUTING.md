# 贡献指南（CONTRIBUTING）

感谢参与！本项目目标是「本地优先、离线可用、可审计」的加密工具箱。

## 5 分钟上手

```bash
git clone <repo> && cd aes256-tool
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/doctor.py        # 环境自检
python scripts/run_tests.py     # 编译 + 测试
```

## 目录约定

- `app/core/`：纯逻辑，**禁止 import 任何 UI 库**，必须可在无显示环境单测。
- `app/services/`：编排、任务队列、AI。
- `app/ui/`：仅做展示与交互，业务逻辑下沉到 core/services。
- `scripts/`：自动化脚本，每个都应 `--help` 可用。
- `tests/`：与模块一一对应。

## 编码规范

- Python 3.9+，`from __future__ import annotations`。
- 每个公共函数写 docstring（首行是一句话摘要，供 `gen_docs.py` 提取）。
- 敏感内存使用 `core/securemem.py` 擦除；路径统一经 `app/paths.py`。
- 新增功能必须补测试；安全相关变更必须更新 `docs/SECURITY.md`。

## 提交前检查

```bash
python scripts/run_tests.py     # 编译 + 全量测试必须全绿
python scripts/doctor.py        # 环境自检
```

## 新增一个功能模块

1. `app/core/<name>.py` 实现纯逻辑，返回结构化 dict。
2. `cli.py` 注册子命令。
3. `app/ui/qt/tools_panel.py` 与 `app/ui/tk/main_tk.py` 各加一个入口。
4. `tests/test_<name>.py` 补断言。

## 提交信息

- 使用祈使句，一行摘要 + 可选正文。
- 安全修复在正文标注影响范围与迁移方式。

## 行为准则

- 不提交真实密钥、密码、个人数据。
- 不引入来源不明或许可证不兼容的依赖。
