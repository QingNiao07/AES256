# 自动化脚本清单（SCRIPTS）

本工具箱自带 13+ 项自动化脚本，覆盖构建 / 打包 / 文档 / 校验 / 运维全流程。
全部为纯标准库 + 项目依赖，离线可用。

## scripts/ 目录

| # | 脚本 | 作用 | 常用命令 |
|---|------|------|----------|
| 1 | `doctor.py` | 环境自检：Python 版本、依赖、Argon2、配置、安全参数 | `python scripts/doctor.py` |
| 2 | `benchmark.py` | KDF 性能基准 + 按本机性能推荐参数 | `python scripts/benchmark.py --save` |
| 3 | `run_tests.py` | 一键跑测试 + 语法编译检查 | `python scripts/run_tests.py` |
| 4 | `verify_all.py` | 批量校验密文完整性（GCM tag + 尾部 HMAC） | `python scripts/verify_all.py <dir>` |
| 5 | `rotate_password.py` | 批量更换密码（重加密，支持 dry-run/断点续跑） | `python scripts/rotate_password.py <dir> --dry-run` |
| 6 | `audit_verify.py` | 审计日志哈希链校验，定位篡改行 | `python scripts/audit_verify.py` |
| 7 | `make_recovery.py` | 生成密钥恢复码（11 组 × 5 字符） | `python scripts/make_recovery.py` |
| 8 | `share_page.py` | 生成自解密分享页 HTML | `python scripts/share_page.py in.zip out.html` |
| 9 | `gen_docs.py` | 从 docstring 生成 API 参考 | `python scripts/gen_docs.py` |
| 10 | `build_exe.py` | PyInstaller 打包 GUI / CLI | `python scripts/build_exe.py` |
| 11 | `release.py` | 生成 SHA256SUMS + 本地打标签 | `python scripts/release.py --tag v1.1.0` |

## 根目录构建脚本

| # | 脚本 | 作用 |
|---|------|------|
| 12 | `build.bat` / `build.sh` | 一键构建（编译 + 打包） |
| 13 | `build_manual.py` | 生成使用手册 |
| 14 | `build_release.py` | 打包发布产物 |
| 15 | `build_all_versions.ps1` | 多版本批量构建 |
| 16 | `init_project.py` | 一键生成工程骨架（新贡献者 5 分钟上手） |

## CI

- `.github/workflows/build.yml`：推送时自动编译 + 跑测试 + 生成产物。

## 典型工作流

```bash
# 1. 上手前先自检
python scripts/doctor.py

# 2. 按本机性能调优安全参数
python scripts/benchmark.py --save

# 3. 开发后跑全量测试
python scripts/run_tests.py

# 4. 校验历史密文是否完好
python scripts/verify_all.py ./vault

# 5. 打包并生成校验清单
python scripts/build_exe.py && python scripts/release.py --tag v1.1.0
```
