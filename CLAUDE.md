# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**jkey** — Python library for password management and TOTP verification。管理 TOTP 密钥和网站密码，生成随机密码，导出明文数据。数据使用 AES-256-CBC + HMAC 加密存储在 `~/.config/jkey/`，每种类型独立文件。

## Commands

### 2FA 验证码
- `uv run jkey 2fa ls [keyword]` — 列出所有账号及当前 TOTP 验证码（可选关键词过滤）
- `uv run jkey 2fa get <account>` — 显示指定账号的 TOTP 验证码
- `uv run jkey 2fa add <name> <secret> [--recovery <file>]` — 手动添加 TOTP 账号
- `uv run jkey 2fa qr <image_path> [--recovery <file>]` — 从 QR 码图片导入账号
- `uv run jkey 2fa rm <account>` — 删除账号

### 密码管理
- `uv run jkey pm gen [-L N] [--no-upper] [--no-lower] [--no-digits] [--no-symbols]` — 生成随机密码
- `uv run jkey pm ls [keyword]` — 列出/过滤存储的密码
- `uv run jkey pm get <name>` — 查看指定密码
- `uv run jkey pm add <name>` — 存储密码（交互式输入）
- `uv run jkey pm rm <name>` — 删除密码
- `uv run jkey pm import <csv_path>` — 从 CSV 文件导入密码（格式：name,password）

### 加密仓库
- `uv run jkey pv init` — 初始化加密仓库（设置主密码）
- `uv run jkey pv unlock` — 解锁仓库
- `uv run jkey pv lock` — 锁定
- `uv run jkey pv set-pw` — 修改主密码
- `uv run jkey pv encrypt <file> [-o output.jkey]` — 加密任意文件
- `uv run jkey pv decrypt <file.jkey> [-o output]` — 解密 .jkey 文件
- `uv run jkey pv export totp [-o file.json]` — 导出 TOTP 密钥 (JSON，需重新验证主密码)
- `uv run jkey pv export passwords [-o file.csv]` — 导出密码 (CSV)
- `uv run jkey pv export recovery [-o file.txt]` — 导出恢复码 (TXT)
- `uv run jkey pv export qr -o <dir>` — 导出二维码图片
- `uv run jkey pv export all -o <dir>` — 全部导出

### 环境变量
- `JKEY_PASS` — 设置主密码环境变量，避免交互式输入

## Project Structure

```
src/
└── jkey/
    ├── __init__.py            # 包标记
    ├── __main__.py            # python -m jkey 入口
    ├── __about__.py           # 版本号
    ├── cli.py                 # argparse CLI 入口
    ├── aes.py                 # AES-256-CBC + HMAC 纯 Python
    ├── vault.py               # 加密存储核心 + 命令
    ├── totp.py                # TOTP 算法 + 账号管理
    ├── qr.py                  # QR 码扫描
    ├── passwords.py           # 密码存储
    ├── generator.py           # 密码生成
    └── export.py              # 数据导出
tests/
├── test_aes.py               # AES 加密解密测试
├── test_totp.py               # TOTP / HOTP RFC 4226 测试
└── test_generator.py          # 密码生成测试
.github/
└── workflows/
    ├── ci.yml                 # CI: ruff lint + pytest
    └── publish.yml            # PyPI 发布（tag 触发）
```

## 架构说明

- **加密存储**：`jkey/vault.py` — AES-256-CBC + HMAC-SHA256。version 3 格式使用独立加密和认证密钥。文件存储在 `~/.config/jkey/`，分为 `totp.jkey`、`passwords.jkey`、`recovery.jkey`，各自独立加密。
- **QR 图片**：扫码时自动加密保存到 `~/.config/jkey/qr/<name>.jkey`。
- **session 机制**：主密码输入后在进程内缓存。`export` 命令需重新验证密码。
- **备份迁移**：备份 `~/.config/jkey/` 目录，换电脑复制回去即可使用。
- **密码生成**：使用 Python `secrets` 模块（CSPRNG），支持自定义长度和字符集。
- **第三方依赖**：仅 `opencv-python-headless`（QR 码识别）。
- **依赖管理**：`uv` + `pyproject.toml`，`tuna` PyPI 镜像为默认索引。Python 3.14+。
- **测试**：`pytest` + `ruff` lint，CI 自动运行。

## Data files

```
~/.config/jkey/
├── totp.jkey         # 加密的 TOTP 密钥
├── passwords.jkey    # 加密的密码
├── recovery.jkey     # 加密的恢复码
└── qr/
    └── <account>.jkey # 加密的二维码图片
```

- `.gitignore` 排除 `.venv`、`.python-version`、`uv.lock`、`*.tmp`、`dist/`。
