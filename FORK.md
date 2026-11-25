# Fork 说明（`wangtao94/pebrel`）

本仓库是 [`Kuddev/pebrel`](https://github.com/Kuddev/pebrel) 的轻量化跟踪 Fork，目标是在**不破坏上游架构规范、保持极小差异面**的前提下，为 Pebrel 提供**可选的 Bitwarden（含自托管 / Vaultwarden）凭据后端**，并通过 GitHub Actions 自动同步上游稳定版本并构建 Windows (x64) / Linux (x64) 安装包。

---

## 与上游 `Kuddev/pebrel` 的差异

| 维度 | 上游 `Kuddev/pebrel` | 本 Fork (`wangtao94/pebrel`) |
| --- | --- | --- |
| **凭据存储后端** | 仅支持系统原生钥匙串（Windows Credential Manager / macOS Keychain / Linux `secret-tool`） | 默认仍为系统钥匙串，**可选切换为 Bitwarden CLI（`bw` 或 `rbw`）**，原生支持官方云端与自托管 Bitwarden / Vaultwarden |
| **设置项与环境变量** | 无外部凭据后端配置 | 在 `pebrel_settings` 新增 `credential_backend`、`bitwarden_cli_path`、`bitwarden_folder`，并支持 `PEBREL_*` 环境变量覆盖 |
| **设置页 UI** | 原生设置页 | **刻意不修改高频变动的设置页 UI 与多语言 JSON**，保持合并上游几乎零冲突 |
| **CI 与发布** | 上游官方发布流水线 | 保留上游全部 workflow 不变，额外新增独立 [`.github/workflows/fork-sync-release.yml`](.github/workflows/fork-sync-release.yml)，自动跟踪上游稳定 Tag 并构建发布 **Windows x64** 与 **Linux x64** 安装包 |

> 完整架构设计与安全边界见 [architecture/notes/pebrel_app/platform/credentials/2026-11-25-bitwarden-cli-backend.md](architecture/notes/pebrel_app/platform/credentials/2026-11-25-bitwarden-cli-backend.md)。

---

## 启用 Bitwarden 凭据后端

### 1. 准备 CLI（二选一，支持自托管 / Vaultwarden）

- **官方 `bw` CLI（推荐 Windows / 全平台通用）**：
  ```bash
  # 自托管 / Vaultwarden 先指向你的服务器地址（官方云端跳过）
  bw config server https://vault.example.com
  bw login
  export BW_SESSION="$(bw unlock --raw)"   # Windows PowerShell: $env:BW_SESSION = bw unlock --raw
  ```
- **社区 Rust CLI `rbw`（推荐 Linux / macOS，带常驻 `rbw-agent`）**：
  ```bash
  rbw config set base_url https://vault.example.com
  rbw config set email you@example.com
  rbw login
  rbw unlock
  ```

### 2. 配置 Pebrel

方式 A — 在 Pebrel 运行时设置文件（`nebula_settings.txt`）中添加：
```ini
credential_backend=bitwarden-bw      # 可选：system | bitwarden-bw (或 bw) | bitwarden-rbw (或 rbw)
bitwarden_folder=Pebrel              # 默认 Pebrel，隔离命名空间；显式留空则不按目录过滤
bitwarden_cli_path=                  # 留空从 PATH 查找，也可填绝对路径
```

方式 B — 通过环境变量覆盖（优先级高于设置文件）：
```bash
export PEBREL_CREDENTIAL_BACKEND=rbw           # 或 bw / bitwarden-bw / bitwarden-rbw / system
export PEBREL_BITWARDEN_FOLDER=Pebrel
export PEBREL_BITWARDEN_CLI_PATH=/usr/local/bin/rbw
```

> 修改凭据后端配置后需**重启 Pebrel**生效；切换后端不会自动迁移旧钥匙串中的已有凭据。

---

## 安全与行为约定

- **密文不走命令行参数**：所有密码与 JSON 负载均通过 `stdin` 传递，内存中通过 `Zeroizing` / `SensitiveJson` 清理，且错误诊断不回显 CLI 原始 stderr。
- **精确匹配防误删**：`rbw` 通过 `--raw` JSON 列表按精确名称 + 目录解析 36 位 UUID 后再执行 `get`/`edit`/`remove`，避免 `rbw` 模糊子串匹配误删其他条目；遇到重复条目显式报错。
- **超时与进程组清理**：每次 CLI 调用限时 15 秒，超时通过进程组（Windows Job Object / Unix setsid）强杀并回收。
- **已知边界**：GPUI SSH 编辑器保存凭据沿用上游既有同步保存路径（与 Linux `secret-tool` 一致），若 CLI 未解锁或网络较慢会短暂等待；渲染路径 `can_store()` 使用启动预热快照，零磁盘/零子进程 I/O。

---

## 分支与同步策略

- `feat/bitwarden-credential-backend`：纯净的上游候选功能分支，不含 Fork 说明文档与 Fork CI，随时可用于向上游 `Kuddev/pebrel` 提交 PR。
- `fork-main`：本 Fork 的日常维护与发布分支，在功能分支之上仅叠加 `FORK.md`、README 顶部说明与 `.github/workflows/fork-sync-release.yml`。
- `.github/workflows/fork-sync-release.yml` 每日定时检查 `Kuddev/pebrel` 最新稳定 Release Tag，无冲突时自动合并并构建发布 Windows x64 + Linux x64 安装包；若遇到合并冲突会自动在本仓库创建 Issue 提醒人工处理。
