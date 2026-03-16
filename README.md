# 记多宝 (Jiduobao) v2.0

一款基于 Rust 开发的**酷炫 TUI 密码管理工具**，采用现代终端界面设计，在本地安全存储和管理账号密码。

```
    _ _ ____              ____
   (_|_)  _ \_   _  ___ | __ )  __ _  ___
   | | | | | | | | |/ _ \|  _ \ / _` |/ _ \
   | | | |_| | |_| | (_) | |_) | (_| | (_) |
  _/ |_|____/ \__,_|\___/|____/ \__,_|\___/
 |__/

        记多宝 - 安全密码管理器
```

## ✨ 功能特点

### 🎨 酷炫 TUI 界面
- **Jiduobao 艺术字 Logo**：顶部显示品牌 ASCII 艺术字
- **表格浏览**：支持上下键浏览、高亮选中、实时搜索过滤
- **色彩丰富**：使用主题色彩区分不同功能区域
- **实时状态栏**：显示操作提示和反馈消息

### 🔐 安全特性
- **AES-256-GCM**：认证加密算法，防止篡改
- **Argon2id**：现代密码哈希算法，抗 GPU/ASIC 破解
- **随机盐值**：每个用户独立的加密盐值
- **本地存储**：数据永不上传，仅保存在本地设备
- **Agent API**：支持程序化访问，可限制访问范围，适用于 CI/CD 场景

### 🚀 交互功能

| 快捷键 | 功能 |
|--------|------|
| `↑/↓` | 上下选择密码条目 |
| `Enter` | 复制选中密码到剪贴板 |
| `u` | 切换账号显示模式（明文/遮盖） |
| `a` | 添加新密码 |
| `d` | 删除选中密码 |
| `e` | 编辑选中密码 |
| `/` 或 `s` | 搜索密码 |
| `g` | 生成随机密码 |
| `k` | API 密钥管理 |
| `x` | 导出密码到 CSV |
| `q` | 退出程序 |

## 📦 安装

### 从 Release 下载（推荐）

访问 [GitHub Releases](https://github.com/yourusername/jiduobao/releases) 页面，下载对应平台的可执行文件：

| 平台 | 文件 | 说明 |
|------|------|------|
| Windows | `jiduobao-windows-x64.exe` | 直接运行 |
| Linux | `jiduobao-linux-x64` | 需要 `chmod +x` |
| macOS (Intel) | `jiduobao-macos-x64` | 需要 `chmod +x` |
| macOS (Apple Silicon) | `jiduobao-macos-arm64` | 需要 `chmod +x` |

### 从源码构建

```bash
# 克隆仓库
git clone <repository-url>
cd jiduobao

# 构建发布版本
cargo build --release

# 可执行文件位置
./target/release/jiduobao
```

### Windows

```powershell
# 直接运行
.\target\release\jiduobao.exe

# 添加到 PATH 后可以使用
jiduobao
```

## 🎮 使用方法

### 交互式 TUI 模式（推荐）

直接运行程序即可进入酷炫的 TUI 界面：

```bash
./jiduobao
```

界面预览：
```
┌─────────────────────────────────────────────────────────────┐
│  Jiduobao Logo                │ 版本: 2.0.0                 │
│                               │ 作者: 赵无为                │
│                               │ 邮箱: cherishtong@...       │
├─────────────────────────────────────────────────────────────┤
│ 序号 │ 标题      │ 账号        │ 分类   │ 备注     │ 创建时间           │ 更新时间           │
├──────┼───────────┼─────────────┼────────┼──────────────────┤
│▶ 1   │ GitHub    │ ****        │ 开发   │ 个人账号 │ 2024-01-15 09:00:00│ 2024-01-15 10:23:00│
│  2   │ 阿里云    │ ****        │ 服务器 │ 生产环境 │ 2024-01-14 08:30:00│ 2024-01-14 09:15:00│
├─────────────────────────────────────────────────────────────┤
│ ✅ 已复制 'GitHub' 的密码到剪贴板                           │
│ ↑↓:选择  Enter:复制  u:显示账号  a:添加  d:删除  e:编辑  /:搜索  q:退出 │
└─────────────────────────────────────────────────────────────┘
```

### 命令行模式

```bash
# 添加密码（交互式）
./jiduobao add

# 快速添加
./jiduobao add --title "GitHub" --account "user" --password "pass"

# 列出所有密码
./jiduobao list

# 搜索密码
./jiduobao search --keyword "github"

# 生成随机密码
./jiduobao generate --length 20

# 导出密码
./jiduobao export --output backup.csv
```

### Agent API（程序化访问）

支持外部程序通过 CLI 调用访问密码，适用于 CI/CD 流水线：

```bash
# 生成 API 密钥（限制只能访问特定账号）
./jiduobao agent key generate --name "CI-Deploy" --expires 24 --account "prod-server"

# 获取密码（返回 JSON）
./jiduobao agent get --key "jdb_xxx" --title "prod-server"
# 输出: {"success":true,"data":{"title":"prod-server","account":"root","password":"secret123"}}

# 搜索密码
./jiduobao agent search --key "jdb_xxx" --keyword "github"

# 列出所有密码
./jiduobao agent list --key "jdb_xxx"
```

**详细文档**: 参见 [AGENT_API.md](./AGENT_API.md)

## 🏗️ 项目结构

```
.
├── Cargo.toml
├── README.md
├── AGENT_API.md        # Agent API 使用文档
├── AGENTS.md           # 开发指南
└── src/
    ├── main.rs         # 程序入口
    ├── lib.rs          # 核心业务逻辑
    ├── agent.rs        # Agent CLI 命令处理
    ├── api_key.rs      # API 密钥管理
    └── ui/             # TUI 界面模块
        ├── mod.rs
        ├── app.rs      # 主应用界面
        ├── api_key_manager.rs  # API 密钥管理界面
        └── taiji.rs    # 标题和作者信息组件
```

## 🔧 技术栈

| 组件 | 用途 | 版本 |
|------|------|------|
| ratatui | TUI 框架 | 0.25 |
| crossterm | 终端控制 | 0.27 |
| dialoguer | 交互式对话框 | 0.11 |
| rusqlite | SQLite 数据库 | 0.30 |
| aes-gcm | AES-256-GCM 加密 | 0.10 |
| argon2 | 密码哈希 | 0.5 |

## 📂 数据存储

- **配置目录**: `{系统配置目录}/jiduobao/`
  - Windows: `%APPDATA%/jiduobao/`
  - macOS: `~/Library/Application Support/jiduobao/`
  - Linux: `~/.config/jiduobao/`
- **数据库文件**: `{配置目录}/pwd.db`

## 🔒 安全说明

1. **加密算法**：使用 AES-256-GCM 进行对称加密
2. **密钥派生**：使用 Argon2id 从主密码派生加密密钥
3. **密码哈希**：主密码使用 Argon2id 哈希存储
4. **随机盐值**：16字节随机盐值，防止彩虹表攻击
5. **注意事项**：
   - 主密码是数据安全的唯一屏障，请妥善保管
   - 忘记主密码将无法恢复已存储的密码
   - 数据库文件包含加密后的数据，建议定期备份

## ⚠️ 兼容性说明

**v2.0 与 v1.0 不兼容**：新版本使用了完全不同的加密方案，无法读取旧版本的数据库。

如需迁移旧数据：
1. 导出旧版本数据（如果可能）
2. 删除 `%APPDATA%/tong_password/` 目录
3. 首次运行新版本重新设置主密码
4. 重新添加密码条目

## 📝 更新日志

### v2.0.1 (2024-03-16)
- 🤖 **Agent API**：支持外部程序程序化访问密码
  - 生成 API 密钥，可设置过期时间和权限
  - 支持限制密钥只能访问特定账号（最小权限原则）
  - 提供 `get`/`search`/`list`/`add` 命令
  - 所有操作返回 JSON 格式，便于脚本解析
- 🎨 **TUI 密钥管理界面**：按 `k` 键进入，支持向导式生成密钥
- 🔐 **安全性增强**：密钥哈希存储、时序安全比较、自动过期检查
- 📚 **完整文档**：添加 AGENT_API.md 详细使用指南

### v2.0.0 (2024)
- 🎨 全新 TUI 界面，ASCII 艺术字 Logo
- 🔐 升级加密方案：AES-256-GCM + Argon2id
- ⌨️ 丰富的键盘快捷键支持
- 📋 剪贴板复制功能
- 🔍 实时搜索过滤
- 📤 CSV 导出功能
- 🎲 密码生成器
- 👤 作者信息展示

## 📜 许可证

MIT License

## 🚀 自动发布

本项目使用 GitHub Actions 自动编译和发布：

### 触发方式

1. **自动触发**: 推送 `v*` 标签时自动触发
   ```bash
   git tag v2.0.1
   git push origin v2.0.1
   ```

2. **手动触发**: 在 Actions 页面选择 "Release" 工作流，输入版本号运行

### 支持平台

- ✅ Windows (x64)
- ✅ Linux (x64)
- ✅ macOS (x64, ARM64)

### 工作流文件

- `.github/workflows/build.yml` - 主要构建和发布工作流
- `.github/workflows/ci.yml` - 日常 CI 测试

## 📧 联系

- **作者**: 赵无为
- **邮箱**: cherishtong@aliyun.com
- **QQ**: 1427730623
