# 记多宝 (Jidobao) - 开发指南

## 项目概述

记多宝是一款基于 Rust 开发的命令行密码管理工具，采用现代 TUI（Terminal User Interface）界面设计，用于在本地安全地存储和管理账号密码信息。

**当前版本**: 2.0.0  
**主要作者**: 赵无为 (cherishtong@aliyun.com)

## 技术架构

### 技术栈

| 组件 | 用途 | 版本 |
|------|------|------|
| Rust | 编程语言 | 2021 edition |
| rusqlite | SQLite 数据库 | 0.30 |
| aes-gcm | AES-256-GCM 加密 | 0.10 |
| argon2 | 密码哈希/密钥派生 | 0.5 |
| ratatui | TUI 框架 | 0.25 |
| crossterm | 终端控制 | 0.27 |
| dialoguer | 交互式对话框 | 0.11 |
| clap | 命令行参数解析 | 4.4 |

### 项目结构

```
.
├── Cargo.toml              # Rust 项目配置
├── README.md               # 项目说明文档
├── AGENTS.md               # 本开发指南
├── LICENSE                 # MIT 许可证
├── resource.res            # Windows 资源文件
├── src/
│   ├── main.rs             # 程序入口（25行）
│   ├── lib.rs              # 核心业务逻辑（900+行）
│   └── ui/                 # TUI 界面模块
│       ├── mod.rs          # 模块入口和导出
│       ├── app.rs          # 应用状态、主循环、事件处理
│       └── taiji.rs        # 标题和作者信息组件
```

## 代码组织

### 模块划分

#### 1. `src/main.rs` - 程序入口
- 解析命令行参数
- 决定进入 TUI 模式或命令行模式
- 错误处理

#### 2. `src/lib.rs` - 核心业务逻辑
包含以下功能模块：

**数据库管理**
- `init_db()`: 初始化数据库连接
- `get_conn()`: 获取数据库连接
- `is_first_run()`: 检查是否首次运行

**加密/解密**
- `derive_key()`: 使用 Argon2 派生密钥
- `encrypt_str()`: AES-256-GCM 加密
- `decrypt_str()`: AES-256-GCM 解密

**密码管理功能**
- `setup_master_password()`: 设置主密码
- `verify_master_password()`: 验证主密码
- `query_all_passwords()`: 查询所有密码
- `search_passwords()`: 搜索密码
- `add_password_dialog()`: 添加密码（Dialoguer）
- `delete_password()`: 删除密码
- `edit_password_dialog()`: 编辑密码
- `generate_random_password()`: 生成随机密码
- `export_passwords_dialog()`: 导出密码到 CSV

**TUI 主循环**
- `run_tui()`: 运行 TUI 主循环
- `handle_post_tui_action()`: 处理 TUI 退出后的操作

**命令行参数**
- `handle_command()`: 处理 CLI 命令

#### 3. `src/ui/app.rs` - TUI 应用状态
**核心结构体**
```rust
pub struct App {
    pub passwords: Vec<PassWord>,       // 密码列表
    pub table_state: TableState,        // 表格状态
    pub mode: AppMode,                  // 当前模式
    pub search_query: String,           // 搜索关键词
    pub running: bool,                  // 是否运行中
    pub status_message: Option<(String, Instant)>, // 状态消息
    pub next_action: NextAction,        // 退出后要执行的操作
    pub show_plaintext: bool,           // 是否显示明文账号
}
```

**关键方法**
- `run()`: 运行应用主循环
- `draw()`: 绘制界面
- `draw_header()`: 绘制标题栏（Logo + 作者信息）
- `draw_main_content()`: 绘制密码表格
- `draw_footer()`: 绘制状态栏
- `handle_key()`: 处理键盘输入

#### 4. `src/ui/taiji.rs` - 标题组件
**BigTitle**: ASCII 艺术字 Logo  
**AuthorInfo**: 作者信息展示（版本、作者、邮箱、QQ）

### 核心数据结构

```rust
#[derive(Debug, Clone)]
pub struct PassWord {
    pub id: i64,
    pub title: String,      // 标题
    pub account: String,    // 账号（加密存储）
    pub password: String,   // 密码（加密存储）
    pub acct_type: String,  // 分类
    pub bz: String,         // 备注
    pub cre_time: String,   // 创建时间
    pub ud_time: String,    // 更新时间
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    Normal,                             // 正常浏览模式
    Searching,                          // 搜索模式
    Confirming(&'static str, ConfirmAction), // 确认对话框
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfirmAction {
    Delete(i64),    // 删除密码
    Export,         // 导出
    Quit,           // 退出
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NextAction {
    None,
    AddPassword,        // 添加密码
    EditPassword(i64),  // 编辑密码
    GeneratePassword,   // 生成密码
}
```

## 数据库 Schema

**root_user 表** - 存储管理员密码：
```sql
CREATE TABLE root_user (
    name TEXT PRIMARY KEY NOT NULL UNIQUE,
    password TEXT NOT NULL,     -- Argon2 哈希
    salt TEXT NOT NULL          -- 随机盐值
);
```

**password 表** - 存储密码条目：
```sql
CREATE TABLE password (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
    title TEXT NOT NULL,        -- 标题
    account TEXT NOT NULL,      -- 账号（AES-256-GCM 加密）
    password TEXT NOT NULL,     -- 密码（AES-256-GCM 加密）
    acct_type TEXT,             -- 分类
    bz TEXT,                    -- 备注
    cre_time TEXT NOT NULL,     -- 创建时间
    ud_time TEXT NOT NULL       -- 更新时间
);
```

## 安全机制

### 加密流程
1. 用户输入主密码
2. 使用 Argon2id 验证密码哈希
3. 派生 32 字节密钥用于 AES-256-GCM
4. 账号和密码使用 AES-256-GCM 加密存储
5. 加密数据包含 12 字节随机 nonce

### 密钥管理
- 主密码哈希使用随机 16 字节盐值
- 加密密钥在内存中，程序退出后清除
- 使用 `once_cell` 全局存储密钥（简化实现）

## 界面布局

```
┌─────────────────────────────────────────────────────────┐
│  JiDuoBao ASCII Logo        │ 版本: 2.0.0               │
│  (taiji.rs)                 │ 作者: 赵无为              │
│                             │ 邮箱: cherishtong@...     │
├─────────────────────────────┴───────────────────────────┤
│ 密码列表 (app.rs)                                         │
│ 序号 │ 标题      │ 账号    │ 分类   │ 备注     │ 创建时间            │ 更新时间            │
├─────────────────────────────────────────────────────────┤
│ 状态栏: 快捷键提示                                      │
└─────────────────────────────────────────────────────────┘
```

## 快捷键映射

| 按键 | 功能 | 实现位置 |
|------|------|----------|
| ↑/↓ | 选择条目 | `handle_normal_key()` |
| Enter | 复制密码 | `handle_normal_key()` |
| u | 切换账号显示模式 | `handle_normal_key()` |
| a | 添加密码 | `handle_normal_key()` → `NextAction::AddPassword` |
| d | 删除密码 | `handle_normal_key()` → 确认对话框 |
| e | 编辑密码 | `handle_normal_key()` → `NextAction::EditPassword` |
| / | 搜索 | `handle_normal_key()` → `AppMode::Searching` |
| g | 生成密码 | `handle_normal_key()` → `NextAction::GeneratePassword` |
| x | 导出 | `handle_normal_key()` → 确认对话框 |
| q | 退出 | `handle_normal_key()` → 确认对话框 |

## 构建命令

```bash
# 开发构建
cargo build

# 发布构建
cargo build --release

# Windows 图标打包
cargo rustc --release --bin jiduobao -- -C link-arg=resource.res

# 运行
cargo run
```

## 代码风格

### 命名规范
- 函数名：snake_case
- 结构体/枚举：PascalCase
- 常量：SCREAMING_SNAKE_CASE
- 文件名：snake_case

### 错误处理
- 使用 `anyhow` 进行错误传播
- 使用 `Result<T>` 作为返回类型
- 关键错误显示中文提示

### 注释风格
- 使用中文注释
- 函数上方添加功能说明
- 复杂逻辑添加行内注释

## 开发注意事项

1. **TUI 尺寸限制**
   - `BigTitle` 要求高度 >= 9
   - 表格列宽使用 `Constraint` 配置
   - 考虑终端最小尺寸（建议 80x24）

2. **中文字符处理**
   - 使用 `chars()` 而非字节索引截断字符串
   - `truncate_chars()` 辅助函数处理中文截断

3. **加密安全**
   - 不要硬编码密钥
   - 敏感数据及时清零（当前实现简化）

4. **数据库操作**
   - 使用 `Arc<Mutex<Connection>>` 共享连接
   - 每次操作前获取锁
   - 启用 WAL 模式提高性能

## CI/CD 配置

### GitHub Actions 工作流

#### 1. `build.yml` - 构建和发布
- **触发条件**: 推送标签 `v*` 或手动触发
- **功能**:
  - 多平台交叉编译 (Windows, Linux, macOS x64/ARM64)
  - 自动创建 GitHub Release
  - 上传编译产物

#### 2. `ci.yml` - 持续集成
- **触发条件**: 推送代码到 main/master 分支或 Pull Request
- **功能**:
  - 代码格式化检查 (`cargo fmt`)
  - Clippy 静态分析 (`cargo clippy`)
  - 多平台构建测试

#### 3. `release.yml` - 传统发布流程
- 备用发布工作流
- 支持手动输入版本号

### 发布流程

```bash
# 1. 更新版本号 (Cargo.toml)
vim Cargo.toml

# 2. 提交更改
git add .
git commit -m "Bump version to v2.0.1"
git push

# 3. 创建标签并推送
git tag v2.0.1
git push origin v2.0.1

# 4. GitHub Actions 自动触发，编译并发布
```

### 工作流文件结构

```
.github/
└── workflows/
    ├── build.yml    # 主要构建发布工作流
    ├── ci.yml       # 日常 CI 测试
    └── release.yml  # 备用发布工作流
```

## 测试策略

当前项目**没有自动化单元测试**，测试通过以下方式验证：

1. **CI 构建测试**: GitHub Actions 在 PR 时自动构建
2. **手动测试**: 
   - 首次运行测试：删除配置目录后运行，验证初始化流程
   - 密码管理测试：增删改查各项功能
   - 加密验证：检查数据库中的敏感字段是否已加密
   - TUI 交互测试：键盘快捷键、搜索、导出功能

## 联系信息

- **作者**: 赵无为
- **邮箱**: cherishtong@aliyun.com
- **QQ**: 1427730623
