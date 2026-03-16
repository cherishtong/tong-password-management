# Agent API 使用指南

记多宝 Agent API 允许外部程序通过 CLI 调用访问密码，无需交互式输入主密码。适用于 CI/CD 流水线、自动化脚本等场景。

## 目录

- [快速开始](#快速开始)
- [密钥管理](#密钥管理)
- [密码操作](#密码操作)
- [使用场景](#使用场景)
- [故障排查](#故障排查)
- [安全注意事项](#安全注意事项)

---

## 快速开始

### 1. 初始化主密码（首次使用）

Agent API 依赖主密码进行数据加密，使用前需要先初始化：

```bash
# 进入 TUI 设置主密码
cargo run
# 或使用已有数据库
```

### 2. 生成 API 密钥

#### 基本用法

```bash
# 生成只读密钥，24小时后过期
cargo run -- agent key generate --name "CI-Deploy" --expires 24

# 生成有写权限的密钥
cargo run -- agent key generate --name "Automation" --expires 168 --permissions readwrite
```

#### 指定允许访问的账号（安全推荐）

```bash
# 限制密钥只能访问特定账号
cargo run -- agent key generate \
  --name "GitHub-Deploy" \
  --expires 24 \
  --account "github" \
  --account "dockerhub"

# 生成只能访问生产环境的密钥
cargo run -- agent key generate \
  --name "Prod-Deploy" \
  --expires 1 \
  --permissions read \
  --account "prod-server" \
  --account "prod-db"
```

**输出示例**：
```json
{
  "success": true,
  "message": "密钥生成成功（仅显示一次，请立即保存）",
  "key": "jdb_djQjXydWGMyznxp1iGooVX2nqFYVkpIc",
  "info": {
    "id": 1,
    "key_id": "jdb_djQjXydWGMyznxp1iGooVX2nqFYVkpIc",
    "name": "GitHub-Deploy",
    "created_at": "2026-03-16 21:11:02",
    "expires_at": "2026-03-17 21:11:02",
    "permissions": "read",
    "allowed_accounts": ["github", "dockerhub"]
  }
}
```

**输出示例**：
```json
{
  "success": true,
  "message": "密钥生成成功（仅显示一次，请立即保存）",
  "key": "jdb_7RZBTL9qrVeujbkMdtplxL3mDedVv9NR",
  "info": {
    "id": 1,
    "key_id": "jdb_7RZBTL9qrVeujbkMdtplxL3mDedVv9NR",
    "name": "CI-Deploy",
    "created_at": "2026-03-16 20:57:08",
    "expires_at": "2026-03-17 20:57:08",
    "permissions": "read"
  }
}
```

⚠️ **重要**：密钥只显示一次，请务必立即保存！

---

## 密钥管理

### 列出所有密钥

```bash
cargo run -- agent key list
```

### 撤销密钥（禁用）

```bash
cargo run -- agent key revoke --key-id jdb_7RZBTL9qrVeujbkMdtplxL3mDedVv9NR
```

### 删除密钥

```bash
cargo run -- agent key delete --key-id jdb_7RZBTL9qrVeujbkMdtplxL3mDedVv9NR
```

---

## 密码操作

### 获取密码

```bash
cargo run -- agent get --key "YOUR_API_KEY" --title "github"
```

**输出示例**：
```json
{
  "success": true,
  "data": {
    "id": 1,
    "title": "github",
    "account": "myuser",
    "password": "mypassword123",
    "category": "开发",
    "note": "",
    "created_at": "2026-03-16 20:00:00",
    "updated_at": "2026-03-16 20:00:00"
  }
}
```

### 搜索密码

```bash
cargo run -- agent search --key "YOUR_API_KEY" --keyword "google"
```

### 列出所有密码（仅摘要）

```bash
cargo run -- agent list --key "YOUR_API_KEY"
```

### 添加密码（需要 write 权限）

```bash
cargo run -- agent add \
  --key "YOUR_WRITE_KEY" \
  --title "new-service" \
  --account "user@example.com" \
  --password "secret123" \
  --category "工作" \
  --note "重要账号"
```

---

## 使用场景

### 场景1: CI/CD 流水线部署

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install jiduobao
        run: |
          # 下载并安装 jiduobao
          curl -L -o jiduobao.tar.gz https://github.com/yourusername/jiduobao/releases/latest/download/jiduobao-linux-x64.tar.gz
          tar xzf jiduobao.tar.gz
          sudo mv jiduobao /usr/local/bin/
      
      - name: Get server credentials
        id: creds
        env:
          JDB_KEY: ${{ secrets.JIDUOBao_API_KEY }}
        run: |
          # 获取密码
          CREDS=$(jiduobao agent get --key "$JDB_KEY" --title "prod-server")
          echo "user=$(echo $CREDS | jq -r .data.account)" >> $GITHUB_OUTPUT
          echo "pass=$(echo $CREDS | jq -r .data.password)" >> $GITHUB_OUTPUT
      
      - name: Deploy to server
        run: |
          sshpass -p "${{ steps.creds.outputs.pass }}" ssh ${{ steps.creds.outputs.user }}@server "deploy.sh"
```

### 场景2: Ansible Playbook

```yaml
# playbook.yml
- name: Deploy Application
  hosts: all
  vars:
    jdb_key: "{{ lookup('env', 'JIDUOBao_API_KEY') }}"
  
  tasks:
    - name: Get database password
      shell: jiduobao agent get --key "{{ jdb_key }}" --title "mysql-prod"
      register: db_creds
      delegate_to: localhost
      no_log: true
      changed_when: false
    
    - name: Set database facts
      set_fact:
        db_user: "{{ db_creds.stdout | from_json | json_query('data.account') }}"
        db_pass: "{{ db_creds.stdout | from_json | json_query('data.password') }}"
      no_log: true
    
    - name: Configure database connection
      template:
        src: config.j2
        dest: /app/config.yml
      vars:
        database_user: "{{ db_user }}"
        database_password: "{{ db_pass }}"
```

### 场景3: Shell 脚本自动化

```bash
#!/bin/bash
# deploy.sh - 自动化部署脚本

set -e

JDB_KEY="${JIDUOBao_API_KEY:-}"
if [ -z "$JDB_KEY" ]; then
    echo "Error: JIDUOBao_API_KEY not set"
    exit 1
fi

# 获取各种服务的密码
echo "正在获取凭证..."

# 数据库密码
DB_CREDS=$(jiduobao agent get --key "$JDB_KEY" --title "production-db")
DB_USER=$(echo "$DB_CREDS" | jq -r '.data.account')
DB_PASS=$(echo "$DB_CREDS" | jq -r '.data.password')

# API 密钥
API_KEY=$(jiduobao agent get --key "$JDB_KEY" --title "api-service" | jq -r '.data.password')

# SSH 密钥
SSH_KEY=$(jiduobao agent get --key "$JDB_KEY" --title "deploy-ssh" | jq -r '.data.password')

# 执行部署
echo "开始部署..."
# ... 使用获取的密码进行部署 ...
```

### 场景4: Docker 容器中使用

```dockerfile
FROM alpine:latest

# 安装 jiduobao
RUN wget -O /usr/local/bin/jiduobao https://github.com/yourusername/jiduobao/releases/latest/download/jiduobao-linux-x64 \
    && chmod +x /usr/local/bin/jiduobao

# 复制预配置的数据库（可选）
COPY pwd.db /root/.config/jiduobao/pwd.db

# 入口脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

```bash
# entrypoint.sh
#!/bin/sh

# 从环境变量获取 API Key，获取密码，执行命令
CREDS=$(jiduobao agent get --key "$JDB_API_KEY" --title "$JDB_TITLE")
export DB_PASSWORD=$(echo "$CREDS" | jq -r '.data.password')

exec "$@"
```

---

## 安全注意事项

### 1. 密钥存储

- **永远不要**将 API 密钥硬编码在代码中
- 使用环境变量或密钥管理服务（如 GitHub Secrets、HashiCorp Vault）
- 定期轮换密钥

### 2. 密钥权限

- 使用最小权限原则：只授予必要的权限
- 读操作使用 `read` 权限
- 只有需要自动添加密码时才使用 `readwrite`

### 3. 账号访问限制（重要）

**强烈建议**为密钥指定允许访问的账号，实现最小数据暴露原则：

```bash
# ✅ 推荐：限制只能访问特定账号
cargo run -- agent key generate \
  --name "CI-Deploy" \
  --account "prod-server" \
  --account "prod-db"

# ❌ 避免：生成可以访问所有账号的密钥
cargo run -- agent key generate --name "CI-Deploy"
```

**好处**：
- 即使密钥泄露，攻击者也只能访问有限的账号
- CI/CD 密钥只能访问部署相关的密码
- 符合最小权限原则

**行为**：
- `get` 命令只能获取指定账号的密码，访问其他账号会返回权限错误
- `search` 命令只返回允许访问的账号结果
- `list` 命令只显示允许访问的账号
- `add` 命令只能添加已授权的账号（如果指定了账号限制）

### 4. 过期时间

- 为密钥设置合理的过期时间
- CI/CD 密钥建议 1-7 天
- 长期使用的密钥建议 30 天并定期轮换

### 5. 审计

```bash
# 定期查看密钥使用情况
cargo run -- agent key list
```

关注 `last_used_at` 字段，发现异常立即撤销密钥。

### 6. TUI 密钥管理

在 TUI 界面中按 `k` 键可以进入密钥管理界面：

```
┌─────────────────────────────────────────────────────────┐
│  API 密钥管理                                            │
│  ID   名称           权限      状态   过期时间    最后使用 │
├─────────────────────────────────────────────────────────┤
│  ▶ 1  CI-Deploy     read      ✓ 正常  2026-03-17  2分钟前 │
│    2  Production    readwrite ✓ 正常  永不过期    从未    │
└─────────────────────────────────────────────────────────┘
```

**快捷键**：
- `n`: 生成新密钥（向导式，支持设置账号限制）
- `Enter`: 查看密钥详情
- `d`: 删除密钥
- `r`: 撤销密钥
- `q/Esc`: 退出

TUI 方式生成密钥更加直观，支持图形化选择允许访问的账号。

### 7. 网络隔离

- 在生产环境中，确保只有授权的服务器可以访问 jiduobao 数据库
- 考虑使用文件权限限制数据库访问：
  ```bash
  chmod 600 ~/.config/jiduobao/pwd.db
  ```

---

## 故障排查

### 错误："主密钥未初始化"

需要先设置主密码：
```bash
cargo run
# 按提示设置主密码
```

### 错误："密钥不存在" 或 "密钥验证失败"

- 检查密钥是否正确复制
- 确认密钥未被撤销或删除

### 错误："密钥已过期"

生成新密钥替换过期的：
```bash
cargo run -- agent key generate --name "new-key" --expires 24
```

### 错误："密钥没有写权限"

生成有写权限的密钥：
```bash
cargo run -- agent key generate --name "write-key" --permissions readwrite
```

### 错误："no such column: allowed_accounts"

这是由于旧版本数据库结构不兼容导致的。Agent API 需要新版数据库结构（包含 `allowed_accounts` 字段）。

**解决方案**：重置数据库（注意：这将删除所有数据！）
```bash
# Linux/Mac
rm ~/.config/jiduobao/pwd.db

# Windows
rmdir /s %APPDATA%\jiduobao\pwd.db
```

然后重新初始化：
```bash
cargo run
# 按提示设置主密码
```

**数据迁移建议**：
- 导出旧数据：`cargo run -- export --output backup.csv`
- 重置数据库
- 重新导入数据

---

## API 参考

### 命令概览

```
jiduobao agent
├── get      # 获取指定标题的密码
├── search   # 搜索密码
├── list     # 列出所有密码
├── add      # 添加密码
└── key      # 密钥管理
    ├── generate  # 生成新密钥
    ├── list      # 列出密钥
    ├── revoke    # 撤销密钥
    └── delete    # 删除密钥
```

### 返回格式

所有命令返回 JSON 格式：

**成功**：
```json
{
  "success": true,
  "data": { ... }
}
```

**失败**：
```json
{
  "success": false,
  "error": "错误信息"
}
```

---

## 贡献

如果你发现了 bug 或有功能建议，欢迎提交 Issue 或 PR。
