//! Agent CLI 命令处理模块
//!
//! 提供 Agent（外部程序）通过 CLI 访问密码的功能。
//! 所有输出为 JSON 格式，便于程序解析。

use std::collections::HashMap;

use anyhow::Result;
use chrono::Local;
use rusqlite::params;
use serde::Serialize;
use serde_json::json;

use crate::{api_key::ApiKeyManager, decrypt_str, encrypt_str, get_conn};

/// Agent 命令类型
#[derive(Debug, Clone)]
pub enum AgentCommand {
    /// 获取指定标题的密码
    Get { api_key: String, title: String },
    /// 搜索密码
    Search { api_key: String, keyword: String },
    /// 列出所有密码（仅标题）
    List { api_key: String },
    /// 添加新密码（需要写权限）
    Add {
        api_key: String,
        title: String,
        account: String,
        password: String,
        category: Option<String>,
        note: Option<String>,
    },
}

/// API 响应结构
#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(msg: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg),
        }
    }
}

/// 密码条目响应
#[derive(Debug, Serialize)]
struct PasswordEntry {
    id: i64,
    title: String,
    account: String,
    password: String,
    category: String,
    note: String,
    created_at: String,
    updated_at: String,
}

/// 数据库查询结果行类型
type PasswordRow = (i64, String, String, String, String, String, String, String);

/// 简化的密码信息（用于列表）
#[derive(Debug, Serialize)]
struct PasswordSummary {
    id: i64,
    title: String,
    category: String,
    updated_at: String,
}

/// 处理 Agent 命令
///
/// # 返回
/// - `Ok(true)`: 命令已处理
/// - `Ok(false)`: 未匹配到命令
/// - `Err`: 处理出错
pub fn handle_agent_command(cmd: &AgentCommand) -> Result<bool> {
    match cmd {
        AgentCommand::Get { api_key, title } => {
            handle_get(api_key, title)?;
            Ok(true)
        }
        AgentCommand::Search { api_key, keyword } => {
            handle_search(api_key, keyword)?;
            Ok(true)
        }
        AgentCommand::List { api_key } => {
            handle_list(api_key)?;
            Ok(true)
        }
        AgentCommand::Add {
            api_key,
            title,
            account,
            password,
            category,
            note,
        } => {
            handle_add(
                api_key,
                title,
                account,
                password,
                category.as_deref(),
                note.as_deref(),
            )?;
            Ok(true)
        }
    }
}

/// 获取指定标题的密码
fn handle_get(api_key: &str, title: &str) -> Result<()> {
    // 验证 API Key
    let verification = match ApiKeyManager::verify(api_key) {
        Ok(v) => v,
        Err(e) => {
            print_error(&e.to_string());
            return Ok(());
        }
    };

    // 检查是否有权限访问该账号
    if !ApiKeyManager::can_access_account(&verification, title) {
        print_error("密钥没有权限访问该账号");
        return Ok(());
    }

    // 查询数据库
    let conn = match get_conn() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("数据库错误: {}", e));
            return Ok(());
        }
    };

    let conn = match conn.lock() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("锁错误: {}", e));
            return Ok(());
        }
    };

    let result: Result<PasswordRow, _> = conn
        .query_row(
            "SELECT id, title, account, password, acct_type, bz, cre_time, ud_time 
         FROM password WHERE title = ?1",
            params![title],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        );

    match result {
        Ok((id, title, enc_account, enc_password, acct_type, bz, cre_time, ud_time)) => {
            // 解密
            let account = decrypt_str(&enc_account).unwrap_or_default();
            let password = decrypt_str(&enc_password).unwrap_or_default();

            let entry = PasswordEntry {
                id,
                title: title.trim().to_string(),
                account,
                password,
                category: acct_type.trim().to_string(),
                note: bz.trim().to_string(),
                created_at: cre_time,
                updated_at: ud_time,
            };

            print_success(entry);
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            print_error(&format!("未找到标题为 '{}' 的密码", title));
        }
        Err(e) => {
            print_error(&format!("查询错误: {}", e));
        }
    }

    Ok(())
}

/// 搜索密码
fn handle_search(api_key: &str, keyword: &str) -> Result<()> {
    // 验证 API Key
    let verification = match ApiKeyManager::verify(api_key) {
        Ok(v) => v,
        Err(e) => {
            print_error(&e.to_string());
            return Ok(());
        }
    };

    let conn = match get_conn() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("数据库错误: {}", e));
            return Ok(());
        }
    };

    let conn = match conn.lock() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("锁错误: {}", e));
            return Ok(());
        }
    };

    let pattern = format!("%{}%", keyword);
    let mut stmt = match conn.prepare(
        "SELECT id, title, account, password, acct_type, bz, cre_time, ud_time 
         FROM password 
         WHERE title LIKE ?1 OR account LIKE ?1 OR acct_type LIKE ?1 OR bz LIKE ?1
         ORDER BY id",
    ) {
        Ok(s) => s,
        Err(e) => {
            print_error(&format!("查询准备错误: {}", e));
            return Ok(());
        }
    };

    let rows = stmt.query_map([&pattern], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ))
    });

    match rows {
        Ok(rows) => {
            let mut entries = Vec::new();
            for row in rows {
                match row {
                    Ok((
                        id,
                        title,
                        enc_account,
                        enc_password,
                        acct_type,
                        bz,
                        cre_time,
                        ud_time,
                    )) => {
                        // 检查是否有权限访问该账号
                        if !ApiKeyManager::can_access_account(&verification, &title) {
                            continue;
                        }

                        let account = decrypt_str(&enc_account).unwrap_or_default();
                        let password = decrypt_str(&enc_password).unwrap_or_default();

                        entries.push(PasswordEntry {
                            id,
                            title: title.trim().to_string(),
                            account,
                            password,
                            category: acct_type.trim().to_string(),
                            note: bz.trim().to_string(),
                            created_at: cre_time,
                            updated_at: ud_time,
                        });
                    }
                    Err(e) => {
                        eprintln!("{{\"warning\": \"解析错误: {}\"}}", e);
                    }
                }
            }

            if entries.is_empty() {
                print_success::<Vec<PasswordEntry>>(vec![]);
            } else {
                print_success(entries);
            }
        }
        Err(e) => {
            print_error(&format!("查询错误: {}", e));
        }
    }

    Ok(())
}

/// 列出所有密码（仅返回摘要信息）
fn handle_list(api_key: &str) -> Result<()> {
    // 验证 API Key
    let verification = match ApiKeyManager::verify(api_key) {
        Ok(v) => v,
        Err(e) => {
            print_error(&e.to_string());
            return Ok(());
        }
    };

    let conn = match get_conn() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("数据库错误: {}", e));
            return Ok(());
        }
    };

    let conn = match conn.lock() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("锁错误: {}", e));
            return Ok(());
        }
    };

    let mut stmt =
        match conn.prepare("SELECT id, title, acct_type, ud_time FROM password ORDER BY id") {
            Ok(s) => s,
            Err(e) => {
                print_error(&format!("查询准备错误: {}", e));
                return Ok(());
            }
        };

    let rows = stmt.query_map([], |row| {
        Ok(PasswordSummary {
            id: row.get(0)?,
            title: row.get::<_, String>(1)?.trim().to_string(),
            category: row.get::<_, String>(2)?.trim().to_string(),
            updated_at: row.get(3)?,
        })
    });

    match rows {
        Ok(rows) => {
            let summaries: Vec<_> = rows
                .filter_map(|r| r.ok())
                .filter(|s| ApiKeyManager::can_access_account(&verification, &s.title))
                .collect();
            print_success(summaries);
        }
        Err(e) => {
            print_error(&format!("查询错误: {}", e));
        }
    }

    Ok(())
}

/// 添加新密码
fn handle_add(
    api_key: &str,
    title: &str,
    account: &str,
    password: &str,
    category: Option<&str>,
    note: Option<&str>,
) -> Result<()> {
    // 验证 API Key 且有写权限
    let verification = match ApiKeyManager::check_write_permission(api_key) {
        Ok(v) => v,
        Err(e) => {
            print_error(&e.to_string());
            return Ok(());
        }
    };

    // 检查是否有权限添加该账号（如果设置了限制）
    if !ApiKeyManager::can_access_account(&verification, title) {
        print_error("密钥没有权限管理该账号");
        return Ok(());
    }

    // 参数验证
    if title.is_empty() {
        print_error("标题不能为空");
        return Ok(());
    }

    let conn = match get_conn() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("数据库错误: {}", e));
            return Ok(());
        }
    };

    let conn = match conn.lock() {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("锁错误: {}", e));
            return Ok(());
        }
    };

    // 检查标题是否已存在
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM password WHERE title = ?1",
            params![title],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if exists {
        print_error(&format!("标题 '{}' 已存在", title));
        return Ok(());
    }

    // 加密敏感数据
    let enc_account = match encrypt_str(account) {
        Ok(s) => s,
        Err(e) => {
            print_error(&format!("加密错误: {}", e));
            return Ok(());
        }
    };

    let enc_password = match encrypt_str(password) {
        Ok(s) => s,
        Err(e) => {
            print_error(&format!("加密错误: {}", e));
            return Ok(());
        }
    };

    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    match conn.execute(
        "INSERT INTO password (title, account, password, acct_type, bz, cre_time, ud_time)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            title.trim(),
            enc_account,
            enc_password,
            category.unwrap_or(""),
            note.unwrap_or(""),
            &now,
            &now,
        ],
    ) {
        Ok(_) => {
            let id = conn.last_insert_rowid();
            let result = HashMap::from([
                ("id", id.to_string()),
                ("title", title.to_string()),
                ("message", "添加成功".to_string()),
            ]);
            print_success(result);
        }
        Err(e) => {
            print_error(&format!("添加失败: {}", e));
        }
    }

    Ok(())
}

/// 打印成功响应（JSON）
fn print_success<T: Serialize>(data: T) {
    let response = ApiResponse::success(data);
    match serde_json::to_string(&response) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{{\"error\": \"JSON序列化错误: {}\"}}", e),
    }
}

/// 打印错误响应（JSON）
fn print_error(msg: &str) {
    let response: ApiResponse<()> = ApiResponse::error(msg.to_string());
    match serde_json::to_string(&response) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{{\"error\": \"{} (JSON错误: {})\"}}", msg, e),
    }
}

/// Agent 密钥管理命令
pub mod key_management {
    use super::*;
    use crate::api_key::ApiKeyManager;

    /// 生成新的 API 密钥
    pub fn generate_key(
        name: &str,
        expires_hours: Option<i64>,
        permissions: &str,
        allowed_accounts: Option<Vec<String>>,
    ) -> Result<()> {
        match ApiKeyManager::generate(name, expires_hours, permissions, allowed_accounts) {
            Ok((raw_key, info)) => {
                // 注意：只在这里打印原始密钥
                let result = json!({
                    "success": true,
                    "message": "密钥生成成功（仅显示一次，请立即保存）",
                    "key": raw_key,
                    "info": {
                        "id": info.id,
                        "key_id": info.key_id,
                        "name": info.name,
                        "created_at": info.created_at,
                        "expires_at": info.expires_at,
                        "permissions": info.permissions,
                        "allowed_accounts": info.allowed_accounts,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
            Err(e) => {
                print_error(&format!("生成失败: {}", e));
                Ok(())
            }
        }
    }

    /// 列出所有密钥
    pub fn list_keys() -> Result<()> {
        match ApiKeyManager::list_all() {
            Ok(keys) => {
                // 隐藏 key_hash，只显示元数据
                let summaries: Vec<_> = keys
                    .into_iter()
                    .map(|k| {
                        json!({
                            "id": k.id,
                            "key_id": k.key_id,
                            "name": k.name,
                            "created_at": k.created_at,
                            "expires_at": k.expires_at,
                            "last_used_at": k.last_used_at,
                            "permissions": k.permissions,
                            "is_active": k.is_active,
                        })
                    })
                    .collect();

                let result = json!({
                    "success": true,
                    "count": summaries.len(),
                    "keys": summaries
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
            Err(e) => {
                print_error(&format!("查询失败: {}", e));
                Ok(())
            }
        }
    }

    /// 撤销密钥
    pub fn revoke_key(key_id: &str) -> Result<()> {
        match ApiKeyManager::revoke(key_id) {
            Ok(_) => {
                print_success(json!({"message": format!("密钥 {} 已撤销", key_id)}));
                Ok(())
            }
            Err(e) => {
                print_error(&format!("撤销失败: {}", e));
                Ok(())
            }
        }
    }

    /// 删除密钥
    pub fn delete_key(key_id: &str) -> Result<()> {
        match ApiKeyManager::delete(key_id) {
            Ok(_) => {
                print_success(json!({"message": format!("密钥 {} 已删除", key_id)}));
                Ok(())
            }
            Err(e) => {
                print_error(&format!("删除失败: {}", e));
                Ok(())
            }
        }
    }
}
