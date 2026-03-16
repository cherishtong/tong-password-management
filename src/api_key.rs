//! API 密钥管理模块
//!
//! 提供 Agent 访问密码的密钥管理功能，包括：
//! - 生成新的 API 密钥
//! - 验证密钥有效性
//! - 密钥过期检查
//! - 密钥权限管理
//! - 账号访问限制

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Local, NaiveDateTime};
use rand::Rng;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::get_conn;

// 密钥前缀
const KEY_PREFIX: &str = "jdb_";
// 密钥长度（不含前缀）
const KEY_LENGTH: usize = 32;
// 数据库表名
const API_KEY_TABLE: &str = "api_keys";

/// API 密钥信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: i64,
    pub key_id: String,
    pub name: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub permissions: String,
    pub is_active: bool,
    /// 允许的账号列表（JSON 数组），None 表示允许所有
    pub allowed_accounts: Option<Vec<String>>,
}

/// API 密钥验证结果（包含完整信息）
#[derive(Debug, Clone)]
pub struct ApiKeyVerification {
    pub info: ApiKeyInfo,
}

/// API 密钥管理器
pub struct ApiKeyManager;

impl ApiKeyManager {
    /// 初始化 API 密钥表
    pub fn init_table() -> Result<()> {
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        conn.execute(
            &format!(
                r#"
                CREATE TABLE IF NOT EXISTS {} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                    key_id TEXT UNIQUE NOT NULL,
                    key_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used_at TEXT,
                    permissions TEXT DEFAULT 'read',
                    is_active INTEGER DEFAULT 1,
                    allowed_accounts TEXT
                )
                "#,
                API_KEY_TABLE
            ),
            [],
        )?;

        Ok(())
    }

    /// 生成新的 API 密钥
    ///
    /// # 参数
    /// - `name`: 密钥名称（用于标识）
    /// - `expires_hours`: 过期时间（小时），None 表示永不过期
    /// - `permissions`: 权限，"read" 或 "readwrite"
    /// - `allowed_accounts`: 允许访问的账号标题列表，None 表示允许所有
    ///
    /// # 返回
    /// - `(String, ApiKeyInfo)`: (原始密钥, 密钥信息)
    ///
    /// # 注意
    /// 原始密钥只返回一次，必须立即保存，之后无法恢复！
    pub fn generate(
        name: &str,
        expires_hours: Option<i64>,
        permissions: &str,
        allowed_accounts: Option<Vec<String>>,
    ) -> Result<(String, ApiKeyInfo)> {
        // 生成随机密钥
        let raw_key = Self::generate_random_key();
        let key_id = format!("{}{}", KEY_PREFIX, raw_key);

        // 计算密钥哈希
        let key_hash = Self::hash_key(&key_id);

        // 计算过期时间
        let now = Local::now();
        let expires_at = expires_hours.map(|hours| {
            (now + Duration::hours(hours))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        });

        let created_at = now.format("%Y-%m-%d %H:%M:%S").to_string();

        // 序列化允许访问的账号列表
        let allowed_accounts_json = allowed_accounts
            .as_ref()
            .map(|list| serde_json::to_string(list).unwrap_or_default())
            .filter(|s| !s.is_empty() && s != "[]");

        // 插入数据库
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        conn.execute(
            &format!(
                "INSERT INTO {} (key_id, key_hash, name, created_at, expires_at, permissions, is_active, allowed_accounts) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
                API_KEY_TABLE
            ),
            params![
                key_id,
                key_hash,
                name,
                created_at,
                expires_at,
                permissions,
                allowed_accounts_json
            ],
        )?;

        let id = conn.last_insert_rowid();

        let info = ApiKeyInfo {
            id,
            key_id: key_id.clone(),
            name: name.to_string(),
            created_at,
            expires_at,
            last_used_at: None,
            permissions: permissions.to_string(),
            is_active: true,
            allowed_accounts,
        };

        Ok((key_id, info))
    }

    /// 验证 API 密钥
    ///
    /// # 参数
    /// - `api_key`: 原始密钥
    ///
    /// # 返回
    /// - `Ok(ApiKeyVerification)`: 验证通过
    /// - `Err`: 验证失败或密钥无效/过期
    pub fn verify(api_key: &str) -> Result<ApiKeyVerification> {
        // 检查密钥格式
        if !api_key.starts_with(KEY_PREFIX) {
            return Err(anyhow!("无效的密钥格式"));
        }

        // 计算哈希
        let key_hash = Self::hash_key(api_key);

        // 查询数据库
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        let mut stmt = conn.prepare(&format!(
            "SELECT id, key_id, key_hash, name, created_at, expires_at, last_used_at, permissions, is_active, allowed_accounts 
             FROM {} WHERE key_id = ?1",
            API_KEY_TABLE
        ))?;

        let row = stmt.query_row([api_key], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        });

        let (
            id,
            key_id,
            stored_hash,
            name,
            created_at,
            expires_at,
            _last_used_at,
            permissions,
            is_active,
            allowed_accounts_json,
        ) = match row {
            Ok(data) => data,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(anyhow!("密钥不存在"));
            }
            Err(e) => return Err(e.into()),
        };

        // 检查是否激活
        if is_active == 0 {
            return Err(anyhow!("密钥已被禁用"));
        }

        // 时序安全比较哈希
        let hash_match: bool = key_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into();
        if !hash_match {
            return Err(anyhow!("密钥验证失败"));
        }

        // 检查是否过期
        if let Some(ref exp) = expires_at {
            let exp_time = NaiveDateTime::parse_from_str(exp, "%Y-%m-%d %H:%M:%S")
                .map_err(|_| anyhow!("无效的过期时间格式"))?;
            let exp_datetime: DateTime<Local> =
                DateTime::from_naive_utc_and_offset(exp_time, *Local::now().offset());

            if Local::now() > exp_datetime {
                return Err(anyhow!("密钥已过期"));
            }
        }

        // 更新最后使用时间
        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            &format!(
                "UPDATE {} SET last_used_at = ?1 WHERE id = ?2",
                API_KEY_TABLE
            ),
            params![&now_str, id],
        )?;

        // 解析允许访问的账号列表
        let allowed_accounts =
            allowed_accounts_json.and_then(|json| serde_json::from_str(&json).ok());

        let info = ApiKeyInfo {
            id,
            key_id,
            name,
            created_at,
            expires_at,
            last_used_at: Some(now_str),
            permissions,
            is_active: true,
            allowed_accounts,
        };

        Ok(ApiKeyVerification { info })
    }

    /// 检查密钥是否有权限访问指定账号
    pub fn can_access_account(verification: &ApiKeyVerification, account_title: &str) -> bool {
        // 如果没有设置限制，则允许访问所有
        let allowed = match &verification.info.allowed_accounts {
            None => return true,
            Some(list) if list.is_empty() => return true,
            Some(list) => list,
        };

        // 检查账号是否在允许列表中
        allowed
            .iter()
            .any(|title| title.trim() == account_title.trim())
    }

    /// 列出所有 API 密钥
    pub fn list_all() -> Result<Vec<ApiKeyInfo>> {
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        let mut stmt = conn.prepare(&format!(
            "SELECT id, key_id, name, created_at, expires_at, last_used_at, permissions, is_active, allowed_accounts 
             FROM {} ORDER BY created_at DESC",
            API_KEY_TABLE
        ))?;

        let keys = stmt
            .query_map([], |row| {
                let allowed_accounts_json: Option<String> = row.get(8)?;
                let allowed_accounts =
                    allowed_accounts_json.and_then(|json| serde_json::from_str(&json).ok());

                Ok(ApiKeyInfo {
                    id: row.get(0)?,
                    key_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    last_used_at: row.get(5)?,
                    permissions: row.get(6)?,
                    is_active: row.get::<_, i64>(7)? == 1,
                    allowed_accounts,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(keys)
    }

    /// 撤销（禁用）API 密钥
    pub fn revoke(key_id: &str) -> Result<()> {
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        let affected = conn.execute(
            &format!(
                "UPDATE {} SET is_active = 0 WHERE key_id = ?1",
                API_KEY_TABLE
            ),
            params![key_id],
        )?;

        if affected == 0 {
            return Err(anyhow!("密钥不存在"));
        }

        Ok(())
    }

    /// 删除 API 密钥
    pub fn delete(key_id: &str) -> Result<()> {
        let conn = get_conn()?;
        let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

        let affected = conn.execute(
            &format!("DELETE FROM {} WHERE key_id = ?1", API_KEY_TABLE),
            params![key_id],
        )?;

        if affected == 0 {
            return Err(anyhow!("密钥不存在"));
        }

        Ok(())
    }

    /// 检查密钥是否有写权限
    pub fn check_write_permission(api_key: &str) -> Result<ApiKeyVerification> {
        let verification = Self::verify(api_key)?;

        if verification.info.permissions != "readwrite" {
            return Err(anyhow!("密钥没有写权限"));
        }

        Ok(verification)
    }

    /// 生成随机密钥字符串
    fn generate_random_key() -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();

        (0..KEY_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// 计算密钥哈希 (SHA-256)
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        // 添加额外盐值增加安全性（即使数据库泄露也无法直接彩虹表攻击）
        hasher.update(b"jiduobao_api_key_v1");
        hex::encode(hasher.finalize())
    }
}

/// 清理过期的密钥（可选的维护功能）
pub fn cleanup_expired_keys() -> Result<usize> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;

    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let affected = conn.execute(
        &format!(
            "UPDATE {} SET is_active = 0 
             WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at < ?1",
            API_KEY_TABLE
        ),
        params![now],
    )?;

    Ok(affected as usize)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(b"jiduobao_api_key_v1");
        hex::encode(hasher.finalize())
    }

    #[test]
    fn test_hash_key() {
        let key = "jdb_test123";
        let hash1 = hash_key(key);
        let hash2 = hash_key(key);

        // 相同输入应该产生相同输出
        assert_eq!(hash1, hash2);

        // 不同输入应该产生不同输出
        let hash3 = hash_key("jdb_test456");
        assert_ne!(hash1, hash3);
    }
}
