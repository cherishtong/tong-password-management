use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use aes_gcm::{
    aead::Aead,
    Aes256Gcm, Key, KeyInit, Nonce,
};
use anyhow::{anyhow, Context, Result};
use chrono::Local;
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password as DialoguerPassword};
use once_cell::sync::OnceCell;
use rand::Rng;
use rusqlite::{params, Connection};

// TUI 模块
pub mod ui;

// =============================================================================
// 常量定义
// =============================================================================

const DB_FILE_NAME: &str = "pwd.db";
pub const APP_NAME: &str = "记多宝";
pub const APP_VERSION: &str = "2.0.0";

// SQL 语句
const CREATE_ROOT_USER_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS root_user (
        name TEXT PRIMARY KEY NOT NULL UNIQUE,
        password TEXT NOT NULL,
        salt TEXT NOT NULL
    );
"#;

const CREATE_PASSWORD_TABLE_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS password (
        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        account TEXT NOT NULL,
        password TEXT NOT NULL,
        acct_type TEXT,
        bz TEXT,
        cre_time TEXT NOT NULL,
        ud_time TEXT NOT NULL
    );
"#;

const INSERT_ROOT_USER_SQL: &str = r#"
    INSERT INTO root_user (name, password, salt) VALUES (?1, ?2, ?3);
"#;

const QUERY_ROOT_USER_SQL: &str = r#"
    SELECT password, salt FROM root_user WHERE name = 'root';
"#;

const SELECT_PASSWORD_LIST: &str = r#"
    SELECT id, title, account, password, acct_type, bz, cre_time, ud_time 
    FROM password ORDER BY id;
"#;

const SEARCH_PASSWORD_SQL: &str = r#"
    SELECT id, title, account, password, acct_type, bz, cre_time, ud_time 
    FROM password 
    WHERE title LIKE ?1 OR account LIKE ?1 OR acct_type LIKE ?1 OR bz LIKE ?1
    ORDER BY id;
"#;

const INSERT_PASSWORD_SQL: &str = r#"
    INSERT INTO password (title, account, password, acct_type, bz, cre_time, ud_time)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
"#;

const DELETE_PASSWORD_ID_SQL: &str = r#"
    DELETE FROM password WHERE id = ?1;
"#;

const UPDATE_PASSWORD_ID_SQL: &str = r#"
    UPDATE password SET 
        title = ?1, account = ?2, password = ?3, acct_type = ?4, 
        bz = ?5, ud_time = ?6 
    WHERE id = ?7;
"#;

// =============================================================================
// 全局状态
// =============================================================================

static DB_CONN: OnceCell<Arc<Mutex<Connection>>> = OnceCell::new();
static MASTER_KEY: OnceCell<Vec<u8>> = OnceCell::new();

// =============================================================================
// 数据结构
// =============================================================================

#[derive(Debug, Clone)]
pub struct PassWord {
    pub id: i64,
    pub title: String,
    pub account: String,
    pub password: String,
    pub acct_type: String,
    pub bz: String,
    pub cre_time: String,
    pub ud_time: String,
}

// =============================================================================
// 数据库管理
// =============================================================================

/// 获取配置目录
fn get_config_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir().context("无法获取配置目录")?;
    let app_dir = config_dir.join("jiduobao");
    
    if !app_dir.exists() {
        fs::create_dir_all(&app_dir).context("创建应用目录失败")?;
    }
    
    Ok(app_dir)
}

/// 获取数据库路径
fn get_db_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join(DB_FILE_NAME))
}

/// 初始化数据库连接
pub fn init_db() -> Result<()> {
    let db_path = get_db_path()?;
    let conn = Connection::open(&db_path).context("无法打开数据库")?;
    
    // 启用 WAL 模式提高性能
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    
    // 创建表
    conn.execute(CREATE_ROOT_USER_SQL, [])?;
    conn.execute(CREATE_PASSWORD_TABLE_SQL, [])?;
    
    DB_CONN.set(Arc::new(Mutex::new(conn)))
        .map_err(|_| anyhow!("数据库连接已初始化"))?;
    
    Ok(())
}

/// 获取数据库连接
fn get_conn() -> Result<Arc<Mutex<Connection>>> {
    DB_CONN.get()
        .cloned()
        .context("数据库未初始化")
}

/// 检查是否是首次运行
fn is_first_run() -> Result<bool> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM root_user WHERE name = 'root'",
        [],
        |row| row.get(0),
    )?;
    
    Ok(count == 0)
}

// =============================================================================
// Base64 编解码
// =============================================================================

mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    pub fn encode(input: &[u8]) -> String {
        STANDARD.encode(input)
    }
    
    pub fn decode(input: &str) -> anyhow::Result<Vec<u8>> {
        STANDARD
            .decode(input)
            .map_err(|e| anyhow::anyhow!("Base64 解码失败: {}", e))
    }
}

// =============================================================================
// 加密/解密
// =============================================================================

/// 使用 Argon2 派生密钥
fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    use argon2::{Argon2, Params};
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    
    let mut output = vec![0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow!("密钥派生失败: {}", e))?;
    
    Ok(output)
}

/// 使用 AES-256-GCM 加密
pub fn encrypt_str(plaintext: &str) -> Result<String> {
    if plaintext.trim().is_empty() {
        return Ok(String::new());
    }
    
    let key_bytes = MASTER_KEY.get().context("主密钥未初始化")?;
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // 生成随机 nonce
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 加密
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("加密失败: {:?}", e))?;
    
    // 组合 nonce 和 ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(b64::encode(&result))
}

/// 使用 AES-256-GCM 解密
pub fn decrypt_str(ciphertext: &str) -> Result<String> {
    if ciphertext.trim().is_empty() {
        return Ok(String::new());
    }
    
    let key_bytes = MASTER_KEY.get().context("主密钥未初始化")?;
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // 解码 base64
    let data = b64::decode(ciphertext).context("Base64 解码失败")?;
    
    if data.len() < 12 {
        return Err(anyhow!("加密数据格式错误"));
    }
    
    // 分离 nonce 和 ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // 解密
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("解密失败: {:?}", e))?;
    
    String::from_utf8(plaintext).context("UTF-8 解码失败")
}

// =============================================================================
// 密码管理功能
// =============================================================================

/// 初始化管理员密码
fn setup_master_password() -> Result<()> {
    println!("\n");
    println!("╔════════════════════════════════════════╗");
    println!("║     欢迎使用 {}！         ║", APP_NAME);
    println!("║  第一次运行，请设置主密码              ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    
    let password = loop {
        let pwd1 = DialoguerPassword::with_theme(&ColorfulTheme::default())
            .with_prompt("请输入主密码")
            .interact()
            .context("读取密码失败")?;
        
        let pwd2 = DialoguerPassword::with_theme(&ColorfulTheme::default())
            .with_prompt("请再次输入确认")
            .interact()
            .context("读取密码失败")?;
        
        if pwd1 == pwd2 && !pwd1.is_empty() {
            if pwd1.len() < 6 {
                println!("⚠ 密码长度至少为6位，请重新设置！");
                continue;
            }
            break pwd1;
        } else {
            println!("⚠ 两次输入不一致或密码为空，请重新输入！");
        }
    };
    
    // 生成随机盐值
    let salt: [u8; 16] = rand::random();
    let salt_b64 = b64::encode(&salt);
    
    // 派生密钥并存储
    let key = derive_key(&password, &salt)?;
    MASTER_KEY.set(key).map_err(|_| anyhow!("主密钥已设置"))?;
    
    // 使用 Argon2 哈希存储密码
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| anyhow!("盐值编码失败: {}", e))?;
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow!("密码哈希失败: {}", e))?;
    
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    conn.execute(INSERT_ROOT_USER_SQL, params![
        "root",
        password_hash.to_string(),
        salt_b64
    ])?;
    
    println!("\n✅ 主密码设置成功！");
    Ok(())
}

/// 验证主密码
fn verify_master_password() -> Result<()> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    let (stored_hash, salt_b64): (String, String) = conn
        .query_row(QUERY_ROOT_USER_SQL, [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .context("无法读取管理员信息")?;
    
    let salt = b64::decode(&salt_b64)?;
    
    loop {
        let password = DialoguerPassword::with_theme(&ColorfulTheme::default())
            .with_prompt("请输入主密码")
            .interact()
            .context("读取密码失败")?;
        
        // 验证密码
        use argon2::{Argon2, PasswordHash, PasswordVerifier};
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|e| anyhow!("密码哈希解析失败: {}", e))?;
        
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => {
                // 验证成功，派生解密密钥
                let key = derive_key(&password, &salt)?;
                MASTER_KEY.set(key).map_err(|_| anyhow!("主密钥已设置"))?;
                return Ok(());
            }
            Err(_) => {
                println!("❌ 密码错误，请重试！\n");
            }
        }
    }
}

/// 查询所有密码
pub fn query_all_passwords() -> Result<Vec<PassWord>> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    let mut stmt = conn.prepare(SELECT_PASSWORD_LIST)?;
    let passwords: Vec<PassWord> = stmt
        .query_map([], |row| {
            Ok(PassWord {
                id: row.get(0)?,
                title: row.get(1)?,
                account: row.get(2)?,
                password: row.get(3)?,
                acct_type: row.get(4)?,
                bz: row.get(5)?,
                cre_time: row.get(6)?,
                ud_time: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    
    Ok(passwords)
}

/// 搜索密码
fn search_passwords(keyword: &str) -> Result<Vec<PassWord>> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    let pattern = format!("%{}%", keyword);
    let mut stmt = conn.prepare(SEARCH_PASSWORD_SQL)?;
    
    let passwords: Vec<PassWord> = stmt
        .query_map([&pattern], |row| {
            Ok(PassWord {
                id: row.get(0)?,
                title: row.get(1)?,
                account: row.get(2)?,
                password: row.get(3)?,
                acct_type: row.get(4)?,
                bz: row.get(5)?,
                cre_time: row.get(6)?,
                ud_time: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    
    Ok(passwords)
}

/// 添加密码（Dialoguer 版本）
pub fn add_password_dialog() -> Result<()> {
    println!("\n=== 添加新密码 ===\n");
    
    let title: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("标题")
        .interact_text()?;
    
    let account: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("账号")
        .interact_text()?;
    
    let use_generated = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("是否自动生成密码?")
        .default(true)
        .interact()?;
    
    let password = if use_generated {
        let length: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("密码长度")
            .default(16)
            .interact_text()?;
        let pwd = generate_random_password(length.max(8));
        println!("🎲 生成的密码: {}", pwd);
        
        // 复制到剪贴板
        if copy_to_clipboard(&pwd).is_ok() {
            println!("📋 已复制到剪贴板");
        }
        pwd
    } else {
        DialoguerPassword::with_theme(&ColorfulTheme::default())
            .with_prompt("密码")
            .interact()?
    };
    
    let acct_type: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("分类")
        .allow_empty(true)
        .interact_text()?;
    
    let bz: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("备注")
        .allow_empty(true)
        .interact_text()?;
    
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // 加密敏感数据
    let encrypted_account = encrypt_str(&account)?;
    let encrypted_password = encrypt_str(&password)?;
    
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    conn.execute(INSERT_PASSWORD_SQL, params![
        title.trim(),
        encrypted_account,
        encrypted_password,
        acct_type.trim(),
        bz.trim(),
        &now,
        &now,
    ])?;
    
    println!("\n✅ 密码添加成功！");
    Ok(())
}

/// 删除密码
pub fn delete_password(id: i64) -> Result<()> {
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    let affected = conn.execute(DELETE_PASSWORD_ID_SQL, [id])?;
    
    if affected > 0 {
        println!("✅ 删除成功！");
    } else {
        println!("❌ 删除失败，密码不存在");
    }
    
    Ok(())
}

/// 编辑密码
pub fn edit_password_dialog(pwd: &PassWord) -> Result<()> {
    println!("\n=== 编辑密码 ===");
    println!("提示: 直接回车表示不修改该项\n");
    
    let title: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("标题")
        .default(pwd.title.trim().to_string())
        .interact_text()?;
    
    let current_account = decrypt_str(&pwd.account)?;
    let account: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("账号")
        .default(current_account)
        .interact_text()?;
    
    let current_password = decrypt_str(&pwd.password)?;
    let change_password = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("是否修改密码?")
        .default(false)
        .interact()?;
    
    let password = if change_password {
        let use_generated = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("自动生成密码?")
            .default(true)
            .interact()?;
        
        if use_generated {
            generate_random_password(16)
        } else {
            DialoguerPassword::with_theme(&ColorfulTheme::default())
                .with_prompt("新密码")
                .interact()?
        }
    } else {
        current_password
    };
    
    let acct_type: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("分类")
        .default(pwd.acct_type.trim().to_string())
        .interact_text()?;
    
    let bz: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("备注")
        .default(pwd.bz.trim().to_string())
        .interact_text()?;
    
    let encrypted_account = encrypt_str(&account)?;
    let encrypted_password = encrypt_str(&password)?;
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    conn.execute(UPDATE_PASSWORD_ID_SQL, params![
        title.trim(),
        encrypted_account,
        encrypted_password,
        acct_type.trim(),
        bz.trim(),
        &now,
        pwd.id,
    ])?;
    
    println!("\n✅ 更新成功！");
    Ok(())
}

/// 生成随机密码
pub fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789!@#$%^&*";
    
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 生成密码对话框
pub fn generate_password_dialog() -> Result<()> {
    println!("\n=== 密码生成器 ===\n");
    
    let length: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("密码长度")
        .default(16)
        .interact_text()?;
    
    let password = generate_random_password(length.max(8));
    
    println!("\n🎲 生成的密码: {}", password);
    
    let copy = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("复制到剪贴板?")
        .default(true)
        .interact()?;
    
    if copy {
        copy_to_clipboard(&password)?;
        println!("📋 已复制到剪贴板！");
    }
    
    let save = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("保存此密码?")
        .default(false)
        .interact()?;
    
    if save {
        add_password_dialog_with_password(&password)?;
    }
    
    Ok(())
}

/// 使用指定密码添加
fn add_password_dialog_with_password(password: &str) -> Result<()> {
    let title: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("标题")
        .interact_text()?;
    
    let account: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("账号")
        .interact_text()?;
    
    let acct_type: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("分类")
        .allow_empty(true)
        .interact_text()?;
    
    let bz: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("备注")
        .allow_empty(true)
        .interact_text()?;
    
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    let encrypted_account = encrypt_str(&account)?;
    let encrypted_password = encrypt_str(password)?;
    
    let conn = get_conn()?;
    let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
    
    conn.execute(INSERT_PASSWORD_SQL, params![
        title.trim(),
        encrypted_account,
        encrypted_password,
        acct_type.trim(),
        bz.trim(),
        &now,
        &now,
    ])?;
    
    println!("✅ 密码保存成功！");
    Ok(())
}

/// 导出密码
pub fn export_passwords_dialog() -> Result<()> {
    println!("\n=== 导出密码 ===");
    println!("⚠️  警告: 导出文件将包含解密后的密码，请妥善保管！\n");
    
    let path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("导出文件路径")
        .default("jiduobao_export.csv".to_string())
        .interact_text()?;
    
    let passwords = query_all_passwords()?;
    
    if passwords.is_empty() {
        println!("没有可导出的密码数据！");
        return Ok(());
    }
    
    let mut wtr = csv::Writer::from_path(&path)?;
    wtr.write_record(&["序号", "标题", "账号", "密码", "分类", "备注", "创建时间", "更新时间"])?;
    
    for pwd in &passwords {
        wtr.write_record(&[
            pwd.id.to_string(),
            pwd.title.trim().to_string(),
            decrypt_str(&pwd.account).unwrap_or_default(),
            decrypt_str(&pwd.password).unwrap_or_default(),
            pwd.acct_type.trim().to_string(),
            pwd.bz.trim().to_string(),
            pwd.cre_time.clone(),
            pwd.ud_time.clone(),
        ])?;
    }
    
    wtr.flush()?;
    
    println!("\n✅ 成功导出 {} 条记录到 {}", passwords.len(), path);
    println!("⚠️  请妥善保管导出文件，使用完毕后建议删除！");
    
    Ok(())
}

/// 复制到剪贴板
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut ctx = ClipboardContext::new()
        .map_err(|e| anyhow!("无法访问剪贴板: {:?}", e))?;
    ctx.set_contents(text.to_owned())
        .map_err(|e| anyhow!("复制到剪贴板失败: {:?}", e))?;
    Ok(())
}

// =============================================================================
// TUI 主循环
// =============================================================================

/// 运行 TUI 主循环
pub fn run_tui() -> Result<()> {
    use ui::{init_terminal, restore_terminal, App, AppMode, ConfirmAction, NextAction};
    
    // 初始化终端
    let mut terminal = init_terminal()?;
    
    loop {
        // 加载密码列表（每次循环重新加载，以获取最新数据）
        let passwords = query_all_passwords()?;
        
        // 创建应用
        let mut app = App::new(passwords);
        
        // 运行主循环
        let result = app.run(&mut terminal);
        
        // 恢复终端
        let _ = restore_terminal();
        
        // 检查是否需要执行后续操作
        if result.is_ok() && !app.running {
            // 检查是否是退出操作
            let should_quit = matches!(app.mode, AppMode::Confirming(_, ConfirmAction::Quit));
            let has_next_action = !matches!(app.next_action, NextAction::None);
            
            if should_quit {
                break;
            }
            
            // 执行后续操作
            handle_post_tui_action(&app)?;
            
            // 如果有后续操作（添加/编辑/生成），重新进入 TUI
            if has_next_action {
                // 重新初始化终端
                terminal = init_terminal()?;
                continue;
            }
            
            // 其他情况（如删除、导出）也重新进入 TUI
            terminal = init_terminal()?;
        } else {
            // 出错了，退出循环
            return result.map_err(|e| anyhow!("TUI 错误: {}", e));
        }
    }
    
    Ok(())
}

/// 处理 TUI 退出后的操作
fn handle_post_tui_action(app: &ui::App) -> Result<()> {
    use ui::{AppMode, ConfirmAction, NextAction};
    
    // 首先处理 next_action
    match app.next_action {
        NextAction::AddPassword => {
            add_password_dialog()?;
        }
        NextAction::EditPassword(id) => {
            if let Some(pwd) = app.passwords.iter().find(|p| p.id == id) {
                edit_password_dialog(pwd)?;
            }
        }
        NextAction::GeneratePassword => {
            generate_password_dialog()?;
        }
        NextAction::None => {}
    }
    
    // 然后处理确认对话框（用户已在 TUI 中确认过）
    match &app.mode {
        AppMode::Confirming(_, action) => {
            match action {
                ConfirmAction::Delete(id) => {
                    // 直接在 TUI 外执行删除，不再询问
                    delete_password(*id)?;
                }
                ConfirmAction::Export => {
                    export_passwords_dialog()?;
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    Ok(())
}

// =============================================================================
// 命令行参数支持
// =============================================================================

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "jiduobao")]
#[command(about = "记多宝 - 安全的本地密码管理工具")]
#[command(version = APP_VERSION)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 添加新密码
    Add {
        #[arg(short, long)]
        title: Option<String>,
        #[arg(short, long)]
        account: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
        #[arg(short, long)]
        note: Option<String>,
    },
    /// 列出所有密码
    List,
    /// 搜索密码
    Search {
        #[arg(short, long)]
        keyword: String,
    },
    /// 生成随机密码
    Generate {
        #[arg(short, long, default_value = "16")]
        length: usize,
    },
    /// 导出密码
    Export {
        #[arg(short, long, default_value = "jiduobao_export.csv")]
        output: String,
    },
}

/// 处理命令行命令
pub fn handle_command(cli: &Cli) -> Result<bool> {
    match &cli.command {
        None => Ok(false), // 没有子命令，进入交互模式
        
        Some(Commands::Add { title, account, password, category, note }) => {
            init_db()?;
            
            if is_first_run()? {
                println!("首次运行，请先设置主密码！");
                setup_master_password()?;
            } else {
                verify_master_password()?;
            }
            
            // 交互式添加
            if title.is_none() {
                add_password_dialog()?;
            } else {
                // 命令行直接添加
                let password = password.clone().unwrap_or_else(|| generate_random_password(16));
                let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                
                let encrypted_account = encrypt_str(account.as_deref().unwrap_or(""))?;
                let encrypted_password = encrypt_str(&password)?;
                
                let conn = get_conn()?;
                let conn = conn.lock().map_err(|e| anyhow!("锁获取失败: {}", e))?;
                
                conn.execute(INSERT_PASSWORD_SQL, params![
                    title.as_deref().unwrap_or(""),
                    encrypted_account,
                    encrypted_password,
                    category.as_deref().unwrap_or(""),
                    note.as_deref().unwrap_or(""),
                    &now, &now,
                ])?;
                
                println!("✅ 密码添加成功！");
            }
            Ok(true)
        }
        
        Some(Commands::List) => {
            init_db()?;
            
            if is_first_run()? {
                println!("数据库为空，请先添加密码！");
                return Ok(true);
            }
            verify_master_password()?;
            
            let passwords = query_all_passwords()?;
            
            if passwords.is_empty() {
                println!("暂无密码记录");
            } else {
                println!("\n{:<6} {:<20} {:<20} {:<15} {}", 
                    "序号", "标题", "账号", "分类", "更新时间");
                println!("{}", "-".repeat(80));
                
                for pwd in &passwords {
                    let account = decrypt_str(&pwd.account).unwrap_or_default();
                    let account_display = truncate_chars(&account, 18);
                    let title_display = truncate_chars(&pwd.title, 18);
                    
                    println!("{:<6} {:<20} {:<20} {:<15} {}",
                        pwd.id,
                        title_display,
                        "*".repeat(account_display.len().min(18)),
                        pwd.acct_type,
                        pwd.ud_time
                    );
                }
                println!("\n共 {} 条记录", passwords.len());
            }
            Ok(true)
        }
        
        Some(Commands::Search { keyword }) => {
            init_db()?;
            
            if is_first_run()? {
                println!("数据库为空！");
                return Ok(true);
            }
            verify_master_password()?;
            
            let passwords = search_passwords(keyword)?;
            
            if passwords.is_empty() {
                println!("未找到匹配的密码记录。");
            } else {
                println!("\n搜索结果 '{}': 共 {} 条\n", keyword, passwords.len());
                for pwd in &passwords {
                    println!("[{}] {} ({}) 更新时间: {}",
                        pwd.id,
                        pwd.title,
                        pwd.acct_type,
                        pwd.ud_time
                    );
                }
            }
            Ok(true)
        }
        
        Some(Commands::Generate { length }) => {
            let password = generate_random_password(*length);
            println!("{}", password);
            
            // 尝试复制到剪贴板
            if copy_to_clipboard(&password).is_ok() {
                eprintln!("📋 已复制到剪贴板");
            }
            Ok(true)
        }
        
        Some(Commands::Export { output }) => {
            init_db()?;
            
            if is_first_run()? {
                println!("数据库为空！");
                return Ok(true);
            }
            verify_master_password()?;
            
            let passwords = query_all_passwords()?;
            
            if passwords.is_empty() {
                println!("没有可导出的密码数据！");
                return Ok(true);
            }
            
            let mut wtr = csv::Writer::from_path(output)?;
            wtr.write_record(&["序号", "标题", "账号", "密码", "分类", "备注", "创建时间", "更新时间"])?;
            
            for pwd in &passwords {
                wtr.write_record(&[
                    pwd.id.to_string(),
                    pwd.title.trim().to_string(),
                    decrypt_str(&pwd.account).unwrap_or_default(),
                    decrypt_str(&pwd.password).unwrap_or_default(),
                    pwd.acct_type.trim().to_string(),
                    pwd.bz.trim().to_string(),
                    pwd.cre_time.clone(),
                    pwd.ud_time.clone(),
                ])?;
            }
            
            wtr.flush()?;
            println!("✅ 成功导出 {} 条记录到 {}", passwords.len(), output);
            Ok(true)
        }
    }
}

// =============================================================================
// 初始化入口
// =============================================================================

/// 初始化应用
pub fn init() -> Result<()> {
    // 初始化数据库
    init_db()?;
    
    // 检查是否是首次运行
    if is_first_run()? {
        setup_master_password()?;
    } else {
        verify_master_password()?;
    }
    
    // 进入 TUI 主循环
    run_tui()
}

// =============================================================================
// 辅助函数
// =============================================================================

/// 安全截断字符串（支持中文）
fn truncate_chars(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = chars.iter().take(max_chars.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}
