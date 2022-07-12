use std::{
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use chrono::Local;
use cli_table::{format::Justify, print_stdout, Cell, Color, Style, Table, WithTitle};
use sqlite3::State;

#[derive(Debug, Table)]
pub struct PassWord {
    #[table(title = "序号", color = "Color::Green")]
    id: i64,
    #[table(title = "账号中文含义", color = "Color::Green")]
    title: String,
    #[table(title = "账号名称", color = "Color::Green")]
    account: String,
    #[table(title = "账号密码", color = "Color::Green")]
    password: String,
    #[table(title = "账号类别", color = "Color::Green")]
    acct_type: String,
    #[table(title = "账号备注", color = "Color::Green")]
    bz: String,
    #[table(title = "账号创建时间", color = "Color::Green")]
    cre_time: String,
    #[table(title = "账号更新时间", color = "Color::Green")]
    ud_time: String,
}

impl Clone for PassWord {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            title: self.title.clone(),
            account: self.account.clone(),
            password: self.password.clone(),
            acct_type: self.acct_type.clone(),
            bz: self.bz.clone(),
            cre_time: self.cre_time.clone(),
            ud_time: self.ud_time.clone(),
        }
    }
}

//创建系统所用表
const CREATE_ROOT_USER_SQL: &str = "CREATE TABLE [root_user](
    [name] TEXT PRIMARY KEY NOT NULL UNIQUE, 
    [password] TEXT);";
const INSERT_ROOT_USER_ROOT_SQL: &str = "INSERT INTO [root_user]
(
[name], 
[password])
VALUES ('root', 'root');

CREATE TABLE [password](
    [id] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, 
    [title] TEXT, 
    [account] TEXT, 
    [password] TEXT, 
    [acct_type] TEXT, 
    [bz] TEXT, 
    [cre_time] TEXT, 
    [ud_time] TEXT);";
//查询是否是root初始密码，来判断用户是否第一次登录本软件
const QUERY_ROOT_USER_ROOT_SQL: &str = "SELECT [password]
FROM   [root_user]
WHERE  [name] = 'root' AND [password] = ?
";
//更新root默认密码
const UPDATE_ROOT_USER_ROOT_SQL: &str = "UPDATE root_user
SET password=?
WHERE name='root'";

const SELECT_PASSWORD_LIST: &str = "SELECT *
FROM   [password];";

const INSERT_PASSWORD_SQL: &str = "INSERT INTO [password]
(
[title], 
[account], 
[password], 
[acct_type], 
[bz], 
[cre_time], 
[ud_time])
VALUES (?, ?, ?, ?, ?, ?, ?);";

const DELETE_PASSWORD_ID_SQL: &str = "DELETE FROM
[password]
WHERE
[id] = ?";

const UPDATE_PASSWORD_ID_SQL: &str = "UPDATE
[password]
SET
[title] = ?, 
[account] = ?, 
[password] = ?, 
[acct_type] = ?, 
[bz] = ?, 
[ud_time] = ?
WHERE
[id] = ?;
";

pub fn init() {
   
    let table = vec![
        vec!["1.添加密码"
            .cell()
            .foreground_color(Some(Color::Green))
            .justify(Justify::Center)
            .bold(true)],
        vec!["2.查看密码"
            .cell()
            .foreground_color(Some(Color::Green))
            .justify(Justify::Center)
            .bold(true)],
        vec!["3.删除密码"
            .cell()
            .foreground_color(Some(Color::Green))
            .justify(Justify::Center)
            .bold(true)],
        vec!["4.更新密码"
            .cell()
            .foreground_color(Some(Color::Green))
            .justify(Justify::Center)
            .bold(true)],
        vec!["5.退出"
            .cell()
            .foreground_color(Some(Color::Green))
            .justify(Justify::Center)
            .bold(true)],
        vec![
            "如有疑问可发邮件至cherishtong@aliyun.com，或添加QQ:1427730623"
                .cell()
                .foreground_color(Some(Color::Green))
                .justify(Justify::Center)
                .bold(true),
        ],
    ]
    .table()
    .title(vec!["小道仝密码管理终端"
        .cell()
        .foreground_color(Some(Color::Green))
        .bold(true)
        .justify(Justify::Center)])
    .bold(true);
    println!("");
    print_stdout(table).unwrap();
    println!("请选择:");
    let mut flag: String = String::new();
    io::stdin().read_line(&mut flag).unwrap();
    let result = flag.trim();
    if result.eq("1") {
        insert_password();
    } else if result.eq("2") {
        show_password_list();
    } else if result.eq("3") {
        delete_password_by_id();
    } else if result.eq("4") {
        update_password();
    } else if result.eq("5") {
        return ;
    } else {
        println!("输入参数不合法请重新输入");
        init();
    }
}

/**
 * 检查目录是否存在，如目录不存在，则手动创建
 */
pub fn check_dir() -> PathBuf {
    //获取当前用户目录
    let home_path = dirs::config_dir().unwrap();

    //创建当前软件配置目录
    let local_path = Path::join(&home_path, "tong_password");

    match local_path.as_path().is_dir() {
        true => local_path,
        false => {
            fs::create_dir(&local_path).unwrap();
            local_path
        }
    }
}

pub fn input_root_password() -> String {
    let mut password1 = String::new();
    let mut password2 = String::new();
    loop {
        println!("第一次进入本软件，请设置管理员密码：");
        io::stdin().read_line(&mut password1).unwrap();
        println!("再次输入确认管理员密码：");
        io::stdin().read_line(&mut password2).unwrap();
        if password1.eq(&password2) {
            break;
        } else {
            println!("两次密码输入不一致，请重新输入!!!!");
            password1.clear();
            password2.clear();
        }
    }
    password1
}

/**
 *
 * 创建数据库
 */
pub fn create_db() {
    let db_path = check_dir();
    let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
    let str = connection.execute(CREATE_ROOT_USER_SQL);

    match str {
        Ok(_) => {
            //表创建成功，然后插入root 用户
            match connection.execute(INSERT_ROOT_USER_ROOT_SQL) {
                Ok(_) => query_root_password(),
                Err(_err) => (),
            }
        }
        Err(_err) => check_root_password(),
    }
}

/**
 * 查询root用户是否为设置的初始密码，如果是初始密码，则让用户输入，并且更新数据库
 */
pub fn query_root_password() {
    let db_path = check_dir();
    let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
    let mut statement = connection.prepare(QUERY_ROOT_USER_ROOT_SQL).unwrap();
    statement.bind(1, "root").unwrap();
    let mut flag: bool = false;
    while let State::Row = statement.next().unwrap() {
        if "root".eq(&statement.read::<String>(0).unwrap()) {
            flag = true;
            break;
        }
    }
    if flag {
        let root_password = input_root_password();
        statement = connection.prepare(UPDATE_ROOT_USER_ROOT_SQL).unwrap();
        statement.bind(1, root_password.trim()).unwrap();
        statement.next().unwrap();
    }
}

/**
 * 校验root用户密码
 */
pub fn check_root_password() {
    println!("请输入管理员密码（第一次进入本终端设置的密码）：");
        let mut pwd = String::new();
        io::stdin().read_line(&mut pwd).unwrap();
        let db_path = check_dir();
        let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
        let mut statement = connection.prepare(QUERY_ROOT_USER_ROOT_SQL).unwrap();
        statement.bind(1, pwd.trim()).unwrap();
        let mut flag: bool = false;
        while let State::Row = statement.next().unwrap() {
            if pwd.trim().eq(&statement.read::<String>(0).unwrap()) {
                flag = true;
                break;
            }
        }
        if flag {
            println!("密码验证通过，进入本终端，欢迎您！！！");
        } else {
            println!("密码验证失败，请重新输入！！！");
            check_root_password();
        }
}

/**
 * 查询所有密码
 */
pub fn query_password_list() -> Option<Vec<PassWord>> {
    let db_path = check_dir();
    let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
    let mut statement = connection.prepare(SELECT_PASSWORD_LIST).unwrap();
    let mut password_list: Vec<PassWord> = Vec::new();
    while let State::Row = statement.next().unwrap() {
        let temp: PassWord = PassWord {
            id: statement.read::<i64>(0).unwrap(),
            title: format_table_data(statement.read::<String>(1)),
            account: format_table_data(statement.read::<String>(2)),
            password: format_table_data(statement.read::<String>(3)),
            acct_type: format_table_data(statement.read::<String>(4)),
            bz: format_table_data(statement.read::<String>(5)),
            cre_time: format_table_data(statement.read::<String>(6)),
            ud_time: format_table_data(statement.read::<String>(7)),
        };
        password_list.push(temp)
    }
    Some(password_list)
}

pub fn show_password_list() -> Option<i8> {
    let password_list = query_password_list().unwrap();
    print_stdout(password_list.with_title()).unwrap();
    back(show_password_list);
    Some(0)
}

pub fn format_table_data(content: Result<String, sqlite3::Error>) -> String {
    match content {
        Ok(ok) => return ok,
        Err(_) => return String::from("-"),
    }
}

/**
 * 添加密码
 */
pub fn insert_password() -> Option<i8> {
    let mut input_password: PassWord = PassWord {
        id: 0,
        title: String::new(),
        account: String::new(),
        password: String::new(),
        acct_type: String::new(),
        bz: String::new(),
        cre_time: String::new(),
        ud_time: String::new(),
    };
    println!("请输入密码标题：");
    io::stdin().read_line(&mut input_password.title).unwrap();
    println!("请输入密码账号：");
    io::stdin().read_line(&mut input_password.account).unwrap();
    println!("请输入密码值：");
    io::stdin().read_line(&mut input_password.password).unwrap();
    println!("请输入密码分类：");
    io::stdin()
        .read_line(&mut input_password.acct_type)
        .unwrap();
    println!("请输入密码备注：");
    io::stdin().read_line(&mut input_password.bz).unwrap();
    input_password.cre_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    input_password.ud_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let db_path = check_dir();
    let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
    let mut statement = connection.prepare(INSERT_PASSWORD_SQL).unwrap();

    statement.bind::<&str>(1, &input_password.title).unwrap();
    statement.bind::<&str>(2, &input_password.account).unwrap();
    statement.bind::<&str>(3, &input_password.password).unwrap();
    statement
        .bind::<&str>(4, &input_password.acct_type)
        .unwrap();
    statement.bind::<&str>(5, &input_password.bz).unwrap();
    statement.bind::<&str>(6, &input_password.cre_time).unwrap();
    statement.bind::<&str>(7, &input_password.ud_time).unwrap();

    match statement.next() {
        Ok(_) => {
            println!("添加成功！！！");
        }
        Err(_) => println!("添加失败，请退出重试！！！"),
    }
    back(insert_password);
    Some(0)
}

/**
 * 根据编号删除密码记录
 */
pub fn delete_password_by_id() -> Option<i8> {
    let password_list = query_password_list().unwrap();
    print_stdout(password_list.with_title()).unwrap();
    println!("请输入需要删除的密码编号,退出请输入-1:");
    let mut flag = String::new();
    io::stdin().read_line(&mut flag).unwrap();
    if flag.as_str().trim().eq("-1") {
        init();
    } else {
        let db_path = check_dir();
        let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
        let mut statement = connection.prepare(DELETE_PASSWORD_ID_SQL).unwrap();
        statement.bind(1, flag.as_str().trim()).unwrap();
        match statement.next() {
            Ok(_) => print!("删除编号{}数据成功", flag),
            Err(_) => print!("删除编号{}数据失败，请重试", flag),
        }
        back(delete_password_by_id);
    }

    Some(0)
}

/**
 * 更新密码
 */

pub fn update_password() -> Option<i8> {
    let password_list = query_password_list().unwrap();
    print_stdout(password_list.with_title()).unwrap();
    println!("请输入需要更新的密码编号,退出请输入-1:");
    let mut flag = String::new();
    io::stdin().read_line(&mut flag).unwrap();
    if flag.as_str().trim().eq("-1") {
        init();
    } else {
        let mut temp: Vec<PassWord> = Vec::new();
        for (_index, item) in password_list.iter().enumerate() {
            if (item.id.to_string()).eq(flag.as_str().trim()) {
                temp.push(item.clone());
            }
        }
        print_stdout(temp.with_title()).unwrap();

        let mut input = String::new();

        let mut upwd = temp.get(0).unwrap().clone();
        println!(
            "当前密码标题(如修改则重新输入,不修改请直接回车):{}",
            upwd.title
        );

        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().is_empty() {
            upwd.title = input.clone()
        }
        println!(
            "当前密码账号(如修改则重新输入即可,不修改请直接回车):{}",
            upwd.account
        );
        input.clear();
        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().is_empty() {
            upwd.account = input.clone()
        }
        println!(
            "当前密码值(如修改则重新输入即可,不修改请直接回车):{}",
            upwd.password
        );
        input.clear();
        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().is_empty() {
            upwd.password = input.clone()
        }
        println!(
            "当前密码分类(如修改则重新输入即可,不修改请直接回车):{}",
            upwd.acct_type
        );
        input.clear();
        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().is_empty() {
            upwd.acct_type = input.clone()
        }
        println!(
            "当前密码备注(如修改则重新输入即可,不修改请直接回车):{}",
            upwd.bz
        );
        input.clear();
        io::stdin().read_line(&mut input).unwrap();

        if !input.trim().is_empty() {
            upwd.bz = input.clone()
        }

        upwd.ud_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        println!("拟要修改成的数据如下，如确定请输入1，放弃则按任意键：");
        let pre_list = vec![upwd];
        print_stdout(pre_list.with_title()).unwrap();
        let mut submit = String::new();
        io::stdin().read_line(&mut submit).unwrap();
        if submit.trim().eq("1") {
            let db_path = check_dir();
            let connection = sqlite3::open(Path::join(db_path.as_path(), "pwd.db")).unwrap();
            let mut statement = connection.prepare(UPDATE_PASSWORD_ID_SQL).unwrap();
            let param = pre_list.get(0).unwrap();
            statement.bind::<&str>(1, &param.title).unwrap();
            statement.bind::<&str>(2, &param.account).unwrap();
            statement.bind::<&str>(3, &param.password).unwrap();
            statement.bind::<&str>(4, &param.acct_type).unwrap();
            statement.bind::<&str>(5, &param.bz).unwrap();
            statement.bind::<&str>(6, &param.ud_time).unwrap();
            statement.bind::<i64>(7, param.id).unwrap();
            match statement.next() {
                Ok(_) => {
                    println!("修改成功！！！");
                }
                Err(_) => println!("添加失败，请退出重试！！！"),
            }
            back(update_password);
        } else {
            back(update_password);
        }
    }
    Some(0)
}

/**
 * 处理所有功能的返回
 */
pub fn back<T>(content: fn() -> Option<T>) {
    println!("输入1继续操作,输入其他返回主菜单！！！");
    let mut flag = String::new();
    io::stdin().read_line(&mut flag).unwrap();
    if flag.as_str().trim().eq("1") {
        content();
    } else {
        init();
    }
}
