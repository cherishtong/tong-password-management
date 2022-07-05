use rusqlite::{Connection, Result};

pub fn create_db() -> Result<Connection> {
    const SQL_DROP_USER: &str = "DROP TABLE USER";

    const SQL_CREATE_USER: &str =
        "CREATE TABLE USER( ID INTEGER PRIMARY KEY,NAME TEXT NOT NULL,PWD TEXT NOT NULL)";
    let database_file = String::from("pwd.db");

    let conn = Connection::open(database_file)?;

    let _ = conn.execute(SQL_DROP_USER, []);

    conn.execute(SQL_CREATE_USER, [])?;

    Ok(conn)
}
