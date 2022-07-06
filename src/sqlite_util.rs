pub fn create_db() {
    let connection = sqlite3::open("pwd.db").unwrap();
    connection
        .execute(
            "
        CREATE TABLE users (name TEXT, age INTEGER);
        INSERT INTO users (name, age) VALUES ('Alice', 42);
        INSERT INTO users (name, age) VALUES ('Bob', 69);
        ",
        )
        .unwrap();
}
