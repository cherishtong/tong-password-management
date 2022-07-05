mod screen;
mod sqlite_util;
fn main() {
    screen::show();
    sqlite_util::create_db().unwrap();
}
