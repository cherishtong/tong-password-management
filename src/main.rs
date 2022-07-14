
mod lib;
use crate::lib::create_db;
use crate::lib::init;
fn main() {
    create_db();
    init();
}
