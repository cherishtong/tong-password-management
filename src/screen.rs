extern crate term;

pub fn show() {
    let mut t = term::stdout().unwrap();
    t.fg(term::color::BRIGHT_BLUE).unwrap();

    writeln!(t,"*************************************").unwrap();
    writeln!(t,"*****         密码管理工具        *******").unwrap();
    writeln!(t,"*****                          *******").unwrap();
    writeln!(t,"*************************************").unwrap();
    t.reset().unwrap();
}
