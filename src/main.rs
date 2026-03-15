use clap::Parser;
use jidobao::{handle_command, init, Cli};

fn main() {
    let cli = Cli::parse();
    
    // 尝试处理命令行命令
    match handle_command(&cli) {
        Ok(true) => {
            // 命令已处理，直接退出
            return;
        }
        Ok(false) => {
            // 没有命令，进入 TUI 交互模式
            if let Err(e) = init() {
                eprintln!("❌ 错误: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("❌ 错误: {}", e);
            std::process::exit(1);
        }
    }
}
