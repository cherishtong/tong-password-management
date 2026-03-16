//! TUI 应用状态管理

use std::{
    io,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    Frame, Terminal,
};

use crate::{PassWord, APP_VERSION};

use super::taiji::{AuthorInfo, BigTitle};

/// 应用模式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    /// 正常浏览模式
    Normal,
    /// 搜索模式
    Searching,
    /// 确认对话框
    Confirming(&'static str, ConfirmAction),
}

/// 确认操作类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfirmAction {
    Delete(i64),
    Export,
    Quit,
}

/// TUI 退出后要执行的操作
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NextAction {
    None,
    AddPassword,
    EditPassword(i64),
    GeneratePassword,
}

/// 应用状态
pub struct App {
    /// 密码列表
    pub passwords: Vec<PassWord>,
    /// 表格状态
    pub table_state: TableState,
    /// 当前模式
    pub mode: AppMode,
    /// 搜索关键词
    pub search_query: String,
    /// 是否运行中
    pub running: bool,
    /// 状态消息
    pub status_message: Option<(String, Instant)>,
    /// 滚动状态
    scroll_state: ScrollbarState,
    /// 退出后要执行的操作
    pub next_action: NextAction,
    /// 是否显示明文账号（true=明文，false=遮盖）
    pub show_plaintext: bool,
}

impl App {
    pub fn new(passwords: Vec<PassWord>) -> Self {
        let mut table_state = TableState::default();
        if !passwords.is_empty() {
            table_state.select(Some(0));
        }
        
        let scroll_state = ScrollbarState::new(passwords.len().saturating_sub(1));

        Self {
            passwords,
            table_state,
            mode: AppMode::Normal,
            search_query: String::new(),
            running: true,
            status_message: None,
            scroll_state,
            next_action: NextAction::None,
            show_plaintext: false,
        }
    }

    /// 运行应用主循环
    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        while self.running {
            // 绘制界面
            terminal.draw(|f| self.draw(f))?;

            // 等待键盘事件
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.handle_key(key.code);
                }
            }

            // 清除过期的状态消息
            if let Some((_, time)) = &self.status_message {
                if time.elapsed() > Duration::from_secs(3) {
                    self.status_message = None;
                }
            }
        }

        Ok(())
    }

    /// 绘制界面
    fn draw(&mut self, frame: &mut Frame) {
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(10),  // 大标题区域
                Constraint::Min(10),     // 主内容区
                Constraint::Length(3),   // 状态栏
            ])
            .split(frame.size());

        // 绘制标题栏（大标题 + 太极图 + 作者信息）
        self.draw_header(frame, main_layout[0]);

        // 绘制主内容区（密码表格）
        self.draw_main_content(frame, main_layout[1]);

        // 绘制状态栏
        self.draw_footer(frame, main_layout[2]);

        // 绘制搜索框（如果需要）
        if matches!(self.mode, AppMode::Searching) {
            self.draw_search_popup(frame);
        }

        // 绘制确认对话框（如果需要）
        if let AppMode::Confirming(msg, _) = self.mode {
            self.draw_confirm_dialog(frame, msg);
        }
    }

    /// 绘制标题栏（大标题 + 太极图 + 作者信息）
    fn draw_header(&mut self, frame: &mut Frame, area: Rect) {
        // 分割为左（大标题）、右（作者信息）
        let header_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(40),      // 左侧：大标题
                Constraint::Length(28),   // 右侧：作者信息
            ])
            .split(area);

        // 绘制大标题
        frame.render_widget(BigTitle, header_layout[0]);

        // 绘制作者信息
        frame.render_widget(AuthorInfo::new(APP_VERSION), header_layout[1]);
    }

    /// 绘制主内容区
    fn draw_main_content(&mut self, frame: &mut Frame, area: Rect) {
        // 如果有搜索关键词，显示过滤器
        let display_passwords: Vec<_> = if self.search_query.is_empty() {
            self.passwords.clone()
        } else {
            self.passwords
                .iter()
                .filter(|p| {
                    p.title.contains(&self.search_query)
                        || p.account.contains(&self.search_query)
                        || p.acct_type.contains(&self.search_query)
                        || p.bz.contains(&self.search_query)
                })
                .cloned()
                .collect()
        };

        // 表格标题行
        let header = Row::new(vec!["序号", "标题", "账号", "分类", "备注", "创建时间", "更新时间"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .height(1);

        // 表格数据行
        let rows: Vec<Row> = display_passwords
            .iter()
            .map(|p| {
                // 根据 show_plaintext 状态决定显示方式
                let account_display = if self.show_plaintext {
                    // 明文模式：显示完整解密账号
                    match crate::decrypt_str(&p.account) {
                        Ok(decrypted) => {
                            if decrypted.is_empty() || decrypted == "-" {
                                "-".to_string()
                            } else {
                                decrypted
                            }
                        }
                        Err(_) => "[解密失败]".to_string(),
                    }
                } else {
                    // 遮盖模式：只显示部分
                    match crate::decrypt_str(&p.account) {
                        Ok(decrypted) => {
                            if decrypted.is_empty() || decrypted == "-" {
                                "-".to_string()
                            } else {
                                mask_string(&decrypted, 8)
                            }
                        }
                        Err(_) => "[解密失败]".to_string(),
                    }
                };
                
                Row::new(vec![
                    p.id.to_string(),
                    p.title.trim().to_string(),
                    account_display,
                    p.acct_type.trim().to_string(),
                    p.bz.trim().to_string(),
                    p.cre_time.clone(),
                    p.ud_time.clone(),
                ])
                .height(1)
            })
            .collect();

        // 列宽配置
        let widths = [
            Constraint::Length(6),
            Constraint::Percentage(22),
            Constraint::Percentage(22),
            Constraint::Percentage(10),
            Constraint::Percentage(15),
            Constraint::Length(22),
            Constraint::Length(22),
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .title(if self.search_query.is_empty() {
                        format!("密码列表 (共 {} 条)", display_passwords.len())
                    } else {
                        format!("搜索结果: '{}' ({} 条)", self.search_query, display_passwords.len())
                    })
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(table, area, &mut self.table_state);

        // 绘制滚动条
        if display_passwords.len() > (area.height as usize).saturating_sub(3) {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));
            
            frame.render_stateful_widget(
                scrollbar,
                area.inner(&Margin {
                    horizontal: 0,
                    vertical: 1,
                }),
                &mut self.scroll_state,
            );
        }
    }

    /// 绘制底部状态栏
    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let footer_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(area);

        // 状态消息（如果有）
        if let Some((msg, _)) = &self.status_message {
            let status = Paragraph::new(Span::styled(msg, Style::default().fg(Color::Green)))
                .alignment(Alignment::Center);
            frame.render_widget(status, footer_layout[0]);
        } else {
            frame.render_widget(Paragraph::new(""), footer_layout[0]);
        }

        // 快捷键帮助
        let help_text = if matches!(self.mode, AppMode::Searching) {
            "Enter:确认  Esc:取消"
        } else {
            "↑↓:选择  Enter:复制密码  u:显示/隐藏账号  a:添加  d:删除  e:编辑  /:搜索  g:生成密码  x:导出  q:退出"
        };

        let help = Paragraph::new(Span::styled(help_text, Style::default().fg(Color::Gray)))
            .block(Block::default().borders(Borders::TOP))
            .alignment(Alignment::Center);

        frame.render_widget(help, footer_layout[1]);
    }

    /// 绘制搜索弹窗
    fn draw_search_popup(&self, frame: &mut Frame) {
        let popup_area = centered_rect(60, 20, frame.size());

        let block = Block::default()
            .title("搜索密码")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let text = Paragraph::new(self.search_query.clone())
            .block(block)
            .style(Style::default().fg(Color::White));

        frame.render_widget(Clear, popup_area);
        frame.render_widget(text, popup_area);
    }

    /// 绘制确认对话框
    fn draw_confirm_dialog(&self, frame: &mut Frame, message: &str) {
        let popup_area = centered_rect(50, 30, frame.size());

        let text = Text::from(vec![
            Line::from(Span::styled(message, Style::default().fg(Color::Yellow))),
            Line::from(""),
            Line::from(vec![
                Span::styled("y", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw(": 确认  "),
                Span::styled("n", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw("/Esc: 取消"),
            ]),
        ]);

        let block = Block::default()
            .title("确认")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);

        frame.render_widget(Clear, popup_area);
        frame.render_widget(paragraph, popup_area);
    }

    /// 处理键盘输入
    fn handle_key(&mut self, key: KeyCode) {
        match self.mode {
            AppMode::Normal => self.handle_normal_key(key),
            AppMode::Searching => self.handle_search_key(key),
            AppMode::Confirming(_, _) => self.handle_confirm_key(key),
        }
    }

    /// 正常模式按键处理
    fn handle_normal_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.mode = AppMode::Confirming("确定要退出吗？", ConfirmAction::Quit);
            }
            KeyCode::Up => {
                if !self.passwords.is_empty() {
                    let idx = self.table_state.selected().unwrap_or(0);
                    if idx > 0 {
                        self.table_state.select(Some(idx - 1));
                        self.scroll_state = self.scroll_state.position(idx - 1);
                    }
                }
            }
            KeyCode::Down => {
                if !self.passwords.is_empty() {
                    let idx = self.table_state.selected().unwrap_or(0);
                    if idx < self.passwords.len().saturating_sub(1) {
                        self.table_state.select(Some(idx + 1));
                        self.scroll_state = self.scroll_state.position(idx + 1);
                    }
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                // 添加密码 - 退出 TUI 模式，返回给调用者处理
                self.next_action = NextAction::AddPassword;
                self.running = false;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                // 删除密码
                if let Some(idx) = self.table_state.selected() {
                    if let Some(pwd) = self.passwords.get(idx) {
                        // 存储确认信息，使用静态字符串
                        self.mode = AppMode::Confirming(
                            "确定要删除这条密码吗？",
                            ConfirmAction::Delete(pwd.id),
                        );
                    }
                }
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                // 编辑密码
                if let Some(idx) = self.table_state.selected() {
                    if let Some(pwd) = self.passwords.get(idx) {
                        self.next_action = NextAction::EditPassword(pwd.id);
                        self.running = false;
                    }
                }
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                // 生成密码
                self.next_action = NextAction::GeneratePassword;
                self.running = false;
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                // 切换账号显示模式（明文/遮盖）
                self.show_plaintext = !self.show_plaintext;
                if self.show_plaintext {
                    self.set_status("🔓 已切换为明文显示模式".to_string());
                } else {
                    self.set_status("🔒 已切换为遮盖显示模式".to_string());
                }
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                // 导出
                self.mode = AppMode::Confirming("确定要导出所有密码吗？", ConfirmAction::Export);
            }
            KeyCode::Char('/') | KeyCode::Char('s') | KeyCode::Char('S') => {
                // 搜索
                self.mode = AppMode::Searching;
                self.search_query.clear();
            }
            KeyCode::Enter => {
                // 复制选中密码到剪贴板
                if let Some(idx) = self.table_state.selected() {
                    if let Some(pwd) = self.passwords.get(idx) {
                        // 解密密码并复制到剪贴板
                        match crate::decrypt_str(&pwd.password) {
                            Ok(decrypted) => {
                                match crate::copy_to_clipboard(&decrypted) {
                                    Ok(_) => {
                                        self.set_status(format!("✅ 已复制 '{}' 的密码到剪贴板", pwd.title.trim()));
                                    }
                                    Err(e) => {
                                        self.set_status(format!("❌ 复制失败: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.set_status(format!("❌ 解密失败: {}", e));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// 搜索模式按键处理
    fn handle_search_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => {
                self.mode = AppMode::Normal;
            }
            KeyCode::Esc => {
                self.search_query.clear();
                self.mode = AppMode::Normal;
            }
            KeyCode::Backspace => {
                self.search_query.pop();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
            }
            _ => {}
        }
    }

    /// 确认模式按键处理
    fn handle_confirm_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let AppMode::Confirming(_, action) = self.mode {
                    match action {
                        ConfirmAction::Quit => {
                            // 退出程序，保持 mode 以便调用处知道是退出
                            self.running = false;
                        }
                        ConfirmAction::Delete(_) => {
                            // 退出 TUI 让调用处处理删除
                            // 保持 mode 为 Confirming 以便调用处知道要删除
                            self.running = false;
                        }
                        ConfirmAction::Export => {
                            // 退出 TUI 让调用处处理导出
                            // 保持 mode 为 Confirming 以便调用处知道要导出
                            self.running = false;
                        }
                    }
                } else {
                    self.mode = AppMode::Normal;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.mode = AppMode::Normal;
            }
            _ => {}
        }
    }

    /// 设置状态消息
    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }

    /// 获取选中的密码
    pub fn selected_password(&self) -> Option<&PassWord> {
        self.table_state
            .selected()
            .and_then(|idx| self.passwords.get(idx))
    }
}

/// 计算居中矩形
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// 遮盖敏感字符串（支持中文）
fn mask_string(s: &str, max_len: usize) -> String {
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    
    if chars.len() <= 4 {
        "****".to_string()
    } else {
        let show_len = chars.len().min(max_len).saturating_sub(4);
        let prefix: String = chars.iter().take(show_len).collect();
        format!("{}****", prefix)
    }
}

/// 初始化终端
pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(io::stdout()))
}

/// 恢复终端
pub fn restore_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
