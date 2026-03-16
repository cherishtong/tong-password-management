//! API 密钥管理 TUI 界面
//!
//! 提供图形化界面管理 API 密钥，包括：
//! - 查看所有密钥列表
//! - 生成新密钥（可设置过期时间、权限、允许访问的账号）
//! - 撤销/删除密钥
//! - 查看密钥详情

use std::io;
use std::time::{Duration, Instant};

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
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState, Wrap,
    },
    Frame, Terminal,
};

use crate::api_key::{ApiKeyInfo, ApiKeyManager};
use crate::query_all_passwords;

use super::taiji::{AuthorInfo, BigTitle};

/// 密钥管理界面模式
#[derive(Debug, Clone, PartialEq)]
enum KeyManagerMode {
    /// 列表浏览模式
    List,
    /// 生成新密钥（输入名称）
    GenerateName,
    /// 生成新密钥（选择过期时间）
    GenerateExpiry,
    /// 生成新密钥（选择权限）
    GeneratePermission,
    /// 生成新密钥（选择允许的账号）
    GenerateAccounts,
    /// 确认对话框
    Confirming(&'static str, ConfirmAction),
    /// 查看详情
    ViewDetail,
}

/// 确认操作类型
#[derive(Debug, Clone, PartialEq)]
enum ConfirmAction {
    Delete(String),
    Revoke(String),
}

/// 过期时间选项
const EXPIRY_OPTIONS: &[(&str, Option<i64>)] = &[
    ("1 小时", Some(1)),
    ("24 小时", Some(24)),
    ("7 天", Some(24 * 7)),
    ("30 天", Some(24 * 30)),
    ("永不过期", None),
];

/// 权限选项
const PERMISSION_OPTIONS: &[(&str, &str)] =
    &[("只读 (read)", "read"), ("读写 (readwrite)", "readwrite")];

/// API 密钥管理器状态
pub struct ApiKeyManagerApp {
    /// 密钥列表
    keys: Vec<ApiKeyInfo>,
    /// 表格状态
    table_state: TableState,
    /// 当前模式
    mode: KeyManagerMode,
    /// 是否运行中
    running: bool,
    /// 状态消息
    status_message: Option<(String, Instant)>,
    /// 新生成的密钥临时存储
    new_key_input: String,
    /// 生成密钥的当前选项索引
    selected_option: usize,
    /// 生成密钥的配置
    generate_config: GenerateConfig,
    /// 可用的账号列表（用于选择）
    available_accounts: Vec<String>,
    /// 选中的账号索引
    selected_accounts: Vec<bool>,
    /// 新生成的原始密钥（用于显示）
    generated_key: Option<String>,
    /// 滚动状态
    scroll_state: ScrollbarState,
}

/// 生成密钥的配置
#[derive(Default)]
struct GenerateConfig {
    name: String,
    expires_hours: Option<i64>,
    permissions: String,
    allowed_accounts: Vec<String>,
}

impl Default for ApiKeyManagerApp {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyManagerApp {
    pub fn new() -> Self {
        let keys = Self::load_keys().unwrap_or_default();
        let mut table_state = TableState::default();
        if !keys.is_empty() {
            table_state.select(Some(0));
        }

        let scroll_state = ScrollbarState::new(keys.len().saturating_sub(1));

        Self {
            keys,
            table_state,
            mode: KeyManagerMode::List,
            running: true,
            status_message: None,
            new_key_input: String::new(),
            selected_option: 0,
            generate_config: GenerateConfig::default(),
            available_accounts: Vec::new(),
            selected_accounts: Vec::new(),
            generated_key: None,
            scroll_state,
        }
    }

    /// 加载密钥列表
    fn load_keys() -> anyhow::Result<Vec<ApiKeyInfo>> {
        ApiKeyManager::list_all()
    }

    /// 刷新密钥列表
    fn refresh_keys(&mut self) {
        if let Ok(keys) = Self::load_keys() {
            self.keys = keys;
            self.scroll_state = ScrollbarState::new(self.keys.len().saturating_sub(1));
            // 保持选中位置
            if let Some(selected) = self.table_state.selected() {
                if selected >= self.keys.len() && !self.keys.is_empty() {
                    self.table_state.select(Some(self.keys.len() - 1));
                }
            }
        }
    }

    /// 运行管理界面
    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        while self.running {
            terminal.draw(|f| self.draw(f))?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.handle_key(key.code);
                }
            }

            // 清除过期状态消息
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
                Constraint::Length(10), // 标题区
                Constraint::Min(10),    // 主内容
                Constraint::Length(3),  // 状态栏
            ])
            .split(frame.size());

        // 绘制标题
        self.draw_header(frame, main_layout[0]);

        // 根据模式绘制不同内容
        match self.mode {
            KeyManagerMode::List => {
                self.draw_key_list(frame, main_layout[1]);
            }
            KeyManagerMode::GenerateName => {
                self.draw_generate_name(frame, main_layout[1]);
            }
            KeyManagerMode::GenerateExpiry => {
                self.draw_generate_expiry(frame, main_layout[1]);
            }
            KeyManagerMode::GeneratePermission => {
                self.draw_generate_permission(frame, main_layout[1]);
            }
            KeyManagerMode::GenerateAccounts => {
                self.draw_generate_accounts(frame, main_layout[1]);
            }
            KeyManagerMode::ViewDetail => {
                self.draw_view_detail(frame, main_layout[1]);
            }
            _ => {}
        }

        // 绘制状态栏
        self.draw_footer(frame, main_layout[2]);

        // 绘制确认对话框
        if let KeyManagerMode::Confirming(_, _) = self.mode {
            self.draw_confirm_dialog(frame);
        }

        // 显示新生成的密钥
        if let Some(ref key) = self.generated_key {
            self.draw_new_key_dialog(frame, key);
        }
    }

    /// 绘制标题栏
    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let header_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // 左侧：大标题
        let big_title = BigTitle;
        frame.render_widget(big_title, header_layout[0]);

        // 右侧：作者信息
        let author_info = AuthorInfo::new(crate::APP_VERSION);
        frame.render_widget(author_info, header_layout[1]);
    }

    /// 绘制密钥列表
    fn draw_key_list(&mut self, frame: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from("ID").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("名称").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("权限").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("状态").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("过期时间").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("最后使用").style(Style::default().add_modifier(Modifier::BOLD)),
        ])
        .height(1)
        .style(Style::default().bg(Color::DarkGray));

        let rows: Vec<Row> = self
            .keys
            .iter()
            .map(|key| {
                let status = if key.is_active {
                    ("✓ 正常", Color::Green)
                } else {
                    ("✗ 禁用", Color::Red)
                };

                let expiry = key.expires_at.as_deref().unwrap_or("永不过期");

                let last_used = key.last_used_at.as_deref().unwrap_or("从未");

                Row::new(vec![
                    Cell::from(key.id.to_string()),
                    Cell::from(key.name.clone()),
                    Cell::from(key.permissions.clone()),
                    Cell::from(Span::styled(status.0, Style::default().fg(status.1))),
                    Cell::from(expiry.to_string()),
                    Cell::from(last_used.to_string()),
                ])
                .height(1)
            })
            .collect();

        let table = Table::new(
            rows,
            vec![
                Constraint::Length(6),
                Constraint::Length(20),
                Constraint::Length(15),
                Constraint::Length(10),
                Constraint::Length(20),
                Constraint::Length(20),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" API 密钥管理 ")
                .title_alignment(Alignment::Center),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_stateful_widget(table, area, &mut self.table_state);

        // 滚动条
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            area.inner(&Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut self.scroll_state,
        );
    }

    /// 绘制生成密钥 - 输入名称
    fn draw_generate_name(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" 生成新密钥 - 步骤 1/4 ")
            .title_alignment(Alignment::Center);

        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("请输入密钥名称（用于标识）: "),
                Span::styled(&self.new_key_input, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from("例如: CI部署密钥、开发环境等"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" 确认  "),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" 取消"),
            ]),
        ];

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    /// 绘制生成密钥 - 选择过期时间
    fn draw_generate_expiry(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" 生成新密钥 - 步骤 2/4 ")
            .title_alignment(Alignment::Center);

        let mut text = vec![
            Line::from(""),
            Line::from("选择密钥过期时间:"),
            Line::from(""),
        ];

        for (i, (label, _)) in EXPIRY_OPTIONS.iter().enumerate() {
            let style = if i == self.selected_option {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            text.push(Line::from(vec![
                Span::raw(if i == self.selected_option {
                    "▶ "
                } else {
                    "  "
                }),
                Span::styled(label.to_string(), style),
            ]));
        }

        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("↑/↓", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 选择  "),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 确认  "),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 返回"),
        ]));

        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
    }

    /// 绘制生成密钥 - 选择权限
    fn draw_generate_permission(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" 生成新密钥 - 步骤 3/4 ")
            .title_alignment(Alignment::Center);

        let mut text = vec![Line::from(""), Line::from("选择密钥权限:"), Line::from("")];

        for (i, (label, _)) in PERMISSION_OPTIONS.iter().enumerate() {
            let style = if i == self.selected_option {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            text.push(Line::from(vec![
                Span::raw(if i == self.selected_option {
                    "▶ "
                } else {
                    "  "
                }),
                Span::styled(label.to_string(), style),
            ]));
        }

        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("↑/↓", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 选择  "),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 确认  "),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 返回"),
        ]));

        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
    }

    /// 绘制生成密钥 - 选择允许的账号
    fn draw_generate_accounts(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" 生成新密钥 - 步骤 4/4 ")
            .title_alignment(Alignment::Center);

        let mut text = vec![
            Line::from(""),
            Line::from("选择允许访问的账号（空格选择/取消，Enter 完成）:"),
            Line::from("不选择则表示允许访问所有账号"),
            Line::from(""),
        ];

        if self.available_accounts.is_empty() {
            text.push(Line::from("暂无可用的账号"));
        } else {
            for (i, account) in self.available_accounts.iter().enumerate() {
                let selected = self.selected_accounts.get(i).copied().unwrap_or(false);
                let style = if i == self.selected_option {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let marker = if selected { "[✓]" } else { "[ ]" };
                let cursor = if i == self.selected_option {
                    "▶ "
                } else {
                    "  "
                };

                text.push(Line::from(vec![
                    Span::raw(cursor),
                    Span::styled(format!("{} {}", marker, account), style),
                ]));
            }
        }

        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("↑/↓", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 移动  "),
            Span::styled("Space", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 选择/取消  "),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 完成  "),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" 返回"),
        ]));

        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
    }

    /// 绘制查看详情
    fn draw_view_detail(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" 密钥详情 ")
            .title_alignment(Alignment::Center);

        let text = if let Some(key) = self.selected_key() {
            let allowed_accounts_str = match &key.allowed_accounts {
                None => "全部账号".to_string(),
                Some(list) if list.is_empty() => "全部账号".to_string(),
                Some(list) => list.join(", "),
            };

            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "基本信息",
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Cyan),
                )]),
                Line::from(vec![Span::raw(format!("  ID:          {}", key.id))]),
                Line::from(vec![Span::raw(format!("  名称:        {}", key.name))]),
                Line::from(vec![Span::raw(format!("  密钥ID:      {}", key.key_id))]),
                Line::from(vec![Span::raw(format!(
                    "  权限:        {}",
                    key.permissions
                ))]),
                Line::from(vec![Span::raw(format!(
                    "  状态:        {}",
                    if key.is_active {
                        "✓ 正常"
                    } else {
                        "✗ 禁用"
                    }
                ))]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "时间信息",
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Cyan),
                )]),
                Line::from(vec![Span::raw(format!(
                    "  创建时间:    {}",
                    key.created_at
                ))]),
                Line::from(vec![Span::raw(format!(
                    "  过期时间:    {}",
                    key.expires_at.as_deref().unwrap_or("永不过期")
                ))]),
                Line::from(vec![Span::raw(format!(
                    "  最后使用:    {}",
                    key.last_used_at.as_deref().unwrap_or("从未使用")
                ))]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "访问限制",
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Cyan),
                )]),
                Line::from(vec![Span::raw(format!(
                    "  允许访问:    {}",
                    allowed_accounts_str
                ))]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" 返回  "),
                    Span::styled("d", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" 删除  "),
                    Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" 撤销"),
                ]),
            ]
        } else {
            vec![Line::from("未选择密钥")]
        };

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    /// 绘制状态栏
    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let (msg, style) = if let Some((msg, _)) = &self.status_message {
            (msg.clone(), Style::default().fg(Color::Yellow))
        } else {
            match self.mode {
                KeyManagerMode::List => (
                    "n:新建  Enter:详情  d:删除  r:撤销  q:退出".to_string(),
                    Style::default(),
                ),
                _ => (String::new(), Style::default()),
            }
        };

        let paragraph = Paragraph::new(Span::styled(msg, style))
            .block(Block::default().borders(Borders::TOP))
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    /// 绘制确认对话框
    fn draw_confirm_dialog(&self, frame: &mut Frame) {
        let area = Self::centered_rect(60, 20, frame.size());
        frame.render_widget(Clear, area);

        let (title, msg) = if let KeyManagerMode::Confirming(text, action) = &self.mode {
            match action {
                ConfirmAction::Delete(id) => ("确认删除", format!("{}\n\n密钥 ID: {}", text, id)),
                ConfirmAction::Revoke(id) => ("确认撤销", format!("{}\n\n密钥 ID: {}", text, id)),
            }
        } else {
            ("确认", String::new())
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_alignment(Alignment::Center)
            .style(Style::default().bg(Color::DarkGray));

        let text = Text::from(vec![
            Line::from(""),
            Line::from(msg).alignment(Alignment::Center),
            Line::from(""),
            Line::from(vec![
                Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" 确认  "),
                Span::styled("n/Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" 取消"),
            ])
            .alignment(Alignment::Center),
        ]);

        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
    }

    /// 绘制新密钥显示对话框
    fn draw_new_key_dialog(&self, frame: &mut Frame, key: &str) {
        let area = Self::centered_rect(70, 40, frame.size());
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" ⚠️  密钥生成成功（仅显示一次！） ")
            .title_alignment(Alignment::Center)
            .style(Style::default().bg(Color::DarkGray));

        let allowed_str = match &self.generate_config.allowed_accounts {
            list if list.is_empty() => "全部账号".to_string(),
            list => list.join(", "),
        };

        let text = Text::from(vec![
            Line::from(""),
            Line::from("请立即复制并保存以下密钥，关闭后将无法再次查看！")
                .alignment(Alignment::Center),
            Line::from(""),
            Line::from(Span::styled(
                key,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
            Line::from(""),
            Line::from("密钥配置:").alignment(Alignment::Center),
            Line::from(format!("  名称: {}", self.generate_config.name))
                .alignment(Alignment::Center),
            Line::from(format!("  权限: {}", self.generate_config.permissions))
                .alignment(Alignment::Center),
            Line::from(format!(
                "  过期: {}",
                match self.generate_config.expires_hours {
                    Some(h) => format!("{} 小时后", h),
                    None => "永不过期".to_string(),
                }
            ))
            .alignment(Alignment::Center),
            Line::from(format!("  允许访问: {}", allowed_str)).alignment(Alignment::Center),
            Line::from(""),
            Line::from(vec![
                Span::styled("Enter/Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" 我已保存"),
            ])
            .alignment(Alignment::Center),
        ]);

        let paragraph = Paragraph::new(text).block(block);
        frame.render_widget(paragraph, area);
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

    /// 处理键盘事件
    fn handle_key(&mut self, key: KeyCode) {
        // 如果显示新生成的密钥，按任意键关闭
        if self.generated_key.is_some() {
            self.generated_key = None;
            self.refresh_keys();
            return;
        }

        match self.mode {
            KeyManagerMode::List => self.handle_list_key(key),
            KeyManagerMode::GenerateName => self.handle_generate_name_key(key),
            KeyManagerMode::GenerateExpiry => self.handle_generate_expiry_key(key),
            KeyManagerMode::GeneratePermission => self.handle_generate_permission_key(key),
            KeyManagerMode::GenerateAccounts => self.handle_generate_accounts_key(key),
            KeyManagerMode::Confirming(_, _) => self.handle_confirm_key(key),
            KeyManagerMode::ViewDetail => self.handle_view_detail_key(key),
        }
    }

    /// 处理列表模式按键
    fn handle_list_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.running = false;
            }
            KeyCode::Char('n') => {
                self.mode = KeyManagerMode::GenerateName;
                self.new_key_input.clear();
                self.generate_config = GenerateConfig::default();
                // 加载可用账号列表
                self.load_available_accounts();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.keys.is_empty() {
                    let i = self.table_state.selected().unwrap_or(0);
                    let new_i = (i + 1).min(self.keys.len() - 1);
                    self.table_state.select(Some(new_i));
                    self.scroll_state = self.scroll_state.position(new_i);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.keys.is_empty() {
                    let i = self.table_state.selected().unwrap_or(0);
                    let new_i = i.saturating_sub(1);
                    self.table_state.select(Some(new_i));
                    self.scroll_state = self.scroll_state.position(new_i);
                }
            }
            KeyCode::Enter => {
                if self.selected_key().is_some() {
                    self.mode = KeyManagerMode::ViewDetail;
                }
            }
            KeyCode::Char('d') => {
                if let Some(key) = self.selected_key() {
                    self.mode = KeyManagerMode::Confirming(
                        "确定要删除此密钥吗？\n删除后将无法恢复。",
                        ConfirmAction::Delete(key.key_id.clone()),
                    );
                }
            }
            KeyCode::Char('r') => {
                if let Some(key) = self.selected_key() {
                    if key.is_active {
                        self.mode = KeyManagerMode::Confirming(
                            "确定要撤销此密钥吗？\n撤销后该密钥将失效。",
                            ConfirmAction::Revoke(key.key_id.clone()),
                        );
                    } else {
                        self.set_status("密钥已被撤销");
                    }
                }
            }
            _ => {}
        }
    }

    /// 处理生成密钥 - 输入名称
    fn handle_generate_name_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.mode = KeyManagerMode::List;
            }
            KeyCode::Enter => {
                if !self.new_key_input.trim().is_empty() {
                    self.generate_config.name = self.new_key_input.trim().to_string();
                    self.mode = KeyManagerMode::GenerateExpiry;
                    self.selected_option = 0;
                }
            }
            KeyCode::Backspace => {
                self.new_key_input.pop();
            }
            KeyCode::Char(c) => {
                self.new_key_input.push(c);
            }
            _ => {}
        }
    }

    /// 处理生成密钥 - 选择过期时间
    fn handle_generate_expiry_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.mode = KeyManagerMode::GenerateName;
            }
            KeyCode::Enter => {
                self.generate_config.expires_hours = EXPIRY_OPTIONS[self.selected_option].1;
                self.mode = KeyManagerMode::GeneratePermission;
                self.selected_option = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_option = self.selected_option.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_option = (self.selected_option + 1).min(EXPIRY_OPTIONS.len() - 1);
            }
            _ => {}
        }
    }

    /// 处理生成密钥 - 选择权限
    fn handle_generate_permission_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.mode = KeyManagerMode::GenerateExpiry;
            }
            KeyCode::Enter => {
                self.generate_config.permissions =
                    PERMISSION_OPTIONS[self.selected_option].1.to_string();
                self.mode = KeyManagerMode::GenerateAccounts;
                self.selected_option = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_option = self.selected_option.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_option = (self.selected_option + 1).min(PERMISSION_OPTIONS.len() - 1);
            }
            _ => {}
        }
    }

    /// 处理生成密钥 - 选择账号
    fn handle_generate_accounts_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.mode = KeyManagerMode::GeneratePermission;
            }
            KeyCode::Enter => {
                // 收集选中的账号
                let selected: Vec<String> = self
                    .available_accounts
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| self.selected_accounts.get(*i).copied().unwrap_or(false))
                    .map(|(_, name)| name.clone())
                    .collect();

                self.generate_config.allowed_accounts = selected;

                // 生成密钥
                match ApiKeyManager::generate(
                    &self.generate_config.name,
                    self.generate_config.expires_hours,
                    &self.generate_config.permissions,
                    if self.generate_config.allowed_accounts.is_empty() {
                        None
                    } else {
                        Some(self.generate_config.allowed_accounts.clone())
                    },
                ) {
                    Ok((raw_key, _)) => {
                        self.generated_key = Some(raw_key);
                        self.mode = KeyManagerMode::List;
                    }
                    Err(e) => {
                        self.set_status(&format!("生成失败: {}", e));
                        self.mode = KeyManagerMode::List;
                    }
                }
            }
            KeyCode::Char(' ') => {
                // 切换选中状态
                if let Some(selected) = self.selected_accounts.get_mut(self.selected_option) {
                    *selected = !*selected;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_option = self.selected_option.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_option =
                    (self.selected_option + 1).min(self.available_accounts.len().saturating_sub(1));
            }
            _ => {}
        }
    }

    /// 处理确认对话框按键
    fn handle_confirm_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let KeyManagerMode::Confirming(_, action) = &self.mode {
                    match action {
                        ConfirmAction::Delete(key_id) => {
                            if let Err(e) = ApiKeyManager::delete(key_id) {
                                self.set_status(&format!("删除失败: {}", e));
                            } else {
                                self.set_status("密钥已删除");
                                self.refresh_keys();
                            }
                        }
                        ConfirmAction::Revoke(key_id) => {
                            if let Err(e) = ApiKeyManager::revoke(key_id) {
                                self.set_status(&format!("撤销失败: {}", e));
                            } else {
                                self.set_status("密钥已撤销");
                                self.refresh_keys();
                            }
                        }
                    }
                }
                self.mode = KeyManagerMode::List;
            }
            _ => {
                self.mode = KeyManagerMode::List;
            }
        }
    }

    /// 处理查看详情按键
    fn handle_view_detail_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                self.mode = KeyManagerMode::List;
            }
            KeyCode::Char('d') => {
                if let Some(key) = self.selected_key() {
                    self.mode = KeyManagerMode::Confirming(
                        "确定要删除此密钥吗？",
                        ConfirmAction::Delete(key.key_id.clone()),
                    );
                }
            }
            KeyCode::Char('r') => {
                if let Some(key) = self.selected_key() {
                    if key.is_active {
                        self.mode = KeyManagerMode::Confirming(
                            "确定要撤销此密钥吗？",
                            ConfirmAction::Revoke(key.key_id.clone()),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    /// 获取当前选中的密钥
    fn selected_key(&self) -> Option<&ApiKeyInfo> {
        self.table_state.selected().and_then(|i| self.keys.get(i))
    }

    /// 设置状态消息
    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), Instant::now()));
    }

    /// 加载可用账号列表
    fn load_available_accounts(&mut self) {
        self.available_accounts = query_all_passwords()
            .map(|passwords| {
                passwords
                    .into_iter()
                    .map(|p| p.title.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        self.selected_accounts = vec![false; self.available_accounts.len()];
    }
}

/// 运行 API 密钥管理界面
pub fn run_api_key_manager() -> anyhow::Result<()> {
    // 初始化终端
    let mut terminal = init_terminal()?;

    let mut app = ApiKeyManagerApp::new();
    let result = app.run(&mut terminal);

    // 恢复终端
    let _ = restore_terminal();

    result?;
    Ok(())
}

/// 初始化终端
fn init_terminal() -> anyhow::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(crossterm::cursor::Hide)?;

    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;

    Ok(terminal)
}

/// 恢复终端
fn restore_terminal() -> anyhow::Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    io::stdout().execute(crossterm::cursor::Show)?;

    Ok(())
}
