//! 标题和作者信息组件

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

/// 大标题组件 - JiDuoBao 艺术字
pub struct BigTitle;

impl Widget for BigTitle {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 9 {
            return;
        }

        // JiDuoBao ASCII 艺术字（使用原始字符串避免转义问题）
        let title: Vec<&str> = vec![
            r#""#,
            r#"    _ _ ____              ____              "#,
            r#"   (_|_)  _ \_   _  ___ | __ )  __ _  ___  "#,
            r#"   | | | | | | | | |/ _ \|  _ \ / _` |/ _ \ "#,
            r#"   | | | |_| | |_| | (_) | |_) | (_| | (_) |"#,
            r#"  _/ |_|____/ \__,_|\___/|____/ \__,_|\___/ "#,
            r#" |__/                                       "#,
            r#""#,
            r#"        记多宝 - 安全密码管理器        "#,
        ];

        let start_y = area.y;
        let start_x = area.x;

        for (y, line) in title.iter().enumerate() {
            let style = if y == 0 || y == 7 {
                Style::default()
            } else if y == 8 {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            };

            let pos_y = start_y + y as u16;
            if pos_y < area.y + area.height {
                buf.set_string(start_x, pos_y, *line, style);
            }
        }
    }
}

/// 作者信息组件
pub struct AuthorInfo<'a> {
    pub version: &'a str,
}

impl<'a> AuthorInfo<'a> {
    pub fn new(version: &'a str) -> Self {
        Self { version }
    }
}

impl<'a> Widget for AuthorInfo<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let info = [
            format!("版本: {}", self.version),
            "作者: 赵无为".to_string(),
            "邮箱: cherishtong@aliyun.com".to_string(),
            "QQ: 1427730623".to_string(),
        ];

        let start_y = area.y + (area.height.saturating_sub(info.len() as u16)) / 2;
        let start_x = area.x;

        for (y, line) in info.iter().enumerate() {
            let style = Style::default().fg(Color::Yellow);
            let pos_y = start_y + y as u16;
            if pos_y < area.y + area.height {
                buf.set_string(start_x, pos_y, line, style);
            }
        }
    }
}
