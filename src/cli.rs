use std::io;
use std::process::{Command, Stdio};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{enable_raw_mode, disable_raw_mode},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Position},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, List, ListItem, Paragraph},
    Terminal,
};
use chrono::Utc;


mod encryption;
mod audit_log;
mod key_manager;
use crate::encryption::{encrypt_file, decrypt_file};
use crate::audit_log::log_encryption_action;

fn main() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    App::new().run(terminal)?;
    disable_raw_mode()?;
    Ok(())
}

enum InputMode {
    Normal,
    Editing,
}

struct App {
    input: String,
    character_index: usize,
    input_mode: InputMode,
    messages: Vec<String>,
}

impl App {
    fn new() -> Self {
        Self {
            input: String::new(),
            character_index: 0,
            input_mode: InputMode::Editing,
            messages: vec!["Welcome to FileEncrypt CLI 🛡️".to_string()],
        }
    }

    fn run(&mut self, mut terminal: Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| self.draw(f))?;

            if let Event::Key(key) = event::read()? {
                match self.input_mode {
                    InputMode::Editing if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char(c) => self.enter_char(c),
                        KeyCode::Backspace => self.delete_char(),
                        KeyCode::Left => self.move_cursor_left(),
                        KeyCode::Right => self.move_cursor_right(),
                        KeyCode::Enter => self.submit_command(),
                        KeyCode::Esc => self.input_mode = InputMode::Normal,
                        KeyCode::Char('q') => return Ok(()),
                        _ => {}
                    },
                    InputMode::Normal => match key.code {
                        KeyCode::Char('e') => self.input_mode = InputMode::Editing,
                        KeyCode::Char('q') => return Ok(()),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    fn draw(&self, frame: &mut ratatui::Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(frame.size());

        let (msg, style) = match self.input_mode {
            InputMode::Normal => (
                vec![
                    "Press ".into(),
                    "e".bold(),
                    " to edit, ".into(),
                    "q".bold(),
                    " to quit.".into(),
                ],
                Style::default(),
            ),
            InputMode::Editing => (
                vec![
                    "Press ".into(),
                    "Enter".bold(),
                    " to run, ".into(),
                    "Esc".bold(),
                    " to stop editing.".into(),
                ],
                Style::default(),
            ),
        };
        let help = Paragraph::new(Text::from(Line::from(msg)).patch_style(style));
        frame.render_widget(help, chunks[0]);

        let input = Paragraph::new(self.input.as_str())
            .style(match self.input_mode {
                InputMode::Editing => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            })
            .block(Block::bordered().title("Enter Command"));
        frame.render_widget(input, chunks[1]);

        if let InputMode::Editing = self.input_mode {
            frame.set_cursor(
                chunks[1].x + self.character_index as u16 + 1,
                chunks[1].y + 1,
            );
        }

        let messages: Vec<ListItem> = self
            .messages
            .iter()
            .map(|m| ListItem::new(Line::from(Span::raw(m))))
            .collect();

        let list = List::new(messages)
            .block(Block::bordered().title("Output"))
            .highlight_style(Style::default().fg(Color::LightGreen));
        frame.render_widget(list, chunks[2]);
    }

    fn move_cursor_left(&mut self) {
        self.character_index = self.character_index.saturating_sub(1);
    }

    fn move_cursor_right(&mut self) {
        self.character_index = (self.character_index + 1).min(self.input.chars().count());
    }

    fn enter_char(&mut self, c: char) {
        let idx = self.byte_index();
        self.input.insert(idx, c);
        self.move_cursor_right();
    }

    fn delete_char(&mut self) {
        if self.character_index == 0 {
            return;
        }
        let idx = self.byte_index();
        let prev = self.input[..idx].chars().rev().next().unwrap().len_utf8();
        self.input.replace_range(idx - prev..idx, "");
        self.move_cursor_left();
    }

    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or_else(|| self.input.len())
    }

    fn submit_command(&mut self) {
        let command = self.input.trim().to_string();
        if command.is_empty() {
            return;
        }

        self.messages.push(format!("> {}", command));
        let result = self.handle_command(&command);
        self.messages.extend(result);

        self.input.clear();
        self.character_index = 0;
    }

    fn handle_command(&self, command: &str) -> Vec<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return vec!["⚠️ Invalid command".to_string()];
        }

        match parts[0] {
            "encrypt" => {
                let input_file = parts.iter().position(|&s| s == "-i").and_then(|i| parts.get(i + 1)).unwrap_or(&"");
                let output_file = parts.iter().position(|&s| s == "-o").and_then(|i| parts.get(i + 1)).unwrap_or(&"");

                if input_file.is_empty() || output_file.is_empty() {
                    return vec!["❌ Usage: encrypt -i input.txt -o encrypted.bin".to_string()];
                }

                // encrypt the file and log the action
                if let Err(e) = encrypt_file(input_file, output_file) {
                    return vec![format!("❌ Encryption failed: {}", e)];
                }
                log_encryption_action("user", "encrypt", input_file);
                vec![
                    format!("🔒 Encrypted '{}' to '{}'", input_file, output_file),
                    "📜 Hashed log entry:".into(),
                    format!("  • File: {}", input_file),
                    format!("  • Output: {}", output_file),
                    format!("  • Time: {}", Utc::now().to_rfc3339()),
                ]
            }

            "decrypt" => {
                let input_file = parts.iter().position(|&s| s == "-i").and_then(|i| parts.get(i + 1)).unwrap_or(&"");
                let output_file = parts.iter().position(|&s| s == "-o").and_then(|i| parts.get(i + 1)).unwrap_or(&"");

                if input_file.is_empty() || output_file.is_empty() {
                    return vec!["❌ Usage: decrypt -i encrypted.bin -o output.txt".to_string()];
                }

                // decrypt the file and log the action
                if let Err(e) = decrypt_file(input_file, output_file) {
                    return vec![format!("❌ Decryption failed: {}", e)];
                }
                log_encryption_action("user", "decrypt", input_file);
                vec![
                    format!("🔓 Decrypted '{}' to '{}'", input_file, output_file),
                    "📜 Hashed log entry:".into(),
                    format!("  • File: {}", input_file),
                    format!("  • Output: {}", output_file),
                    format!("  • Time: {}", Utc::now().to_rfc3339()),
                ]
            }

            "open_gui" => {
                match Command::new(if cfg!(windows) {
                    "FileEncryption.exe"
                } else {
                    "FileEncryption"
                }).spawn()
                {
                    Ok(_) => vec!["🚀 Launching GUI...".into()],
                    Err(e) => vec![format!("❌ Failed to launch GUI: {}", e)],
                }
            }

            _ => {
                let output = Command::new(parts[0])
                    .args(&parts[1..])
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        if stdout.is_empty() {
                            vec!["(no output)".to_string()]
                        } else {
                            stdout.lines().map(|l| l.to_string()).collect()
                        }
                    }
                    Err(_) => vec!["❌ Failed to execute command".to_string()],
                }
            }
        }
    }
}
