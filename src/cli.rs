use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
    text::{Span, Line, Text},
};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use std::{
    io::{self, BufRead},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod encryption;
mod audit_log;
mod key_manager;
use crate::encryption::{encrypt_file, decrypt_file};

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut user_input = String::new();
    let mut command_output: Vec<String> = vec!["Type a command and press Enter.".to_string()];

    let mut last_key: Option<KeyCode> = None;
    let mut last_time = Instant::now();

    loop {
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(80), Constraint::Percentage(20)])
                .split(size);

            let output_text: Text = command_output
                .iter()
                .map(|line| Line::from(Span::raw(line.clone())))
                .collect();

            let output_box = Paragraph::new(output_text)
                .block(Block::default().title(" Output ").borders(Borders::ALL))
                .wrap(Wrap { trim: true });

            let input_box = Paragraph::new(Span::raw(format!("> {}", user_input)))
                .block(Block::default().title(" Enter Command ").borders(Borders::ALL));

            f.render_widget(output_box, chunks[0]);
            f.render_widget(input_box, chunks[1]);
        })?;

        // Poll for events with timeout
        if event::poll(Duration::from_millis(100))? {
            let evt = event::read()?;

            

            if let Event::Key(key) = evt {
                let now = Instant::now();

                // Debounce repeated key events
                if Some(key.code) == last_key && now.duration_since(last_time).as_millis() < 100 {
                    continue;
                }

                last_key = Some(key.code);
                last_time = now;

                match key.code {
                    KeyCode::Enter => {
                        if !user_input.is_empty() {
                            let output = execute_command(&user_input);
                            command_output.push(format!("> {}", user_input));
                            command_output.extend(output);
                            user_input.clear();
                        }
                    }
                    KeyCode::Esc => break,
                    KeyCode::Backspace => {
                        user_input.pop();
                    }
                    KeyCode::Char(c) => {
                        user_input.push(c);
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn execute_command(command: &str) -> Vec<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return vec!["⚠️ Invalid command!".to_string()];
    }

    match parts[0] {
        "encrypt" => {
            let mut input_file = "";
            let mut output_file = "";
            let mut i = 1;
            while i < parts.len() {
                match parts[i] {
                    "-i" if i + 1 < parts.len() => {
                        input_file = parts[i + 1];
                        i += 1;
                    }
                    "-o" if i + 1 < parts.len() => {
                        output_file = parts[i + 1];
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }

            if input_file.is_empty() || output_file.is_empty() {
                return vec!["❌ Usage: encrypt -i input.txt -o encrypted.bin".to_string()];
            }

            
            encrypt_file(input_file, &output_file);
            return vec![format!("🔒 Encrypted '{}' to '{}'", input_file, output_file)];
        }

        "decrypt" => {
            let mut input_file = "";
            let mut output_file = "";
            let mut i = 1;
            while i < parts.len() {
                match parts[i] {
                    "-i" if i + 1 < parts.len() => {
                        input_file = parts[i + 1];
                        i += 1;
                    }
                    "-o" if i + 1 < parts.len() => {
                        output_file = parts[i + 1];
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }

            if input_file.is_empty() || output_file.is_empty() {
                return vec!["❌ Usage: decrypt -i encrypted.bin -o output.txt".to_string()];
            }

            // TODO: Call your decryption function here
            return vec![format!("🔓 Decrypted '{}' to '{}'", input_file, output_file)];
        }

        "audit" if parts.get(1) == Some(&"log") => {
            // TODO: Show audit log
            return vec!["📜 Audit log shown here (not implemented yet)".to_string()];
        }

        "open_gui" => {
            // TODO: You could spawn the GUI binary here
            match Command::new("cargo")
                .arg("run")
                .arg("--bin")
                .arg("FileEncryption")
                .spawn()
            {
                Ok(_) => return vec!["🚀 Launching GUI...".to_string()],
                Err(e) => return vec![format!("❌ Failed to open GUI: {}", e)],
            }
        }

        _ => {
            // Fallback to system command
            let mut cmd = Command::new(parts[0]);
            cmd.args(&parts[1..]);
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            match cmd.spawn() {
                Ok(mut child) => {
                    let stdout = child.stdout.take().unwrap();
                    let reader = io::BufReader::new(stdout);
                    let output: Vec<String> = reader.lines().filter_map(Result::ok).collect();
                    output
                }
                Err(_) => vec!["❌ Failed to execute command!".to_string()],
            }
        }
    }
}
