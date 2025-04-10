use std::io;
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use ratatui::prelude::*;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

mod ui; // UI drawing mode 
mod network; // Network interface module

fn main() -> Result<(), io::Error> {
    // Enable raw mode for terminal input handling
    enable_raw_mode()?;

    let mut stdout = io::stdout(); // Standard output stream
    let mut backend = CrosstermBackend::new(stdout); // Backend for terminal
    let mut terminal = Terminal::new(backend)?; // Terminal instance

    // Clear the terminal screen initially 
    terminal.clear()?;

    loop {
        // Redraw the terminal UI
        terminal.draw(|f| {
            ui::draw_ui(f); // Call the UI drawing function
        })?;

        // Currently just updates every second; will add user input later
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}