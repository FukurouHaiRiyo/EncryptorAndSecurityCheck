use eframe::egui::{self, CentralPanel, Context, TopBottomPanel, Ui}; // Importing egui UI elements
use rfd::FileDialog; // Importing FileDialog for file selection
use crate::encryption::{encrypt_file, decrypt_file}; // Import encryption functions
use crate::verification::ipqs::IPQS; // Import IPQS verification functions
use std::path::PathBuf; // Used for handling file paths

use dotenvy::dotenv;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use once_cell::sync::Lazy;

const OUTPUT_FOLDER: &str = "folder";

static API_KEY: Lazy<String> = Lazy::new(|| {
    dotenv().ok(); // Load environment variables from the .env file
    env::var("API_KEY").expect("API_KEY not found in .env file")
});

/// Enum representing the encryption mode (Encrypt or Decrypt)
#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

/// Enum for managing tabs
#[derive(PartialEq)]
enum Tab {
    Encryption,
    PhoneVerification,
    OpenTerminal,
}

/// Struct representing the GUI application state
pub struct EncryptionApp {
    selected_file: Option<String>, // Stores the selected file path
    mode: Mode, // Stores the selected encryption mode (Encrypt/Decrypt)
    status_message: String, // Stores the success or error message
    active_tab: Tab, // Stores the active tab (Encryption/PhoneVerification)
    phone_number: String, // Input field for phone number verification
    verification_result: String // stores the phone verification result
}

/// Default implementation to initialize the app with default values
impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            selected_file: None,
            mode: Mode::Encrypt,
            status_message: String::new(),
            active_tab: Tab::Encryption,
            phone_number: String::new(),
            verification_result: String::new(),
        }
    }
}

/// Implementation of the graphical interface logic using egui
impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame){
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Tab Buttons
                if ui.button("🔒 Encryption").clicked() {
                    self.active_tab = Tab::Encryption;
                }

                if ui.button("📞 Phone Verification").clicked() {
                    self.active_tab = Tab::PhoneVerification;
                }

                if ui.button("Open terminal").clicked() {
                    self.active_tab = Tab::OpenTerminal;
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Encryption => self.render_encryption_tab(ui),
                Tab::PhoneVerification => self.render_phone_number_verification_tab(ui),
                Tab::OpenTerminal => self.open_terminal(),
            }
        });
    }
}

/// Implementation of the Encryption tab
impl EncryptionApp {
    fn render_encryption_tab(&mut self, ui: &mut Ui) {
        ui.heading("🔒 File Encryption Tool");
        ui.label("📂 Drag and drop a file here or select one manually:");

        let dropped_files = ui.input(|i|i.raw.dropped_files.clone());
        if let Some(file) = dropped_files.first() {
            if let Some(path) = &file.path {
                self.selected_file = Some(path.display().to_string());
            }
        }

        if let Some(file) = &self.selected_file {
            ui.label(format!("📄 Selected file: {}", file));
        }

        if ui.button("📂 Select File").clicked() {
            if let Some(path) = FileDialog::new().pick_file() {
                self.selected_file = Some(path.display().to_string());
            }
        }

        ui.horizontal(|ui| {
            ui.label("🔀 Choose mode:");
            ui.radio_value(&mut self.mode, Mode::Encrypt, "Encrypt");
            ui.radio_value(&mut self.mode, Mode::Decrypt, "Decrypt");
        });

        if ui.button("🔄 Start").clicked() {
            if let Some(file) = &self.selected_file {
                // Ensure the output folder exists
                if !Path::new(OUTPUT_FOLDER).exists() {
                    fs::create_dir_all(OUTPUT_FOLDER).expect("Failed to create output folder");
                }

                // Extract filename from path and append "_enc"
                let filename = Path::new(file)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

                let output_file = format!("{}/{}_enc", OUTPUT_FOLDER, filename);

                let result = match self.mode {
                    Mode::Encrypt => encrypt_file(file, &output_file),
                    Mode::Decrypt => decrypt_file(file, &output_file),
                };

                self.status_message = match result {
                    Ok(_) => format!("✅ Success! File saved as: {}", output_file),
                    Err(e) => format!("❌ Error: {}", e),
                };
            } else {
                self.status_message = "⚠️ Please select a file.".to_string();
            }
        }

        if !self.status_message.is_empty() {
            ui.label(&self.status_message);
        }
    }

    /// Implementation for Phone Verification tab
    fn render_phone_number_verification_tab(&mut self, ui: &mut Ui) {
        ui.heading("📞 Phone Number Verification");

        ui.label("Enter phone number:");
        ui.text_edit_singleline(&mut self.phone_number);

        if ui.button("🔍 Verify").clicked() {
            if !self.phone_number.is_empty() {
                let ipqs = IPQS::new(&API_KEY);
                let additional_params = vec![("country", "US"), ("country", "CA")];
                match ipqs.phone_number_api(&self.phone_number, &additional_params) {
                    Ok(result) => {
                        self.verification_result = format!("{:?}", result);
                    }
                    Err(e) => {
                        self.verification_result = format!("❌ Error: {}", e);
                    }
                }
            } else {
                self.verification_result = "⚠️ Please enter a phone number.".to_string();
            }
        }

        if !self.verification_result.is_empty() {
            ui.label(&self.verification_result);
        }

    }

    /// Implementation to open the terminal instead 
    fn open_terminal(&mut self) {
        // Get the current working directory 
        let current_dir = env::current_dir().expect("Failed to get current directory");

        // Match the operating system 
        if cfg!(target_os = "windows") {
            // on Windows, open the PowerShell or cmd
            if Command::new("powershell")
                .arg("-NoExit")
                .arg("-Command")
                .arg(format!("cd {}", current_dir.display()))
                .spawn()
                .is_err()
            {
                // Fallback to cmd.exe if PowerShell isn't available
                Command::new("cmd")
                    .arg("/K")
                    .arg(format!("cd {}", current_dir.display()))
                    .spawn()
                    .expect("Failed to open Command Prompt");
            }
        } else if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
            // On macOS or Linux, open the default terminal
            if Command::new("X-terminal-emulator")
                .arg(format!("--working-directory={}", current_dir.display()))
                .spawn()
                .is_err()
            {
                // Fallbacks for different desktop environments
                if Command::new("gnome-terminal")
                    .arg(format!("--working-directory={}", current_dir.display()))
                    .spawn()
                    .is_err()
                {
                    Command::new("konsole")
                        .arg(format!("--workdir={}", current_dir.display()))
                        .spawn()
                        .expect("Failed to open terminal");
                }
            }
        } else {
            println!("❌ Unsupported operating system");
        }
    }
}

/// Runs the GUI application
pub fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default(); // Default settings for the GUI
    eframe::run_native("File Encryption Tool", options, Box::new(|_cc| Box::new(EncryptionApp::default())))
}