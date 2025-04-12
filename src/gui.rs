#[allow(unused_imports)]
use eframe::egui;
use eframe::egui::{CentralPanel, Context, TopBottomPanel, Ui, TextEdit}; 
use rfd::{FileDialog, MessageDialog, MessageDialogResult}; 

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::audit_log::read_audit_log;
use crate::hash_file::{compute_file_hash, validate_integrity};
use crate::encryption::{encrypt_file, decrypt_file}; 
use crate::pe_analyzer::{analyze_pe_file, PeInfo};

const OUTPUT_FOLDER: &str = "folder";


#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(PartialEq)]
enum Tab {
    Encryption,
    AuditLog,
    PeAnalyzer
    // OpenTerminal,
}

pub struct EncryptionApp {
    selected_file: Option<String>, 
    mode: Mode, 
    status_message: String, 
    active_tab: Tab, 
    audit_log_data: Arc<Mutex<Option<Vec<String>>>>,
    file_hash: String, 
    pe_file_path: Option<String>,
    pe_analysis_result: Option<PeInfo>,
    pe_analysis_error: Option<String>,
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            selected_file: None,
            mode: Mode::Encrypt,
            status_message: String::new(),
            active_tab: Tab::Encryption,
            audit_log_data: Arc::new(Mutex::new(None)),
            file_hash: String::new(),
            pe_file_path: None,
            pe_analysis_result: None,
            pe_analysis_error: None,
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("🔒 Encryption").clicked() {
                    self.active_tab = Tab::Encryption;
                }
                if ui.button("Audit Log").clicked() {
                    self.active_tab = Tab::AuditLog;
                    let ctx_clone = ctx.clone();
                    self.fetch_audit_log(ctx_clone);
                }
                if ui.button("🧠 PE Analyzer").clicked() {
                    self.active_tab = Tab::PeAnalyzer;
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Encryption => self.render_encryption_tab(ui),
                Tab::AuditLog => self.render_audit_log_tab(ui),
                Tab::PeAnalyzer => self.render_pe_analyzer_tab(ui),
                // Tab::OpenTerminal => self.open_terminal(),
            }
        });
    }
}

#[warn(unused_attributes)]
impl EncryptionApp {
    fn render_encryption_tab(&mut self, ui: &mut Ui) {
        ui.heading("🔒 File Encryption Tool");
        ui.label("📂 Drag and drop a file here or select one manually:");

        let dropped_files = ui.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped_files.first() {
            if let Some(path) = &file.path {
                self.selected_file = Some(path.display().to_string());
            }
        }

        if let Some(file) = &self.selected_file {
            ui.label(format!("📄 Selected file: {}", file));

            // Display File Hash
            let file_clone = file.clone();
            self.show_file_hash_ui(ui, &file_clone);
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
                if !Path::new(OUTPUT_FOLDER).exists() {
                    fs::create_dir_all(OUTPUT_FOLDER).expect("Failed to create output folder");
                }

                let filename = Path::new(file)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                let output_file = format!("{}/{}_enc", OUTPUT_FOLDER, filename);

                // Check if the encrypted file already exists 
                if Path::new(&output_file).exists() {
                    let overwrite = MessageDialog::new()
                        .set_title("Warning")
                        .set_description("The encrypted file already exists. Do you want to overwrite it?")
                        .set_buttons(rfd::MessageButtons::YesNo)
                        .show();

                    if overwrite != MessageDialogResult::Yes {
                        self.status_message = "⚠️ Encryption canceled by user.".to_string();
                        return;
                    }
                }

                let result = match self.mode {
                    Mode::Encrypt => encrypt_file(file, &output_file),
                    Mode::Decrypt => decrypt_file(file, &output_file),
                };

                self.status_message = match result {
                    Ok(_) => {
                        // Show Integrity Check for Decryption
                        if self.mode == Mode::Decrypt {
                            if self.show_integrity_check(ui, file, &output_file) {
                                format!("✅ File integrity check succesfull");
                            }
                        }
                        format!("✅ Success! File saved as: {}", output_file)
                    }
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

    fn show_integrity_check(&self, _ui: &mut egui::Ui, original: &str, decrypted: &str) -> bool {
        if validate_integrity(original, decrypted) {
            return true;
        }
        false
    }

    fn show_file_hash_ui(&mut self, ui: &mut egui::Ui, file_path: &str) {
        if let Ok(hash) = compute_file_hash(file_path) {
            self.file_hash = hash.clone();
            ui.label("🔍 File Hash:");
            ui.add(TextEdit::singleline(&mut self.file_hash).desired_width(400.0));
        } else {
            ui.label("⚠️ Error computing hash.");
        }
    }

    fn render_audit_log_tab(&mut self, ui: &mut Ui) {
        ui.heading("📜 Audit Log");

        let logs = self.audit_log_data.lock().unwrap();
        if let Some(logs) = &*logs {
            for log in logs {
                if log.starts_with("⚠️ Tampered Log") {
                    ui.colored_label(egui::Color32::RED, log);
                } else if log.starts_with("⚠️ Invalid log format") {
                    ui.colored_label(egui::Color32::YELLOW, log);
                } else {
                    ui.colored_label(egui::Color32::GREEN, log);
                }
            }
        } else {
            ui.label("⏳ Loading audit logs...");
        }
    }

    fn fetch_audit_log(&self, ctx: Context) {
        let logs = self.audit_log_data.clone();

        std::thread::spawn(move || {
            let fetched_logs = read_audit_log(); // Fetch logs

            let mut logs_guard = logs.lock().unwrap();
            *logs_guard = Some(fetched_logs);

            ctx.request_repaint(); // Force UI update
        });
    }

    fn render_pe_analyzer_tab(&mut self, ui: &mut Ui) {
        ui.heading("🧠 PE File Analyzer");
        
        if ui.button("📂 Select PE File").clicked() {
            if let Some(path) = FileDialog::new().add_filter("PE files", &["exe", "dll"]).pick_file(){
                let path_str = path.display().to_string();
                self.pe_file_path = Some(path_str.clone());

                match analyze_pe_file(&path_str) {
                    Ok(info) => {
                        self.pe_analysis_result = Some(info);
                        self.pe_analysis_error = None;
                    }
                    Err(e) => {
                        self.pe_analysis_result = None;
                        self.pe_analysis_error = Some(format!("❌ Error: {}", e));
                    }
                }
            }
        }

        if let Some(file) = &self.pe_file_path {
            ui.label(format!("📄 Selected file: {}", file));
        }

        if let Some(err) = &self.pe_analysis_error {
            ui.colored_label(egui::Color32::RED, format!("❌ Error: {}", err));
        }

        if let Some(info) = &self.pe_analysis_result {
            ui.separator();
            ui.label(format!("🔧 Machine: {}", info.machine));
            ui.label(format!("📄 Sections: {}", info.number_of_sections));
            ui.label(format!("⏰ Timestamp: {}", info.timestamp));
            ui.label(format!("🚀 Entry Point: 0x{:08X}", info.entry_point));
            ui.label(format!("🏗️  Image Base: 0x{:016X}", info.image_base));
            ui.label("📚 Section Names:");
            for section in &info.sections {
                ui.label(format!("  • {}", section));
            }
        }
    }
}

pub fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native("File Encryption Tool", options, Box::new(|_cc| Box::new(EncryptionApp::default())))
}
