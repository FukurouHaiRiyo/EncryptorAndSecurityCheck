mod encryption;
mod gui;
mod key_manager; 
mod audit_log;
mod hash_file;
mod pe_analyzer;
mod auth;
mod firebase_storage;

#[warn(unused_must_use)]
fn main() {
    let _ = gui::run_gui();
}