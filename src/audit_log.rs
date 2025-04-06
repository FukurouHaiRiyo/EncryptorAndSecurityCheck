use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use chrono::Utc;
use sha2::{Sha256, Digest};

/// Name of the audit log file where logs are stored.
const LOG_FILE: &str = "audit_log.txt";

/// Ensures the audit log file exists before writing to it.
fn ensure_log_file_exists() {
    if !std::path::Path::new(LOG_FILE).exists() {
        if let Err(e) = File::create(LOG_FILE) {
            eprintln!("❌ Failed to create audit log file: {}", e);
        } else {
            // println!("📄 Audit log file created successfully."); 
        }
    }
}

/// Generates a SHA-256 hash of the given log entry.
fn hash_log_entry(log_entry: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(log_entry.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) // Convert hash to a hex string
}

/// Writes a hashed log entry to the audit log file.
pub fn log_encryption_action(username: &str, action: &str, filename: &str) {
    ensure_log_file_exists();

    let timestamp = Utc::now();
    let log_entry = format!("[{}] User: {} | Action: {} | File: {}", timestamp, username, action, filename);
    
    let hashed_entry = hash_log_entry(&log_entry);
    let final_entry = format!("{} | {}", hashed_entry, log_entry);

    // println!("🔏 Hashed log entry: {}", final_entry); 

    match OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", final_entry) {
                eprintln!("❌ Failed to write log entry: {}", e);
            } else {
                // println!("✅ Successfully wrote to audit log."); 
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to open log file for writing: {}", e);
        }
    }
}

/// Reads and verifies all log entries from the audit log file.
pub fn read_audit_log() -> Vec<String> {
    ensure_log_file_exists();

    let mut file = match File::open(LOG_FILE) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("❌ Failed to open audit log file: {}", e);
            return vec!["⚠️ No log file found".to_string()];
        }
    };

    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        eprintln!("❌ Failed to read audit log file: {}", e);
        return vec!["❌ Failed to read log file".to_string()];
    }

    // println!("📖 Raw log file content:\n{}", content); 

    let mut verified_logs = Vec::new();
    for line in content.lines() {
        if let Some((stored_hash, log_entry)) = line.split_once(" | ") {
            let recomputed_hash = hash_log_entry(log_entry);

            if stored_hash == recomputed_hash {
                // println!("✅ Log entry verified: {}", log_entry); 
                verified_logs.push(log_entry.to_string());
            } else {
                println!("⚠️ Tampered log entry detected: {}", log_entry);
                verified_logs.push(format!("⚠️ Tampered Log: {}", log_entry));
            }
        } else {
            // println!("⚠️ Invalid log format: {}", line); 
            verified_logs.push("⚠️ Invalid log format".to_string());
        }
    }

    verified_logs
}
