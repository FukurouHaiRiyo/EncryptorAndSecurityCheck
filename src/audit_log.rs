use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use chrono::Utc;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use base64::engine::general_purpose;
use base64::Engine;
use rand::RngCore;

/// Name of the audit log file where encrypted logs are stored.
const LOG_FILE: &str = "audit_log.txt";


/// Secret key used for AES-256-GCM encryption.
/// ⚠️ This key should be stored securely and not hardcoded in production.
const SECRET_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

/// Size of the nonce for AES-GCM encryption (12 bytes).
const NONCE_SIZE: usize = 12;

/// Function to encrypt a log message
/// Encrypts a log message before writing it to the audit log.
/// 
/// # Arguments
/// * `message` - The log entry string to encrypt.
///
/// # Returns
/// * A base64-encoded encrypted string with a prepended nonce.
fn encrypt_log_entry(message: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SECRET_KEY);
    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message.as_bytes()).expect("Encryption failed");

    // Prepend the nonce to the ciphertext
    let encrypted_data = [nonce_bytes.to_vec(), ciphertext].concat();

    general_purpose::STANDARD.encode(encrypted_data)
}

/// Decrypts an encrypted log entry to retrieve the original message.
/// 
/// # Arguments
/// * `encrypted_message` - The base64-encoded encrypted log entry.
///
/// # Returns
/// * The decrypted log message as a `String`. If decryption fails, returns `"Decryption failed"`.
fn decrypt_log_entry(encrypted_message: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SECRET_KEY);
    let cipher = Aes256Gcm::new(key);

    let encrypted_data = general_purpose::STANDARD.decode(encrypted_message).expect("Base64 decoding failed");

    // Ensure the data is long enough to contain both nonce and ciphertext
    if encrypted_data.len() < NONCE_SIZE {
        return "Decryption failed: Invalid data format".to_string();
    }

    // Extract the nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => String::from_utf8(plaintext).expect("Invalid UTF-8 in decrypted text"),
        Err(_) => "Decryption failed".to_string(),
    }
}

/// Writes an encrypted log entry to the audit log file.
/// 
/// # Arguments
/// * `username` - The user performing the action.
/// * `action` - The type of action (e.g., "Encrypted" or "Decrypted").
/// * `filename` - The file being acted upon.
///
/// # Behavior
/// - Logs are stored **encrypted** for security.
/// - Entries are **appended** to the log file instead of overwriting it.
pub fn log_encryption_action(username: &str, action: &str, filename: &str) {
    let timestamp = Utc::now();
    let log_entry = format!("[{}] User: {} | Action: {} | File: {}", timestamp, username, action, filename);

    let encrypted_entry = encrypt_log_entry(&log_entry);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .expect("Failed to open log file");

    writeln!(file, "{}", encrypted_entry).expect("Failed to write log entry");
}

/// Reads and decrypts all log entries from the audit log file.
/// 
/// # Returns
/// * A `Vec<String>` containing decrypted log entries.
/// * If the log file doesn't exist, returns a message indicating no logs are found.
pub fn read_audit_log() -> Vec<String> {
    let mut file = match File::open(LOG_FILE) {
        Ok(file) => file,
        Err(_) => return vec!["No log file found".to_string()],
    };

    let mut content = String::new();
    file.read_to_string(&mut content).expect("Failed to read log file");

    content.lines().map(decrypt_log_entry).collect()
}
