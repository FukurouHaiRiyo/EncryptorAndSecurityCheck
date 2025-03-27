use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use chrono::Utc;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use base64::engine::general_purpose;
use base64::Engine;
use google_secretmanager1::{oauth2, SecretManager};
use hyper::Client;
use hyper_rustls::HttpsConnectorBuilder;
use rand::RngCore;

/// Name of the audit log file where encrypted logs are stored.
const LOG_FILE: &str = "audit_log.txt";

/// Size of the nonce for AES-GCM encryption (12 bytes).
const NONCE_SIZE: usize = 12;

// Fetch the secret key from Google Secret Manager
async fn get_secret(secret_name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let credentials_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")?;
    let credentials_content = std::fs::read_to_string(credentials_path)?;
    let service_account_key: oauth2::ServiceAccountKey = serde_json::from_str(&credentials_content)?;

    let auth = oauth2::ServiceAccountAuthenticator::builder(service_account_key)
        .build()
        .await?;

    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let hub = SecretManager::new(Client::builder().build(https), auth);

    let project_id = "filesecurity"; // Replace with your project ID
    let secret_path = format!("projects/{}/secrets/{}/versions/latest", project_id, secret_name);

    let response = hub.projects().secrets_versions_access(&secret_path).doit().await?;

    if let Some(payload) = response.1.payload {
        if let Some(data) = payload.data {
            let secret_value = String::from_utf8(data)?;
            let mut key_bytes = [0u8; 32];
            let secret_bytes = secret_value.as_bytes();

            key_bytes[..secret_bytes.len().min(32)].copy_from_slice(&secret_bytes[..secret_bytes.len().min(32)]);
            return Ok(key_bytes);
        }
    }

    Err("Failed to retrieve secret".into())
}

/// Encrypt a log entry.
/// Returns `Result<String, Box<dyn std::error::Error>>` instead of just `String`.
async fn encrypt_log_entry(message: &str) -> Result<String, Box<dyn std::error::Error>> {
    let secret_key = get_secret("my-secret-key").await?;
    println!("{:?}", secret_key);
    let key = Key::<Aes256Gcm>::from_slice(&secret_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message.as_bytes()).map_err(|_| "Encryption failed")?;

    let encrypted_data = [nonce_bytes.to_vec(), ciphertext].concat();
    Ok(general_purpose::STANDARD.encode(encrypted_data))
}

/// Decrypt an encrypted log entry.
async fn decrypt_log_entry(encrypted_message: &str) -> String {
    let secret_key = match get_secret("my-secret-key").await {
        Ok(key) => key,
        Err(_) => return "Decryption failed: Could not retrieve secret key".to_string(),
    };

    let key = Key::<Aes256Gcm>::from_slice(&secret_key);
    let cipher = Aes256Gcm::new(key);

    let encrypted_data = match general_purpose::STANDARD.decode(encrypted_message) {
        Ok(data) => data,
        Err(_) => return "Decryption failed: Base64 decoding error".to_string(),
    };

    if encrypted_data.len() < NONCE_SIZE {
        return "Decryption failed: Invalid data format".to_string();
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => String::from_utf8(plaintext).unwrap_or_else(|_| "Decryption failed: Invalid UTF-8".to_string()),
        Err(_) => "Decryption failed".to_string(),
    }
}

/// Writes an encrypted log entry to the audit log file.
pub async fn log_encryption_action(username: &str, action: &str, filename: &str) {
    let timestamp = Utc::now();
    let log_entry = format!("[{}] User: {} | Action: {} | File: {}", timestamp, username, action, filename);

    match encrypt_log_entry(&log_entry).await {
        Ok(encrypted_entry) => {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(LOG_FILE) {
                if let Err(e) = writeln!(file, "{}", encrypted_entry) {
                    eprintln!("❌ Failed to write log entry: {}", e);
                }
            } else {
                eprintln!("❌ Failed to open log file.");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to encrypt log entry: {:?}", e);
        }
    }
}

/// Reads and decrypts all log entries from the audit log file.
pub async fn read_audit_log() -> Vec<String> {
    let mut file = match File::open("audit_log.txt") {
        Ok(file) => file,
        Err(_) => return vec!["No log file found".to_string()],
    };

    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
        return vec!["Failed to read log file".to_string()];
    }

    let mut decrypted_logs = Vec::new();
    for line in content.lines() {
        decrypted_logs.push(decrypt_log_entry(line).await);
    }

    decrypted_logs
}
