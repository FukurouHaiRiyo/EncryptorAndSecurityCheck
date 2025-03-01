use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::fs;
use std::path::Path;
use std::io::{Read, Write};
use rand::RngCore;

const KEY_FILE: &str = "key_store.bin";

/// Generate a random encryption key
pub fn generate_key() -> Vec<u8> {
    let mut key = [0u8; 32]; // AES-256 requires a 32-byte key
    rand::thread_rng().fill_bytes(&mut key);
    key.to_vec()
}

/// Save the encryption key securely
pub fn save_key(encryption_key: &[u8]) -> std::io::Result<()> {
    fs::write(KEY_FILE, encryption_key)?;
    Ok(())
}

/// Load the encryption key from storage
pub fn load_key() -> Option<Vec<u8>> {
    if Path::new(KEY_FILE).exists() {
        let mut key_data = Vec::new();
        if let Ok(mut file) = fs::File::open(KEY_FILE) {
            file.read_to_end(&mut key_data).ok()?;
            return Some(key_data);
        }
    }
    None
}
