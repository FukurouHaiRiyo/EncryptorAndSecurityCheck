use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize}; // Import serde traits

const FOLDER: &str = "folder";
const KEY_FILE: &str = "folder/key_store.bin";

/// Constants for key rotation
const KEY_ROTATION_PERIOD: u64 = 60 * 60 * 24 * 30; // 30 days in seconds
const MAX_KEY_USES: u64 = 1000;

/// Struct to store key metadata (timestamp and usage count)
#[derive(Serialize, Deserialize, Debug)] // Add derive attributes
pub struct KeyMetadata {
    timestamp: u64,
    usage_count: u64,
    key: Vec<u8>,
}

impl KeyMetadata {
    pub fn new(key: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        KeyMetadata {
            timestamp,
            usage_count: 0,
            key,
        }
    }

    fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        current_time - self.timestamp >= KEY_ROTATION_PERIOD
    }

    fn needs_rotation(&self) -> bool {
        self.usage_count >= MAX_KEY_USES
    }

    fn increment_usage(&mut self) {
        self.usage_count += 1;
    }
}

/// Generate a random encryption key
pub fn generate_key() -> Vec<u8> {
    let mut key = [0u8; 32]; // AES-256 requires a 32-byte key
    rand::thread_rng().fill_bytes(&mut key);
    key.to_vec()
}

/// Save the encryption key securely with its metadata
pub fn save_key(metadata: &KeyMetadata) -> std::io::Result<()> {
    fs::create_dir_all(FOLDER)?;

    let mut file = File::create(KEY_FILE)?;
    let serialized_metadata = serde_json::to_vec(metadata).unwrap();

    file.write_all(&serialized_metadata)?;
    Ok(())
}

/// Load the encryption key and its metadata from storage
pub fn load_key() -> Option<Vec<u8>> {
    if Path::new(KEY_FILE).exists() {
        let mut key_data = Vec::new();
        if let Ok(mut file) = fs::File::open(KEY_FILE) {
            file.read_to_end(&mut key_data).ok()?;
            let mut metadata: KeyMetadata = serde_json::from_slice(&key_data).unwrap();

            // Check if the key needs to be rotated (expired or too many uses)
            if metadata.is_expired() || metadata.needs_rotation() {
                println!("Key has expired or exceeded usage limit. Rotating key.");
                return None;
            }

            // Increment the usage count of the current key
            metadata.increment_usage();

            // Save the updated metadata, preserving the incremented usage count
            if let Err(e) = save_key(&metadata) {
                eprintln!("Error saving updated key: {}", e);
            }

            return Some(metadata.key);
        }
    }
    None
}