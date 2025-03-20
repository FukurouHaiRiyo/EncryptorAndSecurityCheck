use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize}; 

const FOLDER: &str = "folder";
const KEY_FILE: &str = "folder/aes_store.enc";
const MASTER_KEY_STORE: &str = "folder/aes_store1.bin";
const NONCE_SIZE: usize = 12;

/// Constants for key rotation
const KEY_ROTATION_PERIOD: u64 = 60 * 60 * 24 * 30; // 30 days in seconds
const MAX_KEY_USES: u64 = 1000;

#[derive(Serialize, Deserialize, Debug)]
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

/// Generate a random 32-byte key
pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Save the master key securely
pub fn save_master_key(key: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(FOLDER)?;
    let mut file = File::create(MASTER_KEY_STORE)?;
    file.write_all(key)?;
    Ok(())
}

/// Load the master key from storage, generating it if it doesn't exist
pub fn load_or_generate_master_key() -> [u8; 32] {
    if Path::new(MASTER_KEY_STORE).exists() {
        let mut key = [0u8; 32];
        File::open(MASTER_KEY_STORE)
            .expect("Failed to open master key file")
            .read_exact(&mut key)
            .expect("Failed to read master key");
        key
    } else {
        let key = generate_random_key();
        save_master_key(&key).expect("Failed to save master key");
        key
    }
}

/// Encrypt data with AES-256-GCM
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data).expect("encryption failure");
    
    [nonce.to_vec(), ciphertext].concat()
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let (nonce, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).expect("decryption failure")
}

/// Save the encryption key securely, encrypting it with the master key
pub fn save_key(metadata: &KeyMetadata, master_key: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(FOLDER)?;

    let serialized_metadata = serde_json::to_vec(metadata).unwrap();
    let encrypted_metadata = encrypt(&serialized_metadata, master_key);

    let mut file = File::create(KEY_FILE)?;
    file.write_all(&encrypted_metadata)?;
    Ok(())
}

/// Load the encryption key and its metadata, decrypting with the master key
pub fn load_key(master_key: &[u8]) -> Option<Vec<u8>> {
    if Path::new(KEY_FILE).exists() {
        let mut encrypted_data = Vec::new();
        if let Ok(mut file) = fs::File::open(KEY_FILE) {
            file.read_to_end(&mut encrypted_data).ok()?;

            let decrypted_data = decrypt(&encrypted_data, master_key);
            let mut metadata: KeyMetadata = serde_json::from_slice(&decrypted_data).unwrap();

            // Check if the key needs to be rotated (expired or too many uses)
            if metadata.is_expired() || metadata.needs_rotation() {
                println!("Key has expired or exceeded usage limit. Rotating key.");
                return None;
            }

            // Increment the usage count of the current key
            metadata.increment_usage();

            // Save the updated metadata, preserving the incremented usage count
            if let Err(e) = save_key(&metadata, master_key) {
                eprintln!("Error saving updated key: {}", e);
            }

            return Some(metadata.key);
        }
    }
    None
}