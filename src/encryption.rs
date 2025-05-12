use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-256-GCM encryption
use aes_gcm::aead::{Aead, KeyInit}; // Required traits for encryption/decryption
use rand::{Rng, thread_rng}; // Random number generation
use std::fs; // File handling
use std::path::Path; // Path handling
use serde::{Serialize, Deserialize};
use tokio::runtime::Runtime;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, PasswordHasher as _, PasswordVerifier as _, Output};
use password_hash::rand_core::OsRng;

use crate::key_manager;
use crate::audit_log::log_encryption_action;

/// Struct for file metadata
#[derive(Serialize, Deserialize)]
struct FileMetadata {
    filename: String,
    size: u64,
}

// Password-based helper function
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>, String> {
    let argon2 = Argon2::default();
    let salt_string = SaltString::b64_encode(salt)
        .map_err(|e| format!("❌ Salt encoding failed: {}", e))?;
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| format!("❌ Password hashing failed: {}", e))?;

    let derived = password_hash.hash.ok_or("❌ Missing password hash output.")?;
    let key_bytes = derived.as_bytes();

    if key_bytes.len() < 32 {
        return Err("❌ Derived key too short.".to_string());
    }

    Ok(<Key<Aes256Gcm>>::from_slice(&key_bytes[..32]).clone())
}

/// Encrypts a file using AES-256-GCM encryption with a securely stored key.
///
/// Encrypted file format:
/// ```
/// [12 bytes nonce] + [Ciphertext + 16-byte authentication tag]
/// ```
///
/// # Arguments:
/// - `input_path` - Path to the file to be encrypted.
/// - `output_path` - Path where the encrypted file will be saved.
/// - `password` - password taken from user to generate the encryption key and encrypt the file
///
/// # Returns:
/// - `Ok(())` if encryption succeeds, otherwise `Err(String)`.
pub fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), String> {
    if !Path::new(input_path).exists() {
        return Err(format!("❌ Error: File '{}' not found.", input_path));
    }

    let salt: [u8; 16] = thread_rng().gen(); // 16-byte salt
    let key = derive_key_from_password(password, &salt)?;

    let cipher = Aes256Gcm::new(&key);
    let nonce: [u8; 12] = thread_rng().gen();

    let data = fs::read(input_path).map_err(|e| format!("❌ Error reading file: {}", e))?;
    let metadata = FileMetadata {
        filename: Path::new(input_path).file_name().unwrap().to_string_lossy().into_owned(),
        size: data.len() as u64,
    };

    let serialized_metadata = serde_json::to_vec(&metadata).map_err(|e| format!("❌ Metadata serialization error: {}", e))?;
    let encrypted_metadata = cipher.encrypt(Nonce::from_slice(&nonce), serialized_metadata.as_ref())
        .map_err(|e| format!("❌ Metadata encryption failed: {}", e))?;

    let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data.as_ref())
        .map_err(|e| format!("❌ File encryption failed: {}", e))?;

    let mut output = Vec::new();
    output.extend_from_slice(&salt);                           // 16 bytes
    output.extend_from_slice(&nonce);                          // 12 bytes
    output.extend_from_slice(&(encrypted_metadata.len() as u64).to_be_bytes()); // 8 bytes
    output.extend_from_slice(&encrypted_metadata);
    output.extend_from_slice(&encrypted_data);

    fs::write(output_path, output).map_err(|e| format!("❌ Error writing file: {}", e))?;

    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        log_encryption_action("User", "EncryptWithPassword", input_path);
    });

    Ok(())
}

/// Decrypts a file that was encrypted using AES-256-GCM.
///
/// Expected file format:
/// ```
/// [12 bytes nonce] + [Ciphertext + 16-byte authentication tag]
/// ```
///
/// # Arguments:
/// - `input_path` - Path to the encrypted file.
/// - `output_path` - Path where the decrypted file will be saved.
/// - `password` - password taken from user to decrypt the file
///
/// # Returns:
/// - `Ok(())` if decryption succeeds, otherwise `Err(String)`.
pub fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), String> {
    if !Path::new(input_path).exists() {
        return Err(format!("❌ Encrypted file '{}' not found.", input_path));
    }

    let encrypted_data = fs::read(input_path).map_err(|e| format!("❌ Error reading file: {}", e))?;

    if encrypted_data.len() < 16 + 12 + 8 {
        return Err("❌ Invalid encrypted file format.".to_string());
    }

    let salt = &encrypted_data[..16];
    let nonce = &encrypted_data[16..28];
    let metadata_len = u64::from_be_bytes(encrypted_data[28..36].try_into().unwrap()) as usize;

    if encrypted_data.len() < 36 + metadata_len {
        return Err("❌ Encrypted file format is incomplete.".to_string());
    }

    let encrypted_metadata = &encrypted_data[36..36 + metadata_len];
    let encrypted_file_data = &encrypted_data[36 + metadata_len..];

    let key = derive_key_from_password(password, salt)?;

    let cipher = Aes256Gcm::new(&key);

    let decrypted_metadata = cipher.decrypt(Nonce::from_slice(nonce), encrypted_metadata)
        .map_err(|_| "❌ Metadata decryption failed.".to_string())?;
    let _metadata: FileMetadata = serde_json::from_slice(&decrypted_metadata)
        .map_err(|_| "❌ Failed to deserialize metadata.".to_string())?;

    let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), encrypted_file_data)
        .map_err(|_| "❌ File decryption failed.".to_string())?;

    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("❌ Error writing decrypted file: {}", e))?;

    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        log_encryption_action("User", "DecryptWithPassword", input_path);
    });

    Ok(())
}


/// Loads the encryption key or generates a new one if it doesn't exist.
///
/// # Returns:
/// - `Ok(Key<Aes256Gcm>)` if the key is successfully loaded or generated.
/// - `Err(String)` if key storage fails.
fn load_or_generate_key() -> Result<Key<Aes256Gcm>, String> {
    let master_key = key_manager::load_or_generate_master_key();

    if let Some(stored_key) = key_manager::load_key(&master_key) {
        if stored_key.len() == 32 {
            return Ok(Key::<Aes256Gcm>::from_slice(&stored_key).clone());
        } else {
            return Err("❌ Invalid key size in storage!".to_string());
        }
    }

    // Generate new key if not found
    let new_key = key_manager::generate_random_key().to_vec();
    let metadata = key_manager::KeyMetadata::new(new_key.clone());
    key_manager::save_key(&metadata, &master_key)
        .map_err(|e| format!("❌ Error saving key: {}", e))?;

    // println!("🔑 New encryption key generated and stored securely."); 
    Ok(Key::<Aes256Gcm>::from_slice(&new_key).clone())
}
