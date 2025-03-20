use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-256-GCM encryption
use aes_gcm::aead::{Aead, KeyInit}; // Required traits for encryption/decryption
use rand::Rng; // Random number generation
use std::fs; // File handling
use std::path::Path; // Path handling
use serde::{Serialize, Deserialize};

use crate::key_manager;
use crate::audit_log::log_encryption_action;

/// Struct for file metadata
#[derive(Serialize, Deserialize)]
struct FileMetadata {
    filename: String,
    size: u64,
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
///
/// # Returns:
/// - `Ok(())` if encryption succeeds, otherwise `Err(String)`.
pub fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), String> {
    // Ensure input file exists
    if !Path::new(input_path).exists() {
        return Err(format!("❌ Error: File '{}' not found.", input_path));
    }

    // Load or generate encryption key
    let key = load_or_generate_key()?;

    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new(&key);

    // Generate a 12-byte random nonce
    let nonce: [u8; 12] = rand::thread_rng().gen();

    // Read input file content
    let data = fs::read(input_path).map_err(|e| format!("❌ Error reading file: {}", e))?;
    let metadata = FileMetadata {
        filename: Path::new(input_path).file_name().unwrap().to_string_lossy().into_owned(),
        size: data.len() as u64,
    };

    // Serialize and encrypt metadata 
    let serialized_metadata = serde_json::to_vec(&metadata).map_err(|e| format!("❌ Metadata serialization error: {}", e))?;
    let encrypted_metadata = cipher.encrypt(Nonce::from_slice(&nonce), serialized_metadata.as_ref())
        .map_err(|e| format!("❌ Metadata encryption failed: {}", e))?;

    // Encrypt file data
    let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data.as_ref())
        .map_err(|e| format!("❌ File encryption failed: {}", e))?;

    // Output format: [nonce] + [metadata length] + [encrypted metadata] + [encrypted data]
    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&(encrypted_metadata.len() as u64).to_be_bytes()); // Metadata length
    output.extend_from_slice(&encrypted_metadata);
    output.extend_from_slice(&encrypted_data);

    // Write encrypted data to output file
    fs::write(output_path, output)
        .map_err(|e| format!("❌ Error writing encrypted file: {}", e))?;

    log_encryption_action("User", "Encrypt", input_path); // Log the encryption action
    println!("✅ Encryption successful! File saved as '{}'", output_path);
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
///
/// # Returns:
/// - `Ok(())` if decryption succeeds, otherwise `Err(String)`.
pub fn decrypt_file(input_path: &str, output_path: &str) -> Result<(), String> {
    if !Path::new(input_path).exists() {
        return Err(format!("❌ Error: Encrypted file '{}' not found.", input_path));
    }

    // Load encryption key
    let key = load_or_generate_key()?;

    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new(&key);

    // Read encrypted file content
    let encrypted_data = fs::read(input_path)
        .map_err(|e| format!("❌ Error reading encrypted file: {}", e))?;

    if encrypted_data.len() < 12 + 8 {
        return Err("❌ Invalid encrypted file format (too small)".to_string());
    }

    // Extract nonce, metadata length, encrypted metadata, and encrypted file data
    let nonce = &encrypted_data[..12];
    let metadata_len = u64::from_be_bytes(encrypted_data[12..20].try_into().unwrap()) as usize;

    if encrypted_data.len() < 20 + metadata_len {
        return Err("❌ Encrypted file format is incorrect.".to_string());
    }

    let encrypted_metadata = &encrypted_data[20..20 + metadata_len];
    let encrypted_file_data = &encrypted_data[20 + metadata_len..];

    // Decrypt metadata
    let decrypted_metadata = cipher.decrypt(Nonce::from_slice(nonce), encrypted_metadata)
        .map_err(|_| "❌ Metadata decryption failed.".to_string())?;
    let metadata: FileMetadata = serde_json::from_slice(&decrypted_metadata)
        .map_err(|_| "❌ Failed to deserialize metadata.".to_string())?;

    // Decrypt file data
    let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), encrypted_file_data)
        .map_err(|_| "❌ File decryption failed.".to_string())?;

    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("❌ Error writing decrypted file: {}", e))?;

    log_encryption_action("User", "Decrypt", input_path); // Log the decryption action
    println!(
        "✅ Decryption successful! Original filename: '{}', size: {} bytes. File saved as '{}'",
        metadata.filename, metadata.size, output_path
    );
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

    println!("🔑 New encryption key generated and stored securely.");
    Ok(Key::<Aes256Gcm>::from_slice(&new_key).clone())
}
