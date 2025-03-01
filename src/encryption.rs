use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-256-GCM encryption
use aes_gcm::aead::{Aead, KeyInit}; // Required traits for encryption/decryption
use rand::Rng; // Random number generation
use std::fs; // File handling
use std::path::Path; // Path handling
use crate::key_manager;

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

    // Encrypt file data
    let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data.as_ref())
        .map_err(|e| format!("❌ Encryption failed: {}", e))?;

    // Output format: [nonce] + [ciphertext + auth tag]
    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted_data);

    // Write encrypted data to output file
    fs::write(output_path, output)
        .map_err(|e| format!("❌ Error writing encrypted file: {}", e))?;

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
    // Ensure encrypted file exists
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

    // Ensure valid file structure (at least 12 bytes for nonce)
    if encrypted_data.len() < 12 {
        return Err("❌ Invalid encrypted file format (too small)".to_string());
    }

    // Extract nonce (12 bytes) and encrypted data
    let nonce = &encrypted_data[..12];
    let data = &encrypted_data[12..];

    // Decrypt data
    let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), data)
        .map_err(|_| "❌ Decryption failed: Authentication tag mismatch (file may be tampered)".to_string())?;

    // Write decrypted data to output file
    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("❌ Error writing decrypted file: {}", e))?;

    println!("✅ Decryption successful! File saved as '{}'", output_path);
    Ok(())
}

/// Loads the encryption key or generates a new one if it doesn't exist.
///
/// # Returns:
/// - `Ok(Key<Aes256Gcm>)` if the key is successfully loaded or generated.
/// - `Err(String)` if key storage fails.
fn load_or_generate_key() -> Result<Key<Aes256Gcm>, String> {
    if let Some(stored_key) = key_manager::load_key() {
        if stored_key.len() == 32 {
            return Ok(Key::<Aes256Gcm>::from_slice(&stored_key).clone());
        } else {
            return Err("❌ Invalid key size in storage!".to_string());
        }
    }

    // Generate new key
    let new_key = key_manager::generate_key();
    key_manager::save_key(&new_key).map_err(|e| format!("❌ Error saving key: {}", e))?;

    println!("🔑 New encryption key generated and stored securely.");
    Ok(Key::<Aes256Gcm>::from_slice(&new_key).clone())
}