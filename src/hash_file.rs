use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{self, Read};

/// Computes the SHA-256 hash of a file
pub fn compute_file_hash(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    while let Ok(bytes_read) = file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Validates file integrity by comparing original and decrypted file hashes
pub fn validate_integrity(original_file: &str, decrypt_file: &str) -> bool {
    match (compute_file_hash(original_file), compute_file_hash(decrypt_file)) {
        (Ok(original_hash), Ok(decrypt_hash)) => original_hash == decrypt_hash,
        _ => false,
    }
}