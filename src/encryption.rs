use aes_gcm::{Aes256Gcm, Key, NewAead, Nonce, aead::Aead}; 
use argon2::{self, Argon2};
use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};

/// Encrypt a file
pub fn encrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read input file
    let mut file = File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Derive key from password
    let key = derive_key(password);

    // Generate a random nonce
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill(&mut nonce);

    // Encrypt data
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), buffer.as_ref())
        .map_err(|_| "Encryption failed")?;

    // Write nonce and ciphertext to output file
    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypt a file
pub fn decrypt_file(input_file: &str, output_dir: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read input file
    let mut file = File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Derive key from password
    let key = derive_key(password);

    // Extract nonce and ciphertext
    let (nonce, ciphertext) = buffer.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    // Decrypt data
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed")?;

    // Write plaintext to output file
    let output_file = format!("{}/{}", output_dir, "decrypted_file"); // Adjust as needed
    let mut output = File::create(output_file)?;
    output.write_all(&plaintext)?;

    Ok(())
}

/// Derive a key from a password using Argon2
fn derive_key(password: &str) -> [u8; 32] {
    let salt = b"some_random_salt"; // Use a secure random salt in practice
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}
