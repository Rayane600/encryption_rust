use aes_gcm::{Aes256Gcm, Key, NewAead, Nonce, aead::Aead}; 
use argon2::{self, Argon2};
use rand::{Rng, thread_rng};
use std::fs::File;
use std::io::{Read, Write};

const SALT_SIZE: usize = 16; // Size of the salt

/// Encrypt a file
pub fn encrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read input file
    let mut file = File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Generate a random salt
    let mut salt = [0u8; SALT_SIZE];
    thread_rng().fill(&mut salt);

    // Derive key from password and salt
    let key = derive_key(password, &salt);

    // Generate a random nonce
    let mut nonce = [0u8; 12];
    thread_rng().fill(&mut nonce);

    // Encrypt data
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), buffer.as_ref())
        .map_err(|_| "Encryption failed")?;

    // Write salt, nonce, and ciphertext to output file
    let mut output = File::create(output_file)?;
    output.write_all(&salt)?; // Store salt at the beginning
    output.write_all(&nonce)?; // Store nonce after salt
    output.write_all(&ciphertext)?; // Store encrypted data

    Ok(())
}

/// Decrypt a file
pub fn decrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read input file
    let mut file = File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Ensure the buffer has at least salt + nonce size
    if buffer.len() < SALT_SIZE + 12 {
        return Err("File is too small to contain valid encrypted data".into());
    }

    // Extract salt, nonce, and ciphertext
    let (salt, rest) = buffer.split_at(SALT_SIZE);
    let (nonce, ciphertext) = rest.split_at(12);

    // Derive key using the extracted salt
    let key = derive_key(password, salt);

    // Decrypt data
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .map_err(|_| "Decryption failed: Incorrect password or corrupted data")?;

    // Write plaintext to output file
    let mut output = File::create(output_file)?;
    output.write_all(&plaintext)?;

    Ok(())
}

/// Derive a key from a password using Argon2
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}
