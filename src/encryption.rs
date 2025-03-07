use aes_gcm::{Aes256Gcm, Key, NewAead, Nonce, aead::Aead};
use argon2::Argon2;
use rand::{Rng, thread_rng};
use std::fs::{File, create_dir_all};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use zxcvbn::{zxcvbn,Score};

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

/// Chiffre plusieurs fichiers et les stocke dans un fichier chiffré
pub fn encrypt_files(input_files: &[String], output_file: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut output = BufWriter::new(File::create(output_file)?);

    // Générer le sel et le nonce aléatoires
    let salt: [u8; SALT_SIZE] = thread_rng().gen();
    let nonce: [u8; NONCE_SIZE] = thread_rng().gen();
    output.write_all(&salt)?;
    output.write_all(&nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));

    for file_path in input_files {
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        let mut buffer = Vec::new();
        File::open(file_path)?.read_to_end(&mut buffer)?;

        let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), buffer.as_ref())
            .map_err(|_| "Encryption failed")?;

        output.write_all(&(file_name.len() as u32).to_le_bytes())?;
        output.write_all(file_name.as_bytes())?;
        output.write_all(&(encrypted_data.len() as u32).to_le_bytes())?;
        output.write_all(&encrypted_data)?;
    }
    Ok(())
}

/// Déchiffre une archive chiffrée et restaure les fichiers
pub fn decrypt_files(input_file: &str, output_dir: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = BufReader::new(File::open(input_file)?);
    create_dir_all(output_dir)?;

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    input.read_exact(&mut salt)?;
    input.read_exact(&mut nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));

    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    let mut cursor = &buffer[..];

    while !cursor.is_empty() {
        let name_len = read_u32(&mut cursor)? as usize;
        let mut file_name_bytes = vec![0u8; name_len];
        cursor.read_exact(&mut file_name_bytes)?;
        let file_name = String::from_utf8(file_name_bytes)?;

        let data_len = read_u32(&mut cursor)? as usize;
        let mut encrypted_data = vec![0u8; data_len];
        cursor.read_exact(&mut encrypted_data)?;

        let decrypted_data = cipher.decrypt(Nonce::from_slice(&nonce), encrypted_data.as_ref())
            .map_err(|_| "Decryption failed")?;

        File::create(Path::new(output_dir).join(file_name))?.write_all(&decrypted_data)?;
    }
    Ok(())
}

/// Derive une clé à partir d'un mot de passe avec Argon2
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}

/// Lit un entier 32 bits en little-endian
fn read_u32(cursor: &mut &[u8]) -> Result<u32, std::io::Error> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn pass_strength(pass: &str) -> bool{
    let strength = zxcvbn(pass, &[]).score();
    !(strength== Score::Zero || strength == Score::One || strength == Score::Two)
}