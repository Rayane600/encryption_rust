mod encryption;
mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use encryption::{encrypt_files, decrypt_files};
use std::process;
use rpassword::prompt_password;

fn main() {
    let cli = Cli::parse();

    // Prompt for password securely
    let password = prompt_password("Enter password: ").expect("Failed to read password");

    match &cli.command {
        Commands::Encrypt { input_files, output } => {
            if let Err(e) = encrypt_files(input_files, output, &password) {
                eprintln!("Error encrypting files: {}", e);
                process::exit(1);
            }
        }
        Commands::Decrypt { input_file, output } => {
            if let Err(e) = decrypt_files(input_file, output, &password) {
                eprintln!("Error decrypting files: {}", e);
                process::exit(1);
            }
        }
    }
}