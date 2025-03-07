mod encryption;
mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use encryption::{encrypt_files, decrypt_files,pass_strength};
use std::process;
use rpassword::prompt_password;


fn main() {
    let cli = Cli::parse();
    let mut password = prompt_password("Enter password: ").expect("Failed to read password");
    let mut strong  = pass_strength(&password);
    while !strong{
    // Prompt for password securely
    password = prompt_password("Password too weak try again: ").expect("Failed to read password");   
    strong = pass_strength(&password)

    }
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