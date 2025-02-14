mod encryption;
mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use encryption::{encrypt_file, decrypt_file};
use std::process;

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { input_files, output } => {
            for input_file in input_files {
                if let Err(e) = encrypt_file(input_file, output, &cli.password) {
                    eprintln!("Error encrypting file {}: {}", input_file, e);
                    process::exit(1);
                }
            }
        }
        Commands::Decrypt { input_file, output } => {
            if let Err(e) = decrypt_file(input_file, output, &cli.password) {
                eprintln!("Error decrypting file {}: {}", input_file, e);
                process::exit(1);
            }
        }
    }
}

