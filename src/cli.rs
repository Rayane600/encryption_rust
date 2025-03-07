use clap::{Parser, Subcommand};

/// Command line interface arguments
#[derive(Parser, Debug)]
#[command(name = "dechiffrust")]
#[command(about = "Un outil pour chiffrer et déchiffrer des fichiers", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encypt multiple files :
    /// encrypt --output <output_file> <input_files>
    Encrypt {
        /// Input files to encrypt
        #[arg(required = true)]
        input_files: Vec<String>,

        /// Encrypted file as output
        #[arg(short, long)]
        output: String,
    },
    /// Decrypt an encrypted file :
    /// decrypt --output <output_dir> <input_file>
    Decrypt {
        /// Encrypted file as input
        #[arg(required = true)]
        input_file: String,

        /// Output directory for decrypted files
        #[arg(short, long)]
        output: String,
    },
}