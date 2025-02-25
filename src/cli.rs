use clap::{Parser, Subcommand};

/// Command-line interface arguments
#[derive(Parser, Debug)]
#[command(name = "encryption_tool")]
#[command(about = "A tool to encrypt and decrypt files", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt files
    Encrypt {
        /// Input files to encrypt
        #[arg(required = true)]
        input_files: Vec<String>,

        /// Output file
        #[arg(short, long)]
        output: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(required = true)]
        input_file: String,

        /// Output directory
        #[arg(short, long)]
        output: String,
    },
}
