use clap::{Parser, Subcommand};

/// Arguments de l'interface en ligne de commande
#[derive(Parser, Debug)]
#[command(name = "dechiffrust")]
#[command(about = "Un outil pour chiffrer et déchiffrer des fichiers", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Chiffre plusieurs fichiers
    Encrypt {
        /// Fichiers en entrée à chiffrer
        #[arg(required = true)]
        input_files: Vec<String>,

        /// Fichier chiffré en sortie
        #[arg(short, long)]
        output: String,
    },
    /// Déchiffre un fichier chiffré
    Decrypt {
        /// Fichier chiffré en entrée
        #[arg(required = true)]
        input_file: String,

        /// Dossier de sortie pour les fichiers déchiffrés
        #[arg(short, long)]
        output: String,
    },
}
