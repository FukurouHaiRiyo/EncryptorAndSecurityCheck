use std::env;
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use once_cell::sync::Lazy;

mod encryption;
mod gui;
mod verification;
mod key_manager; // Import key management module

// Load the API key from the .env file
static API_KEY: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    env::var("API_KEY").expect("API_KEY not found in .env file")
});

/// CLI and GUI Interface for AES-256-GCM File Encryption and Phone Verification
#[derive(Parser)]
#[command(name = "AES File Encryptor & Phone Validator")]
#[command(version = "1.0")]
#[command(about = "Encrypt/Decrypt files and Validate Phone Numbers", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Path to the input file
        #[arg(short, long)]
        input: String,
        /// Path to save the encrypted file
        #[arg(short, long)]
        output: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Path to the encrypted file
        #[arg(short, long)]
        input: String,
        /// Path to save the decrypted file
        #[arg(short, long)]
        output: String,
    },
    /// Validate a phone number using IPQS API
    ValidatePhone {
        /// Phone number to validate
        #[arg(short = 'n', long = "number")]
        phone: String,
    }
}

fn main() {
    /// Get the command line arguments
    let args: Vec<String> = env::args().collect();

    // Check if "gui" is specified or if no arguments are passed (launch GUI by default)
    if args.len() == 1 || (args.len() > 1 && args[1] == "gui") {
        println!("🖥️ Launching GUI...");
        gui::run_gui();
    } else {
        // Use Clap to parse CLI commands
        let cli = Cli::parse();

        match &cli.command {
            Some(Commands::Encrypt { input, output }) => {
                println!("🔒 Encrypting file...");
                if let Err(e) = encryption::encrypt_file(&input, &output) {
                    eprintln!("❌ Encryption failed: {}", e);
                    std::process::exit(1);
                }
                println!("✅ File successfully encrypted: {}", output);
            }
            Some(Commands::Decrypt { input, output }) => {
                println!("🔓 Decrypting file...");
                if let Err(e) = encryption::decrypt_file(&input, &output) {
                    eprintln!("❌ Decryption failed: {}", e);
                    std::process::exit(1);
                }
                println!("✅ File successfully decrypted: {}", output);
            }
            Some(Commands::ValidatePhone { phone }) => {
                println!("📱 Phone Validation Mode");
                let ipqs = crate::verification::ipqs::IPQS::new(&API_KEY);

                let additional_params = vec![("country", "US"), ("country", "CA")];
                match ipqs.phone_number_api(phone, &additional_params) {
                    Ok(result) => {
                        if result.success {
                            if !result.valid {
                                println!("❌ This is not a valid number");
                            } else if result.recent_abuse {
                                println!("❌ This is abusive");
                            } else {
                                println!("✅ The phone number is valid and not abusive");
                            }
                        } else {
                            println!("⚠️ Query was not successful");
                        }
                    }
                    Err(e) => {
                        println!("❌ Error occurred: {}", e);
                    }
                }
            }
            None => {
                eprintln!("❌ No command provided. Use --help for available commands.");
                std::process::exit(1);
            }
        }
    }
}