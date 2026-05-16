use argon2::password_hash::SaltString;
use argon2::{PasswordHash, PasswordVerifier};
use clap::{Parser, Subcommand};
use cli::crypto::VaultKeys;
use cli::storage::Metadata;
use cli::{crypto, db_connection, password::PasswordOptions};

use cli::vault::create_vault;
use cli::{
    password::{generate_password, score_password},
    // sync::sync,
};
use dialoguer::Password;
use dialoguer::theme::ColorfulTheme;
use rusqlite::Connection;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Onboard {},
    Login {},
    Password {
        #[command(subcommand)]
        cmd: PasswordCommand,
    },
    Vault {
        #[command(subcommand)]
        cmd: VaultCommand,
    },
    Item {
        #[command(subcommand)]
        cmd: ItemCommand,
    },
    Sync {},
}

#[derive(Subcommand)]
enum PasswordCommand {
    Generate {
        #[arg(short, long, default_value = "20")]
        length: usize,
        #[arg(short, long, default_value = "true")]
        numbers: bool,
        #[arg(short, long, default_value = "true")]
        uppercase: bool,
        #[arg(short, long, default_value = "true")]
        symbols: bool,
    },
    Score {
        #[arg(short, long)]
        password: String,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create a new vault with the given name
    Create {
        #[arg(long)]
        name: String,
    },
    /// List all vaults (id & name)
    List,
    /// Delete a vault by name
    Delete {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum ItemCommand {
    Create {
        #[command(subcommand)]
        cmd: CreateItem,
    },
    List {
        #[arg(long)]
        vault: String,
    },
    View {
        /// The title of the vault
        #[arg(long)]
        vault: String,
        /// The title of the record
        #[arg(long)]
        name: String,
    },
    Delete {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum CreateItem {
    Login {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        url: String,
    },
    Otp {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        issuer: String,
    },
    Ssh {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        public_key: Option<String>,
    },
    Note {
        #[arg(long)]
        content: String,
    },
    Card {
        number: String,
        expiry: String,
        cvv: String,
    },
}

fn main() {
    let cli = Cli::parse();
    // let client = cli::Client::login("mypassword");

    match cli.command {
        Commands::Onboard {} => cli::onboarding::onboard(),
        Commands::Login {} => println!("login"),
        Commands::Password { cmd } => match cmd {
            PasswordCommand::Generate {
                length,
                numbers,
                uppercase,
                symbols,
            } => {
                let options = PasswordOptions {
                    length,
                    numbers,
                    uppercase,
                    symbols,
                };
                let password = generate_password(&options);
                println!("{}", password);
            }
            PasswordCommand::Score { password } => {
                let score = score_password(&password);
                println!("Password strength score: {}/8", score);
            }
        },
        Commands::Vault { cmd } => {
            let (conn, keys) = login();
            match cmd {
                VaultCommand::Create { name } => {
                    create_vault(&conn, &name, keys).unwrap();
                }
                VaultCommand::List => {
                    let vaults = cli::vault::list_vaults(&conn).unwrap();
                    for vault in vaults {
                        println!(
                            "Vault ID: {}, Name: {}",
                            vault.id,
                            vault.decrypt_name(&keys).unwrap()
                        );
                    }
                }
                VaultCommand::Delete { name } => {
                    cli::vault::delete_vault(&conn, &name, keys).unwrap();
                }
            }
        }
        Commands::Item { cmd } => {
            let (conn, keys) = login();
            match cmd {
                ItemCommand::Create { cmd } => match cmd {
                    CreateItem::Login {
                        vault,
                        title,
                        username,
                        password,
                        url,
                    } => {
                        let item = cli::record::Item::Password {
                            title,
                            username,
                            password,
                            url,
                        };
                        cli::record::create_record(&conn, vault, item, keys).unwrap();
                    }
                    _ => todo!(),
                },
                ItemCommand::List { vault } => {
                    let items = cli::record::list_records(&conn, vault, keys);

                    for item in items.unwrap() {
                        println!("{:?}", item);
                    }
                }
                ItemCommand::View { vault, name } => {
                    let record = cli::record::view_record(vault, name).unwrap();
                    println!("{}", record);
                }
                ItemCommand::Delete { .. } => cli::record::delete_record(),
            }
        }
        Commands::Sync {} => (),
    }
}

fn login() -> (Connection, VaultKeys) {
    let conn = db_connection().expect("Failed to connect to vault database");
    let password_hash = Metadata::get_str(&conn, "password_hash")
        .expect("Failed to retrieve password hash from metadata")
        .unwrap();

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .report(false)
        .validate_with(|input: &String| -> Result<(), &str> {
            let hash = PasswordHash::new(&password_hash).unwrap();
            if argon2::Argon2::default()
                .verify_password(input.as_bytes(), &hash)
                .is_ok()
            {
                Ok(())
            } else {
                Err("Password must be longer than 3")
            }
        })
        .interact()
        .unwrap();

    let master_salt = Metadata::get_str(&conn, "salt")
        .expect("Failed to retrieve master salt from metadata")
        .unwrap();
    let root_key =
        crypto::derive_master_key(&password, &SaltString::from_b64(&master_salt).unwrap());
    let keys = crypto::derive_subkeys(&root_key);

    (conn, keys)
}
