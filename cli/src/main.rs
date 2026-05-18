use clap::{Parser, Subcommand};
use cli::login;
use cli::password::PasswordOptions;
use cli::record::Entry;

use cli::password::{generate_password, score_password};
use cli::sync::sync;
use cli::vault::create_vault;

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

        #[arg(long)]
        copy: bool,
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
        vault: String,
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

    match cli.command {
        Commands::Onboard {} => cli::onboarding::onboard(),
        Commands::Login {} => println!("login"),
        Commands::Password { cmd } => match cmd {
            PasswordCommand::Generate {
                length,
                numbers,
                uppercase,
                symbols,
                copy,
            } => {
                let options = PasswordOptions {
                    length,
                    numbers,
                    uppercase,
                    symbols,
                };
                let password = generate_password(&options);
                if copy {
                    let mut clipboard = arboard::Clipboard::new().unwrap();
                    clipboard.set_text(password.clone()).unwrap();
                } else {
                    println!("{}", password);
                }
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
                    create_vault(&conn, &name, &keys).unwrap();
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
                    if let Err(e) = cli::vault::delete_vault(&conn, &name, keys) {
                        eprintln!("Error deleting vault: {}", e);
                    }
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
                        let item = cli::record::Entry::Password {
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
                    let items = cli::record::list_records(&conn, &vault, &keys);

                    for item in items.unwrap() {
                        match item.data {
                            Entry::Password { title, .. } => {
                                println!("ID: {}, Title: {}, Type=Password", item.id, title)
                            }
                        }
                    }
                }
                ItemCommand::View { vault, name } => {
                    let record = cli::record::view_record(&conn, vault, name, keys).unwrap();
                    println!("{:#?}", record.data);
                }
                ItemCommand::Delete { vault, name } => {
                    cli::record::delete_record(&conn, vault, name, keys).unwrap();
                }
            }
        }
        Commands::Sync {} => sync(),
    }
}
