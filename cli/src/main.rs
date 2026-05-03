use clap::{Args, Parser, Subcommand};
use cli::PasswordOptions;

use cli::{
    password::{generate_password, score_password},
    sync::sync,
};

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
    Record {
        #[command(subcommand)]
        cmd: RecordCommand,
    },
    Sync {},
}

#[derive(Subcommand)]
enum PasswordCommand {
    Generate(PasswordOptions),
    Score { password: String },
}

#[derive(Subcommand)]
enum VaultCommand {
    Create { name: String },
    List,
    Delete { name: String },
}

#[derive(Subcommand)]
enum RecordCommand {
    Create {},
    List {},
    Delete {},
}

fn main() {
    let cli = Cli::parse();
    let client = cli::Client::login("mypassword");

    match cli.command {
        Commands::Onboard {} => cli::onboarding::onboard(),
        Commands::Login {} => println!("login"),
        Commands::Password { cmd } => match cmd {
            PasswordCommand::Generate(ref options) => {
                let password = generate_password(options);
                println!("{}", password);
            }
            PasswordCommand::Score { password } => {
                let score = score_password(&password);
                println!("Password strength score: {}/8", score);
            }
        },
        Commands::Vault { cmd } => match cmd {
            VaultCommand::Create { name } => client.create_vault(&name),
            VaultCommand::List {} => client.list_vaults(),
            VaultCommand::Delete { name } => client.delete_vault(&name),
        },
        Commands::Record { cmd } => match cmd {
            RecordCommand::Create {} => cli::record::create_record(),
            RecordCommand::List {} => cli::record::list_records(),
            RecordCommand::Delete {} => cli::record::delete_record(),
        },
        Commands::Sync {} => sync(),
    }
}
