extern crate keyring;

use clap::Parser;
use rpassword::prompt_password;

use keyring::{Entry, Error};

#[derive(Debug, Parser)]
#[clap(author = "github.com/hwchen/keyring-rs")]
/// Keyring CLI: A command-line interface to platform secure storage
pub struct Cli {
    #[clap(short, long, value_parser)]
    /// The target for the entry.
    pub target: Option<String>,

    #[clap(short, long, value_parser, default_value = "keyring-cli")]
    /// The service name for the entry
    pub service: String,

    #[clap(short, long, value_parser, default_value = "")]
    /// The user to store/retrieve the password for [default: user's login name]
    pub user: String,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Set the password in the secure store
    Set {
        #[clap(value_parser)]
        /// The password to set. If not specified, the password
        /// is collected interactively from the terminal
        password: Option<String>,
    },
    /// Get the password from the secure store
    Get,
    /// Delete the entry from the secure store
    Delete,
}

fn main() {
    let mut args: Cli = Cli::parse();
    if args.user.is_empty() {
        args.user = whoami::username()
    }
    execute_args(&args);
}

fn execute_args(args: &Cli) {
    let entry = if let Some(target) = &args.target {
        Entry::new_with_target(target, &args.service, &args.user)
            .unwrap_or_else(|err| panic!("Couldn't create entry: {:?}", err))
    } else {
        Entry::new(&args.service, &args.user)
            .unwrap_or_else(|err| panic!("Couldn't create entry: {:?}", err))
    };
    match &args.command {
        Command::Set {
            password: Some(password),
        } => execute_set_password(&args, &entry, password),
        Command::Set { password: None } => {
            if let Ok(password) = prompt_password("Password: ") {
                execute_set_password(&args, &entry, &password)
            } else {
                eprintln!("(Failed to read password, so none set.)")
            }
        }
        Command::Get => execute_get_password(&args, &entry),
        Command::Delete => execute_delete_password(&args, &entry),
    }
}

fn execute_set_password(args: &Cli, entry: &Entry, password: &str) {
    match entry.set_password(password) {
        Ok(()) => {
            println!(
                "(Password for '{}@{}' set successfully)",
                &args.user, &args.service
            )
        }
        Err(err) => {
            eprintln!(
                "Couldn't set password for '{}@{}': {:?}",
                &args.user, &args.service, err
            );
        }
    }
}

fn execute_get_password(args: &Cli, entry: &Entry) {
    match entry.get_password() {
        Ok(password) => {
            println!(
                "The password for '{}@{}' is '{}'",
                &args.user, &args.service, &password
            );
        }
        Err(Error::NoEntry) => {
            eprintln!("(No password found for '{}@{}')", &args.user, &args.service);
        }
        Err(err) => {
            eprintln!(
                "Couldn't get password for '{}@{}': {:?}",
                &args.user, &args.service, err
            );
        }
    }
}

fn execute_delete_password(args: &Cli, entry: &Entry) {
    match entry.delete_password() {
        Ok(()) => println!("(Password for '{}@{}' deleted)", &args.user, &args.service),
        Err(Error::NoEntry) => {
            eprintln!("(No password for '{}@{}' found)", &args.user, &args.service);
        }
        Err(err) => {
            eprintln!(
                "Couldn't delete password for '{}@{}': {:?}",
                &args.user, &args.service, err
            );
        }
    }
}
