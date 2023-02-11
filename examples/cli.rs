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
    let (description, entry) = if let Some(target) = &args.target {
        (
            format!("[{target}]{}@{}", &args.user, &args.service),
            Entry::new_with_target(target, &args.service, &args.user)
                .unwrap_or_else(|err| panic!("Couldn't create entry: {err}")),
        )
    } else {
        (
            format!("{}@{}", &args.user, &args.service),
            Entry::new(&args.service, &args.user)
                .unwrap_or_else(|err| panic!("Couldn't create entry: {err}")),
        )
    };
    match &args.command {
        Command::Set {
            password: Some(password),
        } => execute_set_password(&description, &entry, password),
        Command::Set { password: None } => {
            if let Ok(password) = prompt_password("Password: ") {
                execute_set_password(&description, &entry, &password)
            } else {
                eprintln!("(Failed to read password, so none set.)")
            }
        }
        Command::Get => execute_get_password(&description, &entry),
        Command::Delete => execute_delete_password(&description, &entry),
    }
}

fn execute_set_password(description: &str, entry: &Entry, password: &str) {
    match entry.set_password(password) {
        Ok(()) => {
            println!("(Password for '{description}' set successfully)")
        }
        Err(err) => {
            eprintln!("Couldn't set password for '{description}': {err}",);
        }
    }
}

fn execute_get_password(description: &str, entry: &Entry) {
    match entry.get_password() {
        Ok(password) => {
            println!("The password for '{description}' is '{password}'");
        }
        Err(Error::NoEntry) => {
            eprintln!("(No password found for '{description}')");
        }
        Err(Error::Ambiguous(creds)) => {
            eprintln!("More than one credential found for {description}: {creds:?}")
        }
        Err(err) => {
            eprintln!("Couldn't get password for '{description}': {err}",);
        }
    }
}

fn execute_delete_password(description: &str, entry: &Entry) {
    match entry.delete_password() {
        Ok(()) => println!("(Password for '{description}' deleted)"),
        Err(Error::NoEntry) => {
            eprintln!("(No password for '{description}' found)");
        }
        Err(err) => {
            eprintln!("Couldn't delete password for '{description}': {err}",);
        }
    }
}
