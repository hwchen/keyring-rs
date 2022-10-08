use clap::Parser;
use rpassword::prompt_password;

extern crate keyring;
use keyring::{Entry, Error};

#[derive(Debug, Parser)]
#[clap(author = "github.com/hwchen/keyring-rs")]
/// Keyring CLI: A command-line interface to platform secure storage
pub struct Cli {
    #[clap(short, action = clap::ArgAction::Count)]
    /// Specify once to retrieve all aspects of credentials on get.
    /// Specify twice to provide structure print of all errors in addition to messages.
    pub verbose: u8,

    #[clap(short, long, value_parser)]
    /// The target for the entry.
    pub target: Option<String>,

    #[clap(short, long, value_parser, default_value = "keyring-cli")]
    /// The service name for the entry
    pub service: String,

    #[clap(short, long, value_parser)]
    /// The user name to store/retrieve the password for [default: user's login name]
    pub username: Option<String>,

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
    let args: Cli = Cli::parse();
    execute_args(&args);
}

fn execute_args(args: &Cli) {
    let username = if let Some(username) = &args.username {
        username.clone()
    } else {
        whoami::username()
    };
    let entry = if let Some(target) = &args.target {
        Entry::new_with_target(target, &args.service, &username)
            .unwrap_or_else(|err| panic!("Couldn't create entry: {:?}", err))
    } else {
        Entry::new(&args.service, &username)
            .unwrap_or_else(|err| panic!("Couldn't create entry: {:?}", err))
    };
    match &args.command {
        Command::Set {
            password: Some(password),
        } => execute_set_password(&username, args.verbose, &entry, password),
        Command::Set { password: None } => {
            if let Ok(password) = prompt_password("Password: ") {
                execute_set_password(&username, args.verbose, &entry, &password)
            } else {
                eprintln!("(Failed to read password, so none set.)")
            }
        }
        Command::Get => execute_get_password(&username, args.verbose, &entry),
        Command::Delete => execute_delete_password(&username, args.verbose, &entry),
    }
}

fn execute_set_password(username: &str, verbose: u8, entry: &Entry, password: &str) {
    match entry.set_password(password) {
        Ok(()) => println!("(Password for user '{}' set successfully)", username),
        Err(err) => {
            eprintln!("Couldn't set password for user '{}': {}", username, err);
            if verbose > 1 {
                eprintln!("Error details: {:?}", err);
            }
        }
    }
}

fn execute_get_password(username: &str, verbose: u8, entry: &Entry) {
    match entry.get_password() {
        Ok(password) => {
            println!("The password for user '{}' is '{}'", username, &password);
        }
        Err(Error::NoEntry) => {
            eprintln!("(No password found for user '{}')", username);
        }
        Err(err) => {
            eprintln!("Couldn't get password for user '{}': {}", username, err);
            if verbose > 1 {
                eprintln!("Error details: {:?}", err);
            }
        }
    }
}

fn execute_delete_password(username: &str, verbose: u8, entry: &Entry) {
    match entry.delete_password() {
        Ok(()) => println!("(Password for user '{}' deleted)", username),
        Err(Error::NoEntry) => {
            eprintln!("(No password for user '{}' found)", username);
            if verbose > 1 {
                eprintln!("Error details: {:?}", Error::NoEntry);
            }
        }
        Err(err) => {
            eprintln!("Couldn't delete password for user '{}': {}", username, err);
            if verbose > 1 {
                eprintln!("Error details: {:?}", err);
            }
        }
    }
}
