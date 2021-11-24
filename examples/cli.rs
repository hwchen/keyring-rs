use rpassword::read_password_from_tty;
use structopt::StructOpt;

extern crate keyring;
use keyring::{Entry, Error};

#[derive(Debug, StructOpt)]
#[structopt(author = "github.com/hwchen/keyring-rs")]
/// Keyring CLI: A command-line interface to platform secure storage
pub struct Cli {
    #[structopt(short, parse(from_occurrences))]
    /// Specify once to retrieve all aspects of credentials on get.
    /// Specify twice to provide structure print of all errors in addition to messages.
    pub verbose: u8,

    #[structopt(short, long)]
    /// The target for the entry.
    pub target: Option<String>,

    #[structopt(short, long, default_value = "keyring-cli")]
    /// The service name for the entry
    pub service: String,

    #[structopt(short, long)]
    /// The user name to store/retrieve the password for [default: user's login name]
    pub username: Option<String>,

    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Set the password in the secure store
    Set {
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
    let args: Cli = Cli::from_args();
    execute_args(&args);
}

fn execute_args(args: &Cli) {
    let username = if let Some(username) = &args.username {
        username.clone()
    } else {
        whoami::username()
    };
    let entry = if let Some(target) = args.target.as_ref() {
        Entry::new_with_target(target, &args.service, &username)
    } else {
        Entry::new(&args.service, &username)
    };
    match &args.command {
        Command::Set {
            password: Some(password),
        } => execute_set_password(&username, args.verbose, &entry, password),
        Command::Set { password: None } => {
            if let Ok(password) = read_password_from_tty(Some("Password: ")) {
                execute_set_password(&username, args.verbose, &entry, &password)
            } else {
                eprintln!("(Failed to read password, so none set.)")
            }
        }
        Command::Get => execute_get_password_and_credential(&username, args.verbose, &entry),
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

fn execute_get_password_and_credential(username: &str, verbose: u8, entry: &Entry) {
    match entry.get_password_and_credential() {
        Ok((password, credential)) => {
            println!("The password for user '{}' is '{}'", username, &password);
            if verbose > 0 {
                println!("Credential is: {:?}", credential)
            }
        }
        Err(Error::NoEntry) => {
            eprintln!("(No password found for user '{}')", username);
            if verbose > 1 {
                eprintln!("Error details: {:?}", Error::NoEntry);
            }
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
