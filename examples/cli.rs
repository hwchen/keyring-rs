extern crate keyring;

use clap::Parser;
use rpassword::prompt_password;

use keyring::{Entry, Error, Result};

fn main() {
    let mut args: Cli = Cli::parse();
    if args.user.is_empty() || args.user.eq_ignore_ascii_case("<whoami>") {
        args.user = whoami::username()
    }
    let entry = match args.entry_for() {
        Ok(entry) => entry,
        Err(err) => {
            if args.verbose {
                let description = args.description();
                eprintln!("Couldn't create entry for '{description}': {err}")
            }
            std::process::exit(1)
        }
    };
    match &args.command {
        Command::Set { .. } => {
            let password = args.get_password();
            match entry.set_password(&password) {
                Ok(()) => args.success_message_for(Some(&password)),
                Err(err) => args.error_message_for(err),
            }
        }
        Command::Get => match entry.get_password() {
            Ok(password) => {
                println!("{password}");
                args.success_message_for(Some(&password));
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Delete => match entry.delete_password() {
            Ok(()) => args.success_message_for(None),
            Err(err) => args.error_message_for(err),
        },
    }
}

#[derive(Debug, Parser)]
#[clap(author = "github.com/hwchen/keyring-rs")]
/// Keyring CLI: A command-line interface to platform secure storage
pub struct Cli {
    #[clap(short, long, action)]
    /// Write debugging info to stderr (shows passwords)
    pub verbose: bool,

    #[clap(short, long, value_parser)]
    /// The target for the entry
    pub target: Option<String>,

    #[clap(short, long, value_parser, default_value = "keyring-cli")]
    /// The service name for the entry
    pub service: String,

    #[clap(short, long, value_parser, default_value = "<whoami>")]
    /// The user to store/retrieve the password for
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

impl Cli {
    fn description(&self) -> String {
        if let Some(target) = &self.target {
            format!("[{target}]{}@{}", &self.user, &self.service)
        } else {
            format!("{}@{}", &self.user, &self.service)
        }
    }

    fn entry_for(&self) -> Result<Entry> {
        if let Some(target) = &self.target {
            Entry::new_with_target(target, &self.service, &self.user)
        } else {
            Entry::new(&self.service, &self.user)
        }
    }

    fn error_message_for(&self, err: Error) {
        if self.verbose {
            let description = self.description();
            match err {
                Error::NoEntry => {
                    eprintln!("No password found for '{description}'");
                }
                Error::Ambiguous(creds) => {
                    eprintln!("More than one credential found for '{description}': {creds:?}");
                }
                err => match self.command {
                    Command::Set { .. } => {
                        eprintln!("Couldn't set password for '{description}': {err}");
                    }
                    Command::Get => {
                        eprintln!("Couldn't get password for '{description}': {err}");
                    }
                    Command::Delete => {
                        eprintln!("Couldn't set password for '{description}': {err}");
                    }
                },
            }
        }
        std::process::exit(1)
    }

    fn success_message_for(&self, password: Option<&str>) {
        if !self.verbose {
            return;
        }
        let description = self.description();
        match self.command {
            Command::Set { .. } => {
                let pw = password.unwrap();
                eprintln!("Set password '{pw}' for '{description}'");
            }
            Command::Get => {
                let pw = password.unwrap();
                eprintln!("Got password '{pw}' for '{description}'");
            }
            Command::Delete => {
                eprintln!("Successfully deleted password for '{description}'");
            }
        }
    }

    fn get_password(&self) -> String {
        match &self.command {
            Command::Set {
                password: Some(password),
            } => password.clone(),
            Command::Set { password: None } => {
                if let Ok(password) = prompt_password("Password: ") {
                    password
                } else {
                    if self.verbose {
                        eprintln!("Failed to read password from terminal");
                    }
                    std::process::exit(1)
                }
            }
            _ => String::new(),
        }
    }
}
