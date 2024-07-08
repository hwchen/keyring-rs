extern crate keyring;

use clap::Parser;

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
            let (secret, password) = args.get_password();
            if let Some(secret) = secret {
                match entry.set_secret(&secret) {
                    Ok(()) => args.success_message_for(Some(&secret), None),
                    Err(err) => args.error_message_for(err),
                }
            } else if let Some(password) = password {
                match entry.set_password(&password) {
                    Ok(()) => args.success_message_for(None, Some(&password)),
                    Err(err) => args.error_message_for(err),
                }
            } else {
                if args.verbose {
                    eprintln!("You must provide a password to the set command");
                }
                std::process::exit(1)
            }
        }
        Command::Password => match entry.get_password() {
            Ok(password) => {
                println!("{password}");
                args.success_message_for(None, Some(&password));
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Secret => match entry.get_secret() {
            Ok(secret) => {
                println!("{}", secret_string(&secret));
                args.success_message_for(Some(&secret), None);
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Delete => match entry.delete_credential() {
            Ok(()) => args.success_message_for(None, None),
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
    Password,
    /// Get the secret from the secure store
    Secret,
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
                    eprintln!("No credential found for '{description}'");
                }
                Error::Ambiguous(creds) => {
                    eprintln!("More than one credential found for '{description}': {creds:?}");
                }
                err => match self.command {
                    Command::Set { .. } => {
                        eprintln!("Couldn't set credential data for '{description}': {err}");
                    }
                    Command::Password => {
                        eprintln!("Couldn't get password for '{description}': {err}");
                    }
                    Command::Secret => {
                        eprintln!("Couldn't get secret for '{description}': {err}");
                    }
                    Command::Delete => {
                        eprintln!("Couldn't delete credential for '{description}': {err}");
                    }
                },
            }
        }
        std::process::exit(1)
    }

    fn success_message_for(&self, secret: Option<&[u8]>, password: Option<&str>) {
        if !self.verbose {
            return;
        }
        let description = self.description();
        match self.command {
            Command::Set { .. } => {
                if let Some(pw) = password {
                    eprintln!("Set password for '{description}' to '{pw}'");
                }
                if let Some(secret) = secret {
                    let secret = secret_string(secret);
                    eprintln!("Set secret for '{description}' to decode of '{secret}'");
                }
            }
            Command::Password => {
                let pw = password.unwrap();
                eprintln!("Password for '{description}' is '{pw}'");
            }
            Command::Secret => {
                let secret = secret_string(secret.unwrap());
                eprintln!("Secret for '{description}' encodes as {secret}");
            }
            Command::Delete => {
                eprintln!("Successfully deleted credential for '{description}'");
            }
        }
    }

    fn get_password(&self) -> (Option<Vec<u8>>, Option<String>) {
        match &self.command {
            Command::Set { password: Some(pw) } => password_or_secret(pw),
            Command::Set { password: None } => {
                if let Ok(password) = rpassword::prompt_password("Password: ") {
                    password_or_secret(&password)
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        }
    }
}

fn secret_string(secret: &[u8]) -> String {
    use base64::prelude::*;

    BASE64_STANDARD.encode(secret)
}

fn password_or_secret(input: &str) -> (Option<Vec<u8>>, Option<String>) {
    use base64::prelude::*;

    match BASE64_STANDARD.decode(input) {
        Ok(secret) => (Some(secret), None),
        Err(_) => (None, Some(input.to_string())),
    }
}
