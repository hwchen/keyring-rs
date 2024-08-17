extern crate keyring;

use clap::Parser;

use keyring::{Entry, Error, Result};

fn main() {
    let mut args: Cli = Cli::parse();
    if args.user.eq_ignore_ascii_case("<logged-in username>") {
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

#[cfg(all(
    any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"),
    any(feature = "sync-secret-service", feature = "async-secret-service")
))]
mod v1 {
    use keyring::{secret_service::SsCredential, Entry, Result};

    /// Create a v1-like entry (one with no target attribute)
    pub fn new_entry(service: &str, user: &str) -> Result<Entry> {
        let cred = SsCredential::new_with_no_target(service, user)?;
        Ok(Entry::new_with_credential(Box::new(cred)))
    }
}
#[cfg(not(all(
    any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"),
    any(feature = "sync-secret-service", feature = "async-secret-service")
)))]
mod v1 {
    use keyring::Entry;

    /// For everything but the secret service, v1 entries are the same as
    /// regular entries with the default target.
    pub fn new_entry(service: &str, user: &str) -> keyring::Result<Entry> {
        Entry::new(service, user)
    }
}

#[derive(Debug, Parser)]
#[clap(author = "github.com/hwchen/keyring-rs")]
/// Keyring CLI: A command-line interface to platform secure storage
pub struct Cli {
    #[clap(short, long, action, verbatim_doc_comment)]
    /// Write debugging info to stderr, including retrieved passwords and secrets.
    /// If an operation fails, detailed error information is provided.
    pub verbose: bool,

    #[clap(short, long, value_parser)]
    /// The (optional) target for the entry.
    pub target: Option<String>,

    #[clap(short, long, value_parser, default_value = "keyring-cli")]
    /// The service for the entry.
    pub service: String,

    #[clap(short, long, value_parser, default_value = "<logged-in username>")]
    /// The user for the entry.
    pub user: String,

    #[clap(long, action, verbatim_doc_comment)]
    /// Whether to look for v1 entries (that have no target).
    /// N.B.: v1 entries can only be read or deleted, not set.
    /// This may also find v2/v3 entries that have a target.
    pub v1: bool,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Set the password in the secure store
    Set {
        #[clap(value_parser)]
        /// The password to set into the secure store.
        /// If it's a valid base64 encoding (with padding),
        /// it will be decoded and used to set the binary secret.
        /// Otherwise, it will be interpreted as a string password.
        /// If no password is specified, it will be
        /// collected interactively (without echo)
        /// from the terminal.
        password: Option<String>,
    },
    /// Retrieve the (string) password from the secure store
    /// and write it to the standard output.
    Password,
    /// Retrieve the (binary) secret from the secure store
    /// and write it in base64 encoding to the standard output.
    Secret,
    /// Delete the underlying credential from the secure store.
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
        if self.v1 {
            if self.target.is_some() {
                eprintln!("usage error: You cannot specify both --target and --v1");
                std::process::exit(1)
            }
            v1::new_entry(&self.service, &self.user)
        } else if let Some(target) = &self.target {
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
