extern crate keyring;

use clap::Parser;
use std::collections::HashMap;

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
            let (secret, password, attributes) = args.get_password_and_attributes();
            if secret.is_none() && password.is_none() && attributes.is_none() {
                eprintln!("You must provide either a password or attributes to the set command");
                std::process::exit(1);
            }
            if let Some(secret) = secret {
                match entry.set_secret(&secret) {
                    Ok(()) => args.success_message_for(Some(&secret), None, None),
                    Err(err) => args.error_message_for(err),
                }
            }
            if let Some(password) = password {
                match entry.set_password(&password) {
                    Ok(()) => args.success_message_for(None, Some(&password), None),
                    Err(err) => args.error_message_for(err),
                }
            }
            if let Some(attributes) = attributes {
                let attrs: HashMap<&str, &str> = attributes
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect();
                match entry.update_attributes(&attrs) {
                    Ok(()) => args.success_message_for(None, None, Some(attributes)),
                    Err(err) => args.error_message_for(err),
                }
            }
        }
        Command::Password => match entry.get_password() {
            Ok(password) => {
                println!("{password}");
                args.success_message_for(None, Some(&password), None);
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Secret => match entry.get_secret() {
            Ok(secret) => {
                println!("{}", secret_string(&secret));
                args.success_message_for(Some(&secret), None, None);
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Attributes => match entry.get_attributes() {
            Ok(attributes) => {
                println!("{}", attributes_string(&attributes));
                args.success_message_for(None, None, Some(attributes));
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Delete => match entry.delete_credential() {
            Ok(()) => args.success_message_for(None, None, None),
            Err(err) => args.error_message_for(err),
        },
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

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Set the password and, optionally, attributes in the secure store
    Set {
        #[clap(short, long, action)]
        /// The password is base64-encoded binary
        binary: bool,

        #[clap(short, long, value_parser, default_value = "")]
        attributes: String,

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
    /// Retrieve attributes available in the secure store.
    Attributes,
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
                    Command::Attributes => {
                        eprintln!("Couldn't get attributes for '{description}': {err}");
                    }
                    Command::Delete => {
                        eprintln!("Couldn't delete credential for '{description}': {err}");
                    }
                },
            }
        }
        std::process::exit(1)
    }

    fn success_message_for(
        &self,
        secret: Option<&[u8]>,
        password: Option<&str>,
        attributes: Option<HashMap<String, String>>,
    ) {
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
                if let Some(attributes) = attributes {
                    eprintln!("Set attributes for '{description}' to:");
                    eprint_attributes(attributes);
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
            Command::Attributes => {
                let attributes = attributes.unwrap();
                if attributes.is_empty() {
                    eprintln!("No attributes found for '{description}'");
                } else {
                    eprintln!("Attributes for '{description}' are:");
                    eprint_attributes(attributes);
                }
            }
            Command::Delete => {
                eprintln!("Successfully deleted credential for '{description}'");
            }
        }
    }

    fn get_password_and_attributes(
        &self,
    ) -> (
        Option<Vec<u8>>,
        Option<String>,
        Option<HashMap<String, String>>,
    ) {
        if let Command::Set {
            binary,
            attributes,
            password,
        } = &self.command
        {
            let secret = if *binary {
                Some(decode_secret(password))
            } else {
                None
            };
            let password = if !*binary {
                Some(read_password(password))
            } else {
                None
            };
            let attributes = parse_attributes(attributes);
            (secret, password, attributes)
        } else {
            panic!("Can't happen: asking for password and attributes on non-set command")
        }
    }
}

fn secret_string(secret: &[u8]) -> String {
    use base64::prelude::*;

    BASE64_STANDARD.encode(secret)
}

fn eprint_attributes(attributes: HashMap<String, String>) {
    for (key, value) in attributes {
        println!("    {key}: {value}");
    }
}

fn decode_secret(input: &Option<String>) -> Vec<u8> {
    use base64::prelude::*;

    let encoded = if let Some(input) = input {
        input.clone()
    } else {
        rpassword::prompt_password("Base64 encoding: ").unwrap_or_else(|_| String::new())
    };
    if encoded.is_empty() {
        return Vec::new();
    }
    match BASE64_STANDARD.decode(encoded) {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("Sorry, the provided secret data is not base64-encoded: {err}");
            std::process::exit(1);
        }
    }
}

fn read_password(input: &Option<String>) -> String {
    let password = if let Some(input) = input {
        input.clone()
    } else {
        rpassword::prompt_password("Password: ").unwrap_or_else(|_| String::new())
    };
    password
}

fn attributes_string(attributes: &HashMap<String, String>) -> String {
    let strings = attributes
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>();
    strings.join(",")
}

fn parse_attributes(input: &String) -> Option<HashMap<String, String>> {
    if input.is_empty() {
        return None;
    }
    let mut attributes = HashMap::new();
    let parts = input.split(',');
    for s in parts.into_iter() {
        let parts: Vec<&str> = s.split("=").collect();
        if parts.len() != 2 || parts[0].is_empty() {
            eprintln!("Sorry, this part of the attributes string is not a key=val pair: {s}");
            std::process::exit(1);
        }
        attributes.insert(parts[0].to_string(), parts[1].to_string());
    }
    Some(attributes)
}
