extern crate keyring;

use std::io::Write;

use clap::Parser;
use rpassword::prompt_password;

use keyring::{CredentialSearchResult, Entry, Error, Result};

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
                Ok(()) => args.success_message_for(Some(&password), None),
                Err(err) => args.error_message_for(err),
            }
        }
        Command::Get => match entry.get_password() {
            Ok(password) => {
                println!("{password}");
                args.success_message_for(Some(&password), None);
            }
            Err(err) => args.error_message_for(err),
        },
        Command::Delete => match entry.delete_password() {
            Ok(()) => args.success_message_for(None, None),
            Err(err) => args.error_message_for(err),
        },
        Command::Search { max, .. } => {
            let results = Entry::search(&args.get_query());
            let list;
            if let Some(max) = max {
                list = Entry::list_max(&results, *max);
            } else {
                list = Entry::list_results(&results)
            }
            println!("{list}");
            args.flush();

            if list == "Search returned no results".to_string() {
                std::process::exit(0)
            }

            if args.entry_from_results() {
                let entries = args.create_entry_vec(&results);
                args.select_entries(entries);
            }
        }
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
    /// Search for entries
    Search {
        #[clap(value_parser)]
        /// The value to search for. If not specified, the
        /// query is collected interactively from the terminal.
        query: Option<String>,
        #[clap(value_parser, default_value = None)]
        /// Optional max value to limit search results
        max: Option<i64>,
    },
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
                    Command::Search { .. } => {
                        eprintln!("Couldn't search for '{description}: {err} ")
                    }
                },
            }
        }
        std::process::exit(1)
    }

    fn success_message_for(&self, password: Option<&str>, query: Option<&str>) {
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
            Command::Search { .. } => {
                let q = query.unwrap();
                eprintln!("Successfully searched for '{q}'");
            }
        }
    }

    fn get_password(&self) -> String {
        match &self.command {
            Command::Set {
                password: Some(password),
            } => password.clone(),
            Command::Set { password: None } | Command::Search { .. } => {
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

    fn get_query(&self) -> String {
        match &self.command {
            Command::Search {
                query: Some(query), ..
            } => query.clone(),
            Command::Search { query: None, .. } => {
                print!("Search query: ");
                self.flush();
                let mut input = String::new();
                match std::io::stdin().read_line(&mut input) {
                    Ok(_) => {
                        input.trim().to_string() // trim to remove newline
                    }
                    Err(err) => {
                        if self.verbose {
                            eprintln!("Failed to read query from terminal: {}", err);
                        }
                        std::process::exit(1)
                    }
                }
            }
            _ => String::new(),
        }
    }

    fn entry_from_results(&self) -> bool {
        print!("Would you like to modify any searched entries? (y/n) ");
        self.flush();
        let mut input = String::new();
        self.read_line(&mut input);
        match input.trim().to_ascii_lowercase().as_str() {
            "y" => return true,
            "n" => {
                println!("Exiting, goodbye!");
                std::process::exit(0);
            }
            _ => self.entry_from_results(),
        }
    }

    fn create_entry_vec(&self, results: &CredentialSearchResult) -> Vec<Entry> {
        let mut entries = vec![];

        let size = match results.as_ref() {
            Ok(results) => results.keys().len(),
            Err(err) => {
                if !self.verbose {
                    eprintln!("Error getting size of result map: {err}");
                }
                std::process::exit(1)
            }
        };

        for id in 1..=size {
            let entry = match Entry::from_search_results(&results, id) {
                Ok(entry) => entry,
                Err(err) => {
                    if self.verbose {
                        eprintln!("Could not create entry from credential '{id}': {err}");
                    }
                    std::process::exit(1);
                }
            };
            entries.push(entry);
        }

        entries
    }

    fn select_entries(&self, entries: Vec<Entry>) {
        print!("Enter the ID of the entry you would like to modify: ");
        self.flush();
        let mut id = String::new();

        self.read_line(&mut id);
        self.modify_entries(entries, self.check_id(id));
    }

    fn check_id(&self, id: String) -> usize {
        match id.trim().to_string().parse::<usize>() {
            Ok(id) => id,
            Err(err) => {
                if self.verbose {
                    eprintln!("Failed to parse ID from String to usize: {err}");
                }
                std::process::exit(1)
            }
        }
    }

    fn modify_entries(&self, entries: Vec<Entry>, id: usize) {
        if id <= entries.len() {
            let mut select = String::new();
            let entry = &entries[id - 1];

            println!("How would you like to modify this entry?\n");
            println!("1. Set new password");
            println!("2. Get current password");
            println!("3. Delete credential\n");
            self.flush();

            self.read_line(&mut select);

            match select.trim().to_ascii_lowercase().as_str() {
                "1" => {
                    let password = self.get_password();
                    match entry.set_password(&password) {
                        Ok(_) => {
                            println!("Set password '{password}' for credential {id}");
                            std::process::exit(0);
                        }
                        Err(err) => {
                            if self.verbose {
                                eprintln!("Error setting password for credential {id}: {err}");
                            }
                            std::process::exit(1);
                        }
                    };
                }
                "2" => {
                    let password = match entry.get_password() {
                        Ok(password) => password,
                        Err(err) => {
                            if self.verbose {
                                eprintln!("Error getting entry password: {err}");
                            }
                            std::process::exit(1)
                        }
                    };

                    println!("Password is '{password}' for credential {id}");
                    std::process::exit(0);
                }
                "3" => {
                    match entry.delete_password() {
                        Ok(_) => {
                            println!("Credential w/ ID: {id} deleted");
                            std::process::exit(0);
                        }
                        Err(err) => {
                            if self.verbose {
                                eprintln!("Error deleting credential {id}: {err}");
                            }
                            std::process::exit(1);
                        }
                    };
                }
                _ => {
                    println!("Invalid input");
                    std::process::exit(1);
                }
            }
        }
    }

    fn flush(&self) {
        match std::io::stdout().flush() {
            Ok(_) => {}
            Err(err) => {
                if self.verbose {
                    eprintln!("Failed to flush stdout: {err}");
                }
                std::process::exit(1)
            }
        }
    }

    fn read_line(&self, input: &mut String) {
        match std::io::stdin().read_line(input) {
            Ok(_) => {}
            Err(err) => {
                if self.verbose {
                    eprintln!("Failed to read line: {}", err);
                }
                std::process::exit(1)
            }
        }
    }
}
