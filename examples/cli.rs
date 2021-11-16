extern crate clap;
extern crate keyring;
extern crate rpassword;

use clap::{App, Arg, SubCommand};
use keyring::Entry;
use rpassword::read_password_from_tty;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("keyring")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Walther Chen <walther.chen@gmail.com>")
        .about("Cross-platform utility to get and set passwords from system vault")
        .subcommand(
            SubCommand::with_name("set")
                .about("For username, set password")
                .arg(
                    Arg::with_name("username")
                        .help("Username")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("For username, get password")
                .arg(
                    Arg::with_name("username")
                        .help("Username")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .about("For username, delete password")
                .arg(
                    Arg::with_name("username")
                        .help("Username")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    let service = "keyring-cli";

    if let Some(set) = matches.subcommand_matches("set") {
        let username = set
            .value_of("username")
            .ok_or("You must specify a Username to set")?;
        let keyring = Entry::new(service, username);

        let password = read_password_from_tty(Some("Password: "))?;
        match keyring.set_password(&password[..]) {
            Ok(_) => println!("Password set for user \"{}\"", username),
            Err(e) => eprintln!("Error setting password for user '{}': {}", username, e),
        }
    }

    if let Some(get) = matches.subcommand_matches("get") {
        let username = get
            .value_of("username")
            .ok_or("You must specify a Username to get")?;
        let keyring = Entry::new(service, username);

        match keyring.get_password() {
            Ok(password) => println!("The password for user '{}' is '{}'", username, password),
            Err(e) => eprintln!("Error getting password for user '{}': {}", username, e),
        }
    }

    if let Some(delete) = matches.subcommand_matches("delete") {
        let username = delete
            .value_of("username")
            .ok_or("You must specify a Username to delete")?;
        let keyring = Entry::new(service, username);

        match keyring.delete_password() {
            Ok(_) => println!("Password deleted for user '{}'", username),
            Err(e) => eprintln!("Error deleting password for user '{}': {}", username, e),
        }
    }

    Ok(())
}
