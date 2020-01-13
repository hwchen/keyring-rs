extern crate clap;
extern crate keyring;
extern crate rpassword;

use clap::{App, Arg, SubCommand};
use keyring::Keyring;
use rpassword::read_password;

use std::error::Error;

fn main() -> Result<(), Box<Error>> {
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

    let service = "keyring-rs";

    if let Some(set) = matches.subcommand_matches("set") {
        let username = set.value_of("username").ok_or("No username found to set")?;
        let keyring = Keyring::new(service, username);

        println!("Enter Password");
        let password = read_password()?;
        //println!("Password is: {:?}", password);

        match keyring.set_password(&password[..]) {
            Ok(_) => println!("Password set for user \"{}\"", username),
            _ => println!("Could not find password for user \"{}\"", username),
        }
    }

    if let Some(get) = matches.subcommand_matches("get") {
        let username = get.value_of("username").ok_or("No username found to get")?;
        let keyring = Keyring::new(service, username);

        match keyring.get_password() {
            Ok(password) => println!("The password for user \"{}\" is \"{}\"", username, password),
            _ => println!("Could not find password for user \"{}\"", username),
        }
    }

    if let Some(delete) = matches.subcommand_matches("delete") {
        let username = delete
            .value_of("username")
            .ok_or("No usernanme found to delete")?;
        let keyring = Keyring::new(service, username);

        match keyring.delete_password() {
            Ok(_) => println!("Password deleted for user \"{}\"", username),
            _ => println!("Could not delete password for user \"{}\"", username),
        }
    }

    Ok(())
}
