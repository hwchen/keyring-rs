mod common;

use serial_test::serial;

use keyring::{Entry, Error};

doc_comment::doctest!("../README.md");

#[test]
#[serial]
fn test_empty_keyring() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let entry = Entry::new(&service, &username);
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Read a password from a non-existent platform item"
    )
}

#[test]
#[serial]
fn test_empty_password_input() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let entry = Entry::new(&service, &username);
    let pass = "";
    entry.set_password(pass).unwrap();
    let out = entry.get_password().unwrap();
    assert_eq!(pass, out, "Stored and retrieved passwords don't match");
    entry.delete_password().unwrap();
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_ascii_password() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let entry = Entry::new(&service, &username);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_non_ascii_password() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let entry = Entry::new(&service, &username);
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_credential() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let entry = Entry::new(&service, &username);
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let (stored_password, credential1) = entry.get_password_and_credential().unwrap();
    assert_eq!(stored_password, password);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let (stored_password, credential2) = entry.get_password_and_credential().unwrap();
    assert_eq!(stored_password, password);
    assert_eq!(credential1, credential2);
    entry.delete_password().unwrap();
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}
