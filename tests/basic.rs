use keyring::Entry;

doc_comment::doctest!("../README.md");

use serial_test::serial;

#[test]
#[serial]
fn test_empty_keyring() {
    let service = generate_random_string();
    let username = generate_random_string();
    let entry = Entry::new(&service, &username);
    assert!(
        entry.get_password().is_err(),
        "Read a password from a non-existent platform item"
    )
}

#[test]
#[serial]
fn test_empty_password_input() {
    let service = generate_random_string();
    let username = generate_random_string();
    let entry = Entry::new(&service, &username);
    let pass = "";
    entry.set_password(pass).unwrap();
    let out = entry.get_password().unwrap();
    assert_eq!(pass, out, "Stored and retrieved passwords don't match");
    entry.delete_password().unwrap();
    assert!(
        entry.get_password().is_err(),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_ascii_password() {
    let service = generate_random_string();
    let username = generate_random_string();
    let entry = Entry::new(&service, &username);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(
        entry.get_password().is_err(),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_non_ascii_password() {
    let service = generate_random_string();
    let username = generate_random_string();
    let entry = Entry::new(&service, &username);
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(
        entry.get_password().is_err(),
        "Able to read a deleted password"
    )
}

#[test]
#[serial]
fn test_round_trip_credential() {
    let service = generate_random_string();
    let username = generate_random_string();
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
        entry.get_password().is_err(),
        "Able to read a deleted password"
    )
}

// TODO: write tests for erroneous input
// This might be better done in a separate test file.

// TODO: write tests for custom mappers.
// This might be better done in a separate test file.

// utility
fn generate_random_string() -> String {
    // from the Rust Cookbook:
    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}
