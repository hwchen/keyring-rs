use keyring::{credential::default_target, platform, Entry, Error};

doc_comment::doctest!("../README.md");

#[test]
fn test_empty_keyring() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_empty_password_input() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let in_pass = "";
    entry.set_password(in_pass).unwrap();
    let out_pass = entry.get_password().unwrap();
    assert_eq!(in_pass, out_pass);
    entry.delete_password().unwrap();
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}

#[test]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_independent_credential_and_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
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

#[test]
fn test_same_target() {
    let name = generate_random_string();
    let entry1 = Entry::new(&name, &name);
    let credential = default_target(&platform(), None, &name, &name);
    let entry2 = Entry::new_with_credential(&credential).unwrap();
    let password1 = generate_random_string();
    entry1.set_password(&password1).unwrap();
    let password2 = entry2.get_password().unwrap();
    assert_eq!(password2, password1);
    entry1.delete_password().unwrap();
    assert!(matches!(entry2.delete_password(), Err(Error::NoEntry)))
}

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
