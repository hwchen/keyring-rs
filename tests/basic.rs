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
    entry
        .set_password(in_pass)
        .expect("Couldn't set empty password");
    let out_pass = entry.get_password().expect("Couldn't get empty password");
    assert_eq!(in_pass, out_pass);
    entry
        .delete_password()
        .expect("Couldn't delete empty password");
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
    entry
        .set_password(password)
        .expect("Couldn't set ascii password");
    let stored_password = entry.get_password().expect("Couldn't get ascii password");
    assert_eq!(stored_password, password);
    entry
        .delete_password()
        .expect("Couldn't delete ascii password");
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let password = "このきれいな花は桜です";
    entry
        .set_password(password)
        .expect("Couldn't set non-ascii password");
    let stored_password = entry
        .get_password()
        .expect("Couldn't get non-ascii password");
    assert_eq!(stored_password, password);
    entry
        .delete_password()
        .expect("Couldn't delete non-ascii password");
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_update() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Couldn't set first password");
    let stored_password = entry.get_password().expect("Couldn't get first password");
    assert_eq!(stored_password, password);
    let password = "このきれいな花は桜です";
    entry
        .set_password(password)
        .expect("Couldn't set second password");
    let stored_password = entry.get_password().expect("Couldn't get second password");
    assert_eq!(stored_password, password);
    entry
        .delete_password()
        .expect("Couldn't delete second password");
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_independent_credential_and_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name);
    let password = "このきれいな花は桜です";
    entry
        .set_password(password)
        .expect("Couldn't set cred non-ascii password");
    let (stored_password, credential1) = entry
        .get_password_and_credential()
        .expect("Couldn't get 1st cred");
    assert_eq!(stored_password, password);
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Couldn't set cred non-ascii password");
    let (stored_password, credential2) = entry
        .get_password_and_credential()
        .expect("Couldn't get 2nd cred");
    assert_eq!(stored_password, password);
    assert_eq!(credential1, credential2);
    entry
        .delete_password()
        .expect("Couldn't delete cred password");
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
    entry1
        .set_password(&password1)
        .expect("Couldn't 1st entry password");
    let password2 = entry2
        .get_password()
        .expect("Couldn't get 2nd entry password");
    assert_eq!(password2, password1);
    entry1
        .delete_password()
        .expect("Couldn't delete 1st entry password");
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
