use keyring::{Entry, Error};

#[no_mangle]
extern "C" fn test() {
    test_empty_keyring();
    test_empty_password_input();
    test_round_trip_ascii_password();
    test_round_trip_non_ascii_password();
    test_update_password();
}

fn test_empty_keyring() {
    let name = "test_empty_keyring".to_string();
    let entry = Entry::new(&name, &name).expect("Failed to create entry");
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

fn test_empty_password_input() {
    let name = "test_empty_password_input".to_string();
    let entry = Entry::new(&name, &name).expect("Failed to create entry");
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

fn test_round_trip_ascii_password() {
    let name = "test_round_trip_ascii_password".to_string();
    let entry = Entry::new(&name, &name).expect("Failed to create entry");
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

fn test_round_trip_non_ascii_password() {
    let name = "test_round_trip_non_ascii_password".to_string();
    let entry = Entry::new(&name, &name).expect("Failed to create entry");
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

fn test_update_password() {
    let name = "test_update_password".to_string();
    let entry = Entry::new(&name, &name).expect("Failed to create entry");
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    let password = "このきれいな花は桜です";
    entry.set_password(password).unwrap();
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    entry.delete_password().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}
