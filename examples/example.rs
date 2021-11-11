extern crate keyring;

use keyring::{Keyring, Result};

fn main() -> Result<()> {
    let username = "example-username";
    let service = "example-service";
    let password = "example-password";
    let keyring = Keyring::new(service, username);
    keyring.set_password(password)?;
    let stored_password = keyring.get_password()?;
    assert_eq!(
        password, stored_password,
        "Stored and retrieved passwords don't match"
    );
    keyring.delete_password()?;
    assert!(
        keyring.get_password().is_err(),
        "No error retrieving password after deletion"
    );

    Ok(())
}
