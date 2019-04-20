extern crate keyring;

use keyring::Keyring;

use std::error::Error;

fn main() -> Result<(), Box<Error>> {
    let keyring = Keyring::new("example-service", "example-username");
    keyring.set_password("example-pass")?;
    let pass = keyring.get_password()?;
    keyring.delete_password()?;
    println!("Retrieved Password {}", pass);

    Ok(())
}
