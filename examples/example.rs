extern crate keyring;

use keyring::Keyring;

fn main() {
    let keyring = Keyring::new("example-service", "example-username");
    keyring.set_password("example-pass").unwrap();
    let pass = keyring.get_password().unwrap();
    keyring.delete_password().unwrap();
    println!("Retrieved Password {}", pass);
}
