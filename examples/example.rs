extern crate keyring;

use keyring::Keychain;

fn main() {
    let keychain = Keychain::new("example-service", "example-username");
    keychain.set_password("example-pass").unwrap();
    let pass = keychain.get_password().unwrap();
    keychain.delete_password().unwrap();
    println!("Retrieved Password {}", pass);
}
