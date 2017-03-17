use ::KeyringError;
use std::io::Write;
use std::process::{Command, Stdio};
use rustc_serialize::hex::FromHex;
use security_framework::os::macos::passwords::{find_generic_password, set_generic_password, delete_generic_password};

pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
}

// Eventually try to get collection into the Keyring struct?
impl<'a> Keyring<'a> {

    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring {
            service: service,
            username: username,
        }
    }

    pub fn set_password(&self, password: &str) -> ::Result<()> {
        try!(set_generic_password(None, self.service, self.username, password.as_bytes()));

        Ok(())
    }

    pub fn get_password(&self) -> ::Result<String> {
        let (password_bytes, _) = try!(find_generic_password(None, self.service, self.username));

        // Mac keychain allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keychain, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keychain by another library

        let password = try!(String::from_utf8(password_bytes));

        Ok(password)
    }

    pub fn delete_password(&self) -> ::Result<()> {
        try!(delete_generic_password(None, self.service, self.username));

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static TEST_SERVICE: &'static str = "test.keychain-rs.io";
    static TEST_USER: &'static str = "user@keychain-rs.io";
    static TEST_ASCII_PASSWORD: &'static str = "my_password";
    static TEST_NON_ASCII_PASSWORD: &'static str = "大根";

    #[test]
    fn test_add_ascii_password() {
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);

        keyring.set_password(TEST_ASCII_PASSWORD).unwrap();

        keyring.delete_password().unwrap();
    }

    #[test]
    fn test_round_trip_ascii_password() {
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);

        keyring.set_password(TEST_ASCII_PASSWORD).unwrap();

        let stored_password = keyring.get_password().unwrap();

        assert_eq!(stored_password, TEST_ASCII_PASSWORD);

        keyring.delete_password().unwrap();
    }

    #[test]
    fn test_add_non_ascii_password() {
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);

        keyring.set_password(TEST_NON_ASCII_PASSWORD).unwrap();

        keyring.delete_password().unwrap();
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);

        keyring.set_password(TEST_NON_ASCII_PASSWORD).unwrap();

        let stored_password = keyring.get_password().unwrap();

        assert_eq!(stored_password, TEST_NON_ASCII_PASSWORD);

        keyring.delete_password().unwrap();
    }
}
