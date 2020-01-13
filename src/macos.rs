use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::find_generic_password;

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
        SecKeychain::default()?.set_generic_password(
            self.service,
            self.username,
            password.as_bytes(),
        )?;

        Ok(())
    }

    pub fn get_password(&self) -> ::Result<String> {
        let (password_bytes, _) = find_generic_password(None, self.service, self.username)?;

        // Mac keychain allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keychain, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keychain by another library

        let password = try!(String::from_utf8(password_bytes.to_vec()));

        Ok(password)
    }

    pub fn delete_password(&self) -> ::Result<()> {
        let (_, item) = find_generic_password(None, self.service, self.username)?;

        item.delete();

        Ok(())
    }
}
