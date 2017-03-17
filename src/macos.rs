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
        let output = Command::new("security")
            .arg("find-generic-password")
            .arg("-g") // g instead of g gets string with " and hex without "
            .arg("-a")
            .arg(self.username)
            .arg("-s")
            .arg(self.service)
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let output_string = String::from_utf8(output.stderr).unwrap().trim().to_owned();
                    if output_string.len() <= 10 {
                        // It's an empty string
                        Ok("".to_owned())
                    } else {
                        if is_not_hex_output(&output_string) {
                            // slice "password: \"" off the front and " off back
                            Ok(output_string[11..output_string.len()-1].to_string())
                        } else {
                            // slice "password: 0x" off the front
                            let bytes = output_string[12..]
                                .from_hex()
                                .expect("error reading hex output");

                            Ok(
                                String::from_utf8(bytes)
                                    .expect("error converting hex to utf8")
                            )
                        }
                    }
                } else {
                    Err(KeyringError::MacOsKeychainError)
                }
            },
            _ => Err(KeyringError::MacOsKeychainError)
        }
    }

    pub fn delete_password(&self) -> ::Result<()> {
        let output = Command::new("security")
            .arg("delete-generic-password")
            .arg("-a")
            .arg(self.username)
            .arg("-s")
            .arg(self.service)
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    Ok(())
                } else {
                    Err(KeyringError::MacOsKeychainError)
                }
            },
            _ => Err(KeyringError::MacOsKeychainError)
        }
    }
}

fn is_not_hex_output(s: &str) -> bool {
    assert!(s.len() >= 11);
    const MATCH_START: &'static str = "password: \"";
    const MATCH_END: char = '\"';

    s.starts_with(MATCH_START) && s.ends_with(MATCH_END)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_password_output_is_not_hex() {
        let output_1 = r#"password: "0xE5A4A7E6A0B9""#;
        let output_2 = r#"password: 0xE5A4A7E6A0B9"#;

        assert_eq!(is_not_hex_output(output_1), true);
        assert_eq!(is_not_hex_output(output_2), false);
    }

    #[test]
    fn test_special_char_passwords() {
        // need to worry about unlocking keychain?

        let password_1 = "大根";
        let password_2 = "0xE5A4A7E6A0B9"; // Above in hex string

        let keyring = Keyring::new("testuser", "testservice");
        keyring.set_password(password_1).unwrap();
        let res_1 = keyring.get_password().unwrap();
        assert_eq!(res_1, password_1);

        keyring.set_password(password_2).unwrap();
        let res_2 = keyring.get_password().unwrap();
        assert_eq!(res_2, password_2);

        keyring.delete_password().unwrap();
    }
}
