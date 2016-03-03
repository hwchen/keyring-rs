use ::KeyringError;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use rustc_serialize::hex::FromHex;

//TODO: hex password output handling
// currently no support for internet password.

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
        self.interactive_set(password)
            .or_else(|_| self.direct_set(password))
    }

    fn interactive_set(&self, password: &str) -> ::Result<()> {
        let security_command = &format!("{} -a '{}' -s '{}' -p '{}' -U\n",
                                     "add-generic-password",
                                     self.username,
                                     self.service,
                                     password)[..];

        let mut process = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("error spawning command process"); // Handle error

        process.stdin
            .as_mut() // for getting mut ref from Option
            .expect("stdin") // Option must be Some(_), so safe to unwrap
            .by_ref() // for providing ref for Write
            .write_all(security_command.as_bytes())
            .unwrap();

        if process.wait().unwrap().success() {
            Ok(())
        } else {
            Err(KeyringError::MacOsKeychainError)
        }
    }

    fn direct_set(&self, password: &str) -> ::Result<()> {
        let output = Command::new("security")
            .arg("add-generic-password")
            .arg("-a")
            .arg(self.username)
            .arg("-s")
            .arg(self.service)
            .arg("-p")
            .arg(password)
            .arg("-U")
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

    pub fn get_password(&self) -> ::Result<String> {
        let output = Command::new("security")
            .arg("find-generic-password")
            .arg("-w") // why not w? instead of g
            .arg("-a")
            .arg(self.username)
            .arg("-s")
            .arg(self.service)
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let output_string = String::from_utf8(output.stdout)
                        .unwrap().trim().to_owned();

                    // How do I know if it's hex? What if output happens to look
                    // like hex?
                    // I assume it uses \0x syntax. I can assume for now that the
                    // serialize library simply won't serialize a non-hex output.
                    // This should be as good as running a regex anyways.
                    match output_string.from_hex() {
                        Ok(from_hex_vec) => Ok(String::from_utf8(from_hex_vec).unwrap()),
                        Err(_) => Ok(output_string),
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

