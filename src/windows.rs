use crate::error::{KeyringError, Result};
use byteorder::{ByteOrder, LittleEndian};
use std::ffi::OsStr;
use std::iter::once;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::slice;
use std::str;
use winapi::shared::minwindef::FILETIME;
use winapi::shared::winerror::{ERROR_NOT_FOUND, ERROR_NO_SUCH_LOGON_SESSION};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::wincred::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC, PCREDENTIALW, PCREDENTIAL_ATTRIBUTEW,
};

// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW

// Note: decision to concatenate user and service name
// to create target is because Windows assumes one user
// per service. See issue here: https://github.com/jaraco/keyring/issues/47

pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
}

pub struct TargetCredential {
    pub username: String,
    pub password: String,
}

impl<'a> Keyring<'a> {
    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring { service, username }
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        // Setting values of credential

        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let target_name: String = if self.username.is_empty() {
            String::from(self.service)
        } else {
            [self.username, self.service].join(".")
        };
        let mut target_name = to_wstr(&target_name);

        // empty string for comments, and target alias,
        // I don't use here
        let mut empty_str = to_wstr("");

        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        // In order to allow editing of the password
        // from within Windows, the password must be
        // transformed into utf16. (but because it's a
        // blob, it then needs to be passed to windows
        // as an array of bytes).
        let blob_u16 = to_wstr_no_null(password);
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);

        let blob_len = blob.len() as u32;
        let persist = CRED_PERSIST_ENTERPRISE;
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut username = to_wstr(self.username);

        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: empty_str.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: empty_str.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };
        // raw pointer to credential, is coerced from &mut
        let pcredential: PCREDENTIALW = &mut credential;

        // Call windows API
        match unsafe { CredWriteW(pcredential, 0) } {
            0 => Err(KeyringError::WindowsVaultError),
            _ => Ok(()),
        }
    }

    pub fn set_credential(&self, password: &str, username: &str) -> Result<()> {
        // Setting values of credential

        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let target_name = String::from(self.service);
        let mut target_name = to_wstr(&target_name);

        // empty string for comments, and target alias,
        // I don't use here
        let mut empty_str = to_wstr("");

        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        // In order to allow editing of the password
        // from within Windows, the password must be
        // transformed into utf16. (but because it's a
        // blob, it then needs to be passed to windows
        // as an array of bytes).
        let blob_u16 = to_wstr_no_null(password);
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);

        let blob_len = blob.len() as u32;
        let persist = CRED_PERSIST_ENTERPRISE;
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut username = to_wstr(username);

        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: empty_str.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: empty_str.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };
        // raw pointer to credential, is coerced from &mut
        let pcredential: PCREDENTIALW = &mut credential;

        // Call windows API
        match unsafe { CredWriteW(pcredential, 0) } {
            0 => Err(KeyringError::WindowsVaultError),
            _ => Ok(()),
        }
    }

    pub fn get_password(&self) -> Result<String> {
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api
        // call CredFree.
        let mut pcredential = MaybeUninit::uninit();

        let target_name: String = [self.username, self.service].join(".");
        let target_name = to_wstr(&target_name);

        let cred_type = CRED_TYPE_GENERIC;

        // Windows api call
        match unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, pcredential.as_mut_ptr()) } {
            0 => unsafe {
                match GetLastError() {
                    ERROR_NOT_FOUND => Err(KeyringError::NoPasswordFound),
                    ERROR_NO_SUCH_LOGON_SESSION => Err(KeyringError::NoBackendFound),
                    _ => Err(KeyringError::WindowsVaultError),
                }
            },
            _ => {
                let pcredential = unsafe { pcredential.assume_init() };
                // Dereferencing pointer to credential
                let credential: CREDENTIALW = unsafe { *pcredential };

                // get blob by creating an array from the pointer
                // and the length reported back from the credential
                let blob_pointer: *const u8 = credential.CredentialBlob;
                let blob_len: usize = credential.CredentialBlobSize as usize;

                // blob needs to be transformed from bytes to an
                // array of u16, which will then be transformed into
                // a utf8 string. As noted above, this is to allow
                // editing of the password from within the vault order
                // or other windows programs, which operate in utf16
                let blob: &[u8] = unsafe { slice::from_raw_parts(blob_pointer, blob_len) };
                let mut blob_u16 = vec![0; blob_len / 2];
                LittleEndian::read_u16_into(&blob, &mut blob_u16);

                // Now can get utf8 string from the array
                let password = String::from_utf16(&blob_u16)
                    .map(|pass| pass.to_string())
                    .map_err(|_| KeyringError::WindowsVaultError);

                // Free the credential
                unsafe {
                    CredFree(pcredential as *mut _);
                }

                password
            }
        }
    }

    pub fn get_credential(&self) -> Result<TargetCredential> {
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api
        // call CredFree.
        let mut pcredential = MaybeUninit::uninit();

        let target_name: String = String::from(self.service);
        let target_name = to_wstr(&target_name);

        let cred_type = CRED_TYPE_GENERIC;

        // Windows api call
        match unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, pcredential.as_mut_ptr()) } {
            0 => unsafe {
                match GetLastError() {
                    ERROR_NOT_FOUND => Err(KeyringError::NoPasswordFound),
                    ERROR_NO_SUCH_LOGON_SESSION => Err(KeyringError::NoBackendFound),
                    _ => Err(KeyringError::WindowsVaultError),
                }
            },
            _ => {
                let pcredential = unsafe { pcredential.assume_init() };
                // Dereferencing pointer to credential
                let credential: CREDENTIALW = unsafe { *pcredential };

                // get blob by creating an array from the pointer
                // and the length reported back from the credential
                let blob_pointer: *const u8 = credential.CredentialBlob;
                let blob_len: usize = credential.CredentialBlobSize as usize;

                // blob needs to be transformed from bytes to an
                // array of u16, which will then be transformed into
                // a utf8 string. As noted above, this is to allow
                // editing of the password from within the vault order
                // or other windows programs, which operate in utf16
                let blob: &[u8] = unsafe { slice::from_raw_parts(blob_pointer, blob_len) };
                let mut blob_u16 = vec![0; blob_len / 2];
                LittleEndian::read_u16_into(&blob, &mut blob_u16);

                // Now can get utf8 string from the array
                let password = String::from_utf16(&blob_u16)
                    .map(|pass| pass.to_string());

                // get the username by converting credential.UserName
                // into a fat pointer, then convert from utf16 to a
                // regular utf8 string
                let user_lpwstr = credential.UserName;
                let user_slice = unsafe {
                    let len = (0..).take_while(|&i| *user_lpwstr.offset(i) != 0).count();
                    std::slice::from_raw_parts(user_lpwstr, len)
                };
                let username = String::from_utf16(&user_slice)
                    .map(|user| user.to_string());

                // Free the credential
                unsafe {
                    CredFree(pcredential as *mut _);
                }

                if username.is_err() || password.is_err() {
                    Err(KeyringError::WindowsVaultError)
                } else {
                    Ok(TargetCredential {
                        username: username.unwrap(),
                        password: password.unwrap(),
                    })
                }
            }
        }
    }

    pub fn delete_password(&self) -> Result<()> {
        let target_name: String = [self.username, self.service].join(".");

        let cred_type = CRED_TYPE_GENERIC;
        let target_name = to_wstr(&target_name);

        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => unsafe {
                match GetLastError() {
                    ERROR_NOT_FOUND => Err(KeyringError::NoPasswordFound),
                    ERROR_NO_SUCH_LOGON_SESSION => Err(KeyringError::NoBackendFound),
                    _ => Err(KeyringError::WindowsVaultError),
                }
            },
            _ => Ok(()),
        }
    }
}

// helper function for turning utf8 strings to windows
// utf16
fn to_wstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let password_1 = "大根";
        let password_2 = "0xE5A4A7E6A0B9"; // Above in hex string

        let keyring = Keyring::new("testservice", "testuser");
        keyring.set_password(password_1).unwrap();
        let res_1 = keyring.get_password().unwrap();
        println!("{}:{}", res_1, password_1);
        assert_eq!(res_1, password_1);

        keyring.set_password(password_2).unwrap();
        let res_2 = keyring.get_password().unwrap();
        println!("{}:{}", res_2, password_2);
        assert_eq!(res_2, password_2);

        keyring.delete_password().unwrap();
    }

    #[test]
    fn test_no_password() {
        let keyring = Keyring::new("testservice", "test-no-password");
        let result = keyring.get_password();
        match result {
            Ok(_) => panic!("expected KeyringError::NoPassword, got Ok"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }

        let result = keyring.delete_password();
        match result {
            Ok(_) => panic!("expected Err(KeyringError::NoPassword), got Ok()"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }
    }
}
