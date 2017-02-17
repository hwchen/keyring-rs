use ::KeyringError;
use advapi32::{CredFree, CredDeleteW, CredReadW, CredWriteW};
use std::ffi::OsStr;
use std::iter::once;
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::slice;
use std::str;
use winapi::minwindef::FILETIME;
use winapi::wincred::{
    CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC,
    CREDENTIALW,
    PCREDENTIAL_ATTRIBUTEW,
    PCREDENTIALW,
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

impl<'a> Keyring<'a> {

    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring {
            service: service,
            username: username,
        }
    }

    pub fn set_password(&self, password: &str) -> ::Result<()> {
        // Setting values of credential

        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let target_name: String = [
            self.username,
            self.service
        ].join(".");
        let mut target_name = to_wstr(&target_name);

        // empty string for comments, and target alias,
        // I don't use here
        let mut empty_str = to_wstr("");

        // Ignored by CredWriteW
        let last_written = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
        };

        let mut blob = password.as_bytes().to_vec();
        let blob_len = blob.len() as u32;
        let persist = CRED_PERSIST_ENTERPRISE;
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = unsafe { mem::uninitialized() };
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
        match unsafe{ CredWriteW(pcredential, 0) } {
            0 => Err(KeyringError::WindowsVaultError),
            _ => Ok(())
        }
    }

    pub fn get_password(&self) -> ::Result<String> {
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api
        // call CredFree.
        let mut pcredential: PCREDENTIALW = unsafe {
            mem::uninitialized()
        };

        let target_name: String = [
            self.username,
            self.service
        ].join(".");
        let target_name = to_wstr(&target_name);

        let cred_type = CRED_TYPE_GENERIC;

        // Windows api call
        match unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, &mut pcredential) } {
            0 => Err(KeyringError::WindowsVaultError),
            _ => {
                // Dereferencing pointer to credential
                let credential: CREDENTIALW = unsafe { *pcredential };
                
                // get blob by creating an array from the pointer
                // and the length reported back from the credential
                let blob_pointer: *const u8 = credential.CredentialBlob;
                let blob_len: usize = credential.CredentialBlobSize as usize;
                let blob: &[u8] = unsafe {
                    slice::from_raw_parts(blob_pointer, blob_len)
                };

                // Now can get utf8 string from the array
                let password = str::from_utf8(blob)
                    .map(|pass| {
                        pass.to_string()
                    })
                    .map_err(|_| {
                        KeyringError::WindowsVaultError
                    });

                // Free the credential
                unsafe { CredFree(pcredential as *mut c_void); }
                
                password
            },
        }

    }

    pub fn delete_password(&self) -> ::Result<()> {
        let target_name: String = [
            self.username,
            self.service
        ].join(".");

        let cred_type = CRED_TYPE_GENERIC;
        let target_name = to_wstr(&target_name);

        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => Err(KeyringError::WindowsVaultError),
            _ => Ok(()),
        }
    }
}

// helper function for turning utf8 strings to windows
// utf16 
fn to_wstr(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(once(0))
        .collect()
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
}
