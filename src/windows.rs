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

use crate::{Error as KeyError, KeyringError, Platform, PlatformIdentity, Result};

pub fn platform() -> Platform {
    Platform::Windows
}

#[derive(Debug)]
pub struct Error(u32); // Windows error codes are long ints

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERROR_NO_SUCH_LOGON_SESSION => write!(f, "Windows ERROR_NO_SUCH_LOGON_SESSION"),
            ERROR_NOT_FOUND => write!(f, "Windows ERROR_NOT_FOUND"),
            err => write!(f, "Windows error code {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW
pub fn set_password(map: &PlatformIdentity, password: &str) -> Result<()> {
    if let PlatformIdentity::Win(map) = map {
        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let mut target_name = to_wstr(&map.target_name);
        // empty string for comments, and target alias, neither of which we set
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
        let mut username = to_wstr(&map.username);
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
            0 => match unsafe { GetLastError() } {
                ERROR_NO_SUCH_LOGON_SESSION => Err(KeyError::new_from_platform(
                    KeyringError::NoStorage,
                    Error(ERROR_NO_SUCH_LOGON_SESSION),
                )),
                err => Err(KeyError::new_from_platform(
                    KeyringError::PlatformFailure,
                    Error(err),
                )),
            },
            _ => Ok(()),
        }
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}

pub fn get_password(map: &PlatformIdentity) -> Result<String> {
    if let PlatformIdentity::Win(map) = map {
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api
        // call CredFree.
        let mut pcredential = MaybeUninit::uninit();
        let target_name = to_wstr(&map.target_name);
        let cred_type = CRED_TYPE_GENERIC;
        // Windows api call
        match unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, pcredential.as_mut_ptr()) } {
            0 => match unsafe { GetLastError() } {
                ERROR_NOT_FOUND => Err(KeyError::new_from_platform(
                    KeyringError::NoEntry,
                    Error(ERROR_NOT_FOUND),
                )),
                ERROR_NO_SUCH_LOGON_SESSION => Err(KeyError::new_from_platform(
                    KeyringError::NoStorage,
                    Error(ERROR_NO_SUCH_LOGON_SESSION),
                )),
                err => Err(KeyError::new_from_platform(
                    KeyringError::PlatformFailure,
                    Error(err),
                )),
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
                // editing of the password from within the vault
                // or other windows programs, which operate in utf16
                let blob: &[u8] = unsafe { slice::from_raw_parts(blob_pointer, blob_len) };
                let mut blob_u16 = vec![0; blob_len / 2];
                LittleEndian::read_u16_into(blob, &mut blob_u16);
                // Now can get utf8 string from the array  The only way this
                // can fail is if a 3rd party wrote a malformed credential.
                let password = String::from_utf16(&blob_u16)
                    .map_err(|_| KeyError::new(KeyringError::BadEncoding));
                // Free the credential
                unsafe {
                    CredFree(pcredential as *mut _);
                }
                password
            }
        }
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}

pub fn delete_password(map: &PlatformIdentity) -> Result<()> {
    if let PlatformIdentity::Win(map) = map {
        let cred_type = CRED_TYPE_GENERIC;
        let target_name = to_wstr(&map.target_name);
        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => unsafe {
                match GetLastError() {
                    ERROR_NOT_FOUND => Err(KeyringError::NoEntry.into()),
                    ERROR_NO_SUCH_LOGON_SESSION => Err(KeyringError::NoStorage.into()),
                    _ => Err(KeyringError::PlatformFailure.into()),
                }
            },
            _ => Ok(()),
        }
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}

// helper function for turning utf8 strings to windows utf16
fn to_wstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}
fn to_wstr_no_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attrs::default_identity_mapper;
    use crate::Platform;

    #[test]
    fn test_basic() {
        let password_1 = "大根";
        let password_2 = "0xE5A4A7E6A0B9"; // Above in hex string
        let map = default_identity_mapper(Platform::Windows, "test-service", "test-user");

        set_password(&map, password_1).unwrap();
        let response_1 = get_password(&map).unwrap();
        assert_eq!(
            response_1, password_1,
            "Stored and retrieved passwords don't match"
        );

        set_password(&map, password_2).unwrap();
        let response_2 = get_password(&map).unwrap();
        assert_eq!(
            response_2, password_2,
            "Stored and retrieved passwords don't match"
        );

        delete_password(&map).unwrap();
        assert!(
            get_password(&map).is_err(),
            "Able to read a deleted password"
        )
    }

    #[test]
    fn test_no_password() {
        let map = default_identity_mapper(Platform::Windows, "testservice", "test-no-password");
        let result = get_password(&map);
        match result {
            Ok(_) => panic!("expected KeyringError::NoPassword, got Ok"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }

        let result = delete_password(&map);
        match result {
            Ok(_) => panic!("expected Err(KeyringError::NoPassword), got Ok()"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }
    }
}
