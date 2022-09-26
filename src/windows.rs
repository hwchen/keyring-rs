use byteorder::{ByteOrder, LittleEndian};
use std::iter::once;
use std::mem::MaybeUninit;
use std::slice;
use std::str;
use winapi::shared::minwindef::FILETIME;
use winapi::shared::winerror::{
    ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND,
    ERROR_NO_SUCH_LOGON_SESSION,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::wincred::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_MAX_CREDENTIAL_BLOB_SIZE,
    CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH,
    CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, PCREDENTIALW, PCREDENTIAL_ATTRIBUTEW,
};

use crate::credential::WinCredential;
use crate::{Error as ErrorCode, Platform, PlatformCredential, Result};

pub fn platform() -> Platform {
    Platform::Windows
}

/// Windows has only one credential store, and each credential is identified
/// by a single string called the "target name".  But generic credentials
/// also have three pieces of metadata with suggestive names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

#[derive(Debug)]
pub struct Error(u32); // Windows error codes are long ints

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERROR_NO_SUCH_LOGON_SESSION => write!(f, "Windows ERROR_NO_SUCH_LOGON_SESSION"),
            ERROR_NOT_FOUND => write!(f, "Windows ERROR_NOT_FOUND"),
            ERROR_BAD_USERNAME => write!(f, "Windows ERROR_BAD_USERNAME"),
            ERROR_INVALID_FLAGS => write!(f, "Windows ERROR_INVALID_FLAGS"),
            ERROR_INVALID_PARAMETER => write!(f, "Windows ERROR_INVALID_PARAMETER"),
            err => write!(f, "Windows error code {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Create the default target credential for a keyring entry.  The caller
/// can provide an optional target parameter to influence the mapping.
///
/// If any of the provided strings are empty, the credential returned is
/// invalid, to prevent it being used.  This is because platform behavior
/// around empty strings for attributes is undefined.
pub fn default_target(
    platform: &Platform,
    target: Option<&str>,
    service: &str,
    username: &str,
) -> PlatformCredential {
    if service.is_empty() || username.is_empty() || target.unwrap_or("none").is_empty() {
        return PlatformCredential::Invalid;
    }
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let custom = if target.is_none() {
        "entry"
    } else {
        "custom entry"
    };
    let metadata = format!(
        "keyring-rs v{} {} for service '{}', user '{}'",
        VERSION, custom, service, username
    );
    match platform {
        Platform::Linux => PlatformCredential::Linux(LinuxCredential {
            collection: target.unwrap_or("default").to_string(),
            attributes: HashMap::from([
                ("service".to_string(), service.to_string()),
                ("username".to_string(), username.to_string()),
                ("application".to_string(), "rust-keyring".to_string()),
            ]),
            label: metadata,
        }),
        Platform::Windows => {
            if let Some(keychain) = target {
                PlatformCredential::Win(WinCredential {
                    // Note: Since Windows doesn't support multiple keychains,
                    // and since it's nice for clients to have control over
                    // the target_name directly, we use the `keychain` value
                    // as the target name if it's specified non-default.
                    username: username.to_string(),
                    target_name: keychain.to_string(),
                    target_alias: String::new(),
                    comment: metadata,
                })
            } else {
                PlatformCredential::Win(WinCredential {
                    // Note: default concatenation of user and service name is
                    // used because windows uses target_name as sole identifier.
                    // See the README for more rationale.  Also see this issue
                    // for Python: https://github.com/jaraco/keyring/issues/47
                    username: username.to_string(),
                    target_name: format!("{}.{}", username, service),
                    target_alias: String::new(),
                    comment: metadata,
                })
            }
        }
        Platform::MacOs => PlatformCredential::Mac(MacCredential {
            domain: target.into(),
            service: service.to_string(),
            account: username.to_string(),
        }),
        Platform::Ios => PlatformCredential::Ios(IosCredential {
            service: service.to_string(),
            account: username.to_string(),
        }),
    }
}

// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW
pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, password)?;
        let mut username = to_wstr(&map.username);
        let mut target_name = to_wstr(&map.target_name);
        let mut target_alias = to_wstr(&map.target_alias);
        let mut comment = to_wstr(&map.comment);
        // Password strings are converted to UTF-16, because that's the native
        // charset for Windows strings.  This allows editing of the password in
        // the Windows native UI.  But the storage for the credential is actually
        // a little-endian blob, because passwords can contain anything.
        let blob_u16 = to_wstr_no_null(password);
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);
        let blob_len = blob.len() as u32;
        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let persist = CRED_PERSIST_ENTERPRISE;
        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // TODO: Allow setting attributes on Windows credentials
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: target_alias.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };
        // raw pointer to credential, is coerced from &mut
        let pcredential: PCREDENTIALW = &mut credential;
        // Call windows API
        match unsafe { CredWriteW(pcredential, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, "")?;
        let target_name = to_wstr(&map.target_name);
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api call CredFree.
        let mut pcredential = MaybeUninit::uninit();
        let cred_type = CRED_TYPE_GENERIC;
        let result =
            unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, pcredential.as_mut_ptr()) };
        match result {
            0 => Err(decode_error()),
            _ => {
                let pcredential = unsafe { pcredential.assume_init() };
                // Dereferencing pointer to credential
                let credential: CREDENTIALW = unsafe { *pcredential };
                decode_attributes(map, &credential);
                let password = extract_password(&credential);
                // Free the credential
                unsafe {
                    CredFree(pcredential as *mut _);
                }
                password
            }
        }
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, "")?;
        let target_name = to_wstr(&map.target_name);
        let cred_type = CRED_TYPE_GENERIC;
        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

fn validate_attributes(map: &WinCredential, password: &str) -> Result<()> {
    if map.username.len() > CRED_MAX_USERNAME_LENGTH as usize {
        return Err(ErrorCode::TooLong(
            String::from("username"),
            CRED_MAX_USERNAME_LENGTH,
        ));
    }
    if map.target_name.len() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
        return Err(ErrorCode::TooLong(
            String::from("target name"),
            CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        ));
    }
    if map.target_alias.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(ErrorCode::TooLong(
            String::from("target alias"),
            CRED_MAX_STRING_LENGTH,
        ));
    }
    if map.comment.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(ErrorCode::TooLong(
            String::from("comment"),
            CRED_MAX_STRING_LENGTH,
        ));
    }
    if password.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(ErrorCode::TooLong(
            String::from("password"),
            CRED_MAX_CREDENTIAL_BLOB_SIZE,
        ));
    }
    Ok(())
}

fn decode_error() -> ErrorCode {
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => ErrorCode::NoEntry,
        ERROR_NO_SUCH_LOGON_SESSION => {
            ErrorCode::NoStorageAccess(Error(ERROR_NO_SUCH_LOGON_SESSION))
        }
        err => ErrorCode::PlatformFailure(Error(err)),
    }
}

fn decode_attributes(map: &mut WinCredential, credential: &CREDENTIALW) {
    map.username = unsafe { from_wstr(credential.UserName) };
    map.comment = unsafe { from_wstr(credential.Comment) };
    map.target_alias = unsafe { from_wstr(credential.TargetAlias) };
}

fn extract_password(credential: &CREDENTIALW) -> Result<String> {
    // get password blob
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    let blob = unsafe { slice::from_raw_parts(blob_pointer, blob_len) };
    // 3rd parties may write credential data with an odd number of bytes,
    // so we make sure that we don't try to decode those as utf16
    if blob.len() % 2 != 0 {
        let err = ErrorCode::BadEncoding(blob.to_vec());
        return Err(err);
    }
    // Now we know this _can_ be a UTF-16 string, so convert it to
    // as UTF-16 vector and then try to decode it.
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(blob, &mut blob_u16);
    String::from_utf16(&blob_u16).map_err(|_| ErrorCode::BadEncoding(blob.to_vec()))
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

unsafe fn from_wstr(ws: *const u16) -> String {
    // null pointer case, return empty string
    if ws.is_null() {
        return String::new();
    }
    // this code from https://stackoverflow.com/a/48587463/558006
    let len = (0..).take_while(|&i| *ws.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ws, len);
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;

    #[test]
    fn test_bad_password() {
        // the first malformed sequence can't be UTF-16 because it has an odd number of bytes.
        // the second malformed sequence has a first surrogate marker (0xd800) without a matching
        // companion (it's taken from the String::fromUTF16 docs).
        let odd_bytes = b"1".to_vec();
        let malformed_utf16 = [0xD834, 0xDD1E, 0x006d, 0x0075, 0xD800, 0x0069, 0x0063];
        let mut malformed_bytes: Vec<u8> = vec![0; malformed_utf16.len() * 2];
        LittleEndian::write_u16_into(&malformed_utf16, &mut malformed_bytes);
        for bytes in [&odd_bytes, &malformed_bytes] {
            let credential = make_platform_credential(bytes.clone());
            match extract_password(&credential) {
                Err(ErrorCode::BadEncoding(str)) => assert_eq!(&str, bytes),
                Err(other) => panic!(
                    "Bad password ({:?}) decode gave wrong error: {}",
                    bytes, other
                ),
                Ok(s) => panic!("Bad password ({:?}) decode gave results: {:?}", bytes, &s),
            }
        }
    }

    fn make_platform_credential(mut password: Vec<u8>) -> CREDENTIALW {
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: null_mut(),
            Comment: null_mut(),
            LastWritten: last_written,
            CredentialBlobSize: password.len() as u32,
            CredentialBlob: password.as_mut_ptr(),
            Persist: CRED_PERSIST_ENTERPRISE,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: null_mut(),
            UserName: null_mut(),
        }
    }

    #[test]
    fn test_bad_inputs() {
        let cred = WinCredential {
            username: "username".to_string(),
            target_name: "target_name".to_string(),
            target_alias: "target_alias".to_string(),
            comment: "comment".to_string(),
        };
        for (attr, len) in [
            ("username", CRED_MAX_USERNAME_LENGTH),
            ("target name", CRED_MAX_GENERIC_TARGET_NAME_LENGTH),
            ("target alias", CRED_MAX_STRING_LENGTH),
            ("comment", CRED_MAX_STRING_LENGTH),
            ("password", CRED_MAX_CREDENTIAL_BLOB_SIZE),
        ] {
            let long_string = generate_random_string(1 + len as usize);
            let mut bad_cred = cred.clone();
            let mut password = "password";
            match attr {
                "username" => bad_cred.username = long_string.clone(),
                "target name" => bad_cred.target_name = long_string.clone(),
                "target alias" => bad_cred.target_alias = long_string.clone(),
                "comment" => bad_cred.comment = long_string.clone(),
                "password" => password = &long_string,
                other => panic!("unexpected attribute: {}", other),
            }
            let map = PlatformCredential::Win(bad_cred);
            validate_attribute_too_long(set_password(&map, password), attr, len);
        }
    }

    fn validate_attribute_too_long(result: Result<()>, attr: &str, len: u32) {
        match result {
            Err(ErrorCode::TooLong(arg, val)) => {
                assert_eq!(&arg, attr, "Error names wrong attribute");
                assert_eq!(val, len, "Error names wrong limit");
            }
            Err(other) => panic!("Err not 'username too long': {}", other),
            Ok(_) => panic!("No error when {} too long", attr),
        }
    }

    fn generate_random_string(len: usize) -> String {
        // from the Rust Cookbook:
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }
}
