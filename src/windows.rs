use winapi::wincred::{CREDENTIALW, PCREDENTIALW};
use winapi::winnt::LPCWSTR;
use winapi::minwindef::{BOOL, DWORD};

use advapi32::{CredReadW};

// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32
// PCREDENTIALW = *mut CREDENTIALW
//

use advapi32;

use ::KeyringError;

pub struct Keyring<'a> {
    attributes: Vec<(&'a str, &'a str)>,
    service: &'a str,
    username: &'a str,
}

impl<'a> Keyring<'a> {

    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        let attributes = vec![
            ("application", "rust-keyring"),
            ("service", service),
            ("username", username),
        ];
        Keyring {
            attributes: attributes,
            service: service,
            username: username,
        }
    }

    pub fn set_password(&self, password: &str) -> ::Result<()> {
        // CredWriteW
//        let credential = CREDENTIALW {
//            Flags:
//            Type:
//            TargetName:
//            Comment:
//            LastWritten:
//            CredentialBlobSize:
//            CredentialBlob:
//            Persist:
//            AttributeCount:
//            Attributes:
//            TargetAlias:
//            UserName:
//        }
        let pcredential: Box<CREDENTIALW> = Box::new(CREDENTIALW{});
        let pcredential: PCREDENTIALW = Box::into_raw(credential);

        let credential_arg: Box<PCREDENTIALW> = Box::new(CredentialW{});
        let credential_arg: *mut PCREDENTIALW = Box::into_raw(credential_arg);

        match CredReadW(target_name, cred_type, 0, credential_arg) {
            0 => Err(KeyringError::WindowsVaultError),
            _ => Ok(()),
        }
    }

    pub fn get_password(&self) -> ::Result<String> {
        // CredReadW
        let credential = PCREDENTIALW;
        Ok("".to_owned())
    }

    pub fn delete_password(&self) -> ::Result<()> {
        // CredDeleteW
        Ok(())
    }
}

