pub use security_framework::base::Error;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// iOS credentials all go in the user keychain identified by service and account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosCredential {
    pub service: String,
    pub account: String,
}

impl CredentialApi for IosCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        set_generic_password(&self.service, &self.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        let password_bytes =
            get_generic_password(&self.service, &self.account).map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    }

    fn delete_password(&self) -> Result<()> {
        delete_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl IosCredential {
    /// Construct a credential from the underlying platform credential
    /// On Ios, this is basically a no-op, because we don't keep any extra attributes.
    /// But at least we make sure the underlying platform credential exists.
    pub fn get_credential(&self) -> Result<Self> {
        get_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(self.clone())
    }

    /// Create the platform credential for a Ios keychain entry.
    ///
    /// A target string is interpreted as the keychain to use for the entry.
    ///
    /// The builder will fail if the service or user strings are empty.
    /// This is because Ios platform behavior around empty strings for attributes
    /// is that they act as wildcards, so there is no way to look up a specific
    /// credential that has an empty service or user string.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(ErrorCode::Invalid(
                "service".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::Invalid(
                "user".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if let Some(target) = target {
            if target.to_ascii_lowercase() != "default" {
                return Err(ErrorCode::Invalid(
                    "target".to_string(),
                    "only 'default' is allowed".to_string(),
                ));
            }
        }
        Ok(Self {
            service: service.to_string(),
            account: user.to_string(),
        })
    }
}

pub struct IosCredentialBuilder {}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(IosCredentialBuilder {})
}

impl CredentialBuilderApi for IosCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(IosCredential::new_with_target(
            target, service, user,
        )?))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The Ios error codes used here are from:
/// https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}
