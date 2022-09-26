/*!
Defines the credential model implemented by platform stores.

The `Credential` trait, defined here, is what this crate expects a platform store to implement.
 */
use super::Result;
use std::any::Any;

/// This is the trait that all platform-specific credentials implement.
pub trait Credential {
    fn set_password(&self, password: &str) -> Result<()>;
    fn get_password(&self) -> Result<String>;
    fn delete_password(&self) -> Result<()>;
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for dyn Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}

/// Platform-specific stores each implement a CredentialBuilder.
pub trait CredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str)
        -> Result<Box<dyn Credential>>;
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for dyn CredentialBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}
