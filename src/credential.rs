/*!
This module defines a plug and play model for platform-specific credential stores.
The model comprises two traits: `CredentialBuilder` for the store service
and `Credential` for the credentials produced by the service.
 */
use super::Result;
use std::any::Any;

/// This trait defines the API that all credentials must implement.
pub trait CredentialApi {
    /// Set a password in the underlying store
    fn set_password(&self, password: &str) -> Result<()>;
    /// Retrieve a password from the underlying store
    fn get_password(&self) -> Result<String>;
    /// Delete a password from the underlying store
    fn delete_password(&self) -> Result<()>;
    /// Cast the credential object to Any.  This allows clients
    /// to downcast the credential to its concrete type so they
    /// can do platform-specific things with it (e.g, unlock it)
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}

/// Credentials must be usable from multiple threads, and they must
/// be movable from thread to thread, so they must be Send and Sync.
pub type Credential = dyn CredentialApi + Send + Sync;

/// This trait defines the API that Credential Builders must implement.
pub trait CredentialBuilderApi {
    /// Build a platform credential for the given parameters
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>>;
    /// Cast the builder as type Any.  This is not so much for clients.
    /// as it is to allow us to derive a Debug trait for builders.
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for CredentialBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}

/// Credential Builders must be Sync so they can be invoked from
/// multiple threads simultaneously.  Although no one expects a
/// Credential Builder to be passed from one thread to another,
/// they are usually objects, so Send should be easy.
pub type CredentialBuilder = dyn CredentialBuilderApi + Send + Sync;
