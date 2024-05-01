/*!

# iOS Keychain credential store

iOS credential stores are called Keychains.  On iOS there is only one of these.
Generic credentials on iOS can be identified by a large number of _key/value_ attributes;
this module (currently) uses only the _account_ and _name_ attributes.

For a given service/user pair,
this module targets a generic credential in the User (login) keychain
whose _account_ is the user and and whose _name_ is the service.
Because of a quirk in the iOS keychain services API, neither the _account_
nor the _name_ may be the empty string. (Empty strings are treated as
wildcards when looking up credentials by attribute value.)

On iOS, the target parameter is ignored, because there is only one keychain
that can be targeted to store a generic credential.
 */
use std::collections::HashMap;

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework::{base::Error, item};

use super::credential::{
    Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialSearch,
    CredentialSearchApi, CredentialSearchResult,
};
use super::error::{decode_password, Error as ErrorCode, Result};

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosCredential {
    pub service: String,
    pub account: String,
}

impl CredentialApi for IosCredential {
    /// Create and write a credential with password for this entry.
    ///
    /// The new credential replaces any existing one in the store.
    /// Since there is only one credential with a given _account_ and _user_
    /// in any given keychain, there is no chance of ambiguity.
    fn set_password(&self, password: &str) -> Result<()> {
        set_generic_password(&self.service, &self.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    }

    /// Look up the password for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn get_password(&self) -> Result<String> {
        let password_bytes =
            get_generic_password(&self.service, &self.account).map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    }

    /// Delete the underlying generic credential for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn delete_password(&self) -> Result<()> {
        delete_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(())
    }

    /// Return the underlying concrete object with an `Any` type so that it can
    /// be downgraded to an [IosCredential] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl IosCredential {
    /// Construct a credential from the underlying generic credential.
    ///
    /// On iOS, this is basically a no-op, because we represent any attributes
    /// other than the ones we use to find the generic credential.
    /// But at least this checks whether the underlying credential exists.
    pub fn get_credential(&self) -> Result<Self> {
        get_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(self.clone())
    }

    /// Create a credential representing a Mac keychain entry.
    ///
    /// The target string is ignored, because there's only one keychain.
    ///
    /// Creating a credential does not put anything into the keychain.
    /// The keychain entry will be created
    /// when [set_password](IosCredential::set_password) is
    /// called.
    ///
    /// This will fail if the service or user strings are empty,
    /// because empty attribute values act as wildcards in the
    /// Keychain Services API.
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

/// The builder for iOS keychain credentials
pub struct IosCredentialBuilder {}

/// Returns an instance of the iOS credential builder.
///
/// On iOS,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(IosCredentialBuilder {})
}

impl CredentialBuilderApi for IosCredentialBuilder {
    /// Build an [IosCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(IosCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to an [IosCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct IosCredentialSearch {}

/// Returns an instance of the Ios credential search.
///
/// This creates a new search structure. The by method
/// integrates with system_framework item search. Works similarly to
/// Mac, however, there are no labels so searching is done by Service, or Account.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(IosCredentialSearch {})
}

impl CredentialSearchApi for IosCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search(by, query)
    }
}

// Search type matching.
enum IosSearchType {
    Service,
    Account,
}

// Perform search, can throw a SearchError, returns a CredentialSearchResult.
// by must be "label", "service", or "account".
fn search(by: &str, query: &str) -> CredentialSearchResult {
    let mut new_search = item::ItemSearchOptions::new();

    let search_default = &mut new_search
        .class(item::ItemClass::generic_password())
        .limit(item::Limit::All)
        .load_attributes(true);

    let by = match by.to_ascii_lowercase().as_str() {
        "service" => IosSearchType::Service,
        "account" => IosSearchType::Account,
        _ => {
            return Err(ErrorCode::SearchError(
                "Invalid search parameter, not Label, Service, or Account".to_string(),
            ))
        }
    };

    let search = match by {
        IosSearchType::Service => search_default.service(query).search(),
        IosSearchType::Account => search_default.account(query).search(),
    };

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    let results = match search {
        Ok(items) => items,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    for item in results {
        match to_credential_search_result(item.simplify_dict(), &mut outer_map) {
            Ok(_) => {}
            Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
        }
    }

    Ok(outer_map)
}
// The returned item from search is converted to CredentialSearchResult type.
// If none, a SearchError is returned for no items found. The outer map's key
// is created with "user"@"service" to differentiate between credentials in the search.
fn to_credential_search_result(
    item: Option<HashMap<String, String>>,
    outer_map: &mut HashMap<String, HashMap<String, String>>,
) -> Result<()> {
    let mut result = match item {
        None => {
            return Err(ErrorCode::SearchError(
                "Search returned no items".to_string(),
            ))
        }
        Some(map) => map,
    };

    let label = "EMPTY LABEL".to_string();

    outer_map.insert(format!("Label: {}", label), result);

    Ok(())
}

/// Map an iOS API error to a crate error with appropriate annotation
///
/// The iOS error code values used here are from
/// [this reference](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html)
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}
