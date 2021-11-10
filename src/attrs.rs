/*
Every platform's secure storage system keeps a set of attributes with
each stored item.  Which attributes are allowed can vary, as can which
of the attributes are required and which are used to identify the item.

The attribute model supported by this crate is that each item has only
two attributes: username and service, and they are used together to
uniquely identify the item.

The mismatch between this crate's attribute model and the underlying
platform's attribute model can lead to incompatibility with 3rd-party
applications whose attribute model, while consistent with the underlying
platform model, may be more or less fine-grained than this crate's model.

For example:

* On Windows, generic credential are identified by an arbitrary string,
and that string may not be constructed by a third party application
the same way this crate constructs it from username and service.
* On Linux, additional attributes can be used by 3rd parties to produce
credentials identified my more than just the two attributes this crate
uses by default.

Thus, to provide interoperability with 3rd party credential clients,
we provide a way for clients of this crate to override this crate's
default algorithm for how the username and service are combined so as to
produce the platform-specific attributes that identify each item.
 */

use std::collections::HashMap;

#[derive(Debug)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
}

#[derive(Debug)]
pub struct LinuxIdentity {
    pub attributes: HashMap<&'static str, String>,
}

#[derive(Debug)]
pub struct WinIdentity {
    pub target_name: String,
}

#[derive(Debug)]
pub struct MacIdentity {
    pub service: String,
    pub account: String,
}

#[derive(Debug)]
pub enum PlatformIdentity {
    Linux(LinuxIdentity),
    Win(WinIdentity),
    Mac(MacIdentity),
}

impl PlatformIdentity {
    pub fn matches_platform(&self, os: &Platform) -> bool {
        match self {
            PlatformIdentity::Linux(_) => matches!(os, Platform::Linux),
            PlatformIdentity::Mac(_) => matches!(os, Platform::MacOs),
            PlatformIdentity::Win(_) => matches!(os, Platform::Windows),
        }
    }
}

// TODO: Make this a Fn trait so we can accept closures
pub type IdentityMapper = fn(&Platform, &str, &str) -> PlatformIdentity;

pub fn default_identity_mapper(os: Platform, service: &str, username: &str) -> PlatformIdentity {
    match os {
        Platform::Linux => PlatformIdentity::Linux(LinuxIdentity {
            attributes: HashMap::from([
                ("service", service.to_string()),
                ("username", username.to_string()),
                ("application", String::from("rust-keyring")),
            ]),
        }),
        Platform::Windows => PlatformIdentity::Win(WinIdentity {
            target_name: format!("{}.{}", username, service),
        }),
        Platform::MacOs => PlatformIdentity::Mac(MacIdentity {
            service: service.to_string(),
            account: username.to_string(),
        }),
    }
}
