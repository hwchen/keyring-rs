use std::collections::HashMap;

use keyring::credential::{
    default_mapper, LinuxCredential, MacCredential, MacKeychainDomain, Platform,
    PlatformCredential, WinCredential,
};

//
// mappers useful in testing
//
#[allow(dead_code)]
pub fn reverse_mapper(platform: &Platform, service: &str, username: &str) -> PlatformCredential {
    default_mapper(platform, username, service)
}

#[allow(dead_code)]
pub fn constant_mapper(platform: &Platform, _: &str, _: &str) -> PlatformCredential {
    // this always gives the same credential to a single process,
    // and different credentials to different processes.
    // On Mac this is very important, because otherwise test runs
    // can clash with credentials created on prior test runs
    let suffix = std::process::id().to_string();
    match platform {
        Platform::Linux => PlatformCredential::Linux(LinuxCredential {
            collection: "default".to_string(),
            attributes: HashMap::from([
                (
                    "service".to_string(),
                    format!("keyring-service-{}", &suffix),
                ),
                (
                    "username".to_string(),
                    format!("keyring-username-{}", &suffix),
                ),
                (
                    "application".to_string(),
                    format!("keyring-application-{}", &suffix),
                ),
                (
                    "additional".to_string(),
                    format!("keyring-additional-{}", &suffix),
                ),
            ]),
            label: format!("keyring-label-{}", &suffix),
        }),
        Platform::Windows => PlatformCredential::Win(WinCredential {
            // Note: default concatenation of user and service name is
            // needed because windows identity is on target_name only
            // See issue here: https://github.com/jaraco/keyring/issues/47
            username: format!("keyring-username-{}", &suffix),
            target_name: format!("keyring-target-name-{}", &suffix),
            target_alias: format!("keyring-target-alias-{}", &suffix),
            comment: format!("keyring-comment-{}", &suffix),
        }),
        Platform::MacOs => PlatformCredential::Mac(MacCredential {
            domain: MacKeychainDomain::User,
            service: format!("keyring-service-{}", &suffix),
            account: format!("keyring-username-{}", &suffix),
        }),
    }
}

//
// utilities for testing
//
#[allow(dead_code)]
pub fn generate_random_string() -> String {
    // from the Rust Cookbook:
    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}
