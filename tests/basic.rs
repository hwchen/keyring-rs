use common::generate_random_string;
use keyring::{Entry, Error};

mod common;

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Missing entry has password"
    )
}

#[test]
fn test_empty_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let in_pass = "";
    entry
        .set_password(in_pass)
        .expect("Can't set empty password");
    let out_pass = entry.get_password().expect("Can't get empty password");
    assert_eq!(
        in_pass, out_pass,
        "Retrieved and set empty passwords don't match"
    );
    entry.delete_password().expect("Can't delete password");
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted password"
    )
}

#[test]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Can't set ascii password");
    let stored_password = entry.get_password().expect("Can't get ascii password");
    assert_eq!(
        stored_password, password,
        "Retrieved and set ascii passwords don't match"
    );
    entry
        .delete_password()
        .expect("Can't delete ascii password");
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted ascii password"
    )
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let password = "このきれいな花は桜です";
    entry
        .set_password(password)
        .expect("Can't set non-ascii password");
    let stored_password = entry.get_password().expect("Can't get non-ascii password");
    assert_eq!(
        stored_password, password,
        "Retrieved and set non-ascii passwords don't match"
    );
    entry
        .delete_password()
        .expect("Can't delete non-ascii password");
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted non-ascii password"
    )
}

#[test]
fn test_error_on_long_password() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let password = "VGhlcmUgb25jZSB3YXMgYSBsb25nIHBhc3N3b3JkLApzbyBsb25nIG1vc3QgdGhvdWdodCBpdCBhYnN1cmQuClRoZW4gYWxvbmUgY2FtZSBhIGhhY2tlciwKd2hvIGdhdmUgaGlzIGtleWJvYXJkIGEgY2xhY2tlciwKYW5kIHRoZSBwYXNzd29yZCdzIHJhdGUgd2FzIHByb3ZlbiB0aGlyZC4KCkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQuIEZ1c2NlIGZpbmlidXMgbWFsZXN1YWRhIG1pIHNpdCBhbWV0IGZldWdpYXQuIE51bmMgdmVoaWN1bGEgb2RpbyBlZ2V0IHZlaGljdWxhIHBvc3VlcmUuIFNlZCBwdWx2aW5hciBkaWFtIHZpdGFlIHNhcGllbiBncmF2aWRhIG1hdHRpcy4gVml2YW11cyBzZWQgcHVydXMgc29sbGljaXR1ZGluLCBsYWNpbmlhIGVuaW0gZXQsIGRpZ25pc3NpbSBvcmNpLiBJbiBpZCBjdXJzdXMgc2FwaWVuLCBpbiBjb25ndWUgbWFzc2EuIFBoYXNlbGx1cyBzaXQgYW1ldCByaXN1cyBub24gc2VtIHZpdmVycmEgYXVjdG9yLiBTZWQgdGVsbHVzIG51bGxhLCB2ZXN0aWJ1bHVtIGNvbW1vZG8gY3Vyc3VzIGEsIGlhY3VsaXMgaW4gZXguClV0IGV4IGxpYmVybywgdnVscHV0YXRlIGFjIHR1cnBpcyBldSwgZWdlc3RhcyB2YXJpdXMgZHVpLiBJbnRlZ2VyIGlkIHF1YW0gZWxpdC4gUHJvaW4gZmF1Y2lidXMgZ3JhdmlkYSBtZXR1cywgcnV0cnVtIHJob25jdXMgbWV0dXMgY29uc2VxdWF0IHF1aXMuIE51bGxhIGlkIHRvcnRvciBzYXBpZW4uIFBlbGxlbnRlc3F1ZSBjb25ndWUgZXN0IGxhY3VzLCBpbiB0ZW1wb3Igb3JjaSBwb3N1ZXJlIHZlbC4gU2VkIGRhcGlidXMgb3JuYXJlIHRyaXN0aXF1ZS4gTWF1cmlzIGxlbyBudW5jLCB0aW5jaWR1bnQgZXQgc2VtIHNlZCwgbWFsZXN1YWRhIGhlbmRyZXJpdCBsb3JlbS4gUHJhZXNlbnQgZmF1Y2lidXMgcGxhY2VyYXQgdmVuZW5hdGlzLiBBbGlxdWFtIGVyYXQgdm9sdXRwYXQuIEN1cmFiaXR1ciBzYWdpdHRpcyBlbGVtZW50dW0gbGliZXJvLiBQcmFlc2VudCBzZWQgbWFsZXN1YWRhIGFyY3UsIHNlZCBsYW9yZWV0IGVyYXQuIEN1cmFiaXR1ciBldCBncmF2aWRhIHR1cnBpcy4gQWVuZWFuIGxhY2luaWEgZXggYXQgZXJvcyB2b2x1dHBhdCB1bGxhbWNvcnBlci4gQWVuZWFuIGF0IHNjZWxlcmlzcXVlIGFudGUu";
    let err = entry
        .set_password(password)
        .err()
        .expect("We managed to set an entry password that was too long to be stored in UTF-16 unexpectedly");

    match err {
        Error::TooLong(param, length) => {
            assert_eq!(param, "password");
            assert_eq!(length, 2560);
        }
        e => panic!("Unexpected error while storing long password: {}", e)
    };
}

#[test]
fn test_update() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Can't set initial ascii password");
    let stored_password = entry.get_password().expect("Can't get ascii password");
    assert_eq!(
        stored_password, password,
        "Retrieved and set initial ascii passwords don't match"
    );
    let password = "このきれいな花は桜です";
    entry
        .set_password(password)
        .expect("Can't update ascii with non-ascii password");
    let stored_password = entry.get_password().expect("Can't get non-ascii password");
    assert_eq!(
        stored_password, password,
        "Retrieved and updated non-ascii passwords don't match"
    );
    entry
        .delete_password()
        .expect("Can't delete updated password");
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Able to read a deleted updated password"
    )
}
