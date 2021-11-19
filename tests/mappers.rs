mod common;

use serial_test::serial;

use crate::common::{constant_mapper, reverse_mapper};
use keyring::{Entry, Error};

#[test]
#[serial]
fn test_reverse_mapper() {
    let service = common::generate_random_string();
    let username = common::generate_random_string();
    let normal_entry = Entry::new(&service, &username);
    let backwards_entry = Entry::new_with_mapper(&username, &service, reverse_mapper).unwrap();
    let normal_password = common::generate_random_string();
    normal_entry.set_password(&normal_password).unwrap();
    let backwards_password = backwards_entry.get_password().unwrap();
    assert_eq!(
        normal_password, backwards_password,
        "Normal and Backwards entry passwords don't match"
    );
    normal_entry.delete_password().unwrap();
    assert!(
        matches!(backwards_entry.delete_password(), Err(Error::NoEntry)),
        "Deleting Normal entry password didn't delete Backwards entry credential"
    )
}

#[test]
#[serial]
fn test_constant_mapper() {
    let foo_entry = Entry::new_with_mapper("foo", "foo", constant_mapper).unwrap();
    let bar_entry = Entry::new_with_mapper("bar", "bar", constant_mapper).unwrap();
    let foo_password = common::generate_random_string();
    foo_entry.set_password(&foo_password).unwrap();
    let bar_password = bar_entry.get_password().unwrap();
    assert_eq!(
        foo_password, bar_password,
        "Foo and Bar entry passwords don't match"
    );
    foo_entry.delete_password().unwrap();
    assert!(
        matches!(bar_entry.delete_password(), Err(Error::NoEntry)),
        "Deleting Foo entry password didn't delete Bar entry credential"
    )
}
