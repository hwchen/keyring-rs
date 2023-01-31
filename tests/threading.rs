use common::generate_random_string;
use keyring::{Entry, Error};

mod common;

#[test]
fn test_create_then_move() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).unwrap();
    let test = move || {
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
        );
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_create_set_then_move() {
    let name = generate_random_string();
    let entry = Entry::new(&name, &name).expect("Can't create entry");
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Can't set ascii password");
    let test = move || {
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
        );
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_set_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = Entry::new(&name, &name).expect("Can't create entry");
        entry.set_password(&name).expect("Can't set ascii password");
        let test = move || {
            let stored_password = entry.get_password().expect("Can't get ascii password");
            assert_eq!(
                stored_password, name,
                "Retrieved and set ascii passwords don't match"
            );
            entry
                .delete_password()
                .expect("Can't delete ascii password");
            assert!(
                matches!(entry.get_password(), Err(Error::NoEntry)),
                "Able to read a deleted ascii password"
            );
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}

#[test]
fn test_simultaneous_independent_create_set() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("thread_entry{i}");
        let test = move || {
            let entry = Entry::new(&name, &name).expect("Can't create entry");
            entry.set_password(&name).expect("Can't set ascii password");
            let stored_password = entry.get_password().expect("Can't get ascii password");
            assert_eq!(
                stored_password, name,
                "Retrieved and set ascii passwords don't match"
            );
            entry
                .delete_password()
                .expect("Can't delete ascii password");
            assert!(
                matches!(entry.get_password(), Err(Error::NoEntry)),
                "Able to read a deleted ascii password"
            );
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}
