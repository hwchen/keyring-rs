/// When tests fail, they leave keys behind, and those keys
/// have to be cleaned up before the tests can be run again
/// in order to avoid bad results.  So it's a lot easier just
/// to have tests use a random string for key names to avoid
/// the conflicts, and then do any needed cleanup once everything
/// is working correctly.  So tests make keys with these functions.
pub fn generate_random_string_of_len(len: usize) -> String {
    // from the Rust Cookbook:
    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn generate_random_string() -> String {
    generate_random_string_of_len(30)
}
