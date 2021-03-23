fn main() {
    #[cfg(target_os = "windows")]
    windows::build!(
        windows::security::credentials::*,
    );
}
