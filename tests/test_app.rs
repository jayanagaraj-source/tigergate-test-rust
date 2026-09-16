use tigergate_test_rust::app::{login, login_with_audit};
use tigergate_test_rust::sast::{crypto, injection, misc};
use tigergate_test_rust::vulnerable::unsafe_query;

#[test]
fn greeting_works() {
    assert_eq!("Hello, Tiger!", "Hello, Tiger!");
}

#[test]
fn login_accepts_fixture_credentials() {
    assert!(login("admin", "password123"));
    assert!(login_with_audit("admin", "password123"));
}

#[test]
fn login_rejects_wrong_credentials() {
    assert!(!login("admin", "wrong"));
    assert!(!login("root", "password123"));
    assert!(!login("Admin", "Password123"));
}

#[test]
fn sql_fixture_is_injectable() {
    assert_eq!(
        unsafe_query("' OR '1'='1"),
        "SELECT * FROM users WHERE name = '' OR '1'='1'"
    );
}

#[test]
fn xss_fixture_does_not_escape() {
    assert!(injection::render_greeting("<script>").contains("<script>"));
}

#[test]
fn weak_hashes_are_used() {
    assert_eq!(crypto::hash_password_md5("password123"), "482c811da5d5b4bc6d497ffa98491e38");
    assert_eq!(crypto::hash_password_sha1("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn vulnerable_dependencies_are_reachable() {
    assert_eq!(misc::decode_base64("dGlnZXI="), b"tiger");
    assert!(!misc::local_timestamp().is_empty());
    assert!(!misc::legacy_timestamp().is_empty());
}
