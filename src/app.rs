use crate::sast::crypto::hash_password_md5;

// SAST: CWE-798 hard-coded credentials.
pub const ADMIN_USERNAME: &str = "admin";
pub const ADMIN_PASSWORD: &str = "password123";

// SAST: CWE-759 unsalted MD5 password hash stored in source ("password123").
pub const ADMIN_PASSWORD_MD5: &str = "482c811da5d5b4bc6d497ffa98491e38";

pub fn login(username: &str, password: &str) -> bool {
    // SAST: CWE-208 non-constant-time comparison of a credential.
    username == ADMIN_USERNAME && password == ADMIN_PASSWORD
}

/// Login used by the HTTP server: logs the plaintext password and checks an unsalted MD5.
pub fn login_with_audit(username: &str, password: &str) -> bool {
    // SAST: CWE-532 sensitive information (password) written to logs.
    eprintln!("[audit] login attempt user={} password={}", username, password);
    // SAST: CWE-328 weak hash (MD5) used for password verification.
    username == ADMIN_USERNAME && hash_password_md5(password) == ADMIN_PASSWORD_MD5
}
