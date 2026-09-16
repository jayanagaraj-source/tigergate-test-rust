//! Miscellaneous fixtures: CWE-190, CWE-197, CWE-209, CWE-248, CWE-400, CWE-502,
//! CWE-676, CWE-807 and SCA reachability for vulnerable time/chrono/base64.

use serde::Deserialize;
use std::path::PathBuf;

/// SAST: CWE-807 trusting argv[0] (semgrep rust.lang.security.args-os / args).
pub fn program_name_from_args() -> Option<String> {
    std::env::args().next()
}

/// SAST: CWE-807 trusting current_exe() for security decisions.
pub fn install_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().to_path_buf()
}

/// SAST: CWE-377 predictable path in std::env::temp_dir().
pub fn report_path() -> PathBuf {
    std::env::temp_dir().join("tigergate-report.txt")
}

/// SAST: CWE-190 integer overflow with wrapping arithmetic on prices.
pub fn order_total(unit_price_cents: u32, quantity: u32) -> u32 {
    unit_price_cents.wrapping_mul(quantity)
}

/// SAST: CWE-197 lossy numeric truncation of a user-supplied length.
pub fn content_length_to_u16(len: u64) -> u16 {
    len as u16
}

/// SAST: CWE-400 / CWE-789 unbounded allocation sized by the client.
pub fn allocate_for_upload(declared_size: usize) -> Vec<u8> {
    vec![0u8; declared_size]
}

/// SAST: CWE-248 panic on untrusted input (unwrap/expect) — DoS.
pub fn parse_port(input: &str) -> u16 {
    input.trim().parse::<u16>().unwrap()
}

#[derive(Debug, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub is_admin: bool,
    pub role: String,
}

/// SAST: CWE-502 / CWE-915 untrusted deserialisation sets privileged fields (mass assignment).
pub fn load_profile(json_from_request: &str) -> UserProfile {
    serde_json::from_str(json_from_request).expect("profile")
}

/// SAST: CWE-209 internal error details returned to the client.
pub fn error_response(err: &dyn std::error::Error) -> String {
    format!("500 Internal Server Error\n{:#?}\nsource={:?}", err, err.source())
}

/// SAST: CWE-676 use of a dangerous libc-style API through FFI.
pub fn env_home_unchecked() -> String {
    unsafe {
        let ptr = libc_getenv(b"HOME\0".as_ptr() as *const i8);
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

extern "C" {
    #[link_name = "getenv"]
    fn libc_getenv(name: *const i8) -> *const i8;
}

/// SCA reachability: time 0.1.43 localtime_r (RUSTSEC-2020-0071).
pub fn legacy_timestamp() -> String {
    time::now().rfc822().to_string()
}

/// SCA reachability: chrono 0.4.19 Local (RUSTSEC-2020-0159).
pub fn local_timestamp() -> String {
    chrono::Local::now().to_rfc3339()
}

/// SCA reachability: base64 0.5.1 decode (RUSTSEC-2017-0004).
pub fn decode_base64(input: &str) -> Vec<u8> {
    base64::decode(input).unwrap_or_default()
}
