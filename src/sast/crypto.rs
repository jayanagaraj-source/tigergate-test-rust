//! Cryptography fixtures: CWE-327, CWE-328, CWE-321, CWE-329, CWE-330, CWE-326, CWE-208.

use openssl::rsa::Rsa;
use openssl::symm::{encrypt, Cipher};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

// SAST: CWE-321 hard-coded symmetric key.
const HARDCODED_AES_KEY: &[u8; 16] = b"0123456789abcdef";
// SAST: CWE-329 static (non-random) IV.
const STATIC_IV: &[u8; 16] = b"fedcba9876543210";
// SAST: CWE-321 hard-coded 3DES key.
const HARDCODED_3DES_KEY: &[u8; 24] = b"tigergate3deskey12345678";

/// SAST: CWE-328 MD5 used for password hashing.
pub fn hash_password_md5(password: &str) -> String {
    format!("{:x}", md5::compute(password.as_bytes()))
}

/// SAST: CWE-328 SHA-1 used for password hashing (unsalted).
pub fn hash_password_sha1(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// SAST: CWE-327 AES in ECB mode with a hard-coded key.
pub fn encrypt_ecb(plaintext: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_128_ecb(), HARDCODED_AES_KEY, None, plaintext).expect("ecb encrypt")
}

/// SAST: CWE-329 AES-CBC with a static IV and hard-coded key (no authentication).
pub fn encrypt_cbc_static_iv(plaintext: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_128_cbc(), HARDCODED_AES_KEY, Some(STATIC_IV), plaintext).expect("cbc encrypt")
}

/// SAST: CWE-327 broken/legacy cipher (Triple DES) with a static IV.
pub fn encrypt_3des(plaintext: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    encrypt(Cipher::des_ede3_cbc(), HARDCODED_3DES_KEY, Some(b"00000000"), plaintext)
}

/// SAST: CWE-326 inadequate RSA key size (512 bits).
pub fn generate_weak_rsa_key() -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let rsa = Rsa::generate(512)?;
    rsa.private_key_to_pem()
}

/// SAST: CWE-330 / CWE-338 predictable, time-seeded RNG used for a security token.
pub fn generate_password_reset_token() -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = StdRng::seed_from_u64(seed);
    format!("{:016x}", rng.gen::<u64>())
}

/// SAST: CWE-330 session id derived from the clock instead of a CSPRNG.
pub fn generate_session_id(username: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    hash_password_md5(&format!("{}{}", username, nanos))
}

/// SAST: CWE-208 timing side channel on API key comparison.
pub fn verify_api_key(provided: &str, expected: &str) -> bool {
    provided == expected
}
