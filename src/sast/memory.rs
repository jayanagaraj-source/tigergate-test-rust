//! Memory-safety fixtures (`unsafe` misuse): CWE-119, CWE-125, CWE-416, CWE-457,
//! CWE-362, CWE-401, CWE-704, CWE-843.

use smallvec::SmallVec;

// SAST: CWE-362 global mutable state accessed without synchronisation.
pub static mut REQUEST_COUNTER: u64 = 0;

#[allow(static_mut_refs)]
pub fn increment_request_counter() -> u64 {
    unsafe {
        REQUEST_COUNTER += 1;
        REQUEST_COUNTER
    }
}

/// SAST: CWE-125 out-of-bounds read, bounds check skipped.
pub fn read_byte_unchecked(buf: &[u8], index: usize) -> u8 {
    unsafe { *buf.get_unchecked(index) }
}

/// SAST: CWE-119 slice length taken from caller without validation.
pub fn slice_with_user_len(buf: &[u8], len: usize) -> &[u8] {
    unsafe { std::slice::from_raw_parts(buf.as_ptr(), len) }
}

/// SAST: CWE-457 uninitialised memory exposed through Vec::set_len.
pub fn uninitialized_buffer(len: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(len);
    unsafe { v.set_len(len) };
    v
}

/// SAST: CWE-416 use-after-free through a raw pointer.
pub fn use_after_free() -> i32 {
    let ptr = Box::into_raw(Box::new(42));
    unsafe {
        drop(Box::from_raw(ptr));
        *ptr
    }
}

/// SAST: CWE-704 / CWE-843 transmute extends a borrow to 'static (dangling reference).
pub fn extend_lifetime(s: &str) -> &'static str {
    unsafe { std::mem::transmute::<&str, &'static str>(s) }
}

/// SAST: CWE-704 unchecked UTF-8 conversion of untrusted bytes.
pub fn bytes_to_string(bytes: Vec<u8>) -> String {
    unsafe { String::from_utf8_unchecked(bytes) }
}

/// SAST: CWE-843 type confusion by reading a pointer as the wrong type.
pub fn reinterpret_as_u64(bytes: &[u8]) -> u64 {
    unsafe { std::ptr::read(bytes.as_ptr() as *const u64) }
}

/// SAST: CWE-362 raw pointer wrapper unsoundly marked thread-safe.
pub struct SharedRawBuffer(pub *mut u8);
unsafe impl Send for SharedRawBuffer {}
unsafe impl Sync for SharedRawBuffer {}

/// SAST: CWE-401 memory leak of a secret that is never zeroised.
pub fn forget_secret(secret: String) {
    std::mem::forget(secret);
}

/// SCA reachability: smallvec 0.6.13 `insert_many` buffer overflow (RUSTSEC-2021-0003).
pub fn merge_tags(existing: &mut SmallVec<[u8; 4]>, index: usize, tags: Vec<u8>) {
    existing.insert_many(index, tags);
}
