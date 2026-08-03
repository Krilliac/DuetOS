// DuetFS encryption primitives.
//
// Two surfaces:
//   - AES-256-XTS: per-block encrypt / decrypt for the v6 encrypted-
//     volume layout. Sector number == FS block LBA. The 64-byte key
//     splits into a 32-byte data key + a 32-byte tweak key; both come
//     out of Argon2id.
//   - Argon2id KDF: turn a password + salt + (m, t, p) cost params
//     into the 64-byte XTS key. Argon2id resists both side-channels
//     (memory access patterns) and tradeoff attacks (TMTO).
//
// The Rust crate exposes these as plain FFIs (see `ffi.rs`); the
// kernel C++ side composes them into an "encrypted Device" wrapper
// that decrypts on read and encrypts on write. Block 0 (SB) is the
// only LBA the C++ wrapper passes through unmodified — Mount needs
// to read the SB raw to discover the salt + cost params before it
// can derive the key.
//
// Only AES-256 is supported in v6. AES-128 / Twofish-XTS / etc.
// would require a key_kind flag in the SB and a small FFI dispatch;
// the slot is reserved (Superblock::reserved_after_kdf) but no
// caller plumbing for it.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use xts_mode::Xts128;

pub const XTS_KEY_BYTES: usize = 64; // 32 data + 32 tweak
pub const SECTOR_BYTES: usize = 4096; // matches BLOCK_SIZE
pub const ARGON2_MAX_PASSWORD_BYTES: usize = 1024;
pub const ARGON2_MAX_SALT_BYTES: usize = 64;
// The complete kernel heap is 64 MiB. Keep one admitted derivation at
// or below one eighth of it so unrelated kernel work retains headroom.
pub const ARGON2_MAX_MEMORY_KIB: u32 = 8 * 1024;
pub const ARGON2_MAX_TIME_COST: u32 = 10;
pub const ARGON2_MAX_PARALLELISM: u32 = 4;

static ARGON2_KDF_ACTIVE: AtomicBool = AtomicBool::new(false);

struct Argon2Admission;

impl Argon2Admission {
    fn try_acquire() -> Option<Self> {
        ARGON2_KDF_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for Argon2Admission {
    fn drop(&mut self) {
        ARGON2_KDF_ACTIVE.store(false, Ordering::Release);
    }
}

/// Build an XTS context from a 64-byte key. The first 32 bytes are
/// the data-cipher key; the last 32 are the tweak-cipher key.
fn make_xts(key: &[u8; XTS_KEY_BYTES]) -> Xts128<Aes256> {
    let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
    let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));
    Xts128::<Aes256>::new(cipher_1, cipher_2)
}

/// Encrypt one 4096-byte sector in place. `sector` is the FS LBA;
/// it determines the XTS tweak so the same plaintext at different
/// LBAs produces different ciphertext (a property XTS gives that
/// raw AES-CBC doesn't).
pub fn xts_encrypt_in_place(key: &[u8; XTS_KEY_BYTES], sector: u64, buf: &mut [u8]) {
    debug_assert_eq!(buf.len(), SECTOR_BYTES);
    let xts = make_xts(key);
    let tweak = xts_mode::get_tweak_default(sector as u128);
    xts.encrypt_sector(buf, tweak);
}

/// Decrypt one 4096-byte sector in place. Inverse of
/// `xts_encrypt_in_place` — same key + same sector.
pub fn xts_decrypt_in_place(key: &[u8; XTS_KEY_BYTES], sector: u64, buf: &mut [u8]) {
    debug_assert_eq!(buf.len(), SECTOR_BYTES);
    let xts = make_xts(key);
    let tweak = xts_mode::get_tweak_default(sector as u128);
    xts.decrypt_sector(buf, tweak);
}

/// Argon2id KDF. Turns a password + salt + (m_cost, t_cost, p_cost)
/// triple into a 64-byte key. Returns true on success; false on
/// param-validation failure (Argon2 enforces minimum salt length 8,
/// minimum m_cost 8 KiB, minimum t_cost 1, minimum p_cost 1).
///
/// Default v6 params (callers may override): m = 4096 KiB (4 MiB),
/// t = 3, p = 1. Targets ~100 ms per derivation on a 2GHz core —
/// short enough that a single mount is fast, long enough to make
/// brute-force search expensive.
pub fn argon2id_kdf(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out_key: &mut [u8; XTS_KEY_BYTES],
) -> bool {
    if password.is_empty()
        || password.len() > ARGON2_MAX_PASSWORD_BYTES
        || salt.is_empty()
        || salt.len() > ARGON2_MAX_SALT_BYTES
        || !argon2id_params_valid(m_cost_kib, t_cost, p_cost)
    {
        return false;
    }
    let params = match Params::new(m_cost_kib, t_cost, p_cost, Some(XTS_KEY_BYTES)) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Admission is non-blocking: a concurrent caller fails closed rather
    // than spinning while another CPU performs an expensive derivation.
    let Some(_admission) = Argon2Admission::try_acquire() else {
        return false;
    };

    let block_count = params.block_count();
    let mut workspace = Vec::<Block>::new();
    if workspace.try_reserve_exact(block_count).is_err() {
        return false;
    }
    // Capacity is already reserved fallibly, so resize cannot request a
    // second allocation and cannot enter the infallible OOM path.
    workspace.resize(block_count, Block::default());
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // The caller-owned workspace keeps allocation failure observable
    // instead of invoking the global allocation-error path.
    argon2
        .hash_password_into_with_memory(password, salt, out_key, &mut workspace)
        .is_ok()
}

/// Validate costs without allocating. Both the formatter and the KDF
/// use this gate so hostile on-disk metadata cannot request unbounded
/// kernel heap or CPU work and invalid costs are never persisted.
pub fn argon2id_params_valid(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> bool {
    if m_cost_kib > ARGON2_MAX_MEMORY_KIB || t_cost > ARGON2_MAX_TIME_COST || p_cost > ARGON2_MAX_PARALLELISM {
        return false;
    }
    Params::new(m_cost_kib, t_cost, p_cost, Some(XTS_KEY_BYTES)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_policy_is_bounded_and_keeps_the_default() {
        assert!(argon2id_params_valid(4096, 3, 1));
        assert!(!argon2id_params_valid(ARGON2_MAX_MEMORY_KIB + 1, 3, 1));
        assert!(!argon2id_params_valid(4096, ARGON2_MAX_TIME_COST + 1, 1));
        assert!(!argon2id_params_valid(4096, 3, ARGON2_MAX_PARALLELISM + 1));
    }

    #[test]
    fn argon2_admission_is_nonblocking_and_released() {
        let first = Argon2Admission::try_acquire().expect("first derivation should be admitted");
        assert!(Argon2Admission::try_acquire().is_none());
        drop(first);
        assert!(Argon2Admission::try_acquire().is_some());
    }
}
