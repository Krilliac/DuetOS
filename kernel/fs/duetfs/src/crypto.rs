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

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use xts_mode::Xts128;

pub const XTS_KEY_BYTES: usize = 64; // 32 data + 32 tweak
pub const SECTOR_BYTES: usize = 4096; // matches BLOCK_SIZE

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
    let params = match Params::new(m_cost_kib, t_cost, p_cost, Some(XTS_KEY_BYTES)) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // The argon2 crate's hash_password_into requires a heap-backed
    // workspace; the alloc feature provides that. For our memory
    // budgets (4 MiB working set with default params) this is fine
    // — the kernel heap accommodates it during the brief mount.
    let mut buf = Vec::from([0u8; XTS_KEY_BYTES]);
    if argon2.hash_password_into(password, salt, &mut buf).is_err() {
        return false;
    }
    out_key.copy_from_slice(&buf);
    true
}
