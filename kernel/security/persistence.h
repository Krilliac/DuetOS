#pragma once

#include "util/types.h"

/*
 * DuetOS — secrets-at-rest envelope (RFC-aligned, wiki design home
 * is wiki/security/Persistence.md).
 *
 * Backend-agnostic encode/decode for the "DuetSecretsFile"
 * envelope. Operates on caller-supplied byte buffers; a writable
 * VFS is NOT a prerequisite — the persistence layer encodes the
 * in-memory account / role / membership tables into a single
 * encrypted blob the caller can stash anywhere (initrd embed,
 * tmpfs, a future writable system FS).
 *
 * Envelope (locked at format_version = 1):
 *
 *   struct DuetSecretsFile {
 *       u8  magic[4];           // 'D','S','E','C'
 *       u32 format_version;     // = 1
 *       u32 record_count;       // logical records inside
 *       u32 record_size;        // bytes per record
 *       u8  kdf_salt[16];       // Argon2id KEK salt (cleartext)
 *       u32 kdf_memory_kib;     // Argon2id parameters used to
 *       u32 kdf_time_cost;      //   derive the KEK from the user
 *       u32 kdf_parallelism;    //   password at this install.
 *       u32 reserved;           // zero
 *       u8  nonce[12];          // ChaCha20-Poly1305 nonce
 *       u8  ciphertext[record_count * record_size];
 *       u8  mac[16];            // Poly1305 tag over header + ct
 *   }
 *
 * Header total: 4 + 4 + 4 + 4 + 16 + 4 + 4 + 4 + 4 + 12 = 60 bytes.
 *
 * The MAC covers EVERY byte of the header that precedes the
 * ciphertext (it's the AEAD's "associated data" field), so a
 * tampered version field or record count is detected.
 *
 * The KEK derivation:
 *
 *   KEK = Argon2id(
 *       password=user_admin_password,
 *       salt=kdf_salt,
 *       memory=kdf_memory_kib,
 *       time=kdf_time_cost,
 *       parallelism=kdf_parallelism,
 *       tag_len=32
 *   )
 *
 * Then:
 *
 *   ciphertext, tag = ChaCha20-Poly1305-Encrypt(
 *       key=KEK,
 *       nonce=nonce,
 *       ad=header_bytes_before_ciphertext,
 *       pt=record_bytes
 *   )
 *
 * Both KAT-verified primitives (kernel/security/argon2id.h,
 * kernel/security/chacha20_poly1305.h).
 *
 * Test coverage: PersistenceSelfTest exercises an encode → decode
 * round-trip plus tamper-rejection paths. Wired into the boot
 * self-test sequence; panics on regression.
 */

namespace duetos::security
{

constexpr u32 kPersistenceFormatVersion = 1;
constexpr u32 kPersistenceMagicBytes = 4;
constexpr u32 kPersistenceSaltBytes = 16;
constexpr u32 kPersistenceNonceBytes = 12;
constexpr u32 kPersistenceMacBytes = 16;
constexpr u32 kPersistenceHeaderBytes = 60;

struct PersistenceParams
{
    u32 memory_kib;
    u32 time_cost;
    u32 parallelism;
};

/// Compute the encoded envelope size for a (records, record_count,
/// record_size) tuple. Does NOT include any record padding — the
/// records are written verbatim. Use to size the output buffer
/// before calling `PersistenceEncode`.
u32 PersistenceEncodedSize(u32 record_count, u32 record_size);

/// Encode `record_count` records of `record_size` bytes each into
/// the envelope at `out` (must be at least `PersistenceEncodedSize`
/// bytes). Derives a fresh KEK from the password + a freshly-drawn
/// salt, encrypts the records under a freshly-drawn nonce, and
/// writes header + ciphertext + MAC.
///
/// Returns false on parameter validation failure (bad sizes, KEK
/// derivation failure, weird params). On success, `*out_len`
/// receives the total bytes written.
bool PersistenceEncode(const u8* records, u32 record_count, u32 record_size, const char* password, u32 password_len,
                       const PersistenceParams& kdf_params, u8* out, u32 out_capacity, u32* out_len);

/// Decode an envelope from `in` (length `in_len`) using `password`
/// to derive the KEK from the embedded salt. On verified decrypt
/// writes `record_count * record_size` plaintext bytes to
/// `records_out`, populates `*records_out_count` and
/// `*record_size_out`, and returns true.
///
/// Returns false on:
///   - magic / version mismatch,
///   - claimed total size exceeds `in_len`,
///   - records_out_capacity too small,
///   - Poly1305 tag mismatch (tampered envelope or wrong password).
///
/// The plaintext buffer is NOT touched on a tag mismatch.
bool PersistenceDecode(const u8* in, u32 in_len, const char* password, u32 password_len, u8* records_out,
                       u32 records_out_capacity, u32* records_out_count, u32* record_size_out);

/// Boot self-test: encode a known set of records, decode them
/// back, compare byte-for-byte; flip a tag/ciphertext/header byte
/// and confirm decode fails closed; flip the password and confirm
/// decode fails closed. Panics on any regression.
void PersistenceSelfTest();

} // namespace duetos::security
