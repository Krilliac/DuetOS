#pragma once

#include "util/types.h"

/*
 * DuetOS — SHA-384 hash (FIPS 180-4).
 *
 * Added for the ECDSA certificate path: ecdsa-with-SHA384 (the
 * signature algorithm used by every P-384 web root we embed — DigiCert
 * Global Root G3, ISRG Root X2, the GTS R* ECC roots) hashes the
 * tbsCertificate with SHA-384 before the ECDSA verify. SHA-256 alone
 * cannot validate those chains.
 *
 * SHA-384 is SHA-512 with a different IV, truncated to the first 48
 * output bytes. The 64-bit-word block compression is shared internally;
 * only the IV and the output length differ.
 *
 * Same interface shape as `sha256.h`. No allocation, no global state,
 * pure functions — safe from any context.
 */

namespace duetos::crypto
{

inline constexpr u32 kSha384DigestBytes = 48;
inline constexpr u32 kSha384BlockBytes = 128;

struct Sha384Ctx
{
    u64 state[8];
    u64 length_low;  // total message length in bits (low 64 bits)
    u64 length_high; // high 64 bits — messages we hash never reach this
    u32 buffered_bytes;
    u8 block[kSha384BlockBytes];
};

void Sha384Init(Sha384Ctx& ctx);
void Sha384Update(Sha384Ctx& ctx, const u8* data, u32 length);
void Sha384Final(Sha384Ctx& ctx, u8 out[kSha384DigestBytes]);
void Sha384Hash(const u8* data, u32 length, u8 out[kSha384DigestBytes]);

void Sha384SelfTest();

} // namespace duetos::crypto
