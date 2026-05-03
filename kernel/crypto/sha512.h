#pragma once

#include "util/types.h"

/*
 * DuetOS — SHA-384 + SHA-512 (FIPS 180-4 §6.4 / §6.5, clean room).
 *
 * SHA-512 operates on 128-byte blocks and 64-bit lanes (SHA-256
 * is 64-byte blocks and 32-bit lanes). SHA-384 is the SHA-512
 * algorithm with a different IV and a truncated digest.
 *
 * Eventual consumers:
 *   - HMAC-SHA384 / HMAC-SHA512: TLS 1.2 GCM-with-SHA384 cipher
 *     suites and TLS 1.3 SHA-384-suite handshake hash.
 *   - WPA3-SAE-256 (P-521 EC option) — uses HMAC-SHA512.
 *   - Future Curve448 + Ed448 signature paths.
 *
 * Same shape as `sha256.h`: caller-owned context, no allocation,
 * no global state.
 */

namespace duetos::crypto
{

inline constexpr u32 kSha384DigestBytes = 48;
inline constexpr u32 kSha512DigestBytes = 64;
inline constexpr u32 kSha512BlockBytes = 128;

struct Sha512Ctx
{
    u64 state[8];
    u64 length_bits_lo; // 128-bit length is bits_hi:bits_lo
    u64 length_bits_hi;
    u32 buffered_bytes;
    u8 block[kSha512BlockBytes];
};

void Sha512Init(Sha512Ctx& ctx);
void Sha384Init(Sha512Ctx& ctx);
void Sha512Update(Sha512Ctx& ctx, const u8* data, u32 length);
void Sha512Final(Sha512Ctx& ctx, u8 out[kSha512DigestBytes]);
void Sha384Final(Sha512Ctx& ctx, u8 out[kSha384DigestBytes]);
void Sha512Hash(const u8* data, u32 length, u8 out[kSha512DigestBytes]);
void Sha384Hash(const u8* data, u32 length, u8 out[kSha384DigestBytes]);

void Sha512SelfTest();

} // namespace duetos::crypto
