#pragma once

#include "util/types.h"

/*
 * DuetOS — SHA-256 hash for WPA3 / SHA256-suite AKMs.
 *
 * Used by HMAC-SHA256 (RFC 6234), which in turn is the primitive
 * for the 802.11 KDF-Hash function selected when AKM is one of
 * { 8021xSha256, PskSha256, FT-..., SAE, FILS }. WPA3-Personal
 * (SAE) terminates in HMAC-SHA256 for PMK derivation.
 *
 * Same interface shape as `sha1.h`. No allocation, no global state.
 */

namespace duetos::net::wireless::crypto
{

inline constexpr u32 kSha256DigestBytes = 32;
inline constexpr u32 kSha256BlockBytes = 64;

struct Sha256Ctx
{
    u32 state[8];
    u64 length_bits;
    u32 buffered_bytes;
    u8 block[kSha256BlockBytes];
};

void Sha256Init(Sha256Ctx& ctx);
void Sha256Update(Sha256Ctx& ctx, const u8* data, u32 length);
void Sha256Final(Sha256Ctx& ctx, u8 out[kSha256DigestBytes]);
void Sha256Hash(const u8* data, u32 length, u8 out[kSha256DigestBytes]);

void Sha256SelfTest();

} // namespace duetos::net::wireless::crypto
