#pragma once

#include "util/types.h"

/*
 * DuetOS — MD5 (RFC 1321).
 *
 * MD5 is broken as a collision-resistant hash and MUST NOT be
 * used for any new security-sensitive code path. It's kept here
 * because legacy interop drags it in:
 *
 *   - HMAC-MD5 for NTLMv1 / Digest auth (RFC 2069).
 *   - Old TLS_RSA_WITH_*_MD5 cipher suites (deprecated; we will
 *     not implement them, but a TLS handshake parser may need to
 *     decode an MD5-flagged certificate).
 *   - Some legacy file-format checksums (PKZIP MD5, .iso MD5SUMS).
 *
 * If you reach for MD5 in a new feature, stop and use SHA-256
 * instead. The only valid v0 consumer is HMAC-MD5 for NTLM
 * which is itself a security smell.
 *
 * Same context-update-final shape as `sha1.h` / `sha256.h`. No
 * allocation, no global state.
 */

namespace duetos::net::wireless::crypto
{

inline constexpr u32 kMd5DigestBytes = 16;
inline constexpr u32 kMd5BlockBytes = 64;

struct Md5Ctx
{
    u32 state[4];
    u64 length_bits;
    u32 buffered_bytes;
    u8 block[kMd5BlockBytes];
};

void Md5Init(Md5Ctx& ctx);
void Md5Update(Md5Ctx& ctx, const u8* data, u32 length);
void Md5Final(Md5Ctx& ctx, u8 out[kMd5DigestBytes]);
void Md5Hash(const u8* data, u32 length, u8 out[kMd5DigestBytes]);

void Md5SelfTest();

} // namespace duetos::net::wireless::crypto
