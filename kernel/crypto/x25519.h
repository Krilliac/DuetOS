#pragma once

#include "util/types.h"

// X25519 (Curve25519 ECDH, RFC 7748) — the key-exchange primitive for
// TLS 1.3 (the `x25519` named group / key_share). Constant-time
// Montgomery-ladder scalar multiplication; the scalar is clamped
// internally per RFC 7748 §5, so a caller may pass raw random bytes.

namespace duetos::crypto
{

/// out = scalar * u  on Curve25519. `out`, `scalar`, `u` are 32-byte
/// little-endian. Used to compute the ECDHE shared secret from our
/// private scalar and the peer's public u-coordinate.
void X25519(u8 out[32], const u8 scalar[32], const u8 u[32]);

/// out = scalar * basepoint (u = 9): derive the public key to send in a
/// key_share from a freshly-generated private scalar.
void X25519Base(u8 out[32], const u8 scalar[32]);

} // namespace duetos::crypto
