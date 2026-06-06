#pragma once

#include "util/types.h"

/*
 * DuetOS — DRSH (DuetOS Remote SHell + desktop) service, v0.
 *
 * A from-scratch encrypted remote-access protocol for DuetOS. Plays the
 * role SSH plays elsewhere — a single authenticated, encrypted carrier
 * that multiplexes interactive shell access and full-desktop access —
 * but is NOT bit-compatible with SSH-2:
 *
 *   - No big-int crypto in v0 (no RSA / DH / curve25519). The kernel
 *     currently exposes AES-128, HMAC-SHA256, PBKDF2-HMAC-SHA256;
 *     that's enough for a pre-shared-secret design and not enough for
 *     public-key auth. When a big-int + curve subsystem lands, an
 *     ECDHE handshake variant can plug in alongside the PSK one.
 *   - Single concurrent session in v0. The kernel's TCP stack only
 *     hosts one bidirectional connection at a time; layering accept-
 *     multiplex on top would invent a stack capability that doesn't
 *     exist. The protocol IS designed so a stack-v1 multi-accept slot
 *     drops in without protocol changes — server state is per-session.
 *
 * Wire protocol (after handshake):
 *
 *   Every record on the wire is a `DrshFrame`:
 *
 *     u8  type        — kDrshFrame*
 *     u8  channel     — 0 = control, 1..N = open channels
 *     u16 length      — big-endian, length of `payload` (0..kDrshMaxPayload)
 *     u8  payload[length]
 *     u8  mac[16]     — HMAC-SHA256(session_mac_key, hdr || payload)[:16]
 *
 *   Payload is encrypted with AES-128-CTR under session_enc_key with a
 *   per-direction monotonic counter; the header (type/channel/length)
 *   is in the clear so the receiver can frame-parse, but is fed into
 *   the MAC so it can't be tampered with. This is straightforward
 *   encrypt-then-MAC framing — same shape used by IPsec / SSH BCS.
 *
 * Handshake (peer roles are server S / client C):
 *
 *     C -> S : DrshHello   { magic, version, nonce_c[16] }
 *     S -> C : DrshHello   { magic, version, nonce_s[16] }
 *     S -> C : DrshChallenge { challenge[32] }   (random)
 *     C -> S : DrshAuth     { hmac_response[32] }
 *           hmac_response = HMAC-SHA256(pmk, "DRSH-AUTH" || nonce_s || nonce_c || challenge)
 *           pmk           = PBKDF2-HMAC-SHA256(password, "DRSH-PMK" || nonce_s, 4096, 32)
 *     S verifies; on success derives session keys:
 *           kdf_in       = nonce_s || nonce_c
 *           session_enc_key  = HMAC-SHA256(pmk, "DRSH-ENC" || kdf_in)[:16]
 *           session_mac_key  = HMAC-SHA256(pmk, "DRSH-MAC" || kdf_in)[:32]
 *           session_ctr_s2c  = HMAC-SHA256(pmk, "DRSH-IVS" || kdf_in)[:16]
 *           session_ctr_c2s  = HMAC-SHA256(pmk, "DRSH-IVC" || kdf_in)[:16]
 *     S -> C : DrshAuthOk
 *
 * Channels (after auth):
 *
 *     ChannelOpen { type } -> ChannelOpenAck { channel_id } | ChannelDenied
 *     ChannelType: 0 = kDrshChShell      — line-buffered terminal
 *                  1 = kDrshChDesktop    — framebuffer tiles + input
 *     ChannelData carries channel-specific payload; ChannelClose tears down.
 *
 * Threat model: protocol assumes an attacker on the wire (passive +
 * active), but TRUSTS the local host. The pre-shared key lives in
 * kernel state (via `drshd passwd`) and is rotated by the admin. A
 * compromised admin shell trivially defeats this — that's outside the
 * model and consistent with how SSH treats /etc/shadow.
 *
 * Context: kernel. The service runs as a kernel task spawned by
 * `DrshServerStart`; channels execute in that task's context. Auth
 * + crypto are wholly kernel-resident (no userland trampoline).
 */

namespace duetos::net::drsh
{

// ---------------------------------------------------------------
// Protocol constants.
// ---------------------------------------------------------------

inline constexpr u32 kDrshMagic = 0x44525348; // "DRSH"
inline constexpr u16 kDrshVersion = 0x0001;
inline constexpr u16 kDrshDefaultPort = 4322;

inline constexpr u32 kDrshMaxPayload = 4096; // per-frame ciphertext cap
inline constexpr u32 kDrshNonceBytes = 16;
inline constexpr u32 kDrshChallengeBytes = 32;
inline constexpr u32 kDrshHmacTagBytes = 16; // truncated HMAC-SHA256 for frame MAC
inline constexpr u32 kDrshEncKeyBytes = 16;  // AES-128
inline constexpr u32 kDrshMacKeyBytes = 32;
inline constexpr u32 kDrshCtrBytes = 16; // AES-CTR initial counter

inline constexpr u32 kDrshPbkdfIters = 4096;
inline constexpr u32 kDrshPmkBytes = 32;

inline constexpr u32 kDrshMaxPasswordBytes = 64;

// Brute-force lockout policy — mirrors the local-login lockout in
// security/auth.h (kAuthLockoutThreshold / kAuthLockoutDurationNs) so
// a remote attacker faces the same wall the console login already
// puts up. After kDrshLockoutThreshold consecutive handshakes that
// complete the AUTH step with a WRONG password, the listener refuses
// ALL new connections — without running any crypto — for
// kDrshLockoutDurationNs. A successful handshake, a password
// rotation, or `drshd unlock` clears the streak.
//
// Only genuine bad-credential handshakes feed the streak: malformed
// frames, version mismatches, and bare TCP connects that drop before
// AUTH do NOT count. Counting raw connection noise would let a port
// scanner lock the admin out of their own box (a self-DoS) — the
// opposite of what the wall is for.
inline constexpr u32 kDrshLockoutThreshold = 5;
inline constexpr u64 kDrshLockoutDurationNs = 60ull * 1000ull * 1000ull * 1000ull; // 60 s

// Channel identifiers — 0 reserved for control.
inline constexpr u8 kDrshChannelControl = 0;
inline constexpr u8 kDrshChannelShell = 1;
inline constexpr u8 kDrshChannelDesktop = 2;

// Frame types (the `type` byte on the wire).
enum DrshFrameType : u8
{
    kDrshFrameHelloC = 1, // client hello
    kDrshFrameHelloS = 2, // server hello
    kDrshFrameChallenge = 3,
    kDrshFrameAuth = 4,
    kDrshFrameAuthOk = 5,
    kDrshFrameAuthFail = 6,
    kDrshFrameChannelOpen = 10,
    kDrshFrameChannelOpenAck = 11,
    kDrshFrameChannelDenied = 12,
    kDrshFrameChannelData = 13,
    kDrshFrameChannelClose = 14,
    kDrshFrameDisconnect = 20,
    kDrshFramePing = 30,
    kDrshFramePong = 31,
};

// Channel "type" tag carried in ChannelOpen payload.
enum DrshChannelKind : u8
{
    kDrshKindShell = 0,
    kDrshKindDesktop = 1,
};

// ---------------------------------------------------------------
// Service control API — what the shell + initcalls call.
// ---------------------------------------------------------------

struct DrshStatus
{
    bool running;
    bool listening;
    bool session_active;
    bool authenticated;
    u8 password_set; // 0 = no password configured, 1 = set
    u8 _pad[3];
    u16 listen_port;
    u16 _pad2;
    u64 connections_total;
    u64 auth_failures_total;
    u64 frames_rx;
    u64 frames_tx;
    u64 bytes_rx;
    u64 bytes_tx;
    // Brute-force throttle state (see kDrshLockoutThreshold).
    u64 throttled_total; // connections refused while the lockout was armed
    u64 locked_until_ns; // 0 = not locked; else MonotonicNs at which the lockout lifts
    u32 failed_streak;   // consecutive bad-credential handshakes since last success / unlock
    u32 _pad3;
};

/// One-time module init. Idempotent. Wires the service into the
/// kernel without starting it (no listener, no password). Safe to
/// call from boot.
void DrshInit();

/// Set / replace the pre-shared password. Empty string clears it
/// (after which connect attempts are rejected outright). Caps at
/// kDrshMaxPasswordBytes; returns false on overflow.
bool DrshSetPassword(const char* password);

/// Start the listener on `port` (or kDrshDefaultPort if 0). Returns
/// false if the service is already running, no password is set, or
/// the underlying socket layer refuses the bind.
bool DrshServerStart(u16 port);

/// Stop the listener and tear down any active session. Idempotent.
void DrshServerStop();

/// Clear an active brute-force lockout: zero the consecutive-failure
/// streak and lift any timed lockout immediately. Idempotent. Caller-
/// side policy (admin-only) is enforced by the `drshd unlock` shell
/// command, mirroring AuthUnlockUser. Publishes an unlock event only
/// when a lockout was actually armed at call time.
void DrshUnlock();

/// Snapshot status for `drshd status` + diag.
DrshStatus DrshServerStatus();

/// Boot-time self-test. Exercises framing, crypto round-trip, and
/// HMAC equality. Emits a single "PASS" line on success (via
/// arch::SerialWrite, like the other selftests).
void DrshSelfTest();

} // namespace duetos::net::drsh
