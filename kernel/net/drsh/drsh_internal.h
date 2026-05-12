#pragma once

#include "net/drsh/drsh.h"
#include "crypto/aes.h"
#include "util/types.h"

/*
 * DRSH — TU-private surface. Only files inside kernel/net/drsh/ may
 * include this header. The public surface lives in drsh.h.
 *
 * Frame layout (re-used by drsh_proto.cpp on both sides):
 *
 *     offset  size   field
 *     0       1      type           (cleartext)
 *     1       1      channel        (cleartext)
 *     2       2      length (BE)    (cleartext, == ciphertext bytes)
 *     4       length payload        (AES-CTR ciphertext)
 *     4+len   16     mac            (HMAC-SHA256(mac_key, type|channel|length|ciphertext)[:16])
 *
 * Total on-wire bytes = 4 + length + 16. Maximum = 4 + kDrshMaxPayload + 16.
 *
 * Two CTR counters per session — one for each direction — so a
 * passive observer can't replay or reorder frames. Each counter is
 * incremented by ceil(length / 16) AES-block units after every
 * transmit / receive so encryption keystreams never overlap. The
 * MAC key is not reused across directions because the keystreams
 * are; an attacker who flips header bytes still fails the MAC check.
 */

namespace duetos::net::drsh::internal
{

inline constexpr u32 kDrshFrameHdrBytes = 4;
inline constexpr u32 kDrshFrameMacBytes = kDrshHmacTagBytes;
inline constexpr u32 kDrshFrameMaxBytes = kDrshFrameHdrBytes + kDrshMaxPayload + kDrshFrameMacBytes;

// Session key material — populated by drsh_auth.cpp after a
// successful handshake. Stays alive for the duration of the
// session; zeroed on disconnect.
struct DrshSession
{
    bool authenticated;
    u8 _pad[3];
    crypto::AesCtx aes_enc; // AES-128 expanded key, both directions share
    u8 mac_key[kDrshMacKeyBytes];
    u8 ctr_s2c[kDrshCtrBytes]; // current AES-CTR counter, server -> client
    u8 ctr_c2s[kDrshCtrBytes]; // current AES-CTR counter, client -> server
    u64 frames_tx;
    u64 frames_rx;
    u64 bytes_tx;
    u64 bytes_rx;
};

// Transport callbacks — the protocol layer is transport-agnostic so
// the same framer can drive a TCP socket today and a kernel-pipe
// loopback tomorrow. Both calls block until len bytes have been
// read/written or the link drops; partial reads/writes are converted
// to a single failure return.
struct DrshTransport
{
    // ReadExact reads exactly `len` bytes into `buf`. Returns true on
    // success, false on EOF / link drop / configured cap exceeded.
    bool (*ReadExact)(void* ctx, u8* buf, u32 len);
    // WriteAll writes exactly `len` bytes from `buf`. Returns false
    // on link drop.
    bool (*WriteAll)(void* ctx, const u8* buf, u32 len);
    // Hint that the peer should be torn down — best effort.
    void (*Close)(void* ctx);
    void* ctx;
};

// Pre-encryption helper: build the cleartext header byte stream and
// fill `out_hdr[4]`. Caller supplies type/channel/payload-length.
void BuildFrameHeader(u8 type, u8 channel, u16 payload_len, u8 out_hdr[kDrshFrameHdrBytes]);

// drsh_crypto.cpp — apply AES-CTR keystream to `buf` in place using
// the session's enc context and the counter pointed to by `ctr`.
// `ctr` is advanced past the keystream that was consumed. Length
// must be <= kDrshMaxPayload.
void ApplyAesCtr(crypto::AesCtx& ctx, u8 ctr[kDrshCtrBytes], u8* buf, u32 len);

// drsh_crypto.cpp — compute HMAC-SHA256(mac_key, hdr || ciphertext)[:tag_bytes]
// into out_tag. tag_bytes <= 32; we always pass kDrshHmacTagBytes (16).
void ComputeFrameMac(const u8 mac_key[kDrshMacKeyBytes], const u8 hdr[kDrshFrameHdrBytes], const u8* payload,
                     u32 payload_len, u8* out_tag, u32 tag_bytes);

// drsh_crypto.cpp — constant-time compare for two byte buffers.
bool ConstantTimeEquals(const u8* a, const u8* b, u32 len);

// drsh_proto.cpp / drsh_server.cpp — send + receive a frame over the
// transport. Caller supplies (type, channel, plaintext, plaintext_len);
// SendFrame encrypts, MACs, and pushes it. RecvFrame reads + verifies
// + decrypts and returns plaintext in `out_payload` (caller-supplied
// buffer of capacity kDrshMaxPayload). The TLS-style "decryption MUST
// happen before MAC verification" trap doesn't apply — we encrypt-
// then-MAC and verify the MAC before touching the ciphertext.
bool SendFrame(DrshTransport& t, DrshSession& s, u8 type, u8 channel, const u8* payload, u32 payload_len);
bool RecvFrame(DrshTransport& t, DrshSession& s, u8* out_type, u8* out_channel, u8* out_payload, u32* out_payload_len);

// drsh_auth.cpp — server-side handshake. Drives the wire flow on top
// of the unauthenticated transport, fills `out_session` on success.
// On any deviation from the script (wrong magic, version mismatch,
// MAC mismatch on AUTH, etc.) returns false; caller drops the link.
bool ServerHandshake(DrshTransport& t, const u8* password, u32 password_len, DrshSession& out_session);

// drsh_auth.cpp — derive the four session keys (enc, mac, ctr_s2c,
// ctr_c2s) into `out_session` from the negotiated nonces + the PMK
// the handshake already computed. Visible to the unit test so a
// host-side fuzzer can replay the KDF.
void DeriveSessionKeys(const u8 pmk[kDrshPmkBytes], const u8 nonce_s[kDrshNonceBytes],
                       const u8 nonce_c[kDrshNonceBytes], DrshSession& out_session);

// drsh_shell.cpp — service the shell channel. Reads frames until
// the channel is closed or the transport drops. Returns false iff
// the transport died (caller tears the whole session down).
bool ShellChannelService(DrshTransport& t, DrshSession& s, u8 channel_id);

// drsh_desktop.cpp — service the desktop channel.
bool DesktopChannelService(DrshTransport& t, DrshSession& s, u8 channel_id);

// drsh_server.cpp — accept loop, handshake invocation, channel demux.
// Spawned as a kernel task by DrshServerStart. Returns when the
// listener is torn down or the kernel asks the task to exit.
void ServerMainLoop();

// drsh_transport.cpp — build a transport over the kernel socket pool.
// Returns false if no listener can be opened. The transport's ctx is
// allocated from the heap; Close() frees it.
bool MakeSocketTransport(u32 socket_idx, DrshTransport& out);

// Global state accessors — drsh_server.cpp owns the singleton, but
// shell_drsh.cpp (status command) needs a peek.
struct DrshGlobal
{
    bool initialized;
    bool password_set;
    bool listener_running;
    bool session_active;
    u16 listen_port;
    u8 password[kDrshMaxPasswordBytes];
    u32 password_len;
    u64 connections_total;
    u64 auth_failures_total;
    DrshSession session;
};

DrshGlobal& Globals();

} // namespace duetos::net::drsh::internal
