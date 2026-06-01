#pragma once

#include "net/tls.h"
#include "util/types.h"

/*
 * DuetOS — TLS-over-transport driver (the glue that makes HTTPS
 * bytes actually flow).
 *
 * kernel/net/tls.h provides a COMPLETE but pure-functional TLS 1.2
 * client state machine: it tells the caller which bytes to send and
 * consumes the bytes the server sent, but it never touches a socket.
 * This module is the missing I/O loop: it drives a tls::Connection
 * to Established over a caller-supplied byte transport, then exposes
 * a simple send / recv / close surface for application data.
 *
 * The transport is abstracted (TlsTransport) so the SAME driver runs
 * over:
 *   - a real net::Socket (TlsSocketConnect — what the browser uses), or
 *   - an in-memory pipe (the boot self-test's loopback handshake).
 *
 * Trust model: this module does NOT reimplement crypto and does NOT
 * itself validate the server certificate chain. It exposes a
 * decoupled verifier hook (CertVerifyFn) so the x509 chain-validation
 * module can be wired in without this file depending on it. Until a
 * verifier is installed, a permissive default accepts any leaf and
 * logs one warning — see the GAP marker in tls_socket.cpp.
 *
 * Threading: TlsSocketState is caller-owned. No global mutable state
 * except the process-wide verifier hook (set once at init). Safe from
 * any context that can do AES + RSA + SHA-256 and block on the
 * transport's read/write.
 */

namespace duetos::net::tls
{

/// Byte transport the driver moves handshake + application records
/// over. `read` blocks until at least one byte is available and
/// returns the count read (>0), 0 on orderly EOF, or <0 on error.
/// `write` writes all `len` bytes and returns `len` on success or <0
/// on error. `ctx` is opaque driver-defined state (a socket index, a
/// pipe-pair pointer, ...).
struct TlsTransport
{
    i64 (*read)(void* ctx, u8* buf, u32 len);
    i64 (*write)(void* ctx, const u8* buf, u32 len);
    void* ctx;
};

/// Certificate-verify hook. Called once, right after the server's
/// Certificate message is parsed and the leaf DER is available.
/// Returns true to accept the chain, false to abort the handshake.
/// `ctx` is the opaque pointer registered alongside the function.
///
/// Decoupled on purpose: this header has NO dependency on the x509
/// module, so the verifier can be wired in (swarm 2) without
/// dragging crypto/x509.h into every TLS-socket caller.
using CertVerifyFn = bool (*)(const u8* leaf_der, u32 leaf_len, const char* hostname, void* ctx);

/// Install the process-wide certificate verifier. Pass nullptr to
/// fall back to the permissive default (accept-any + one warning).
/// Set once during init; not synchronised against concurrent
/// handshakes.
void TlsSocketSetVerifier(CertVerifyFn fn, void* ctx);

/// Driver state: an established (or in-flight) TLS connection bound
/// to a transport. Caller-owned; one per logical HTTPS connection.
struct TlsSocketState
{
    Connection conn;
    TlsTransport transport;
    char hostname[256];
};

/// Run the full TLS 1.2 handshake over `transport` to completion:
/// emit ClientHello (with SNI = hostname), then loop reading server
/// records, feeding them through the connection state machine, and
/// writing the bytes it emits, until the connection reaches
/// Established (server Finished verified) or fails.
///
/// `client_random` (32 bytes) and `pms` (48 bytes, first two = 0x03
/// 0x03) are caller-supplied CSPRNG material — same contract as
/// ConnectionStart. Returns true on Established, false on any
/// handshake / transport / verify failure (state ends Failed).
bool TlsSocketHandshake(TlsSocketState* s, const TlsTransport& transport, const char* hostname,
                        const u8 client_random[kClientRandomBytes], const u8 pms[kPreMasterSecretBytes]);

/// Encrypt + transmit one application-data payload. Only valid after
/// a successful handshake. Returns bytes of plaintext sent (== len)
/// or <0 on error.
i64 TlsSocketSend(TlsSocketState* s, const u8* pt, u32 len);

/// Read + decrypt one inbound application-data record into `buf`.
/// Returns plaintext bytes written (>0), 0 on orderly EOF, or <0 on
/// error. v0: one record per call (the record must fit in `cap`).
i64 TlsSocketRecv(TlsSocketState* s, u8* buf, u32 cap);

/// Tear the connection down. v0: marks the state machine Failed so a
/// stale state can't be reused; the underlying transport (socket) is
/// owned and closed by the caller.
void TlsSocketClose(TlsSocketState* s);

/// net::Socket-backed convenience: open a TCP socket to (ip, port),
/// then drive the TLS handshake with SNI = host. On success, fills
/// `s` (whose transport reads/writes the socket) and returns the
/// socket pool index; on failure returns -1 and releases any socket
/// it opened. The caller owns the returned socket index and must
/// SocketRelease it after TlsSocketClose.
i32 TlsSocketConnect(TlsSocketState* s, const char* host, u32 ip_be, u16 port);

/// Boot self-test: an in-memory loopback handshake (client driver vs.
/// a server half built from the same tls.h primitives) plus an
/// app-data round-trip both directions. Emits
/// "[tls-socket-selftest] PASS (...)" on success.
void TlsSocketSelfTest();

} // namespace duetos::net::tls
