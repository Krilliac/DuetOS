/*
 * DuetOS — TLS-over-transport driver + in-memory loopback self-test.
 *
 * See tls_socket.h for the surface contract. This TU is the I/O loop
 * that turns kernel/net/tls.h's pure-functional state machine into a
 * working HTTPS byte pipe, plus a boot self-test that proves the loop
 * by handshaking against a loopback "server" built from the same
 * tls.h primitives and round-tripping one app-data record each way.
 *
 * No crypto is reimplemented here — every cipher / PRF / RSA step is
 * a call into tls.h or the crypto modules. The only "server" crypto in the
 * self-test is an RSA private-key ModExp to recover the PMS, which is
 * the one operation a real server does that the client half doesn't.
 */

#include "net/tls_socket.h"

#include "arch/x86_64/serial.h"
#include "crypto/bigint.h"
#include "crypto/rsa.h"
#include "crypto/x509.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "util/random.h"

namespace duetos::net::tls
{

namespace
{

// Process-wide cert verifier. nullptr -> permissive default.
CertVerifyFn g_cert_verify_fn = nullptr;
void* g_cert_verify_ctx = nullptr;

// Largest TLS record / flight we buffer in one read pass. A server's
// first flight (ServerHello + Certificate + ServerHelloDone) with a
// single leaf cert fits comfortably.
constexpr u32 kRecordBufBytes = 8192;

// Per-call random byte for PKCS#1 padding (must be non-zero). Mirrors
// the wrapper tls.cpp's own callers use over the kernel CSPRNG.
u8 RandomNonzeroByte()
{
    for (;;)
    {
        const u8 b = static_cast<u8>(core::RandomU64() & 0xFF);
        if (b != 0)
            return b;
    }
}

// The server's Certificate message lists the leaf followed by zero or
// more intermediates, all in wire order. We hand the verifier the leaf
// plus up to this many intermediates; net::x509::Verify only consults
// the first usable one (depth-2 cap), but we forward what the server
// sent so the builder can search. Sized to match
// net::x509::kMaxChainCerts without depending on that header.
constexpr u32 kMaxIntermediates = 8;

// Parsed server certificate chain: the leaf plus the intermediate DER
// slices that followed it in the Certificate message. All pointers
// alias into the caller's handshake buffer — valid only while that
// buffer is live.
struct ServerChain
{
    const u8* leaf;
    u32 leaf_len;
    const u8* inter[kMaxIntermediates];
    u32 inter_len[kMaxIntermediates];
    u32 inter_count;
};

// Walk one Certificate-message body (3-byte list_len, then a run of
// [3-byte cert_len || cert_der] entries) and split out the leaf and
// the trailing intermediates. Mirrors the wire format the Rust
// TlsParseCertificateLeaf validates for the leaf, extended to the
// remaining entries. Every length is bounds-checked against the body
// and fails CLOSED (returns false) on any inconsistency — this body is
// attacker-controlled. Returns true with `out` populated on success.
bool ParseCertificateChain(const u8* body, u32 len, ServerChain* out)
{
    if (body == nullptr || out == nullptr || len < 6)
        return false;
    auto u24 = [](const u8* p) -> u32
    { return (static_cast<u32>(p[0]) << 16) | (static_cast<u32>(p[1]) << 8) | static_cast<u32>(p[2]); };

    const u32 list_len = u24(body);
    if (list_len < 3 || 3u + list_len > len)
        return false;

    out->leaf = nullptr;
    out->leaf_len = 0;
    out->inter_count = 0;

    u32 off = 3; // skip the 3-byte list length
    const u32 list_end = 3 + list_len;
    bool have_leaf = false;
    while (off + 3 <= list_end)
    {
        const u32 cert_len = u24(body + off);
        off += 3;
        if (cert_len == 0 || off + cert_len > list_end)
            return false;
        const u8* cert = body + off;
        if (!have_leaf)
        {
            out->leaf = cert;
            out->leaf_len = cert_len;
            have_leaf = true;
        }
        else if (out->inter_count < kMaxIntermediates)
        {
            out->inter[out->inter_count] = cert;
            out->inter_len[out->inter_count] = cert_len;
            ++out->inter_count;
        }
        // else: more intermediates than we forward — silently drop the
        // overflow; the depth-2 verifier never needs them.
        off += cert_len;
    }
    return have_leaf;
}

// Scan a buffered server flight (`buf[0..len)`, a run of TLS records)
// for the Certificate handshake message and parse out the full chain
// (leaf + intermediates). Returns true and populates `out` on success.
// Uses only the public peek helpers from tls.h — no crypto.
bool FindServerChain(const u8* buf, u32 len, ServerChain* out)
{
    u32 rec_off = 0;
    while (rec_off + 5 <= len)
    {
        RecordView rv{};
        if (!TlsPeekRecord(buf + rec_off, len - rec_off, &rv))
            return false;
        if (5u + rv.length > len - rec_off)
            return false;
        if (rv.type == kContentHandshake)
        {
            u32 hs_off = 0;
            while (hs_off < rv.length)
            {
                HandshakeView hv{};
                if (!TlsPeekHandshake(rv.payload + hs_off, rv.length - hs_off, &hv))
                    break;
                if (hv.type == kHandshakeCertificate)
                    return ParseCertificateChain(hv.body, hv.length, out);
                hs_off += 4u + hv.length;
            }
        }
        rec_off += 5u + rv.length;
    }
    return false;
}

// Run the installed verifier (or the permissive default) over the
// chain the server sent. `chain` comes from FindServerChain; when the
// chain could not be parsed, `chain` is nullptr (leaf unavailable).
bool RunCertVerifier(const ServerChain* chain, const char* hostname)
{
    if (g_cert_verify_fn != nullptr)
    {
        const u8* leaf = (chain != nullptr) ? chain->leaf : nullptr;
        const u32 leaf_len = (chain != nullptr) ? chain->leaf_len : 0;
        const u8* const* inter = (chain != nullptr && chain->inter_count > 0) ? chain->inter : nullptr;
        const u32* inter_len = (chain != nullptr && chain->inter_count > 0) ? chain->inter_len : nullptr;
        const u32 inter_count = (chain != nullptr) ? chain->inter_count : 0;
        return g_cert_verify_fn(leaf, leaf_len, inter, inter_len, inter_count, hostname, g_cert_verify_ctx);
    }

    // No cert verifier installed: FAIL CLOSED. A TLS caller that never
    // installed a verifier (via TlsSocketSetVerifier) must not silently
    // accept an unauthenticated chain — that's a MITM. This matches the
    // fail-closed philosophy of the verifier itself (net/x509_verify):
    // an unverifiable peer is refused, not waved through. Real callers
    // install net::x509::Verify (the browser does so before its first
    // HTTPS; see apps/browser.cpp::InstallTlsVerifierOnce); a caller
    // that legitimately wants no authentication (e.g. a self-signed
    // loopback test) must install an explicit accept-any verifier and
    // own that decision.
    KLOG_WARN("net/tls-sock", "no cert verifier installed — refusing server chain (fail-closed)");
    return false;
}

} // namespace

void TlsSocketSetVerifier(CertVerifyFn fn, void* ctx)
{
    g_cert_verify_fn = fn;
    g_cert_verify_ctx = ctx;
}

void TlsSocketClose(TlsSocketState* s)
{
    if (s == nullptr)
        return;
    // Mark Failed so a stale state can't be reused for app data. The
    // transport (socket) lifetime is the caller's.
    s->conn.state = State::Failed;
    s->conn.err = "closed by TlsSocketClose";
}

bool TlsSocketHandshake(TlsSocketState* s, const TlsTransport& transport, const char* hostname,
                        const u8 client_random[kClientRandomBytes], const u8 pms[kPreMasterSecretBytes])
{
    if (s == nullptr || transport.read == nullptr || transport.write == nullptr)
        return false;

    s->transport = transport;
    s->hostname[0] = '\0';
    if (hostname != nullptr)
    {
        u32 i = 0;
        while (hostname[i] != '\0' && i + 1 < sizeof(s->hostname))
        {
            s->hostname[i] = hostname[i];
            ++i;
        }
        s->hostname[i] = '\0';
    }

    // The two 8 KiB TLS record buffers (`in` + `out`) live on the heap, not
    // the stack. TlsSocketHandshake sits at the head of the deep
    // handshake -> x509 -> ASN.1 -> RSA/EC verify chain; a 16 KiB stack frame
    // here is what would push that chain past a 64 KiB scheduler-thread stack
    // (boot ran it on the 512 KiB boot stack, but a real TLS handshake on a
    // net worker thread has only 64 KiB). Off-stack, the chain fits a worker
    // stack with comfortable margin. The local guard frees on EVERY exit path
    // — this function has many early returns — so there is no per-return KFree.
    struct RecordScratch
    {
        u8 in[kRecordBufBytes];
        u8 out[kRecordBufBytes];
    };
    auto* scratch = static_cast<RecordScratch*>(mm::KMalloc(sizeof(RecordScratch)));
    if (scratch == nullptr)
    {
        KLOG_WARN("net/tls-sock", "handshake: record-buffer alloc failed");
        return false;
    }
    struct ScratchGuard
    {
        RecordScratch* p;
        ~ScratchGuard() { mm::KFree(p); }
    } scratch_guard{scratch};
    u8* const out = scratch->out;
    u8* const in = scratch->in;

    // 1. ClientHello (SNI = hostname).
    const u32 ch_len = ConnectionStart(&s->conn, client_random, pms, s->hostname, out, kRecordBufBytes);
    if (ch_len == 0)
    {
        KLOG_WARN("net/tls-sock", "handshake: ClientHello build failed");
        return false;
    }
    if (transport.write(transport.ctx, out, ch_len) != static_cast<i64>(ch_len))
    {
        KLOG_WARN("net/tls-sock", "handshake: ClientHello write failed");
        return false;
    }

    // 2. Drive the state machine: read a flight, feed it, write what
    //    the connection emits, until Established or Failed.
    u32 in_len = 0;
    bool verifier_ran = false;
    u32 guard = 0;
    while (!ConnectionIsEstablished(&s->conn))
    {
        if (++guard > 64)
        {
            arch::SerialWrite("[tls-sock] DBG loop-guard state=");
            arch::SerialWriteHex(static_cast<u64>(s->conn.state));
            arch::SerialWrite(" in_len=");
            arch::SerialWriteHex(in_len);
            arch::SerialWrite("\n");
            return false;
        }
        if (s->conn.state == State::Failed)
        {
            KLOG_WARN("net/tls-sock", "handshake: connection entered Failed");
            return false;
        }
        if (in_len >= kRecordBufBytes)
        {
            KLOG_WARN("net/tls-sock", "handshake: server flight exceeds record buffer");
            TlsSocketClose(s);
            return false;
        }
        const i64 n = transport.read(transport.ctx, in + in_len, kRecordBufBytes - in_len);
        if (n <= 0)
        {
            KLOG_WARN("net/tls-sock", "handshake: transport EOF/error mid-handshake");
            return false;
        }
        in_len += static_cast<u32>(n);

        const u32 wrote = ConnectionFeed(&s->conn, in, in_len, out, kRecordBufBytes, RandomNonzeroByte);
        if (s->conn.state == State::Failed)
        {
            KLOG_WARN("net/tls-sock", "handshake: ConnectionFeed -> Failed");
            if (s->conn.err != nullptr)
                arch::SerialWrite(s->conn.err);
            arch::SerialWrite("\n");
            return false;
        }

        // Once the server cert has been parsed, run the verifier hook
        // exactly once — before we transmit the ClientKeyExchange that
        // commits to the server's public key. We extract the leaf DER
        // from the buffered flight via the public peek/parse helpers.
        if (!verifier_ran && s->conn.server_cert_seen)
        {
            ServerChain chain{};
            const bool have_chain = FindServerChain(in, in_len, &chain);
            if (!RunCertVerifier(have_chain ? &chain : nullptr, s->hostname))
            {
                KLOG_WARN("net/tls-sock", "handshake: certificate verifier rejected chain");
                TlsSocketClose(s);
                return false;
            }
            verifier_ran = true;
        }

        if (wrote > 0)
        {
            if (transport.write(transport.ctx, out, wrote) != static_cast<i64>(wrote))
            {
                KLOG_WARN("net/tls-sock", "handshake: client flight write failed");
                return false;
            }
            // The emitted flight consumed the buffered server bytes;
            // reset for the next flight (server CCS + Finished).
            in_len = 0;
        }
    }
    return true;
}

i64 TlsSocketSend(TlsSocketState* s, const u8* pt, u32 len)
{
    if (s == nullptr || pt == nullptr || !ConnectionIsEstablished(&s->conn))
        return -1;
    u8 rec[kRecordBufBytes];
    const u32 rec_len = ConnectionEncryptApp(&s->conn, pt, len, rec, sizeof(rec));
    if (rec_len == 0)
        return -1;
    if (s->transport.write(s->transport.ctx, rec, rec_len) != static_cast<i64>(rec_len))
        return -1;
    return static_cast<i64>(len);
}

namespace
{

// Read exactly one complete TLS record off the transport into `rec`.
// Returns the total record length (>0), 0 on EOF, <0 on error.
i64 ReadOneRecord(const TlsTransport& t, u8* rec, u32 cap)
{
    if (cap < 5)
        return -1;
    u32 got = 0;
    while (got < 5)
    {
        const i64 n = t.read(t.ctx, rec + got, 5 - got);
        if (n == 0)
            return 0;
        if (n < 0)
            return -1;
        got += static_cast<u32>(n);
    }
    const u32 payload_len = (static_cast<u32>(rec[3]) << 8) | rec[4];
    const u32 total = 5 + payload_len;
    if (total > cap)
        return -1;
    while (got < total)
    {
        const i64 n = t.read(t.ctx, rec + got, total - got);
        if (n == 0)
            return 0;
        if (n < 0)
            return -1;
        got += static_cast<u32>(n);
    }
    return static_cast<i64>(total);
}

} // namespace

i64 TlsSocketRecv(TlsSocketState* s, u8* buf, u32 cap)
{
    if (s == nullptr || buf == nullptr || !ConnectionIsEstablished(&s->conn))
        return -1;
    u8 rec[kRecordBufBytes];
    const i64 rec_len = ReadOneRecord(s->transport, rec, sizeof(rec));
    if (rec_len <= 0)
        return rec_len; // 0 = EOF, <0 = error
    u32 pt_len = 0;
    if (!ConnectionDecryptApp(&s->conn, rec, static_cast<u32>(rec_len), buf, cap, &pt_len))
        return -1;
    return static_cast<i64>(pt_len);
}

// ---------------------------------------------------------------------------
// net::Socket-backed transport + connect factory
// ---------------------------------------------------------------------------

namespace
{

// The transport ctx is the socket pool index packed into the void*.
i64 SocketTransportRead(void* ctx, u8* buf, u32 len)
{
    const u32 idx = static_cast<u32>(reinterpret_cast<u64>(ctx));
    return SocketRecvStream(idx, buf, len);
}

i64 SocketTransportWrite(void* ctx, const u8* buf, u32 len)
{
    const u32 idx = static_cast<u32>(reinterpret_cast<u64>(ctx));
    u32 sent = 0;
    while (sent < len)
    {
        const i64 n = SocketSendStream(idx, buf + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += static_cast<u32>(n);
    }
    return static_cast<i64>(len);
}

// Fill 32-byte client_random + 48-byte pms (first two bytes 0x03 0x03)
// from the kernel CSPRNG. Shared by TlsSocketConnect and the self-test.
void SeedHandshakeMaterial(u8 client_random[kClientRandomBytes], u8 pms[kPreMasterSecretBytes])
{
    for (u32 i = 0; i < kClientRandomBytes; ++i)
        client_random[i] = static_cast<u8>(core::RandomU64() & 0xFF);
    pms[0] = 0x03;
    pms[1] = 0x03;
    for (u32 i = 2; i < kPreMasterSecretBytes; ++i)
        pms[i] = static_cast<u8>(core::RandomU64() & 0xFF);
}

} // namespace

i32 TlsSocketConnect(TlsSocketState* s, const char* host, u32 ip_be, u16 port)
{
    if (s == nullptr)
        return -1;

    const i32 idx = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
    if (idx < 0)
    {
        KLOG_WARN("net/tls-sock", "connect: socket alloc failed");
        return -1;
    }

    Ipv4Address peer{};
    peer.octets[0] = static_cast<u8>(ip_be & 0xFF);
    peer.octets[1] = static_cast<u8>((ip_be >> 8) & 0xFF);
    peer.octets[2] = static_cast<u8>((ip_be >> 16) & 0xFF);
    peer.octets[3] = static_cast<u8>((ip_be >> 24) & 0xFF);
    if (!SocketConnect(static_cast<u32>(idx), peer, port))
    {
        KLOG_WARN("net/tls-sock", "connect: TCP connect failed");
        SocketRelease(static_cast<u32>(idx));
        return -1;
    }

    TlsTransport t{};
    t.read = SocketTransportRead;
    t.write = SocketTransportWrite;
    t.ctx = reinterpret_cast<void*>(static_cast<u64>(static_cast<u32>(idx)));

    u8 client_random[kClientRandomBytes];
    u8 pms[kPreMasterSecretBytes];
    SeedHandshakeMaterial(client_random, pms);

    if (!TlsSocketHandshake(s, t, host, client_random, pms))
    {
        SocketRelease(static_cast<u32>(idx));
        return -1;
    }
    return idx;
}

// ---------------------------------------------------------------------------
// Boot self-test: in-memory loopback handshake against a server half
// built from the same tls.h primitives, then an app-data round-trip
// each direction. No sockets, no threads — the server is a reactive
// function of the client's writes.
// ---------------------------------------------------------------------------

namespace
{

// 512-bit RSA keypair (e = 65537). n is embedded in the self-signed
// leaf cert below; d is the matching private exponent the loopback
// server uses to recover the PMS from the ClientKeyExchange. Test-
// only material — never used for real connections.
constexpr u8 kServerModulus[64] = {0xd3, 0x1d, 0x5f, 0x09, 0x6c, 0x6c, 0xd0, 0xe7, 0x37, 0x5a, 0x4b, 0x4b, 0x19,
                                   0xad, 0x05, 0x98, 0xa9, 0x6d, 0xa8, 0x59, 0xec, 0x71, 0x40, 0x8e, 0x93, 0xa6,
                                   0x6d, 0x64, 0xfa, 0xf3, 0xa7, 0xd2, 0xfb, 0x7e, 0x6b, 0xb0, 0x8c, 0x90, 0x7e,
                                   0xf7, 0x7e, 0xdc, 0xd3, 0x2d, 0x1b, 0xec, 0xc9, 0xcd, 0x82, 0x1a, 0xce, 0x40,
                                   0xc2, 0xcc, 0xfc, 0x21, 0x6f, 0xe2, 0x24, 0xbb, 0xa5, 0x92, 0x5b, 0x13};
constexpr u8 kServerPrivExp[64] = {0x7e, 0x86, 0xc5, 0xe4, 0xb1, 0xf4, 0xed, 0xa7, 0x05, 0xc7, 0xba, 0x04, 0x82,
                                   0x98, 0xee, 0x17, 0xb6, 0xc3, 0x9f, 0xf8, 0x74, 0xfa, 0xd3, 0x44, 0x20, 0x3d,
                                   0xc8, 0xa6, 0x92, 0xb8, 0xe1, 0x45, 0x3d, 0x07, 0x3d, 0x36, 0xf9, 0x7f, 0x62,
                                   0x9a, 0xaf, 0x9a, 0xd6, 0xb1, 0x18, 0x8b, 0x80, 0x09, 0x8c, 0xa9, 0x98, 0x0f,
                                   0xf6, 0x44, 0xb7, 0x8f, 0x66, 0x3a, 0xc2, 0x18, 0x66, 0xce, 0xb8, 0x61};

// Self-signed leaf for CN=tls-loopback.duetos.test carrying the
// modulus above. Parseable by crypto::x509::Parse (RSA SPKI).
constexpr u8 kServerCertDer[] = {
    0x30, 0x82, 0x01, 0x76, 0x30, 0x82, 0x01, 0x20, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x1b, 0x48, 0x64, 0xbd,
    0x57, 0xc1, 0x2e, 0xc5, 0x74, 0x7b, 0x19, 0xe7, 0x15, 0x7b, 0x8b, 0xcd, 0x8e, 0xea, 0xd8, 0x28, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x18, 0x74, 0x6c, 0x73, 0x2d, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, 0x2e,
    0x64, 0x75, 0x65, 0x74, 0x6f, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36,
    0x30, 0x31, 0x31, 0x32, 0x30, 0x36, 0x31, 0x34, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x35, 0x32, 0x39, 0x31, 0x32,
    0x30, 0x36, 0x31, 0x34, 0x5a, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x18, 0x74,
    0x6c, 0x73, 0x2d, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, 0x2e, 0x64, 0x75, 0x65, 0x74, 0x6f, 0x73, 0x2e,
    0x74, 0x65, 0x73, 0x74, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0xd3, 0x1d, 0x5f, 0x09, 0x6c, 0x6c, 0xd0, 0xe7, 0x37,
    0x5a, 0x4b, 0x4b, 0x19, 0xad, 0x05, 0x98, 0xa9, 0x6d, 0xa8, 0x59, 0xec, 0x71, 0x40, 0x8e, 0x93, 0xa6, 0x6d, 0x64,
    0xfa, 0xf3, 0xa7, 0xd2, 0xfb, 0x7e, 0x6b, 0xb0, 0x8c, 0x90, 0x7e, 0xf7, 0x7e, 0xdc, 0xd3, 0x2d, 0x1b, 0xec, 0xc9,
    0xcd, 0x82, 0x1a, 0xce, 0x40, 0xc2, 0xcc, 0xfc, 0x21, 0x6f, 0xe2, 0x24, 0xbb, 0xa5, 0x92, 0x5b, 0x13, 0x02, 0x03,
    0x01, 0x00, 0x01, 0xa3, 0x2c, 0x30, 0x2a, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x02, 0x5f, 0x61, 0x8b, 0x4b, 0xb2, 0x3c, 0xc3, 0x48,
    0x16, 0x8d, 0xc0, 0xef, 0xab, 0x53, 0x1e, 0x9a, 0xa2, 0x54, 0x9a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x41, 0x00, 0x6a, 0x8d, 0xca, 0xb2, 0x1f, 0x42, 0xb2, 0x41, 0x58,
    0x12, 0xd4, 0xde, 0xe3, 0xbf, 0x36, 0xe5, 0xb5, 0x0b, 0xff, 0x9a, 0xfe, 0xd1, 0xcf, 0x31, 0x4d, 0x2a, 0x1b, 0xff,
    0xf5, 0x2d, 0x62, 0xa0, 0xde, 0x65, 0x18, 0x09, 0xfe, 0x2b, 0xcd, 0x8c, 0xce, 0x3b, 0xef, 0x68, 0x31, 0xb0, 0x44,
    0x6d, 0x64, 0x66, 0x4c, 0x6e, 0xf1, 0x02, 0x85, 0x2c, 0xfb, 0x2b, 0xb2, 0xf6, 0xd7, 0x46, 0xc2, 0x3a};

void EmitFail(const char* label)
{
    arch::SerialWrite("[tls-socket-selftest] FAIL (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0x715Cu);
}

// The loopback "server": holds the server-side handshake state and a
// byte ring the client's transport reads from. It is a pure reactive
// function of the client's writes — no threads. Every crypto step is
// a tls.h or crypto-module call; the only server-only operation is the RSA
// private-key ModExp that recovers the PMS.
struct LoopbackServer
{
    Transcript transcript;
    u8 server_random[kServerRandomBytes];
    u8 client_random[kClientRandomBytes];
    u8 master_secret[kMasterSecretBytes];
    u8 client_key[kAesGcmKeyBytes];
    u8 server_key[kAesGcmKeyBytes];
    u8 client_iv[kAesGcmFixedIvBytes];
    u8 server_iv[kAesGcmFixedIvBytes];
    crypto::BigInt n;
    crypto::BigInt d;
    u8 out[kRecordBufBytes];
    u32 out_len;
    u32 out_consumed;
    u32 flight; // 0 = awaiting ClientHello, 1 = awaiting CKE flight, 2 = done
    bool failed;
    const char* err;
};

void ServerInit(LoopbackServer* sv)
{
    TranscriptInit(&sv->transcript);
    for (u32 i = 0; i < kServerRandomBytes; ++i)
        sv->server_random[i] = static_cast<u8>(0xA0 + i);
    sv->out_len = 0;
    sv->out_consumed = 0;
    sv->flight = 0;
    sv->failed = false;
    sv->err = nullptr;
    crypto::BigIntFromBytesBE(&sv->n, kServerModulus, sizeof(kServerModulus));
    crypto::BigIntFromBytesBE(&sv->d, kServerPrivExp, sizeof(kServerPrivExp));
}

void ServerFail(LoopbackServer* sv, const char* why)
{
    sv->failed = true;
    sv->err = why;
}

// Recover the 48-byte PMS from a ClientKeyExchange body. body =
// 2-byte length + RSA ciphertext (modulus-width). Decrypts via
// ct^d mod n, then strips PKCS#1 v1.5 type-2 padding (00 02 PS 00 M).
bool ServerRecoverPms(LoopbackServer* sv, const u8* cke_body, u32 cke_len, u8 pms[kPreMasterSecretBytes])
{
    if (cke_len < 2)
        return false;
    const u32 ct_len = (static_cast<u32>(cke_body[0]) << 8) | cke_body[1];
    if (ct_len != sizeof(kServerModulus) || 2u + ct_len > cke_len)
        return false;
    crypto::BigInt ct{};
    if (!crypto::BigIntFromBytesBE(&ct, cke_body + 2, ct_len))
        return false;
    crypto::BigInt m{};
    crypto::BigIntModExp(&m, ct, sv->d, sv->n);
    u8 em[sizeof(kServerModulus)];
    crypto::BigIntToBytesBE(m, em, sizeof(em));
    // Expect 00 02 <PS, >= 8 nonzero> 00 <48-byte PMS>.
    if (em[0] != 0x00 || em[1] != 0x02)
        return false;
    u32 i = 2;
    while (i < sizeof(em) && em[i] != 0x00)
        ++i;
    if (i < 10 || i >= sizeof(em))
        return false;
    ++i; // skip the 0x00 separator
    if (sizeof(em) - i != kPreMasterSecretBytes)
        return false;
    for (u32 j = 0; j < kPreMasterSecretBytes; ++j)
        pms[j] = em[i + j];
    return true;
}

// Process the client's first flight (one ClientHello record). Mixes
// it into the transcript, then builds ServerHello + Certificate +
// ServerHelloDone into the out-ring (also mixing each into the
// transcript, matching what the client absorbs).
bool ServerHandleClientHello(LoopbackServer* sv, const u8* rec, u32 rec_len)
{
    RecordView rv{};
    if (!TlsPeekRecord(rec, rec_len, &rv) || rv.type != kContentHandshake)
        return false;
    // Mix the ClientHello handshake message (record payload =
    // header+body) into the server transcript, then capture the
    // client_random from the ServerHello-shaped body offset.
    TranscriptUpdate(&sv->transcript, rv.payload, rv.length);
    HandshakeView hv{};
    if (!TlsPeekHandshake(rv.payload, rv.length, &hv) || hv.type != kHandshakeClientHello)
        return false;
    // ClientHello body: version(2) || client_random(32) || ...
    if (hv.length < 2 + kClientRandomBytes)
        return false;
    for (u32 i = 0; i < kClientRandomBytes; ++i)
        sv->client_random[i] = hv.body[2 + i];

    // ServerHello body (38 bytes): version || random || sid_len(0) ||
    // cipher(0x009C) || compression(0).
    u8 sh_body[2 + kServerRandomBytes + 1 + 2 + 1];
    u32 o = 0;
    sh_body[o++] = 0x03;
    sh_body[o++] = 0x03;
    for (u32 i = 0; i < kServerRandomBytes; ++i)
        sh_body[o++] = sv->server_random[i];
    sh_body[o++] = 0x00; // session_id length
    sh_body[o++] = 0x00; // cipher hi
    sh_body[o++] = 0x9C; // cipher lo
    sh_body[o++] = 0x00; // compression
    const u32 sh_body_len = o;

    // Certificate body: 3-byte list_len || 3-byte cert_len || DER.
    u8 cert_body[16 + sizeof(kServerCertDer)];
    const u32 cert_len = static_cast<u32>(sizeof(kServerCertDer));
    const u32 list_len = 3 + cert_len;
    cert_body[0] = static_cast<u8>((list_len >> 16) & 0xFF);
    cert_body[1] = static_cast<u8>((list_len >> 8) & 0xFF);
    cert_body[2] = static_cast<u8>(list_len & 0xFF);
    cert_body[3] = static_cast<u8>((cert_len >> 16) & 0xFF);
    cert_body[4] = static_cast<u8>((cert_len >> 8) & 0xFF);
    cert_body[5] = static_cast<u8>(cert_len & 0xFF);
    for (u32 i = 0; i < cert_len; ++i)
        cert_body[6 + i] = kServerCertDer[i];
    const u32 cert_body_len = 6 + cert_len;

    // Mix each server handshake message (header+body) into the
    // transcript exactly as the client's ConsumeServerHandshakes does.
    auto mixHs = [&](u8 type, const u8* body, u32 blen)
    {
        u8 hdr[4];
        hdr[0] = type;
        hdr[1] = static_cast<u8>((blen >> 16) & 0xFF);
        hdr[2] = static_cast<u8>((blen >> 8) & 0xFF);
        hdr[3] = static_cast<u8>(blen & 0xFF);
        TranscriptUpdate(&sv->transcript, hdr, 4);
        TranscriptUpdate(&sv->transcript, body, blen);
    };
    mixHs(kHandshakeServerHello, sh_body, sh_body_len);
    mixHs(kHandshakeCertificate, cert_body, cert_body_len);
    mixHs(kHandshakeServerHelloDone, nullptr, 0);

    // Emit the first server flight as ONE coalesced handshake record:
    // [ServerHello | Certificate | ServerHelloDone] concatenated inside
    // a single TLS record payload. Real TLS servers commonly pack the
    // whole flight into one record, and the client's ConnectionFeed
    // completes its SentClientHello -> RecvServerHelloBundle transition
    // off server_cert_seen, which only mixes the trailing
    // ServerHelloDone into the transcript when it rides in the SAME
    // record as the Certificate. Emitting three separate records here
    // (the previous behaviour) dropped the SHD from the client's
    // transcript, diverging it from the server's and breaking the
    // Finished verify. One record mirrors the production happy path.
    auto appendHs = [&](u8 type, const u8* body, u32 blen, u8* dst, u32 dst_off) -> u32
    {
        dst[dst_off + 0] = type;
        dst[dst_off + 1] = static_cast<u8>((blen >> 16) & 0xFF);
        dst[dst_off + 2] = static_cast<u8>((blen >> 8) & 0xFF);
        dst[dst_off + 3] = static_cast<u8>(blen & 0xFF);
        for (u32 i = 0; i < blen; ++i)
            dst[dst_off + 4 + i] = body[i];
        return 4 + blen;
    };
    // Bound: 3 handshake headers + ServerHello body + Certificate body.
    u8 flight[3 * 4 + sizeof(sh_body) + sizeof(cert_body)];
    u32 hs_len = 0;
    hs_len += appendHs(kHandshakeServerHello, sh_body, sh_body_len, flight, hs_len);
    hs_len += appendHs(kHandshakeCertificate, cert_body, cert_body_len, flight, hs_len);
    hs_len += appendHs(kHandshakeServerHelloDone, nullptr, 0, flight, hs_len);
    const u32 off = TlsWrapRecord(kContentHandshake, flight, hs_len, sv->out, sizeof(sv->out));
    sv->out_len = off;
    sv->out_consumed = 0;
    return off > 0;
}

// Process the client's second flight (CKE record + CCS record +
// encrypted client Finished record). Recovers the PMS, derives keys,
// reconstructs the client-Finished transcript contribution, then
// emits server CCS + encrypted server Finished into the out-ring.
bool ServerHandleClientKeyAndFinish(LoopbackServer* sv, const u8* buf, u32 len)
{
    // Record 1: CKE handshake.
    RecordView cke_rv{};
    if (!TlsPeekRecord(buf, len, &cke_rv) || cke_rv.type != kContentHandshake)
        return false;
    HandshakeView cke_hv{};
    if (!TlsPeekHandshake(cke_rv.payload, cke_rv.length, &cke_hv) || cke_hv.type != kHandshakeClientKeyExchange)
        return false;

    u8 pms[kPreMasterSecretBytes];
    if (!ServerRecoverPms(sv, cke_hv.body, cke_hv.length, pms))
        return false;

    // Mix the CKE handshake message (header+body) into the transcript.
    TranscriptUpdate(&sv->transcript, cke_rv.payload, cke_rv.length);

    // Derive master_secret + key_block (same call order as the client).
    TlsMasterSecret(pms, sv->client_random, sv->server_random, sv->master_secret);
    u8 kb[kKeyBlockBytes];
    TlsKeyBlock(sv->master_secret, sv->server_random, sv->client_random, kb);
    u32 o = 0;
    for (u32 i = 0; i < kAesGcmKeyBytes; ++i)
        sv->client_key[i] = kb[o++];
    for (u32 i = 0; i < kAesGcmKeyBytes; ++i)
        sv->server_key[i] = kb[o++];
    for (u32 i = 0; i < kAesGcmFixedIvBytes; ++i)
        sv->client_iv[i] = kb[o++];
    for (u32 i = 0; i < kAesGcmFixedIvBytes; ++i)
        sv->server_iv[i] = kb[o++];

    // Record 2: client ChangeCipherSpec. Record 3: encrypted client
    // Finished. Decrypt the real client Finished (client_key/iv, seq 0)
    // and mix its 16-byte plaintext into the transcript — this is what
    // a real server does, and it guarantees the server's transcript
    // contribution byte-matches whatever the client actually sent.
    const u32 cke_rec_total = 5 + cke_rv.length;
    RecordView ccs_rv{};
    if (!TlsPeekRecord(buf + cke_rec_total, len - cke_rec_total, &ccs_rv) || ccs_rv.type != kContentChangeCipherSpec ||
        ccs_rv.length != 1 || ccs_rv.payload[0] != 0x01)
        return false;
    const u32 ccs_rec_total = 5 + ccs_rv.length;
    const u8* fin_rec = buf + cke_rec_total + ccs_rec_total;
    const u32 fin_rec_len = len - cke_rec_total - ccs_rec_total;
    u8 client_fin_msg[64];
    u32 cfm_len = 0;
    u8 cfm_ctype = 0;
    if (!TlsDecryptRecord(sv->client_key, sv->client_iv, /*seq_num=*/0, fin_rec, fin_rec_len, client_fin_msg,
                          sizeof(client_fin_msg), &cfm_len, &cfm_ctype))
        return false;
    if (cfm_ctype != kContentHandshake || cfm_len != 4 + kVerifyDataBytes || client_fin_msg[0] != kHandshakeFinished)
        return false;
    TranscriptUpdate(&sv->transcript, client_fin_msg, cfm_len);

    // Emit: server ChangeCipherSpec + encrypted server Finished
    // (seq 0, is_client=false, under the server write key/iv).
    u32 off = 0;
    static constexpr u8 ccs_payload[1] = {0x01};
    off += TlsWrapRecord(kContentChangeCipherSpec, ccs_payload, 1, sv->out + off, sizeof(sv->out) - off);
    off += TlsBuildEncryptedFinished(sv->master_secret, sv->transcript, sv->server_key, sv->server_iv,
                                     /*seq_num=*/0, /*is_client=*/false, sv->out + off, sizeof(sv->out) - off);
    sv->out_len = off;
    sv->out_consumed = 0;
    return off > 0;
}

// Transport callbacks: the ctx is a LoopbackServer*. The client's
// write feeds the server (which produces its response into out); the
// client's read drains that out-ring.
i64 LoopbackWrite(void* ctx, const u8* buf, u32 len)
{
    LoopbackServer* sv = static_cast<LoopbackServer*>(ctx);
    if (sv->failed)
        return -1;
    // The client writes exactly two flights: ClientHello (flight 0),
    // then ClientKeyExchange + CCS + Finished (flight 1). Each write
    // is one full flight (the driver writes the connection's emitted
    // bytes in one transport.write call).
    bool ok;
    if (sv->flight == 0)
    {
        ok = ServerHandleClientHello(sv, buf, len);
        sv->flight = 1;
    }
    else if (sv->flight == 1)
    {
        ok = ServerHandleClientKeyAndFinish(sv, buf, len);
        sv->flight = 2;
    }
    else
    {
        ServerFail(sv, "unexpected client write after handshake");
        return -1;
    }
    if (!ok)
    {
        ServerFail(sv, "server flight build failed");
        return -1;
    }
    return static_cast<i64>(len);
}

i64 LoopbackRead(void* ctx, u8* buf, u32 len)
{
    LoopbackServer* sv = static_cast<LoopbackServer*>(ctx);
    if (sv->failed)
        return -1;
    const u32 avail = sv->out_len - sv->out_consumed;
    if (avail == 0)
        return -1; // nothing queued — protocol error in the test
    const u32 n = (len < avail) ? len : avail;
    for (u32 i = 0; i < n; ++i)
        buf[i] = sv->out[sv->out_consumed + i];
    sv->out_consumed += n;
    return static_cast<i64>(n);
}

bool BytesEqual(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

// Exercise ParseCertificateChain — the chain plumbing that now feeds
// the verifier the server's intermediates as well as the leaf. We feed
// a synthetic Certificate body with a leaf + one intermediate (the DER
// payloads are opaque to the parser — it only walks the 3-byte length
// framing) and assert the slices come back pointing at exactly the
// bytes we packed. We also assert two malformed framings fail CLOSED.
// This does NOT prove cryptographic chain validity (X509VerifySelfTest
// owns that against embedded real roots); it pins the wire-splitting
// that delivers the intermediates to net::x509::Verify. Returns true on
// pass; on failure writes a label via the caller's EmitFail.
bool ChainParserSelfCheck(const char** out_fail_label)
{
    // Build a Certificate body: 3-byte list_len || [3-byte len||DER]*.
    // Two opaque "certs": leaf = 5 bytes, intermediate = 7 bytes.
    const u8 leaf_bytes[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const u8 inter_bytes[7] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    u8 body[3 + 3 + sizeof(leaf_bytes) + 3 + sizeof(inter_bytes)];
    u32 o = 0;
    const u32 list_len = 3 + sizeof(leaf_bytes) + 3 + sizeof(inter_bytes);
    body[o++] = static_cast<u8>((list_len >> 16) & 0xFF);
    body[o++] = static_cast<u8>((list_len >> 8) & 0xFF);
    body[o++] = static_cast<u8>(list_len & 0xFF);
    body[o++] = 0x00;
    body[o++] = 0x00;
    body[o++] = static_cast<u8>(sizeof(leaf_bytes));
    for (u8 b : leaf_bytes)
        body[o++] = b;
    body[o++] = 0x00;
    body[o++] = 0x00;
    body[o++] = static_cast<u8>(sizeof(inter_bytes));
    for (u8 b : inter_bytes)
        body[o++] = b;

    ServerChain chain{};
    if (!ParseCertificateChain(body, o, &chain))
    {
        *out_fail_label = "chain-parse-valid-rejected";
        return false;
    }
    if (chain.leaf_len != sizeof(leaf_bytes) || !BytesEqual(chain.leaf, leaf_bytes, sizeof(leaf_bytes)))
    {
        *out_fail_label = "chain-parse-leaf-mismatch";
        return false;
    }
    if (chain.inter_count != 1 || chain.inter_len[0] != sizeof(inter_bytes) ||
        !BytesEqual(chain.inter[0], inter_bytes, sizeof(inter_bytes)))
    {
        *out_fail_label = "chain-parse-inter-mismatch";
        return false;
    }

    // Malformed 1: list_len claims more than the body holds.
    u8 over[6] = {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x05};
    ServerChain bad{};
    if (ParseCertificateChain(over, sizeof(over), &bad))
    {
        *out_fail_label = "chain-parse-overflow-accepted";
        return false;
    }
    // Malformed 2: an inner cert_len runs past the list end.
    u8 runover[9] = {0x00, 0x00, 0x06, 0x00, 0x00, 0x09, 0x01, 0x02, 0x03};
    if (ParseCertificateChain(runover, sizeof(runover), &bad))
    {
        *out_fail_label = "chain-parse-runover-accepted";
        return false;
    }
    return true;
}

} // namespace

// Accept-any verifier for the loopback self-test, which presents a
// self-signed leaf to exercise handshake mechanics, NOT peer auth. The
// default is now fail-closed, so the test must opt in explicitly and
// own that decision (and restore the default afterwards).
static bool SelfTestAcceptAnyVerify(const u8*, u32, const u8* const*, const u32*, u32, const char*, void*)
{
    return true;
}

void TlsSocketSelfTest()
{
    // Install an explicit accept-any verifier for the duration of the
    // test (the loopback cert is self-signed; this test is not about
    // authentication). Saved/restored so the secure fail-closed default
    // is back in place when the test returns.
    CertVerifyFn saved_fn = g_cert_verify_fn;
    void* saved_ctx = g_cert_verify_ctx;
    TlsSocketSetVerifier(SelfTestAcceptAnyVerify, nullptr);
    // Restore the (fail-closed) default on EVERY exit — this function
    // has many early returns on failure legs.
    struct VerifierRestore
    {
        CertVerifyFn fn;
        void* ctx;
        ~VerifierRestore() { TlsSocketSetVerifier(fn, ctx); }
    } verifier_restore{saved_fn, saved_ctx};

    // 1. In-memory loopback handshake: client driver vs. a server
    //    built from the same tls.h primitives.
    static LoopbackServer sv;
    ServerInit(&sv);

    TlsTransport t{};
    t.read = LoopbackRead;
    t.write = LoopbackWrite;
    t.ctx = &sv;

    static TlsSocketState client;
    u8 client_random[kClientRandomBytes];
    u8 pms[kPreMasterSecretBytes];
    SeedHandshakeMaterial(client_random, pms);

    // SNI empty so the server's CN-less expectation doesn't force a
    // hostname match against the test cert (the cert's CN is fixed;
    // the client's cert-CN check is exercised by the x509 self-test).
    if (!TlsSocketHandshake(&client, t, "", client_random, pms))
    {
        // Regression breadcrumb (failure path only — quiet on a clean
        // boot). The historical failure mode was a client/server
        // handshake-transcript divergence: the master secrets matched
        // but the Finished verify_data was computed over different
        // transcript hashes. Dump the master-secret prefix from both
        // halves plus the client's final transcript hash so a future
        // regression here is localised without re-deriving the probe.
        const bool ms_match = BytesEqual(client.conn.master_secret, sv.master_secret, kMasterSecretBytes);
        u8 cli_th[32];
        TranscriptSnapshot(&client.conn.transcript, cli_th);
        arch::SerialWrite("[tls-sock] DBG handshake-failed ms-match=");
        arch::SerialWriteHex(ms_match ? 1u : 0u);
        arch::SerialWrite(" cli-th=");
        arch::SerialWriteHex(static_cast<u64>(cli_th[0]) << 24 | static_cast<u64>(cli_th[1]) << 16 |
                             static_cast<u64>(cli_th[2]) << 8 | cli_th[3]);
        arch::SerialWrite(" state=");
        arch::SerialWriteHex(static_cast<u64>(client.conn.state));
        arch::SerialWrite("\n");
        EmitFail("handshake-not-established");
        return;
    }
    if (!ConnectionIsEstablished(&client.conn))
    {
        EmitFail("client-not-established");
        return;
    }
    if (sv.failed)
    {
        EmitFail("server-failed");
        return;
    }

    // 2. App-data round-trip: client -> server.
    const u8 c2s[] = {'D', 'u', 'e', 't', 'O', 'S', '-', 'C', '2', 'S'};
    u8 rec[256];
    const u32 c2s_rec = ConnectionEncryptApp(&client.conn, c2s, sizeof(c2s), rec, sizeof(rec));
    if (c2s_rec == 0)
    {
        EmitFail("c2s-encrypt");
        return;
    }
    // Server decrypts with the client write key/iv at the client seq
    // the connection used: the client Finished was record seq 0 under
    // the new cipher, so the first app record is seq 1.
    {
        u8 pt[256];
        u32 pt_len = 0;
        u8 ctype = 0;
        if (!TlsDecryptRecord(sv.client_key, sv.client_iv, /*seq_num=*/1, rec, c2s_rec, pt, sizeof(pt), &pt_len,
                              &ctype))
        {
            EmitFail("c2s-decrypt");
            return;
        }
        if (ctype != kContentApplicationData || pt_len != sizeof(c2s) || !BytesEqual(pt, c2s, pt_len))
        {
            EmitFail("c2s-plaintext-mismatch");
            return;
        }
    }

    // 3. App-data round-trip: server -> client.
    // The server Finished was record seq 0 under the new cipher, so
    // its first app-data record is seq 1 — which is the server_seq the
    // client's ConnectionDecryptApp expects (it incremented to 1 after
    // verifying the server Finished).
    const u8 s2c[] = {'D', 'u', 'e', 't', 'O', 'S', '-', 'S', '2', 'C'};
    const u32 s2c_rec = TlsEncryptRecord(sv.server_key, sv.server_iv, /*seq_num=*/1, kContentApplicationData, s2c,
                                         sizeof(s2c), rec, sizeof(rec));
    if (s2c_rec == 0)
    {
        EmitFail("s2c-encrypt");
        return;
    }
    {
        u8 pt[256];
        u32 pt_len = 0;
        if (!ConnectionDecryptApp(&client.conn, rec, s2c_rec, pt, sizeof(pt), &pt_len))
        {
            EmitFail("s2c-decrypt");
            return;
        }
        if (pt_len != sizeof(s2c) || !BytesEqual(pt, s2c, pt_len))
        {
            EmitFail("s2c-plaintext-mismatch");
            return;
        }
    }

    TlsSocketClose(&client);

    // 4. Chain-parser plumbing: prove the leaf + intermediate split
    //    that now feeds net::x509::Verify its intermediates.
    {
        const char* chain_fail = nullptr;
        if (!ChainParserSelfCheck(&chain_fail))
        {
            EmitFail(chain_fail);
            return;
        }
    }

    arch::SerialWrite(
        "[tls-socket-selftest] PASS (loopback handshake established + app-data round-trip both ways + chain-parse)\n");
}

} // namespace duetos::net::tls
