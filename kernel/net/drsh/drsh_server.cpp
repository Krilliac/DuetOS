#include "net/drsh/drsh.h"
#include "net/drsh/drsh_internal.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "security/event_ring.h"
#include "time/timekeeper.h"

/*
 * DRSH — service orchestration.
 *
 * Owns the singleton DrshGlobal, the listener socket, and the server
 * task. `DrshServerStart` opens the listener and spawns the task;
 * `DrshServerStop` flips a stop flag the task polls on its accept
 * boundary and the inner channel loops; the task drops the socket
 * and exits cleanly once it lands at the boundary.
 *
 * Accept loop discipline: SocketAcceptLoopback returns -1 when no
 * pair is pending. We poll on a ~10ms cadence (one scheduler tick at
 * 100 Hz) so a hot CPU doesn't melt when nobody is connecting; the
 * `running` flag is checked between polls so a stop request is
 * acted on within one tick. Once a connection arrives we hand the
 * accepted socket to `MakeSocketTransport`, drive the handshake, and
 * run a channel-multiplex loop until the client disconnects or any
 * frame returns false (link drop).
 *
 * Session lifecycle:
 *
 *   listener -> accept -> handshake
 *     pass: ServerHandshake fills g_global.session, marks
 *           session_active, ConnectionsTotal++
 *     fail: drop link, AuthFailuresTotal++
 *
 *   while authenticated:
 *     RecvFrame
 *       ChannelOpen{ kind=Shell|Desktop } -> open exactly one
 *           channel of that kind, run ShellChannelService /
 *           DesktopChannelService until it returns
 *       ChannelClose / Disconnect -> tear down session
 *       anything else -> tear down (protocol violation)
 *
 *   session teardown clears every byte of session keys with an
 *   explicit overwrite — leaving the slab cell with old AES round
 *   keys in it would be a recovery target for a later allocation.
 */

namespace duetos::net::drsh
{

namespace internal
{

namespace
{

constinit DrshGlobal g_global = {};

void ResetSessionKeys()
{
    auto& sess = g_global.session;
    sess.authenticated = false;
    for (u32 i = 0; i < sizeof(sess.aes_enc.round_keys) / sizeof(sess.aes_enc.round_keys[0]); ++i)
        sess.aes_enc.round_keys[i] = 0;
    for (u32 i = 0; i < kDrshMacKeyBytes; ++i)
        sess.mac_key[i] = 0;
    for (u32 i = 0; i < kDrshCtrBytes; ++i)
        sess.ctr_s2c[i] = 0;
    for (u32 i = 0; i < kDrshCtrBytes; ++i)
        sess.ctr_c2s[i] = 0;
    sess.frames_tx = 0;
    sess.frames_rx = 0;
    sess.bytes_tx = 0;
    sess.bytes_rx = 0;
}

// ----------------------------------------------------------------
// Brute-force lockout — the same shape as security/auth.cpp's
// per-account lockout, applied to the (single, system-wide) DRSH
// pre-shared key. State lives in DrshGlobal; all access is from the
// server task (single-threaded accept loop) plus the admin shell
// commands, which are serialised against it by the scheduler.
// ----------------------------------------------------------------

// True iff the listener is currently refusing connections because the
// failure threshold was crossed. Side effect (mirrors auth.cpp's
// AccountIsLocked): an expired lockout auto-thaws — the streak and
// timer are cleared and an unlock event is published — so the next
// accept boundary that runs past the threshold window re-opens the
// door without a separate sweep.
bool LockoutActive(u64 now_ns)
{
    if (g_global.locked_until_ns == 0)
        return false;
    if (now_ns < g_global.locked_until_ns)
        return true;
    g_global.locked_until_ns = 0;
    g_global.failed_streak = 0;
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountUnlocked, 0, 0 /*expired*/, 0,
                                           "drshd");
    return false;
}

// A successful handshake clears the streak — the legitimate admin just
// proved they hold the key, so an attacker's prior misses shouldn't
// keep them on the brink.
void RegisterAuthSuccess()
{
    g_global.failed_streak = 0;
    g_global.locked_until_ns = 0;
}

// A genuine wrong-credential handshake bumps the streak and, on
// crossing the threshold, arms the timed lockout.
void RegisterAuthFailure(u64 now_ns)
{
    if (g_global.failed_streak < 0xFFFFFFFFu)
        ++g_global.failed_streak;
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthLoginFailure, 0, 0, g_global.failed_streak,
                                           "drshd");
    if (g_global.failed_streak >= kDrshLockoutThreshold && g_global.locked_until_ns == 0)
    {
        g_global.locked_until_ns = now_ns + kDrshLockoutDurationNs;
        duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountLocked, 0,
                                               g_global.failed_streak, kDrshLockoutDurationNs, "drshd");
        KLOG_WARN("net/drsh", "listener locked (consecutive bad-credential handshakes)");
    }
}

bool OpenListenerSocket(u16 port, i32* out_idx)
{
    const i32 idx = duetos::net::SocketAlloc(duetos::net::kSocketDomainInet, duetos::net::kSocketTypeStream);
    if (idx < 0)
        return false;
    duetos::net::Ipv4Address any = {{0, 0, 0, 0}};
    if (!duetos::net::SocketBind(static_cast<u32>(idx), any, port))
    {
        duetos::net::SocketRelease(static_cast<u32>(idx));
        return false;
    }
    if (!duetos::net::SocketListen(static_cast<u32>(idx), /*backlog=*/1))
    {
        duetos::net::SocketRelease(static_cast<u32>(idx));
        return false;
    }
    *out_idx = idx;
    return true;
}

bool HandleSessionFrames(DrshTransport& t)
{
    auto& sess = g_global.session;
    u8 payload[kDrshMaxPayload];
    u32 plen = 0;
    u8 type = 0;
    u8 chan = 0;
    while (g_global.listener_running)
    {
        if (!RecvFrame(t, sess, &type, &chan, payload, &plen))
            return false;
        if (chan != kDrshChannelControl)
        {
            // Channel data outside an open channel — protocol error.
            return false;
        }
        if (type == kDrshFrameDisconnect)
            return true;
        if (type == kDrshFramePing)
        {
            if (!SendFrame(t, sess, kDrshFramePong, kDrshChannelControl, nullptr, 0))
                return false;
            continue;
        }
        if (type != kDrshFrameChannelOpen)
            return false;
        if (plen != 1)
            return false;
        const u8 kind = payload[0];
        if (kind == kDrshKindShell)
        {
            u8 ack = kDrshChannelShell;
            if (!SendFrame(t, sess, kDrshFrameChannelOpenAck, kDrshChannelControl, &ack, 1))
                return false;
            if (!ShellChannelService(t, sess, kDrshChannelShell))
                return false;
        }
        else if (kind == kDrshKindDesktop)
        {
            u8 ack = kDrshChannelDesktop;
            if (!SendFrame(t, sess, kDrshFrameChannelOpenAck, kDrshChannelControl, &ack, 1))
                return false;
            if (!DesktopChannelService(t, sess, kDrshChannelDesktop))
                return false;
        }
        else
        {
            const u8 reason = 0;
            (void)SendFrame(t, sess, kDrshFrameChannelDenied, kDrshChannelControl, &reason, 1);
            // Stay on the control channel so the client can ask for
            // a different kind without re-handshaking.
        }
    }
    return true;
}

void RunOneSession(u32 accepted_idx)
{
    DrshTransport t{};
    if (!MakeSocketTransport(accepted_idx, t))
    {
        duetos::net::SocketRelease(accepted_idx);
        return;
    }
    ResetSessionKeys();
    g_global.session_active = true;

    const HandshakeOutcome outcome = ServerHandshake(t, g_global.password, g_global.password_len, g_global.session);
    if (outcome == HandshakeOutcome::Ok)
    {
        g_global.connections_total += 1;
        RegisterAuthSuccess();
        (void)HandleSessionFrames(t);
    }
    else
    {
        // Any non-Ok outcome counts as a refused handshake for the
        // visible counter, but only a genuine wrong-password attempt
        // (BadCredentials) feeds the brute-force lockout — wire noise
        // and malformed frames must not let a scanner lock out the
        // legitimate admin. See kDrshLockoutThreshold in drsh.h.
        g_global.auth_failures_total += 1;
        if (outcome == HandshakeOutcome::BadCredentials)
            RegisterAuthFailure(duetos::time::MonotonicNs());
        KLOG_WARN("net/drsh", "handshake refused");
    }

    // Best-effort orderly disconnect; ignore failure (likely the
    // peer already closed). Note: cannot send a MAC'd disconnect
    // if auth never completed, but SendFrame handles that.
    (void)SendFrame(t, g_global.session, kDrshFrameDisconnect, kDrshChannelControl, nullptr, 0);

    if (t.Close != nullptr)
        t.Close(t.ctx);
    duetos::net::SocketRelease(accepted_idx);

    ResetSessionKeys();
    g_global.session_active = false;
}

void ServerTaskEntry(void* /*arg*/)
{
    i32 listener_idx = -1;
    if (!OpenListenerSocket(g_global.listen_port, &listener_idx))
    {
        KLOG_ERROR("net/drsh", "listener bind failed");
        g_global.listener_running = false;
        return;
    }
    KLOG_INFO_V("net/drsh", "listening on TCP port", g_global.listen_port);

    while (g_global.listener_running)
    {
        duetos::net::Ipv4Address peer_ip{};
        u16 peer_port = 0;
        const i32 accepted = duetos::net::SocketAcceptLoopback(static_cast<u32>(listener_idx), &peer_ip, &peer_port);
        if (accepted < 0)
        {
            // No pending pair — sleep one tick and re-poll. The
            // stop flag is re-read at the top of the loop so a
            // stop arrives within ~10 ms.
            duetos::sched::SchedSleepTicks(1);
            continue;
        }
        if (g_global.password_len == 0)
        {
            // Listener was running but the password got cleared
            // mid-flight — refuse the connection without crypto.
            duetos::net::SocketRelease(static_cast<u32>(accepted));
            continue;
        }
        if (LockoutActive(duetos::time::MonotonicNs()))
        {
            // Brute-force wall is up: drop the connection before any
            // crypto runs, so a flood of attempts during the lockout
            // window costs the box a SocketRelease, not a PBKDF2.
            g_global.throttled_total += 1;
            duetos::net::SocketRelease(static_cast<u32>(accepted));
            continue;
        }
        RunOneSession(static_cast<u32>(accepted));
    }

    KLOG_INFO("net/drsh", "listener stopping");
    duetos::net::SocketRelease(static_cast<u32>(listener_idx));
    g_global.listener_running = false;
}

} // namespace

DrshGlobal& Globals()
{
    return g_global;
}

bool RunLockoutSelfTest()
{
    // Snapshot the live lockout fields so the boot self-test is
    // non-destructive — the service is off at boot, but the streak /
    // timer are real global state and we must hand them back intact.
    const u32 saved_streak = g_global.failed_streak;
    const u64 saved_until = g_global.locked_until_ns;
    const u64 saved_throttled = g_global.throttled_total;

    bool ok = true;
    const u64 t0 = 1'000'000'000ull; // arbitrary synthetic clock base

    g_global.failed_streak = 0;
    g_global.locked_until_ns = 0;

    // Below threshold: no lock.
    for (u32 i = 0; i + 1 < kDrshLockoutThreshold; ++i)
        RegisterAuthFailure(t0);
    if (LockoutActive(t0))
        ok = false;

    // Crossing the threshold arms the timed lockout.
    RegisterAuthFailure(t0);
    if (!LockoutActive(t0))
        ok = false;
    // A wrong attempt while locked must still be refused by the clock,
    // not re-armed past the original window.
    if (!LockoutActive(t0 + kDrshLockoutDurationNs - 1))
        ok = false;

    // Past expiry: auto-thaw clears both the timer and the streak.
    if (LockoutActive(t0 + kDrshLockoutDurationNs))
        ok = false;
    if (g_global.locked_until_ns != 0 || g_global.failed_streak != 0)
        ok = false;

    // Re-arm, then confirm the manual clear path drops the lock.
    for (u32 i = 0; i < kDrshLockoutThreshold; ++i)
        RegisterAuthFailure(t0);
    if (!LockoutActive(t0))
        ok = false;
    g_global.failed_streak = 0;
    g_global.locked_until_ns = 0;
    if (LockoutActive(t0))
        ok = false;

    // Restore.
    g_global.failed_streak = saved_streak;
    g_global.locked_until_ns = saved_until;
    g_global.throttled_total = saved_throttled;
    return ok;
}

} // namespace internal

void DrshInit()
{
    auto& g = internal::g_global;
    if (g.initialized)
        return;
    g.initialized = true;
    g.password_set = false;
    g.listener_running = false;
    g.session_active = false;
    g.listen_port = kDrshDefaultPort;
    g.password_len = 0;
    for (u32 i = 0; i < kDrshMaxPasswordBytes; ++i)
        g.password[i] = 0;
    g.connections_total = 0;
    g.auth_failures_total = 0;
    g.failed_streak = 0;
    g.locked_until_ns = 0;
    g.throttled_total = 0;
    internal::ResetSessionKeys();
}

bool DrshSetPassword(const char* password)
{
    DrshInit();
    auto& g = internal::g_global;
    if (g.listener_running)
    {
        // Refuse to rotate while a session might be in flight; the
        // KDF binds the password into the session keys, and a
        // rotation now would break an in-flight handshake without
        // any way for the client to learn it should retry.
        return false;
    }
    if (password == nullptr)
        return false;
    u32 len = 0;
    while (password[len] != '\0' && len < kDrshMaxPasswordBytes)
        ++len;
    if (password[len] != '\0' && len == kDrshMaxPasswordBytes)
        return false; // overflow
    for (u32 i = 0; i < kDrshMaxPasswordBytes; ++i)
        g.password[i] = 0;
    for (u32 i = 0; i < len; ++i)
        g.password[i] = static_cast<u8>(password[i]);
    g.password_len = len;
    g.password_set = (len > 0);
    // A key rotation is a clean slate, mirroring AuthChangePassword:
    // lift any standing lockout and zero the failure streak so the
    // admin who just set a new secret isn't left locked out by the
    // attempts that prompted the rotation.
    g.failed_streak = 0;
    g.locked_until_ns = 0;
    return true;
}

bool DrshServerStart(u16 port)
{
    DrshInit();
    auto& g = internal::g_global;
    if (g.listener_running)
        return false;
    if (!g.password_set)
    {
        KLOG_WARN("net/drsh", "refusing to start: no password set");
        return false;
    }
    g.listen_port = (port == 0) ? kDrshDefaultPort : port;
    g.listener_running = true;
    duetos::sched::SchedCreate(&internal::ServerTaskEntry, nullptr, "drshd");
    return true;
}

void DrshServerStop()
{
    auto& g = internal::g_global;
    if (!g.listener_running)
        return;
    g.listener_running = false;
    // Server task will exit on its next accept poll (~10 ms). We
    // do NOT block here — caller is a shell command and the user
    // will see the listener_running flag flip in `drshd status`.
}

void DrshUnlock()
{
    auto& g = internal::g_global;
    const bool was_locked = g.locked_until_ns != 0;
    g.failed_streak = 0;
    g.locked_until_ns = 0;
    if (was_locked)
    {
        duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountUnlocked, 0, 1 /*manual*/, 0,
                                               "drshd");
    }
}

DrshStatus DrshServerStatus()
{
    auto& g = internal::g_global;
    DrshStatus s{};
    s.running = g.listener_running;
    s.listening = g.listener_running;
    s.session_active = g.session_active;
    s.authenticated = g.session.authenticated;
    s.password_set = g.password_set ? 1 : 0;
    s.listen_port = g.listen_port;
    s.connections_total = g.connections_total;
    s.auth_failures_total = g.auth_failures_total;
    s.frames_rx = g.session.frames_rx;
    s.frames_tx = g.session.frames_tx;
    s.bytes_rx = g.session.bytes_rx;
    s.bytes_tx = g.session.bytes_tx;
    s.throttled_total = g.throttled_total;
    s.locked_until_ns = g.locked_until_ns;
    s.failed_streak = g.failed_streak;
    return s;
}

void DrshSelfTest()
{
    // Cheap, deterministic round-trip: derive a fixed pair of
    // session keys, encrypt+MAC a frame, decrypt+verify on the
    // same struct, ensure plaintext matches. No transport involved.
    const u8 pmk[kDrshPmkBytes] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    const u8 nonce_s[kDrshNonceBytes] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                         0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    const u8 nonce_c[kDrshNonceBytes] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                                         0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};

    internal::DrshSession tx{};
    internal::DrshSession rx{};
    internal::DeriveSessionKeys(pmk, nonce_s, nonce_c, tx);
    internal::DeriveSessionKeys(pmk, nonce_s, nonce_c, rx);
    tx.authenticated = true;
    rx.authenticated = true;

    // DeriveSessionKeys produces a server-side session: SendFrame uses
    // ctr_s2c, RecvFrame uses ctr_c2s. For the selftest's in-memory
    // round-trip, tx acts as the server (sends on s2c) and rx must act
    // as the client peer (receives s2c-encrypted bytes). Swap rx's
    // counter slots so RecvFrame's ctr_c2s read decrypts with the
    // counter tx used to encrypt. Production callers never need this
    // swap — only the server runs in-tree today, and its SendFrame /
    // RecvFrame pair is the natural s2c-out / c2s-in mapping.
    {
        u8 swap_tmp[kDrshCtrBytes];
        for (u32 i = 0; i < kDrshCtrBytes; ++i)
            swap_tmp[i] = rx.ctr_s2c[i];
        for (u32 i = 0; i < kDrshCtrBytes; ++i)
            rx.ctr_s2c[i] = rx.ctr_c2s[i];
        for (u32 i = 0; i < kDrshCtrBytes; ++i)
            rx.ctr_c2s[i] = swap_tmp[i];
    }

    // Build a synthetic transport over an in-memory pipe.
    struct Pipe
    {
        u8 buf[internal::kDrshFrameHdrBytes + kDrshMaxPayload + kDrshHmacTagBytes];
        u32 len;
        u32 read_off;
    };
    Pipe pipe{};
    pipe.len = 0;
    pipe.read_off = 0;

    auto pipe_write = [](void* ctx, const u8* b, u32 n) -> bool
    {
        auto* p = reinterpret_cast<Pipe*>(ctx);
        if (p->len + n > sizeof(p->buf))
            return false;
        for (u32 i = 0; i < n; ++i)
            p->buf[p->len + i] = b[i];
        p->len += n;
        return true;
    };
    auto pipe_read = [](void* ctx, u8* b, u32 n) -> bool
    {
        auto* p = reinterpret_cast<Pipe*>(ctx);
        if (p->read_off + n > p->len)
            return false;
        for (u32 i = 0; i < n; ++i)
            b[i] = p->buf[p->read_off + i];
        p->read_off += n;
        return true;
    };

    internal::DrshTransport sink{};
    sink.ctx = &pipe;
    sink.WriteAll = pipe_write;
    sink.ReadExact = pipe_read;
    sink.Close = nullptr;

    const u8 msg[] = "DRSH-SELFTEST";
    if (!internal::SendFrame(sink, tx, kDrshFrameChannelData, kDrshChannelShell, msg, sizeof(msg) - 1))
    {
        arch::SerialWrite("[net/drsh-selftest] FAIL (send)\n");
        return;
    }
    u8 type = 0;
    u8 chan = 0;
    u8 got[kDrshMaxPayload];
    u32 got_len = 0;
    if (!internal::RecvFrame(sink, rx, &type, &chan, got, &got_len))
    {
        arch::SerialWrite("[net/drsh-selftest] FAIL (recv)\n");
        return;
    }
    if (type != kDrshFrameChannelData || chan != kDrshChannelShell || got_len != sizeof(msg) - 1)
    {
        arch::SerialWrite("[net/drsh-selftest] FAIL (shape)\n");
        return;
    }
    for (u32 i = 0; i < got_len; ++i)
    {
        if (got[i] != msg[i])
        {
            arch::SerialWrite("[net/drsh-selftest] FAIL (mismatch)\n");
            return;
        }
    }

    if (!internal::RunLockoutSelfTest())
    {
        arch::SerialWrite("[net/drsh-selftest] FAIL (lockout)\n");
        return;
    }

    arch::SerialWrite("[net/drsh-selftest] PASS (frame round-trip + lockout)\n");
}

} // namespace duetos::net::drsh
