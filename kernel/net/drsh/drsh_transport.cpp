#include "net/drsh/drsh_internal.h"

#include "mm/kheap.h"
#include "net/socket.h"
#include "sched/sched.h"

/*
 * DRSH — socket-backed transport.
 *
 * Wraps a kernel TCP socket (post-accept) in the DrshTransport vtable
 * the protocol layer talks to. ReadExact / WriteAll drive SocketRecv-
 * Stream / SocketSendStream in a loop until the requested byte count
 * is delivered or the socket reports EOF / error.
 *
 * Why this lives in its own TU: keeps the framer + auth + channel
 * code free of socket-layer knowledge. When the kernel grows a
 * second carrier (a VirtIO console, a USB CDC pipe, etc.), a new
 * transport TU plugs in without touching the protocol.
 *
 * v0 caveat — the kernel TCP stack only carries one bidirectional
 * connection at a time. Loopback paired-socket sessions work today;
 * a real on-wire client is reachable only as long as no other TCP
 * caller (e.g. `http` shell command) is competing for the slot. The
 * service does NOT attempt to arbitrate that — the existing slot
 * mechanism returns false to the second caller, which is the
 * desired refusal shape. A stack-v1 multi-connection slot will
 * remove the limit without protocol changes.
 */

namespace duetos::net::drsh::internal
{

namespace
{

struct SocketCtx
{
    u32 socket_idx;
    bool closed;
};

bool SocketReadExact(void* opaque, u8* buf, u32 len)
{
    auto* ctx = reinterpret_cast<SocketCtx*>(opaque);
    if (ctx == nullptr || ctx->closed)
        return false;
    u32 got = 0;
    while (got < len)
    {
        const i64 r = duetos::net::SocketRecvStream(ctx->socket_idx, buf + got, len - got);
        if (r == 0)
        {
            // EOF / peer half-close — the requested byte count is
            // not deliverable. Caller must drop the frame and tear
            // down. Mark closed so any later WriteAll fails fast.
            ctx->closed = true;
            return false;
        }
        if (r < 0)
        {
            // -EAGAIN comes back during handshake startup; everything
            // else is fatal. We yield a tick and retry on EAGAIN so
            // the framer doesn't spin.
            if (r == -11) // EAGAIN
            {
                duetos::sched::SchedSleepTicks(1);
                continue;
            }
            ctx->closed = true;
            return false;
        }
        got += static_cast<u32>(r);
    }
    return true;
}

bool SocketWriteAll(void* opaque, const u8* buf, u32 len)
{
    auto* ctx = reinterpret_cast<SocketCtx*>(opaque);
    if (ctx == nullptr || ctx->closed)
        return false;
    u32 sent = 0;
    while (sent < len)
    {
        const i64 w = duetos::net::SocketSendStream(ctx->socket_idx, buf + sent, len - sent);
        if (w == 0)
        {
            // Zero-byte send on a non-zero request is an unusual
            // socket-layer response; treat it as transient and
            // yield once before retry.
            duetos::sched::SchedSleepTicks(1);
            continue;
        }
        if (w < 0)
        {
            if (w == -11) // EAGAIN — handshake / window-full
            {
                duetos::sched::SchedSleepTicks(1);
                continue;
            }
            ctx->closed = true;
            return false;
        }
        sent += static_cast<u32>(w);
    }
    return true;
}

void SocketCloseTransport(void* opaque)
{
    auto* ctx = reinterpret_cast<SocketCtx*>(opaque);
    if (ctx == nullptr)
        return;
    if (!ctx->closed)
    {
        // SHUT_RDWR — orderly half-close in both directions. The
        // socket itself is owned by the listener accept path; the
        // server loop releases the socket idx after this returns.
        duetos::net::SocketShutdown(ctx->socket_idx, 2);
        ctx->closed = true;
    }
    duetos::mm::KFree(ctx);
}

} // namespace

bool MakeSocketTransport(u32 socket_idx, DrshTransport& out)
{
    auto* ctx = reinterpret_cast<SocketCtx*>(duetos::mm::KMalloc(sizeof(SocketCtx)));
    if (ctx == nullptr)
        return false;
    ctx->socket_idx = socket_idx;
    ctx->closed = false;
    out.ctx = ctx;
    out.ReadExact = &SocketReadExact;
    out.WriteAll = &SocketWriteAll;
    out.Close = &SocketCloseTransport;
    return true;
}

} // namespace duetos::net::drsh::internal
