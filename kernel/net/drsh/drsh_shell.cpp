#include "net/drsh/drsh_internal.h"

#include "drivers/video/console.h"
#include "log/klog.h"
#include "shell/shell_internal.h"

/*
 * DRSH — shell channel.
 *
 * One-line-at-a-time terminal session bridged into the kernel shell
 * dispatcher. Each inbound ChannelData payload is treated as a UTF-8
 * command line; we hand it to `Dispatch()` and tee the resulting
 * shell-console writes back to the client as a ChannelData reply.
 *
 * Why "line at a time" instead of true pty-style char-by-char:
 *
 *   - The kernel shell already exposes `Dispatch(char*)` as the
 *     single entry point. Re-using it gives us, for free, the full
 *     command surface (~200 verbs), the cap-gated admin checks, env
 *     vars, history, pipes, aliases — without re-implementing any
 *     of it.
 *   - The shell doesn't have a per-task input multiplexer; the
 *     local keyboard-driven shell and a remote DRSH client cannot
 *     share an active line-editor without a per-session input
 *     stream the v0 shell doesn't expose.
 *   - Tab completion and line editing are client-side concerns;
 *     a sensible DRSH client reads a full line locally and submits
 *     it. This matches how most legacy SSH-based admin tools used
 *     to run before the pty path was standardised.
 *
 * Output capture uses `ConsoleBeginCapture` / `ConsoleEndCapture`,
 * the same hooks the shell's pipe stage uses internally. While
 * capture is active, the local framebuffer console doesn't display
 * the output — that's intentional: we don't want a remote command
 * to spew on the operator's screen, and we don't want the remote
 * output to also tee through the local serial mirror.
 */

namespace duetos::net::drsh::internal
{

namespace
{

// Per-command output buffer. Sized to a single DRSH frame so we can
// flush in one ChannelData send without re-fragmenting. Long output
// is chunked: capture fills, we send, we re-arm capture, the shell
// keeps writing.
constexpr u32 kShellChunkBytes = kDrshMaxPayload - 4; // leave space for in-band markers
static char g_chunk_buf[kShellChunkBytes];
static u32 g_chunk_len = 0;

bool SendShellLine(DrshTransport& t, DrshSession& s, u8 channel_id, const char* data, u32 len)
{
    return SendFrame(t, s, kDrshFrameChannelData, channel_id, reinterpret_cast<const u8*>(data), len);
}

// Best-effort prompt — emit a "$ " into the chunk so the client UI
// can render it like a local terminal. The actual kernel shell's
// $PS1 is a per-session concept the remote terminal isn't bound to,
// so we keep this constant.
bool SendShellPrompt(DrshTransport& t, DrshSession& s, u8 channel_id)
{
    const char prompt[] = "drsh$ ";
    return SendShellLine(t, s, channel_id, prompt, sizeof(prompt) - 1);
}

// Drain any captured output into a ChannelData frame back to the
// client. Returns false on transport failure.
bool FlushCapturedOutput(DrshTransport& t, DrshSession& s, u8 channel_id)
{
    if (g_chunk_len == 0)
        return true;
    const bool ok = SendShellLine(t, s, channel_id, g_chunk_buf, g_chunk_len);
    g_chunk_len = 0;
    return ok;
}

} // namespace

bool ShellChannelService(DrshTransport& t, DrshSession& s, u8 channel_id)
{
    // Greet the client so it knows the channel is live.
    if (!SendShellPrompt(t, s, channel_id))
        return false;

    // Per-command input line. Caps at one DRSH payload — any more
    // than that on one line and the client should have submitted
    // it as a separate command anyway.
    static char line_buf[kDrshMaxPayload + 1];

    u8 payload[kDrshMaxPayload];
    u32 plen = 0;
    u8 type = 0;
    u8 chan = 0;
    while (true)
    {
        if (!RecvFrame(t, s, &type, &chan, payload, &plen))
            return false;

        if (chan != channel_id)
        {
            // Out-of-channel frames at this point are a protocol
            // violation; drop the link.
            return false;
        }
        if (type == kDrshFrameChannelClose)
        {
            KLOG_INFO("net/drsh", "shell channel: close requested by client");
            return true;
        }
        if (type == kDrshFramePing)
        {
            if (!SendFrame(t, s, kDrshFramePong, kDrshChannelControl, nullptr, 0))
                return false;
            continue;
        }
        if (type != kDrshFrameChannelData)
        {
            // Unknown frame type — drop the link, this client is
            // misbehaving and we'd rather be safe than guess.
            return false;
        }
        if (plen == 0)
        {
            // Empty data = bare Enter; re-prompt and continue.
            if (!SendShellPrompt(t, s, channel_id))
                return false;
            continue;
        }
        if (plen >= sizeof(line_buf))
        {
            // Oversize line — refuse cleanly rather than silently
            // truncate. A truncated command would execute the
            // wrong thing.
            const char msg[] = "drsh: line too long\n";
            if (!SendShellLine(t, s, channel_id, msg, sizeof(msg) - 1))
                return false;
            if (!SendShellPrompt(t, s, channel_id))
                return false;
            continue;
        }

        // Copy payload to a null-terminated mutable buffer for
        // Dispatch (which writes into the line). Strip a trailing
        // CR / LF if the client included them.
        u32 nlen = plen;
        while (nlen > 0 && (payload[nlen - 1] == '\r' || payload[nlen - 1] == '\n'))
            --nlen;
        for (u32 i = 0; i < nlen; ++i)
            line_buf[i] = static_cast<char>(payload[i]);
        line_buf[nlen] = '\0';

        // Special-case "exit" / "quit" — close the channel without
        // letting the kernel shell take down the local session.
        if ((nlen == 4 && line_buf[0] == 'e' && line_buf[1] == 'x' && line_buf[2] == 'i' && line_buf[3] == 't') ||
            (nlen == 4 && line_buf[0] == 'q' && line_buf[1] == 'u' && line_buf[2] == 'i' && line_buf[3] == 't'))
        {
            const char msg[] = "drsh: goodbye\n";
            (void)SendShellLine(t, s, channel_id, msg, sizeof(msg) - 1);
            (void)SendFrame(t, s, kDrshFrameChannelClose, channel_id, nullptr, 0);
            return true;
        }

        // Run the line under output capture; flush to client.
        g_chunk_len = 0;
        duetos::drivers::video::ConsoleBeginCapture(g_chunk_buf, kShellChunkBytes, &g_chunk_len);
        duetos::core::shell::internal::Dispatch(line_buf);
        duetos::drivers::video::ConsoleEndCapture();
        if (!FlushCapturedOutput(t, s, channel_id))
            return false;
        if (!SendShellPrompt(t, s, channel_id))
            return false;
    }
}

} // namespace duetos::net::drsh::internal
