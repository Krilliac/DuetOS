// Rust → C++ panic bridge.
//
// The duetfs crate's #[panic_handler] (kernel/fs/duetfs/src/panic.rs)
// calls `duetos_rust_panic(msg, msg_len)`. Rust string slices are
// (ptr, len) without a NUL terminator, so we copy into a fixed
// kernel buffer, terminate, and route through the standard
// kernel Panic() path — same dump format as a C++ Panic(),
// distinguishable by the `rust/duetfs` subsystem tag.
//
// Buffer is intentionally small. A useful Rust panic literal in
// this crate fits in 192 bytes; longer messages get truncated
// rather than spilling onto the kernel stack. The caller's
// `msg_len` is the source-of-truth length — we never strlen the
// pointer.

#include "core/panic.h"
#include "util/types.h"

extern "C" [[noreturn]] void duetos_rust_panic(const duetos::u8* msg, duetos::usize msg_len)
{
    using duetos::u8;
    using duetos::usize;

    static constexpr usize kBufMax = 191;
    char buf[kBufMax + 1] = {};

    if (msg != nullptr && msg_len > 0)
    {
        const usize n = (msg_len < kBufMax) ? msg_len : kBufMax;
        for (usize i = 0; i < n; ++i)
        {
            const u8 b = msg[i];
            // Strip non-printable bytes — a panic message should be
            // ASCII; anything else is corruption.
            buf[i] = (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '?';
        }
        buf[n] = '\0';
    }
    else
    {
        const char fallback[] = "duetfs panic (no message)";
        for (usize i = 0; i < sizeof(fallback); ++i)
        {
            buf[i] = fallback[i];
        }
    }

    duetos::core::Panic("rust/duetfs", buf);
}
