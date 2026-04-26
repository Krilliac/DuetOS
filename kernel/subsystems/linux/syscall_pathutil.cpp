/*
 * DuetOS — Linux ABI: path-handling helpers shared across slices.
 *
 * Sibling TU of syscall.cpp. Houses the small primitives every
 * filesystem-touching handler reuses:
 *
 *   StripFatPrefix:        skip a leading "/fat/" mount prefix.
 *   CopyAndStripFatPath:   user pointer → kernel buffer + strip.
 *   AtFdCwdOnly:           the *at-family AT_FDCWD-only guard.
 *
 * These have no internal state and depend only on mm::CopyFromUser
 * + serial logging, so they sit in their own TU rather than living
 * inside any per-domain handler file. Decls in syscall_internal.h.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/serial.h"
#include "mm/address_space.h"

namespace duetos::subsystems::linux::internal
{

const char* StripFatPrefix(const char* p)
{
    while (*p == '/')
        ++p;
    if (p[0] == 'f' && p[1] == 'a' && p[2] == 't' && p[3] == '/')
        return p + 4;
    return p;
}

bool CopyAndStripFatPath(u64 user_path, char (&kbuf)[64], const char*& out_leaf)
{
    for (u32 i = 0; i < sizeof(kbuf); ++i)
        kbuf[i] = 0;
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_path), sizeof(kbuf) - 1))
        return false;
    kbuf[sizeof(kbuf) - 1] = 0;
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(kbuf); ++i)
    {
        if (kbuf[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
        return false;
    out_leaf = StripFatPrefix(kbuf);
    return true;
}

i64 AtFdCwdOnly(i64 dirfd)
{
    if (dirfd == kAtFdCwd)
        return 0;
    arch::SerialWrite("[linux] *at-family: unsupported dirfd=");
    arch::SerialWriteHex(static_cast<u64>(dirfd));
    arch::SerialWrite(" (AT_FDCWD-only in v0)\n");
    return kEBADF;
}

} // namespace duetos::subsystems::linux::internal
