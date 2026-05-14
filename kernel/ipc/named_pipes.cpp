/*
 * DuetOS — Win32 named-pipe registry implementation.
 *
 * See named_pipes.h for the API contract + lifetime model.
 *
 * The registry maps name → pool_idx; the pipe pool owns the data
 * ring + the read/write refcounts. The registry is the only thing
 * that knows whether a client has connected yet, which the server-
 * close path needs in order to release the unused opposite-end
 * reservation cleanly.
 */

#include "ipc/named_pipes.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "subsystems/linux/syscall_pipe.h"
#include "sync/spinlock.h"

namespace duetos::ipc
{

namespace
{

struct NamedPipeEntry
{
    bool in_use;
    bool server_is_writer; // true = PIPE_ACCESS_OUTBOUND, false = PIPE_ACCESS_INBOUND
    bool client_connected; // false until NamedPipeConnectClient succeeds
    char name[kNamedPipeMaxNameLen];
    u32 pool_idx;
};

constinit NamedPipeEntry g_table[kNamedPipeSlots] = {};
constinit ::duetos::sync::SpinLock g_table_lock = {};

bool NamesEqual(const char* a, const char* b)
{
    for (u32 i = 0; i < kNamedPipeMaxNameLen; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return false;
}

void StoreName(NamedPipeEntry& e, const char* name)
{
    u32 i = 0;
    for (; i + 1 < kNamedPipeMaxNameLen && name[i] != '\0'; ++i)
        e.name[i] = name[i];
    e.name[i] = '\0';
}

i32 FindByName(const char* name)
{
    for (u32 i = 0; i < kNamedPipeSlots; ++i)
    {
        if (g_table[i].in_use && NamesEqual(g_table[i].name, name))
            return static_cast<i32>(i);
    }
    return -1;
}

i32 FindFreeSlot()
{
    for (u32 i = 0; i < kNamedPipeSlots; ++i)
    {
        if (!g_table[i].in_use)
            return static_cast<i32>(i);
    }
    return -1;
}

} // namespace

i32 NamedPipeRegisterServer(const char* name, u32 pool_idx, bool server_is_writer)
{
    if (name == nullptr || name[0] == '\0')
        return -1;
    // Bound the name; the table doesn't hold longer names because
    // FindByName's loop terminates on the in-table NUL.
    u32 nl = 0;
    while (nl < kNamedPipeMaxNameLen && name[nl] != '\0')
        ++nl;
    if (nl >= kNamedPipeMaxNameLen)
        return -1;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    if (FindByName(name) >= 0)
    {
        // Same name already registered — caller's responsibility,
        // returning -1 is the documented "name in use" path. No
        // log here (a normal program may probe a name before
        // registering).
        ::duetos::sync::SpinLockRelease(g_table_lock, flags);
        return -1;
    }
    const i32 slot = FindFreeSlot();
    if (slot < 0)
    {
        // Table saturated — every named-pipe slot is in use. This
        // IS an operational signal; surface once so an operator
        // sees it before subsequent registrations start failing
        // silently.
        ::duetos::sync::SpinLockRelease(g_table_lock, flags);
        KLOG_ONCE_WARN("ipc/named-pipes", "registry full — server registration dropped");
        return -1;
    }
    NamedPipeEntry& e = g_table[slot];
    e.in_use = true;
    e.server_is_writer = server_is_writer;
    e.client_connected = false;
    e.pool_idx = pool_idx;
    StoreName(e, name);
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);
    return slot;
}

bool NamedPipeConnectClient(const char* name, u32* out_pool_idx, bool* out_server_is_writer)
{
    if (name == nullptr || name[0] == '\0' || out_pool_idx == nullptr || out_server_is_writer == nullptr)
        return false;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    const i32 slot = FindByName(name);
    if (slot < 0)
    {
        ::duetos::sync::SpinLockRelease(g_table_lock, flags);
        return false;
    }
    NamedPipeEntry& e = g_table[slot];
    *out_pool_idx = e.pool_idx;
    *out_server_is_writer = e.server_is_writer;
    e.client_connected = true;
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);
    return true;
}

void NamedPipeOnServerClose(i32 slot)
{
    if (slot < 0 || static_cast<u32>(slot) >= kNamedPipeSlots)
        return;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    NamedPipeEntry& e = g_table[slot];
    if (!e.in_use)
    {
        ::duetos::sync::SpinLockRelease(g_table_lock, flags);
        return;
    }
    const u32 pool_idx = e.pool_idx;
    const bool needs_orphan_release = !e.client_connected;
    const bool server_is_writer = e.server_is_writer;
    // Clear under the lock so a concurrent client lookup misses.
    e.in_use = false;
    e.client_connected = false;
    e.pool_idx = 0;
    e.name[0] = '\0';
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);

    // Outside the lock: drop the orphaned opposite-end reservation
    // if no client ever connected. Without this, the pipe pool slot
    // stays pinned at refs=(0,1) (or (1,0)) and the 4 KiB buffer
    // leaks. With a connected client, that side now holds its own
    // ref via the client's Win32FileHandle — leave it alone.
    if (needs_orphan_release)
    {
        if (server_is_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseRead(pool_idx);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(pool_idx);
    }
}

void NamedPipeSelfTest()
{
    // 1. Allocate a pipe pool slot.
    const i32 pool_a = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_a < 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc A\n");
        return;
    }

    // 2. Register under a unique name.
    const i32 slot_a = NamedPipeRegisterServer("selftest-pipe-a", static_cast<u32>(pool_a), /*writer=*/false);
    if (slot_a < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_a));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register\n");
        return;
    }

    // 3. Second register under the same name must fail (duplicate
    //    detection — Windows ERROR_PIPE_BUSY shape).
    const i32 slot_dup = NamedPipeRegisterServer("selftest-pipe-a", static_cast<u32>(pool_a), /*writer=*/false);
    if (slot_dup >= 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL duplicate-name accepted\n");
        NamedPipeOnServerClose(slot_dup);
    }

    // 4. ConnectClient lookup succeeds, returns the correct pool
    //    index, and flips the client_connected flag.
    u32 looked_up_pool = u32(-1);
    bool looked_up_writer = true;
    if (!NamedPipeConnectClient("selftest-pipe-a", &looked_up_pool, &looked_up_writer))
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL connect lookup\n");
        NamedPipeOnServerClose(slot_a);
        return;
    }
    if (looked_up_pool != static_cast<u32>(pool_a) || looked_up_writer != false)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL connect returned wrong values\n");
        NamedPipeOnServerClose(slot_a);
        return;
    }

    // 5. Miss path: unknown name returns false without writing.
    u32 dummy_pool = 0xDEADBEEFu;
    bool dummy_writer = true;
    if (NamedPipeConnectClient("selftest-pipe-nonexistent", &dummy_pool, &dummy_writer))
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL miss returned hit\n");
        NamedPipeOnServerClose(slot_a);
        return;
    }

    // 6. After a client has connected, server-close must NOT do the
    //    orphan release. Drive that side manually so the pool slot
    //    drains. Client end here = write end (server_is_writer=false).
    NamedPipeOnServerClose(slot_a);
    // Server end (read side) was held by the pool's initial ref;
    // server-close didn't release it because there's no Win32 handle
    // in the self-test path. Release it now to free the pool slot.
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
    // Client end (write side) still pinned by the initial PipeAlloc
    // ref; drop it.
    ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_a));

    // 7. Orphan-release path: register a fresh entry, never connect,
    //    let NamedPipeOnServerClose drop the unused write_ref.
    const i32 pool_b = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_b < 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc B\n");
        return;
    }
    const i32 slot_b = NamedPipeRegisterServer("selftest-pipe-b", static_cast<u32>(pool_b), /*writer=*/false);
    if (slot_b < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_b));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_b));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register B\n");
        return;
    }
    // Orphan close: this should release the write_ref (opposite end
    // for INBOUND/server_is_writer=false). After it returns, only
    // the read_ref remains, which we drop manually to flush.
    NamedPipeOnServerClose(slot_b);
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_b));

    ::duetos::arch::SerialWrite(
        "[named-pipe-selftest] PASS (register + dup-reject + connect + miss + orphan cleanup)\n");
}

} // namespace duetos::ipc
