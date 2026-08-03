/*
 * DuetOS — Win32 named-pipe registry implementation.
 *
 * See named_pipes.h for the API contract + lifetime model.
 *
 * The registry maps name → pool_idx; the pipe pool owns the data
 * ring + the read/write refcounts. PipeAlloc's opposite-end reference is
 * owned by the registry until exact server close. Every client takes a fresh
 * reference of its own, so registry teardown releases its reference whether
 * or not a client connected.
 */

#include "ipc/named_pipes.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
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
    char name[kNamedPipeMaxNameLen];
    u32 pool_idx;
    // Bumped on every claim of this slot. The only identity the
    // registry carries: {in_use, name, pool_idx} are all recycled,
    // and FindFreeSlot hands back the lowest free index, so a torn-
    // down slot is the very next one issued. Without a generation,
    // NamedPipeOnServerClose could not tell a stale close from a
    // legitimate one and would tear down the registration that
    // recycled the index.
    u32 generation;
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
        // Generation zero is invalid and wrap is never permitted: once a slot
        // has issued UINT32_MAX it retires instead of replaying an old token.
        if (!g_table[i].in_use && g_table[i].generation != ~0U)
            return static_cast<i32>(i);
    }
    return -1;
}

} // namespace

i32 NamedPipeRegisterServer(const char* name, u32 pool_idx, bool server_is_writer, u32* out_generation)
{
    if (name == nullptr || name[0] == '\0' || out_generation == nullptr)
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
    e.pool_idx = pool_idx;
    // Bump before publishing so every registration this slot has ever held
    // owns a distinct non-zero generation. FindFreeSlot permanently retires a
    // saturated row; ABA identity is never allowed to wrap.
    e.generation += 1;
    StoreName(e, name);
    *out_generation = e.generation;
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
    const u32 pool_idx = e.pool_idx;
    const bool server_is_writer = e.server_is_writer;
    // Exact server close must remove this same entry under g_table_lock before
    // releasing the registry-owned opposite end. Take the client's distinct
    // retain before exposing the pool index, closing the lookup -> close ->
    // pool-recycle race without transferring registry ownership.
    const bool client_is_writer = !server_is_writer;
    const bool retained = client_is_writer ? ::duetos::subsystems::linux::internal::PipeRetainWrite(pool_idx)
                                           : ::duetos::subsystems::linux::internal::PipeRetainRead(pool_idx);
    if (retained)
    {
        *out_pool_idx = pool_idx;
        *out_server_is_writer = server_is_writer;
    }
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);
    return retained;
}

void NamedPipeOnServerClose(i32 slot, u32 generation)
{
    if (slot < 0 || static_cast<u32>(slot) >= kNamedPipeSlots)
        return;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    // Belt-and-braces post-guard: the bound was just verified in the
    // early return above. Wild-store to a local `slot` between the
    // check and this index would silently scribble outside g_table,
    // overwriting the SpinLock storage or adjacent state. KASSERT
    // catches it before the index hits the array.
    KASSERT_WITH_VALUE(static_cast<u32>(slot) < kNamedPipeSlots, "ipc/named_pipes", "slot index oob after guard",
                       static_cast<u64>(slot));
    NamedPipeEntry& e = g_table[slot];
    // Identity gate. `in_use` alone only rejects a replay against a
    // still-free slot; the dangerous case is a slot that a DIFFERENT
    // CreateNamedPipe has since recycled, where the teardown below
    // would unregister a live name and drop a pool reference the
    // caller never owned. The generation is the registry's only
    // identity, so check it before touching anything.
    if (!e.in_use || e.generation != generation)
    {
        ::duetos::sync::SpinLockRelease(g_table_lock, flags);
        return;
    }
    const u32 pool_idx = e.pool_idx;
    const bool server_is_writer = e.server_is_writer;
    // Clear under the lock so a concurrent client lookup misses.
    e.in_use = false;
    e.pool_idx = 0;
    e.name[0] = '\0';
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);

    // Outside the lock: always release the registry-owned opposite-end
    // reference seeded by PipeAlloc. A connected client owns a distinct fresh
    // retain; treating that retain as if it replaced the registry reference
    // leaves refs=(0,1)/(1,0) after the client closes and leaks the pool slot.
    if (server_is_writer)
        ::duetos::subsystems::linux::internal::PipeReleaseRead(pool_idx);
    else
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(pool_idx);
}

namespace
{

// ABA identity check, split out of NamedPipeSelfTest so neither
// function grows past the readable-length guideline. Returns false
// only when the pool ran dry (setup failure, not a regression);
// property failures emit their own FAIL line and still return true
// so the remaining teardown runs.
bool NamedPipeAbaReplayCheck()
{
    // Replaying a torn-down registration's close must NOT tear down
    // the registration that recycled the slot. FindFreeSlot returns
    // the lowest free index, so C's slot is handed straight back to
    // D — the recycle needs no race. This pins the fix for the
    // inherited-handle bug: a duplicated server slot that outlived
    // its registration used to unregister a live name and drop a
    // pool ref its holder never owned (a cross-process confused
    // deputy — the stale holder could be an untrusted child that
    // only ever got stdout).
    const i32 pool_c = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_c < 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc C\n");
        return false;
    }
    u32 gen_c = 0;
    const i32 slot_c = NamedPipeRegisterServer("selftest-pipe-c", static_cast<u32>(pool_c), /*writer=*/false, &gen_c);
    if (slot_c < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_c));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_c));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register C\n");
        return false;
    }
    // Tear C down completely so its slot goes back on the free list.
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_c));
    NamedPipeOnServerClose(slot_c, gen_c);

    const i32 pool_d = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_d < 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc D\n");
        return false;
    }
    u32 gen_d = 0;
    const i32 slot_d = NamedPipeRegisterServer("selftest-pipe-d", static_cast<u32>(pool_d), /*writer=*/false, &gen_d);
    if (slot_d < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_d));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_d));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register D\n");
        return false;
    }
    if (slot_d != slot_c)
        ::duetos::core::Panic("ipc/named-pipes", "ABA fixture did not recycle the expected registry slot");
    if (gen_d == gen_c)
        ::duetos::core::Panic("ipc/named-pipes", "registry generation did not advance on slot reuse");

    // Replay C's close. D must survive it untouched.
    NamedPipeOnServerClose(slot_c, gen_c);
    u32 aba_pool = u32(-1);
    bool aba_writer = true;
    const bool aba_connected = NamedPipeConnectClient("selftest-pipe-d", &aba_pool, &aba_writer);
    if (!aba_connected || aba_pool != static_cast<u32>(pool_d))
        ::duetos::core::Panic("ipc/named-pipes", "stale close unregistered a recycled live entry");
    // D's ring is empty and its write end is still reserved, so a read
    // would block — PipeReadReady only turns true once every writer is
    // gone. A wrongly-fired orphan release would have dropped exactly
    // that reservation.
    if (::duetos::subsystems::linux::internal::PipeReadReady(static_cast<u32>(pool_d)))
        ::duetos::core::Panic("ipc/named-pipes", "stale close dropped a recycled reservation reference");

    // Drain the server end, registry reservation, and the probe's atomically
    // retained client end in real close order.
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_d));
    NamedPipeOnServerClose(slot_d, gen_d);
    if (aba_connected)
    {
        if (!aba_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(aba_pool);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(aba_pool);
    }
    return true;
}

} // namespace

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
    u32 gen_a = 0;
    const i32 slot_a = NamedPipeRegisterServer("selftest-pipe-a", static_cast<u32>(pool_a), /*writer=*/false, &gen_a);
    if (slot_a < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_a));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register\n");
        return;
    }

    // 3. Second register under the same name must fail (duplicate
    //    detection — Windows ERROR_PIPE_BUSY shape). Give the probe its own
    //    reference set so a rejection regression cannot corrupt pool_a.
    const i32 pool_dup = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_dup < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        NamedPipeOnServerClose(slot_a, gen_a);
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc duplicate probe\n");
        return;
    }
    u32 gen_dup = 0;
    const i32 slot_dup =
        NamedPipeRegisterServer("selftest-pipe-a", static_cast<u32>(pool_dup), /*writer=*/false, &gen_dup);
    if (slot_dup >= 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_dup));
        NamedPipeOnServerClose(slot_dup, gen_dup);
        ::duetos::core::Panic("ipc/named-pipes", "duplicate named-pipe registration was accepted");
    }
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_dup));
    ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_dup));

    // 4. ConnectClient lookup succeeds, returns the correct pool index, and
    //    atomically retains the client end before exposing the pool identity.
    u32 looked_up_pool = u32(-1);
    bool looked_up_writer = true;
    if (!NamedPipeConnectClient("selftest-pipe-a", &looked_up_pool, &looked_up_writer))
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL connect lookup\n");
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        NamedPipeOnServerClose(slot_a, gen_a);
        return;
    }
    if (looked_up_pool != static_cast<u32>(pool_a) || looked_up_writer != false)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL connect returned wrong values\n");
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        NamedPipeOnServerClose(slot_a, gen_a);
        if (!looked_up_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(looked_up_pool);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(looked_up_pool);
        return;
    }

    // 5. Miss path: unknown name returns false without writing.
    u32 dummy_pool = 0xDEADBEEFu;
    bool dummy_writer = true;
    if (NamedPipeConnectClient("selftest-pipe-nonexistent", &dummy_pool, &dummy_writer))
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL miss returned hit\n");
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
        NamedPipeOnServerClose(slot_a, gen_a);
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_a));
        if (!dummy_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(dummy_pool);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(dummy_pool);
        return;
    }

    // 6. Model actual close order: the server handle drops its read ref, the
    //    registry drops its always-owned initial write ref, then the atomic
    //    connect retain is dropped. The pool must become reusable.
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_a));
    NamedPipeOnServerClose(slot_a, gen_a);
    ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_a));

    // 7. Orphan-release path: register a fresh entry, never connect,
    //    let NamedPipeOnServerClose drop the unused write_ref.
    const i32 pool_b = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_b < 0)
    {
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL PipeAlloc B\n");
        return;
    }
    if (pool_b != pool_a)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_b));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_b));
        ::duetos::core::Panic("ipc/named-pipes", "connected close did not free pipe-pool slot");
    }
    u32 gen_b = 0;
    const i32 slot_b = NamedPipeRegisterServer("selftest-pipe-b", static_cast<u32>(pool_b), /*writer=*/false, &gen_b);
    if (slot_b < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_b));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_b));
        ::duetos::arch::SerialWrite("[selftest:named-pipe] FAIL register B\n");
        return;
    }
    // Orphan close follows the same ownership rule: server read first, then
    // the registry-owned initial write reference.
    ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_b));
    NamedPipeOnServerClose(slot_b, gen_b);

    // 8. ABA identity — stale (slot, generation) replay must be inert.
    if (!NamedPipeAbaReplayCheck())
        return;

    ::duetos::arch::SerialWrite(
        "[named-pipe-selftest] PASS (register + connected-ref balance + slot reuse + orphan cleanup + aba-replay)\n");
}

} // namespace duetos::ipc
