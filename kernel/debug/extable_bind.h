#pragma once

#include "debug/extable.h"
#include "util/types.h"

/*
 * DuetOS — convenience macros for binding a code region to a
 * fault domain via the kernel exception table.
 *
 * The bare `KernelExtableRegisterWithDomain(start, end, fixup,
 * tag, domain_id)` API takes raw VAs. Drivers don't have those
 * — they have function bodies. This header wraps the address
 * collection in a tiny inline assembler block: a leading +
 * trailing label bracket the bound region, and a constructor-
 * registered glue function calls KernelExtableRegisterWithDomain
 * with their addresses at startup.
 *
 * Usage:
 *
 *     // Drivers/net.cpp
 *     namespace
 *     {
 *     ::duetos::core::FaultDomainId g_net_domain = ::duetos::core::kFaultDomainInvalid;
 *     u64 NetTxFixup() { return 0; }  // returns 0 == "send failed"
 *     }
 *
 *     int NetTx(...)
 *     {
 *         EXTABLE_BIND_BEGIN(net_tx_region);
 *         // ... body that may dereference a stale pointer ...
 *         EXTABLE_BIND_END(net_tx_region);
 *         return 1;
 *     }
 *
 *     void NetInit()
 *     {
 *         g_net_domain = duetos::security::RegisterDriverDomain("drivers/net", ...);
 *         EXTABLE_BIND_REGISTER(net_tx_region, g_net_domain,
 *                               reinterpret_cast<u64>(&NetTxFixup),
 *                               "drivers/net.tx");
 *     }
 *
 * On a kernel-mode #PF / #GP whose RIP lands inside [BEGIN,
 * END), the trap dispatcher rewrites RIP to fixup_rip and
 * iretq's, AND `FaultDomainMarkRestart(domain_id)` runs from
 * the heartbeat next beat — same path as the existing
 * `__copy_user_fault_fixup` row, just labelled.
 *
 * Why labels and not function-attributes: function attributes
 * (start_address / end_address) aren't portable; inline asm
 * labels are universal across GCC + Clang. The pair-symbol
 * approach also lets a single function host multiple bound
 * regions, each with its own fixup.
 *
 * Context: kernel. Registration runs at subsystem init time
 * (typically the same call that does FaultDomainRegister). The
 * macro is zero-cost at runtime — labels emit no instructions.
 */

namespace duetos::debug
{

/// Register a region [rip_start, rip_end) with `domain_id`. Thin
/// wrapper around `KernelExtableRegisterWithDomain` so call sites
/// can pass label-derived addresses without knowing the longer
/// API name. Returns false if the table is full or the args
/// malformed.
inline bool ExtableBindRegion(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag, u32 domain_id)
{
    return ::duetos::debug::KernelExtableRegisterWithDomain(rip_start, rip_end, fixup_rip, tag, domain_id);
}

} // namespace duetos::debug

// Open the bound region. The asm label is local to the
// translation unit so different files can reuse the same `name`
// without colliding. Emits zero instructions.
#define EXTABLE_BIND_BEGIN(name) __asm__ volatile(".local _extbind_" #name "_begin\n_extbind_" #name "_begin:\n" : : :)

// Close the bound region. Pair with EXTABLE_BIND_BEGIN(name).
#define EXTABLE_BIND_END(name) __asm__ volatile(".local _extbind_" #name "_end\n_extbind_" #name "_end:\n" : : :)

// Resolve the (begin, end) pair to addresses and call the
// registration helper. Use at init time, AFTER the domain is
// registered so the domain_id is valid.
//
// Note: we cast through `u64` rather than `uintptr_t` — the
// kernel codebase uses `u64` consistently for addresses and the
// type guarantees a 64-bit zero-extended capture across both
// inline-asm output and the runtime helper.
#define EXTABLE_BIND_REGISTER(name, domain_id, fixup_rip, tag)                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::u64 _b = 0;                                                                                          \
        ::duetos::u64 _e = 0;                                                                                          \
        __asm__ volatile("leaq _extbind_" #name "_begin(%%rip), %0\n"                                                  \
                         "leaq _extbind_" #name "_end(%%rip), %1\n"                                                    \
                         : "=r"(_b), "=r"(_e)::);                                                                      \
        (void)::duetos::debug::ExtableBindRegion(_b, _e, (fixup_rip), (tag), (domain_id));                             \
    } while (0)
