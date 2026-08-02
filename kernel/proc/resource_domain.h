#pragma once

/*
 * Stable resource domains for spawn-tree aggregate accounting.
 *
 * A Process owns one generation-safe ResourceDomainKey.  Child Processes
 * retain and inherit that exact key; they never create a fresh domain merely
 * because a PID changed.  Resource consumers charge the domain and keep the
 * returned generation-safe charge key until the resource's final reference.
 * The service therefore contains no Process pointers or PIDs and cannot be
 * confused by process exit, PID reuse, or a wide spawn tree.
 *
 * Threading and ownership:
 *   - Every entry point is callable from any CPU/task context.
 *   - One IRQ-safe spinlock protects the fixed-capacity metadata only.
 *   - No allocation, logging, scheduler operation, or other external call is
 *     made while that lock is held.
 *   - Process owners retain/release ResourceDomainKey references.
 *   - A live Section owns exactly one ResourceSectionChargeKey and a live
 *     ChannelCore owns exactly one ResourceChannelChargeKey.  A ChannelCore
 *     charge records its exact bounded queue-storage bytes as well as one
 *     object. Construction failures roll back the acquired charge; a
 *     published resource releases it only on its final ownership transition.
 *   - Charge rows pin a zero-owner Closing domain until the last exact charge
 *     of every class is released. Keys never wrap; exhausted rows are
 *     permanently retired.
 */

#include "util/types.h"

namespace duetos::core
{

// One domain per independently rooted process tree.  User-originated children
// inherit a row, so they do not consume additional rows.  Sixty-four rows keep
// the metadata small while covering the kernel's boot/service roots with ample
// headroom.
constexpr u32 kResourceDomainCapacity = 64;

// The Section pool is globally bounded at eight objects.  Matching that bound
// here makes every live Section charge uniquely represented and replay-safe.
constexpr u32 kResourceSectionChargeCapacity = 8;
constexpr u32 kResourceSectionPoolCapacity = 8;
constexpr u32 kResourceSectionReservedServiceSlots = 2;
constexpr u32 kResourceSectionOrdinaryPoolCapacity =
    kResourceSectionPoolCapacity - kResourceSectionReservedServiceSlots;

// One exact row per live ChannelCore charge. This is the kernel-wide hard
// bound; immutable per-profile object and byte limits below are enforced by
// ResourceDomainTryChargeChannel before one of these rows is consumed.
constexpr u32 kResourceChannelChargeCapacity = 64;

constexpr u32 kSandboxSectionObjectLimit = 2;
constexpr u32 kSandboxSectionPageLimitMaximum = 8;
constexpr u32 kTrustedSectionObjectLimit = 2;
constexpr u32 kTrustedSectionPageLimit = 1024;
constexpr u32 kAuthenticatedServiceSectionObjectLimit = 4;
constexpr u32 kAuthenticatedServiceSectionPageLimit = 2048;

// Conservative immutable channel limits.  They are authoritative ResourceDomain
// policy, not advisory ServiceDirectory counters.  A current ChannelCore owns
// two 4-KiB MessagePort queues, so these pairs admit exactly 2, 8, and 32
// ordinary cores respectively while retaining the object limit as an
// independent defense against artificially tiny byte charges.
constexpr u32 kSandboxChannelObjectLimit = 2;
constexpr u64 kSandboxChannelByteLimit = 16ULL * 1024;
constexpr u32 kTrustedChannelObjectLimit = 8;
constexpr u64 kTrustedChannelByteLimit = 64ULL * 1024;
constexpr u32 kAuthenticatedServiceChannelObjectLimit = 32;
constexpr u64 kAuthenticatedServiceChannelByteLimit = 256ULL * 1024;

// Internal identities are not ABI handles, but use the same non-wrapping
// generation discipline as the public fixed-capacity services.
constexpr u64 kResourceDomainGenerationMaximum = (1ULL << 51) - 1;
constexpr u64 kResourceSectionChargeGenerationMaximum = (1ULL << 51) - 1;
constexpr u64 kResourceChannelChargeGenerationMaximum = (1ULL << 51) - 1;

struct ResourceDomainKey
{
    u32 slot;
    u64 generation;
};

constexpr ResourceDomainKey kInvalidResourceDomainKey{kResourceDomainCapacity, 0};

constexpr bool ResourceDomainKeyIsValid(ResourceDomainKey key)
{
    return key.slot < kResourceDomainCapacity && key.generation != 0 &&
           key.generation <= kResourceDomainGenerationMaximum;
}

constexpr bool operator==(ResourceDomainKey lhs, ResourceDomainKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

struct ResourceSectionChargeKey
{
    u32 slot;
    u64 generation;
};

struct ResourceChannelChargeKey
{
    u32 slot;
    u64 generation;
};

constexpr ResourceChannelChargeKey kInvalidResourceChannelChargeKey{kResourceChannelChargeCapacity, 0};

constexpr bool ResourceChannelChargeKeyIsValid(ResourceChannelChargeKey key)
{
    return key.slot < kResourceChannelChargeCapacity && key.generation != 0 &&
           key.generation <= kResourceChannelChargeGenerationMaximum;
}

constexpr bool operator==(ResourceChannelChargeKey lhs, ResourceChannelChargeKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

constexpr ResourceSectionChargeKey kInvalidResourceSectionChargeKey{kResourceSectionChargeCapacity, 0};

constexpr bool ResourceSectionChargeKeyIsValid(ResourceSectionChargeKey key)
{
    return key.slot < kResourceSectionChargeCapacity && key.generation != 0 &&
           key.generation <= kResourceSectionChargeGenerationMaximum;
}

constexpr bool operator==(ResourceSectionChargeKey lhs, ResourceSectionChargeKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

enum class ResourceDomainProfile : u8
{
    Sandbox = 0,
    Trusted,
    AuthenticatedService,
};

enum class ResourceDomainState : u8
{
    Retired = 0,
    Live,
    Closing,
};

// Section uses this immutable result to choose its physical slot partition.
// Ordinary domains may reserve only slots [0, 6); authenticated services try
// the two reserved slots first and may spill into the ordinary partition.
enum class ResourceSectionPoolClass : u8
{
    Ordinary = 0,
    AuthenticatedService,
};

struct ResourceDomainSnapshot
{
    ResourceDomainState state;
    ResourceDomainProfile profile;
    ResourceSectionPoolClass section_pool_class;
    u32 owner_references;
    u32 section_objects;
    u32 section_pages;
    u32 channel_objects;
    u64 channel_bytes;
    u32 section_object_limit;
    u32 section_page_limit;
    u32 channel_object_limit;
    u64 channel_byte_limit;
};

/// Create a sandbox domain.  Its aggregate Section page limit is
/// min(frame_budget_pages, 8); a zero frame budget is invalid.
bool ResourceDomainCreateSandbox(u64 frame_budget_pages, ResourceDomainKey* out_key);

/// Create an ordinary trusted domain (2 Section objects / 1024 pages).
bool ResourceDomainCreateTrusted(ResourceDomainKey* out_key);

/// Create a service domain (4 Section objects / 2048 pages) that may use the
/// reserved Section slots.  This is a kernel authority-bearing entry point:
/// call it only from the service manager or execd after authenticating the
/// service origin.  Never select this profile from user-supplied caps, names,
/// paths, PIDs, or syscall arguments.
bool ResourceDomainCreateAuthenticatedService(ResourceDomainKey* out_key);

/// Create an authenticated-service domain whose immutable Section limits are
/// the exact non-zero manifest-authenticated requests. Both values must fit
/// within the profile maxima; refusal invalidates a non-null output. Channel
/// limits remain the authenticated-service maxima because the current signed
/// manifest does not carry independent channel requests.
bool ResourceDomainCreateBoundedAuthenticatedService(u32 requested_section_objects, u32 requested_section_pages,
                                                     ResourceDomainKey* out_key);

/// Retain/release one Process-owner reference.  Spawned children retain the
/// parent's exact key before publication and release it with Process teardown.
/// Retain refuses a Closing domain and saturated reference counts.
bool ResourceDomainRetain(ResourceDomainKey key);
bool ResourceDomainRelease(ResourceDomainKey key);

/// Atomically charge one prospective Section against an exact live domain.
/// On success, out_charge owns the charge and out_pool_class identifies the
/// Section slot partition.  On failure no counters change and out_charge is
/// invalid.  The pool-class output may be null.
bool ResourceDomainTryChargeSection(ResourceDomainKey domain, u32 num_pages, ResourceSectionChargeKey* out_charge,
                                    ResourceSectionPoolClass* out_pool_class);

/// Consume an exact live Section charge.  A stale, copied, double-released, or
/// malformed key is refused without changing accounting.  On success the
/// caller's key is replaced with kInvalidResourceSectionChargeKey.
bool ResourceDomainReleaseSection(ResourceSectionChargeKey* charge);

/// Atomically charge one prospective ChannelCore and its exact non-zero
/// bounded queue-storage extent against an exact live domain.  Both immutable
/// per-profile object and byte limits are enforced in the same lock critical
/// section as fixed-row allocation. Success returns one generation-safe
/// ownership token. Failure makes no accounting change and stores
/// kInvalidResourceChannelChargeKey.
bool ResourceDomainTryChargeChannel(ResourceDomainKey domain, u64 queued_buffer_bytes,
                                    ResourceChannelChargeKey* out_charge);

/// Consume one exact live ChannelCore charge. Stale, copied, malformed, and
/// double-released keys fail closed without manufacturing capacity. Success
/// invalidates the caller's token and may retire a zero-owner Closing domain.
bool ResourceDomainReleaseChannel(ResourceChannelChargeKey* charge);

/// Diagnostic view of an exact generation, including Closing/Retired rows.
/// Returns false once the slot has been reused for a newer generation.
bool ResourceDomainInspectExact(ResourceDomainKey key, ResourceDomainSnapshot* out_snapshot);

/// Allocation-free policy/lifetime regression.  Intended for early boot,
/// before concurrent Process roots exist; returns false rather than panicking.
bool ResourceDomainSelfTest();

} // namespace duetos::core
