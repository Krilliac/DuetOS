/*
 * Stable resource-domain accounting.
 *
 * State machine (under g_resource_domain_lock):
 *
 *   Retired -> Live -> Closing -> Retired
 *                 \--------------^
 *
 * Last-owner release moves a charged row to Closing.  Exact charge rows keep
 * the domain generation present until their resources reach final release.
 */

#include "proc/resource_domain.h"

#include "sync/spinlock.h"

namespace duetos::core
{

namespace
{

enum class ResourceSectionChargeState : u8
{
    Retired = 0,
    Live,
};

enum class ResourceChannelChargeState : u8
{
    Retired = 0,
    Live,
};

struct ResourceDomainRow
{
    ResourceDomainState state;
    ResourceDomainProfile profile;
    ResourceSectionPoolClass section_pool_class;
    u8 _pad0;
    u64 generation;
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

struct ResourceSectionChargeRow
{
    ResourceSectionChargeState state;
    u8 _pad0[3];
    u64 generation;
    ResourceDomainKey domain;
    u32 pages;
};

struct ResourceChannelChargeRow
{
    ResourceChannelChargeState state;
    u8 _pad0[3];
    u64 generation;
    ResourceDomainKey domain;
    u64 queued_buffer_bytes;
};

constinit ResourceDomainRow g_resource_domains[kResourceDomainCapacity]{};
constinit ResourceSectionChargeRow g_section_charges[kResourceSectionChargeCapacity]{};
constinit ResourceChannelChargeRow g_channel_charges[kResourceChannelChargeCapacity]{};
constinit sync::SpinLock g_resource_domain_lock{};

ResourceDomainRow* ResolveDomainExactLocked(ResourceDomainKey key)
{
    if (!ResourceDomainKeyIsValid(key))
    {
        return nullptr;
    }
    ResourceDomainRow& row = g_resource_domains[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

ResourceSectionChargeRow* ResolveSectionChargeExactLocked(ResourceSectionChargeKey key)
{
    if (!ResourceSectionChargeKeyIsValid(key))
    {
        return nullptr;
    }
    ResourceSectionChargeRow& row = g_section_charges[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

ResourceChannelChargeRow* ResolveChannelChargeExactLocked(ResourceChannelChargeKey key)
{
    if (!ResourceChannelChargeKeyIsValid(key))
    {
        return nullptr;
    }
    ResourceChannelChargeRow& row = g_channel_charges[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

void RetireDomainLocked(ResourceDomainRow& row)
{
    // Generation and immutable diagnostic policy are preserved until reuse.
    row.owner_references = 0;
    row.section_objects = 0;
    row.section_pages = 0;
    row.channel_objects = 0;
    row.channel_bytes = 0;
    row.state = ResourceDomainState::Retired;
}

bool CreateDomain(ResourceDomainProfile profile, ResourceSectionPoolClass pool_class, u32 object_limit, u32 page_limit,
                  u32 channel_object_limit, u64 channel_byte_limit, ResourceDomainKey* out_key)
{
    if (out_key == nullptr || object_limit == 0 || page_limit == 0 || channel_object_limit == 0 ||
        channel_byte_limit == 0)
    {
        return false;
    }
    *out_key = kInvalidResourceDomainKey;

    sync::SpinLockGuard guard(g_resource_domain_lock);
    for (u32 slot = 0; slot < kResourceDomainCapacity; ++slot)
    {
        ResourceDomainRow& row = g_resource_domains[slot];
        if (row.state != ResourceDomainState::Retired || row.generation >= kResourceDomainGenerationMaximum)
        {
            continue;
        }

        ++row.generation;
        row.profile = profile;
        row.section_pool_class = pool_class;
        row.owner_references = 1;
        row.section_objects = 0;
        row.section_pages = 0;
        row.channel_objects = 0;
        row.channel_bytes = 0;
        row.section_object_limit = object_limit;
        row.section_page_limit = page_limit;
        row.channel_object_limit = channel_object_limit;
        row.channel_byte_limit = channel_byte_limit;
        row.state = ResourceDomainState::Live;
        *out_key = ResourceDomainKey{slot, row.generation};
        return true;
    }
    return false;
}

bool SnapshotMatches(const ResourceDomainSnapshot& snapshot, ResourceDomainState state, ResourceDomainProfile profile,
                     ResourceSectionPoolClass pool_class, u32 refs, u32 objects, u32 pages, u32 object_limit,
                     u32 page_limit, u32 channel_object_limit, u64 channel_byte_limit)
{
    return snapshot.state == state && snapshot.profile == profile && snapshot.section_pool_class == pool_class &&
           snapshot.owner_references == refs && snapshot.section_objects == objects &&
           snapshot.section_pages == pages && snapshot.channel_objects == 0 && snapshot.channel_bytes == 0 &&
           snapshot.section_object_limit == object_limit && snapshot.section_page_limit == page_limit &&
           snapshot.channel_object_limit == channel_object_limit && snapshot.channel_byte_limit == channel_byte_limit;
}

} // namespace

bool ResourceDomainCreateSandbox(u64 frame_budget_pages, ResourceDomainKey* out_key)
{
    if (out_key == nullptr)
    {
        return false;
    }
    *out_key = kInvalidResourceDomainKey;
    if (frame_budget_pages == 0)
    {
        return false;
    }
    const u32 page_limit = static_cast<u32>(
        frame_budget_pages < kSandboxSectionPageLimitMaximum ? frame_budget_pages : kSandboxSectionPageLimitMaximum);
    return CreateDomain(ResourceDomainProfile::Sandbox, ResourceSectionPoolClass::Ordinary, kSandboxSectionObjectLimit,
                        page_limit, kSandboxChannelObjectLimit, kSandboxChannelByteLimit, out_key);
}

bool ResourceDomainCreateTrusted(ResourceDomainKey* out_key)
{
    return CreateDomain(ResourceDomainProfile::Trusted, ResourceSectionPoolClass::Ordinary, kTrustedSectionObjectLimit,
                        kTrustedSectionPageLimit, kTrustedChannelObjectLimit, kTrustedChannelByteLimit, out_key);
}

bool ResourceDomainCreateAuthenticatedService(ResourceDomainKey* out_key)
{
    return ResourceDomainCreateBoundedAuthenticatedService(kAuthenticatedServiceSectionObjectLimit,
                                                           kAuthenticatedServiceSectionPageLimit, out_key);
}

bool ResourceDomainCreateBoundedAuthenticatedService(u32 requested_section_objects, u32 requested_section_pages,
                                                     ResourceDomainKey* out_key)
{
    if (out_key == nullptr)
        return false;
    *out_key = kInvalidResourceDomainKey;
    if (requested_section_objects == 0 || requested_section_objects > kAuthenticatedServiceSectionObjectLimit ||
        requested_section_pages == 0 || requested_section_pages > kAuthenticatedServiceSectionPageLimit)
    {
        return false;
    }
    return CreateDomain(ResourceDomainProfile::AuthenticatedService, ResourceSectionPoolClass::AuthenticatedService,
                        requested_section_objects, requested_section_pages, kAuthenticatedServiceChannelObjectLimit,
                        kAuthenticatedServiceChannelByteLimit, out_key);
}

bool ResourceDomainRetain(ResourceDomainKey key)
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceDomainRow* row = ResolveDomainExactLocked(key);
    if (row == nullptr || row->state != ResourceDomainState::Live || row->owner_references == 0 ||
        row->owner_references == static_cast<u32>(~0U))
    {
        return false;
    }
    ++row->owner_references;
    return true;
}

bool ResourceDomainRelease(ResourceDomainKey key)
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceDomainRow* row = ResolveDomainExactLocked(key);
    if (row == nullptr || row->state != ResourceDomainState::Live || row->owner_references == 0)
    {
        return false;
    }

    --row->owner_references;
    if (row->owner_references != 0)
    {
        return true;
    }
    if (row->section_objects != 0 || row->section_pages != 0 || row->channel_objects != 0 || row->channel_bytes != 0)
    {
        row->state = ResourceDomainState::Closing;
    }
    else
    {
        RetireDomainLocked(*row);
    }
    return true;
}

bool ResourceDomainTryChargeSection(ResourceDomainKey domain, u32 num_pages, ResourceSectionChargeKey* out_charge,
                                    ResourceSectionPoolClass* out_pool_class)
{
    if (out_charge == nullptr)
    {
        return false;
    }
    *out_charge = kInvalidResourceSectionChargeKey;
    if (out_pool_class != nullptr)
    {
        *out_pool_class = ResourceSectionPoolClass::Ordinary;
    }
    if (num_pages == 0)
    {
        return false;
    }

    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceDomainRow* domain_row = ResolveDomainExactLocked(domain);
    if (domain_row == nullptr || domain_row->state != ResourceDomainState::Live || domain_row->owner_references == 0 ||
        domain_row->section_objects >= domain_row->section_object_limit ||
        domain_row->section_pages > domain_row->section_page_limit ||
        num_pages > domain_row->section_page_limit - domain_row->section_pages)
    {
        return false;
    }

    for (u32 slot = 0; slot < kResourceSectionChargeCapacity; ++slot)
    {
        ResourceSectionChargeRow& charge = g_section_charges[slot];
        if (charge.state != ResourceSectionChargeState::Retired ||
            charge.generation >= kResourceSectionChargeGenerationMaximum)
        {
            continue;
        }

        ++charge.generation;
        charge.domain = domain;
        charge.pages = num_pages;
        charge.state = ResourceSectionChargeState::Live;
        ++domain_row->section_objects;
        domain_row->section_pages += num_pages;

        *out_charge = ResourceSectionChargeKey{slot, charge.generation};
        if (out_pool_class != nullptr)
        {
            *out_pool_class = domain_row->section_pool_class;
        }
        return true;
    }
    return false;
}

bool ResourceDomainReleaseSection(ResourceSectionChargeKey* charge_key)
{
    if (charge_key == nullptr || !ResourceSectionChargeKeyIsValid(*charge_key))
    {
        return false;
    }

    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceSectionChargeRow* charge = ResolveSectionChargeExactLocked(*charge_key);
    if (charge == nullptr || charge->state != ResourceSectionChargeState::Live || charge->pages == 0)
    {
        return false;
    }
    ResourceDomainRow* domain = ResolveDomainExactLocked(charge->domain);
    if (domain == nullptr ||
        (domain->state != ResourceDomainState::Live && domain->state != ResourceDomainState::Closing) ||
        domain->section_objects == 0 || domain->section_pages < charge->pages)
    {
        // Fail closed: never let a malformed/stale charge underflow or debit a
        // different generation.  Keeping the row charged is safer than
        // manufacturing capacity after an internal invariant failure.
        return false;
    }

    --domain->section_objects;
    domain->section_pages -= charge->pages;
    charge->domain = kInvalidResourceDomainKey;
    charge->pages = 0;
    charge->state = ResourceSectionChargeState::Retired;
    *charge_key = kInvalidResourceSectionChargeKey;

    if (domain->state == ResourceDomainState::Closing && domain->section_objects == 0 && domain->section_pages == 0 &&
        domain->channel_objects == 0 && domain->channel_bytes == 0)
    {
        RetireDomainLocked(*domain);
    }
    return true;
}

bool ResourceDomainTryChargeChannel(ResourceDomainKey domain, u64 queued_buffer_bytes,
                                    ResourceChannelChargeKey* out_charge)
{
    if (out_charge == nullptr)
    {
        return false;
    }
    *out_charge = kInvalidResourceChannelChargeKey;
    if (queued_buffer_bytes == 0)
    {
        return false;
    }

    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceDomainRow* domain_row = ResolveDomainExactLocked(domain);
    if (domain_row == nullptr || domain_row->state != ResourceDomainState::Live || domain_row->owner_references == 0 ||
        domain_row->channel_objects >= domain_row->channel_object_limit ||
        domain_row->channel_bytes > domain_row->channel_byte_limit ||
        queued_buffer_bytes > domain_row->channel_byte_limit - domain_row->channel_bytes)
    {
        return false;
    }

    for (u32 slot = 0; slot < kResourceChannelChargeCapacity; ++slot)
    {
        ResourceChannelChargeRow& charge = g_channel_charges[slot];
        if (charge.state != ResourceChannelChargeState::Retired ||
            charge.generation >= kResourceChannelChargeGenerationMaximum)
        {
            continue;
        }

        ++charge.generation;
        charge.domain = domain;
        charge.queued_buffer_bytes = queued_buffer_bytes;
        charge.state = ResourceChannelChargeState::Live;
        ++domain_row->channel_objects;
        domain_row->channel_bytes += queued_buffer_bytes;
        *out_charge = ResourceChannelChargeKey{slot, charge.generation};
        return true;
    }
    return false;
}

bool ResourceDomainReleaseChannel(ResourceChannelChargeKey* charge_key)
{
    if (charge_key == nullptr || !ResourceChannelChargeKeyIsValid(*charge_key))
    {
        return false;
    }

    sync::SpinLockGuard guard(g_resource_domain_lock);
    ResourceChannelChargeRow* charge = ResolveChannelChargeExactLocked(*charge_key);
    if (charge == nullptr || charge->state != ResourceChannelChargeState::Live || charge->queued_buffer_bytes == 0)
    {
        return false;
    }
    ResourceDomainRow* domain = ResolveDomainExactLocked(charge->domain);
    if (domain == nullptr ||
        (domain->state != ResourceDomainState::Live && domain->state != ResourceDomainState::Closing) ||
        domain->channel_objects == 0 || domain->channel_bytes < charge->queued_buffer_bytes)
    {
        return false;
    }

    --domain->channel_objects;
    domain->channel_bytes -= charge->queued_buffer_bytes;
    charge->domain = kInvalidResourceDomainKey;
    charge->queued_buffer_bytes = 0;
    charge->state = ResourceChannelChargeState::Retired;
    *charge_key = kInvalidResourceChannelChargeKey;

    if (domain->state == ResourceDomainState::Closing && domain->section_objects == 0 && domain->section_pages == 0 &&
        domain->channel_objects == 0 && domain->channel_bytes == 0)
    {
        RetireDomainLocked(*domain);
    }
    return true;
}

bool ResourceDomainInspectExact(ResourceDomainKey key, ResourceDomainSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
    {
        return false;
    }
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_resource_domain_lock);
    const ResourceDomainRow* row = ResolveDomainExactLocked(key);
    if (row == nullptr)
    {
        return false;
    }
    out_snapshot->state = row->state;
    out_snapshot->profile = row->profile;
    out_snapshot->section_pool_class = row->section_pool_class;
    out_snapshot->owner_references = row->owner_references;
    out_snapshot->section_objects = row->section_objects;
    out_snapshot->section_pages = row->section_pages;
    out_snapshot->channel_objects = row->channel_objects;
    out_snapshot->channel_bytes = row->channel_bytes;
    out_snapshot->section_object_limit = row->section_object_limit;
    out_snapshot->section_page_limit = row->section_page_limit;
    out_snapshot->channel_object_limit = row->channel_object_limit;
    out_snapshot->channel_byte_limit = row->channel_byte_limit;
    return true;
}

bool ResourceDomainSelfTest()
{
    bool ok = true;

    // Retain models a child inheriting the exact parent domain.  Both Section
    // charges then debit that one aggregate row; releasing the last Process
    // owner closes the row but does not erase the live resource charges.
    ResourceDomainKey sandbox = kInvalidResourceDomainKey;
    ResourceSectionChargeKey sandbox_a = kInvalidResourceSectionChargeKey;
    ResourceSectionChargeKey sandbox_b = kInvalidResourceSectionChargeKey;
    ResourceSectionChargeKey rejected = kInvalidResourceSectionChargeKey;
    ResourceSectionPoolClass pool_class = ResourceSectionPoolClass::AuthenticatedService;
    ResourceDomainSnapshot snapshot{};
    ok = ResourceDomainCreateSandbox(3, &sandbox) && ok;
    if (ResourceDomainKeyIsValid(sandbox))
    {
        ok = ResourceDomainInspectExact(sandbox, &snapshot) &&
             SnapshotMatches(snapshot, ResourceDomainState::Live, ResourceDomainProfile::Sandbox,
                             ResourceSectionPoolClass::Ordinary, 1, 0, 0, kSandboxSectionObjectLimit, 3,
                             kSandboxChannelObjectLimit, kSandboxChannelByteLimit) &&
             ok;
        ok = ResourceDomainRetain(sandbox) && ok;
        ok = ResourceDomainRelease(sandbox) && ok;
        ok = ResourceDomainTryChargeSection(sandbox, 2, &sandbox_a, &pool_class) &&
             pool_class == ResourceSectionPoolClass::Ordinary && ok;
        ok = !ResourceDomainTryChargeSection(sandbox, 2, &rejected, nullptr) &&
             rejected == kInvalidResourceSectionChargeKey && ok;
        ok = ResourceDomainTryChargeSection(sandbox, 1, &sandbox_b, nullptr) && ok;
        ok = !ResourceDomainTryChargeSection(sandbox, 1, &rejected, nullptr) && ok;

        ResourceSectionChargeKey replay = sandbox_a;
        ok = ResourceDomainRelease(sandbox) && ok;
        ok = ResourceDomainInspectExact(sandbox, &snapshot) &&
             SnapshotMatches(snapshot, ResourceDomainState::Closing, ResourceDomainProfile::Sandbox,
                             ResourceSectionPoolClass::Ordinary, 0, 2, 3, kSandboxSectionObjectLimit, 3,
                             kSandboxChannelObjectLimit, kSandboxChannelByteLimit) &&
             ok;
        ok = !ResourceDomainRetain(sandbox) && !ResourceDomainTryChargeSection(sandbox, 1, &rejected, nullptr) && ok;
        if (ResourceSectionChargeKeyIsValid(sandbox_a))
        {
            ok = ResourceDomainReleaseSection(&sandbox_a) && ok;
            ok = !ResourceDomainReleaseSection(&replay) && ok;
        }
        if (ResourceSectionChargeKeyIsValid(sandbox_b))
        {
            ok = ResourceDomainReleaseSection(&sandbox_b) && ok;
        }
        ok = ResourceDomainInspectExact(sandbox, &snapshot) && snapshot.state == ResourceDomainState::Retired &&
             snapshot.owner_references == 0 && snapshot.section_objects == 0 && snapshot.section_pages == 0 && ok;
    }

    ResourceDomainKey wide_sandbox = kInvalidResourceDomainKey;
    ok = ResourceDomainCreateSandbox(4096, &wide_sandbox) && ok;
    if (ResourceDomainKeyIsValid(wide_sandbox))
    {
        ok = ResourceDomainInspectExact(wide_sandbox, &snapshot) &&
             snapshot.profile == ResourceDomainProfile::Sandbox &&
             snapshot.section_page_limit == kSandboxSectionPageLimitMaximum && ok;
        ok = ResourceDomainRelease(wide_sandbox) && ok;
    }

    ResourceDomainKey trusted = kInvalidResourceDomainKey;
    ResourceSectionChargeKey trusted_a = kInvalidResourceSectionChargeKey;
    ResourceSectionChargeKey trusted_b = kInvalidResourceSectionChargeKey;
    ok = ResourceDomainCreateTrusted(&trusted) && ok;
    if (ResourceDomainKeyIsValid(trusted))
    {
        ok = ResourceDomainInspectExact(trusted, &snapshot) &&
             SnapshotMatches(snapshot, ResourceDomainState::Live, ResourceDomainProfile::Trusted,
                             ResourceSectionPoolClass::Ordinary, 1, 0, 0, kTrustedSectionObjectLimit,
                             kTrustedSectionPageLimit, kTrustedChannelObjectLimit, kTrustedChannelByteLimit) &&
             ok;
        ok = ResourceDomainTryChargeSection(trusted, 512, &trusted_a, nullptr) &&
             ResourceDomainTryChargeSection(trusted, 512, &trusted_b, nullptr) && ok;
        ok = !ResourceDomainTryChargeSection(trusted, 1, &rejected, nullptr) && ok;
        if (ResourceSectionChargeKeyIsValid(trusted_a))
        {
            ok = ResourceDomainReleaseSection(&trusted_a) && ok;
        }
        if (ResourceSectionChargeKeyIsValid(trusted_b))
        {
            ok = ResourceDomainReleaseSection(&trusted_b) && ok;
        }
        ok = ResourceDomainRelease(trusted) && ok;
    }

    ResourceDomainKey service = kInvalidResourceDomainKey;
    ResourceSectionChargeKey service_charges[kAuthenticatedServiceSectionObjectLimit]{};
    ok = ResourceDomainCreateAuthenticatedService(&service) && ok;
    if (ResourceDomainKeyIsValid(service))
    {
        ok = ResourceDomainInspectExact(service, &snapshot) &&
             SnapshotMatches(snapshot, ResourceDomainState::Live, ResourceDomainProfile::AuthenticatedService,
                             ResourceSectionPoolClass::AuthenticatedService, 1, 0, 0,
                             kAuthenticatedServiceSectionObjectLimit, kAuthenticatedServiceSectionPageLimit,
                             kAuthenticatedServiceChannelObjectLimit, kAuthenticatedServiceChannelByteLimit) &&
             ok;
        for (u32 index = 0; index < kAuthenticatedServiceSectionObjectLimit; ++index)
        {
            pool_class = ResourceSectionPoolClass::Ordinary;
            ok = ResourceDomainTryChargeSection(service, 512, &service_charges[index], &pool_class) &&
                 pool_class == ResourceSectionPoolClass::AuthenticatedService && ok;
        }
        ok = !ResourceDomainTryChargeSection(service, 1, &rejected, nullptr) && ok;
        for (u32 index = 0; index < kAuthenticatedServiceSectionObjectLimit; ++index)
        {
            if (ResourceSectionChargeKeyIsValid(service_charges[index]))
            {
                ok = ResourceDomainReleaseSection(&service_charges[index]) && ok;
            }
        }
        ok = ResourceDomainRelease(service) && ok;
    }

    // A zero-budget sandbox must never accidentally become an unlimited row.
    ResourceDomainKey zero_budget = ResourceDomainKey{0, 1};
    ok = !ResourceDomainCreateSandbox(0, &zero_budget) && zero_budget == kInvalidResourceDomainKey && ok;
    return ok;
}

} // namespace duetos::core
