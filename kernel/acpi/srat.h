#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI SRAT (System Resource Affinity Table) parser, v0.
 *
 * Walks the SRAT's processor-affinity records and builds a flat
 * APIC-ID -> NUMA-domain table. Memory-affinity records (subtype 1)
 * land in a sibling table consumed by the NUMA-aware page allocator;
 * other entry types (GICC / ITS / Generic Initiator) are ignored.
 *
 * Coverage in v0:
 *   - Subtype 0  Processor Local APIC/SAPIC Affinity (16 bytes)
 *   - Subtype 1  Memory Affinity                     (40 bytes)
 *   - Subtype 2  Processor Local x2APIC Affinity     (24 bytes)
 *   - Subtype 3  Processor Local GICC Affinity       — ignored (ARM)
 *   - Subtype 4  GIC ITS Affinity                    — ignored (ARM)
 *   - Subtype 5  Generic Initiator Affinity          — ignored
 *
 * The SRAT is optional — UMA (single-NUMA-node) machines may not
 * have one at all. Absence is not an error: SratPresent() returns
 * false and `SratNodeForApic` reports unknown for every APIC ID.
 *
 * Context: kernel. SratInit runs once from inside AcpiInit, after
 * the RSDP has been located. Lookups are read-only after that and
 * safe from any context.
 */

namespace duetos::acpi::srat
{

/// Maximum APIC ID we keep a per-APIC node mapping for. APs with
/// IDs >= 256 (rare, x2APIC-heavy multi-socket) are logged once
/// and skipped — covered by a follow-up slice.
inline constexpr u32 kMaxApicId = 256;

/// Maximum dense NUMA-node index. The parser remaps SRAT's 32-bit
/// proximity-domain values into a dense 0..(N-1) range so callers
/// store a u8 per CPU.
inline constexpr u8 kMaxNumaNodes = 16;

/// Sentinel for "no SRAT entry exists for this APIC ID". Distinct
/// from any valid dense node index (which fall in 0..kMaxNumaNodes-1).
inline constexpr u8 kNoNode = 0xFF;

/// Parse the SRAT pointed to by `srat_table`. Pass nullptr when
/// the SDT search returned no SRAT — the cache is reset to empty
/// and SratPresent() returns false thereafter. Validates the
/// table's checksum non-fatally (a bad SRAT is treated as absent).
/// Idempotent: re-calling with the same pointer yields the same
/// result.
void SratInit(const void* srat_table);

/// True iff a valid SRAT was parsed and at least one processor
/// affinity record was registered.
bool SratPresent();

/// True iff SratInit was given a non-null table that failed to
/// validate (wrong signature, length-too-small, checksum
/// mismatch). Distinct from `!SratPresent()`: a clean machine
/// with no SRAT returns false from both. A machine whose
/// firmware shipped a broken SRAT returns true here even though
/// SratPresent() is false.
bool SratCorrupt();

/// Look up the NUMA node for a given APIC ID. Returns true and
/// writes the dense node index to *out_node when known; returns
/// false and leaves *out_node unchanged when no entry exists.
bool SratNodeForApic(u32 apic_id, u8* out_node);

/// Number of distinct NUMA nodes seen in the SRAT (0 if absent).
u8 SratNodeCount();

// ===================================================================
// Memory affinity records (Subtype 1). Each record names a physical
// memory range and the proximity domain (NUMA node) that owns it.
// The NUMA-aware page allocator consumes these to bias allocations
// toward the requesting CPU's local node.
// ===================================================================

/// Maximum memory-affinity records we keep. A typical UMA / dual-
/// socket workstation has 1..4 records; larger NUMA topologies
/// (e.g. four-socket EPYC) commonly stay under 16. A workload that
/// overflows this slots into a roadmap follow-up.
inline constexpr u8 kMaxMemoryRanges = 16;

struct MemoryRange
{
    u64 base;   ///< physical base address (byte-granular)
    u64 length; ///< length in bytes
    u8 node;    ///< dense node index, same namespace as `SratNodeForApic`
    bool enabled;
    u8 _pad[6];
};

/// Number of memory-affinity records we collected. 0 when SRAT is
/// absent or had no enabled subtype-1 records.
u8 SratMemoryRangeCount();

/// Read the `idx`th memory-affinity record. Returns false on
/// out-of-range. Pointer is stable for the kernel's lifetime
/// (records sit in `.bss`).
bool SratMemoryRange(u8 idx, MemoryRange* out);

} // namespace duetos::acpi::srat
