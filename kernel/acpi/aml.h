#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — ACPI AML namespace walker, v0.
 *
 * Walks the AML byte stream of every cached DSDT + SSDT and builds
 * a flat table of named ACPI objects: `\_SB`, `\_SB.PCI0`,
 * `\_SB.PCI0.LPCB`, `\_PR.CPU0._STA`, etc. NOT a full AML
 * interpreter — we don't evaluate methods or follow forward
 * references. Just enough scaffolding that a future slice can
 * find `_PRT` (PCI interrupt routing), `_STA` (device status),
 * `_CRS` (current resources) by name and locate their byte
 * offsets without re-walking the stream.
 *
 * Coverage in v0:
 *   - DefScope        (0x10)        — recurse into its TermList.
 *   - DefName         (0x08)        — record + skip the value blob.
 *   - DefMethod       (0x14)        — record + DON'T recurse.
 *   - DefDevice       (0x5B 0x82)   — recurse.
 *   - DefOpRegion     (0x5B 0x80)   — record + skip operands.
 *   - DefMutex        (0x5B 0x01)   — record + skip flags.
 *   - DefEvent        (0x5B 0x02)   — record.
 *   - DefAlias        (0x06)        — record + skip target NameString.
 *   - DefExternal     (0x15)        — record + skip object-type/argc.
 *   - DefProcessor    (0x5B 0x83)   — recurse (deprecated but common).
 *   - DefThermalZone  (0x5B 0x85)   — recurse.
 *   - DefPowerRes     (0x5B 0x84)   — recurse.
 *
 * On any opcode we don't recognise, the walker stops the current
 * TermList. Because every recursable container is wrapped in
 * PkgLength (we know its end byte exactly), an unknown body opcode
 * does NOT corrupt the parent walk — the parent simply continues
 * past the package end.
 *
 * Path encoding: canonical "\_SB.PCI0.LPCB.SIO_" form. Root prefix
 * is always present. Path cap is 64 chars (15 segments) — long
 * enough for every shipping firmware.
 *
 * Context: kernel. AmlNamespaceBuild runs ONCE after AcpiInit.
 */

namespace duetos::acpi
{

inline constexpr u32 kMaxAmlNsEntries = 512;

enum class AmlObjectKind : u8
{
    Scope,
    Device,
    Method,
    Name,
    OpRegion,
    Mutex,
    Event,
    Alias,
    External,
    Processor,
    ThermalZone,
    PowerResource,
    Field,
    Unknown,
};

// ACPI region-space identifiers (ACPI 6.x §5.5.2.2 / Table 19-187).
enum class AmlRegionSpace : u8
{
    SystemMemory = 0x00,
    SystemIO = 0x01,
    PciConfig = 0x02,
    EmbeddedControl = 0x03,
    SmBus = 0x04,
    Cmos = 0x05,
    Other = 0xFF,
};

// One OperationRegion with a constant offset/length. Regions whose
// offset or length is a computed TermArg (rare on the EC / battery /
// brightness path) are not indexed in v0 — see aml.cpp.
struct AmlRegionInfo
{
    char path[64];
    AmlRegionSpace space;
    u8 source_table_idx;
    u8 _pad[2];
    u64 base;   // RegionOffset (constant)
    u64 length; // RegionLen (constant)
};

// One named FieldUnit inside a region: bit offset + bit width + the
// access width declared by the enclosing Field's FieldFlags. The
// interpreter resolves a NameString to this and reads/writes the
// backing region through a registered region handler.
struct AmlFieldInfo
{
    char path[64];   // canonical "\_SB.PCI0.EC0.BAT0..." of the unit
    char region[64]; // canonical path of the parent OperationRegion
    u32 bit_offset;
    u32 bit_width;
    u8 access_bytes; // 1/2/4/8 — AccessType from FieldFlags
    u8 source_table_idx;
    u8 _pad[2];
};

const char* AmlObjectKindName(AmlObjectKind k);

struct AmlNamespaceEntry
{
    char path[64]; // canonical "\_SB.PCI0..."  NUL-terminated
    AmlObjectKind kind;
    u8 method_args;      // 0 unless kind == Method
    u8 source_table_idx; // 0 = DSDT, 1+ = SSDT (source_table_idx-1)
    u8 _pad;
    u32 aml_offset; // byte offset into the source table's AML body
};

/// Walk every cached DSDT + SSDT, populate the namespace table,
/// log a one-line summary. Idempotent — second call returns early
/// until `AmlNamespaceShutdown` has cleared the live flag.
void AmlNamespaceBuild();

/// Drop every entry, clear the "built" flag so the next
/// `AmlNamespaceBuild` re-walks DSDT/SSDT. Always succeeds — this
/// subsystem has no external resources to surrender.
::duetos::core::Result<void> AmlNamespaceShutdown();

/// Number of named objects discovered. 0 until AmlNamespaceBuild()
/// has run.
u32 AmlNamespaceCount();

/// Random access; nullptr for out-of-range.
const AmlNamespaceEntry* AmlNamespaceEntryAt(u32 i);

/// Lookup by canonical path. Linear scan; returns nullptr if not
/// found. Path matching is exact, including the leading "\".
const AmlNamespaceEntry* AmlNamespaceFind(const char* path);

/// How many entries match a kind. Useful for boot-log scoreboard
/// and quick "do I have any thermal zones declared?" predicates.
u32 AmlNamespaceCountByKind(AmlObjectKind k);

/// Decode the `\_S5` (soft-off) sleep-state values from AML.
/// Populates `*slp_typa` / `*slp_typb` with the first two
/// elements of the `Package { SLP_TYPa, SLP_TYPb, ... }`
/// declaration. Returns false on missing name, unexpected
/// opcode, or element encodings outside v0's supported subset
/// (ZeroOp / OneOp / BytePrefix). Callers on false stay in
/// "ACPI shutdown unsupported" — we don't guess bits.
bool AmlReadS5(u8* slp_typa, u8* slp_typb);

// --- Region / Field index (populated by AmlNamespaceBuild) ----------

u32 AmlRegionCount();
const AmlRegionInfo* AmlRegionAt(u32 i);
const AmlRegionInfo* AmlRegionFind(const char* path);

u32 AmlFieldCount();
const AmlFieldInfo* AmlFieldAt(u32 i);
const AmlFieldInfo* AmlFieldFind(const char* path);

// Locate a Method's body TermList inside its source table. `entry`
// must be `kind == Method`. On success `*body`/`*body_len` bracket
// the method's TermList (after PkgLength + NameString + MethodFlags)
// and `*argc` is the declared argument count. Returns false on a
// malformed / unmappable table.
bool AmlMethodBody(const AmlNamespaceEntry* entry, const u8** body, u32* body_len, u8* argc);

// For a `kind == Name` entry, point `*data`/`*data_len` at the
// DataRefObject bytes following the recorded NameString. Returns
// false on a malformed / unmappable table.
bool AmlNameValue(const AmlNamespaceEntry* entry, const u8** data, u32* data_len);

} // namespace duetos::acpi
