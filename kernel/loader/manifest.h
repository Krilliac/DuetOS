#pragma once

#include "util/types.h"

/*
 * DuetOS — Win32 SxS assembly-manifest parser.
 *
 * Win32 PE executables embed an XML "assembly manifest" as an
 * RT_MANIFEST resource (resource type 24, resource ID 1 for
 * executables, 2 for DLLs). The manifest declares:
 *
 *   - Requested execution level (asInvoker / highestAvailable /
 *     requireAdministrator) and uiAccess flag.
 *   - DPI awareness (unaware / system-aware / per-monitor /
 *     per-monitor-v2).
 *   - Long-path awareness.
 *   - Side-by-side (SxS) assembly dependencies — the DLLs and
 *     versions the application wants loaded from the WinSxS store.
 *   - Registration-free COM class declarations.
 *
 * This parser extracts the above from the XML blob. It is NOT a
 * general XML parser — it handles the well-defined assembly manifest
 * schema by scanning for known element/attribute patterns, which is
 * sufficient because manifests are machine-generated, tightly
 * schematised, and never carry CDATA / processing-instructions /
 * entity references that would trip a scan-based approach.
 *
 * On malformed input the parser returns a default ManifestInfo with
 * has_manifest = false, matching Windows behaviour (a PE with a
 * garbled manifest still loads).
 *
 * Context: kernel (freestanding — no libc, no heap). Called from the
 * PE spawn path after PeLoad, using the raw PE file bytes that are
 * still in kernel memory. The result is copied onto Process and
 * consulted by Win32 thunks (IsProcessDPIAware, token queries, etc.).
 *
 * Thread safety: stateless pure function — safe from any context.
 */

namespace duetos::core
{

struct ManifestInfo
{
    enum class ExecutionLevel : u8
    {
        AsInvoker,
        HighestAvailable,
        RequireAdministrator
    };

    enum class DpiAwareness : u8
    {
        Unaware,
        SystemAware,
        PerMonitorAware,
        PerMonitorV2
    };

    ExecutionLevel execution_level = ExecutionLevel::AsInvoker;
    DpiAwareness dpi_awareness = DpiAwareness::Unaware;
    bool ui_access = false;
    bool has_manifest = false;
    bool long_path_aware = false;
    u8 _pad[3] = {};

    // SxS dependency identities — stored as fixed-size name strings.
    // A real system would carry version quadruples, publicKeyToken,
    // processorArchitecture, etc. v0 stores just the assembly name
    // so the SxS DLL loader can search for matching directories.
    // GAP: version/publicKeyToken/arch fields — when SxS versioning
    //       matters for a real app.
    static constexpr u32 kMaxSxsDeps = 8;
    static constexpr u32 kSxsNameMax = 64;
    u32 sxs_dep_count = 0;
    char sxs_deps[kMaxSxsDeps][kSxsNameMax] = {};
};

/// Parse a Win32 assembly manifest XML blob. On success returns a
/// ManifestInfo with has_manifest = true and the extracted fields
/// populated. On malformed / empty input returns a default-
/// constructed ManifestInfo (has_manifest = false).
ManifestInfo ParseManifestXml(const u8* xml, u64 len);

/// Extract the RT_MANIFEST resource from a raw (unmapped) PE file
/// and parse it. Walks the PE resource directory to find resource
/// type 24, ID 1 (exe) or 2 (dll), extracts the XML blob, and
/// calls ParseManifestXml. Returns a default ManifestInfo if the
/// PE has no resource directory or no RT_MANIFEST entry.
///
/// `file` is the raw PE file bytes (NOT a mapped image).
ManifestInfo ParseManifestFromPe(const u8* file, u64 file_len);

} // namespace duetos::core
