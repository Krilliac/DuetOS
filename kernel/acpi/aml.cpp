#include "aml.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../mm/page.h"
#include "acpi.h"

namespace customos::acpi
{

namespace
{

constinit AmlNamespaceEntry g_entries[kMaxAmlNsEntries] = {};
constinit u32 g_entry_count = 0;

// Top-level AML opcodes we recognise. Anything not on this list
// terminates the current TermList (the caller advances to its
// PkgLength end and continues).
constexpr u8 kOpZero = 0x00;
constexpr u8 kOpOne = 0x01;
constexpr u8 kOpAlias = 0x06;
constexpr u8 kOpName = 0x08;
constexpr u8 kOpScope = 0x10;
constexpr u8 kOpBuffer = 0x11;
constexpr u8 kOpPackage = 0x12;
constexpr u8 kOpVarPackage = 0x13;
constexpr u8 kOpMethod = 0x14;
constexpr u8 kOpExternal = 0x15;
constexpr u8 kOpExtPrefix = 0x5B;

// Extended opcodes (after 0x5B prefix).
constexpr u8 kExtMutex = 0x01;
constexpr u8 kExtEvent = 0x02;
constexpr u8 kExtOpRegion = 0x80;
constexpr u8 kExtField = 0x81;
constexpr u8 kExtDevice = 0x82;
constexpr u8 kExtProcessor = 0x83;
constexpr u8 kExtPowerRes = 0x84;
constexpr u8 kExtThermalZone = 0x85;

inline bool IsLeadNameChar(u8 c)
{
    return c == '_' || (c >= 'A' && c <= 'Z');
}
inline bool IsNameChar(u8 c)
{
    return IsLeadNameChar(c) || (c >= '0' && c <= '9');
}

// Decode a PkgLength field. ACPI 6.x §20.2.4. Returns the encoded
// length in `*out_len` and the byte count consumed in `*out_consumed`.
// On malformed input returns false (caller stops the walk).
bool ReadPkgLength(const u8* p, u64 remaining, u32* out_len, u32* out_consumed)
{
    if (remaining < 1)
        return false;
    const u8 lead = p[0];
    const u32 follow = (lead >> 6) & 0x3;
    if (remaining < u64(1 + follow))
        return false;
    if (follow == 0)
    {
        *out_len = lead & 0x3F;
        *out_consumed = 1;
        return true;
    }
    u32 len = lead & 0x0F;
    for (u32 i = 0; i < follow; ++i)
        len |= u32(p[1 + i]) << (4 + i * 8);
    *out_len = len;
    *out_consumed = 1 + follow;
    return true;
}

// Parse a NameString (ACPI 6.x §20.2.2) into a flat C-string.
// Forms:
//   '\\' (root) followed by NamePath
//   ('^')+      followed by NamePath
//   NamePath
//
// NamePath:
//   NameSeg            (4 chars: lead + 3 name chars)
//   DualNamePath       0x2E NameSeg NameSeg
//   MultiNamePath      0x2F SegCount NameSeg{SegCount}
//   NullName           0x00
//
// We emit "\seg.seg.seg" or "^^seg.seg" or just "seg.seg" (no
// leading separator). out_buf is at least 64 bytes.
struct NameStringInfo
{
    char text[64];    // NUL-terminated
    u32 prefix_caret; // count of leading '^' chars (parent-scope hops)
    bool absolute;    // true iff started with '\\'
    bool null_name;   // true iff the entire name was 0x00 (NullName)
};

bool ReadNameString(const u8* p, u64 remaining, NameStringInfo* out, u32* out_consumed)
{
    *out = NameStringInfo{};
    u32 pos = 0;

    // Prefix: at most one of '\\' or many '^'.
    if (pos < remaining && p[pos] == '\\')
    {
        out->absolute = true;
        ++pos;
    }
    else
    {
        while (pos < remaining && p[pos] == '^')
        {
            ++out->prefix_caret;
            ++pos;
        }
    }

    if (pos >= remaining)
        return false;

    // NullName.
    if (p[pos] == 0x00)
    {
        out->null_name = true;
        out->text[0] = '\0';
        *out_consumed = pos + 1;
        return true;
    }

    u8 seg_count = 1;
    if (p[pos] == 0x2E) // DualNamePrefix
    {
        seg_count = 2;
        ++pos;
    }
    else if (p[pos] == 0x2F) // MultiNamePrefix
    {
        ++pos;
        if (pos >= remaining)
            return false;
        seg_count = p[pos];
        ++pos;
        if (seg_count == 0)
            return false;
    }

    if (pos + u64(seg_count) * 4 > remaining)
        return false;

    u32 write = 0;
    for (u8 s = 0; s < seg_count; ++s)
    {
        if (s != 0)
        {
            if (write + 1 >= sizeof(out->text))
                return false;
            out->text[write++] = '.';
        }
        for (u8 i = 0; i < 4; ++i)
        {
            const u8 c = p[pos + i];
            if (i == 0 ? !IsLeadNameChar(c) : !IsNameChar(c))
                return false;
            if (write + 1 >= sizeof(out->text))
                return false;
            out->text[write++] = char(c);
        }
        pos += 4;
    }
    out->text[write] = '\0';
    *out_consumed = pos;
    return true;
}

// Compose `current_scope` + parsed NameString into an absolute
// canonical path written to `out` (cap kPathCap bytes). Returns
// true on success, false if the result would overflow.
constexpr u32 kPathCap = sizeof(AmlNamespaceEntry::path);

bool ComposePath(const char* scope, const NameStringInfo& name, char* out)
{
    char buf[kPathCap];
    u32 w = 0;

    if (name.absolute)
    {
        // Start fresh at root.
        if (w + 1 >= kPathCap)
            return false;
        buf[w++] = '\\';
    }
    else
    {
        // Copy current scope verbatim, then trim `prefix_caret`
        // segments off the right-hand side.
        u32 i = 0;
        while (scope[i] != '\0' && w + 1 < kPathCap)
            buf[w++] = scope[i++];
        for (u32 c = 0; c < name.prefix_caret; ++c)
        {
            // Trim back to the previous '.' or '\\'.
            while (w > 0 && buf[w - 1] != '.' && buf[w - 1] != '\\')
                --w;
            if (w > 0 && buf[w - 1] == '.')
                --w;
            else if (w == 0)
                return false; // tried to '^' past the root
        }
    }

    if (!name.null_name)
    {
        // Need '.' separator unless we just placed the root '\\' or
        // the buffer is empty (relative + scope was empty).
        const bool need_dot = (w > 0 && buf[w - 1] != '\\');
        if (need_dot)
        {
            if (w + 1 >= kPathCap)
                return false;
            buf[w++] = '.';
        }
        u32 i = 0;
        while (name.text[i] != '\0' && w + 1 < kPathCap)
            buf[w++] = name.text[i++];
        if (name.text[i] != '\0')
            return false; // truncated
    }

    if (w + 1 > kPathCap)
        return false;
    buf[w] = '\0';
    for (u32 i = 0; i <= w; ++i)
        out[i] = buf[i];
    return true;
}

bool RecordEntry(const char* path, AmlObjectKind kind, u8 method_args, u8 source_idx, u32 aml_off)
{
    if (g_entry_count >= kMaxAmlNsEntries)
        return false;
    AmlNamespaceEntry& e = g_entries[g_entry_count];
    u32 i = 0;
    while (path[i] != '\0' && i + 1 < sizeof(e.path))
    {
        e.path[i] = path[i];
        ++i;
    }
    e.path[i] = '\0';
    e.kind = kind;
    e.method_args = method_args;
    e.source_table_idx = source_idx;
    e._pad = 0;
    e.aml_offset = aml_off;
    ++g_entry_count;
    return true;
}

// Skip past a DataRefObject (common cases only). Returns the
// number of bytes consumed, or 0 if we don't recognise the encoding
// — the caller takes that as "stop the current TermList".
//
// Not exhaustive. Anything past the simple-data forms (BufferOp,
// PackageOp, computed expressions) we punt on; the walker stops at
// the parent's PkgLength end so it stays safe.
u32 SkipDataRefObject(const u8* p, u32 remaining)
{
    if (remaining == 0)
        return 0;
    const u8 op = p[0];
    switch (op)
    {
    case 0x00: // ZeroOp
    case 0x01: // OneOp
    case 0xFF: // OnesOp
        return 1;
    case 0x0A: // BytePrefix
        return remaining >= 2 ? 2 : 0;
    case 0x0B: // WordPrefix
        return remaining >= 3 ? 3 : 0;
    case 0x0C: // DWordPrefix
        return remaining >= 5 ? 5 : 0;
    case 0x0E: // QWordPrefix
        return remaining >= 9 ? 9 : 0;
    case 0x0D: // StringPrefix — NUL-terminated ASCII
    {
        u32 i = 1;
        while (i < remaining && p[i] != 0)
            ++i;
        if (i >= remaining)
            return 0;
        return i + 1;
    }
    case 0x11: // BufferOp: PkgLength BufferSize ByteList
    case 0x12: // PackageOp: PkgLength NumElements PackageElementList
    case 0x13: // VarPackageOp
    {
        u32 pkg_len = 0;
        u32 plen_consumed = 0;
        if (!ReadPkgLength(p + 1, remaining - 1, &pkg_len, &plen_consumed))
            return 0;
        const u32 total = 1 + pkg_len;
        return (total <= remaining) ? total : 0;
    }
    default:
        return 0;
    }
}

// The walker. Produces entries into the global table.
struct Walker
{
    const u8* base; // start of the AML body for this table
    u64 length;     // bytes available
    u8 source_idx;  // 0=DSDT, N+1 = SSDT[N]

    // Walk a TermList that ends at byte offset `end`. `scope` is
    // the current canonical path (NUL-terminated, ≤ kPathCap).
    // Returns when pos >= end or an unknown opcode is hit.
    void WalkTermList(u32 pos, u32 end, const char* scope)
    {
        while (pos < end && pos < length && g_entry_count < kMaxAmlNsEntries)
        {
            const u32 start = pos;
            const u8 op = base[pos++];

            if (op == kOpExtPrefix)
            {
                if (pos >= end)
                    return;
                const u8 ext = base[pos++];
                if (!HandleExt(start, pos, end, scope, ext))
                    return;
                pos = next_pos_;
                continue;
            }

            switch (op)
            {
            case kOpZero:
            case kOpOne:
                continue; // 1-byte literal, no payload
            case kOpAlias:
            {
                // AliasOp NameString NameString
                if (!RecordNamePair(start, pos, end, scope, AmlObjectKind::Alias))
                    return;
                pos = next_pos_;
                continue;
            }
            case kOpName:
            {
                // NameOp NameString DataRefObject
                NameStringInfo ns;
                u32 consumed = 0;
                if (!ReadNameString(base + pos, end - pos, &ns, &consumed))
                    return;
                char path[kPathCap];
                if (!ComposePath(scope, ns, path))
                    return;
                RecordEntry(path, AmlObjectKind::Name, 0, source_idx, start);
                pos += consumed;
                // Try to skip past a simple DataRefObject so the
                // walk can continue. Anything beyond the common
                // simple-data forms (BufferOp, PackageOp, computed
                // TermArgs) we don't decode — bail; parent's
                // PkgLength end keeps the parent walk safe.
                const u32 dr = SkipDataRefObject(base + pos, end - pos);
                if (dr == 0)
                    return;
                pos += dr;
                continue;
            }
            case kOpScope:
            {
                if (!HandleContainer(start, pos, end, scope, AmlObjectKind::Scope, /*recurse=*/true))
                    return;
                pos = next_pos_;
                continue;
            }
            case kOpMethod:
            {
                if (!HandleMethod(start, pos, end, scope))
                    return;
                pos = next_pos_;
                continue;
            }
            case kOpBuffer:
            case kOpPackage:
            case kOpVarPackage:
            {
                // These have a PkgLength wrapper but no NameString;
                // they'd only appear as DataRefObjects which we
                // already bail on. Treat at TermList-level as
                // "unknown" — stop.
                return;
            }
            case kOpExternal:
            {
                // ExternalOp NameString ObjectType ArgumentCount
                NameStringInfo ns;
                u32 consumed = 0;
                if (!ReadNameString(base + pos, end - pos, &ns, &consumed))
                    return;
                if (pos + consumed + 2 > end)
                    return;
                char path[kPathCap];
                if (!ComposePath(scope, ns, path))
                    return;
                RecordEntry(path, AmlObjectKind::External, 0, source_idx, start);
                pos += consumed + 2;
                continue;
            }
            default:
                return; // unknown opcode at this level
            }
        }
    }

  private:
    u32 next_pos_ = 0;

    bool HandleExt(u32 start, u32 after_op, u32 end, const char* scope, u8 ext)
    {
        switch (ext)
        {
        case kExtDevice:
            return HandleContainer(start, after_op, end, scope, AmlObjectKind::Device, /*recurse=*/true);
        case kExtProcessor:
            return HandleContainer(start, after_op, end, scope, AmlObjectKind::Processor, /*recurse=*/true);
        case kExtPowerRes:
            return HandleContainer(start, after_op, end, scope, AmlObjectKind::PowerResource, /*recurse=*/true);
        case kExtThermalZone:
            return HandleContainer(start, after_op, end, scope, AmlObjectKind::ThermalZone, /*recurse=*/true);
        case kExtOpRegion:
        {
            // OpRegion: NameString RegionSpace RegionOffset RegionLen
            // RegionOffset/Len are TermArgs (arbitrary expressions).
            // We record the name and then bail — calculating the
            // size of arbitrary TermArgs needs the full interpreter.
            NameStringInfo ns;
            u32 consumed = 0;
            if (!ReadNameString(base + after_op, end - after_op, &ns, &consumed))
                return false;
            char path[kPathCap];
            if (!ComposePath(scope, ns, path))
                return false;
            RecordEntry(path, AmlObjectKind::OpRegion, 0, source_idx, start);
            // We can't reliably skip past the TermArgs; signal stop.
            return false;
        }
        case kExtMutex:
        {
            NameStringInfo ns;
            u32 consumed = 0;
            if (!ReadNameString(base + after_op, end - after_op, &ns, &consumed))
                return false;
            if (after_op + consumed + 1 > end)
                return false;
            char path[kPathCap];
            if (!ComposePath(scope, ns, path))
                return false;
            RecordEntry(path, AmlObjectKind::Mutex, 0, source_idx, start);
            next_pos_ = after_op + consumed + 1;
            return true;
        }
        case kExtEvent:
        {
            NameStringInfo ns;
            u32 consumed = 0;
            if (!ReadNameString(base + after_op, end - after_op, &ns, &consumed))
                return false;
            char path[kPathCap];
            if (!ComposePath(scope, ns, path))
                return false;
            RecordEntry(path, AmlObjectKind::Event, 0, source_idx, start);
            next_pos_ = after_op + consumed;
            return true;
        }
        case kExtField:
            // Field: PkgLength NameString FieldFlags FieldList
            // FieldList contents are not nameable; just skip the
            // package.
            return SkipPackage(start, after_op, end);
        default:
            return false;
        }
    }

    // Handle Scope / Device / Processor / PowerRes / ThermalZone:
    //   <op> PkgLength NameString TermList
    bool HandleContainer(u32 start, u32 after_op, u32 end, const char* scope, AmlObjectKind kind, bool recurse)
    {
        u32 pkg_len = 0;
        u32 plen_consumed = 0;
        if (!ReadPkgLength(base + after_op, end - after_op, &pkg_len, &plen_consumed))
            return false;
        const u32 pkg_end = after_op + pkg_len;
        if (pkg_end > end)
            return false;
        const u32 name_off = after_op + plen_consumed;
        NameStringInfo ns;
        u32 consumed = 0;
        if (!ReadNameString(base + name_off, pkg_end - name_off, &ns, &consumed))
            return false;
        char path[kPathCap];
        if (!ComposePath(scope, ns, path))
            return false;
        RecordEntry(path, kind, 0, source_idx, start);
        const u32 body_off = name_off + consumed;
        // Processor adds 6 bytes (proc_id + pblk_addr + pblk_len)
        // before the TermList; PowerRes adds 3 (system_level +
        // resource_order). Skip them so recursion lands on the
        // TermList head.
        u32 body = body_off;
        if (kind == AmlObjectKind::Processor && body + 6 <= pkg_end)
            body += 6;
        else if (kind == AmlObjectKind::PowerResource && body + 3 <= pkg_end)
            body += 3;
        if (recurse)
            WalkTermList(body, pkg_end, path);
        next_pos_ = pkg_end;
        return true;
    }

    bool HandleMethod(u32 start, u32 after_op, u32 end, const char* scope)
    {
        u32 pkg_len = 0;
        u32 plen_consumed = 0;
        if (!ReadPkgLength(base + after_op, end - after_op, &pkg_len, &plen_consumed))
            return false;
        const u32 pkg_end = after_op + pkg_len;
        if (pkg_end > end)
            return false;
        const u32 name_off = after_op + plen_consumed;
        NameStringInfo ns;
        u32 consumed = 0;
        if (!ReadNameString(base + name_off, pkg_end - name_off, &ns, &consumed))
            return false;
        const u32 flags_off = name_off + consumed;
        if (flags_off >= pkg_end)
            return false;
        const u8 method_flags = base[flags_off];
        const u8 method_args = method_flags & 0x07;
        char path[kPathCap];
        if (!ComposePath(scope, ns, path))
            return false;
        RecordEntry(path, AmlObjectKind::Method, method_args, source_idx, start);
        next_pos_ = pkg_end;
        return true;
    }

    bool RecordNamePair(u32 start, u32 after_op, u32 end, const char* scope, AmlObjectKind kind)
    {
        NameStringInfo first;
        u32 c1 = 0;
        if (!ReadNameString(base + after_op, end - after_op, &first, &c1))
            return false;
        NameStringInfo second;
        u32 c2 = 0;
        if (!ReadNameString(base + after_op + c1, end - after_op - c1, &second, &c2))
            return false;
        char path[kPathCap];
        if (!ComposePath(scope, first, path))
            return false;
        RecordEntry(path, kind, 0, source_idx, start);
        next_pos_ = after_op + c1 + c2;
        return true;
    }

    bool SkipPackage(u32 start, u32 after_op, u32 end)
    {
        u32 pkg_len = 0;
        u32 plen_consumed = 0;
        if (!ReadPkgLength(base + after_op, end - after_op, &pkg_len, &plen_consumed))
            return false;
        const u32 pkg_end = after_op + pkg_len;
        if (pkg_end > end)
            return false;
        (void)start;
        next_pos_ = pkg_end;
        return true;
    }
};

void WalkTable(const u8* sdt, u32 total_len, u8 source_idx)
{
    constexpr u32 kSdtHeaderSize = 36;
    if (total_len <= kSdtHeaderSize)
        return;
    const u32 aml_len = total_len - kSdtHeaderSize;
    Walker w{};
    w.base = sdt + kSdtHeaderSize;
    w.length = aml_len;
    w.source_idx = source_idx;
    w.WalkTermList(0, aml_len, "\\");
}

} // namespace

const char* AmlObjectKindName(AmlObjectKind k)
{
    switch (k)
    {
    case AmlObjectKind::Scope:
        return "Scope";
    case AmlObjectKind::Device:
        return "Device";
    case AmlObjectKind::Method:
        return "Method";
    case AmlObjectKind::Name:
        return "Name";
    case AmlObjectKind::OpRegion:
        return "OpRegion";
    case AmlObjectKind::Mutex:
        return "Mutex";
    case AmlObjectKind::Event:
        return "Event";
    case AmlObjectKind::Alias:
        return "Alias";
    case AmlObjectKind::External:
        return "External";
    case AmlObjectKind::Processor:
        return "Processor";
    case AmlObjectKind::ThermalZone:
        return "ThermalZone";
    case AmlObjectKind::PowerResource:
        return "PowerResource";
    default:
        return "?";
    }
}

void AmlNamespaceBuild()
{
    KLOG_TRACE_SCOPE("acpi/aml", "AmlNamespaceBuild");
    static constinit bool s_done = false;
    KASSERT(!s_done, "acpi/aml", "AmlNamespaceBuild called twice");
    s_done = true;

    const u64 dsdt_phys = DsdtAddress();
    const u32 dsdt_len = DsdtLength();
    if (dsdt_phys != 0 && dsdt_len >= 36)
    {
        const auto* sdt = static_cast<const u8*>(mm::PhysToVirt(dsdt_phys));
        if (sdt != nullptr)
            WalkTable(sdt, dsdt_len, /*source_idx=*/0);
    }
    const u64 ssdt_n = SsdtCount();
    for (u64 i = 0; i < ssdt_n; ++i)
    {
        const u64 phys = SsdtAddress(i);
        const u32 len = SsdtLength(i);
        if (phys == 0 || len < 36)
            continue;
        const auto* sdt = static_cast<const u8*>(mm::PhysToVirt(phys));
        if (sdt != nullptr)
            WalkTable(sdt, len, u8(i + 1));
    }

    arch::SerialWrite("[acpi/aml] namespace: ");
    arch::SerialWriteHex(g_entry_count);
    arch::SerialWrite(" entries (cap ");
    arch::SerialWriteHex(kMaxAmlNsEntries);
    arch::SerialWrite("): scopes=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Scope));
    arch::SerialWrite(" devices=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Device));
    arch::SerialWrite(" methods=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Method));
    arch::SerialWrite(" opregions=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::OpRegion));
    arch::SerialWrite(" thermal=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::ThermalZone));
    arch::SerialWrite(" power=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::PowerResource));
    arch::SerialWrite(" cpus=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Processor));
    arch::SerialWrite("\n");
}

u32 AmlNamespaceCount()
{
    return g_entry_count;
}

const AmlNamespaceEntry* AmlNamespaceEntryAt(u32 i)
{
    if (i >= g_entry_count)
        return nullptr;
    return &g_entries[i];
}

const AmlNamespaceEntry* AmlNamespaceFind(const char* path)
{
    if (path == nullptr)
        return nullptr;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        const char* a = g_entries[i].path;
        const char* b = path;
        while (*a != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0')
            return &g_entries[i];
    }
    return nullptr;
}

u32 AmlNamespaceCountByKind(AmlObjectKind k)
{
    u32 n = 0;
    for (u32 i = 0; i < g_entry_count; ++i)
    {
        if (g_entries[i].kind == k)
            ++n;
    }
    return n;
}

} // namespace customos::acpi
