#include "dll_loader.h"
#include "pe_exports.h"

#include "../arch/x86_64/serial.h"
#include "../mm/address_space.h"

#include "generated_customdll.h"

/*
 * End-to-end smoke test for the stage-2 EAT parser + DLL
 * loader. Called once from `kernel_main` after the Win32 NT
 * coverage scoreboard is logged. Exercises:
 *
 *   1. PeParseExports on the embedded customdll.dll bytes.
 *      Expects Ok status + three named exports (CustomAdd,
 *      CustomMul, CustomVersion) in an ENT sorted
 *      alphabetically.
 *
 *   2. DllLoad into a scratch AddressSpace. Expects
 *      DllLoadStatus::Ok with has_exports == true and the
 *      `IMAGE_FILE_DLL` bit correctly detected. Releases the
 *      scratch AS right after so no frames leak into the
 *      steady-state boot image.
 *
 *   3. DllResolveExport("CustomAdd") + ("CustomMul") + ...
 *      return non-zero VAs inside the mapped DLL range.
 *
 *   4. DllResolveOrdinal(1) matches DllResolveExport("CustomAdd")
 *      (lld-link emits exports in alphabetical order, so
 *      ordinal 1 is the first name).
 *
 * On any failure the test emits a `[dll-test] FAIL ...` line
 * and returns — we deliberately DON'T panic here because this
 * is a boot-time diagnostic, not a safety-critical invariant.
 * A future slice may promote the assertion to KASSERT-style
 * if the DLL loader becomes load-bearing.
 */

namespace customos::core
{

namespace
{

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return a == b;
    while (*a && *b)
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

bool Expect(bool ok, const char* label)
{
    using arch::SerialWrite;
    if (!ok)
    {
        SerialWrite("[dll-test] FAIL ");
        SerialWrite(label);
        SerialWrite("\n");
    }
    return ok;
}

} // namespace

void DllLoaderSelfTest()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u8* bytes = customos::fs::generated::kBinCustomDllBytes;
    const u64 len = customos::fs::generated::kBinCustomDllBytes_len;

    SerialWrite("[dll-test] begin customdll.dll bytes=");
    SerialWriteHex(len);
    SerialWrite("\n");

    // --- 1. Parse EAT directly on the raw bytes ---
    PeExports exp{};
    const PeExportStatus pes = PeParseExports(bytes, len, exp);
    if (!Expect(pes == PeExportStatus::Ok, "PeParseExports"))
        return;

    const char* dll_name = PeExportsDllName(exp);
    if (!Expect(dll_name != nullptr, "PeExportsDllName"))
        return;
    if (!Expect(StrEq(dll_name, "customdll.dll"), "dll-name match"))
    {
        SerialWrite("  got=\"");
        SerialWrite(dll_name);
        SerialWrite("\"\n");
        return;
    }
    if (!Expect(exp.num_funcs == 3, "num_funcs==3"))
    {
        SerialWrite("  got=");
        SerialWriteHex(exp.num_funcs);
        SerialWrite("\n");
        return;
    }
    if (!Expect(exp.num_names == 3, "num_names==3"))
        return;

    PeExport e_add{};
    PeExport e_mul{};
    PeExport e_ver{};
    if (!Expect(PeExportLookupName(exp, "CustomAdd", e_add), "lookup CustomAdd"))
        return;
    if (!Expect(PeExportLookupName(exp, "CustomMul", e_mul), "lookup CustomMul"))
        return;
    if (!Expect(PeExportLookupName(exp, "CustomVersion", e_ver), "lookup CustomVersion"))
        return;

    // Miss case: a name that doesn't exist in the EAT.
    PeExport e_miss{};
    if (!Expect(!PeExportLookupName(exp, "DoesNotExist", e_miss), "lookup miss"))
        return;

    // Ordinal path: lld-link emits exports in source order
    // with no /ordinal directives, which means ENT is sorted
    // alphabetically: CustomAdd, CustomMul, CustomVersion.
    // Absolute ordinals are base + index in the EAT, which IS
    // the alphabetical order: CustomAdd=1, CustomMul=2,
    // CustomVersion=3.
    PeExport e_ord1{};
    if (!Expect(PeExportLookupOrdinal(exp, 1, e_ord1), "lookup ord=1"))
        return;
    if (!Expect(e_ord1.rva == e_add.rva, "ord=1 rva==CustomAdd.rva"))
        return;

    SerialWrite("[dll-test] EAT parse OK — CustomAdd rva=");
    SerialWriteHex(e_add.rva);
    SerialWrite(" CustomMul rva=");
    SerialWriteHex(e_mul.rva);
    SerialWrite(" CustomVersion rva=");
    SerialWriteHex(e_ver.rva);
    SerialWrite("\n");

    // --- 2. DllLoad into a scratch AS ---
    // Small frame budget: the DLL is ~2 KiB, so one section
    // page + one header page + one reloc patch page is the
    // ceiling. 16 frames is a safety margin.
    constexpr u64 kScratchBudget = 16;
    customos::mm::AddressSpace* as = customos::mm::AddressSpaceCreate(kScratchBudget);
    if (!Expect(as != nullptr, "AddressSpaceCreate"))
        return;

    DllLoadResult r = DllLoad(bytes, len, as, /*aslr_delta=*/0);
    const bool loaded = (r.status == DllLoadStatus::Ok);
    if (!Expect(loaded, "DllLoad"))
    {
        SerialWrite("  status=");
        SerialWrite(DllLoadStatusName(r.status));
        SerialWrite("\n");
        customos::mm::AddressSpaceRelease(as);
        return;
    }
    if (!Expect(r.image.has_exports, "image.has_exports"))
    {
        customos::mm::AddressSpaceRelease(as);
        return;
    }

    const u64 va_add = DllResolveExport(r.image, "CustomAdd");
    const u64 va_mul = DllResolveExport(r.image, "CustomMul");
    const u64 va_ver = DllResolveExport(r.image, "CustomVersion");
    const u64 va_ord1 = DllResolveOrdinal(r.image, 1);

    // Every resolved VA should land inside [base_va, base_va+size).
    const bool in_range_add = (va_add != 0 && va_add >= r.image.base_va && va_add < r.image.base_va + r.image.size);
    const bool in_range_mul = (va_mul != 0 && va_mul >= r.image.base_va && va_mul < r.image.base_va + r.image.size);
    const bool in_range_ver = (va_ver != 0 && va_ver >= r.image.base_va && va_ver < r.image.base_va + r.image.size);

    Expect(in_range_add, "DllResolveExport CustomAdd in range");
    Expect(in_range_mul, "DllResolveExport CustomMul in range");
    Expect(in_range_ver, "DllResolveExport CustomVersion in range");
    Expect(va_ord1 == va_add, "DllResolveOrdinal(1) == CustomAdd");

    SerialWrite("[dll-test] DllLoad OK base_va=");
    SerialWriteHex(r.image.base_va);
    SerialWrite(" CustomAdd VA=");
    SerialWriteHex(va_add);
    SerialWrite("\n");

    customos::mm::AddressSpaceRelease(as);
}

} // namespace customos::core
