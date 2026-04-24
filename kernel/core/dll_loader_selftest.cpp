#include "dll_loader.h"
#include "pe_exports.h"
#include "process.h"

#include "../arch/x86_64/serial.h"
#include "../mm/address_space.h"
#include "../mm/kheap.h"

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

    // --- 3. Per-process DLL table (slice 3) ---
    // Zero-initialise a scratch Process — we don't go through
    // ProcessCreate because we only care about the DLL-table
    // fields, and a full ProcessCreate would drag in the AS
    // ownership transfer (the scratch AS was already released
    // above is NOT true — we hold it through this step).
    //
    // Wait — we still hold `as` here; release happens below. A
    // full ProcessCreate would take ownership of `as` and
    // release it on ProcessRelease, which is fine: the table
    // test is purely about whether `ProcessRegisterDllImage` +
    // `ProcessResolveDllExport` round-trip correctly.
    auto* proc = static_cast<Process*>(customos::mm::KMalloc(sizeof(Process)));
    if (!Expect(proc != nullptr, "scratch Process KMalloc"))
    {
        customos::mm::AddressSpaceRelease(as);
        return;
    }
    // Zero every byte — ProcessRegisterDllImage only reads
    // dll_image_count + pid, ProcessResolveDllExport only reads
    // dll_image_count + dll_images. Everything else stays zero.
    auto* proc_bytes = reinterpret_cast<u8*>(proc);
    for (u64 i = 0; i < sizeof(Process); ++i)
        proc_bytes[i] = 0;
    proc->pid = 0xD11; // visible in any [proc] dll-table FULL log line

    // Register once — first slot should be filled.
    if (!Expect(ProcessRegisterDllImage(proc, r.image), "ProcessRegisterDllImage"))
    {
        customos::mm::KFree(proc);
        customos::mm::AddressSpaceRelease(as);
        return;
    }
    if (!Expect(proc->dll_image_count == 1, "dll_image_count == 1"))
    {
        customos::mm::KFree(proc);
        customos::mm::AddressSpaceRelease(as);
        return;
    }

    // Case A: resolve with explicit DLL name — exact match.
    const u64 va_add_viaproc = ProcessResolveDllExport(proc, "customdll.dll", "CustomAdd");
    Expect(va_add_viaproc == va_add, "resolve via proc (exact dll match)");

    // Case B: resolve with mixed-case DLL name — case-insensitive.
    const u64 va_mul_viaproc = ProcessResolveDllExport(proc, "CUSTOMDLL.DLL", "CustomMul");
    Expect(va_mul_viaproc == va_mul, "resolve via proc (ci dll match)");

    // Case C: resolve with NULL dll_name — any registered DLL.
    const u64 va_ver_viaproc = ProcessResolveDllExport(proc, nullptr, "CustomVersion");
    Expect(va_ver_viaproc == va_ver, "resolve via proc (any dll)");

    // Case D: unknown DLL name → miss even if func name matches.
    const u64 va_wrongdll = ProcessResolveDllExport(proc, "kernel32.dll", "CustomAdd");
    Expect(va_wrongdll == 0, "resolve via proc (wrong dll)");

    // Case E: unknown function → miss.
    const u64 va_wrongfunc = ProcessResolveDllExport(proc, "customdll.dll", "DoesNotExist");
    Expect(va_wrongfunc == 0, "resolve via proc (wrong func)");

    SerialWrite("[dll-test] ProcessRegisterDllImage + ProcessResolveDllExport OK\n");

    // --- 4. HMODULE-based resolve (slice 4, backs SYS_DLL_PROC_ADDRESS) ---
    // Mirror the Win32 GetProcAddress(HMODULE, LPCSTR) shape.
    // The HMODULE a real caller passes is the DLL's load base VA —
    // exactly what DllLoad wrote into r.image.base_va.
    const u64 va_by_base_add = ProcessResolveDllExportByBase(proc, r.image.base_va, "CustomAdd");
    Expect(va_by_base_add == va_add, "ByBase(base_va, CustomAdd)");

    // HMODULE=0 means "any registered DLL" — matches the slice-3
    // ProcessResolveDllExport(proc, nullptr, ...) fallthrough.
    const u64 va_by_base_any = ProcessResolveDllExportByBase(proc, 0, "CustomMul");
    Expect(va_by_base_any == va_mul, "ByBase(0, CustomMul)");

    // A bogus HMODULE → no match, clean 0.
    const u64 va_by_base_bogus = ProcessResolveDllExportByBase(proc, 0xDEADBEEF, "CustomAdd");
    Expect(va_by_base_bogus == 0, "ByBase(bogus, CustomAdd)");

    SerialWrite("[dll-test] ProcessResolveDllExportByBase OK (SYS_DLL_PROC_ADDRESS backing)\n");

    customos::mm::KFree(proc);
    customos::mm::AddressSpaceRelease(as);
}

} // namespace customos::core
