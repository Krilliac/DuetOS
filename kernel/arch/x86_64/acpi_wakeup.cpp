#include "arch/x86_64/acpi_wakeup.h"

#include "acpi/acpi.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/page.h"

namespace duetos::arch
{

// Linker-emitted bounds of the trampoline image in acpi_wakeup.S.
extern "C" const u8 acpi_wake_tramp_start[];
extern "C" const u8 acpi_wake_tramp_end[];

// Referenced by name (RIP-relative) from AcpiWakeResume64, which runs
// before any argument register can be trusted. `extern "C"` so the
// assembler's `g_acpi_wake_ctx` resolves without mangling; not `static`
// for the same reason.
extern "C" AcpiWakeContext g_acpi_wake_ctx;
constinit AcpiWakeContext g_acpi_wake_ctx{};

extern "C" void AcpiWakeResume64();

namespace
{

// Parameter-block offsets inside the copied blob. Mirrored from the
// `.set OFF_*` lines in acpi_wakeup.S — a drift here resumes the
// machine into garbage, so the self-test re-derives them from the
// blob's own GDT pointer rather than trusting the constants blindly.
constexpr u64 kOffPml4 = 0x0F00;
constexpr u64 kOffResume = 0x0F08;
constexpr u64 kTrampolineMaxLen = 0x1000;

// The AcpiWakeContext layout is shared with acpi_wakeup.S by raw byte
// offset. These are the contract; the .S file's CTX_* constants must
// match one-for-one.
static_assert(__builtin_offsetof(AcpiWakeContext, rsp) == 0, "CTX_RSP");
static_assert(__builtin_offsetof(AcpiWakeContext, cr0) == 8, "CTX_CR0");
static_assert(__builtin_offsetof(AcpiWakeContext, cr3) == 16, "CTX_CR3");
static_assert(__builtin_offsetof(AcpiWakeContext, cr4) == 24, "CTX_CR4");
static_assert(__builtin_offsetof(AcpiWakeContext, efer) == 32, "CTX_EFER");
static_assert(__builtin_offsetof(AcpiWakeContext, star) == 40, "CTX_STAR");
static_assert(__builtin_offsetof(AcpiWakeContext, lstar) == 48, "CTX_LSTAR");
static_assert(__builtin_offsetof(AcpiWakeContext, sfmask) == 56, "CTX_SFMASK");
static_assert(__builtin_offsetof(AcpiWakeContext, fs_base) == 64, "CTX_FS_BASE");
static_assert(__builtin_offsetof(AcpiWakeContext, gs_base) == 72, "CTX_GS_BASE");
static_assert(__builtin_offsetof(AcpiWakeContext, kernel_gs_base) == 80, "CTX_KGS_BASE");
static_assert(__builtin_offsetof(AcpiWakeContext, tss_rsp0) == 88, "CTX_TSS_RSP0");
static_assert(__builtin_offsetof(AcpiWakeContext, gdtr) == 96, "CTX_GDTR");
static_assert(__builtin_offsetof(AcpiWakeContext, idtr) == 106, "CTX_IDTR");
static_assert(__builtin_offsetof(AcpiWakeContext, tr) == 116, "CTX_TR");
static_assert(__builtin_offsetof(AcpiWakeContext, cs) == 118, "CTX_CS");
static_assert(__builtin_offsetof(AcpiWakeContext, ss) == 120, "CTX_SS");
static_assert(__builtin_offsetof(AcpiWakeContext, ds) == 122, "CTX_DS");
static_assert(__builtin_offsetof(AcpiWakeContext, resume_count) == 124, "CTX_RESUME_COUNT");
static_assert(sizeof(AcpiWakeContext) == 128, "AcpiWakeContext is 128 bytes");

u64 ReadCr3()
{
    u64 v = 0;
    asm volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

} // namespace

AcpiWakeContext& AcpiWakeContextGet()
{
    return g_acpi_wake_ctx;
}

bool AcpiWakeArm()
{
    const u64 start = reinterpret_cast<u64>(acpi_wake_tramp_start);
    const u64 end = reinterpret_cast<u64>(acpi_wake_tramp_end);
    const u64 len = end >= start ? end - start : 0;
    if (len == 0 || len > kTrampolineMaxLen)
    {
        KLOG_WARN_V("arch/acpi-wake", "wake trampoline image does not fit its page — S3 unavailable", len);
        return false;
    }

    // Physical 0x9000 sits inside the low 1 MiB the frame allocator
    // keeps permanently reserved (same guarantee the AP trampoline at
    // 0x8000 relies on), so this write cannot land on someone's page.
    auto* dst = static_cast<u8*>(mm::PhysToVirt(kAcpiWakePhys));
    if (dst == nullptr)
    {
        KLOG_WARN("arch/acpi-wake", "low-memory wake page is not mapped — S3 unavailable");
        return false;
    }
    for (u64 i = 0; i < len; ++i)
        dst[i] = acpi_wake_tramp_start[i];

    // Seed the parameter block the trampoline reads on the way up.
    const u64 pml4 = ReadCr3();
    const u64 resume_va = reinterpret_cast<u64>(&AcpiWakeResume64);
    __builtin_memcpy(dst + kOffPml4, &pml4, sizeof(pml4));
    __builtin_memcpy(dst + kOffResume, &resume_va, sizeof(resume_va));

    // CR3 must be below 4 GiB: the trampoline loads it with a 32-bit
    // `mov cr3, eax` while still in protected mode. Every x86_64 board
    // we target allocates page tables low, but a truncated CR3 would
    // resume into a wild page hierarchy, so verify rather than assume.
    if ((pml4 >> 32) != 0)
    {
        KLOG_WARN("arch/acpi-wake", "kernel PML4 is above 4 GiB — wake trampoline cannot load it, S3 unavailable");
        return false;
    }

    // Publish the vector last: until this succeeds the firmware has no
    // reason to jump anywhere, and a failure here must leave suspend
    // refused rather than half-armed.
    if (!acpi::AcpiSetWakingVector(static_cast<u32>(kAcpiWakePhys)))
    {
        KLOG_WARN("arch/acpi-wake", "FACS waking vector unavailable — S3 unavailable");
        return false;
    }
    return true;
}

void AcpiWakeSelfTest()
{
    using core::PanicWithValue;

    const u64 start = reinterpret_cast<u64>(acpi_wake_tramp_start);
    const u64 end = reinterpret_cast<u64>(acpi_wake_tramp_end);
    const u64 len = end >= start ? end - start : 0;
    if (len != kTrampolineMaxLen)
        PanicWithValue("arch/acpi-wake", "wake trampoline blob is not exactly one page", len);

    // The waking vector is handed to firmware as a real-mode CS:IP, so
    // the landing address must be below 1 MiB and paragraph-aligned.
    if (kAcpiWakePhys >= 0x100000 || (kAcpiWakePhys & 0xF) != 0)
        PanicWithValue("arch/acpi-wake", "wake page is not a valid real-mode vector", kAcpiWakePhys);

    // The blob must not overlap the AP trampoline's page at 0x8000.
    if (kAcpiWakePhys < 0x9000)
        PanicWithValue("arch/acpi-wake", "wake page overlaps the AP trampoline", kAcpiWakePhys);

    // Re-derive the GDT-pointer offset from the blob itself: the
    // 6-byte GDTR image at OFF_GDT_PTR must carry limit 0x27 and base
    // WAKE_BASE + OFF_GDT. If the .S offsets drift out of step with
    // the constants above, this catches it at boot rather than at the
    // one moment we can least afford a fault.
    constexpr u64 kOffGdtPtr = 0x0118;
    constexpr u64 kOffGdt = 0x00F0;
    u16 limit = 0;
    u64 base = 0;
    __builtin_memcpy(&limit, acpi_wake_tramp_start + kOffGdtPtr, sizeof(limit));
    __builtin_memcpy(&base, acpi_wake_tramp_start + kOffGdtPtr + 2, sizeof(base));
    if (limit != 0x27)
        PanicWithValue("arch/acpi-wake", "wake trampoline GDT limit wrong", limit);
    if (base != kAcpiWakePhys + kOffGdt)
        PanicWithValue("arch/acpi-wake", "wake trampoline GDT base wrong", base);

    // A fresh boot has never resumed. If this is non-zero the context
    // is aliasing something else's memory.
    if (g_acpi_wake_ctx.resume_count != 0)
        PanicWithValue("arch/acpi-wake", "wake context resume_count non-zero at boot", g_acpi_wake_ctx.resume_count);

    SerialWrite("[acpi-wake-selftest] PASS (blob one page, real-mode vector, GDT ptr, context layout)\n");
}

} // namespace duetos::arch
