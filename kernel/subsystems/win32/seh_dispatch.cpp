#include "subsystems/win32/seh_dispatch.h"

#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "subsystems/win32/seh_unwind.h"

namespace duetos::subsystems::win32
{

namespace
{

// Microsoft x64 EXCEPTION_RECORD. Fixed layout — a PE built
// against <windows.h> reads exactly these offsets, and ntdll's
// KiUserExceptionDispatcher / __C_specific_handler (our userland
// reimplementation) consumes the same shape.
struct ExceptionRecord
{
    u32 ExceptionCode;
    u32 ExceptionFlags;
    u64 ExceptionRecordPtr; // nested EXCEPTION_RECORD (always 0 here)
    u64 ExceptionAddress;
    u32 NumberParameters;
    u32 _alignment;
    u64 ExceptionInformation[15];
};

static_assert(sizeof(ExceptionRecord) == 0x98, "EXCEPTION_RECORD must match Microsoft x64 layout");

constexpr u32 kContextFlagsAll = 0x0010001F; // AMD64 | CONTROL | INTEGER | SEGMENTS | FLOATING_POINT

void ZeroBytes(void* p, u64 n)
{
    auto* b = static_cast<u8*>(p);
    for (u64 i = 0; i < n; ++i)
    {
        b[i] = 0;
    }
}

u64 AlignDown16(u64 v)
{
    return v & ~static_cast<u64>(0xF);
}

// `int 0x29` — the two bytes MSVC emits for the `__fastfail`
// intrinsic. Vector 0x29 has no IDT gate, so the CPU raises
// #GP with error_code = 0x29 * 8 + 2 (IDT-relative selector,
// external = 0). Both the opcode and the error code are checked:
// the opcode alone would misread a #GP raised on some other
// instruction that merely happens to sit next to those bytes.
constexpr u8 kIntImm8Opcode = 0xCD;
constexpr u8 kFastFailVector = 0x29;
constexpr u64 kFastFailGpErrorCode = (u64(kFastFailVector) << 3) | 0x2;

} // namespace

bool Win32DecodeFastFail(const arch::TrapFrame* frame, u32* out_code)
{
    if (frame == nullptr || out_code == nullptr)
    {
        return false;
    }
    // Ring-3 #GP only. A kernel-mode `int 0x29` is not a Win32
    // fail-fast — it would be a kernel bug, and must keep taking
    // the panic path rather than being reinterpreted as a guest
    // exception.
    if (frame->vector != 13 || (frame->cs & 0x3) != 0x3)
    {
        return false;
    }
    if (frame->error_code != kFastFailGpErrorCode)
    {
        return false;
    }

    // Read the faulting instruction from user memory. CopyFromUser
    // gates on the user half + SMAP and fails closed via the
    // extable, so an unmapped RIP returns false instead of
    // double-faulting the kernel inside the fault handler.
    u8 insn[2] = {0, 0};
    if (!duetos::mm::CopyFromUser(insn, reinterpret_cast<const void*>(frame->rip), sizeof(insn)))
    {
        return false;
    }
    if (insn[0] != kIntImm8Opcode || insn[1] != kFastFailVector)
    {
        return false;
    }

    // `__fastfail(code)` passes the reason in ECX per the x64
    // calling convention. Only the low 32 bits are meaningful.
    *out_code = static_cast<u32>(frame->rcx & 0xFFFFFFFFULL);
    return true;
}

const char* Win32FastFailName(u32 code)
{
    // The documented subset the MSVC CRT and our own PE corpus
    // actually raise. Anything else logs as a bare number rather
    // than being guessed at.
    switch (code)
    {
    case 0:
        return "LEGACY_GS_VIOLATION";
    case 1:
        return "VTGUARD_CHECK_FAILURE";
    case 2:
        return "STACK_COOKIE_CHECK_FAILURE";
    case 3:
        return "CORRUPT_LIST_ENTRY";
    case 4:
        return "INCORRECT_STACK";
    case 5:
        return "INVALID_ARG";
    case 6:
        return "GS_COOKIE_INIT";
    case 7:
        return "FATAL_APP_EXIT";
    case 8:
        return "RANGE_CHECK_FAILURE";
    case 9:
        return "UNSAFE_REGISTRY_ACCESS";
    case 18:
        return "INVALID_FAST_FAIL_CODE";
    case 29:
        return "INVALID_SET_OF_CONTEXT";
    default:
        return nullptr;
    }
}

bool Win32DeliverException(arch::TrapFrame* frame, u32 ntstatus, bool is_pf, bool pf_write, u64 fault_va)
{
    if (frame == nullptr)
    {
        return false;
    }

    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return false;
    }

    // The dispatcher entry point lives in this process's ntdll. If
    // it doesn't resolve, the process isn't a Win32 PE with our
    // ntdll mapped (native ELF, Linux ELF, or a kernel32-only PE
    // that never pulled ntdll) — fall back to the legacy task-kill
    // so behaviour for non-SEH processes is unchanged.
    //
    // dll_name is nullptr (search every registered image) rather
    // than "ntdll": the per-image export-directory Name that
    // ProcessResolveDllExport's name filter compares against is not
    // reliably "ntdll" for our lld-link-built ntdll.dll, and the
    // symbol is ntdll-unique anyway, so an unfiltered search is
    // both correct and robust against that mismatch.
    const u64 kidisp = core::ProcessResolveDllExport(proc, nullptr, "KiUserExceptionDispatcher");
    if (kidisp == 0)
    {
        // DEBUG, not WARN: reaching here means the faulting process
        // has no ntdll!KiUserExceptionDispatcher, i.e. it isn't a
        // Win32 PE with our ntdll mapped (native ELF, Linux ELF,
        // bare ring-3 test stub, kernel32-only PE). For all of those
        // the task-kill below is the CORRECT, by-design outcome — it
        // is not an anomaly, so a WARN here just floods the log on a
        // legitimate path (it fired repeatedly for the deliberate
        // ring-3 fault-injection probes, which intentionally carry no
        // ntdll). The real notification is the `return false` →
        // caller task-kill. A genuine "PE app has ntdll but the
        // dispatcher export is missing" is a loader/build defect that
        // the seh_pe / seh_try_pe self-tests catch loudly; we don't
        // rely on this per-fault line for it. (The re-fault-loop
        // guard below stays WARN — that one IS an anomaly.)
        KLOG_DEBUG("win32/seh", "no ntdll!KiUserExceptionDispatcher — non-Win32 process, task-kill (expected)");
        return false;
    }

    // Recursion guard: if the SAME instruction keeps faulting into
    // the dispatcher, the unhandled-exception path is wedged. Bail
    // to task-kill so an unhandled fault terminates instead of
    // looping forever in ntdll.
    if (!sched::SchedSehDeliveryAllowed(sched::CurrentTask(), frame->rip))
    {
        KLOG_WARN_V("win32/seh", "delivery guard tripped (re-fault loop) rip", frame->rip);
        return false;
    }

    // Build the CONTEXT capturing the faulting register state.
    duetos::win32::Context ctx;
    ZeroBytes(&ctx, sizeof(ctx));
    ctx.ContextFlags = kContextFlagsAll;
    ctx.MxCsr = 0x1F80;
    // Seed a valid FXSAVE image in FltSave. RtlRestoreContext does
    // an unconditional `fxrstor` of this area on resume; a zeroed
    // image would load FCW=0 / MXCSR=0 (all x87 + SSE exceptions
    // unmasked), so a resumed thread doing FP work could take a
    // spurious #MF/#XF. Default control words: FCW=0x037F,
    // MXCSR=0x1F80, MXCSR_MASK=0xFFFF. FXSAVE layout: [0..1]=FCW,
    // [24..27]=MXCSR, [28..31]=MXCSR_MASK.
    ctx.FltSave[0] = 0x7F;
    ctx.FltSave[1] = 0x03;
    ctx.FltSave[24] = 0x80;
    ctx.FltSave[25] = 0x1F;
    ctx.FltSave[28] = 0xFF;
    ctx.FltSave[29] = 0xFF;
    ctx.Rax = frame->rax;
    ctx.Rcx = frame->rcx;
    ctx.Rdx = frame->rdx;
    ctx.Rbx = frame->rbx;
    ctx.Rsp = frame->rsp;
    ctx.Rbp = frame->rbp;
    ctx.Rsi = frame->rsi;
    ctx.Rdi = frame->rdi;
    ctx.R8 = frame->r8;
    ctx.R9 = frame->r9;
    ctx.R10 = frame->r10;
    ctx.R11 = frame->r11;
    ctx.R12 = frame->r12;
    ctx.R13 = frame->r13;
    ctx.R14 = frame->r14;
    ctx.R15 = frame->r15;
    ctx.Rip = frame->rip;
    ctx.EFlags = static_cast<u32>(frame->rflags);
    ctx.SegCs = static_cast<u16>(frame->cs);
    ctx.SegSs = static_cast<u16>(frame->ss);

    // Build the EXCEPTION_RECORD.
    ExceptionRecord rec;
    ZeroBytes(&rec, sizeof(rec));
    rec.ExceptionCode = ntstatus;
    rec.ExceptionFlags = 0;
    rec.ExceptionRecordPtr = 0;
    rec.ExceptionAddress = frame->rip;
    if (is_pf)
    {
        // Windows AV record: [0] = access type (0 read, 1 write,
        // 8 execute), [1] = faulting VA.
        rec.NumberParameters = 2;
        rec.ExceptionInformation[0] = pf_write ? 1u : 0u;
        rec.ExceptionInformation[1] = fault_va;
    }
    else if (ntstatus == kStatusStackBufferOverrun)
    {
        // __fastfail: Windows reports the reason code as the single
        // ExceptionInformation element. The caller passes it in
        // `fault_va` — the generic "extra word" slot for the
        // non-#PF codes, unused by every other status we deliver.
        // A debugger or an __except filter reads the reason from
        // here, not from our boot log.
        rec.NumberParameters = 1;
        rec.ExceptionInformation[0] = fault_va;
    }
    else
    {
        rec.NumberParameters = 0;
    }

    // Carve the records out of the faulting thread's own user
    // stack, below the current rsp (past the x64 red zone for
    // safety), 16-byte aligned. The final rsp is left ≡ 8 (mod 16)
    // so it mimics the post-CALL alignment the ring-3 entry path
    // already establishes — KiUserExceptionDispatcher's naked
    // trampoline re-aligns from there.
    const u64 region_top = AlignDown16(frame->rsp - 0x100);
    const u64 ctx_addr = AlignDown16(region_top - sizeof(duetos::win32::Context));
    const u64 rec_addr = AlignDown16(ctx_addr - sizeof(ExceptionRecord));
    const u64 new_rsp = rec_addr - 8;

    if (ctx_addr < 0x10000 || rec_addr < 0x10000 || new_rsp >= frame->rsp)
    {
        // Stack pointer was garbage / too low to host the records.
        KLOG_WARN_V("win32/seh", "user rsp too low for records — task-kill fallback rsp", frame->rsp);
        return false;
    }

    // Exception delivery can itself be the thing that needs a page:
    // the records land ~0x600 bytes below rsp, which on a
    // demand-grown stack may be past the committed edge. CopyToUser
    // pre-checks accessibility and returns false rather than
    // faulting, so nothing would grow the stack for us — commit the
    // range explicitly first. Returns false (leaving the range
    // uncommitted) when it is outside the reservation or the stack
    // is genuinely exhausted, in which case CopyToUser below fails
    // and we fall back to the task-kill path exactly as before.
    (void)core::UserStackCommitRange(new_rsp, region_top);

    if (!mm::CopyToUser(reinterpret_cast<void*>(ctx_addr), &ctx, sizeof(ctx)))
    {
        KLOG_WARN_V("win32/seh", "CopyToUser(CONTEXT) failed — task-kill fallback addr", ctx_addr);
        return false;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(rec_addr), &rec, sizeof(rec)))
    {
        KLOG_WARN_V("win32/seh", "CopyToUser(EXCEPTION_RECORD) failed — task-kill fallback addr", rec_addr);
        return false;
    }

    KLOG_DEBUG_V("win32/seh", "deliver exception code", ntstatus);
    KLOG_DEBUG_V("win32/seh", "  faulting rip", frame->rip);
    if (is_pf)
    {
        // Faulting VA + access kind localise the bad pointer that a
        // ring-3 PE dereferenced. (access: 0=read 1=write 8=exec)
        KLOG_DEBUG_V("win32/seh", "  faulting va", fault_va);
        KLOG_DEBUG_V("win32/seh", "  access (0=r 1=w 8=x)", pf_write ? 1u : 0u);
    }
    KLOG_DEBUG_V("win32/seh", "  resume at KiUserExceptionDispatcher", kidisp);

    // Rewrite the trap frame: resume in user mode at the dispatcher
    // with rcx = EXCEPTION_RECORD, rdx = CONTEXT. Keep cs/ss/rflags
    // (still ring-3); clear TF so we don't take an immediate #DB in
    // the dispatcher, and force IF on so the resumed thread can be
    // pre-empted.
    frame->rip = kidisp;
    frame->rsp = new_rsp;
    frame->rcx = rec_addr;
    frame->rdx = ctx_addr;
    frame->rflags = (frame->rflags & ~static_cast<u64>(1ULL << 8)) | (1ULL << 9);
    return true;
}

} // namespace duetos::subsystems::win32
