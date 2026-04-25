/*
 * DuetOS — log-name lookup tables: implementation.
 *
 * Companion to log_names.h — see there for the API.
 *
 * WHAT
 *   Translates kernel-internal numeric IDs (syscall numbers,
 *   capability bits, exception vectors, fault-domain tags) into
 *   human-readable strings for the boot log, panic dump, and
 *   shell `inspect` commands.
 *
 * HOW
 *   One `static constexpr` lookup table per ID space, paired
 *   with a `*ToName(id)` accessor. Tables are kept in numeric
 *   order so a binary search compiles into a tight jump (most
 *   are small enough that linear scan is faster).
 *
 * WHY THIS FILE IS LARGE
 *   The tables are the file. Adding a SYS_* / cap / vector
 *   means appending a row here. The size is a direct readout
 *   of "how much of the kernel has names."
 */

#include "log_names.h"

#include "../arch/x86_64/serial.h"
#include "process.h"

namespace duetos::core
{

const char* SyscallName(u64 num)
{
    // Mirrors kernel/core/syscall.h SYS_*. Keep in sync when new
    // syscalls land — the linker doesn't enforce coverage so a
    // missing entry just shows up as "?" in the trace dump.
    switch (num)
    {
    case 0:
        return "SYS_EXIT";
    case 1:
        return "SYS_GETPID";
    case 2:
        return "SYS_WRITE";
    case 3:
        return "SYS_YIELD";
    case 4:
        return "SYS_STAT";
    case 5:
        return "SYS_READ";
    case 6:
        return "SYS_DROPCAPS";
    case 7:
        return "SYS_SPAWN";
    case 8:
        return "SYS_GETPROCID";
    case 9:
        return "SYS_GETLASTERROR";
    case 10:
        return "SYS_SETLASTERROR";
    case 11:
        return "SYS_HEAP_ALLOC";
    case 12:
        return "SYS_HEAP_FREE";
    case 13:
        return "SYS_PERF_COUNTER";
    case 14:
        return "SYS_HEAP_SIZE";
    case 15:
        return "SYS_HEAP_REALLOC";
    case 17:
        return "SYS_GETTIME_FT";
    case 18:
        return "SYS_NOW_NS";
    case 19:
        return "SYS_SLEEP_MS";
    case 20:
        return "SYS_FILE_OPEN";
    case 21:
        return "SYS_FILE_READ";
    case 22:
        return "SYS_FILE_CLOSE";
    case 23:
        return "SYS_FILE_SEEK";
    case 24:
        return "SYS_FILE_FSTAT";
    case 25:
        return "SYS_MUTEX_CREATE";
    case 26:
        return "SYS_MUTEX_WAIT";
    case 27:
        return "SYS_MUTEX_RELEASE";
    case 28:
        return "SYS_VMAP";
    case 29:
        return "SYS_VUNMAP";
    case 30:
        return "SYS_EVENT_CREATE";
    case 31:
        return "SYS_EVENT_SET";
    case 32:
        return "SYS_EVENT_RESET";
    case 33:
        return "SYS_EVENT_WAIT";
    case 34:
        return "SYS_TLS_ALLOC";
    case 35:
        return "SYS_TLS_FREE";
    case 36:
        return "SYS_TLS_GET";
    case 37:
        return "SYS_TLS_SET";
    case 38:
        return "SYS_BP_INSTALL";
    case 39:
        return "SYS_BP_REMOVE";
    case 40:
        return "SYS_GETTIME_ST";
    case 41:
        return "SYS_ST_TO_FT";
    case 42:
        return "SYS_FT_TO_ST";
    case 43:
        return "SYS_FILE_WRITE";
    case 44:
        return "SYS_FILE_CREATE";
    case 45:
        return "SYS_THREAD_CREATE";
    case 46:
        return "SYS_DEBUG_PRINT";
    case 47:
        return "SYS_MEM_STATUS";
    case 48:
        return "SYS_WAIT_MULTI";
    case 49:
        return "SYS_SYSTEM_INFO";
    case 50:
        return "SYS_DEBUG_PRINTW";
    case 51:
        return "SYS_SEM_CREATE";
    case 52:
        return "SYS_SEM_RELEASE";
    case 53:
        return "SYS_SEM_WAIT";
    case 54:
        return "SYS_THREAD_WAIT";
    case 55:
        return "SYS_THREAD_EXIT_CODE";
    case 56:
        return "SYS_NT_INVOKE";
    case 57:
        return "SYS_DLL_PROC_ADDRESS";
    case 58:
        return "SYS_WIN_CREATE";
    case 59:
        return "SYS_WIN_DESTROY";
    case 60:
        return "SYS_WIN_SHOW";
    case 61:
        return "SYS_WIN_MSGBOX";
    case 62:
        return "SYS_WIN_PEEK_MSG";
    case 63:
        return "SYS_WIN_GET_MSG";
    case 64:
        return "SYS_WIN_POST_MSG";
    case 65:
        return "SYS_GDI_FILL_RECT";
    case 66:
        return "SYS_GDI_TEXT_OUT";
    case 67:
        return "SYS_GDI_RECTANGLE";
    case 68:
        return "SYS_GDI_CLEAR";
    case 69:
        return "SYS_WIN_MOVE";
    case 70:
        return "SYS_WIN_GET_RECT";
    case 71:
        return "SYS_WIN_SET_TEXT";
    case 72:
        return "SYS_WIN_TIMER_SET";
    case 73:
        return "SYS_WIN_TIMER_KILL";
    case 74:
        return "SYS_GDI_LINE";
    case 75:
        return "SYS_GDI_ELLIPSE";
    case 76:
        return "SYS_GDI_SET_PIXEL";
    case 77:
        return "SYS_WIN_GET_KEYSTATE";
    case 78:
        return "SYS_WIN_GET_CURSOR";
    case 79:
        return "SYS_WIN_SET_CURSOR";
    case 80:
        return "SYS_WIN_SET_CAPTURE";
    case 81:
        return "SYS_WIN_RELEASE_CAPTURE";
    case 82:
        return "SYS_WIN_GET_CAPTURE";
    case 83:
        return "SYS_WIN_CLIP_SET_TEXT";
    case 84:
        return "SYS_WIN_CLIP_GET_TEXT";
    case 85:
        return "SYS_WIN_GET_LONG";
    case 86:
        return "SYS_WIN_SET_LONG";
    case 87:
        return "SYS_WIN_INVALIDATE";
    case 88:
        return "SYS_WIN_VALIDATE";
    case 89:
        return "SYS_WIN_GET_ACTIVE";
    case 90:
        return "SYS_WIN_SET_ACTIVE";
    case 91:
        return "SYS_WIN_GET_METRIC";
    case 92:
        return "SYS_WIN_ENUM";
    case 93:
        return "SYS_WIN_FIND";
    case 94:
        return "SYS_WIN_SET_PARENT";
    case 95:
        return "SYS_WIN_GET_PARENT";
    case 96:
        return "SYS_WIN_GET_RELATED";
    case 97:
        return "SYS_WIN_SET_FOCUS";
    case 98:
        return "SYS_WIN_GET_FOCUS";
    case 99:
        return "SYS_WIN_CARET";
    case 100:
        return "SYS_WIN_BEEP";
    case 102:
        return "SYS_GDI_BITBLT";
    case 103:
        return "SYS_WIN_BEGIN_PAINT";
    case 104:
        return "SYS_WIN_END_PAINT";
    case 105:
        return "SYS_GDI_FILL_RECT_USER";
    case 106:
        return "SYS_GDI_CREATE_COMPAT_DC";
    case 107:
        return "SYS_GDI_CREATE_COMPAT_BITMAP";
    case 108:
        return "SYS_GDI_CREATE_SOLID_BRUSH";
    case 109:
        return "SYS_GDI_GET_STOCK_OBJECT";
    case 110:
        return "SYS_GDI_SELECT_OBJECT";
    case 111:
        return "SYS_GDI_DELETE_DC";
    case 112:
        return "SYS_GDI_DELETE_OBJECT";
    case 113:
        return "SYS_GDI_BITBLT_DC";
    case 114:
        return "SYS_GDI_SET_TEXT_COLOR";
    case 115:
        return "SYS_GDI_SET_BK_COLOR";
    case 116:
        return "SYS_GDI_SET_BK_MODE";
    case 117:
        return "SYS_GDI_STRETCH_BLT_DC";
    case 118:
        return "SYS_GDI_CREATE_PEN";
    case 119:
        return "SYS_GDI_MOVE_TO_EX";
    case 120:
        return "SYS_GDI_LINE_TO";
    case 121:
        return "SYS_GDI_DRAW_TEXT_USER";
    case 122:
        return "SYS_GDI_RECTANGLE_FILLED";
    case 123:
        return "SYS_GDI_ELLIPSE_FILLED";
    case 124:
        return "SYS_GDI_PAT_BLT";
    case 125:
        return "SYS_GDI_TEXT_OUT_W";
    case 126:
        return "SYS_GDI_DRAW_TEXT_W";
    case 127:
        return "SYS_GDI_GET_SYS_COLOR";
    case 128:
        return "SYS_GDI_GET_SYS_COLOR_BRUSH";
    default:
        return "?";
    }
}

const char* LinuxSyscallName(u64 nr)
{
    // Common subset of the Linux x86_64 syscall ABI. Only the
    // entries we have ever observed in a clean-room boot survey
    // (plus their close neighbours) are listed; "?" for anything
    // else keeps the trace honest.
    switch (nr)
    {
    case 0:
        return "read";
    case 1:
        return "write";
    case 2:
        return "open";
    case 3:
        return "close";
    case 4:
        return "stat";
    case 5:
        return "fstat";
    case 8:
        return "lseek";
    case 9:
        return "mmap";
    case 10:
        return "mprotect";
    case 11:
        return "munmap";
    case 12:
        return "brk";
    case 13:
        return "rt_sigaction";
    case 14:
        return "rt_sigprocmask";
    case 16:
        return "ioctl";
    case 21:
        return "access";
    case 28:
        return "madvise";
    case 39:
        return "getpid";
    case 56:
        return "clone";
    case 57:
        return "fork";
    case 58:
        return "vfork";
    case 59:
        return "execve";
    case 60:
        return "exit";
    case 63:
        return "uname";
    case 72:
        return "fcntl";
    case 79:
        return "getcwd";
    case 89:
        return "readlink";
    case 90:
        return "chmod";
    case 96:
        return "gettimeofday";
    case 158:
        return "arch_prctl";
    case 186:
        return "gettid";
    case 202:
        return "futex";
    case 218:
        return "set_tid_address";
    case 228:
        return "clock_gettime";
    case 231:
        return "exit_group";
    case 257:
        return "openat";
    case 273:
        return "set_robust_list";
    case 302:
        return "prlimit64";
    case 318:
        return "getrandom";
    case 322:
        return "execveat";
    case 334:
        return "rseq";
    default:
        return "?";
    }
}

const char* WifiSecurityName(u64 sec)
{
    switch (sec)
    {
    case 0:
        return "OPEN";
    case 1:
        return "WPA2-PSK";
    default:
        return "?";
    }
}

const char* FwSourcePolicyName(u64 policy)
{
    switch (policy)
    {
    case 0:
        return "open-then-vendor";
    case 1:
        return "open-only";
    case 2:
        return "vendor-only";
    default:
        return "?";
    }
}

const char* PciVendorName(u64 vid)
{
    // Common PCIe vendor IDs we expect to see on commodity PC
    // hardware + the QEMU emulated devices we boot under in CI.
    // Fed by https://pcisig.com/membership/member-companies and
    // QEMU's own device files.
    switch (vid)
    {
    case 0x1022:
        return "AMD";
    case 0x10de:
        return "NVIDIA";
    case 0x10ec:
        return "Realtek";
    case 0x1234:
        return "QEMU-Bochs";
    case 0x14e4:
        return "Broadcom";
    case 0x1814:
        return "Ralink";
    case 0x1969:
        return "Atheros/Qualcomm";
    case 0x1af4:
        return "Red Hat (virtio)";
    case 0x1b36:
        return "Red Hat (qemu)";
    case 0x8086:
        return "Intel";
    case 0x9710:
        return "MosChip";
    default:
        return "?";
    }
}

const char* PeMachineName(u64 machine)
{
    // Subset of IMAGE_FILE_MACHINE_* the PE loader can plausibly
    // see. Values from MS-PECOFF spec Section 3.3.1.
    switch (machine)
    {
    case 0x0000:
        return "Unknown";
    case 0x014c:
        return "x86";
    case 0x0200:
        return "ItaniumIA64";
    case 0x8664:
        return "x86-64";
    case 0x01c0:
        return "ARM";
    case 0xaa64:
        return "ARM64";
    case 0x01c4:
        return "ARMNT";
    case 0x0ebc:
        return "EBC";
    case 0x5032:
        return "RISCV32";
    case 0x5064:
        return "RISCV64";
    default:
        return "?";
    }
}

const char* IdtVectorName(u64 vec)
{
    // Architectural exceptions (Intel SDM Vol. 3, Table 6-1)
    // and the small set of vectors DuetOS programs explicitly.
    switch (vec)
    {
    case 0x00:
        return "#DE divide-by-zero";
    case 0x01:
        return "#DB debug";
    case 0x02:
        return "NMI";
    case 0x03:
        return "#BP breakpoint";
    case 0x04:
        return "#OF overflow";
    case 0x05:
        return "#BR bound-range";
    case 0x06:
        return "#UD invalid-opcode";
    case 0x07:
        return "#NM device-not-available";
    case 0x08:
        return "#DF double-fault";
    case 0x0a:
        return "#TS invalid-tss";
    case 0x0b:
        return "#NP segment-not-present";
    case 0x0c:
        return "#SS stack-segment";
    case 0x0d:
        return "#GP general-protection";
    case 0x0e:
        return "#PF page-fault";
    case 0x10:
        return "#MF x87-fpu";
    case 0x11:
        return "#AC alignment-check";
    case 0x12:
        return "#MC machine-check";
    case 0x13:
        return "#XM simd-fpu";
    case 0x14:
        return "#VE virtualization";
    case 0x15:
        return "#CP control-protection";
    case 0x20:
        return "lapic-timer";
    case 0x21:
        return "ps2-keyboard";
    case 0x2c:
        return "ps2-mouse";
    case 0x80:
        return "syscall (int 0x80)";
    case 0xfd:
        return "lapic-error";
    case 0xfe:
        return "lapic-ipi";
    case 0xff:
        return "lapic-spurious";
    default:
        if (vec >= 0x21 && vec < 0x80)
            return "external-irq";
        return "?";
    }
}

void SerialWriteCapBits(u64 bits)
{
    if (bits == 0)
    {
        arch::SerialWrite("<none>");
        return;
    }
    bool first = true;
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        if ((bits & (1ULL << c)) == 0)
            continue;
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(CapName(static_cast<Cap>(c)));
        first = false;
    }
    // Anything outside the known bit range — log it raw so a
    // future cap that hasn't reached the lookup table yet is
    // still visible instead of silently dropped.
    const u64 known_mask = (1ULL << static_cast<u32>(kCapCount)) - 2; // bits [1..kCapCount)
    const u64 unknown = bits & ~known_mask;
    if (unknown != 0)
    {
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite("?bits=");
        arch::SerialWriteHex(unknown);
    }
}

const char* LinuxSignalName(u64 sig)
{
    switch (sig)
    {
    case 1:
        return "SIGHUP";
    case 2:
        return "SIGINT";
    case 3:
        return "SIGQUIT";
    case 4:
        return "SIGILL";
    case 5:
        return "SIGTRAP";
    case 6:
        return "SIGABRT";
    case 7:
        return "SIGBUS";
    case 8:
        return "SIGFPE";
    case 9:
        return "SIGKILL";
    case 10:
        return "SIGUSR1";
    case 11:
        return "SIGSEGV";
    case 12:
        return "SIGUSR2";
    case 13:
        return "SIGPIPE";
    case 14:
        return "SIGALRM";
    case 15:
        return "SIGTERM";
    case 16:
        return "SIGSTKFLT";
    case 17:
        return "SIGCHLD";
    case 18:
        return "SIGCONT";
    case 19:
        return "SIGSTOP";
    case 20:
        return "SIGTSTP";
    case 21:
        return "SIGTTIN";
    case 22:
        return "SIGTTOU";
    case 23:
        return "SIGURG";
    case 24:
        return "SIGXCPU";
    case 25:
        return "SIGXFSZ";
    case 26:
        return "SIGVTALRM";
    case 27:
        return "SIGPROF";
    case 28:
        return "SIGWINCH";
    case 29:
        return "SIGIO";
    case 30:
        return "SIGPWR";
    case 31:
        return "SIGSYS";
    case 32:
        return "SIGRTMIN";
    case 64:
        return "SIGRTMAX";
    }
    if (sig >= 33 && sig <= 63)
    {
        return "SIGRT";
    }
    return "?";
}

const char* LinuxErrnoName(u64 e)
{
    switch (e)
    {
    case 1:
        return "EPERM";
    case 2:
        return "ENOENT";
    case 3:
        return "ESRCH";
    case 4:
        return "EINTR";
    case 5:
        return "EIO";
    case 6:
        return "ENXIO";
    case 7:
        return "E2BIG";
    case 8:
        return "ENOEXEC";
    case 9:
        return "EBADF";
    case 10:
        return "ECHILD";
    case 11:
        return "EAGAIN";
    case 12:
        return "ENOMEM";
    case 13:
        return "EACCES";
    case 14:
        return "EFAULT";
    case 15:
        return "ENOTBLK";
    case 16:
        return "EBUSY";
    case 17:
        return "EEXIST";
    case 18:
        return "EXDEV";
    case 19:
        return "ENODEV";
    case 20:
        return "ENOTDIR";
    case 21:
        return "EISDIR";
    case 22:
        return "EINVAL";
    case 23:
        return "ENFILE";
    case 24:
        return "EMFILE";
    case 25:
        return "ENOTTY";
    case 26:
        return "ETXTBSY";
    case 27:
        return "EFBIG";
    case 28:
        return "ENOSPC";
    case 29:
        return "ESPIPE";
    case 30:
        return "EROFS";
    case 31:
        return "EMLINK";
    case 32:
        return "EPIPE";
    case 33:
        return "EDOM";
    case 34:
        return "ERANGE";
    case 35:
        return "EDEADLK";
    case 36:
        return "ENAMETOOLONG";
    case 37:
        return "ENOLCK";
    case 38:
        return "ENOSYS";
    case 39:
        return "ENOTEMPTY";
    case 40:
        return "ELOOP";
    case 42:
        return "ENOMSG";
    case 75:
        return "EOVERFLOW";
    case 84:
        return "EILSEQ";
    case 88:
        return "ENOTSOCK";
    case 90:
        return "EMSGSIZE";
    case 95:
        return "EOPNOTSUPP";
    case 97:
        return "EAFNOSUPPORT";
    case 98:
        return "EADDRINUSE";
    case 99:
        return "EADDRNOTAVAIL";
    case 101:
        return "ENETUNREACH";
    case 103:
        return "ECONNABORTED";
    case 104:
        return "ECONNRESET";
    case 105:
        return "ENOBUFS";
    case 106:
        return "EISCONN";
    case 107:
        return "ENOTCONN";
    case 110:
        return "ETIMEDOUT";
    case 111:
        return "ECONNREFUSED";
    case 112:
        return "EHOSTDOWN";
    case 113:
        return "EHOSTUNREACH";
    case 114:
        return "EALREADY";
    case 115:
        return "EINPROGRESS";
    }
    return "?";
}

const char* NtStatusName(u64 status)
{
    // Curated subset — the codes the Win32 subsystem actually
    // returns, plus a handful of adjacent ones a debugger might
    // see while bisecting.
    switch (status)
    {
    case 0x00000000ULL:
        return "STATUS_SUCCESS";
    case 0x00000103ULL:
        return "STATUS_PENDING";
    case 0x40000000ULL:
        return "STATUS_OBJECT_NAME_EXISTS";
    case 0x80000005ULL:
        return "STATUS_BUFFER_OVERFLOW";
    case 0x80000006ULL:
        return "STATUS_NO_MORE_FILES";
    case 0xC0000001ULL:
        return "STATUS_UNSUCCESSFUL";
    case 0xC0000002ULL:
        return "STATUS_NOT_IMPLEMENTED";
    case 0xC0000005ULL:
        return "STATUS_ACCESS_VIOLATION";
    case 0xC0000008ULL:
        return "STATUS_INVALID_HANDLE";
    case 0xC000000DULL:
        return "STATUS_INVALID_PARAMETER";
    case 0xC000000EULL:
        return "STATUS_NO_SUCH_DEVICE";
    case 0xC000000FULL:
        return "STATUS_NO_SUCH_FILE";
    case 0xC0000010ULL:
        return "STATUS_INVALID_DEVICE_REQUEST";
    case 0xC0000011ULL:
        return "STATUS_END_OF_FILE";
    case 0xC0000017ULL:
        return "STATUS_NO_MEMORY";
    case 0xC0000022ULL:
        return "STATUS_ACCESS_DENIED";
    case 0xC0000023ULL:
        return "STATUS_BUFFER_TOO_SMALL";
    case 0xC0000024ULL:
        return "STATUS_OBJECT_TYPE_MISMATCH";
    case 0xC0000034ULL:
        return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035ULL:
        return "STATUS_OBJECT_NAME_COLLISION";
    case 0xC000003AULL:
        return "STATUS_OBJECT_PATH_NOT_FOUND";
    case 0xC0000043ULL:
        return "STATUS_SHARING_VIOLATION";
    case 0xC0000056ULL:
        return "STATUS_DELETE_PENDING";
    case 0xC000007FULL:
        return "STATUS_DISK_FULL";
    case 0xC00000B5ULL:
        return "STATUS_IO_TIMEOUT";
    case 0xC0000120ULL:
        return "STATUS_CANCELLED";
    case 0xC0000135ULL:
        return "STATUS_DLL_NOT_FOUND";
    case 0xC0000139ULL:
        return "STATUS_ENTRYPOINT_NOT_FOUND";
    }
    return "?";
}

void SerialWriteWin32AccessMask(u64 mask)
{
    arch::SerialWrite("[");
    bool first = true;
    auto emit = [&](const char* name)
    {
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(name);
        first = false;
    };
    if (mask & 0x80000000ULL)
        emit("GENERIC_READ");
    if (mask & 0x40000000ULL)
        emit("GENERIC_WRITE");
    if (mask & 0x20000000ULL)
        emit("GENERIC_EXECUTE");
    if (mask & 0x10000000ULL)
        emit("GENERIC_ALL");
    if (mask & 0x00100000ULL)
        emit("SYNCHRONIZE");
    if (mask & 0x00010000ULL)
        emit("DELETE");
    if (mask & 0x00020000ULL)
        emit("READ_CONTROL");
    if (mask & 0x00040000ULL)
        emit("WRITE_DAC");
    if (mask & 0x00080000ULL)
        emit("WRITE_OWNER");
    if (mask & 0x00000001ULL)
        emit("FILE_READ_DATA");
    if (mask & 0x00000002ULL)
        emit("FILE_WRITE_DATA");
    if (mask & 0x00000004ULL)
        emit("FILE_APPEND_DATA");
    if (mask & 0x00000008ULL)
        emit("FILE_READ_EA");
    if (mask & 0x00000010ULL)
        emit("FILE_WRITE_EA");
    if (mask & 0x00000020ULL)
        emit("FILE_EXECUTE");
    if (mask & 0x00000080ULL)
        emit("FILE_READ_ATTRIBUTES");
    if (mask & 0x00000100ULL)
        emit("FILE_WRITE_ATTRIBUTES");
    if (first)
        arch::SerialWrite("none");
    arch::SerialWrite("]");
}

void SerialWriteOpenFlags(u64 flags)
{
    arch::SerialWrite("[");
    bool first = true;
    // Access mode is the LOW two bits as a 2-bit field, not a
    // bitmask; emit it as a single token.
    switch (flags & 0x3)
    {
    case 0:
        arch::SerialWrite("O_RDONLY");
        first = false;
        break;
    case 1:
        arch::SerialWrite("O_WRONLY");
        first = false;
        break;
    case 2:
        arch::SerialWrite("O_RDWR");
        first = false;
        break;
    case 3:
        arch::SerialWrite("O_RDWR?");
        first = false;
        break;
    }
    auto emit = [&](u64 bit, const char* name)
    {
        if ((flags & bit) == 0)
            return;
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(name);
        first = false;
    };
    emit(0x40, "O_CREAT");
    emit(0x80, "O_EXCL");
    emit(0x100, "O_NOCTTY");
    emit(0x200, "O_TRUNC");
    emit(0x400, "O_APPEND");
    emit(0x800, "O_NONBLOCK");
    emit(0x1000, "O_DSYNC");
    emit(0x2000, "FASYNC");
    emit(0x4000, "O_DIRECT");
    emit(0x10000, "O_DIRECTORY");
    emit(0x20000, "O_NOFOLLOW");
    emit(0x40000, "O_NOATIME");
    emit(0x80000, "O_CLOEXEC");
    emit(0x100000, "O_SYNC");
    emit(0x200000, "O_PATH");
    emit(0x400000, "O_TMPFILE");
    arch::SerialWrite("]");
}

void SerialWriteMmapProt(u64 prot)
{
    arch::SerialWrite("[");
    if (prot == 0)
    {
        arch::SerialWrite("PROT_NONE]");
        return;
    }
    bool first = true;
    auto emit = [&](u64 bit, const char* name)
    {
        if ((prot & bit) == 0)
            return;
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(name);
        first = false;
    };
    emit(0x1, "R");
    emit(0x2, "W");
    emit(0x4, "X");
    arch::SerialWrite("]");
}

void SerialWriteMmapFlags(u64 flags)
{
    arch::SerialWrite("[");
    bool first = true;
    // Sharing mode is a 2-bit field at bits [1:0] (1 = SHARED,
    // 2 = PRIVATE, 3 = SHARED_VALIDATE).
    switch (flags & 0xF)
    {
    case 1:
        arch::SerialWrite("MAP_SHARED");
        first = false;
        break;
    case 2:
        arch::SerialWrite("MAP_PRIVATE");
        first = false;
        break;
    case 3:
        arch::SerialWrite("MAP_SHARED_VALIDATE");
        first = false;
        break;
    }
    auto emit = [&](u64 bit, const char* name)
    {
        if ((flags & bit) == 0)
            return;
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(name);
        first = false;
    };
    emit(0x10, "FIXED");
    emit(0x20, "ANONYMOUS");
    emit(0x100, "GROWSDOWN");
    emit(0x800, "DENYWRITE");
    emit(0x1000, "EXECUTABLE");
    emit(0x2000, "LOCKED");
    emit(0x4000, "NORESERVE");
    emit(0x8000, "POPULATE");
    emit(0x10000, "NONBLOCK");
    emit(0x20000, "STACK");
    emit(0x40000, "HUGETLB");
    if (first)
        arch::SerialWrite("none");
    arch::SerialWrite("]");
}

void SerialWriteInodeMode(u64 mode)
{
    arch::SerialWrite("[");
    // File-type bits live at S_IFMT (0xF000); emit a 3-letter
    // tag mirroring `ls -l`'s first column.
    const u64 type = mode & 0xF000;
    switch (type)
    {
    case 0x1000:
        arch::SerialWrite("FIFO ");
        break;
    case 0x2000:
        arch::SerialWrite("CHR  ");
        break;
    case 0x4000:
        arch::SerialWrite("DIR  ");
        break;
    case 0x6000:
        arch::SerialWrite("BLK  ");
        break;
    case 0x8000:
        arch::SerialWrite("REG  ");
        break;
    case 0xA000:
        arch::SerialWrite("LNK  ");
        break;
    case 0xC000:
        arch::SerialWrite("SOCK ");
        break;
    default:
        arch::SerialWrite("?    ");
        break;
    }
    // Permission bits in `rwxrwxrwx` form.
    auto bit = [&](u64 m, char c)
    {
        const char buf[2] = {c, 0};
        arch::SerialWrite((mode & m) ? buf : "-");
    };
    bit(0400, 'r');
    bit(0200, 'w');
    bit(0100, 'x');
    bit(0040, 'r');
    bit(0020, 'w');
    bit(0010, 'x');
    bit(0004, 'r');
    bit(0002, 'w');
    bit(0001, 'x');
    if (mode & 04000)
        arch::SerialWrite(" suid");
    if (mode & 02000)
        arch::SerialWrite(" sgid");
    if (mode & 01000)
        arch::SerialWrite(" sticky");
    arch::SerialWrite("]");
}

void SerialWriteFatAttr(u64 attr)
{
    // Long-File-Name escape value — 0x0F (RO|H|S|V) — surfaces
    // as a single token rather than being unpacked into its
    // four-flag form.
    if ((attr & 0x3F) == 0x0F)
    {
        arch::SerialWrite("[LFN]");
        return;
    }
    arch::SerialWrite("[");
    bool first = true;
    auto emit = [&](u64 bit, char c)
    {
        if ((attr & bit) == 0)
            return;
        if (!first)
            arch::SerialWrite("|");
        const char buf[2] = {c, 0};
        arch::SerialWrite(buf);
        first = false;
    };
    emit(0x01, 'R'); // read-only
    emit(0x02, 'H'); // hidden
    emit(0x04, 'S'); // system
    emit(0x08, 'V'); // volume id
    emit(0x10, 'D'); // directory
    emit(0x20, 'A'); // archive
    if (first)
        arch::SerialWrite("none");
    arch::SerialWrite("]");
}

} // namespace duetos::core
