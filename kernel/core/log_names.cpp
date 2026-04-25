#include "log_names.h"

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

} // namespace duetos::core
