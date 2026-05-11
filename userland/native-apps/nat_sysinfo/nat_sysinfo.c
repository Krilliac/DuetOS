/*
 * DuetOS — portable system-info CLI, v0.
 *
 * Reads the kernel's system-state via three real syscalls and
 * prints a uname / free / date style report. NO widget framework
 * — pure stdout. The companion in-kernel GUI sysmon
 * (`kernel/apps/sysmon.cpp`) renders the same data in a window
 * via the widget framework; this is the portable CLI peer.
 *
 * Syscalls exercised:
 *   - SYS_SYSTEM_INFO (49)  → Win32 SYSTEM_INFO (48 bytes)
 *   - SYS_MEM_STATUS  (47)  → Win32 MEMORYSTATUSEX (64 bytes)
 *   - SYS_GETTIME_ST  (40)  → Win32 SYSTEMTIME (16 bytes)
 *
 * Once `libduet-widget` lands and existing kernel apps migrate
 * out, this app is the template the in-kernel sysmon's CLI
 * mode collapses into. See `wiki/tooling/Native-Apps.md` for
 * the broader migration plan.
 */

#include "duet/syscall.h"
#include "stdio.h"
#include "string.h"
#include "unistd.h"

#include <stdint.h>

#define SYS_SYSTEM_INFO 49
#define SYS_MEM_STATUS 47
#define SYS_GETTIME_ST 40

/* Win32 SYSTEM_INFO (48 bytes). */
typedef struct
{
    uint16_t processor_architecture;
    uint16_t reserved;
    uint32_t page_size;
    uint64_t min_app_address;
    uint64_t max_app_address;
    uint64_t active_processor_mask;
    uint32_t number_of_processors;
    uint32_t processor_type;
    uint32_t allocation_granularity;
    uint16_t processor_level;
    uint16_t processor_revision;
} SystemInfo;

/* Win32 MEMORYSTATUSEX (64 bytes). */
typedef struct
{
    uint32_t length;
    uint32_t memory_load;
    uint64_t total_phys;
    uint64_t avail_phys;
    uint64_t total_page_file;
    uint64_t avail_page_file;
    uint64_t total_virtual;
    uint64_t avail_virtual;
    uint64_t avail_extended_virtual;
} MemoryStatus;

/* Win32 SYSTEMTIME (16 bytes). */
typedef struct
{
    uint16_t year;
    uint16_t month;
    uint16_t day_of_week;
    uint16_t day;
    uint16_t hour;
    uint16_t minute;
    uint16_t second;
    uint16_t milliseconds;
} SystemTime;

static long syscall1(long num, long a)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(num), "D"(a) : "memory", "rcx", "r11");
    return rv;
}

static const char* arch_name(uint16_t code)
{
    /* PROCESSOR_ARCHITECTURE_AMD64 = 9. The Win32 kernel
     * subsystem returns 9 unconditionally on x86_64 today. */
    switch (code)
    {
    case 0:
        return "x86";
    case 5:
        return "arm";
    case 9:
        return "x86_64";
    case 12:
        return "arm64";
    default:
        return "unknown";
    }
}

static void print_arch(void)
{
    SystemInfo si;
    memset(&si, 0, sizeof(si));
    const long rc = syscall1(SYS_SYSTEM_INFO, (long)&si);
    if (rc < 0)
    {
        println("[nat-sysinfo] uname: SYS_SYSTEM_INFO failed");
        return;
    }
    print_fmt("[nat-sysinfo] uname  arch=%s cpus=%u page_size=%u alloc_gran=%u\n", arch_name(si.processor_architecture),
              (unsigned)si.number_of_processors, (unsigned)si.page_size, (unsigned)si.allocation_granularity);
    print_fmt("[nat-sysinfo] uname  proc_level=%u proc_rev=0x%x mask=0x%lx\n", (unsigned)si.processor_level,
              (unsigned)si.processor_revision, (unsigned long)si.active_processor_mask);
}

static void print_memory(void)
{
    MemoryStatus ms;
    memset(&ms, 0, sizeof(ms));
    ms.length = sizeof(ms);
    const long rc = syscall1(SYS_MEM_STATUS, (long)&ms);
    if (rc < 0)
    {
        println("[nat-sysinfo] mem: SYS_MEM_STATUS failed");
        return;
    }
    print_fmt("[nat-sysinfo] mem    load=%u%% phys_total=%lu phys_avail=%lu\n", (unsigned)ms.memory_load,
              (unsigned long)ms.total_phys, (unsigned long)ms.avail_phys);
    print_fmt("[nat-sysinfo] mem    virt_total=%lu virt_avail=%lu\n", (unsigned long)ms.total_virtual,
              (unsigned long)ms.avail_virtual);
}

static void print_clock(void)
{
    SystemTime st;
    memset(&st, 0, sizeof(st));
    const long rc = syscall1(SYS_GETTIME_ST, (long)&st);
    if (rc < 0)
    {
        println("[nat-sysinfo] time: SYS_GETTIME_ST failed");
        return;
    }
    /* ISO 8601 ish — manual format so we don't need printf
     * width specifiers (the v0 print_fmt subset doesn't cover
     * zero-padded widths). */
    print_fmt("[nat-sysinfo] time   %u-", (unsigned)st.year);
    if (st.month < 10)
        puts_char('0');
    print_int(st.month);
    puts_char('-');
    if (st.day < 10)
        puts_char('0');
    print_int(st.day);
    puts_char('T');
    if (st.hour < 10)
        puts_char('0');
    print_int(st.hour);
    puts_char(':');
    if (st.minute < 10)
        puts_char('0');
    print_int(st.minute);
    puts_char(':');
    if (st.second < 10)
        puts_char('0');
    print_int(st.second);
    puts_str("Z\n");
}

int main(void)
{
    println("[nat-sysinfo] portable native system-info report");
    print_arch();
    print_memory();
    print_clock();
    println("[nat-sysinfo] report complete");
    return 0x5159; /* 'SIN' — sentinel for the smoke harness */
}
