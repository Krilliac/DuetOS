/*
 * jobobj_smoke - verdict-bearing Job-object ABI and lifecycle coverage.
 *
 * Exercises the real kernel32 -> ntdll -> SYS_JOB_* path, including
 * ProcessBasicInformation-backed process exit queries, pseudo-current-
 * process assignment, partial variable-length query layouts, permanent
 * membership after last-handle close, empty-Job termination, and stale
 * generation rejection through CloseHandle.
 */
#include <windows.h>

typedef char job_basic_accounting_must_be_48_bytes[(sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) == 48) ? 1 : -1];
typedef char job_basic_and_io_must_be_96_bytes[(sizeof(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION) == 96) ? 1 : -1];

typedef struct
{
    DWORD NumberOfAssignedProcesses;
    DWORD NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[32];
} DUETOS_JOB_PROCESS_ID_LIST;

typedef struct
{
    DWORD NumberOfAssignedProcesses;
    DWORD NumberOfProcessIdsInList;
} DUETOS_JOB_PROCESS_ID_HEADER;

/* This fixture is linked with -nostdlib. GCC lowers the two large aggregate
 * zero initializers below to memset even at the smoke build's default
 * optimization level, so keep the freestanding implementation local. */
void* memset(void* dst, int value, unsigned long long size)
{
    unsigned char* bytes = (unsigned char*)dst;
    for (unsigned long long index = 0; index < size; ++index)
        bytes[index] = (unsigned char)value;
    return dst;
}

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteFile(h, s, len, &n, 0);
}

static void Fail(const char* stage)
{
    Out("[jobobj_smoke] FAIL: ");
    Out(stage);
    Out("\r\n");
    ExitProcess(1);
}

static void Check(BOOL condition, const char* stage)
{
    if (!condition)
        Fail(stage);
}

void __cdecl mainCRTStartup(void)
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};
    JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION accounting_and_io = {0};
    DUETOS_JOB_PROCESS_ID_LIST process_ids = {0};
    DWORD return_length = 0;
    DWORD exit_code = 0;
    BOOL in_job = TRUE;
    HANDLE self = GetCurrentProcess();

    Out("[jobobj_smoke] starting\r\n");

    Check(GetExitCodeProcess(self, &exit_code) && exit_code == STILL_ACTIVE,
          "GetExitCodeProcess self not STILL_ACTIVE");

    SetLastError(0);
    Check(!GetExitCodeProcess(self, NULL), "GetExitCodeProcess accepted null output");
    Check(GetLastError() == ERROR_INVALID_PARAMETER, "GetExitCodeProcess null-output LastError");

    exit_code = 0xA5A5A5A5UL;
    SetLastError(0);
    Check(!GetExitCodeProcess((HANDLE)(ULONG_PTR)0x700UL, &exit_code),
          "GetExitCodeProcess accepted slot-only Process handle");
    Check(GetLastError() == ERROR_INVALID_HANDLE, "GetExitCodeProcess bad-handle LastError");
    Check(exit_code == 0xA5A5A5A5UL, "GetExitCodeProcess bad handle mutated output");

    HANDLE job = CreateJobObjectW(NULL, NULL);
    Check(job != NULL, "CreateJobObjectW");

    Check(IsProcessInJob(self, job, &in_job) && !in_job, "specific membership before assign");

    Check(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting),
                                    &return_length),
          "empty basic accounting query");
    Check(return_length == sizeof(accounting), "basic accounting return length");
    Check(accounting.TotalProcesses == 0 && accounting.ActiveProcesses == 0, "empty basic accounting counters");

    return_length = 0xA5A5A5A5UL;
    SetLastError(0);
    Check(!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting) - 1,
                                     &return_length),
          "short accounting query accepted");
    Check(GetLastError() == ERROR_BAD_LENGTH, "short accounting LastError");
    Check(return_length == 0xA5A5A5A5UL, "short accounting ReturnLength mutated");

    Check(AssignProcessToJobObject(job, self), "AssignProcessToJobObject self");

    in_job = FALSE;
    Check(IsProcessInJob(self, job, &in_job) && in_job, "specific membership after assign");
    in_job = FALSE;
    Check(IsProcessInJob(self, NULL, &in_job) && in_job, "any-Job membership after assign");

    return_length = 0;
    Check(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting),
                                    &return_length),
          "assigned basic accounting query");
    Check(return_length == sizeof(accounting), "assigned basic accounting length");
    Check(accounting.TotalProcesses == 1 && accounting.ActiveProcesses == 1, "assigned basic accounting counters");

    return_length = 0;
    Check(QueryInformationJobObject(job, JobObjectBasicAndIoAccountingInformation, &accounting_and_io,
                                    sizeof(accounting_and_io), &return_length),
          "basic and IO accounting query");
    Check(return_length == sizeof(accounting_and_io), "basic and IO accounting length");
    Check(accounting_and_io.BasicInfo.TotalProcesses == 1 && accounting_and_io.BasicInfo.ActiveProcesses == 1,
          "basic and IO accounting counters");

    return_length = 0;
    Check(
        QueryInformationJobObject(job, JobObjectBasicProcessIdList, &process_ids, sizeof(process_ids), &return_length),
        "process ID list query");
    Check(return_length == 8 + sizeof(ULONG_PTR), "process ID list length");
    Check(process_ids.NumberOfAssignedProcesses == 1 && process_ids.NumberOfProcessIdsInList == 1,
          "process ID list counters");
    Check(process_ids.ProcessIdList[0] == (ULONG_PTR)GetCurrentProcessId(), "process ID list PID");

    DUETOS_JOB_PROCESS_ID_HEADER process_id_header = {0xA5A5A5A5UL, 0xA5A5A5A5UL};
    return_length = 0;
    Check(QueryInformationJobObject(job, JobObjectBasicProcessIdList, &process_id_header, sizeof(process_id_header),
                                    &return_length),
          "header-only process ID list query");
    Check(return_length == sizeof(process_id_header), "header-only process ID list length");
    Check(process_id_header.NumberOfAssignedProcesses == 1 && process_id_header.NumberOfProcessIdsInList == 0,
          "header-only process ID list truncation counters");

    Check(CloseHandle(job), "first Job close");

    in_job = FALSE;
    Check(IsProcessInJob(self, NULL, &in_job) && in_job, "last Job close severed live membership");

    SetLastError(0);
    Check(!CloseHandle(job), "stale Job double-close accepted");
    Check(GetLastError() == ERROR_INVALID_HANDLE, "stale Job close LastError");

    SetLastError(0);
    Check(!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting),
                                     &return_length),
          "stale Job query accepted");
    Check(GetLastError() == ERROR_INVALID_HANDLE, "stale Job query LastError");

    SetLastError(0);
    Check(!TerminateJobObject(job, 0x4A4F42UL), "stale Job termination accepted");
    Check(GetLastError() == ERROR_INVALID_HANDLE, "stale Job terminate LastError");

    SetLastError(0);
    Check(!CloseHandle((HANDLE)(ULONG_PTR)0xC00UL), "slot-only legacy Job handle accepted");
    Check(GetLastError() == ERROR_INVALID_HANDLE, "slot-only Job close LastError");

    HANDLE empty_job = CreateJobObjectW(NULL, NULL);
    Check(empty_job != NULL, "empty Job create");
    Check(TerminateJobObject(empty_job, 0x4A4F42UL), "empty Job termination");
    Check(CloseHandle(empty_job), "terminated empty Job close");

    Out("[jobobj_smoke] done\r\n");
    Out("[ring3-jobobj-smoke] PASS\r\n");
    ExitProcess(0);
}
