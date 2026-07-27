/*
 * thread3_smoke — extended thread-control APIs.
 *
 *   Suspend/Get/Set/Resume context on a live local thread handle
 *   SYS_THREAD_OPEN foreign-handle exit, close, and slot-reuse isolation
 *   OpenThread (on self TID)
 *   GetThreadDescription / SetThreadDescription (Win10+)
 *   GetThreadIOPendingFlag
 *   GetThreadInformation (skipped)
 *   ResumeThread on a brand-new suspended thread
 *   Exited-thread context quiescence under slot/context churn
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

typedef struct QuiescenceCanary
{
    volatile DWORD before;
    volatile DWORD heartbeat;
    volatile DWORD stop;
    volatile DWORD returned;
    volatile DWORD after;
} QuiescenceCanary;

#define QUIESCENCE_CANARY_BEFORE 0x71DCA11Du
#define QUIESCENCE_CANARY_AFTER 0xC07E57EDu
#define QUIESCENCE_RETURNED 0x51A7E0FFu
#define QUIESCENCE_CHURN_THREADS 12u
#define DUET_STATUS_SUCCESS 0x00000000u
#define DUET_STATUS_INVALID_HANDLE 0xC0000008u
#define DUET_STATUS_INVALID_PARAMETER 0xC000000Du
#define DUET_CONTEXT_AMD64_INTEGER 0x00100002u

/*
 * First 0x100 bytes of AMD64 CONTEXT. The kernel context syscalls
 * intentionally copy exactly this integer/control prefix; the vector
 * tail is irrelevant to this INTEGER-only round trip.
 */
typedef struct __attribute__((aligned(16))) MinimalAmd64Context
{
    unsigned long long P1Home;
    unsigned long long P2Home;
    unsigned long long P3Home;
    unsigned long long P4Home;
    unsigned long long P5Home;
    unsigned long long P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    unsigned short SegCs;
    unsigned short SegDs;
    unsigned short SegEs;
    unsigned short SegFs;
    unsigned short SegGs;
    unsigned short SegSs;
    DWORD EFlags;
    unsigned long long Dr0;
    unsigned long long Dr1;
    unsigned long long Dr2;
    unsigned long long Dr3;
    unsigned long long Dr6;
    unsigned long long Dr7;
    unsigned long long Rax;
    unsigned long long Rcx;
    unsigned long long Rdx;
    unsigned long long Rbx;
    unsigned long long Rsp;
    unsigned long long Rbp;
    unsigned long long Rsi;
    unsigned long long Rdi;
    unsigned long long R8;
    unsigned long long R9;
    unsigned long long R10;
    unsigned long long R11;
    unsigned long long R12;
    unsigned long long R13;
    unsigned long long R14;
    unsigned long long R15;
    unsigned long long Rip;
} MinimalAmd64Context;

typedef char MinimalAmd64ContextMustBe0x100[(sizeof(MinimalAmd64Context) == 0x100) ? 1 : -1];

typedef struct __attribute__((aligned(16))) ContextProbe
{
    MinimalAmd64Context context;
    DWORD canary0;
    DWORD canary1;
    DWORD canary2;
    DWORD canary3;
} ContextProbe;

typedef struct ForeignThreadProbe
{
    volatile DWORD before;
    volatile DWORD tid;
    volatile DWORD heartbeat;
    volatile DWORD stop;
    volatile DWORD returned;
    volatile DWORD after;
} ForeignThreadProbe;

#define CONTEXT_CANARY0 0xA17ECA11u
#define CONTEXT_CANARY1 0xB26FB22Du
#define CONTEXT_CANARY2 0xC370C33Eu
#define CONTEXT_CANARY3 0xD481D44Fu
#define FOREIGN_CANARY_BEFORE 0xF04E19A1u
#define FOREIGN_CANARY_AFTER 0xF04E19A2u
#define FOREIGN_RETURNED 0xF04E19A3u

static QuiescenceCanary g_quiescence = {
    QUIESCENCE_CANARY_BEFORE, 0, 0, 0, QUIESCENCE_CANARY_AFTER,
};
static volatile DWORD g_churn_completed = 0;
static volatile DWORD g_context_heartbeat = 0;
static volatile DWORD g_context_stop = 0;
static ForeignThreadProbe g_foreign_a;
static ForeignThreadProbe g_foreign_b;

static void InitializeContextProbe(ContextProbe* probe)
{
    unsigned char* bytes = (unsigned char*)probe;
    for (unsigned long long i = 0; i < sizeof(*probe); ++i)
        bytes[i] = 0;
    probe->context.ContextFlags = DUET_CONTEXT_AMD64_INTEGER;
    probe->canary0 = CONTEXT_CANARY0;
    probe->canary1 = CONTEXT_CANARY1;
    probe->canary2 = CONTEXT_CANARY2;
    probe->canary3 = CONTEXT_CANARY3;
}

static BOOL ContextCanariesIntact(const ContextProbe* probe)
{
    return probe->canary0 == CONTEXT_CANARY0 && probe->canary1 == CONTEXT_CANARY1 &&
           probe->canary2 == CONTEXT_CANARY2 && probe->canary3 == CONTEXT_CANARY3;
}

static BOOL IntegerContextEqual(const MinimalAmd64Context* left, const MinimalAmd64Context* right)
{
    return left->Rax == right->Rax && left->Rcx == right->Rcx && left->Rdx == right->Rdx && left->Rbx == right->Rbx &&
           left->Rbp == right->Rbp && left->Rsi == right->Rsi && left->Rdi == right->Rdi && left->R8 == right->R8 &&
           left->R9 == right->R9 && left->R10 == right->R10 && left->R11 == right->R11 && left->R12 == right->R12 &&
           left->R13 == right->R13 && left->R14 == right->R14 && left->R15 == right->R15;
}

static DWORD LocalSuspendThread(HANDLE thread)
{
    long long result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"((long long)135), "D"((long long)thread) : "memory");
    return result < 0 ? (DWORD)-1 : (DWORD)result;
}

static HANDLE LocalOpenThread(DWORD tid)
{
    unsigned long long result;
    __asm__ volatile("int $0x80"
                     : "=a"(result)
                     : "a"((unsigned long long)139), "D"((unsigned long long)tid)
                     : "memory");
    return (HANDLE)result;
}

static DWORD LocalResumeThread(HANDLE thread)
{
    long long result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"((long long)136), "D"((long long)thread) : "memory");
    return result < 0 ? (DWORD)-1 : (DWORD)result;
}

static DWORD LocalGetThreadContext(HANDLE thread, MinimalAmd64Context* context)
{
    unsigned long long result;
    __asm__ volatile("int $0x80"
                     : "=a"(result)
                     : "a"((unsigned long long)137), "D"((unsigned long long)thread), "S"((unsigned long long)context),
                       "d"((unsigned long long)context->ContextFlags)
                     : "memory");
    return (DWORD)result;
}

static DWORD LocalSetThreadContext(HANDLE thread, const MinimalAmd64Context* context)
{
    unsigned long long result;
    __asm__ volatile("int $0x80"
                     : "=a"(result)
                     : "a"((unsigned long long)138), "D"((unsigned long long)thread), "S"((unsigned long long)context),
                       "d"((unsigned long long)context->ContextFlags)
                     : "memory");
    return (DWORD)result;
}

static DWORD WINAPI suspended_worker(LPVOID p)
{
    (void)p;
    Sleep(50);
    return 0;
}

static DWORD WINAPI quiescence_worker(LPVOID p)
{
    (void)p;
    while (g_quiescence.stop == 0)
    {
        ++g_quiescence.heartbeat;
        SwitchToThread();
    }
    g_quiescence.returned = QUIESCENCE_RETURNED;
    return 0x73;
}

static DWORD WINAPI churn_worker(LPVOID p)
{
    (void)p;
    ++g_churn_completed;
    SwitchToThread();
    return 0;
}

static DWORD WINAPI context_worker(LPVOID p)
{
    (void)p;
    while (g_context_stop == 0)
    {
        ++g_context_heartbeat;
        SwitchToThread();
    }
    return 0x63;
}

static void InitializeForeignProbe(ForeignThreadProbe* probe)
{
    probe->before = FOREIGN_CANARY_BEFORE;
    probe->tid = 0;
    probe->heartbeat = 0;
    probe->stop = 0;
    probe->returned = 0;
    probe->after = FOREIGN_CANARY_AFTER;
}

static BOOL ForeignCanariesIntact(const ForeignThreadProbe* probe)
{
    return probe->before == FOREIGN_CANARY_BEFORE && probe->after == FOREIGN_CANARY_AFTER;
}

static DWORD WINAPI foreign_worker(LPVOID p)
{
    ForeignThreadProbe* probe = (ForeignThreadProbe*)p;
    probe->tid = GetCurrentThreadId();
    while (probe->stop == 0)
    {
        ++probe->heartbeat;
        SwitchToThread();
    }
    probe->returned = FOREIGN_RETURNED;
    return 0x74;
}

static BOOL WaitForForeignReady(ForeignThreadProbe* probe)
{
    DWORD budget = 3000;
    while ((probe->tid == 0 || probe->heartbeat == 0) && budget-- != 0)
        Sleep(1);
    return probe->tid != 0 && probe->heartbeat != 0 && ForeignCanariesIntact(probe);
}

static BOOL TestForeignThreadHandleLifecycle(void)
{
    InitializeForeignProbe(&g_foreign_a);
    HANDLE local_a = CreateThread(NULL, 0, foreign_worker, &g_foreign_a, 0, NULL);
    if (local_a == NULL || !WaitForForeignReady(&g_foreign_a))
    {
        if (local_a != NULL)
        {
            g_foreign_a.stop = 1;
            (void)WaitForSingleObject(local_a, 5000);
            CloseHandle(local_a);
        }
        return FALSE;
    }

    HANDLE foreign_a = LocalOpenThread(g_foreign_a.tid);
    if (foreign_a == NULL)
    {
        g_foreign_a.stop = 1;
        (void)WaitForSingleObject(local_a, 5000);
        CloseHandle(local_a);
        return FALSE;
    }

    DWORD previous_suspend = LocalSuspendThread(foreign_a);
    ContextProbe captured;
    InitializeContextProbe(&captured);
    DWORD get_status = DUET_STATUS_INVALID_PARAMETER;
    DWORD get_budget = 2000;
    while (previous_suspend != (DWORD)-1 && get_budget-- != 0)
    {
        get_status = LocalGetThreadContext(foreign_a, &captured.context);
        if (get_status == DUET_STATUS_SUCCESS)
            break;
        if (get_status != DUET_STATUS_INVALID_PARAMETER)
            break;
        Sleep(1);
    }
    DWORD frozen = g_foreign_a.heartbeat;
    Sleep(20);
    BOOL controlled = previous_suspend == 0 && get_status == DUET_STATUS_SUCCESS && g_foreign_a.heartbeat == frozen &&
                      ContextCanariesIntact(&captured);
    DWORD previous_resume = previous_suspend != (DWORD)-1 ? LocalResumeThread(foreign_a) : (DWORD)-1;
    DWORD progress_budget = 2000;
    while (g_foreign_a.heartbeat == frozen && progress_budget-- != 0)
        Sleep(1);
    controlled = controlled && previous_resume == 1 && g_foreign_a.heartbeat != frozen;
    Out(controlled ? "[thread3_smoke] foreign live control     = PASS\r\n"
                   : "[thread3_smoke] foreign live control     = FAIL\r\n");

    g_foreign_a.stop = 1;
    BOOL exited = WaitForSingleObject(local_a, 5000) == WAIT_OBJECT_0 && g_foreign_a.returned == FOREIGN_RETURNED &&
                  ForeignCanariesIntact(&g_foreign_a);
    CloseHandle(local_a);
    Sleep(20);
    Out(exited ? "[thread3_smoke] foreign target exit      = PASS\r\n"
               : "[thread3_smoke] foreign target exit      = FAIL\r\n");

    ContextProbe stale_context;
    InitializeContextProbe(&stale_context);
    DWORD stale_get = LocalGetThreadContext(foreign_a, &stale_context.context);
    BOOL stale_rejected = LocalSuspendThread(foreign_a) == (DWORD)-1 && stale_get == DUET_STATUS_INVALID_HANDLE &&
                          ContextCanariesIntact(&stale_context);
    Out(stale_rejected ? "[thread3_smoke] foreign stale rejected   = PASS\r\n"
                       : "[thread3_smoke] foreign stale rejected   = FAIL\r\n");
    HANDLE stale_numeric = foreign_a;
    CloseHandle(foreign_a);

    InitializeForeignProbe(&g_foreign_b);
    HANDLE local_b = CreateThread(NULL, 0, foreign_worker, &g_foreign_b, 0, NULL);
    BOOL second_ready = local_b != NULL && WaitForForeignReady(&g_foreign_b);
    HANDLE foreign_b = second_ready ? LocalOpenThread(g_foreign_b.tid) : NULL;
    BOOL reused = foreign_b != NULL && foreign_b == stale_numeric;
    DWORD second_suspend = foreign_b != NULL ? LocalSuspendThread(foreign_b) : (DWORD)-1;
    DWORD second_resume = second_suspend != (DWORD)-1 ? LocalResumeThread(foreign_b) : (DWORD)-1;
    BOOL fresh_controlled = reused && second_suspend == 0 && second_resume == 1;
    Out(fresh_controlled ? "[thread3_smoke] foreign slot reuse       = PASS\r\n"
                         : "[thread3_smoke] foreign slot reuse       = FAIL\r\n");
    g_foreign_b.stop = 1;
    BOOL second_exited = local_b != NULL && WaitForSingleObject(local_b, 5000) == WAIT_OBJECT_0 &&
                         g_foreign_b.returned == FOREIGN_RETURNED && ForeignCanariesIntact(&g_foreign_b);
    if (local_b != NULL)
        CloseHandle(local_b);
    if (foreign_b != NULL)
        CloseHandle(foreign_b);

    return controlled && exited && stale_rejected && fresh_controlled && second_exited;
}

static BOOL TestLocalThreadContext(void)
{
    g_context_heartbeat = 0;
    g_context_stop = 0;
    HANDLE thread = CreateThread(NULL, 0, context_worker, NULL, 0, NULL);
    if (thread == NULL)
        return FALSE;

    DWORD start_budget = 2000;
    while (g_context_heartbeat == 0 && start_budget-- != 0)
        Sleep(1);

    ContextProbe running;
    InitializeContextProbe(&running);
    running.context.Rax = 0x1122334455667788ULL;
    DWORD running_status = LocalGetThreadContext(thread, &running.context);
    BOOL running_rejected = g_context_heartbeat != 0 && running_status == DUET_STATUS_INVALID_PARAMETER &&
                            running.context.Rax == 0x1122334455667788ULL && ContextCanariesIntact(&running);

    DWORD previous_suspend = LocalSuspendThread(thread);
    BOOL suspended = previous_suspend != (DWORD)-1;

    ContextProbe captured;
    InitializeContextProbe(&captured);
    DWORD get_status = DUET_STATUS_INVALID_PARAMETER;
    DWORD get_budget = 2000;
    while (suspended && get_budget-- != 0)
    {
        get_status = LocalGetThreadContext(thread, &captured.context);
        if (get_status == DUET_STATUS_SUCCESS)
            break;
        if (get_status != DUET_STATUS_INVALID_PARAMETER)
            break;
        Sleep(1);
    }

    DWORD frozen_heartbeat = g_context_heartbeat;
    Sleep(20);
    BOOL off_cpu = suspended && previous_suspend == 0 && get_status == DUET_STATUS_SUCCESS &&
                   g_context_heartbeat == frozen_heartbeat &&
                   captured.context.ContextFlags == DUET_CONTEXT_AMD64_INTEGER && captured.context.Rip == 0 &&
                   captured.context.Rsp == 0 && ContextCanariesIntact(&captured);

    DWORD set_status = off_cpu ? LocalSetThreadContext(thread, &captured.context) : DUET_STATUS_INVALID_PARAMETER;
    ContextProbe verified;
    InitializeContextProbe(&verified);
    DWORD verify_status = set_status == DUET_STATUS_SUCCESS ? LocalGetThreadContext(thread, &verified.context)
                                                            : DUET_STATUS_INVALID_PARAMETER;
    BOOL round_trip = set_status == DUET_STATUS_SUCCESS && verify_status == DUET_STATUS_SUCCESS &&
                      verified.context.ContextFlags == DUET_CONTEXT_AMD64_INTEGER && verified.context.Rip == 0 &&
                      verified.context.Rsp == 0 && IntegerContextEqual(&captured.context, &verified.context) &&
                      ContextCanariesIntact(&verified);

    DWORD previous_resume = suspended ? LocalResumeThread(thread) : (DWORD)-1;
    if (previous_resume != (DWORD)-1)
        suspended = previous_resume > 1;

    DWORD progress_budget = 2000;
    while (g_context_heartbeat == frozen_heartbeat && progress_budget-- != 0)
        Sleep(1);
    BOOL resumed = previous_resume == 1 && g_context_heartbeat != frozen_heartbeat;

    g_context_stop = 1;
    if (suspended)
        (void)LocalResumeThread(thread);
    BOOL finished = WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0;
    CloseHandle(thread);

    return running_rejected && off_cpu && round_trip && resumed && finished;
}

void __cdecl mainCRTStartup(void)
{
    BOOL regression_ok = TRUE;
    Out("[thread3_smoke] starting\r\n");

    /* OpenThread on self. */
    HANDLE me = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    Out("[thread3_smoke] OpenThread(self)      = ");
    Out(me != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (me != NULL)
        CloseHandle(me);
    else
        regression_ok = FALSE;

    /*
     * The linked kernel32 Suspend/Get/Set wrappers are not real yet,
     * so this fixture uses their stable syscall ABI directly. The
     * handle itself is the ordinary caller-local CreateThread handle.
     */
    BOOL context_ok = TestLocalThreadContext();
    Out(context_ok ? "[thread3_smoke] local context round-trip= PASS\r\n"
                   : "[thread3_smoke] local context round-trip= FAIL\r\n");
    if (!context_ok)
        regression_ok = FALSE;

    BOOL foreign_ok = TestForeignThreadHandleLifecycle();
    Out(foreign_ok ? "[thread3_smoke] foreign close/reuse      = PASS\r\n"
                   : "[thread3_smoke] foreign close/reuse      = FAIL\r\n");
    if (!foreign_ok)
        regression_ok = FALSE;

    /* CreateThread suspended → ResumeThread → wait. */
    {
        HANDLE t = CreateThread(NULL, 0, suspended_worker, NULL, CREATE_SUSPENDED, NULL);
        Out("[thread3_smoke] CreateThread(suspended)= ");
        Out(t != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (t != NULL)
        {
            DWORD prev = ResumeThread(t);
            Out("[thread3_smoke] ResumeThread          = ");
            Out(prev != (DWORD)-1 ? "PASS\r\n" : "FAIL/STUB\r\n");
            if (prev == (DWORD)-1)
                regression_ok = FALSE;

            DWORD r = WaitForSingleObject(t, 5000);
            Out("[thread3_smoke] Wait + finish         = ");
            Out(r == WAIT_OBJECT_0 ? "PASS\r\n" : "FAIL/STUB\r\n");
            if (r != WAIT_OBJECT_0)
                regression_ok = FALSE;

            CloseHandle(t);
        }
        else
        {
            regression_ok = FALSE;
        }
    }

    /* GetThreadIOPendingFlag. */
    {
        BOOL pending = TRUE;
        BOOL ok = GetThreadIOPendingFlag(GetCurrentThread(), &pending);
        Out("[thread3_smoke] GetThreadIOPendingFlag= ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (!ok)
            regression_ok = FALSE;
    }

    /*
     * Once WaitForSingleObject reports the worker exited, its saved
     * scheduler context must never become runnable again. Exercise
     * repeated slot allocation/reaping and voluntary context switches,
     * then require the exited worker's heartbeat and surrounding
     * canaries to remain bit-for-bit stable.
     */
    {
        HANDLE exited = CreateThread(NULL, 0, quiescence_worker, NULL, 0, NULL);
        DWORD start_budget = 5000;
        while (exited != NULL && g_quiescence.heartbeat == 0 && start_budget-- != 0)
            Sleep(1);

        g_quiescence.stop = 1;
        BOOL exited_ok =
            exited != NULL && g_quiescence.heartbeat != 0 && WaitForSingleObject(exited, 5000) == WAIT_OBJECT_0 &&
            g_quiescence.returned == QUIESCENCE_RETURNED && g_quiescence.before == QUIESCENCE_CANARY_BEFORE &&
            g_quiescence.after == QUIESCENCE_CANARY_AFTER;
        DWORD stable_heartbeat = g_quiescence.heartbeat;
        if (exited != NULL)
            CloseHandle(exited);

        for (DWORD i = 0; i < QUIESCENCE_CHURN_THREADS; ++i)
        {
            HANDLE churn = CreateThread(NULL, 0, churn_worker, NULL, 0, NULL);
            if (churn == NULL || WaitForSingleObject(churn, 5000) != WAIT_OBJECT_0)
            {
                exited_ok = FALSE;
                if (churn != NULL)
                    CloseHandle(churn);
                break;
            }
            CloseHandle(churn);
        }
        Sleep(20);

        BOOL quiescent = exited_ok && g_churn_completed == QUIESCENCE_CHURN_THREADS &&
                         g_quiescence.heartbeat == stable_heartbeat && g_quiescence.returned == QUIESCENCE_RETURNED &&
                         g_quiescence.before == QUIESCENCE_CANARY_BEFORE &&
                         g_quiescence.after == QUIESCENCE_CANARY_AFTER;
        Out(quiescent ? "[thread3_smoke] exited context quiescent= PASS\r\n"
                      : "[thread3_smoke] exited context quiescent= FAIL\r\n");
        if (!quiescent)
            regression_ok = FALSE;
    }

    Out("[thread3_smoke] done\r\n");
    Out(regression_ok ? "[ring3-thread3-smoke] PASS\r\n" : "[ring3-thread3-smoke] FAIL\r\n");
    ExitProcess(regression_ok ? 0 : 1);
}
