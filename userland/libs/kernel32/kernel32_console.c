/*
 * userland/libs/kernel32/kernel32_console.c
 *
 * Console-input surface of the split kernel32.dll: ReadConsoleA/W,
 * ReadConsoleInputA/W, PeekConsoleInputA/W,
 * GetNumberOfConsoleInputEvents, FlushConsoleInputBuffer.
 *
 * Input source — one path, kernel-owned: SYS_STDIN_READ (171)
 * drains the calling process's stdin ring (fed by the kbd-reader
 * task in kernel/core/boot_tasks.cpp once the process holds stdin
 * focus). The ring delivers cooked ASCII bytes; this TU translates
 * them into KEY_EVENT INPUT_RECORDs (down + up pair per byte) via
 * the freestanding core in kernel32_console_input.h and buffers
 * them in a small in-process queue so PeekConsoleInput /
 * GetNumberOfConsoleInputEvents can answer without consuming.
 *
 * // GAP: SYS_STDIN_READ has no non-blocking probe, so Peek /
 * GetNumberOfConsoleInputEvents only see records already drained
 * into this queue by a previous blocking read — bytes still in the
 * kernel ring are invisible until ReadConsoleInput/ReadConsole
 * blocks once. Needs a SYS_STDIN_PEEK (kernel/proc/process.cpp +
 * kernel/syscall dispatch) to close.
 *
 * // GAP: single-threaded model — no lock around the record queue /
 * byte carry, matching the anonymous-pipe ring precedent in
 * kernel32_io.c. Revisit with real multi-threaded console readers.
 */

#include "kernel32_console_input.h"
#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * Syscall glue
 * ------------------------------------------------------------------ */

/* Blocking drain of the kernel stdin ring: returns >= 1 bytes, or
 * negative on bad parameters. */
static long long stdin_read_blocking(void* buf, unsigned cap)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)171), /* SYS_STDIN_READ */
                       "D"((long long)buf), "S"((long long)cap)
                     : "memory");
    return rv;
}

/* Echo bytes to the console (SYS_WRITE fd=1) for ENABLE_ECHO_INPUT. */
static void console_echo(const char* buf, unsigned len)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)2), /* SYS_WRITE */
                       "D"((long long)1), "S"((long long)buf), "d"((long long)len)
                     : "memory");
}

/* ------------------------------------------------------------------
 * Byte carry — surplus cooked bytes between ReadConsole calls
 *
 * A blocking drain can return more bytes than the current call
 * consumes (type-ahead past Enter). The surplus parks here so the
 * next ReadConsole / ReadConsoleInput call sees it first.
 * ------------------------------------------------------------------ */

static unsigned char g_carry[128];
static unsigned g_carry_head = 0;
static unsigned g_carry_tail = 0;

static int carry_pop(unsigned char* c)
{
    if (g_carry_head == g_carry_tail)
        return 0;
    *c = g_carry[g_carry_tail & 127u];
    ++g_carry_tail;
    return 1;
}

static void carry_push(unsigned char c)
{
    if (g_carry_head - g_carry_tail >= 128u)
        ++g_carry_tail; /* drop oldest — matches the stdin-ring policy */
    g_carry[g_carry_head & 127u] = c;
    ++g_carry_head;
}

/* Fetch one cooked byte: carry first, else block on the kernel
 * ring and park the surplus. Returns 0 only on syscall failure. */
static int stdin_next_byte(unsigned char* c)
{
    if (carry_pop(c))
        return 1;
    unsigned char raw[64];
    const long long got = stdin_read_blocking(raw, sizeof raw);
    if (got <= 0)
        return 0;
    for (long long i = 1; i < got; ++i)
        carry_push(raw[i]);
    *c = raw[0];
    return 1;
}

/* ------------------------------------------------------------------
 * INPUT_RECORD queue
 * ------------------------------------------------------------------ */

/* Win32 INPUT_RECORD, KEY_EVENT arm only: 20 bytes.
 *   WORD EventType; (2 pad) then KEY_EVENT_RECORD {
 *     BOOL bKeyDown; WORD wRepeatCount; WORD wVirtualKeyCode;
 *     WORD wVirtualScanCode; WCHAR UnicodeChar; DWORD dwControlKeyState; } */
typedef struct
{
    unsigned short event_type;
    unsigned short pad_;
    int key_down;
    unsigned short repeat;
    unsigned short vk;
    unsigned short scan;
    unsigned short uchar; /* WCHAR; the A view reads the low byte */
    DWORD ctrl_state;
} DUETOS_INPUT_RECORD;

#define DUETOS_KEY_EVENT 0x0001

enum
{
    kRecCap = 64 /* power of two */
};
static DUETOS_INPUT_RECORD g_rec[kRecCap];
static unsigned g_rec_head = 0;
static unsigned g_rec_tail = 0;

static unsigned rec_count(void)
{
    return g_rec_head - g_rec_tail;
}

static void rec_push_stroke(const duetos_key_stroke* ks)
{
    /* Down + up pair per byte, dropping the oldest pair on
     * overflow so the ring never splits a pair. */
    if (rec_count() + 2u > (unsigned)kRecCap)
        g_rec_tail += 2;
    DUETOS_INPUT_RECORD r;
    r.event_type = DUETOS_KEY_EVENT;
    r.pad_ = 0;
    r.key_down = 1;
    r.repeat = 1;
    r.vk = ks->vk;
    r.scan = 0; /* // GAP: no scan codes from the cooked ring */
    r.uchar = ks->ascii;
    r.ctrl_state = ks->ctrl_state;
    g_rec[g_rec_head & (kRecCap - 1u)] = r;
    ++g_rec_head;
    r.key_down = 0;
    g_rec[g_rec_head & (kRecCap - 1u)] = r;
    ++g_rec_head;
}

/* Refill the record queue, blocking until at least one key event
 * is queued. Carry bytes (type-ahead) translate without blocking. */
static int rec_fill_blocking(void)
{
    unsigned char c;
    while (carry_pop(&c))
    {
        duetos_key_stroke ks;
        duetos_console_byte_to_stroke(c, &ks);
        rec_push_stroke(&ks);
    }
    if (rec_count() != 0)
        return 1;
    unsigned char raw[24]; /* 24 bytes -> up to 48 records, < kRecCap */
    const long long got = stdin_read_blocking(raw, sizeof raw);
    if (got <= 0)
        return 0;
    for (long long i = 0; i < got; ++i)
    {
        duetos_key_stroke ks;
        duetos_console_byte_to_stroke(raw[i], &ks);
        rec_push_stroke(&ks);
    }
    return rec_count() != 0;
}

static void rec_copy_out(DUETOS_INPUT_RECORD* dst, DWORD max, DWORD* copied, int consume)
{
    DWORD n = 0;
    unsigned tail = g_rec_tail;
    while (n < max && tail != g_rec_head)
    {
        dst[n++] = g_rec[tail & (kRecCap - 1u)];
        ++tail;
    }
    if (consume)
        g_rec_tail = tail;
    *copied = n;
}

/* ------------------------------------------------------------------
 * Exports — event-mode input
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL ReadConsoleInputW(HANDLE hConsoleInput, void* lpBuffer, DWORD nLength,
                                             DWORD* lpNumberOfEventsRead)
{
    (void)hConsoleInput;
    if (lpBuffer == (void*)0 || nLength == 0)
    {
        if (lpNumberOfEventsRead != (DWORD*)0)
            *lpNumberOfEventsRead = 0;
        return 0;
    }
    while (rec_count() == 0)
    {
        if (!rec_fill_blocking())
        {
            /* Syscall failure (no process context / bad ring) —
             * fail rather than spin. */
            if (lpNumberOfEventsRead != (DWORD*)0)
                *lpNumberOfEventsRead = 0;
            return 0;
        }
    }
    DWORD copied = 0;
    rec_copy_out((DUETOS_INPUT_RECORD*)lpBuffer, nLength, &copied, 1);
    if (lpNumberOfEventsRead != (DWORD*)0)
        *lpNumberOfEventsRead = copied;
    return 1;
}

/* The A and W records only differ in the uChar arm (CHAR vs WCHAR
 * in the same 2-byte slot); for the ASCII range the layouts are
 * byte-identical, so the A export shares the W implementation. */
__declspec(dllexport) BOOL ReadConsoleInputA(HANDLE hConsoleInput, void* lpBuffer, DWORD nLength,
                                             DWORD* lpNumberOfEventsRead)
{
    return ReadConsoleInputW(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
}

__declspec(dllexport) BOOL PeekConsoleInputW(HANDLE hConsoleInput, void* lpBuffer, DWORD nLength,
                                             DWORD* lpNumberOfEventsRead)
{
    (void)hConsoleInput;
    if (lpBuffer == (void*)0 || nLength == 0)
    {
        if (lpNumberOfEventsRead != (DWORD*)0)
            *lpNumberOfEventsRead = 0;
        return lpBuffer == (void*)0 ? 0 : 1;
    }
    /* Translate any parked type-ahead bytes so Peek sees them, but
     * never block — an empty queue reports zero events. */
    unsigned char c;
    while (carry_pop(&c))
    {
        duetos_key_stroke ks;
        duetos_console_byte_to_stroke(c, &ks);
        rec_push_stroke(&ks);
    }
    DWORD copied = 0;
    rec_copy_out((DUETOS_INPUT_RECORD*)lpBuffer, nLength, &copied, 0);
    if (lpNumberOfEventsRead != (DWORD*)0)
        *lpNumberOfEventsRead = copied;
    return 1;
}

__declspec(dllexport) BOOL PeekConsoleInputA(HANDLE hConsoleInput, void* lpBuffer, DWORD nLength,
                                             DWORD* lpNumberOfEventsRead)
{
    return PeekConsoleInputW(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
}

__declspec(dllexport) BOOL GetNumberOfConsoleInputEvents(HANDLE hConsoleInput, DWORD* lpNumberOfEvents)
{
    (void)hConsoleInput;
    if (lpNumberOfEvents == (DWORD*)0)
        return 0;
    /* Fold parked type-ahead into the visible count. // GAP: bytes
     * still in the kernel ring are not counted (no non-blocking
     * stdin probe syscall yet). */
    unsigned char c;
    while (carry_pop(&c))
    {
        duetos_key_stroke ks;
        duetos_console_byte_to_stroke(c, &ks);
        rec_push_stroke(&ks);
    }
    *lpNumberOfEvents = rec_count();
    return 1;
}

__declspec(dllexport) BOOL FlushConsoleInputBuffer(HANDLE hConsoleInput)
{
    (void)hConsoleInput;
    g_rec_tail = g_rec_head;
    g_carry_tail = g_carry_head;
    /* // GAP: bytes already in the kernel stdin ring survive a flush
     * — no kernel-side discard call. They surface on the next
     * blocking read. */
    return 1;
}

/* ------------------------------------------------------------------
 * Exports — character-mode input (ReadConsoleA/W)
 * ------------------------------------------------------------------ */

/* Cooked-mode core shared by both width variants. Honours the
 * stdin handle's mode word:
 *   ENABLE_LINE_INPUT (0x2): accumulate until Enter; DEL/BS edits
 *     the tail; the returned line ends "\r\n" (Win32 contract).
 *   ENABLE_ECHO_INPUT (0x4): echo typed bytes ("\b \b" for an
 *     edit, "\r\n" for Enter).
 * Raw mode returns whatever one blocking drain hands back.
 * // GAP: pInputControl (CtrlWakeup mask) is ignored. */
static DWORD read_console_core(char* dst, DWORD cap)
{
    const DWORD mode = kernel32_console_mode_of((HANDLE)(UINT_PTR)0xFFFFFFF6ULL); /* STD_INPUT_HANDLE */
    const int line_mode = (mode & 0x2u) != 0;
    const int echo = (mode & 0x4u) != 0;

    if (!line_mode)
    {
        unsigned char c;
        DWORD n = 0;
        if (!stdin_next_byte(&c))
            return 0;
        dst[n++] = (char)c;
        /* Drain any parked type-ahead without blocking again. */
        while (n < cap && carry_pop(&c))
            dst[n++] = (char)c;
        if (echo)
            console_echo(dst, n);
        return n;
    }

    DWORD len = 0;
    for (;;)
    {
        unsigned char c;
        if (!stdin_next_byte(&c))
            return len;
        if (c == 0x7F || c == 0x08)
        {
            if (len > 0)
            {
                --len;
                if (echo)
                    console_echo("\b \b", 3);
            }
            continue;
        }
        if (c == '\n' || c == '\r')
        {
            if (echo)
                console_echo("\r\n", 2);
            if (len < cap)
                dst[len++] = '\r';
            if (len < cap)
                dst[len++] = '\n';
            return len;
        }
        if (len + 2 < cap) /* keep room for the trailing CR LF */
        {
            dst[len++] = (char)c;
            if (echo)
                console_echo((const char*)&c, 1);
        }
    }
}

__declspec(dllexport) BOOL ReadConsoleA(HANDLE hConsoleInput, void* lpBuffer, DWORD nNumberOfCharsToRead,
                                        DWORD* lpNumberOfCharsRead, void* pInputControl)
{
    (void)hConsoleInput;
    (void)pInputControl;
    if (lpBuffer == (void*)0 || nNumberOfCharsToRead == 0)
    {
        if (lpNumberOfCharsRead != (DWORD*)0)
            *lpNumberOfCharsRead = 0;
        return lpBuffer == (void*)0 ? 0 : 1;
    }
    const DWORD got = read_console_core((char*)lpBuffer, nNumberOfCharsToRead);
    if (lpNumberOfCharsRead != (DWORD*)0)
        *lpNumberOfCharsRead = got;
    return 1;
}

__declspec(dllexport) BOOL ReadConsoleW(HANDLE hConsoleInput, wchar_t16* lpBuffer, DWORD nNumberOfCharsToRead,
                                        DWORD* lpNumberOfCharsRead, void* pInputControl)
{
    (void)hConsoleInput;
    (void)pInputControl;
    if (lpBuffer == (wchar_t16*)0 || nNumberOfCharsToRead == 0)
    {
        if (lpNumberOfCharsRead != (DWORD*)0)
            *lpNumberOfCharsRead = 0;
        return lpBuffer == (wchar_t16*)0 ? 0 : 1;
    }
    char narrow[256];
    DWORD cap = nNumberOfCharsToRead > 256 ? 256 : nNumberOfCharsToRead;
    const DWORD got = read_console_core(narrow, cap);
    for (DWORD i = 0; i < got; ++i)
        lpBuffer[i] = (wchar_t16)(unsigned char)narrow[i];
    if (lpNumberOfCharsRead != (DWORD*)0)
        *lpNumberOfCharsRead = got;
    return 1;
}
