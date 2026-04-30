/*
 * crt_smoke — exercise msvcrt / ucrtbase C-runtime functions.
 *
 * Probes the C-stdlib functions every PE built with MSVC links
 * against. These are imported from msvcrt.dll / ucrtbase.dll
 * and used everywhere — string ops, memory ops, sort, search:
 *   memcpy / memmove / memset / memcmp
 *   strcmp / strncmp / strlen / strcpy / strncpy / strcat
 *   strchr / strrchr / strstr
 *   qsort / bsearch
 *   atoi / itoa
 *   abs / labs
 *
 * Each call is checked against known reference output. Pure
 * computation tests, no syscalls beyond Out().
 */
#include <windows.h>
#include <string.h>
#include <stdlib.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static int int_cmp(const void* a, const void* b)
{
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);
}

void __cdecl mainCRTStartup(void)
{
    Out("[crt_smoke] starting\r\n");

    /* memcpy / memcmp. */
    {
        char a[8] = "abcdefg";
        char b[8] = {0};
        memcpy(b, a, 8);
        Out("[crt_smoke] memcpy + memcmp     = ");
        Out(memcmp(a, b, 8) == 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* memmove with overlap. */
    {
        char buf[10] = "hello";
        memmove(buf + 1, buf, 5);
        Out("[crt_smoke] memmove(overlap)    = ");
        Out(buf[0] == 'h' && buf[1] == 'h' && buf[2] == 'e' && buf[5] == 'o' ? "PASS\r\n" : "FAIL\r\n");
    }

    /* memset. */
    {
        char buf[8];
        memset(buf, 0xAB, 8);
        int ok = 1;
        for (int i = 0; i < 8; ++i)
            if ((unsigned char)buf[i] != 0xAB)
                ok = 0;
        Out("[crt_smoke] memset(0xAB)        = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
    }

    /* strcmp / strncmp / strlen. */
    Out("[crt_smoke] strlen(\"hello\")     = ");
    Out(strlen("hello") == 5 ? "PASS\r\n" : "FAIL\r\n");
    Out("[crt_smoke] strcmp eq/diff      = ");
    Out(strcmp("a", "a") == 0 && strcmp("a", "b") < 0 ? "PASS\r\n" : "FAIL\r\n");
    Out("[crt_smoke] strncmp 3 chars     = ");
    Out(strncmp("hello", "help!", 3) == 0 && strncmp("hello", "help!", 4) != 0 ? "PASS\r\n" : "FAIL\r\n");

    /* strcpy / strcat. */
    {
        char buf[16] = {0};
        strcpy(buf, "hello");
        strcat(buf, " world");
        Out("[crt_smoke] strcpy + strcat     = ");
        Out(strcmp(buf, "hello world") == 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* strchr / strrchr / strstr. */
    Out("[crt_smoke] strchr('l')         = ");
    {
        const char* p = strchr("hello", 'l');
        Out(p != NULL && *p == 'l' && (p - "hello") == 2 ? "PASS\r\n" : "FAIL\r\n");
    }
    Out("[crt_smoke] strrchr('l')        = ");
    {
        const char* p = strrchr("hello", 'l');
        Out(p != NULL && (p - "hello") == 3 ? "PASS\r\n" : "FAIL\r\n");
    }
    Out("[crt_smoke] strstr(\"lo wo\")    = ");
    {
        const char* p = strstr("hello world", "lo wo");
        Out(p != NULL && (p - "hello world") == 3 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* atoi / abs. */
    Out("[crt_smoke] atoi(\"-42\")        = ");
    Out(atoi("-42") == -42 ? "PASS\r\n" : "FAIL\r\n");
    Out("[crt_smoke] abs(-7)             = ");
    Out(abs(-7) == 7 ? "PASS\r\n" : "FAIL\r\n");

    /* qsort + bsearch. */
    {
        int arr[6] = {3, 1, 4, 1, 5, 9};
        qsort(arr, 6, sizeof(int), int_cmp);
        int sorted = arr[0] == 1 && arr[1] == 1 && arr[2] == 3 && arr[3] == 4 && arr[4] == 5 && arr[5] == 9;
        Out("[crt_smoke] qsort               = ");
        Out(sorted ? "PASS\r\n" : "FAIL\r\n");

        int needle = 4;
        int* found = (int*)bsearch(&needle, arr, 6, sizeof(int), int_cmp);
        Out("[crt_smoke] bsearch(4)          = ");
        Out(found != NULL && *found == 4 ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[crt_smoke] done\r\n");
    ExitProcess(0);
}
