/*
 * DuetOS — userland shell, v0.
 *
 * Replaces the 181-byte hand-coded ELF stub that previously
 * shipped at /bin/usershell.elf. The hand-built version was
 * "spawn pipeline alive" proof; this is a real C program built
 * via the toolchain that other userland binaries will share
 * (see userland/libc/).
 *
 * Behavior:
 *   1. Print a banner + greet line so we can see the shell came
 *      up cleanly.
 *   2. Print our own PID via SYS_GETPID — sanity check that the
 *      process model is plumbed end-to-end.
 *   3. Attempt to read a line from stdin (SYS_READ). If the
 *      kernel doesn't yet wire SYS_READ to a per-process queue
 *      (today it returns -ENOSYS for non-trusted callers; the
 *      trusted-spawn path used here may also short-circuit), we
 *      gracefully exit with the PID as the code so the kernel
 *      reaper still logs the round-trip cleanly.
 *
 * No malloc, no printf — just `write()` with hand-formatted
 * decimal expansions. That's fine for the v0 shell; a real
 * stdio lands when a second native binary needs it.
 */

#include "string.h"
#include "unistd.h"

/* Convert non-negative int to decimal ASCII. Returns the number of
 * bytes written into `buf`; buf must have at least 12 bytes. */
static size_t int_to_dec(int v, char* buf)
{
    if (v == 0)
    {
        buf[0] = '0';
        return 1;
    }
    char tmp[12];
    size_t n = 0;
    int x = (v < 0) ? -v : v;
    while (x > 0 && n < sizeof(tmp))
    {
        tmp[n++] = (char)('0' + (x % 10));
        x /= 10;
    }
    size_t out = 0;
    if (v < 0)
        buf[out++] = '-';
    for (size_t i = 0; i < n; ++i)
        buf[out++] = tmp[n - 1 - i];
    return out;
}

static void put_str(const char* s)
{
    write(STDOUT_FILENO, s, strlen(s));
}

static void put_int(int v)
{
    char buf[12];
    size_t n = int_to_dec(v, buf);
    write(STDOUT_FILENO, buf, n);
}

/* Minimal built-in command dispatcher. Reused by slice 6 once
 * SYS_READ has a per-process queue. */
static int dispatch(const char* line)
{
    if (strcmp(line, "help") == 0)
    {
        put_str("commands: help, pid, echo <args>, exit\n");
        return 0;
    }
    if (strcmp(line, "pid") == 0)
    {
        put_int(getpid());
        put_str("\n");
        return 0;
    }
    if (line[0] == 'e' && line[1] == 'c' && line[2] == 'h' && line[3] == 'o' && (line[4] == ' ' || line[4] == '\0'))
    {
        const char* rest = (line[4] == ' ') ? &line[5] : "";
        put_str(rest);
        put_str("\n");
        return 0;
    }
    if (strcmp(line, "exit") == 0)
    {
        return 1; /* ask main to terminate */
    }
    if (line[0] != '\0')
    {
        put_str("unknown command: ");
        put_str(line);
        put_str("\n");
    }
    return 0;
}

int main(void)
{
    put_str("DuetOS userland shell v0\n");
    put_str("pid=");
    put_int(getpid());
    put_str("\n");
    put_str("type 'help' for commands.\n");

    /* Try to read a line. If SYS_READ short-circuits (the v0
     * trusted-spawn path may not yet have stdin wired), the
     * loop exits cleanly with the PID as the code. */
    char line[256];
    while (1)
    {
        put_str("duet$ ");
        ssize_t n = read(STDIN_FILENO, line, sizeof(line) - 1);
        if (n <= 0)
        {
            put_str("(no stdin yet — exiting)\n");
            break;
        }
        if (n > (ssize_t)(sizeof(line) - 1))
            n = sizeof(line) - 1;
        line[n] = '\0';
        /* Strip trailing newline. */
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (dispatch(line) != 0)
            break;
    }
    return getpid();
}
