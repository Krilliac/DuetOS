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
 *   3. Drive a real read/eval/print loop. `read()` blocks via
 *      SYS_STDIN_READ on the per-process stdin ring; the kbd-
 *      reader thread in kernel/core/main.cpp pushes printable
 *      ASCII + Enter ('\n') + Backspace ('\x7F') bytes into the
 *      ring once login is closed, so each Enter delivers a full
 *      line into our line buffer. Backspace edits in place; the
 *      `dispatch` table runs the line; "exit" terminates the
 *      shell.
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

/* Minimal built-in command dispatcher. */
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

    /* Line-buffered REPL. `read()` returns up to N bytes from
     * the kernel's per-process stdin ring; we accumulate into
     * `line` until we see an Enter ('\n'), then dispatch the
     * complete line. Backspace ('\x7F' from the kbd-reader)
     * rubs out the last char in the buffer with a CR-erase-CR
     * echo so the prompt redraw is visible to the user. */
    char line[256];
    size_t pos = 0;
    put_str("duet$ ");
    for (;;)
    {
        char chunk[64];
        ssize_t n = read(STDIN_FILENO, chunk, sizeof(chunk));
        if (n <= 0)
        {
            /* Read failed (e.g. stdin closed) — exit cleanly so
             * the reaper logs a clean round-trip rather than
             * leaving the task in a busy spin. */
            put_str("\n[shell] stdin closed — exiting\n");
            break;
        }
        for (ssize_t i = 0; i < n; ++i)
        {
            const char c = chunk[i];
            if (c == '\n' || c == '\r')
            {
                /* Echo the newline so the next prompt starts
                 * on a fresh line, then dispatch + reprompt. */
                put_str("\n");
                line[pos] = '\0';
                int rc = dispatch(line);
                pos = 0;
                if (rc != 0)
                    return getpid();
                put_str("duet$ ");
            }
            else if (c == '\x7F' || c == '\b')
            {
                if (pos > 0)
                {
                    --pos;
                    /* Visual erase: backspace, space, backspace. */
                    put_str("\b \b");
                }
            }
            else if (pos + 1 < sizeof(line))
            {
                line[pos++] = c;
                /* Echo the character locally — the kbd-reader's
                 * COM1 mirror happens kernel-side before SYS_
                 * STDIN_READ delivers, but the userland-visible
                 * stdout still needs the echo. */
                char buf[2] = {c, '\0'};
                put_str(buf);
            }
            /* Buffer full — drop the byte silently. A real shell
             * would beep; we don't have an audible alert tier. */
        }
    }
    return getpid();
}
