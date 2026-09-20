#ifndef DUETOS_KERNEL32_CREATEPROCESS_CMDLINE_H
#define DUETOS_KERNEL32_CREATEPROCESS_CMDLINE_H

/*
 * Bounded executable-token extraction for CreateProcessA/W.
 *
 * A non-null application name is copied exactly. Otherwise the first
 * whitespace-delimited command-line token is selected, with a quoted first
 * token allowing spaces in the executable path. The current spawn ABI accepts
 * only this path; trailing arguments remain intentionally unpropagated.
 *
 * These helpers fail closed on empty, unterminated, overlong, or non-ASCII
 * wide paths and always leave `out` empty on failure.
 */

static inline int Win32CreateProcessIsSpace(unsigned int c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static inline int Win32ExtractCreateProcessExecutableA(const char* application, const char* command_line, char* out,
                                                       unsigned long out_cap)
{
    if (out == (char*)0 || out_cap == 0)
        return 0;
    out[0] = '\0';

    const char* src = application;
    int quoted = 0;
    if (src == (const char*)0)
    {
        src = command_line;
        if (src == (const char*)0)
            return 0;
        while (Win32CreateProcessIsSpace((unsigned char)*src))
            ++src;
        if (*src == '"')
        {
            quoted = 1;
            ++src;
        }
    }

    unsigned long length = 0;
    for (;;)
    {
        const unsigned char c = (unsigned char)*src;
        if (quoted)
        {
            if (c == '"')
            {
                if (length == 0 || (src[1] != '\0' && !Win32CreateProcessIsSpace((unsigned char)src[1])))
                {
                    out[0] = '\0';
                    return 0;
                }
                out[length] = '\0';
                return 1;
            }
            if (c == '\0')
            {
                out[0] = '\0';
                return 0;
            }
        }
        else if (c == '\0' || (application == (const char*)0 && Win32CreateProcessIsSpace(c)))
        {
            if (length == 0)
                return 0;
            out[length] = '\0';
            return 1;
        }

        if (length + 1 >= out_cap)
        {
            out[0] = '\0';
            return 0;
        }
        out[length++] = (char)c;
        ++src;
    }
}

static inline int Win32ExtractCreateProcessExecutableW(const unsigned short* application,
                                                       const unsigned short* command_line, char* out,
                                                       unsigned long out_cap)
{
    if (out == (char*)0 || out_cap == 0)
        return 0;
    out[0] = '\0';

    const unsigned short* src = application;
    int quoted = 0;
    if (src == (const unsigned short*)0)
    {
        src = command_line;
        if (src == (const unsigned short*)0)
            return 0;
        while (Win32CreateProcessIsSpace((unsigned int)*src))
            ++src;
        if (*src == (unsigned short)'"')
        {
            quoted = 1;
            ++src;
        }
    }

    unsigned long length = 0;
    for (;;)
    {
        const unsigned int c = (unsigned int)*src;
        if (quoted)
        {
            if (c == (unsigned int)'"')
            {
                if (length == 0 || (src[1] != 0 && !Win32CreateProcessIsSpace((unsigned int)src[1])))
                {
                    out[0] = '\0';
                    return 0;
                }
                out[length] = '\0';
                return 1;
            }
            if (c == 0)
            {
                out[0] = '\0';
                return 0;
            }
        }
        else if (c == 0 || (application == (const unsigned short*)0 && Win32CreateProcessIsSpace(c)))
        {
            if (length == 0)
                return 0;
            out[length] = '\0';
            return 1;
        }

        if (c > 0x7Fu || length + 1 >= out_cap)
        {
            out[0] = '\0';
            return 0;
        }
        out[length++] = (char)c;
        ++src;
    }
}

#endif /* DUETOS_KERNEL32_CREATEPROCESS_CMDLINE_H */
