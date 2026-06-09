#pragma once

// Freestanding omnibox input classifier — pure char logic, no kernel or
// std dependencies, so tests/host can exercise it directly (and the
// browser includes it from kernel space). Decides whether typed text is
// a URL to navigate or a search query, and builds a search URL.
//
// Without this, the URL bar fed every typed string straight into the
// fetch path: a bare word like "weather" became host "weather" -> DNS
// failure -> blank page, which read to the user as "nothing happens /
// back to the search bar". See docs/browser/2026-06-08-render-diagnosis.

namespace duetos::apps::browser
{

// True if `s` should be navigated as a URL/host; false if it should be
// sent to a search engine. Heuristic (Chromium-style "what you typed"):
//   - explicit "scheme://"            -> URL
//   - any internal whitespace         -> search (multi-word query)
//   - "localhost" [:port|/path]       -> URL
//   - a dotted host before the path   -> URL  (google.com, 192.168.1.1)
//   - otherwise (bare word, no dot)   -> search
inline bool OmniboxLooksLikeUrl(const char* s)
{
    if (s == nullptr)
    {
        return false;
    }
    // Trim leading whitespace.
    while (*s == ' ' || *s == '\t')
    {
        ++s;
    }
    if (*s == '\0')
    {
        return false;
    }

    // Explicit "scheme://" before any space -> URL.
    for (const char* p = s; *p != '\0' && *p != ' ' && *p != '\t'; ++p)
    {
        if (p[0] == ':' && p[1] == '/' && p[2] == '/')
        {
            return true;
        }
    }

    // Any internal whitespace (a space followed by more non-space
    // content) means a multi-word query -> search. Trailing spaces are
    // ignored.
    for (const char* p = s; *p != '\0'; ++p)
    {
        if (*p == ' ' || *p == '\t')
        {
            for (const char* q = p + 1; *q != '\0'; ++q)
            {
                if (*q != ' ' && *q != '\t')
                {
                    return false;
                }
            }
            break;
        }
    }

    // "localhost" optionally followed by :port or /path.
    {
        const char* lit = "localhost";
        const char* p = s;
        const char* q = lit;
        while (*q != '\0' && *p == *q)
        {
            ++p;
            ++q;
        }
        if (*q == '\0' && (*p == '\0' || *p == ':' || *p == '/'))
        {
            return true;
        }
    }

    // Dotted host: a '.' in the host part (everything before the first
    // '/' or whitespace), neither leading nor trailing-of-host. Catches
    // google.com, example.com/path, 192.168.1.1; rejects a lone ".".
    const char* host_end = s;
    while (*host_end != '\0' && *host_end != '/' && *host_end != ' ' && *host_end != '\t')
    {
        ++host_end;
    }
    for (const char* p = s; p < host_end; ++p)
    {
        if (*p == '.' && p != s && (p + 1) < host_end)
        {
            return true;
        }
    }
    return false;
}

// Percent-encode `query` (x-www-form-urlencoded: space -> '+', the
// unreserved set [A-Za-z0-9-_.~] literal, everything else -> %XX) into a
// search URL written NUL-terminated into `out`, bounded by `cap`.
// Default engine: DuckDuckGo's lightweight HTML endpoint (its leaf
// chains to an embedded root, and the no-JS page suits the v0 engine).
inline void OmniboxBuildSearchUrl(const char* query, char* out, unsigned cap)
{
    if (out == nullptr || cap == 0)
    {
        return;
    }
    unsigned n = 0;
    for (const char* p = "https://duckduckgo.com/html/?q="; *p != '\0' && n + 1 < cap; ++p)
    {
        out[n++] = *p;
    }
    const char* kHex = "0123456789ABCDEF";
    if (query != nullptr)
    {
        while (*query == ' ' || *query == '\t')
        {
            ++query;
        }
        for (const char* p = query; *p != '\0' && n + 1 < cap; ++p)
        {
            const char c = *p;
            const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                    c == '-' || c == '_' || c == '.' || c == '~';
            if (c == ' ')
            {
                out[n++] = '+';
            }
            else if (unreserved)
            {
                out[n++] = c;
            }
            else if (n + 3 < cap)
            {
                const unsigned char b = static_cast<unsigned char>(c);
                out[n++] = '%';
                out[n++] = kHex[(b >> 4) & 0xF];
                out[n++] = kHex[b & 0xF];
            }
        }
    }
    out[(n < cap) ? n : cap - 1] = '\0';
}

} // namespace duetos::apps::browser
