#pragma once
// cookies.h — RFC 6265-ish in-kernel cookie jar.
//
// Public surface used by browser.cpp and the browser's HTTP layer.
// All state lives in a single process-global jar (g_cookie_jar in
// cookies.cpp); access is single-threaded today (browser app owns
// the jar — no concurrent writer).
//
// Threading model: caller serialises. No internal locking.
//
// Capacity: kCookieJarCap entries (128). When full, the oldest
// entry (by insertion order) is evicted to make room.
//
// GAP: public-suffix list (a site cannot set a cookie for ".com");
//      __Secure-/__Host- name prefixes; SameSite attribute;
//      third-party (cross-origin) policy.

#include "util/types.h"

namespace duetos::net
{

// Maximum number of cookies stored simultaneously.
constexpr duetos::u32 kCookieJarCap = 128;

// Maximum byte length of the Name, Value, Domain, and Path fields
// (including the NUL terminator). These mirror the browser.cpp
// URL/title caps so a Set-Cookie header that arrives from a page
// the browser loaded cannot overflow the jar on-stack buffers.
constexpr duetos::u32 kCookieNameCap = 128;
constexpr duetos::u32 kCookieValueCap = 512;
constexpr duetos::u32 kCookieDomCap = 256;
constexpr duetos::u32 kCookiePathCap = 256;

// -----------------------------------------------------------------
// CookieSetFromHeader
//
// Parse a raw Set-Cookie header value (everything after the ": ")
// and upsert into the global jar.
//
// Parameters:
//   host          — hostname that sent the response (ASCII, e.g.
//                   "example.com"). Used as the default domain and
//                   to validate the Domain attribute.
//   req_path      — URL path of the request that received the
//                   Set-Cookie header (e.g. "/foo/bar.html").
//                   Used to derive the default Path attribute.
//   set_cookie_hv — the raw header value string, e.g.
//                   "sid=abc; Domain=.example.com; Path=/; Secure".
//   now_unix      — current UNIX timestamp (seconds since epoch).
//                   Used to evaluate Max-Age and Expires.
//
// Behaviour:
//   - An existing cookie with the same (name, domain, path) triple
//     is replaced.
//   - Max-Age=0 or a past Expires deletes the matching entry (if
//     any) rather than inserting a new one.
//   - If the jar is full, the oldest (lowest slot index) entry is
//     evicted before the new one is inserted.
// -----------------------------------------------------------------
void CookieSetFromHeader(const char* host, const char* req_path, const char* set_cookie_hv, duetos::i64 now_unix);

// -----------------------------------------------------------------
// CookieBuildHeader
//
// Build the value of a "Cookie:" request header for the given URL
// context and write it into `out` (NUL-terminated, at most
// `cap - 1` bytes of content).
//
// Parameters:
//   host     — target hostname (used for domain matching).
//   path     — target URL path (used for path-prefix matching).
//   secure   — true if the connection is HTTPS/TLS.
//   now_unix — current UNIX timestamp; expired cookies are skipped.
//   out      — output buffer.
//   cap      — byte capacity of `out` including the NUL terminator.
//
// Returns: number of bytes written (not counting the NUL).
//
// Ordering: longest path first per RFC 6265 §5.4 pt 2, then by
//           insertion order (earliest first) within the same path
//           length.
// -----------------------------------------------------------------
duetos::u32 CookieBuildHeader(const char* host, const char* path, bool secure, duetos::i64 now_unix, char* out,
                              duetos::u32 cap);

// -----------------------------------------------------------------
// CookieJarLoad / CookieJarSave
//
// Persist the jar to / from the FAT32 root volume at
// kCookieFilePath.  Both are no-ops when no FAT32 volume is
// mounted; callers must not treat a no-op as an error.
//
// Load replaces the in-memory jar with whatever was on disk.
// Save serialises the current in-memory jar to disk.
//
// GAP (disk round-trip): persistence is implemented but only
// exercised at runtime when a FAT32 volume is available. The boot
// self-test exercises the in-memory jar only; real FS I/O is not
// exercised in that path.
// -----------------------------------------------------------------
void CookieJarLoad();
void CookieJarSave();

// Boot self-test. Emits "[cookie-selftest] PASS (...)" on success;
// "[cookie-selftest] FAIL (...)" + kBootSelftestFail probe on any
// failed assertion.
void CookieSelfTest();

} // namespace duetos::net
