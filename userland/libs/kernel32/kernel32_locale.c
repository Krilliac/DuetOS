#include "kernel32_console_vt.h" /* screen-buffer mirror VT tracker */
#include "kernel32_internal.h"
#include "kernel32_nls_format.h" /* nls_locale_number (LOCALE_RETURN_NUMBER) */

/* ------------------------------------------------------------------
 * Locale APIs — fixed en-US (LCID 0x0409). DuetOS has no real
 * locale tables yet; these return canned strings keyed off the
 * common LCType selectors that real apps query.
 * ------------------------------------------------------------------ */

#define DUETOS_LCID_EN_US 0x0409UL
#define DUETOS_LANGID_EN_US 0x0409U

__declspec(dllexport) unsigned long GetUserDefaultLCID(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned long GetSystemDefaultLCID(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned long GetThreadLocale(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned short GetUserDefaultLangID(void)
{
    return DUETOS_LANGID_EN_US;
}
__declspec(dllexport) unsigned short GetSystemDefaultLangID(void)
{
    return DUETOS_LANGID_EN_US;
}
__declspec(dllexport) BOOL SetThreadLocale(unsigned long lcid)
{
    (void)lcid;
    return 1;
}

__declspec(dllexport) BOOL IsValidLocale(unsigned long lcid, DWORD flags)
{
    (void)flags;
    return (lcid == DUETOS_LCID_EN_US || lcid == 0x0800 || lcid == 0x0400) ? 1 : 0;
}

/* LCType constant reference (WINNLS.H):
 *   LOCALE_ILANGUAGE       0x0001   hex lang id
 *   LOCALE_SLANGUAGE       0x0002   localised language name
 *   LOCALE_SENGLANGUAGE    0x1001   English language name
 *   LOCALE_SABBREVLANGNAME 0x0003   abbreviated language name
 *   LOCALE_SNATIVELANGNAME 0x0004   native language name
 *   LOCALE_ICOUNTRY        0x0005   country code
 *   LOCALE_SCOUNTRY        0x0006   localised country name
 *   LOCALE_SENGCOUNTRY     0x1002   English country name
 *   LOCALE_SABBREVCTRYNAME 0x0007   abbreviated country name
 *   LOCALE_SNATIVECTRYNAME 0x0008   native country name
 *   LOCALE_SDECIMAL        0x000E   decimal separator
 *   LOCALE_STHOUSAND       0x000F   thousands separator
 *   LOCALE_SGROUPING       0x0010   digit grouping
 *   LOCALE_IDIGITS         0x0011   decimal digit count
 *   LOCALE_ILZERO          0x0012   leading zeros flag
 *   LOCALE_INEGNUMBER      0x1010   negative number format
 *   LOCALE_SCURRENCY       0x0014   local currency symbol
 *   LOCALE_SSHORTDATE      0x001F   short date format picture
 *   LOCALE_SLONGDATE       0x0020   long date format picture
 *   LOCALE_STIMEFORMAT     0x1003   time format picture
 *   LOCALE_SISO639LANGNAME 0x0059   ISO 639 two-letter language code
 *   LOCALE_SISO3166CTRYNAME 0x005A  ISO 3166 two-letter country code
 *   Day/month name LCTypes (LOCALE_SDAYNAME1..7, LOCALE_SMONTHNAME1..12,
 *   LOCALE_SABBREVDAYNAME1..7, LOCALE_SABBREVMONTHNAME1..12)
 */

/* Wide string literals for all en-US locale data entries. */
static const wchar_t16 sLang[] = {'e', 'n', 0};
static const wchar_t16 sCountry[] = {'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', 0};
static const wchar_t16 sCountryAbbrev[] = {'U', 'S', 'A', 0};
static const wchar_t16 sLangName[] = {'E', 'n', 'g', 'l', 'i', 's', 'h', 0};
static const wchar_t16 sIso3166[] = {'U', 'S', 0};
static const wchar_t16 sIso639[] = {'e', 'n', 0};
static const wchar_t16 sDecimal[] = {'.', 0};
static const wchar_t16 sThousand[] = {',', 0};
static const wchar_t16 sGrouping[] = {'3', ';', '0', 0};
static const wchar_t16 sDigits[] = {'2', 0};
static const wchar_t16 sLZero[] = {'1', 0};
static const wchar_t16 sNegNum[] = {'1', 0}; /* -1.1 style */
static const wchar_t16 sCurrency[] = {'$', 0};
/* Short date: M/d/yyyy (en-US locale default) */
static const wchar_t16 sShortDate[] = {'M', '/', 'd', '/', 'y', 'y', 'y', 'y', 0};
/* Long date: dddd, MMMM d, yyyy */
static const wchar_t16 sLongDate[] = {'d', 'd', 'd', 'd', ',', ' ', 'M', 'M', 'M', 'M',
                                      ' ', 'd', ',', ' ', 'y', 'y', 'y', 'y', 0};
/* Time format: h:mm:ss tt (12-hour with AM/PM) */
static const wchar_t16 sTimeFormat[] = {'h', ':', 'm', 'm', ':', 's', 's', ' ', 't', 't', 0};
/* Short time: h:mm tt (LOCALE_SSHORTTIME) */
static const wchar_t16 sShortTime[] = {'h', ':', 'm', 'm', ' ', 't', 't', 0};
/* Hex LANGID string (LOCALE_ILANGUAGE returns "0409" as text). */
static const wchar_t16 sLangId[] = {'0', '4', '0', '9', 0};
/* AM/PM designators (LOCALE_S1159 / LOCALE_S2359). */
static const wchar_t16 sAm[] = {'A', 'M', 0};
static const wchar_t16 sPm[] = {'P', 'M', 0};
/* Obsolete-since-Vista date/time separators, derived from the pictures. */
static const wchar_t16 sDateSep[] = {'/', 0};
static const wchar_t16 sTimeSep[] = {':', 0};

/* Full day names (1=Monday..7=Sunday, Win32 convention) */
static const wchar_t16 sDayMon[] = {'M', 'o', 'n', 'd', 'a', 'y', 0};
static const wchar_t16 sDayTue[] = {'T', 'u', 'e', 's', 'd', 'a', 'y', 0};
static const wchar_t16 sDayWed[] = {'W', 'e', 'd', 'n', 'e', 's', 'd', 'a', 'y', 0};
static const wchar_t16 sDayThu[] = {'T', 'h', 'u', 'r', 's', 'd', 'a', 'y', 0};
static const wchar_t16 sDayFri[] = {'F', 'r', 'i', 'd', 'a', 'y', 0};
static const wchar_t16 sDaySat[] = {'S', 'a', 't', 'u', 'r', 'd', 'a', 'y', 0};
static const wchar_t16 sDaySun[] = {'S', 'u', 'n', 'd', 'a', 'y', 0};

/* Abbreviated day names */
static const wchar_t16 sAbbDayMon[] = {'M', 'o', 'n', 0};
static const wchar_t16 sAbbDayTue[] = {'T', 'u', 'e', 0};
static const wchar_t16 sAbbDayWed[] = {'W', 'e', 'd', 0};
static const wchar_t16 sAbbDayThu[] = {'T', 'h', 'u', 0};
static const wchar_t16 sAbbDayFri[] = {'F', 'r', 'i', 0};
static const wchar_t16 sAbbDaySat[] = {'S', 'a', 't', 0};
static const wchar_t16 sAbbDaySun[] = {'S', 'u', 'n', 0};

/* Full month names (1=January..12=December) */
static const wchar_t16 sMonJan[] = {'J', 'a', 'n', 'u', 'a', 'r', 'y', 0};
static const wchar_t16 sMonFeb[] = {'F', 'e', 'b', 'r', 'u', 'a', 'r', 'y', 0};
static const wchar_t16 sMonMar[] = {'M', 'a', 'r', 'c', 'h', 0};
static const wchar_t16 sMonApr[] = {'A', 'p', 'r', 'i', 'l', 0};
static const wchar_t16 sMonMay[] = {'M', 'a', 'y', 0};
static const wchar_t16 sMonJun[] = {'J', 'u', 'n', 'e', 0};
static const wchar_t16 sMonJul[] = {'J', 'u', 'l', 'y', 0};
static const wchar_t16 sMonAug[] = {'A', 'u', 'g', 'u', 's', 't', 0};
static const wchar_t16 sMonSep[] = {'S', 'e', 'p', 't', 'e', 'm', 'b', 'e', 'r', 0};
static const wchar_t16 sMonOct[] = {'O', 'c', 't', 'o', 'b', 'e', 'r', 0};
static const wchar_t16 sMonNov[] = {'N', 'o', 'v', 'e', 'm', 'b', 'e', 'r', 0};
static const wchar_t16 sMonDec[] = {'D', 'e', 'c', 'e', 'm', 'b', 'e', 'r', 0};

/* Abbreviated month names */
static const wchar_t16 sAbbMonJan[] = {'J', 'a', 'n', 0};
static const wchar_t16 sAbbMonFeb[] = {'F', 'e', 'b', 0};
static const wchar_t16 sAbbMonMar[] = {'M', 'a', 'r', 0};
static const wchar_t16 sAbbMonApr[] = {'A', 'p', 'r', 0};
static const wchar_t16 sAbbMonMay[] = {'M', 'a', 'y', 0};
static const wchar_t16 sAbbMonJun[] = {'J', 'u', 'n', 0};
static const wchar_t16 sAbbMonJul[] = {'J', 'u', 'l', 0};
static const wchar_t16 sAbbMonAug[] = {'A', 'u', 'g', 0};
static const wchar_t16 sAbbMonSep[] = {'S', 'e', 'p', 0};
static const wchar_t16 sAbbMonOct[] = {'O', 'c', 't', 0};
static const wchar_t16 sAbbMonNov[] = {'N', 'o', 'v', 0};
static const wchar_t16 sAbbMonDec[] = {'D', 'e', 'c', 0};

__declspec(dllexport) int GetLocaleInfoW(unsigned long lcid, unsigned long lctype, wchar_t16* buf, int cchData)
{
    (void)lcid;
    /* LOCALE_RETURN_NUMBER (0x20000000): return the value as a binary
     * DWORD rather than a string, and return its size in WCHAR units. */
    int return_number = (lctype & 0x20000000UL) != 0;
    lctype &= 0x0FFFFFFFUL;
    if (return_number)
    {
        unsigned int uval;
        if (!nls_locale_number((unsigned int)lctype, &uval))
            return 0; /* RETURN_NUMBER on a non-numeric LCType is invalid */
        if (cchData == 0)
            return 2; /* a DWORD occupies 2 WCHARs */
        if (buf == (wchar_t16*)0 || cchData < 2)
            return 0;
        DWORD val = (DWORD)uval;
        __builtin_memcpy(buf, &val, sizeof(val));
        return 2;
    }
    const wchar_t16* msg;
    switch (lctype)
    {
    case 0x0002: /* LOCALE_SLANGUAGE / LOCALE_SENGLANGUAGE */
        msg = sLangName;
        break;
    case 0x0006: /* LOCALE_SCOUNTRY */
        msg = sCountry;
        break;
    case 0x0007: /* LOCALE_SABBREVCTRYNAME */
        msg = sCountryAbbrev;
        break;
    case 0x000E: /* LOCALE_SDECIMAL */
        msg = sDecimal;
        break;
    case 0x000F: /* LOCALE_STHOUSAND */
        msg = sThousand;
        break;
    case 0x0010: /* LOCALE_SGROUPING */
        msg = sGrouping;
        break;
    case 0x0011: /* LOCALE_IDIGITS */
        msg = sDigits;
        break;
    case 0x0012: /* LOCALE_ILZERO */
        msg = sLZero;
        break;
    case 0x1010: /* LOCALE_INEGNUMBER */
        msg = sNegNum;
        break;
    case 0x0014: /* LOCALE_SCURRENCY */
        msg = sCurrency;
        break;
    case 0x001F: /* LOCALE_SSHORTDATE */
        msg = sShortDate;
        break;
    case 0x0020: /* LOCALE_SLONGDATE */
        msg = sLongDate;
        break;
    case 0x1003: /* LOCALE_STIMEFORMAT */
        msg = sTimeFormat;
        break;
    /* Full day names: LOCALE_SDAYNAME1..7 = 0x002A..0x0030 */
    case 0x002A:
        msg = sDayMon;
        break;
    case 0x002B:
        msg = sDayTue;
        break;
    case 0x002C:
        msg = sDayWed;
        break;
    case 0x002D:
        msg = sDayThu;
        break;
    case 0x002E:
        msg = sDayFri;
        break;
    case 0x002F:
        msg = sDaySat;
        break;
    case 0x0030:
        msg = sDaySun;
        break;
    /* Abbreviated day names: LOCALE_SABBREVDAYNAME1..7 = 0x0031..0x0037 */
    case 0x0031:
        msg = sAbbDayMon;
        break;
    case 0x0032:
        msg = sAbbDayTue;
        break;
    case 0x0033:
        msg = sAbbDayWed;
        break;
    case 0x0034:
        msg = sAbbDayThu;
        break;
    case 0x0035:
        msg = sAbbDayFri;
        break;
    case 0x0036:
        msg = sAbbDaySat;
        break;
    case 0x0037:
        msg = sAbbDaySun;
        break;
    /* Full month names: LOCALE_SMONTHNAME1..12 = 0x0038..0x0043 */
    case 0x0038:
        msg = sMonJan;
        break;
    case 0x0039:
        msg = sMonFeb;
        break;
    case 0x003A:
        msg = sMonMar;
        break;
    case 0x003B:
        msg = sMonApr;
        break;
    case 0x003C:
        msg = sMonMay;
        break;
    case 0x003D:
        msg = sMonJun;
        break;
    case 0x003E:
        msg = sMonJul;
        break;
    case 0x003F:
        msg = sMonAug;
        break;
    case 0x0040:
        msg = sMonSep;
        break;
    case 0x0041:
        msg = sMonOct;
        break;
    case 0x0042:
        msg = sMonNov;
        break;
    case 0x0043:
        msg = sMonDec;
        break;
    /* Abbreviated month names: LOCALE_SABBREVMONTHNAME1..12 = 0x0044..0x004F */
    case 0x0044:
        msg = sAbbMonJan;
        break;
    case 0x0045:
        msg = sAbbMonFeb;
        break;
    case 0x0046:
        msg = sAbbMonMar;
        break;
    case 0x0047:
        msg = sAbbMonApr;
        break;
    case 0x0048:
        msg = sAbbMonMay;
        break;
    case 0x0049:
        msg = sAbbMonJun;
        break;
    case 0x004A:
        msg = sAbbMonJul;
        break;
    case 0x004B:
        msg = sAbbMonAug;
        break;
    case 0x004C:
        msg = sAbbMonSep;
        break;
    case 0x004D:
        msg = sAbbMonOct;
        break;
    case 0x004E:
        msg = sAbbMonNov;
        break;
    case 0x004F:
        msg = sAbbMonDec;
        break;
    case 0x0059: /* LOCALE_SISO639LANGNAME */
        msg = sIso639;
        break;
    case 0x005A: /* LOCALE_SISO3166CTRYNAME */
        msg = sIso3166;
        break;
    case 0x0001: /* LOCALE_ILANGUAGE — hex LANGID as text */
        msg = sLangId;
        break;
    case 0x0004: /* LOCALE_SNATIVELANGNAME */
    case 0x1001: /* LOCALE_SENGLANGUAGE */
        msg = sLangName;
        break;
    case 0x001D: /* LOCALE_SDATE — date separator (derived) */
        msg = sDateSep;
        break;
    case 0x001E: /* LOCALE_STIME — time separator (derived) */
        msg = sTimeSep;
        break;
    case 0x0028: /* LOCALE_S1159 — AM designator */
        msg = sAm;
        break;
    case 0x0029: /* LOCALE_S2359 — PM designator */
        msg = sPm;
        break;
    case 0x0079: /* LOCALE_SSHORTTIME */
        msg = sShortTime;
        break;
    default:
        msg = sLang;
        break;
    }
    int needed = 0;
    while (msg[needed] != 0)
        ++needed;
    ++needed;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    int j = 0;
    while (msg[j] != 0)
    {
        buf[j] = msg[j];
        ++j;
    }
    buf[j] = 0;
    return needed;
}

/* ------------------------------------------------------------------
 * Userland atom table — 32 slots, shared between local + global
 * (matches older Windows). Atoms in [0xC000, 0xC020).
 * ------------------------------------------------------------------ */

#define DUETOS_ATOM_MAX 32
#define DUETOS_ATOM_BASE 0xC000U

typedef struct
{
    char name[64];
    int in_use;
    unsigned int refcnt;
} DuetosAtomSlot;

static DuetosAtomSlot g_atoms[DUETOS_ATOM_MAX];

static int astr_eq_ci(const char* a, const char* b)
{
    int i = 0;
    for (;;)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
        ++i;
    }
}

static unsigned short atom_add_internal(const char* name)
{
    if (name == (const char*)0)
        return 0;
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (g_atoms[i].in_use && astr_eq_ci(g_atoms[i].name, name))
        {
            g_atoms[i].refcnt++;
            return (unsigned short)(DUETOS_ATOM_BASE + i);
        }
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (!g_atoms[i].in_use)
        {
            int j = 0;
            while (j < 63 && name[j] != 0)
            {
                g_atoms[i].name[j] = name[j];
                ++j;
            }
            g_atoms[i].name[j] = 0;
            g_atoms[i].in_use = 1;
            g_atoms[i].refcnt = 1;
            return (unsigned short)(DUETOS_ATOM_BASE + i);
        }
    return 0;
}

__declspec(dllexport) unsigned short AddAtomA(const char* name)
{
    return atom_add_internal(name);
}
__declspec(dllexport) unsigned short GlobalAddAtomA(const char* name)
{
    return atom_add_internal(name);
}

__declspec(dllexport) unsigned short FindAtomA(const char* name)
{
    if (name == (const char*)0)
        return 0;
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (g_atoms[i].in_use && astr_eq_ci(g_atoms[i].name, name))
            return (unsigned short)(DUETOS_ATOM_BASE + i);
    return 0;
}
__declspec(dllexport) unsigned short GlobalFindAtomA(const char* name)
{
    return FindAtomA(name);
}

__declspec(dllexport) unsigned int GlobalGetAtomNameA(unsigned short atom, char* buf, int cch)
{
    if (atom < DUETOS_ATOM_BASE || buf == (char*)0 || cch == 0)
        return 0;
    int idx = atom - DUETOS_ATOM_BASE;
    if (idx < 0 || idx >= DUETOS_ATOM_MAX || !g_atoms[idx].in_use)
        return 0;
    int j = 0;
    while (j < cch - 1 && g_atoms[idx].name[j] != 0)
    {
        buf[j] = g_atoms[idx].name[j];
        ++j;
    }
    buf[j] = 0;
    return (unsigned int)j;
}
__declspec(dllexport) unsigned int GetAtomNameA(unsigned short atom, char* buf, int cch)
{
    return GlobalGetAtomNameA(atom, buf, cch);
}

__declspec(dllexport) unsigned short GlobalDeleteAtom(unsigned short atom)
{
    if (atom < DUETOS_ATOM_BASE)
        return atom;
    int idx = atom - DUETOS_ATOM_BASE;
    if (idx < 0 || idx >= DUETOS_ATOM_MAX || !g_atoms[idx].in_use)
        return atom;
    if (--g_atoms[idx].refcnt == 0)
        g_atoms[idx].in_use = 0;
    return 0;
}
__declspec(dllexport) unsigned short DeleteAtom(unsigned short atom)
{
    return GlobalDeleteAtom(atom);
}

/* GetTimeZoneInformation — return UTC-0 with no DST. */
typedef struct
{
    long Bias;
    wchar_t16 StandardName[32];
    unsigned short StandardDateY, StandardDateM, StandardDateDayOfWeek, StandardDateDay;
    unsigned short StandardDateH, StandardDateMin, StandardDateS, StandardDateMs;
    long StandardBias;
    wchar_t16 DaylightName[32];
    unsigned short DaylightDateY, DaylightDateM, DaylightDateDayOfWeek, DaylightDateDay;
    unsigned short DaylightDateH, DaylightDateMin, DaylightDateS, DaylightDateMs;
    long DaylightBias;
} DUETOS_TZ_INFORMATION;

__declspec(dllexport) DWORD GetTimeZoneInformation(DUETOS_TZ_INFORMATION* tzi)
{
    if (tzi == (DUETOS_TZ_INFORMATION*)0)
        return 0xFFFFFFFFUL;
    unsigned char* b = (unsigned char*)tzi;
    for (unsigned long i = 0; i < sizeof(*tzi); ++i)
        b[i] = 0;
    static const wchar_t16 utc[] = {'U', 'T', 'C', 0};
    for (int i = 0; utc[i] != 0; ++i)
        tzi->StandardName[i] = utc[i];
    return 1;
}

typedef struct
{
    short cols, rows;
    short cur_x, cur_y;
    unsigned short attrs;
    short win_left, win_top, win_right, win_bot;
    short max_cols, max_rows;
} DUETOS_CONSOLE_SBI;

/* In-memory screen-buffer mirror: cursor + attributes + the VT
 * tracker state (kernel32_console_vt.h). Explicit console API
 * calls (SetConsoleCursorPosition / SetConsoleTextAttribute) and
 * VT sequences written under ENABLE_VIRTUAL_TERMINAL_PROCESSING
 * both land here, so GetConsoleScreenBufferInfo reflects either
 * control style. Field order: cols, rows, cur_x, cur_y, attrs,
 * then zeroed parser state. */
static duetos_cvt_state g_console_mirror = {80, 25, 0, 0, 0x07, 0, 0, 0, 0, {0}};
static int g_console_cursor_visible = 1;
static int g_console_cursor_size = 25; /* pct of cell */

/* Cross-TU entry (declared in kernel32_internal.h): observe bytes
 * written to a console OUTPUT handle. Only stdout/stderr with
 * ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4) feed the tracker — on
 * the stdin handle the same bit means ENABLE_ECHO_INPUT, so input
 * handles never reach the mirror. */
void kernel32_console_vt_observe(HANDLE h, const void* buf, DWORD len)
{
    const unsigned long long raw = (unsigned long long)(UINT_PTR)h;
    if (raw != 0xFFFFFFF5ULL && raw != 0xFFFFFFF4ULL) /* STD_OUTPUT / STD_ERROR only */
        return;
    if ((kernel32_console_mode_of(h) & 0x4u) == 0)
        return;
    duetos_cvt_feed(&g_console_mirror, (const unsigned char*)buf, len);
}

/* Emit raw bytes to stdout via SYS_WRITE(fd=1). Used by
 * SetConsoleCursorPosition, SetConsoleTextAttribute and
 * FillConsoleOutputCharacterA to push ANSI escapes to the
 * kernel terminal. */
static void console_emit_raw(const char* buf, int len)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)2), /* SYS_WRITE */
                       "D"((long long)1), /* fd=1 stdout */
                       "S"((long long)buf), "d"((long long)len)
                     : "memory");
}

/* Format a small unsigned int (0..9999) into `out`, returning
 * the number of digits written. No NUL terminator. */
static int console_itoa(unsigned v, char* out)
{
    if (v == 0)
    {
        out[0] = '0';
        return 1;
    }
    char tmp[8];
    int n = 0;
    while (v > 0)
    {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0; i < n; ++i)
        out[i] = tmp[n - 1 - i];
    return n;
}

__declspec(dllexport) BOOL GetConsoleScreenBufferInfo(HANDLE h, DUETOS_CONSOLE_SBI* info)
{
    (void)h;
    if (info == (DUETOS_CONSOLE_SBI*)0)
        return 0;
    info->cols = g_console_mirror.cols;
    info->rows = g_console_mirror.rows;
    /* The tracker uses deferred wrap (cursor may sit at x == cols
     * after filling the last column, like the kernel Terminal);
     * Win32 reports the cursor inside the buffer, so clamp. */
    info->cur_x =
        (g_console_mirror.cur_x >= g_console_mirror.cols) ? (short)(g_console_mirror.cols - 1) : g_console_mirror.cur_x;
    info->cur_y = g_console_mirror.cur_y;
    info->attrs = g_console_mirror.attrs;
    info->win_left = 0;
    info->win_top = 0;
    info->win_right = (short)(g_console_mirror.cols - 1);
    info->win_bot = (short)(g_console_mirror.rows - 1);
    info->max_cols = g_console_mirror.cols;
    info->max_rows = g_console_mirror.rows;
    return 1;
}

typedef struct
{
    short x, y;
} DUETOS_COORD;
typedef struct
{
    DWORD size;
    BOOL visible;
} DUETOS_CONSOLE_CURSOR_INFO;

/* SetConsoleCursorPosition — store + emit ESC[row;colH.
 * Win32 COORD is 0-based; ANSI CUP is 1-based. */
__declspec(dllexport) BOOL SetConsoleCursorPosition(HANDLE h, DUETOS_COORD pos)
{
    (void)h;
    g_console_mirror.cur_x = pos.x;
    g_console_mirror.cur_y = pos.y;
    /* Emit ANSI CUP: ESC [ <row+1> ; <col+1> H */
    char esc[24];
    int p = 0;
    esc[p++] = '\x1b';
    esc[p++] = '[';
    p += console_itoa((unsigned)(pos.y + 1), esc + p);
    esc[p++] = ';';
    p += console_itoa((unsigned)(pos.x + 1), esc + p);
    esc[p++] = 'H';
    console_emit_raw(esc, p);
    return 1;
}

__declspec(dllexport) BOOL GetConsoleCursorInfo(HANDLE h, DUETOS_CONSOLE_CURSOR_INFO* ci)
{
    (void)h;
    if (ci == (DUETOS_CONSOLE_CURSOR_INFO*)0)
        return 0;
    ci->size = (DWORD)g_console_cursor_size;
    ci->visible = g_console_cursor_visible;
    return 1;
}

__declspec(dllexport) BOOL SetConsoleCursorInfo(HANDLE h, const DUETOS_CONSOLE_CURSOR_INFO* ci)
{
    (void)h;
    if (ci == (const DUETOS_CONSOLE_CURSOR_INFO*)0)
        return 0;
    g_console_cursor_size = (int)ci->size;
    g_console_cursor_visible = ci->visible ? 1 : 0;
    return 1;
}

/* SetConsoleTextAttribute — store + emit ANSI SGR.
 *
 * Win32 attribute bits:
 *   0x01 FOREGROUND_BLUE    0x10 BACKGROUND_BLUE
 *   0x02 FOREGROUND_GREEN   0x20 BACKGROUND_GREEN
 *   0x04 FOREGROUND_RED     0x40 BACKGROUND_RED
 *   0x08 FOREGROUND_INTENSITY  0x80 BACKGROUND_INTENSITY
 *
 * ANSI SGR: 30-37 = fg, 40-47 = bg, 90-97 = bright fg,
 * 100-107 = bright bg. Win32 color order is BGR; ANSI is
 * BGR too (30=black,31=red,32=green,33=yellow,34=blue,
 * 35=magenta,36=cyan,37=white).
 *
 * Win32 bit layout → ANSI index mapping:
 *   bits[2:0] = R,G,B → ANSI = 30 + (B<<2|G<<1|R) with
 *   R and B swapped: win32 bit0=B,bit1=G,bit2=R →
 *   ANSI index = (bit2>>2)|(bit1)|(bit0<<2) =
 *   swap bit0 and bit2. */
static unsigned short win32_color_to_ansi_idx(unsigned short c)
{
    /* c is a 3-bit Win32 color: bit0=BLUE, bit1=GREEN, bit2=RED.
     * ANSI: bit0=RED, bit1=GREEN, bit2=BLUE. Swap bits 0 and 2. */
    unsigned short r = (c >> 2) & 1; /* Win32 RED  -> ANSI bit0 */
    unsigned short g = (c >> 1) & 1; /* Win32 GREEN stays */
    unsigned short b = c & 1;        /* Win32 BLUE -> ANSI bit2 */
    return (b << 2) | (g << 1) | r;
}

__declspec(dllexport) BOOL SetConsoleTextAttribute(HANDLE h, unsigned short attrs)
{
    (void)h;
    g_console_mirror.attrs = attrs;
    /* Emit ANSI SGR: ESC [ 0 ; <fg> ; <bg> m */
    unsigned short fg3 = attrs & 0x07;
    int fg_bright = (attrs & 0x08) ? 1 : 0;
    unsigned short bg3 = (attrs >> 4) & 0x07;
    int bg_bright = (attrs & 0x80) ? 1 : 0;
    unsigned short fg_code = (fg_bright ? 90 : 30) + win32_color_to_ansi_idx(fg3);
    unsigned short bg_code = (bg_bright ? 100 : 40) + win32_color_to_ansi_idx(bg3);
    char esc[24];
    int p = 0;
    esc[p++] = '\x1b';
    esc[p++] = '[';
    esc[p++] = '0'; /* reset first */
    esc[p++] = ';';
    p += console_itoa(fg_code, esc + p);
    esc[p++] = ';';
    p += console_itoa(bg_code, esc + p);
    esc[p++] = 'm';
    console_emit_raw(esc, p);
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputAttribute(HANDLE h, unsigned short attr, DWORD count, DUETOS_COORD origin,
                                                      DWORD* written)
{
    (void)h;
    (void)attr;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

/* FillConsoleOutputCharacterA — emit fill characters.
 *
 * The most common call pattern is FillConsoleOutputCharacterA(
 * hOut, ' ', cols*rows, {0,0}, &written) — i.e. "clear the
 * screen." We detect that (ch==' ' && origin=={0,0} && count
 * >= 80*25) and emit ESC[2J ESC[H (clear+home) instead of
 * 2000 spaces. For other calls, emit the character `count`
 * times in batches through SYS_WRITE. */
__declspec(dllexport) BOOL FillConsoleOutputCharacterA(HANDLE h, char ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    (void)h;
    if (ch == ' ' && origin.x == 0 && origin.y == 0 && count >= 80u * 25u)
    {
        /* Screen-clear shortcut. */
        console_emit_raw("\x1b[2J\x1b[H", 7);
    }
    else
    {
        /* Emit `count` copies of `ch` in 128-byte batches. */
        char batch[128];
        for (int i = 0; i < 128; ++i)
            batch[i] = ch;
        DWORD remaining = count;
        while (remaining > 0)
        {
            int n = remaining > 128 ? 128 : (int)remaining;
            console_emit_raw(batch, n);
            remaining -= (DWORD)n;
        }
    }
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputCharacterW(HANDLE h, wchar_t16 ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    /* Route through the A variant with low-byte strip. */
    return FillConsoleOutputCharacterA(h, (char)(ch & 0xFF), count, origin, written);
}

/* GetNumberOfConsoleInputEvents moved to kernel32_console.c, which
 * owns the INPUT_RECORD queue it reports on. */

/* ------------------------------------------------------------------
 * Local-time conversion
 *
 * Both entry points below are exact arithmetic over whatever
 * TIME_ZONE_INFORMATION they are handed. The only thing DuetOS
 * cannot supply is a zoneinfo database, so the *current* zone
 * (GetTimeZoneInformation, above) is UTC with a zero bias — a
 * caller that passes its own TIME_ZONE_INFORMATION gets a correct
 * conversion for that zone's standard time.
 * ------------------------------------------------------------------ */

/* Win32 SYSTEMTIME. Layout must match kernel32_io.c's copy —
 * FileTimeToSystemTime / SystemTimeToFileTime are the workhorses
 * this slice composes with. */
typedef struct
{
    unsigned short y, m, dow, d, h, min, s, ms;
} DUETOS_SYSTEMTIME_TZ;

__declspec(dllexport) BOOL SystemTimeToFileTime(const DUETOS_SYSTEMTIME_TZ* st, void* ft);
__declspec(dllexport) BOOL FileTimeToSystemTime(const void* ft, DUETOS_SYSTEMTIME_TZ* st);

/* FileTimeToLocalFileTime — UTC FILETIME to local FILETIME.
 * Win32 subtracts the active zone's bias (which is expressed as
 * "UTC = local + Bias" minutes, so local = UTC - Bias). */
__declspec(dllexport) BOOL FileTimeToLocalFileTime(const void* utc, void* local)
{
    if (utc == (const void*)0 || local == (void*)0)
        return 0;
    DUETOS_TZ_INFORMATION tzi;
    if (GetTimeZoneInformation(&tzi) == 0xFFFFFFFFUL)
        return 0;
    const long long bias_100ns = (long long)tzi.Bias * 60LL * 10000000LL;
    *(long long*)local = *(const long long*)utc - bias_100ns;
    return 1;
}

/* SystemTimeToTzSpecificLocalTime — UTC SYSTEMTIME to the local
 * SYSTEMTIME of `tzi` (NULL = the active zone). Bias and
 * StandardBias are applied exactly. */
// GAP: DaylightDate/StandardDate transition rules are not evaluated, so
// DaylightBias never applies and the result is always the zone's standard
// time — revisit when a zoneinfo database and a DST-aware clock land.
__declspec(dllexport) BOOL SystemTimeToTzSpecificLocalTime(const DUETOS_TZ_INFORMATION* tzi,
                                                           const DUETOS_SYSTEMTIME_TZ* utc, DUETOS_SYSTEMTIME_TZ* local)
{
    if (utc == (const DUETOS_SYSTEMTIME_TZ*)0 || local == (DUETOS_SYSTEMTIME_TZ*)0)
        return 0;

    DUETOS_TZ_INFORMATION active;
    if (tzi == (const DUETOS_TZ_INFORMATION*)0)
    {
        if (GetTimeZoneInformation(&active) == 0xFFFFFFFFUL)
            return 0;
        tzi = &active;
    }

    long long ticks = 0;
    if (!SystemTimeToFileTime(utc, &ticks))
        return 0;
    const long long bias_100ns = ((long long)tzi->Bias + (long long)tzi->StandardBias) * 60LL * 10000000LL;
    ticks -= bias_100ns;
    if (ticks < 0)
        return 0;
    return FileTimeToSystemTime(&ticks, local);
}

/* ------------------------------------------------------------------
 * Ordinal comparison + locale-name mapping
 * ------------------------------------------------------------------ */

/* CompareStringOrdinal — code-unit comparison, no collation. This
 * is the one string comparison whose Win32 contract asks for
 * exactly what a from-scratch OS can deliver: compare UTF-16 code
 * units, optionally after an invariant upper-case fold.
 *
 * Returns CSTR_LESS_THAN(1) / CSTR_EQUAL(2) / CSTR_GREATER_THAN(3),
 * or 0 with ERROR_INVALID_PARAMETER on a bad argument. */
__declspec(dllexport) int CompareStringOrdinal(const wchar_t16* lhs, int cchLhs, const wchar_t16* rhs, int cchRhs,
                                               BOOL bIgnoreCase)
{
    if (lhs == (const wchar_t16*)0 || rhs == (const wchar_t16*)0)
    {
        SetLastError(87 /* ERROR_INVALID_PARAMETER */);
        return 0;
    }
    int n1 = cchLhs;
    if (n1 < 0)
    {
        n1 = 0;
        while (lhs[n1] != 0)
            ++n1;
    }
    int n2 = cchRhs;
    if (n2 < 0)
    {
        n2 = 0;
        while (rhs[n2] != 0)
            ++n2;
    }
    const int n = n1 < n2 ? n1 : n2;
    for (int i = 0; i < n; ++i)
    {
        wchar_t16 a = lhs[i];
        wchar_t16 b = rhs[i];
        if (bIgnoreCase)
        {
            /* Win32 folds to UPPER case here (OrdinalIgnoreCase is
             * defined as an invariant upper-case map), which matters
             * for the ASCII range where '_' (0x5F) sorts between the
             * upper and lower alphabets. */
            if (a >= 'a' && a <= 'z')
                a = (wchar_t16)(a - ('a' - 'A'));
            if (b >= 'a' && b <= 'z')
                b = (wchar_t16)(b - ('a' - 'A'));
        }
        if (a < b)
            return 1;
        if (a > b)
            return 3;
    }
    if (n1 < n2)
        return 1;
    if (n1 > n2)
        return 3;
    return 2;
}

/* FindStringOrdinal — ordinal substring search, the natural sibling
 * of CompareStringOrdinal above and the other half of the pair the
 * ordinal-comparison APIs come in.
 *
 * Returns the 0-based index of the match in lpStringSource, or -1
 * when there is no match (and -1 + ERROR_INVALID_PARAMETER on a bad
 * argument, which the caller distinguishes via GetLastError).
 * A negative cch means "null-terminated". */
__declspec(dllexport) int FindStringOrdinal(DWORD dwFindStringOrdinalFlags, const wchar_t16* lpStringSource,
                                            int cchSource, const wchar_t16* lpStringValue, int cchValue,
                                            BOOL bIgnoreCase)
{
    const DWORD FIND_STARTSWITH = 0x00100000UL;
    const DWORD FIND_ENDSWITH = 0x00200000UL;
    const DWORD FIND_FROMSTART = 0x00400000UL;
    const DWORD FIND_FROMEND = 0x00800000UL;

    if (lpStringSource == (const wchar_t16*)0 || lpStringValue == (const wchar_t16*)0)
    {
        SetLastError(87 /* ERROR_INVALID_PARAMETER */);
        return -1;
    }
    if ((dwFindStringOrdinalFlags & (FIND_STARTSWITH | FIND_ENDSWITH | FIND_FROMSTART | FIND_FROMEND)) == 0)
    {
        SetLastError(87 /* ERROR_INVALID_PARAMETER */);
        return -1;
    }

    int n_src = cchSource;
    if (n_src < 0)
    {
        n_src = 0;
        while (lpStringSource[n_src] != 0)
            ++n_src;
    }
    int n_val = cchValue;
    if (n_val < 0)
    {
        n_val = 0;
        while (lpStringValue[n_val] != 0)
            ++n_val;
    }

    /* An empty needle matches at the anchor the search direction
     * implies — Win32 reports 0 searching forward and cchSource
     * searching backward. */
    if (n_val == 0)
        return (dwFindStringOrdinalFlags & (FIND_FROMEND | FIND_ENDSWITH)) ? n_src : 0;
    if (n_val > n_src)
        return -1;

    if (dwFindStringOrdinalFlags & FIND_STARTSWITH)
        return CompareStringOrdinal(lpStringSource, n_val, lpStringValue, n_val, bIgnoreCase) == 2 ? 0 : -1;
    if (dwFindStringOrdinalFlags & FIND_ENDSWITH)
    {
        const int at = n_src - n_val;
        return CompareStringOrdinal(lpStringSource + at, n_val, lpStringValue, n_val, bIgnoreCase) == 2 ? at : -1;
    }

    const int last = n_src - n_val;
    if (dwFindStringOrdinalFlags & FIND_FROMEND)
    {
        for (int at = last; at >= 0; --at)
        {
            if (CompareStringOrdinal(lpStringSource + at, n_val, lpStringValue, n_val, bIgnoreCase) == 2)
                return at;
        }
        return -1;
    }
    for (int at = 0; at <= last; ++at)
    {
        if (CompareStringOrdinal(lpStringSource + at, n_val, lpStringValue, n_val, bIgnoreCase) == 2)
            return at;
    }
    return -1;
}

/* LCIDToLocaleName — LCID to BCP-47 name. An LCID with no installed
 * locale fails with ERROR_INVALID_PARAMETER, which is the documented
 * Win32 behaviour, so callers branch correctly. */
// GAP: only en-US (the one installed locale) and the invariant / neutral /
// system-default pseudo-LCIDs resolve — extend the table when a second
// locale ships.
__declspec(dllexport) int LCIDToLocaleName(unsigned long lcid, wchar_t16* name, int cchName, DWORD dwFlags)
{
    (void)dwFlags;
    static const wchar_t16 k_en_us[] = {'e', 'n', '-', 'U', 'S', 0};
    static const wchar_t16 k_invariant[] = {0};

    const wchar_t16* pick;
    int len;
    if (lcid == 0x007F) /* LOCALE_INVARIANT */
    {
        pick = k_invariant;
        len = 0;
    }
    else if (lcid == DUETOS_LCID_EN_US || lcid == 0x0400 /* USER_DEFAULT */
             || lcid == 0x0800 /* SYSTEM_DEFAULT */ || lcid == 0x0C00 /* CUSTOM_DEFAULT */)
    {
        pick = k_en_us;
        len = 5;
    }
    else
    {
        SetLastError(87 /* ERROR_INVALID_PARAMETER */);
        return 0;
    }

    /* cchName == 0 is the documented "how big a buffer do I need"
     * probe; it returns the length including the terminator. */
    if (cchName == 0)
        return len + 1;
    if (name == (wchar_t16*)0 || cchName < len + 1)
    {
        SetLastError(122 /* ERROR_INSUFFICIENT_BUFFER */);
        return 0;
    }
    for (int i = 0; i < len; ++i)
        name[i] = pick[i];
    name[len] = 0;
    return len + 1;
}

/* SetThreadUILanguage — Win32 returns the LANGID actually selected,
 * which may differ from the request when the asked-for language is
 * not installed (0 means "pick the best match for the console
 * code page"). Callers that check the return value behave
 * correctly — this is the same shape Windows exhibits on a
 * single-language install. */
// GAP: en-US is the only installed UI language, so every request resolves
// to it and a caller that assumes its request was honoured renders en-US —
// revisit when a second UI language ships.
__declspec(dllexport) unsigned short SetThreadUILanguage(unsigned short LangId)
{
    (void)LangId;
    return DUETOS_LANGID_EN_US;
}

/* GetProductInfo — the Windows *edition* selector. Win32 requires
 * FALSE + PRODUCT_UNDEFINED when the caller asks about a newer OS
 * than the one running, which we honour. */
// GAP: DuetOS has no edition concept — we answer PRODUCT_PROFESSIONAL, the
// edition consistent with the version GetVersionExW already reports, so a
// feature gated on "not Home / not Server" sees the same answer everywhere.
__declspec(dllexport) BOOL GetProductInfo(DWORD dwOSMajor, DWORD dwOSMinor, DWORD dwSpMajor, DWORD dwSpMinor,
                                          DWORD* pdwReturnedProductType)
{
    (void)dwSpMajor;
    (void)dwSpMinor;
    if (pdwReturnedProductType == (DWORD*)0)
        return 0;
    /* We report ourselves as 10.0; anything above that is a query
     * about a future OS. */
    if (dwOSMajor > 10 || (dwOSMajor == 10 && dwOSMinor > 0))
    {
        *pdwReturnedProductType = 0x00000000; /* PRODUCT_UNDEFINED */
        return 0;
    }
    *pdwReturnedProductType = 0x00000030; /* PRODUCT_PROFESSIONAL */
    return 1;
}
