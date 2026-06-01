#include "kernel32_internal.h"

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
    lctype &= 0x0FFFFFFFUL;
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

/* In-memory cursor + attribute state. */
static short g_console_cur_x = 0, g_console_cur_y = 0;
static unsigned short g_console_attrs = 0x07;
static int g_console_cursor_visible = 1;
static int g_console_cursor_size = 25; /* pct of cell */

__declspec(dllexport) BOOL GetConsoleScreenBufferInfo(HANDLE h, DUETOS_CONSOLE_SBI* info)
{
    (void)h;
    if (info == (DUETOS_CONSOLE_SBI*)0)
        return 0;
    info->cols = 80;
    info->rows = 25;
    info->cur_x = g_console_cur_x;
    info->cur_y = g_console_cur_y;
    info->attrs = g_console_attrs;
    info->win_left = 0;
    info->win_top = 0;
    info->win_right = 79;
    info->win_bot = 24;
    info->max_cols = 80;
    info->max_rows = 25;
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

__declspec(dllexport) BOOL SetConsoleCursorPosition(HANDLE h, DUETOS_COORD pos)
{
    (void)h;
    g_console_cur_x = pos.x;
    g_console_cur_y = pos.y;
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

__declspec(dllexport) BOOL SetConsoleTextAttribute(HANDLE h, unsigned short attrs)
{
    (void)h;
    g_console_attrs = attrs;
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

__declspec(dllexport) BOOL FillConsoleOutputCharacterA(HANDLE h, char ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    (void)h;
    (void)ch;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputCharacterW(HANDLE h, wchar_t16 ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    (void)h;
    (void)ch;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL GetNumberOfConsoleInputEvents(HANDLE h, DWORD* count)
{
    (void)h;
    if (count != (DWORD*)0)
        *count = 0; /* No queued console input under emulator. */
    return 1;
}
