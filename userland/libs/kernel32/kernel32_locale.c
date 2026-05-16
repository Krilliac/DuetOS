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

__declspec(dllexport) int GetLocaleInfoW(unsigned long lcid, unsigned long lctype, wchar_t16* buf, int cchData)
{
    (void)lcid;
    lctype &= 0x0FFFFFFF;
    static const wchar_t16 sLang[] = {'e', 'n', 0};
    static const wchar_t16 sCountry[] = {'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', 0};
    static const wchar_t16 sCountryAbbrev[] = {'U', 'S', 'A', 0};
    static const wchar_t16 sLangName[] = {'E', 'n', 'g', 'l', 'i', 's', 'h', 0};
    static const wchar_t16 sIso3166[] = {'U', 'S', 0};
    static const wchar_t16 sIso639[] = {'e', 'n', 0};
    static const wchar_t16 sDecimal[] = {'.', 0};
    static const wchar_t16 sThousand[] = {',', 0};
    const wchar_t16* msg;
    switch (lctype)
    {
    case 0x0002:
        msg = sLangName;
        break;
    case 0x0006:
        msg = sCountry;
        break;
    case 0x0007:
        msg = sCountryAbbrev;
        break;
    case 0x000E:
        msg = sDecimal;
        break;
    case 0x000F:
        msg = sThousand;
        break;
    case 0x0059:
        msg = sIso639;
        break;
    case 0x005A:
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
