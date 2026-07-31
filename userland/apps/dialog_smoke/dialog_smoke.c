/*
 * dialog_smoke -- exercise the Win32 dialog manager.
 *
 * Builds a DLGTEMPLATE in memory (no PE resources), creates a
 * modal dialog via DialogBoxIndirectParamA, and verifies:
 *
 *   - WM_INITDIALOG fires
 *   - GetDlgItem returns non-NULL for known control IDs
 *   - PostMessageA + EndDialog unwind the modal loop
 *   - DialogBoxIndirectParamA returns the expected exit code
 *
 * Controls in the template:
 *   STATIC  (class 0x0082)  id=100  "Hello Dialog"
 *   BUTTON  (class 0x0080)  id=1    "OK"       (IDOK)
 *   BUTTON  (class 0x0080)  id=2    "Cancel"   (IDCANCEL)
 */
#include <windows.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

/* Track failures observed inside the dialog proc. */
static int g_initFired = 0;
static int g_getDlgItemOk = 1;
static int g_getDlgItemStatic = 1;

/* ------------------------------------------------------------------ */
/*  DLGTEMPLATE builder helpers                                       */
/* ------------------------------------------------------------------ */

/* Round a byte offset up to the next DWORD boundary. */
static DWORD AlignDword(DWORD off)
{
    return (off + 3) & ~(DWORD)3;
}

static void PutWord(unsigned char* buf, DWORD* off, WORD val)
{
    buf[*off] = (unsigned char)(val & 0xFF);
    buf[*off + 1] = (unsigned char)((val >> 8) & 0xFF);
    *off += 2;
}

static void PutDword(unsigned char* buf, DWORD* off, DWORD val)
{
    buf[*off] = (unsigned char)(val & 0xFF);
    buf[*off + 1] = (unsigned char)((val >> 8) & 0xFF);
    buf[*off + 2] = (unsigned char)((val >> 16) & 0xFF);
    buf[*off + 3] = (unsigned char)((val >> 24) & 0xFF);
    *off += 4;
}

/* Write a narrow ASCII string as a null-terminated WCHAR sequence. */
static void PutWstr(unsigned char* buf, DWORD* off, const char* s)
{
    while (*s)
    {
        PutWord(buf, off, (WORD)(unsigned char)*s);
        ++s;
    }
    PutWord(buf, off, 0); /* null terminator */
}

/* ------------------------------------------------------------------ */
/*  Dialog procedure                                                  */
/* ------------------------------------------------------------------ */

static INT_PTR CALLBACK DlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    (void)lParam;

    switch (msg)
    {
    case WM_INITDIALOG:
        g_initFired = 1;

        /* Verify GetDlgItem for the OK button (IDOK = 1). */
        if (GetDlgItem(dlg, IDOK) == NULL)
            g_getDlgItemOk = 0;

        /* Verify GetDlgItem for the STATIC label (id = 100). */
        if (GetDlgItem(dlg, 100) == NULL)
            g_getDlgItemStatic = 0;

        /* Post WM_COMMAND / IDOK to ourselves so EndDialog fires
         * and the modal loop unwinds without user interaction. */
        PostMessageA(dlg, WM_COMMAND, (WPARAM)IDOK, 0);
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  Template builder                                                  */
/* ------------------------------------------------------------------ */

/*
 * Build a DLGTEMPLATE + 3 DLGITEMTEMPLATE entries in |buf|.
 * Returns the total byte count consumed (always <= bufSize).
 *
 * Layout reference (all little-endian, WORD-aligned header fields,
 * each DLGITEMTEMPLATE starts on a DWORD boundary):
 *
 * DLGTEMPLATE:
 *   DWORD style
 *   DWORD dwExtendedStyle
 *   WORD  cdit
 *   short x, y, cx, cy
 *   WORD  menu   (0x0000 = none)
 *   WORD  class  (0x0000 = default)
 *   WCHAR title[]
 *
 * DLGITEMTEMPLATE (DWORD-aligned):
 *   DWORD style
 *   DWORD dwExtendedStyle
 *   short x, y, cx, cy
 *   WORD  id
 *   WORD  0xFFFF, WORD classOrdinal   (predefined class)
 *   WCHAR title[]
 *   WORD  extraCount (0x0000)
 */
static DWORD BuildTemplate(unsigned char* buf, DWORD bufSize)
{
    DWORD off = 0;
    DWORD i;

    /* Zero the buffer. */
    for (i = 0; i < bufSize; ++i)
        buf[i] = 0;

    /* --- DLGTEMPLATE -------------------------------------------- */
    /* style: WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME */
    PutDword(buf, &off, 0x80C80080UL);
    /* dwExtendedStyle */
    PutDword(buf, &off, 0);
    /* cdit = 3 items */
    PutWord(buf, &off, 3);
    /* x, y, cx, cy (dialog units) */
    PutWord(buf, &off, 0);   /* x   */
    PutWord(buf, &off, 0);   /* y   */
    PutWord(buf, &off, 200); /* cx  */
    PutWord(buf, &off, 100); /* cy  */
    /* menu = none */
    PutWord(buf, &off, 0);
    /* class = default */
    PutWord(buf, &off, 0);
    /* title = "Test" */
    PutWstr(buf, &off, "Test");

    /* --- Item 1: STATIC label, id=100 -------------------------- */
    off = AlignDword(off);
    /* style: WS_CHILD | WS_VISIBLE | SS_LEFT */
    PutDword(buf, &off, 0x50000000UL);
    /* dwExtendedStyle */
    PutDword(buf, &off, 0);
    /* x, y, cx, cy */
    PutWord(buf, &off, 10); /* x   */
    PutWord(buf, &off, 10); /* y   */
    PutWord(buf, &off, 80); /* cx  */
    PutWord(buf, &off, 10); /* cy  */
    /* id */
    PutWord(buf, &off, 100);
    /* class: predefined ordinal 0x0082 (STATIC) */
    PutWord(buf, &off, 0xFFFF);
    PutWord(buf, &off, 0x0082);
    /* title */
    PutWstr(buf, &off, "Hello Dialog");
    /* extraCount */
    PutWord(buf, &off, 0);

    /* --- Item 2: BUTTON "OK", id=IDOK (1) ---------------------- */
    off = AlignDword(off);
    /* style: WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON */
    PutDword(buf, &off, 0x50000001UL);
    /* dwExtendedStyle */
    PutDword(buf, &off, 0);
    /* x, y, cx, cy */
    PutWord(buf, &off, 40); /* x   */
    PutWord(buf, &off, 70); /* y   */
    PutWord(buf, &off, 50); /* cx  */
    PutWord(buf, &off, 14); /* cy  */
    /* id = IDOK */
    PutWord(buf, &off, 1);
    /* class: predefined ordinal 0x0080 (BUTTON) */
    PutWord(buf, &off, 0xFFFF);
    PutWord(buf, &off, 0x0080);
    /* title */
    PutWstr(buf, &off, "OK");
    /* extraCount */
    PutWord(buf, &off, 0);

    /* --- Item 3: BUTTON "Cancel", id=IDCANCEL (2) -------------- */
    off = AlignDword(off);
    /* style: WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON */
    PutDword(buf, &off, 0x50000000UL);
    /* dwExtendedStyle */
    PutDword(buf, &off, 0);
    /* x, y, cx, cy */
    PutWord(buf, &off, 110); /* x   */
    PutWord(buf, &off, 70);  /* y   */
    PutWord(buf, &off, 50);  /* cx  */
    PutWord(buf, &off, 14);  /* cy  */
    /* id = IDCANCEL */
    PutWord(buf, &off, 2);
    /* class: predefined ordinal 0x0080 (BUTTON) */
    PutWord(buf, &off, 0xFFFF);
    PutWord(buf, &off, 0x0080);
    /* title */
    PutWstr(buf, &off, "Cancel");
    /* extraCount */
    PutWord(buf, &off, 0);

    return off;
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                       */
/* ------------------------------------------------------------------ */

void __cdecl mainCRTStartup(void)
{
    Out("[dialog_smoke] starting\r\n");

    /* Build the in-memory dialog template. */
    __attribute__((aligned(4))) unsigned char tmpl[512];
    DWORD tmplSize = BuildTemplate(tmpl, sizeof(tmpl));
    (void)tmplSize;

    Out("[dialog_smoke] template built\r\n");

    /* Launch the modal dialog. The DlgProc posts IDOK to itself
     * during WM_INITDIALOG, so this returns without user input. */
    INT_PTR ret = DialogBoxIndirectParamA(NULL,                 /* hInstance     */
                                          (LPCDLGTEMPLATE)tmpl, /* lpTemplate    */
                                          NULL,                 /* hWndParent    */
                                          DlgProc,              /* lpDialogFunc  */
                                          0);                   /* dwInitParam   */

    /* --- Report sub-checks ------------------------------------ */

    Out("[dialog_smoke] WM_INITDIALOG fired    = ");
    Out(g_initFired ? "PASS\r\n" : "FAIL\r\n");

    Out("[dialog_smoke] GetDlgItem(IDOK)       = ");
    Out(g_getDlgItemOk ? "PASS\r\n" : "FAIL\r\n");

    Out("[dialog_smoke] GetDlgItem(100)        = ");
    Out(g_getDlgItemStatic ? "PASS\r\n" : "FAIL\r\n");

    Out("[dialog_smoke] DialogBox returned IDOK = ");
    Out(ret == IDOK ? "PASS\r\n" : "FAIL\r\n");

    /* --- Final verdict ---------------------------------------- */

    if (g_initFired && g_getDlgItemOk && g_getDlgItemStatic && ret == IDOK)
    {
        Out("[ring3-dialog-smoke] PASS\r\n");
    }
    else
    {
        Out("[ring3-dialog-smoke] FAIL checks:");
        if (!g_initFired)
            Out(" WM_INITDIALOG-missing");
        if (!g_getDlgItemOk)
            Out(" GetDlgItem(IDOK)-null");
        if (!g_getDlgItemStatic)
            Out(" GetDlgItem(100)-null");
        if (ret != IDOK)
            Out(" DialogBox-retval-wrong");
        Out("\r\n");
    }

    ExitProcess(0);
}
