/*
 * userland/libs/dinput8/dinput8.c — DuetOS DirectInput 8 v0.
 *
 * Provides the IDirectInput8 + IDirectInputDevice8 COM surface so PEs
 * that initialise input via DirectInput don't crash, and routes
 * keyboard / mouse GetDeviceState through the same SYS_WIN_GET_KEYSTATE
 * / SYS_WIN_GET_CURSOR syscalls user32 uses, so DI-based apps see the
 * same input as GetAsyncKeyState/GetCursorPos callers. Joystick devices
 * still report zero connected (XInput is the modern path).
 *
 * Device kind is detected from the GUID passed to CreateDevice
 * (GUID_SysKeyboard / GUID_SysMouse). Unknown GUIDs zero-fill.
 *
 * Exports:
 *   DirectInput8Create
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10270000).
 */

#include "../dx_shared.h"

/* IID_IDirectInput8W = {bf798031-483a-4da2-aa99-5d64ed369700} */
static const DxGuid kIID_IDirectInput8W = {
    0xbf798031, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};
/* IID_IDirectInput8A = {bf798030-483a-4da2-aa99-5d64ed369700} */
static const DxGuid kIID_IDirectInput8A = {
    0xbf798030, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};
/* IID_IDirectInputDevice8W = {54d41081-dc15-4833-a41b-748f73a38179} */
static const DxGuid kIID_IDirectInputDevice8W = {
    0x54d41081, 0xdc15, 0x4833, {0xa4, 0x1b, 0x74, 0x8f, 0x73, 0xa3, 0x81, 0x79}};
/* GUID_SysKeyboard = {6f1d2b61-d5a0-11cf-bfc7-444553540000} */
static const DxGuid kGUID_SysKeyboard = {0x6f1d2b61, 0xd5a0, 0x11cf, {0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
/* GUID_SysMouse = {6f1d2b60-d5a0-11cf-bfc7-444553540000} */
static const DxGuid kGUID_SysMouse = {0x6f1d2b60, 0xd5a0, 0x11cf, {0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};

/* SYS_WIN_GET_KEYSTATE = 77, SYS_WIN_GET_CURSOR = 78 — same numbers
 * user32.dll uses. Returning a real key state out of GetDeviceState is
 * the only path Win32 PEs that use DirectInput keyboard/mouse have to
 * the input subsystem. */
static inline int dx_get_key_state(int vk)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)77), "D"((long long)(unsigned)vk) : "memory");
    return (int)(short)rv;
}

/* SYS_WIN_GET_MOUSE_DELTA = 170 — drains the kernel's per-event mouse
 * accumulator. Out buffer is the same DIMOUSESTATE shape we want to
 * fill (16 bytes: lX, lY, lZ as i32; rgbButtons[4]) so we just hand
 * the caller's buffer straight in. Returns 1 on success. */
static inline int dx_get_mouse_delta(void* out_dimousestate)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)170), "D"((long long)(unsigned long long)out_dimousestate)
                     : "memory");
    return (int)rv;
}

/* DirectInput Scan Code → Win32 Virtual Key. Set 1 PS/2 codes, the same
 * encoding DirectInput exposes through GetDeviceState. Entries left zero
 * mean "no kernel mapping yet" — the slot reads back as released. */
static unsigned char DikToVk(unsigned dik)
{
    switch (dik)
    {
    case 0x01:
        return 0x1B; /* ESCAPE */
    case 0x02:
        return '1';
    case 0x03:
        return '2';
    case 0x04:
        return '3';
    case 0x05:
        return '4';
    case 0x06:
        return '5';
    case 0x07:
        return '6';
    case 0x08:
        return '7';
    case 0x09:
        return '8';
    case 0x0A:
        return '9';
    case 0x0B:
        return '0';
    case 0x0E:
        return 0x08; /* BACK */
    case 0x0F:
        return 0x09; /* TAB */
    case 0x10:
        return 'Q';
    case 0x11:
        return 'W';
    case 0x12:
        return 'E';
    case 0x13:
        return 'R';
    case 0x14:
        return 'T';
    case 0x15:
        return 'Y';
    case 0x16:
        return 'U';
    case 0x17:
        return 'I';
    case 0x18:
        return 'O';
    case 0x19:
        return 'P';
    case 0x1C:
        return 0x0D; /* RETURN */
    case 0x1D:
        return 0xA2; /* LCONTROL */
    case 0x1E:
        return 'A';
    case 0x1F:
        return 'S';
    case 0x20:
        return 'D';
    case 0x21:
        return 'F';
    case 0x22:
        return 'G';
    case 0x23:
        return 'H';
    case 0x24:
        return 'J';
    case 0x25:
        return 'K';
    case 0x26:
        return 'L';
    case 0x2A:
        return 0xA0; /* LSHIFT */
    case 0x2C:
        return 'Z';
    case 0x2D:
        return 'X';
    case 0x2E:
        return 'C';
    case 0x2F:
        return 'V';
    case 0x30:
        return 'B';
    case 0x31:
        return 'N';
    case 0x32:
        return 'M';
    case 0x36:
        return 0xA1; /* RSHIFT */
    case 0x38:
        return 0xA4; /* LMENU (alt) */
    case 0x39:
        return 0x20; /* SPACE */
    case 0x3B:
        return 0x70; /* F1 */
    case 0x3C:
        return 0x71;
    case 0x3D:
        return 0x72;
    case 0x3E:
        return 0x73;
    case 0x3F:
        return 0x74;
    case 0x40:
        return 0x75;
    case 0x41:
        return 0x76;
    case 0x42:
        return 0x77;
    case 0x43:
        return 0x78;
    case 0x44:
        return 0x79; /* F10 */
    case 0x57:
        return 0x7A; /* F11 */
    case 0x58:
        return 0x7B; /* F12 */
    case 0xC8:
        return 0x26; /* UP */
    case 0xCB:
        return 0x25; /* LEFT */
    case 0xCD:
        return 0x27; /* RIGHT */
    case 0xD0:
        return 0x28; /* DOWN */
    default:
        return 0;
    }
}

/* ---------------------------------------------------------------- *
 * IDirectInputDevice8 — IUnknown(3) + 28 device methods.           *
 * v0 implements:                                                    *
 *   slot 0..2  IUnknown (QI / AddRef / Release)                     *
 *   slot 3   GetCapabilities (zero-fill)                            *
 *   slot 9   SetDataFormat                                          *
 *   slot 10  GetDeviceState (real for keyboard/mouse)               *
 *   slot 11  GetDeviceData (no buffered events)                     *
 *   slot 12  Acquire / 13 Unacquire                                 *
 *   slot 14  SetCooperativeLevel                                    *
 *   slot 25  Poll                                                   *
 * Most others → DX_HSTUB.                                           *
 * ---------------------------------------------------------------- */

#define DIDEV_VTBL_SLOTS 31

typedef enum DiDeviceKind
{
    kDiKindUnknown = 0,
    kDiKindKeyboard = 1,
    kDiKindMouse = 2,
} DiDeviceKind;

typedef struct DiDeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT format_size; /* size requested by SetDataFormat */
    UINT kind;        /* DiDeviceKind */
} DiDeviceImpl;

static HRESULT didev_QueryInterface(DiDeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectInputDevice8W))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG didev_AddRef(DiDeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG didev_Release(DiDeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT didev_GetCapabilities(DiDeviceImpl* self, void* caps)
{
    (void)self;
    if (caps)
        dx_memzero(caps, 24); /* DIDEVCAPS, leading dwSize is enough */
    return DX_S_OK;
}
static HRESULT didev_SetDataFormat(DiDeviceImpl* self, const void* fmt)
{
    (void)fmt;
    self->format_size = 256; /* enough for keyboard/mouse buffer */
    return DX_S_OK;
}
static HRESULT didev_SetCooperativeLevel(DiDeviceImpl* self, HWND h, DWORD f)
{
    (void)self;
    (void)h;
    (void)f;
    return DX_S_OK;
}
static HRESULT didev_Acquire(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT didev_Unacquire(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT didev_GetDeviceState(DiDeviceImpl* self, DWORD size, void* data)
{
    if (!data || size == 0 || size > 4096)
        return DX_E_INVALIDARG;
    dx_memzero(data, size);

    if (self->kind == kDiKindKeyboard)
    {
        /* DirectInput keyboard format: 256-byte array indexed by DIK,
         * each byte's high bit set when pressed. Apps typically pass
         * exactly 256 — we honor any size up to that. */
        BYTE* state = (BYTE*)data;
        DWORD lim = size > 256 ? 256 : size;
        for (DWORD dik = 1; dik < lim; ++dik)
        {
            unsigned char vk = DikToVk(dik);
            if (vk == 0)
                continue;
            int ks = dx_get_key_state((int)vk);
            if (ks & 0x8000)
                state[dik] = 0x80;
        }
        return DX_S_OK;
    }

    if (self->kind == kDiKindMouse)
    {
        /* DIMOUSESTATE: lX, lY, lZ (each LONG = 4B) + rgbButtons[4] = 16B.
         * DIMOUSESTATE2: + rgbButtons[8] tail; total 20B. We honor either
         * by writing only what the caller's `size` covers.
         *
         * Drain the kernel's raw-motion accumulator — it tracks true
         * per-packet deltas + wheel ticks, immune to programmatic
         * SetCursor warps. The kernel writes lX/lY/lZ + first 4
         * rgbButtons. Larger buffers (DIMOUSESTATE2) get extended
         * button slots filled by GetKeyState fallback. */
        if (size < 16)
            return DX_E_INVALIDARG;

        BYTE scratch[16] = {0};
        if (!dx_get_mouse_delta(scratch))
        {
            /* No movement reported by the input syscall — return
             * S_OK with a zeroed buffer (matches DI's "successful
             * poll, no events" idiom for mouse devices). */
            BYTE* zp = (BYTE*)data;
            for (DWORD i = 0; i < size; ++i)
                zp[i] = 0;
            return DX_S_OK;
        }
        BYTE* p = (BYTE*)data;
        for (DWORD i = 0; i < (size < 16 ? size : 16); ++i)
            p[i] = scratch[i];

        /* Extend rgbButtons past the kernel-provided 4 slots for
         * DIMOUSESTATE2 callers — the X1/X2 buttons aren't reported
         * by the kernel accumulator, so fall back to GetKeyState. */
        if (size > 16)
        {
            const int kBtnVk[4] = {5, 6, 0, 0}; /* XBUTTON1, XBUTTON2 */
            DWORD blim = size - 16;
            if (blim > 4)
                blim = 4;
            for (DWORD i = 0; i < blim; ++i)
            {
                if (kBtnVk[i] == 0)
                {
                    p[16 + i] = 0;
                    continue;
                }
                int ks = dx_get_key_state(kBtnVk[i]);
                p[16 + i] = (ks & 0x8000) ? 0x80 : 0;
            }
        }
        return DX_S_OK;
    }

    /* Unknown device kind — buffer is already zero-filled. */
    return DX_S_OK;
}
static HRESULT didev_GetDeviceData(DiDeviceImpl* self, DWORD obj_size, void* rg, DWORD* in_out, DWORD flags)
{
    (void)self;
    (void)obj_size;
    (void)rg;
    (void)flags;
    if (in_out)
        *in_out = 0; /* no buffered events */
    return DX_S_OK;
}
static HRESULT didev_Poll(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}

static void* g_didev_vtbl[DIDEV_VTBL_SLOTS];
static void didev_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DIDEV_VTBL_SLOTS; ++i)
        g_didev_vtbl[i] = DX_HSTUB;
    g_didev_vtbl[0] = (void*)didev_QueryInterface;
    g_didev_vtbl[1] = (void*)didev_AddRef;
    g_didev_vtbl[2] = (void*)didev_Release;
    g_didev_vtbl[3] = (void*)didev_GetCapabilities;
    g_didev_vtbl[9] = (void*)didev_SetDataFormat;
    g_didev_vtbl[10] = (void*)didev_GetDeviceState;
    g_didev_vtbl[11] = (void*)didev_GetDeviceData;
    g_didev_vtbl[12] = (void*)didev_Acquire;
    g_didev_vtbl[13] = (void*)didev_Unacquire;
    g_didev_vtbl[14] = (void*)didev_SetCooperativeLevel;
    g_didev_vtbl[25] = (void*)didev_Poll;
}

static DiDeviceImpl* didev_alloc(UINT kind)
{
    didev_init_vtbl_once();
    DiDeviceImpl* d = (DiDeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_didev_vtbl;
    d->refcount = 1;
    d->kind = kind;
    return d;
}

/* ---------------------------------------------------------------- *
 * IDirectInput8 — IUnknown(3) + 12 methods                         *
 *   slot 3  CreateDevice                                            *
 *   slot 4  EnumDevices (no devices)                                *
 *   slot 5  GetDeviceStatus                                         *
 *   slot 6  RunControlPanel                                         *
 *   slot 7  Initialize                                              *
 * ---------------------------------------------------------------- */

#define DI_VTBL_SLOTS 12

typedef struct DiImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} DiImpl;

static HRESULT di_QueryInterface(DiImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectInput8W) ||
        dx_guid_eq(riid, &kIID_IDirectInput8A))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG di_AddRef(DiImpl* self)
{
    return ++self->refcount;
}
static ULONG di_Release(DiImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT di_CreateDevice(DiImpl* self, REFIID guid, void** dev_out, void* unk)
{
    (void)self;
    (void)unk;
    if (!dev_out)
        return DX_E_POINTER;
    UINT kind = kDiKindUnknown;
    if (guid)
    {
        if (dx_guid_eq(guid, &kGUID_SysKeyboard))
            kind = kDiKindKeyboard;
        else if (dx_guid_eq(guid, &kGUID_SysMouse))
            kind = kDiKindMouse;
    }
    DiDeviceImpl* d = didev_alloc(kind);
    if (!d)
    {
        *dev_out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *dev_out = d;
    return DX_S_OK;
}
static HRESULT di_EnumDevices(DiImpl* self, DWORD type, void* cb, void* ctx, DWORD flags)
{
    (void)self;
    (void)type;
    (void)cb;
    (void)ctx;
    (void)flags;
    /* No devices to enumerate. */
    return DX_S_OK;
}
static HRESULT di_GetDeviceStatus(DiImpl* self, REFIID guid)
{
    (void)self;
    (void)guid;
    return DX_S_OK;
}
static HRESULT di_Initialize(DiImpl* self, HMODULE inst, DWORD ver)
{
    (void)self;
    (void)inst;
    (void)ver;
    return DX_S_OK;
}

static void* g_di_vtbl[DI_VTBL_SLOTS];
static void di_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DI_VTBL_SLOTS; ++i)
        g_di_vtbl[i] = DX_HSTUB;
    g_di_vtbl[0] = (void*)di_QueryInterface;
    g_di_vtbl[1] = (void*)di_AddRef;
    g_di_vtbl[2] = (void*)di_Release;
    g_di_vtbl[3] = (void*)di_CreateDevice;
    g_di_vtbl[4] = (void*)di_EnumDevices;
    g_di_vtbl[5] = (void*)di_GetDeviceStatus;
    g_di_vtbl[7] = (void*)di_Initialize;
}

static DiImpl* di_alloc(void)
{
    di_init_vtbl_once();
    DiImpl* d = (DiImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_di_vtbl;
    d->refcount = 1;
    return d;
}

__declspec(dllexport) HRESULT DirectInput8Create(HMODULE inst, DWORD ver, REFIID riid, void** out, void* unk)
{
    (void)inst;
    (void)ver;
    (void)riid;
    (void)unk;
    dx_gfx_trace(5);
    if (!out)
        return DX_E_POINTER;
    DiImpl* d = di_alloc();
    if (!d)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}
