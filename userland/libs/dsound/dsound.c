/*
 * userland/libs/dsound/dsound.c — DuetOS DirectSound v0.
 *
 * Apps create an IDirectSound, then secondary buffers with audio
 * data. v0 hands out objects whose Lock/Unlock map to a heap region
 * (so apps can write into the buffer); Play succeeds but no audio
 * actually streams to the DSP — the kernel HDA mixer isn't yet
 * wired through here.
 *
 * Exports:
 *   DirectSoundCreate, DirectSoundCreate8, DirectSoundEnumerateA,
 *   DirectSoundEnumerateW, GetDeviceID
 *
 * Build: tools/build/build-stub-dll.sh (base 0x102A0000).
 */

#include "../dx_shared.h"

/* IID_IDirectSound = {279afa83-4981-11ce-a521-0020af0be560} */
static const DxGuid kIID_IDirectSound = {0x279afa83, 0x4981, 0x11ce, {0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60}};
/* IID_IDirectSound8 = {c50a7e93-f395-4834-9ef6-7fa99de50966} */
static const DxGuid kIID_IDirectSound8 = {0xc50a7e93, 0xf395, 0x4834, {0x9e, 0xf6, 0x7f, 0xa9, 0x9d, 0xe5, 0x09, 0x66}};
/* IID_IDirectSoundBuffer = {279afa85-4981-11ce-a521-0020af0be560} */
static const DxGuid kIID_IDirectSoundBuffer = {
    0x279afa85, 0x4981, 0x11ce, {0xa5, 0x21, 0x00, 0x20, 0xaf, 0x0b, 0xe5, 0x60}};

/* ---------------------------------------------------------------- *
 * IDirectSoundBuffer — IUnknown(3) + 18 methods                    *
 *   slot 3  GetCaps, 4 GetCurrentPosition, 5 GetFormat, 6 GetVolume*
 *   slot 11 Lock, 12 Play, 13 SetCurrentPosition, 14 SetFormat,    *
 *   slot 15 SetVolume, 16 SetPan, 17 SetFrequency, 18 Stop, 19 Unlock*
 * ---------------------------------------------------------------- */

#define DSB_VTBL_SLOTS 21

typedef struct DsBufferImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT bytes;
    UINT freq; /* sample rate */
    DWORD play_cursor;
    BYTE* mem; /* primary mapping; Lock returns mem+offset */
} DsBufferImpl;

static HRESULT dsb_QueryInterface(DsBufferImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectSoundBuffer))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dsb_AddRef(DsBufferImpl* self)
{
    return ++self->refcount;
}
static ULONG dsb_Release(DsBufferImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->mem)
            dx_heap_free(self->mem);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT dsb_GetCurrentPosition(DsBufferImpl* self, DWORD* play, DWORD* write)
{
    if (play)
        *play = self->play_cursor;
    if (write)
        *write = self->play_cursor;
    /* Advance cursor on every poll so apps that wait for it move on. */
    self->play_cursor = (self->play_cursor + 32) % (self->bytes ? self->bytes : 1);
    return DX_S_OK;
}
static HRESULT dsb_Lock(DsBufferImpl* self, DWORD offset, DWORD bytes, void** ptr1, DWORD* bytes1, void** ptr2,
                        DWORD* bytes2, DWORD flags)
{
    (void)flags;
    if (!ptr1 || !bytes1 || !self->mem)
        return DX_E_POINTER;
    if (offset >= self->bytes)
        offset = 0;
    DWORD avail = self->bytes - offset;
    DWORD give = (bytes < avail) ? bytes : avail;
    *ptr1 = self->mem + offset;
    *bytes1 = give;
    if (ptr2)
        *ptr2 = NULL;
    if (bytes2)
        *bytes2 = 0;
    return DX_S_OK;
}
static HRESULT dsb_Unlock(DsBufferImpl* self, void* p1, DWORD n1, void* p2, DWORD n2)
{
    (void)self;
    (void)p1;
    (void)n1;
    (void)p2;
    (void)n2;
    return DX_S_OK;
}
static HRESULT dsb_Play(DsBufferImpl* self, DWORD reserved, DWORD priority, DWORD flags)
{
    (void)self;
    (void)reserved;
    (void)priority;
    (void)flags;
    return DX_S_OK;
}
static HRESULT dsb_Stop(DsBufferImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT dsb_SetVolume(DsBufferImpl* self, LONG vol)
{
    (void)self;
    (void)vol;
    return DX_S_OK;
}
static HRESULT dsb_GetVolume(DsBufferImpl* self, LONG* vol)
{
    (void)self;
    if (vol)
        *vol = 0; /* DSBVOLUME_MAX */
    return DX_S_OK;
}
static HRESULT dsb_GetCaps(DsBufferImpl* self, void* caps)
{
    (void)self;
    if (caps)
        dx_memzero(caps, 32); /* DSBCAPS */
    return DX_S_OK;
}
static HRESULT dsb_GetFormat(DsBufferImpl* self, void* fmt, DWORD size, DWORD* size_written)
{
    (void)self;
    if (fmt && size >= 18)
    {
        /* WAVEFORMATEX: 16-bit PCM stereo 48 kHz */
        BYTE* w = (BYTE*)fmt;
        dx_memzero(w, 18);
        *(WORD*)(w + 0) = 1; /* WAVE_FORMAT_PCM */
        *(WORD*)(w + 2) = 2; /* channels */
        *(DWORD*)(w + 4) = 48000;
        *(DWORD*)(w + 8) = 48000 * 4;
        *(WORD*)(w + 12) = 4;  /* block align */
        *(WORD*)(w + 14) = 16; /* bits per sample */
    }
    if (size_written)
        *size_written = 18;
    return DX_S_OK;
}

static void* g_dsb_vtbl[DSB_VTBL_SLOTS];
static void dsb_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DSB_VTBL_SLOTS; ++i)
        g_dsb_vtbl[i] = DX_HSTUB;
    g_dsb_vtbl[0] = (void*)dsb_QueryInterface;
    g_dsb_vtbl[1] = (void*)dsb_AddRef;
    g_dsb_vtbl[2] = (void*)dsb_Release;
    g_dsb_vtbl[3] = (void*)dsb_GetCaps;
    g_dsb_vtbl[4] = (void*)dsb_GetCurrentPosition;
    g_dsb_vtbl[5] = (void*)dsb_GetFormat;
    g_dsb_vtbl[6] = (void*)dsb_GetVolume;
    g_dsb_vtbl[11] = (void*)dsb_Lock;
    g_dsb_vtbl[12] = (void*)dsb_Play;
    g_dsb_vtbl[15] = (void*)dsb_SetVolume;
    g_dsb_vtbl[18] = (void*)dsb_Stop;
    g_dsb_vtbl[19] = (void*)dsb_Unlock;
}

static DsBufferImpl* dsb_alloc(UINT bytes, UINT freq)
{
    dsb_init_vtbl_once();
    DsBufferImpl* b = (DsBufferImpl*)dx_heap_alloc(sizeof(*b));
    if (!b)
        return NULL;
    dx_memzero(b, sizeof(*b));
    b->lpVtbl = g_dsb_vtbl;
    b->refcount = 1;
    b->bytes = bytes ? bytes : 1024;
    b->freq = freq ? freq : 48000;
    b->mem = (BYTE*)dx_heap_alloc(b->bytes);
    if (!b->mem)
    {
        dx_heap_free(b);
        return NULL;
    }
    dx_memzero(b->mem, b->bytes);
    return b;
}

/* ---------------------------------------------------------------- *
 * IDirectSound — IUnknown(3) + 6 methods                           *
 *   slot 3  CreateSoundBuffer                                       *
 *   slot 4  GetCaps                                                 *
 *   slot 5  DuplicateSoundBuffer                                    *
 *   slot 6  SetCooperativeLevel                                     *
 *   slot 7  Compact                                                 *
 *   slot 8  GetSpeakerConfig                                        *
 *   slot 9  SetSpeakerConfig                                        *
 *   slot 10 Initialize (v8)                                         *
 * ---------------------------------------------------------------- */

#define DS_VTBL_SLOTS 12

typedef struct DsImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} DsImpl;

static HRESULT ds_QueryInterface(DsImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectSound) ||
        dx_guid_eq(riid, &kIID_IDirectSound8))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG ds_AddRef(DsImpl* self)
{
    return ++self->refcount;
}
static ULONG ds_Release(DsImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT ds_CreateSoundBuffer(DsImpl* self, const void* desc, void** buf, void* unk)
{
    (void)self;
    (void)unk;
    if (!buf || !desc)
        return DX_E_POINTER;
    /* DSBUFFERDESC: dwSize(0) dwFlags(4) dwBufferBytes(8) dwReserved(12)
     *               LPWAVEFORMATEX lpwfxFormat(16) ... */
    UINT bytes = *(const UINT*)((const BYTE*)desc + 8);
    UINT freq = 48000;
    const void* fmt = *(const void* const*)((const BYTE*)desc + 16);
    if (fmt)
        freq = *(const DWORD*)((const BYTE*)fmt + 4);
    DsBufferImpl* b = dsb_alloc(bytes, freq);
    if (!b)
    {
        *buf = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *buf = b;
    return DX_S_OK;
}
static HRESULT ds_SetCooperativeLevel(DsImpl* self, HWND hwnd, DWORD level)
{
    (void)self;
    (void)hwnd;
    (void)level;
    return DX_S_OK;
}
static HRESULT ds_GetCaps(DsImpl* self, void* caps)
{
    (void)self;
    if (caps)
        dx_memzero(caps, 64);
    return DX_S_OK;
}
static HRESULT ds_Initialize(DsImpl* self, const void* guid)
{
    (void)self;
    (void)guid;
    return DX_S_OK;
}

static void* g_ds_vtbl[DS_VTBL_SLOTS];
static void ds_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DS_VTBL_SLOTS; ++i)
        g_ds_vtbl[i] = DX_HSTUB;
    g_ds_vtbl[0] = (void*)ds_QueryInterface;
    g_ds_vtbl[1] = (void*)ds_AddRef;
    g_ds_vtbl[2] = (void*)ds_Release;
    g_ds_vtbl[3] = (void*)ds_CreateSoundBuffer;
    g_ds_vtbl[4] = (void*)ds_GetCaps;
    g_ds_vtbl[6] = (void*)ds_SetCooperativeLevel;
    g_ds_vtbl[10] = (void*)ds_Initialize;
}

static DsImpl* ds_alloc(void)
{
    ds_init_vtbl_once();
    DsImpl* d = (DsImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_ds_vtbl;
    d->refcount = 1;
    return d;
}

__declspec(dllexport) HRESULT DirectSoundCreate(const void* device_guid, void** out, void* unk)
{
    (void)device_guid;
    (void)unk;
    if (!out)
        return DX_E_POINTER;
    DsImpl* d = ds_alloc();
    if (!d)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT DirectSoundCreate8(const void* device_guid, void** out, void* unk)
{
    return DirectSoundCreate(device_guid, out, unk);
}

__declspec(dllexport) HRESULT DirectSoundEnumerateA(void* cb, void* ctx)
{
    (void)cb;
    (void)ctx;
    /* No devices to enumerate — app's callback is never invoked. */
    return DX_S_OK;
}

__declspec(dllexport) HRESULT DirectSoundEnumerateW(void* cb, void* ctx)
{
    return DirectSoundEnumerateA(cb, ctx);
}

__declspec(dllexport) HRESULT GetDeviceID(const void* in, void* out)
{
    (void)in;
    if (out)
        dx_memzero(out, 16); /* GUID */
    return DX_S_OK;
}
