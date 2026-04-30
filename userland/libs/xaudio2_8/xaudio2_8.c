/*
 * userland/libs/xaudio2_8/xaudio2_8.c — DuetOS XAudio2 v0.
 *
 * Apps create an IXAudio2, then a mastering voice, then source
 * voices. v0 hands out objects whose Submit / Start / Stop succeed
 * but no audio is actually played — the kernel HDA driver mixer
 * isn't yet wired through here. This is sufficient for engines that
 * gate startup on XAudio2Create returning S_OK and the master voice
 * existing.
 *
 * Exports:
 *   XAudio2Create, CreateAudioReverb, CreateAudioVolumeMeter
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10290000).
 */

#include "../dx_shared.h"

/* IID_IXAudio2 = {60d8dac8-5aa1-4e8e-b597-2f5e2883d484} */
static const DxGuid kIID_IXAudio2 = {0x60d8dac8, 0x5aa1, 0x4e8e, {0xb5, 0x97, 0x2f, 0x5e, 0x28, 0x83, 0xd4, 0x84}};

/* ---------------------------------------------------------------- *
 * IXAudio2Voice (base for source / submix / mastering)              *
 * 21-method vtable. v0 implements:                                  *
 *   slot 0  GetVoiceDetails (zero-fill)                             *
 *   slot 16 SetVolume / 17 GetVolume                                *
 *   slot 19 DestroyVoice                                            *
 * ---------------------------------------------------------------- */

#define VOICE_VTBL_SLOTS 21

typedef struct VoiceImpl
{
    void* const* lpVtbl;
    UINT kind; /* 0=source, 1=submix, 2=mastering */
    float volume;
    UINT sample_rate;
} VoiceImpl;

static void voice_GetVoiceDetails(VoiceImpl* self, void* details)
{
    if (!details)
        return;
    /* XAUDIO2_VOICE_DETAILS = { UINT CreationFlags, UINT ActiveFlags,
     *                           UINT InputChannels, UINT InputSampleRate } */
    BYTE* d = (BYTE*)details;
    dx_memzero(d, 16);
    *(UINT*)(d + 8) = 2;                  /* stereo */
    *(UINT*)(d + 12) = self->sample_rate; /* default 48000 */
}
static HRESULT voice_SetVolume(VoiceImpl* self, float vol, UINT op)
{
    (void)op;
    self->volume = vol;
    return DX_S_OK;
}
static void voice_GetVolume(VoiceImpl* self, float* vol)
{
    if (vol)
        *vol = self->volume;
}
static void voice_DestroyVoice(VoiceImpl* self)
{
    dx_heap_free(self);
}

/* Source voice extras (slots 21..28 in real XAudio2 — v0 inlines 24..28 in same vtable):
 * For simplicity v0 puts source-specific methods at slots 21..28 of an
 * extended vtable. Most apps ignore E_NOTIMPL on Submit and continue. */

#define SOURCE_VTBL_SLOTS 31

static HRESULT source_Start(VoiceImpl* self, UINT flags, UINT op)
{
    (void)self;
    (void)flags;
    (void)op;
    return DX_S_OK;
}
static HRESULT source_Stop(VoiceImpl* self, UINT flags, UINT op)
{
    (void)self;
    (void)flags;
    (void)op;
    return DX_S_OK;
}
static HRESULT source_SubmitSourceBuffer(VoiceImpl* self, const void* buffer, const void* wma)
{
    (void)self;
    (void)buffer;
    (void)wma;
    /* Audio dropped — no playback path yet. */
    return DX_S_OK;
}
static HRESULT source_FlushSourceBuffers(VoiceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static void source_GetState(VoiceImpl* self, void* state, UINT flags)
{
    (void)self;
    (void)flags;
    if (state)
        dx_memzero(state, 24); /* XAUDIO2_VOICE_STATE */
}

static void* g_source_vtbl[SOURCE_VTBL_SLOTS];
static void source_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < SOURCE_VTBL_SLOTS; ++i)
        g_source_vtbl[i] = DX_HSTUB;
    g_source_vtbl[0] = (void*)voice_GetVoiceDetails;
    g_source_vtbl[12] = (void*)voice_SetVolume;
    g_source_vtbl[13] = (void*)voice_GetVolume;
    g_source_vtbl[19] = (void*)voice_DestroyVoice;
    g_source_vtbl[21] = (void*)source_Start;
    g_source_vtbl[22] = (void*)source_Stop;
    g_source_vtbl[23] = (void*)source_SubmitSourceBuffer;
    g_source_vtbl[24] = (void*)source_FlushSourceBuffers;
    g_source_vtbl[27] = (void*)source_GetState;
}

static void* g_master_vtbl[VOICE_VTBL_SLOTS];
static void master_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < VOICE_VTBL_SLOTS; ++i)
        g_master_vtbl[i] = DX_HSTUB;
    g_master_vtbl[0] = (void*)voice_GetVoiceDetails;
    g_master_vtbl[12] = (void*)voice_SetVolume;
    g_master_vtbl[13] = (void*)voice_GetVolume;
    g_master_vtbl[19] = (void*)voice_DestroyVoice;
}

static VoiceImpl* voice_alloc(UINT kind)
{
    source_init_vtbl_once();
    master_init_vtbl_once();
    VoiceImpl* v = (VoiceImpl*)dx_heap_alloc(sizeof(*v));
    if (!v)
        return NULL;
    dx_memzero(v, sizeof(*v));
    v->lpVtbl = (kind == 0) ? g_source_vtbl : g_master_vtbl;
    v->kind = kind;
    v->volume = 1.0f;
    v->sample_rate = 48000;
    return v;
}

/* ---------------------------------------------------------------- *
 * IXAudio2 — IUnknown(3) + 12 methods                              *
 *   slot 3  RegisterForCallbacks                                    *
 *   slot 5  CreateSourceVoice                                       *
 *   slot 6  CreateSubmixVoice                                       *
 *   slot 7  CreateMasteringVoice                                    *
 *   slot 8  StartEngine / 9 StopEngine                              *
 *   slot 11 GetPerformanceData                                      *
 * ---------------------------------------------------------------- */

#define X2_VTBL_SLOTS 15

typedef struct X2Impl
{
    void* const* lpVtbl;
    ULONG refcount;
} X2Impl;

static HRESULT x2_QueryInterface(X2Impl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IXAudio2))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG x2_AddRef(X2Impl* self)
{
    return ++self->refcount;
}
static ULONG x2_Release(X2Impl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT x2_CreateSourceVoice(X2Impl* self, void** voice, const void* fmt, UINT flags, float max_freq,
                                    void* callback, const void* sends, const void* effect_chain)
{
    (void)self;
    (void)fmt;
    (void)flags;
    (void)max_freq;
    (void)callback;
    (void)sends;
    (void)effect_chain;
    if (!voice)
        return DX_E_POINTER;
    VoiceImpl* v = voice_alloc(0);
    if (!v)
    {
        *voice = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *voice = v;
    return DX_S_OK;
}
static HRESULT x2_CreateMasteringVoice(X2Impl* self, void** voice, UINT input_channels, UINT input_sample_rate,
                                       UINT flags, UINT device_index, const void* sends, UINT category)
{
    (void)self;
    (void)input_channels;
    (void)flags;
    (void)device_index;
    (void)sends;
    (void)category;
    if (!voice)
        return DX_E_POINTER;
    VoiceImpl* v = voice_alloc(2);
    if (!v)
    {
        *voice = NULL;
        return DX_E_OUTOFMEMORY;
    }
    if (input_sample_rate)
        v->sample_rate = input_sample_rate;
    *voice = v;
    return DX_S_OK;
}
static HRESULT x2_StartEngine(X2Impl* self)
{
    (void)self;
    return DX_S_OK;
}
static void x2_StopEngine(X2Impl* self)
{
    (void)self;
}
static void x2_GetPerformanceData(X2Impl* self, void* data)
{
    (void)self;
    if (data)
        dx_memzero(data, 64); /* XAUDIO2_PERFORMANCE_DATA ~64B */
}

static void* g_x2_vtbl[X2_VTBL_SLOTS];
static void x2_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < X2_VTBL_SLOTS; ++i)
        g_x2_vtbl[i] = DX_HSTUB;
    g_x2_vtbl[0] = (void*)x2_QueryInterface;
    g_x2_vtbl[1] = (void*)x2_AddRef;
    g_x2_vtbl[2] = (void*)x2_Release;
    g_x2_vtbl[5] = (void*)x2_CreateSourceVoice;
    g_x2_vtbl[7] = (void*)x2_CreateMasteringVoice;
    g_x2_vtbl[8] = (void*)x2_StartEngine;
    g_x2_vtbl[9] = (void*)x2_StopEngine;
    g_x2_vtbl[11] = (void*)x2_GetPerformanceData;
}

__declspec(dllexport) HRESULT XAudio2Create(void** out, UINT flags, UINT processor)
{
    (void)flags;
    (void)processor;
    dx_gfx_trace(7);
    if (!out)
        return DX_E_POINTER;
    x2_init_vtbl_once();
    X2Impl* x = (X2Impl*)dx_heap_alloc(sizeof(*x));
    if (!x)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    dx_memzero(x, sizeof(*x));
    x->lpVtbl = g_x2_vtbl;
    x->refcount = 1;
    *out = x;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT CreateAudioReverb(void** out)
{
    if (out)
        *out = NULL;
    return DX_E_NOTIMPL;
}

__declspec(dllexport) HRESULT CreateAudioVolumeMeter(void** out)
{
    if (out)
        *out = NULL;
    return DX_E_NOTIMPL;
}
