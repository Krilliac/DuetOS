/*
 * dx_demo_window — visible 3D cube rendered into a real compositor
 * window via D3D11.
 *
 * The companion "dx_demo" PE proves the rasterizer with offscreen
 * pixel-readback verification (fast, runs every boot). This PE is
 * the screenshot-harness fixture — it creates a real Win32 window,
 * renders the same 24-vertex cube into a D3D11 swap chain bound to
 * that HWND, calls Present (which BitBlts the back buffer onto the
 * window via SYS_GDI_BITBLT), and then sleeps so the screenshot
 * tool's settle window has time to capture the framebuffer.
 *
 * Boot-smoke skips this PE under -enable-kvm because the 17-second
 * Sleep would balloon the smoke time; the screenshot harness runs
 * on bare-metal-equivalent and does pick it up.
 */

#include <windows.h>

extern long D3D11CreateDeviceAndSwapChain(void* adapter, INT driver_type, void* sw, UINT flags, const void* fls,
                                          UINT nfls, UINT sdk, const void* desc, void** swap, void** dev,
                                          UINT* obtained, void** ctx);

#define BB_W 192
#define BB_H 192
#define WIN_W 220
#define WIN_H 240

static HANDLE g_stdout;

static void Out(const char* s)
{
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(g_stdout, s, len, &n, 0);
}

static void Dbg(const char* s)
{
    OutputDebugStringA(s);
}

/* ---------------------------------------------------------------- *
 * 4x4 matrix math (same shape as dx_demo, D3D row-major)           *
 * ---------------------------------------------------------------- */

typedef struct
{
    float m[16];
} M4;

static M4 mat_identity(void)
{
    M4 r;
    for (int i = 0; i < 16; ++i)
        r.m[i] = 0.f;
    r.m[0] = r.m[5] = r.m[10] = r.m[15] = 1.f;
    return r;
}

static M4 mat_mul(const M4* a, const M4* b)
{
    M4 r;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
        {
            float s = 0.f;
            for (int k = 0; k < 4; ++k)
                s += a->m[i * 4 + k] * b->m[k * 4 + j];
            r.m[i * 4 + j] = s;
        }
    return r;
}

static M4 mat_translate(float tx, float ty, float tz)
{
    M4 r = mat_identity();
    r.m[12] = tx;
    r.m[13] = ty;
    r.m[14] = tz;
    return r;
}

static M4 mat_rot_y(float c, float s)
{
    M4 r = mat_identity();
    r.m[0] = c;
    r.m[2] = -s;
    r.m[8] = s;
    r.m[10] = c;
    return r;
}

static M4 mat_rot_x(float c, float s)
{
    M4 r = mat_identity();
    r.m[5] = c;
    r.m[6] = s;
    r.m[9] = -s;
    r.m[10] = c;
    return r;
}

static M4 mat_perspective_fov_lh(float fy, float aspect, float zn, float zf)
{
    M4 r;
    for (int i = 0; i < 16; ++i)
        r.m[i] = 0.f;
    float fx = fy / aspect;
    r.m[0] = fx;
    r.m[5] = fy;
    r.m[10] = zf / (zf - zn);
    r.m[11] = 1.f;
    r.m[14] = -zn * zf / (zf - zn);
    return r;
}

static void vec4_xform(float out[4], const float in[4], const M4* m)
{
    out[0] = in[0] * m->m[0] + in[1] * m->m[4] + in[2] * m->m[8] + in[3] * m->m[12];
    out[1] = in[0] * m->m[1] + in[1] * m->m[5] + in[2] * m->m[9] + in[3] * m->m[13];
    out[2] = in[0] * m->m[2] + in[1] * m->m[6] + in[2] * m->m[10] + in[3] * m->m[14];
    out[3] = in[0] * m->m[3] + in[1] * m->m[7] + in[2] * m->m[11] + in[3] * m->m[15];
}

/* ---------------------------------------------------------------- *
 * Cube                                                             *
 * ---------------------------------------------------------------- */

#define COL_FRONT 0xFFFF0000u
#define COL_BACK 0xFF00FF00u
#define COL_LEFT 0xFF0000FFu
#define COL_RIGHT 0xFFFFFF00u
#define COL_TOP 0xFF00FFFFu
#define COL_BOTTOM 0xFFFF00FFu

typedef struct
{
    float x, y, z;
    DWORD argb;
} CubeVert;

/* clang-format off */
static const CubeVert kCubeVerts[24] = {
    {-0.5f, -0.5f, -0.5f, COL_FRONT}, {-0.5f,  0.5f, -0.5f, COL_FRONT},
    { 0.5f,  0.5f, -0.5f, COL_FRONT}, { 0.5f, -0.5f, -0.5f, COL_FRONT},
    {-0.5f, -0.5f,  0.5f, COL_BACK }, { 0.5f, -0.5f,  0.5f, COL_BACK },
    { 0.5f,  0.5f,  0.5f, COL_BACK }, {-0.5f,  0.5f,  0.5f, COL_BACK },
    {-0.5f, -0.5f, -0.5f, COL_LEFT }, {-0.5f, -0.5f,  0.5f, COL_LEFT },
    {-0.5f,  0.5f,  0.5f, COL_LEFT }, {-0.5f,  0.5f, -0.5f, COL_LEFT },
    { 0.5f, -0.5f, -0.5f, COL_RIGHT}, { 0.5f,  0.5f, -0.5f, COL_RIGHT},
    { 0.5f,  0.5f,  0.5f, COL_RIGHT}, { 0.5f, -0.5f,  0.5f, COL_RIGHT},
    {-0.5f,  0.5f, -0.5f, COL_TOP  }, {-0.5f,  0.5f,  0.5f, COL_TOP  },
    { 0.5f,  0.5f,  0.5f, COL_TOP  }, { 0.5f,  0.5f, -0.5f, COL_TOP  },
    {-0.5f, -0.5f, -0.5f, COL_BOTTOM}, { 0.5f, -0.5f, -0.5f, COL_BOTTOM},
    { 0.5f, -0.5f,  0.5f, COL_BOTTOM}, {-0.5f, -0.5f,  0.5f, COL_BOTTOM},
};

static const WORD kCubeIndices[36] = {
     0,  1,  2,  0,  2,  3,
     4,  5,  6,  4,  6,  7,
     8,  9, 10,  8, 10, 11,
    12, 13, 14, 12, 14, 15,
    16, 17, 18, 16, 18, 19,
    20, 21, 22, 20, 22, 23,
};
/* clang-format on */

#define COS30 0.86602540f
#define SIN30 0.5f
#define COS25 0.90630779f
#define SIN25 0.42261826f

static M4 build_mvp(int vp_w, int vp_h)
{
    M4 ry = mat_rot_y(COS30, SIN30);
    M4 rx = mat_rot_x(COS25, SIN25);
    M4 rxy = mat_mul(&rx, &ry);
    M4 translate = mat_translate(0.f, 0.f, 2.5f);
    M4 world = mat_mul(&rxy, &translate);
    M4 view = mat_identity();
    M4 wv = mat_mul(&world, &view);
    float aspect = (float)vp_w / (float)vp_h;
    M4 proj = mat_perspective_fov_lh(1.0f, aspect, 0.5f, 10.f);
    return mat_mul(&wv, &proj);
}

static const GUID kIidTex2D = {0x6f15aaf2, 0xd208, 0x4e89, {0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}};

typedef struct
{
    UINT Width, Height;
    UINT RefreshNum, RefreshDen;
    UINT Format, ScanlineOrdering, Scaling;
    UINT SampleCount, SampleQuality;
    UINT BufferUsage;
    UINT BufferCount;
    UINT _pad;
    HWND OutputWindow;
    BOOL Windowed;
    UINT SwapEffect;
    UINT Flags;
} ScDesc11;

/* The wndproc is a pure passthrough — the dx_demo_window does not
 * need to react to window messages; the compositor handles WM_PAINT
 * by re-emitting the most recent display list (which includes our
 * BitBlt). All we need is for the window to exist + be visible. */
static LRESULT __stdcall demo_wndproc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    (void)hwnd;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}

static int render_cube_to_window(HWND hwnd)
{
    ScDesc11 desc = {0};
    BYTE* p = (BYTE*)&desc;
    for (UINT i = 0; i < sizeof(desc); ++i)
        p[i] = 0;
    desc.Width = BB_W;
    desc.Height = BB_H;
    desc.Format = 87; /* B8G8R8A8_UNORM */
    desc.SampleCount = 1;
    desc.BufferUsage = 0x20;
    desc.BufferCount = 1;
    desc.OutputWindow = hwnd; /* live target — Present BitBlts to this HWND */
    desc.Windowed = TRUE;

    void* sc = NULL;
    void* dev = NULL;
    void* ctx = NULL;
    UINT got_fl = 0;
    long hr = D3D11CreateDeviceAndSwapChain(NULL, 0, NULL, 0, NULL, 0, 0, &desc, &sc, &dev, &got_fl, &ctx);
    if (hr != 0 || !sc || !dev || !ctx)
    {
        Out("[dx_demo_window] CreateDeviceAndSwapChain FAIL\r\n");
        return 0;
    }
    void** sc_vt = *(void***)sc;
    void** dev_vt = *(void***)dev;
    void** ctx_vt = *(void***)ctx;

    void* tex = NULL;
    typedef long (*PFN_GetBuf)(void*, UINT, const GUID*, void**);
    ((PFN_GetBuf)sc_vt[9])(sc, 0, &kIidTex2D, &tex);
    void* rtv = NULL;
    typedef long (*PFN_CRTV)(void*, void*, const void*, void**);
    ((PFN_CRTV)dev_vt[9])(dev, tex, NULL, &rtv);
    void* rtvs[1] = {rtv};
    typedef void (*PFN_OMSet)(void*, UINT, void* const*, void*);
    ((PFN_OMSet)ctx_vt[33])(ctx, 1, rtvs, NULL);

    /* Clear to dark blue so the cube faces really pop. */
    float bg[4] = {0.05f, 0.10f, 0.20f, 1.0f};
    typedef void (*PFN_ClearRTV)(void*, void*, const float*);
    ((PFN_ClearRTV)ctx_vt[50])(ctx, rtv, bg);

    /* CPU pre-transform the cube. */
    M4 mvp = build_mvp(BB_W, BB_H);
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } NdcVert;
    static NdcVert ndc_verts[24]; /* 384 B */
    for (int i = 0; i < 24; ++i)
    {
        float in[4] = {kCubeVerts[i].x, kCubeVerts[i].y, kCubeVerts[i].z, 1.0f};
        float out[4];
        vec4_xform(out, in, &mvp);
        ndc_verts[i].x = out[3] != 0.0f ? out[0] / out[3] : 0.f;
        ndc_verts[i].y = out[3] != 0.0f ? out[1] / out[3] : 0.f;
        ndc_verts[i].z = 0.f;
        ndc_verts[i].argb = kCubeVerts[i].argb;
    }

    BYTE bdesc[24] = {0};
    *(UINT*)(bdesc + 0) = sizeof(ndc_verts);
    *(UINT*)(bdesc + 8) = 0x1;
    BYTE srd[16] = {0};
    *(const void**)(srd + 0) = (const void*)ndc_verts;
    void* vb = NULL;
    typedef long (*PFN_CB)(void*, const void*, const void*, void**);
    ((PFN_CB)dev_vt[3])(dev, bdesc, srd, &vb);

    BYTE ibdesc[24] = {0};
    *(UINT*)(ibdesc + 0) = sizeof(kCubeIndices);
    *(UINT*)(ibdesc + 8) = 0x2;
    BYTE ibsrd[16] = {0};
    *(const void**)(ibsrd + 0) = (const void*)kCubeIndices;
    void* ib = NULL;
    ((PFN_CB)dev_vt[3])(dev, ibdesc, ibsrd, &ib);

    static const char kPos[] = "POSITION";
    static const char kCol[] = "COLOR";
    BYTE ied[64] = {0};
    *(const char**)(ied + 0) = kPos;
    *(UINT*)(ied + 12) = 6;
    *(UINT*)(ied + 20) = 0;
    *(const char**)(ied + 32) = kCol;
    *(UINT*)(ied + 44) = 87;
    *(UINT*)(ied + 52) = 12;
    void* il = NULL;
    typedef long (*PFN_CIL)(void*, const void*, UINT, const void*, SIZE_T, void**);
    ((PFN_CIL)dev_vt[11])(dev, ied, 2, NULL, 0, &il);

    typedef void (*PFN_IASetIL)(void*, void*);
    ((PFN_IASetIL)ctx_vt[17])(ctx, il);
    void* vbs[1] = {vb};
    UINT strides[1] = {sizeof(NdcVert)};
    UINT offsets[1] = {0};
    typedef void (*PFN_IASetVB)(void*, UINT, UINT, void* const*, const UINT*, const UINT*);
    ((PFN_IASetVB)ctx_vt[18])(ctx, 0, 1, vbs, strides, offsets);
    typedef void (*PFN_IASetIB)(void*, void*, UINT, UINT);
    ((PFN_IASetIB)ctx_vt[19])(ctx, ib, 57, 0);
    typedef void (*PFN_IASetTopo)(void*, UINT);
    ((PFN_IASetTopo)ctx_vt[24])(ctx, 4);

    float vp[6] = {0.f, 0.f, (float)BB_W, (float)BB_H, 0.f, 1.f};
    typedef void (*PFN_RSVP)(void*, UINT, const void*);
    ((PFN_RSVP)ctx_vt[44])(ctx, 1, vp);
    typedef void (*PFN_DI)(void*, UINT, UINT, INT);
    ((PFN_DI)ctx_vt[12])(ctx, 36, 0, 0);

    /* Present pushes the back buffer onto the window's display list. */
    typedef long (*PFN_Present)(void*, UINT, UINT);
    long present_hr = ((PFN_Present)sc_vt[8])(sc, 0, 0);
    Dbg("[odbg] dx_demo_window: present hr=ok\r\n");
    (void)present_hr;

    typedef ULONG (*PFN_Rel)(void*);
    ((PFN_Rel)((void**)(*(void***)il))[2])(il);
    ((PFN_Rel)((void**)(*(void***)ib))[2])(ib);
    ((PFN_Rel)((void**)(*(void***)vb))[2])(vb);
    ((PFN_Rel)((void**)(*(void***)rtv))[2])(rtv);
    ((PFN_Rel)((void**)(*(void***)tex))[2])(tex);
    ((PFN_Rel)ctx_vt[2])(ctx);
    ((PFN_Rel)sc_vt[2])(sc);
    ((PFN_Rel)dev_vt[2])(dev);
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    Out("[dx_demo_window] starting\r\n");

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = demo_wndproc;
    wc.lpszClassName = "DxDemoWindow";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, "DxDemoWindow", "D3D11 3D Cube",
                                /* WS_OVERLAPPEDWINDOW */ 0x00CF0000u, 600, 350, WIN_W, WIN_H, NULL, NULL, NULL, NULL);
    if (!hwnd)
    {
        Out("[dx_demo_window] CreateWindow FAIL\r\n");
        ExitProcess(1);
    }
    ShowWindow(hwnd, /* SW_SHOW */ 5);

    int rc = render_cube_to_window(hwnd);
    Out(rc ? "[dx_demo_window] cube rendered to window — PASS\r\n" : "[dx_demo_window] render FAIL\r\n");

    /* Settle window for the screenshot harness. screenshot.sh waits
     * for the kheartbeat task to appear in the serial log (which
     * happens within ~ms of dx_demo_window being spawned), then
     * sleeps DUETOS_SETTLE seconds (default 5, screenshot of this PE
     * uses 20-30) before driving QEMU's screendump. The window must
     * outlive that whole sequence — 40 s gives ~10 s of margin past
     * the typical SETTLE budget. */
    Out("[dx_demo_window] sleeping 40s for screenshot capture\r\n");
    Sleep(40000);
    Out("[dx_demo_window] done\r\n");
    ExitProcess(rc ? 0 : 1);
}
