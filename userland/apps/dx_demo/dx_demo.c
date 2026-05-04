/*
 * dx_demo — comprehensive DirectX exercise for DuetOS v0.1.
 *
 * This is the "everything DirectX" smoke PE. It walks the full
 * surface of every DLL we built, then proves the software rasterizer
 * actually renders 3D geometry by reading back the rendered pixels
 * and asserting non-background colour pixels.
 *
 * Pipeline per backend (D3D9 / D3D11 / D3D12):
 *
 *   1. Define a 24-vertex unit cube (each face has its own colour
 *      so we can identify which face is visible after rotation).
 *   2. Compute world * view * projection on the CPU and pre-transform
 *      every vertex to clip space (D3D11 / D3D12 don't have FF
 *      transforms; we feed the rasterizer NDC-ish coords directly).
 *      D3D9 gets the raw object-space cube + SetTransform calls and
 *      exercises the FF transform path inside the DLL itself.
 *   3. Clear the back buffer to dark grey.
 *   4. Draw the cube via the backend's geometry path.
 *   5. Map the back buffer, count pixels of each face colour, assert
 *      at least one face was visible.
 *
 * Plus probes for DXGI / D2D1 / DWrite / DInput / XInput.
 */

#include <windows.h>

extern long D3D11CreateDeviceAndSwapChain(void* adapter, INT driver_type, void* sw, UINT flags, const void* fls,
                                          UINT nfls, UINT sdk, const void* desc, void** swap, void** dev,
                                          UINT* obtained, void** ctx);
extern void* Direct3DCreate9(UINT sdk);
extern long D3D12CreateDevice(void* adapter, UINT min_feature_level, const GUID* riid, void** device);
extern long CreateDXGIFactory(const GUID* riid, void** factory);
extern long D2D1CreateFactory(UINT factoryType, const GUID* riid, const void* opts, void** factory);
extern long DWriteCreateFactory(UINT factoryType, const GUID* riid, void** factory);
extern long DirectInput8Create(HINSTANCE inst, DWORD ver, const GUID* riid, void** out, void* unk);
extern UINT XInputGetState(DWORD idx, void* state);

/* DuetOS_D3D9_PeekBackBuffer is a non-Win32 introspection export
 * that mingw's libd3d9.a doesn't know about — resolve it at runtime
 * via GetProcAddress so the .exe still links against the stock
 * import library. */
typedef int (*PFN_D3D9PeekBackBuffer)(void*, void**, UINT*, UINT*);

/* ---------------------------------------------------------------- *
 * Console helpers                                                  *
 * ---------------------------------------------------------------- */

static HANDLE g_stdout;

static void Out(const char* s)
{
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(g_stdout, s, len, &n, 0);
}

static void OutHex32(DWORD v)
{
    char buf[11] = "0x";
    static const char* d = "0123456789abcdef";
    for (int i = 0; i < 8; ++i)
        buf[2 + i] = d[(v >> ((7 - i) * 4)) & 0xF];
    buf[10] = 0;
    Out(buf);
}

static void OutDec(unsigned v)
{
    char buf[12];
    int n = 0;
    if (v == 0)
    {
        Out("0");
        return;
    }
    char tmp[12];
    while (v && n < 11)
    {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0; i < n; ++i)
        buf[i] = tmp[n - 1 - i];
    buf[n] = 0;
    Out(buf);
}

/* ---------------------------------------------------------------- *
 * 4x4 matrix math (D3D row-major, row vectors)                     *
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

/* Translate by (tx, ty, tz). Row-major D3D layout: translation
 * components live in the bottom row. */
static M4 mat_translate(float tx, float ty, float tz)
{
    M4 r = mat_identity();
    r.m[12] = tx;
    r.m[13] = ty;
    r.m[14] = tz;
    return r;
}

/* Rotate around the Y axis by (cos, sin) for left-handed D3D:
 *   [ c   0  -s   0 ]
 *   [ 0   1   0   0 ]
 *   [ s   0   c   0 ]
 *   [ 0   0   0   1 ]
 * Pre-computed cos / sin avoid pulling in libm. */
static M4 mat_rot_y(float c, float s)
{
    M4 r = mat_identity();
    r.m[0] = c;
    r.m[2] = -s;
    r.m[8] = s;
    r.m[10] = c;
    return r;
}

/* Rotate around X axis (left-handed D3D):
 *   [ 1   0   0   0 ]
 *   [ 0   c   s   0 ]
 *   [ 0  -s   c   0 ]
 *   [ 0   0   0   1 ] */
static M4 mat_rot_x(float c, float s)
{
    M4 r = mat_identity();
    r.m[5] = c;
    r.m[6] = s;
    r.m[9] = -s;
    r.m[10] = c;
    return r;
}

/* Left-handed perspective FOV. fy = 1/tan(fov_y/2) precomputed by
 * the caller (no libm). aspect = width / height. */
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

/* Transform a 4D row vector by a 4x4 row-major matrix. */
static void vec4_xform(float out[4], const float in[4], const M4* m)
{
    out[0] = in[0] * m->m[0] + in[1] * m->m[4] + in[2] * m->m[8] + in[3] * m->m[12];
    out[1] = in[0] * m->m[1] + in[1] * m->m[5] + in[2] * m->m[9] + in[3] * m->m[13];
    out[2] = in[0] * m->m[2] + in[1] * m->m[6] + in[2] * m->m[10] + in[3] * m->m[14];
    out[3] = in[0] * m->m[3] + in[1] * m->m[7] + in[2] * m->m[11] + in[3] * m->m[15];
}

/* ---------------------------------------------------------------- *
 * Cube geometry                                                    *
 *                                                                  *
 * 24 vertices, 36 indices. Each face is a separate quad of 4       *
 * vertices coloured uniformly so the post-render pixel scan can    *
 * tell which face is showing. CW from outside (D3D default is      *
 * FrontCounterClockwise = FALSE → CW = front).                     *
 *                                                                  *
 * Face colours (D3DCOLOR, 0xAARRGGBB):                             *
 *   Front  (-Z): red       0xFFFF0000                              *
 *   Back   (+Z): green     0xFF00FF00                              *
 *   Left   (-X): blue      0xFF0000FF                              *
 *   Right  (+X): yellow    0xFFFFFF00                              *
 *   Top    (+Y): cyan      0xFF00FFFF                              *
 *   Bottom (-Y): magenta   0xFFFF00FF                              *
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
    /* Front face (-Z, normal -Z, CW from outside which is -Z side) */
    {-0.5f, -0.5f, -0.5f, COL_FRONT}, {-0.5f,  0.5f, -0.5f, COL_FRONT},
    { 0.5f,  0.5f, -0.5f, COL_FRONT}, { 0.5f, -0.5f, -0.5f, COL_FRONT},
    /* Back face (+Z) */
    {-0.5f, -0.5f,  0.5f, COL_BACK }, { 0.5f, -0.5f,  0.5f, COL_BACK },
    { 0.5f,  0.5f,  0.5f, COL_BACK }, {-0.5f,  0.5f,  0.5f, COL_BACK },
    /* Left face (-X) */
    {-0.5f, -0.5f, -0.5f, COL_LEFT }, {-0.5f, -0.5f,  0.5f, COL_LEFT },
    {-0.5f,  0.5f,  0.5f, COL_LEFT }, {-0.5f,  0.5f, -0.5f, COL_LEFT },
    /* Right face (+X) */
    { 0.5f, -0.5f, -0.5f, COL_RIGHT}, { 0.5f,  0.5f, -0.5f, COL_RIGHT},
    { 0.5f,  0.5f,  0.5f, COL_RIGHT}, { 0.5f, -0.5f,  0.5f, COL_RIGHT},
    /* Top face (+Y) */
    {-0.5f,  0.5f, -0.5f, COL_TOP  }, {-0.5f,  0.5f,  0.5f, COL_TOP  },
    { 0.5f,  0.5f,  0.5f, COL_TOP  }, { 0.5f,  0.5f, -0.5f, COL_TOP  },
    /* Bottom face (-Y) */
    {-0.5f, -0.5f, -0.5f, COL_BOTTOM}, { 0.5f, -0.5f, -0.5f, COL_BOTTOM},
    { 0.5f, -0.5f,  0.5f, COL_BOTTOM}, {-0.5f, -0.5f,  0.5f, COL_BOTTOM},
};

static const WORD kCubeIndices[36] = {
    /* Front  (-Z): verts 0..3 — CW from -Z viewer */
     0,  1,  2,  0,  2,  3,
    /* Back   (+Z): verts 4..7 — CW from +Z viewer */
     4,  5,  6,  4,  6,  7,
    /* Left   (-X): verts 8..11 — CW from -X viewer */
     8,  9, 10,  8, 10, 11,
    /* Right  (+X): verts 12..15 — CW from +X viewer */
    12, 13, 14, 12, 14, 15,
    /* Top    (+Y): verts 16..19 — CW from +Y viewer */
    16, 17, 18, 16, 18, 19,
    /* Bottom (-Y): verts 20..23 — CW from -Y viewer */
    20, 21, 22, 20, 22, 23,
};
/* clang-format on */

/* Pre-rotated cube transform: 30° around Y, then 25° around X.
 * Hard-coded sin / cos avoid libm. The composite matrix puts the
 * cube into world space rotated, then translates it +z 2.5 so it
 * sits in front of an LH camera at the world origin. */
#define COS30 0.86602540f
#define SIN30 0.5f
#define COS25 0.90630779f
#define SIN25 0.42261826f

/* Compose: world * view * proj. Aspect=1, 90° FOV (fy = 1.0f),
 * near=0.5, far=10. */
static M4 build_mvp(int vp_w, int vp_h)
{
    M4 ry = mat_rot_y(COS30, SIN30);
    M4 rx = mat_rot_x(COS25, SIN25);
    M4 rxy = mat_mul(&rx, &ry);
    M4 translate = mat_translate(0.f, 0.f, 2.5f);
    M4 world = mat_mul(&rxy, &translate);
    M4 view = mat_identity(); /* camera at origin, looking +Z */
    M4 wv = mat_mul(&world, &view);
    float aspect = (float)vp_w / (float)vp_h;
    M4 proj = mat_perspective_fov_lh(1.0f, aspect, 0.5f, 10.f);
    return mat_mul(&wv, &proj);
}

/* ---------------------------------------------------------------- *
 * Pixel-readback verification                                      *
 *                                                                  *
 * Walk a width x height BGRA8 buffer, count exact-colour matches   *
 * for each cube face. A face is "visible" if at least 4 pixels of  *
 * its colour are present (filters out single-pixel rasterizer      *
 * artifacts at edges). Returns the number of distinct visible      *
 * faces.                                                           *
 * ---------------------------------------------------------------- */

/* D3DCOLOR (0xAARRGGBB) → BGRA8 byte order to compare against pixels
 * the rasterizer writes. dx_bb_clear_rgba and dxr_pack_d3dcolor both
 * pack as: ((A << 24) | (R << 16) | (G << 8) | B). */
static DWORD argb_to_bgra8(DWORD argb)
{
    BYTE a = (BYTE)((argb >> 24) & 0xFF);
    BYTE r = (BYTE)((argb >> 16) & 0xFF);
    BYTE g = (BYTE)((argb >> 8) & 0xFF);
    BYTE b = (BYTE)(argb & 0xFF);
    return ((DWORD)a << 24) | ((DWORD)r << 16) | ((DWORD)g << 8) | (DWORD)b;
}

static int count_face_pixels(const DWORD* pixels, UINT width, UINT height, DWORD argb_color)
{
    DWORD target = argb_to_bgra8(argb_color);
    int count = 0;
    UINT total = width * height;
    for (UINT i = 0; i < total; ++i)
        if (pixels[i] == target)
            ++count;
    return count;
}

/* Dump a low-res ASCII version of the rendered image so the boot
 * log shows a recognizable cube silhouette. Each character = one
 * pixel; legend:
 *   '.' background    'R' red front    'G' green back
 *   'B' blue left     'Y' yellow right 'C' cyan top
 *   'M' magenta bottom '?' unknown colour */
static char pixel_to_ascii(DWORD bgra)
{
    if (bgra == argb_to_bgra8(COL_FRONT))
        return 'R';
    if (bgra == argb_to_bgra8(COL_BACK))
        return 'G';
    if (bgra == argb_to_bgra8(COL_LEFT))
        return 'B';
    if (bgra == argb_to_bgra8(COL_RIGHT))
        return 'Y';
    if (bgra == argb_to_bgra8(COL_TOP))
        return 'C';
    if (bgra == argb_to_bgra8(COL_BOTTOM))
        return 'M';
    /* Background = uniform low-grey (truncation of 0.125f * 255 lands at
     * 0x1F, not 0x20). Any uniform-grey low-luma pixel → '.'. */
    BYTE r = (BYTE)((bgra >> 16) & 0xFF);
    BYTE g = (BYTE)((bgra >> 8) & 0xFF);
    BYTE b = (BYTE)(bgra & 0xFF);
    if (r == g && g == b && r < 0x40)
        return '.';
    return '?';
}

static void dump_pixels_ascii(const char* tag, const DWORD* pixels, UINT width, UINT height)
{
    Out("[dx_demo] ");
    Out(tag);
    Out(" ASCII render:\r\n");
    /* Reduce to 32x16 for a wider-than-tall printout (terminal chars
     * are ~2x taller than they are wide; sample every 2nd column +
     * every 4th row for a 64x64 buffer). */
    UINT stride_x = width / 32;
    UINT stride_y = height / 16;
    if (stride_x == 0)
        stride_x = 1;
    if (stride_y == 0)
        stride_y = 1;
    char line[34];
    for (UINT y = 0; y < height; y += stride_y)
    {
        UINT n = 0;
        for (UINT x = 0; x < width && n < 32; x += stride_x)
            line[n++] = pixel_to_ascii(pixels[y * width + x]);
        line[n++] = '\r';
        line[n++] = '\n';
        line[n] = 0;
        Out("[dx_demo]   ");
        Out(line);
    }
}

static int verify_cube_render(const char* tag, const DWORD* pixels, UINT width, UINT height)
{
    int rf = count_face_pixels(pixels, width, height, COL_FRONT);
    int rb = count_face_pixels(pixels, width, height, COL_BACK);
    int rl = count_face_pixels(pixels, width, height, COL_LEFT);
    int rr = count_face_pixels(pixels, width, height, COL_RIGHT);
    int rt = count_face_pixels(pixels, width, height, COL_TOP);
    int rbm = count_face_pixels(pixels, width, height, COL_BOTTOM);
    int faces_visible = 0;
    if (rf >= 4)
        ++faces_visible;
    if (rb >= 4)
        ++faces_visible;
    if (rl >= 4)
        ++faces_visible;
    if (rr >= 4)
        ++faces_visible;
    if (rt >= 4)
        ++faces_visible;
    if (rbm >= 4)
        ++faces_visible;

    /* Only dump the ASCII render once (D3D11 is canonical). The
     * other backends produce identical pixels by construction; the
     * duplicate dumps would just clutter the boot log. */
    static int dumped_once = 0;
    if (!dumped_once)
    {
        dump_pixels_ascii(tag, pixels, width, height);
        dumped_once = 1;
    }
    Out("[dx_demo] ");
    Out(tag);
    Out(" pixel-count: red=");
    OutDec((unsigned)rf);
    Out(" green=");
    OutDec((unsigned)rb);
    Out(" blue=");
    OutDec((unsigned)rl);
    Out(" yellow=");
    OutDec((unsigned)rr);
    Out(" cyan=");
    OutDec((unsigned)rt);
    Out(" magenta=");
    OutDec((unsigned)rbm);
    Out(" → faces=");
    OutDec((unsigned)faces_visible);
    Out("\r\n");
    return faces_visible;
}

/* ---------------------------------------------------------------- *
 * DXGI test                                                        *
 * ---------------------------------------------------------------- */

static const GUID kIidIDXGIFactory = {0x7b7166ec, 0x21c7, 0x44ae, {0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69}};

static int test_dxgi(void)
{
    Out("[dx_demo] --- DXGI ---\r\n");
    void* factory = NULL;
    long hr = CreateDXGIFactory(&kIidIDXGIFactory, &factory);
    if (hr != 0 || !factory)
    {
        Out("[dx_demo] dxgi: CreateDXGIFactory FAIL\r\n");
        return 0;
    }
    void** fac_vt = *(void***)factory;
    /* slot 7 = EnumAdapters(idx, **out) */
    void* adapter = NULL;
    typedef long (*PFN_Enum)(void*, UINT, void**);
    hr = ((PFN_Enum)fac_vt[7])(factory, 0, &adapter);
    if (hr != 0 || !adapter)
    {
        Out("[dx_demo] dxgi: EnumAdapters FAIL\r\n");
        return 0;
    }
    void** ad_vt = *(void***)adapter;
    /* slot 8 = GetDesc(*desc) */
    BYTE desc[304] = {0};
    typedef long (*PFN_GetDesc)(void*, void*);
    hr = ((PFN_GetDesc)ad_vt[8])(adapter, desc);
    if (hr == 0)
    {
        Out("[dx_demo] dxgi: VendorId=");
        OutHex32(*(UINT*)(desc + 256));
        Out(" DeviceId=");
        OutHex32(*(UINT*)(desc + 260));
        Out("\r\n");
    }
    /* slot 7 = EnumOutputs */
    void* output = NULL;
    typedef long (*PFN_EnumOut)(void*, UINT, void**);
    hr = ((PFN_EnumOut)ad_vt[7])(adapter, 0, &output);
    if (hr == 0 && output)
    {
        void** out_vt = *(void***)output;
        UINT mode_count = 0;
        typedef long (*PFN_ModeList)(void*, UINT, UINT, UINT*, void*);
        ((PFN_ModeList)out_vt[8])(output, 87, 0, &mode_count, NULL);
        Out("[dx_demo] dxgi: GetDisplayModeList count=");
        OutDec(mode_count);
        Out("\r\n");
        typedef ULONG (*PFN_Rel)(void*);
        ((PFN_Rel)out_vt[2])(output);
    }
    typedef ULONG (*PFN_Rel)(void*);
    ((PFN_Rel)ad_vt[2])(adapter);
    ((PFN_Rel)fac_vt[2])(factory);
    Out("[dx_demo] dxgi: PASS\r\n");
    return 1;
}

/* ---------------------------------------------------------------- *
 * D3D11 3D cube                                                    *
 * ---------------------------------------------------------------- */

static const GUID kIidTex2D = {0x6f15aaf2, 0xd208, 0x4e89, {0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}};

#define BB_W 64
#define BB_H 64

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

static int test_d3d11_cube(void)
{
    Out("[dx_demo] --- D3D11 3D cube ---\r\n");

    ScDesc11 desc = {0};
    BYTE* pdesc = (BYTE*)&desc;
    for (UINT i = 0; i < sizeof(desc); ++i)
        pdesc[i] = 0;
    desc.Width = BB_W;
    desc.Height = BB_H;
    desc.Format = 87; /* BGRA8 */
    desc.SampleCount = 1;
    desc.BufferUsage = 0x20;
    desc.BufferCount = 1;
    desc.OutputWindow = NULL; /* offscreen */
    desc.Windowed = TRUE;

    void* sc = NULL;
    void* dev = NULL;
    void* ctx = NULL;
    UINT got_fl = 0;
    long hr = D3D11CreateDeviceAndSwapChain(NULL, 0, NULL, 0, NULL, 0, 0, &desc, &sc, &dev, &got_fl, &ctx);
    if (hr != 0 || !sc || !dev || !ctx)
    {
        Out("[dx_demo] d3d11: CreateDeviceAndSwapChain FAIL\r\n");
        return 0;
    }
    void** sc_vt = *(void***)sc;
    void** dev_vt = *(void***)dev;
    void** ctx_vt = *(void***)ctx;

    /* GetBuffer + CreateRTV + OMSetRenderTargets */
    void* tex = NULL;
    typedef long (*PFN_GetBuf)(void*, UINT, const GUID*, void**);
    hr = ((PFN_GetBuf)sc_vt[9])(sc, 0, &kIidTex2D, &tex);
    void* rtv = NULL;
    typedef long (*PFN_CRTV)(void*, void*, const void*, void**);
    hr = ((PFN_CRTV)dev_vt[9])(dev, tex, NULL, &rtv);
    void* rtvs[1] = {rtv};
    typedef void (*PFN_OMSet)(void*, UINT, void* const*, void*);
    ((PFN_OMSet)ctx_vt[33])(ctx, 1, rtvs, NULL);

    /* Clear to dark grey 0x202020 so face colours stand out. */
    float bg[4] = {0.125f, 0.125f, 0.125f, 1.0f};
    typedef void (*PFN_ClearRTV)(void*, void*, const float*);
    ((PFN_ClearRTV)ctx_vt[50])(ctx, rtv, bg);

    /* Pre-transform the 24-vertex cube on the CPU. The rasterizer
     * inside d3d11.dll just does NDC → viewport mapping; we hand it
     * vertices already in clip space (with w computed). */
    M4 mvp = build_mvp(BB_W, BB_H);
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } NdcVert; /* 16 B */
    NdcVert ndc_verts[24];
    for (int i = 0; i < 24; ++i)
    {
        float in[4] = {kCubeVerts[i].x, kCubeVerts[i].y, kCubeVerts[i].z, 1.0f};
        float out[4];
        vec4_xform(out, in, &mvp);
        /* Perspective divide here; we feed NDC x/y to the rasterizer
         * with w=1 so its dxr_project doesn't double-divide. */
        if (out[3] != 0.0f)
        {
            ndc_verts[i].x = out[0] / out[3];
            ndc_verts[i].y = out[1] / out[3];
        }
        else
        {
            ndc_verts[i].x = 0.f;
            ndc_verts[i].y = 0.f;
        }
        ndc_verts[i].z = 0.f;
        ndc_verts[i].argb = kCubeVerts[i].argb;
    }

    /* CreateBuffer for vertex data */
    BYTE bdesc[24] = {0};
    *(UINT*)(bdesc + 0) = sizeof(ndc_verts);
    *(UINT*)(bdesc + 8) = 0x1; /* D3D11_BIND_VERTEX_BUFFER */
    BYTE srd[16] = {0};
    *(const void**)(srd + 0) = (const void*)ndc_verts;
    void* vb = NULL;
    typedef long (*PFN_CB)(void*, const void*, const void*, void**);
    hr = ((PFN_CB)dev_vt[3])(dev, bdesc, srd, &vb);

    /* Index buffer */
    BYTE ibdesc[24] = {0};
    *(UINT*)(ibdesc + 0) = sizeof(kCubeIndices);
    *(UINT*)(ibdesc + 8) = 0x2; /* D3D11_BIND_INDEX_BUFFER */
    BYTE ibsrd[16] = {0};
    *(const void**)(ibsrd + 0) = (const void*)kCubeIndices;
    void* ib = NULL;
    hr = ((PFN_CB)dev_vt[3])(dev, ibdesc, ibsrd, &ib);

    /* Input layout: POSITION (R32G32B32_FLOAT) + COLOR (B8G8R8A8_UNORM,
     * since our CubeVert.argb is packed AARRGGBB and B8G8R8A8_UNORM
     * matches that byte order on little-endian). */
    static const char kPos[] = "POSITION";
    static const char kCol[] = "COLOR";
    BYTE ied[64] = {0};
    *(const char**)(ied + 0) = kPos;
    *(UINT*)(ied + 12) = 6; /* DXGI_FORMAT_R32G32B32_FLOAT */
    *(UINT*)(ied + 20) = 0;
    *(const char**)(ied + 32) = kCol;
    *(UINT*)(ied + 44) = 87; /* DXGI_FORMAT_B8G8R8A8_UNORM (matches AARRGGBB byte order) */
    *(UINT*)(ied + 52) = 12;
    void* il = NULL;
    typedef long (*PFN_CIL)(void*, const void*, UINT, const void*, SIZE_T, void**);
    hr = ((PFN_CIL)dev_vt[11])(dev, ied, 2, NULL, 0, &il);

    typedef void (*PFN_IASetIL)(void*, void*);
    ((PFN_IASetIL)ctx_vt[17])(ctx, il);
    void* vbs[1] = {vb};
    UINT strides[1] = {sizeof(NdcVert)};
    UINT offsets[1] = {0};
    typedef void (*PFN_IASetVB)(void*, UINT, UINT, void* const*, const UINT*, const UINT*);
    ((PFN_IASetVB)ctx_vt[18])(ctx, 0, 1, vbs, strides, offsets);
    typedef void (*PFN_IASetIB)(void*, void*, UINT, UINT);
    ((PFN_IASetIB)ctx_vt[19])(ctx, ib, 57 /*R16_UINT*/, 0);
    typedef void (*PFN_IASetTopo)(void*, UINT);
    ((PFN_IASetTopo)ctx_vt[24])(ctx, 4); /* TRIANGLELIST */

    float vp[6] = {0.f, 0.f, (float)BB_W, (float)BB_H, 0.f, 1.f};
    typedef void (*PFN_RSVP)(void*, UINT, const void*);
    ((PFN_RSVP)ctx_vt[44])(ctx, 1, vp);

    typedef void (*PFN_DI)(void*, UINT, UINT, INT);
    ((PFN_DI)ctx_vt[12])(ctx, 36, 0, 0); /* DrawIndexed(36, 0, 0) */

    /* Map the back buffer to read pixels */
    BYTE mapped[24] = {0};
    typedef long (*PFN_Map)(void*, void*, UINT, UINT, UINT, void*);
    hr = ((PFN_Map)ctx_vt[14])(ctx, tex, 0, 1, 0, mapped);
    int faces = 0;
    if (hr == 0)
    {
        const DWORD* pixels = *(const DWORD**)(mapped + 0);
        faces = verify_cube_render("d3d11", pixels, BB_W, BB_H);
        typedef void (*PFN_Unmap)(void*, void*, UINT);
        ((PFN_Unmap)ctx_vt[15])(ctx, tex, 0);
    }

    /* Cleanup */
    typedef ULONG (*PFN_Rel)(void*);
    ((PFN_Rel)((void**)(*(void***)il))[2])(il);
    ((PFN_Rel)((void**)(*(void***)ib))[2])(ib);
    ((PFN_Rel)((void**)(*(void***)vb))[2])(vb);
    ((PFN_Rel)((void**)(*(void***)rtv))[2])(rtv);
    ((PFN_Rel)((void**)(*(void***)tex))[2])(tex);
    ((PFN_Rel)ctx_vt[2])(ctx);
    ((PFN_Rel)sc_vt[2])(sc);
    ((PFN_Rel)dev_vt[2])(dev);

    if (faces >= 1)
    {
        Out("[dx_demo] d3d11: cube rasterized, ");
        OutDec((unsigned)faces);
        Out(" face(s) visible — PASS\r\n");
        return 1;
    }
    Out("[dx_demo] d3d11: NO FACES rasterized — FAIL\r\n");
    return 0;
}

/* ---------------------------------------------------------------- *
 * D3D9 3D cube via the FF transform path                           *
 *                                                                  *
 * The whole point of D3D9 here is that the DLL itself runs the     *
 * world*view*proj matrix multiply (we set the matrices via         *
 * SetTransform). We only ship raw object-space XYZ vertices.       *
 * ---------------------------------------------------------------- */

typedef struct
{
    UINT BackBufferWidth, BackBufferHeight;
    UINT BackBufferFormat, BackBufferCount;
    UINT MultiSampleType, MultiSampleQuality;
    UINT SwapEffect, _pad;
    HWND hDeviceWindow;
    BOOL Windowed;
    BOOL EnableAutoDepthStencil;
    UINT AutoDepthStencilFormat;
    UINT Flags;
    UINT FullScreen_RefreshRateInHz;
    UINT PresentationInterval;
} PresentParams9;

static int test_d3d9_cube(void)
{
    Out("[dx_demo] --- D3D9 3D cube (FF transform) ---\r\n");
    void* d3d = Direct3DCreate9(32);
    if (!d3d)
    {
        Out("[dx_demo] d3d9: Direct3DCreate9 FAIL\r\n");
        return 0;
    }
    void** d3d_vt = *(void***)d3d;
    PresentParams9 pp = {0};
    pp.BackBufferWidth = BB_W;
    pp.BackBufferHeight = BB_H;
    pp.BackBufferCount = 1;
    pp.SwapEffect = 1;
    pp.Windowed = TRUE;
    void* dev = NULL;
    typedef long (*PFN_CD)(void*, UINT, UINT, HWND, DWORD, void*, void**);
    long hr = ((PFN_CD)d3d_vt[16])(d3d, 0, 1, NULL, 0x40, &pp, &dev);
    if (hr != 0 || !dev)
    {
        Out("[dx_demo] d3d9: CreateDevice FAIL\r\n");
        typedef ULONG (*PFN_Rel)(void*);
        ((PFN_Rel)d3d_vt[2])(d3d);
        return 0;
    }
    void** dev_vt = *(void***)dev;

    /* Set the three FF transforms. State IDs:
     *   D3DTS_VIEW       = 2
     *   D3DTS_PROJECTION = 3
     *   D3DTS_WORLD      = 256 */
    M4 ry = mat_rot_y(COS30, SIN30);
    M4 rx = mat_rot_x(COS25, SIN25);
    M4 rxy = mat_mul(&rx, &ry);
    M4 translate = mat_translate(0.f, 0.f, 2.5f);
    M4 world = mat_mul(&rxy, &translate);
    M4 view = mat_identity();
    M4 proj = mat_perspective_fov_lh(1.0f, 1.0f, 0.5f, 10.f);
    typedef long (*PFN_SetTx)(void*, DWORD, const void*);
    ((PFN_SetTx)dev_vt[44])(dev, 256, &world);
    ((PFN_SetTx)dev_vt[44])(dev, 2, &view);
    ((PFN_SetTx)dev_vt[44])(dev, 3, &proj);

    /* SetViewport — required so my software raster knows the back
     * buffer extent. D3DVIEWPORT9: X(0,4), Y(4,4), W(8,4), H(12,4),
     * MinZ(16,4), MaxZ(20,4). */
    DWORD vp9[6] = {0, 0, BB_W, BB_H, 0, 0};
    typedef long (*PFN_SVP)(void*, const void*);
    ((PFN_SVP)dev_vt[47])(dev, vp9);

    /* SetFVF — D3DFVF_XYZ (2) | D3DFVF_DIFFUSE (0x40) = 0x42. The
     * draw path uses the FF transforms set above to project. */
    typedef long (*PFN_FVF)(void*, DWORD);
    ((PFN_FVF)dev_vt[89])(dev, 0x42);

    /* Clear, BeginScene, draw, EndScene, Present. */
    typedef long (*PFN_BS)(void*);
    ((PFN_BS)dev_vt[41])(dev);
    typedef long (*PFN_Clear)(void*, DWORD, const void*, DWORD, DWORD, float, DWORD);
    ((PFN_Clear)dev_vt[43])(dev, 0, NULL, 1, 0xFF202020 /* dark grey */, 1.0f, 0);

    /* DrawPrimitiveUP(D3DPT_TRIANGLELIST=4, primCount, data, stride).
     * primCount = 12 triangles. We also need to inline the indexed
     * vertex stream — DrawPrimitiveUP is non-indexed, so unwrap the
     * 36 indices into 36 sequential verts (well within the 18 KiB
     * heap budget: 36 * 16 B = 576 B). */
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } Fvf42;
    Fvf42 unrolled[36];
    for (int i = 0; i < 36; ++i)
    {
        WORD idx = kCubeIndices[i];
        unrolled[i].x = kCubeVerts[idx].x;
        unrolled[i].y = kCubeVerts[idx].y;
        unrolled[i].z = kCubeVerts[idx].z;
        unrolled[i].argb = kCubeVerts[idx].argb;
    }
    typedef long (*PFN_DUP)(void*, UINT, UINT, const void*, UINT);
    ((PFN_DUP)dev_vt[83])(dev, 4, 12, unrolled, sizeof(Fvf42));
    ((PFN_BS)dev_vt[42])(dev); /* EndScene */

    /* Peek the back buffer via the introspection helper. D3D9's
     * proper read-back path goes through GetRenderTargetData →
     * IDirect3DSurface9::LockRect, which v0 doesn't carry yet; the
     * peek export is a non-Win32 hatch that hands back the raw bb
     * pixel pointer so this test can verify the FF transform path
     * actually rasterized. */
    typedef long (*PFN_Pres)(void*, const void*, const void*, HWND, const void*);
    ((PFN_Pres)dev_vt[17])(dev, NULL, NULL, NULL, NULL);

    void* d9_pixels = NULL;
    UINT d9_w = 0, d9_h = 0;
    int d9_faces = 0;
    HMODULE d9_mod = LoadLibraryA("d3d9.dll");
    PFN_D3D9PeekBackBuffer peek =
        d9_mod ? (PFN_D3D9PeekBackBuffer)GetProcAddress(d9_mod, "DuetOS_D3D9_PeekBackBuffer") : NULL;
    if (peek && peek(dev, &d9_pixels, &d9_w, &d9_h))
        d9_faces = verify_cube_render("d3d9", (const DWORD*)d9_pixels, d9_w, d9_h);
    else
        Out("[dx_demo] d3d9: PeekBackBuffer unavailable\r\n");

    typedef ULONG (*PFN_Rel)(void*);
    ((PFN_Rel)dev_vt[2])(dev);
    ((PFN_Rel)d3d_vt[2])(d3d);
    if (d9_faces >= 1)
    {
        Out("[dx_demo] d3d9: FF transform cube rasterized, ");
        OutDec((unsigned)d9_faces);
        Out(" face(s) visible — PASS\r\n");
        return 1;
    }
    Out("[dx_demo] d3d9: NO FACES rasterized — FAIL\r\n");
    return 0;
}

/* ---------------------------------------------------------------- *
 * D3D12 cube via the new draw path                                 *
 * ---------------------------------------------------------------- */

static const GUID kIidD12Device = {0x189819f1, 0x1db6, 0x4b57, {0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7}};

typedef struct
{
    UINT Type, Priority, Flags, NodeMask;
} D12QDesc;
typedef struct
{
    UINT Type, NumDescriptors, Flags, NodeMask;
} D12HDesc;
typedef struct
{
    UINT Type, CPUPageProperty, MemoryPoolPreference, CreationNodeMask, VisibleNodeMask;
} D12HProps;
typedef struct
{
    UINT Dimension, Alignment;
    UINT64 Width;
    UINT Height;
    WORD DepthOrArraySize, MipLevels;
    UINT Format;
    UINT _rest[10];
} D12RDesc;

static int test_d3d12_cube(void)
{
    Out("[dx_demo] --- D3D12 3D cube ---\r\n");
    void* dev = NULL;
    long hr = D3D12CreateDevice(NULL, 0xb000, &kIidD12Device, &dev);
    if (hr != 0 || !dev)
    {
        Out("[dx_demo] d3d12: CreateDevice FAIL\r\n");
        return 0;
    }
    void** dev_vt = *(void***)dev;

    /* Queue + allocator + list */
    D12QDesc qd = {0, 0, 0, 0};
    void* queue = NULL;
    typedef long (*PFN_CQ)(void*, const void*, const GUID*, void**);
    ((PFN_CQ)dev_vt[8])(dev, &qd, NULL, &queue);
    void* alloc = NULL;
    typedef long (*PFN_CA)(void*, UINT, const GUID*, void**);
    ((PFN_CA)dev_vt[9])(dev, 0, NULL, &alloc);
    void* list = NULL;
    typedef long (*PFN_CL)(void*, UINT, UINT, void*, void*, const GUID*, void**);
    ((PFN_CL)dev_vt[12])(dev, 0, 0, alloc, NULL, NULL, &list);

    /* RTV heap + back-buffer texture + RTV */
    D12HDesc hd = {2, 1, 0, 0};
    void* heap = NULL;
    typedef long (*PFN_CH)(void*, const void*, const GUID*, void**);
    ((PFN_CH)dev_vt[14])(dev, &hd, NULL, &heap);
    void** heap_vt = *(void***)heap;
    typedef SIZE_T (*PFN_GetCPU)(void*);
    SIZE_T cpu_h = ((PFN_GetCPU)heap_vt[9])(heap);

    D12HProps hp = {1, 0, 0, 0, 0};
    D12RDesc rd = {0};
    rd.Dimension = 4; /* TEXTURE2D */
    rd.Width = BB_W;
    rd.Height = BB_H;
    rd.DepthOrArraySize = 1;
    rd.MipLevels = 1;
    rd.Format = 87;
    void* rt = NULL;
    typedef long (*PFN_CR)(void*, const void*, UINT, const void*, UINT, const void*, const GUID*, void**);
    ((PFN_CR)dev_vt[27])(dev, &hp, 0, &rd, 4, NULL, NULL, &rt);

    typedef void (*PFN_CRTV)(void*, void*, const void*, SIZE_T);
    ((PFN_CRTV)dev_vt[20])(dev, rt, NULL, cpu_h);

    /* Build NDC vertex buffer (resource of dimension BUFFER) */
    M4 mvp = build_mvp(BB_W, BB_H);
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } NdcVert;
    NdcVert ndc[24];
    for (int i = 0; i < 24; ++i)
    {
        float in[4] = {kCubeVerts[i].x, kCubeVerts[i].y, kCubeVerts[i].z, 1.0f};
        float out[4];
        vec4_xform(out, in, &mvp);
        ndc[i].x = out[3] != 0.0f ? out[0] / out[3] : 0.f;
        ndc[i].y = out[3] != 0.0f ? out[1] / out[3] : 0.f;
        ndc[i].z = 0.f;
        ndc[i].argb = kCubeVerts[i].argb;
    }

    D12RDesc bdesc = {0};
    bdesc.Dimension = 1;
    bdesc.Width = sizeof(ndc);
    bdesc.Height = 1;
    bdesc.DepthOrArraySize = 1;
    bdesc.MipLevels = 1;
    void* vb = NULL;
    ((PFN_CR)dev_vt[27])(dev, &hp, 0, &bdesc, 0, NULL, NULL, &vb);
    void** vb_vt = *(void***)vb;
    typedef long (*PFN_Map)(void*, UINT, const void*, void**);
    void* vb_data = NULL;
    ((PFN_Map)vb_vt[8])(vb, 0, NULL, &vb_data);
    {
        BYTE* d = (BYTE*)vb_data;
        const BYTE* s = (const BYTE*)ndc;
        for (UINT i = 0; i < sizeof(ndc); ++i)
            d[i] = s[i];
    }
    typedef void (*PFN_Unmap)(void*, UINT, const void*);
    ((PFN_Unmap)vb_vt[9])(vb, 0, NULL);
    typedef UINT64 (*PFN_GetGPUVA)(void*);
    UINT64 vb_va = ((PFN_GetGPUVA)vb_vt[11])(vb);

    /* Index buffer too */
    D12RDesc ibdesc = {0};
    ibdesc.Dimension = 1;
    ibdesc.Width = sizeof(kCubeIndices);
    ibdesc.Height = 1;
    ibdesc.DepthOrArraySize = 1;
    ibdesc.MipLevels = 1;
    void* ib = NULL;
    ((PFN_CR)dev_vt[27])(dev, &hp, 0, &ibdesc, 0, NULL, NULL, &ib);
    void** ib_vt = *(void***)ib;
    void* ib_data = NULL;
    ((PFN_Map)ib_vt[8])(ib, 0, NULL, &ib_data);
    {
        BYTE* d = (BYTE*)ib_data;
        const BYTE* s = (const BYTE*)kCubeIndices;
        for (UINT i = 0; i < sizeof(kCubeIndices); ++i)
            d[i] = s[i];
    }
    ((PFN_Unmap)ib_vt[9])(ib, 0, NULL);
    UINT64 ib_va = ((PFN_GetGPUVA)ib_vt[11])(ib);

    /* PSO with input layout */
    static const char kPos[] = "POSITION";
    static const char kCol[] = "COLOR";
    BYTE ied[64] = {0};
    *(const char**)(ied + 0) = kPos;
    *(UINT*)(ied + 12) = 6;
    *(UINT*)(ied + 20) = 0;
    *(const char**)(ied + 32) = kCol;
    *(UINT*)(ied + 44) = 87;
    *(UINT*)(ied + 52) = 12;
    BYTE psodesc[400] = {0};
    *(const void**)(psodesc + 348) = (const void*)ied;
    *(UINT*)(psodesc + 356) = 2;
    *(UINT*)(psodesc + 368) = 3; /* TRIANGLE */
    void* pso = NULL;
    typedef long (*PFN_GPSO)(void*, const void*, const GUID*, void**);
    ((PFN_GPSO)dev_vt[10])(dev, psodesc, NULL, &pso);

    /* Record */
    void** list_vt = *(void***)list;
    float bg[4] = {0.125f, 0.125f, 0.125f, 1.0f};
    typedef void (*PFN_CRT)(void*, SIZE_T, const float*, UINT, const void*);
    ((PFN_CRT)list_vt[48])(list, cpu_h, bg, 0, NULL);
    typedef void (*PFN_SetPSO)(void*, void*);
    ((PFN_SetPSO)list_vt[25])(list, pso);
    typedef void (*PFN_SetTopo)(void*, UINT);
    ((PFN_SetTopo)list_vt[20])(list, 4);
    float vp12[6] = {0.f, 0.f, (float)BB_W, (float)BB_H, 0.f, 1.f};
    typedef void (*PFN_RSVP)(void*, UINT, const void*);
    ((PFN_RSVP)list_vt[21])(list, 1, vp12);
    typedef void (*PFN_OM)(void*, UINT, const void*, BOOL, const void*);
    ((PFN_OM)list_vt[46])(list, 1, &cpu_h, FALSE, NULL);
    BYTE vbview[16];
    *(UINT64*)(vbview + 0) = vb_va;
    *(UINT*)(vbview + 8) = sizeof(ndc);
    *(UINT*)(vbview + 12) = sizeof(NdcVert);
    typedef void (*PFN_IAVB)(void*, UINT, UINT, const void*);
    ((PFN_IAVB)list_vt[44])(list, 0, 1, vbview);
    BYTE ibview[16];
    *(UINT64*)(ibview + 0) = ib_va;
    *(UINT*)(ibview + 8) = sizeof(kCubeIndices);
    *(UINT*)(ibview + 12) = 57; /* R16_UINT */
    typedef void (*PFN_IAIB)(void*, const void*);
    ((PFN_IAIB)list_vt[43])(list, ibview);
    typedef void (*PFN_DII)(void*, UINT, UINT, UINT, INT, UINT);
    ((PFN_DII)list_vt[13])(list, 36, 1, 0, 0, 0);

    typedef long (*PFN_Close)(void*);
    ((PFN_Close)list_vt[9])(list);
    void** q_vt = *(void***)queue;
    void* lists[1] = {list};
    typedef void (*PFN_Exec)(void*, UINT, void* const*);
    ((PFN_Exec)q_vt[10])(queue, 1, lists);

    /* Read back via Map on the texture resource */
    void** rt_vt = *(void***)rt;
    void* rt_pixels = NULL;
    ((PFN_Map)rt_vt[8])(rt, 0, NULL, &rt_pixels);
    int faces = 0;
    if (rt_pixels)
        faces = verify_cube_render("d3d12", (const DWORD*)rt_pixels, BB_W, BB_H);
    ((PFN_Unmap)rt_vt[9])(rt, 0, NULL);

    /* Cleanup */
    typedef ULONG (*PFN_Rel)(void*);
    ((PFN_Rel)((void**)(*(void***)pso))[2])(pso);
    ((PFN_Rel)ib_vt[2])(ib);
    ((PFN_Rel)vb_vt[2])(vb);
    ((PFN_Rel)rt_vt[2])(rt);
    ((PFN_Rel)heap_vt[2])(heap);
    ((PFN_Rel)list_vt[2])(list);
    ((PFN_Rel)((void**)(*(void***)alloc))[2])(alloc);
    ((PFN_Rel)q_vt[2])(queue);
    ((PFN_Rel)dev_vt[2])(dev);

    if (faces >= 1)
    {
        Out("[dx_demo] d3d12: cube rasterized, ");
        OutDec((unsigned)faces);
        Out(" face(s) visible — PASS\r\n");
        return 1;
    }
    Out("[dx_demo] d3d12: NO FACES rasterized — FAIL\r\n");
    return 0;
}

/* ---------------------------------------------------------------- *
 * D2D1 + DWrite + DInput + XInput probes                           *
 * ---------------------------------------------------------------- */

static const GUID kIidID2D1Factory = {0x06152247, 0x6f50, 0x465a, {0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}};
static const GUID kIidIDWriteFactory = {0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};
static const GUID kIidIDirectInput8W = {0xbf798031, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};

static int test_misc(void)
{
    Out("[dx_demo] --- D2D1 / DWrite / DInput8 / XInput ---\r\n");
    void* d2d = NULL;
    long hr = D2D1CreateFactory(0, &kIidID2D1Factory, NULL, &d2d);
    if (hr == 0 && d2d)
    {
        Out("[dx_demo] d2d1: factory OK\r\n");
        typedef ULONG (*PFN_Rel)(void*);
        ((PFN_Rel)((void**)(*(void***)d2d))[2])(d2d);
    }
    void* dw = NULL;
    hr = DWriteCreateFactory(0, &kIidIDWriteFactory, &dw);
    if (hr == 0 && dw)
    {
        Out("[dx_demo] dwrite: factory OK\r\n");
        typedef ULONG (*PFN_Rel)(void*);
        ((PFN_Rel)((void**)(*(void***)dw))[2])(dw);
    }
    void* di = NULL;
    hr = DirectInput8Create(NULL, 0x0800, &kIidIDirectInput8W, &di, NULL);
    if (hr == 0 && di)
    {
        Out("[dx_demo] dinput8: factory OK\r\n");
        typedef ULONG (*PFN_Rel)(void*);
        ((PFN_Rel)((void**)(*(void***)di))[2])(di);
    }
    BYTE xstate[16] = {0};
    UINT xrc = XInputGetState(0, xstate);
    Out("[dx_demo] xinput: GetState rc=");
    OutHex32(xrc);
    Out("\r\n");
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    Out("[dx_demo] starting\r\n");

    int total = 0, pass = 0;
    total++;
    pass += test_dxgi();
    total++;
    pass += test_d3d11_cube();
    total++;
    pass += test_d3d12_cube();
    total++;
    pass += test_d3d9_cube();
    total++;
    pass += test_misc();

    Out("[dx_demo] summary: ");
    OutDec((unsigned)pass);
    Out("/");
    OutDec((unsigned)total);
    Out(" sections passed\r\n");
    Out("[dx_demo] done\r\n");
    ExitProcess(pass == total ? 0 : 1);
}
