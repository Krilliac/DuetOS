// tests/host/test_d3dcompiler.cpp
//
// Hosted unit tests for userland/libs/d3dcompiler/d3dcompiler.c —
// the HLSL frontend (lexer + parser + DXBC-shaped bytecode emitter).
//
// The DLL source is compiled for the x86_64-pc-windows-msvc target
// in production. Here we want to exercise the compiler logic on a
// host Linux toolchain so CTest can catch regressions without
// going through QEMU. We do that by:
//
//   1. Defining tiny Linux-side replacements for the dx_shared.h
//      Win32-flavour types (BYTE, UINT, ULONG, HRESULT, SIZE_T,
//      DxGuid) and the dx_heap_*/dx_memcpy/dx_memzero/dx_guid_eq
//      helpers (malloc/free/memcpy/memset under the hood).
//
//   2. Suppressing the parts of dx_shared.h that don't make sense
//      on a hosted Linux build (the `_fltused` MSVC PE symbol,
//      `__attribute__((dllexport))` markers).
//
//   3. Including the d3dcompiler.c source directly. It's
//      self-contained — every external symbol it references is
//      provided by the shim below.
//
// The compiler's correctness contract for v0:
//   - A trivial vs/ps shader compiles to a non-zero blob.
//   - The blob starts with the 'DXBC' magic.
//   - The blob is byte-exact between two compiles of the same
//     source (deterministic — important for round-tripping
//     through D3DReflect).
//   - Single-bit source changes produce different blobs (the
//     hash + emitted opcode stream are sensitive to inputs).
//   - Lex / parse failures surface as non-success HRESULTs,
//     and out_code is left null.

#include "host_test_helper.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

// --- dx_shared.h compatibility shim ---------------------------
// These mirror the names the d3dcompiler source expects, but
// rooted in standard C types instead of the MSVC ABI flavour.

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned long long UINT64;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef long LONG;
typedef int INT;
typedef int BOOL;
typedef unsigned long HRESULT;
typedef unsigned long long SIZE_T;
typedef long long SSIZE_T;
typedef void* HWND;
typedef void* HANDLE;
typedef void* HMODULE;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef unsigned int UINT32;
typedef unsigned long long UINT64_T;

#ifndef NULL
#define NULL ((void*)0)
#endif

#define DX_S_OK ((HRESULT)0x00000000UL)
#define DX_S_FALSE ((HRESULT)0x00000001UL)
#define DX_E_FAIL ((HRESULT)0x80004005UL)
#define DX_E_NOTIMPL ((HRESULT)0x80004001UL)
#define DX_E_NOINTERFACE ((HRESULT)0x80004002UL)
#define DX_E_POINTER ((HRESULT)0x80004003UL)
#define DX_E_INVALIDARG ((HRESULT)0x80070057UL)
#define DX_E_OUTOFMEMORY ((HRESULT)0x8007000EUL)
#define DXGI_ERROR_NOT_FOUND ((HRESULT)0x887A0002UL)
#define DXGI_ERROR_INVALID_CALL ((HRESULT)0x887A0001UL)

typedef struct DxGuid
{
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} DxGuid;

typedef const DxGuid* REFIID;

#define DX_NO_BUILTIN

static inline void dx_memzero(void* p, SIZE_T n)
{
    std::memset(p, 0, n);
}
static inline void dx_memset(void* p, int v, SIZE_T n)
{
    std::memset(p, v, n);
}
static inline void dx_memcpy(void* dst, const void* src, SIZE_T n)
{
    std::memcpy(dst, src, n);
}
static inline int dx_guid_eq(const DxGuid* a, const DxGuid* b)
{
    if (!a || !b)
        return 0;
    return std::memcmp(a, b, sizeof(DxGuid)) == 0;
}
static inline void* dx_heap_alloc(SIZE_T n)
{
    return std::malloc(n);
}
static inline void dx_heap_free(void* p)
{
    std::free(p);
}

static const DxGuid kIID_IUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

// dx_shared.h drops _fltused into every TU; we don't want it on
// Linux. The d3dcompiler source pulls dx_shared.h via the
// `#include "../dx_shared.h"` line — we satisfy that include
// with a stub header inline by setting an include guard.

#define DUETOS_DX_SHARED_H 1

// Expansion of `__attribute__((dllexport))` on a hosted compiler
// triggers -Wignored-attributes under -Werror. Map it away —
// downstream compile is identical because the host test calls
// these functions by name from this same TU.
#define dllexport_orig dllexport
#undef dllexport_orig

// We also want to avoid pulling in the canonical dx_shared.h from
// disk; the in-tree path is `userland/libs/dx_shared.h`. By
// defining DUETOS_DX_SHARED_H above, the header's include guard
// short-circuits even if the include is found by the preprocessor.

// --- include the d3dcompiler source as a translation unit ----

// Suppress the dllexport attribute warning by overriding via macro.
// The C source uses the form `__attribute__((dllexport))`; we
// replace `dllexport` with `used` so the attribute remains valid.
#define dllexport used

// d3dcompiler.c uses C-style linkage. Including it from C++ is fine
// because the file is mostly C-compatible syntax; the `volatile` /
// `static` semantics carry over. The source file is built for the
// MSVC target with -Wall -Wextra; the host test build adds
// -Wpedantic -Wconversion -Wsign-conversion -Werror, which trips
// on a handful of patterns the MSVC build accepts. Quiet those
// here so the test stays focused on the compiler's behaviour
// rather than its style.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wpedantic"

extern "C"
{
#include "../../userland/libs/d3dcompiler/d3dcompiler.c"
}

#pragma GCC diagnostic pop

#undef dllexport

// --- helpers for tests ---------------------------------------

// Compile + return the resulting blob on success. Caller frees
// via blob->lpVtbl->Release.
static HRESULT compile_source(const char* src, ID3DBlobImpl** out)
{
    return D3DCompile(src, std::strlen(src), "shader.hlsl", nullptr, nullptr, "main", "vs_4_0", 0, 0, out, nullptr);
}

// Hex-print a few bytes. Useful when a byte-exact comparison fails
// and we want to see the divergence in CI logs.
static void dump_blob_head(const char* label, const ID3DBlobImpl* b)
{
    if (!b || b->size == 0)
    {
        std::fprintf(stderr, "%s: <empty blob>\n", label);
        return;
    }
    std::fprintf(stderr, "%s: size=%llu head=", label, (unsigned long long)b->size);
    SIZE_T n = b->size < 8 ? b->size : 8;
    for (SIZE_T i = 0; i < n; ++i)
        std::fprintf(stderr, "%02x", (unsigned)b->data[i]);
    std::fprintf(stderr, "\n");
}

// --- tests ----------------------------------------------------

static int test_blob_create_release()
{
    ID3DBlobImpl* b = nullptr;
    EXPECT_EQ(D3DCreateBlob(64, &b), DX_S_OK);
    ASSERT_TRUE(b != nullptr);
    EXPECT_EQ(b->lpVtbl->GetBufferSize(b), (SIZE_T)64);
    EXPECT_TRUE(b->lpVtbl->GetBufferPointer(b) != nullptr);
    EXPECT_EQ(b->lpVtbl->Release(b), 0u);
    return 0;
}

static int test_compile_trivial_vertex_shader()
{
    static const char kSource[] = "struct VS_IN { float4 pos : POSITION; float4 col : COLOR; };\n"
                                  "struct VS_OUT { float4 pos : SV_POSITION; float4 col : COLOR; };\n"
                                  "VS_OUT main(VS_IN i) {\n"
                                  "    VS_OUT o;\n"
                                  "    o.pos = i.pos;\n"
                                  "    o.col = i.col;\n"
                                  "    return o;\n"
                                  "}\n";

    ID3DBlobImpl* blob = nullptr;
    HRESULT rc = compile_source(kSource, &blob);
    EXPECT_EQ(rc, DX_S_OK);
    ASSERT_TRUE(blob != nullptr);
    ASSERT_TRUE(blob->size >= 48);

    // DXBC magic is at offset 0.
    EXPECT_EQ(blob->data[0], (BYTE)'D');
    EXPECT_EQ(blob->data[1], (BYTE)'X');
    EXPECT_EQ(blob->data[2], (BYTE)'B');
    EXPECT_EQ(blob->data[3], (BYTE)'C');

    // Size field at offset 24 (little-endian).
    UINT total = (UINT)blob->data[24] | ((UINT)blob->data[25] << 8) | ((UINT)blob->data[26] << 16) |
                 ((UINT)blob->data[27] << 24);
    EXPECT_EQ((SIZE_T)total, blob->size);

    // Chunk count at offset 28 should be 4 (SHEX/ISGN/OSGN/STAT).
    UINT chunk_count = (UINT)blob->data[28] | ((UINT)blob->data[29] << 8) | ((UINT)blob->data[30] << 16) |
                       ((UINT)blob->data[31] << 24);
    EXPECT_EQ(chunk_count, 4u);

    // PeekBlobMagic should read 'DXBC'.
    UINT peek = DuetOS_D3DCompiler_PeekBlobMagic(blob);
    UINT want = (UINT)'D' | ((UINT)'X' << 8) | ((UINT)'B' << 16) | ((UINT)'C' << 24);
    EXPECT_EQ(peek, want);

    blob->lpVtbl->Release(blob);
    return 0;
}

static int test_compile_is_deterministic()
{
    static const char kSource[] = "float4 main(float4 p : POSITION) : SV_POSITION { return p; }\n";

    ID3DBlobImpl* a = nullptr;
    ID3DBlobImpl* b = nullptr;
    EXPECT_EQ(compile_source(kSource, &a), DX_S_OK);
    EXPECT_EQ(compile_source(kSource, &b), DX_S_OK);
    ASSERT_TRUE(a != nullptr);
    ASSERT_TRUE(b != nullptr);

    EXPECT_EQ(a->size, b->size);
    if (a->size == b->size)
    {
        const int eq = std::memcmp(a->data, b->data, a->size) == 0;
        if (!eq)
        {
            dump_blob_head("a", a);
            dump_blob_head("b", b);
        }
        EXPECT_TRUE(eq);
    }
    a->lpVtbl->Release(a);
    b->lpVtbl->Release(b);
    return 0;
}

static int test_compile_responds_to_source_changes()
{
    static const char kA[] = "float4 main(float4 p : POSITION) : SV_POSITION { return p; }\n";
    static const char kB[] = "float4 main(float4 p : POSITION) : SV_POSITION { return p + p; }\n";

    ID3DBlobImpl* a = nullptr;
    ID3DBlobImpl* b = nullptr;
    EXPECT_EQ(compile_source(kA, &a), DX_S_OK);
    EXPECT_EQ(compile_source(kB, &b), DX_S_OK);
    ASSERT_TRUE(a != nullptr);
    ASSERT_TRUE(b != nullptr);
    // Either size differs or hash differs; both blobs should not
    // be byte-equal because the SHEX opcode stream gained a binop.
    int same = (a->size == b->size) && (std::memcmp(a->data, b->data, a->size) == 0);
    EXPECT_FALSE(same);
    a->lpVtbl->Release(a);
    b->lpVtbl->Release(b);
    return 0;
}

static int test_compile_rejects_garbage()
{
    static const char kBad[] = "@@@ this is not HLSL @@@";
    ID3DBlobImpl* blob = nullptr;
    HRESULT rc = compile_source(kBad, &blob);
    EXPECT_NE(rc, DX_S_OK);
    EXPECT_TRUE(blob == nullptr);
    return 0;
}

static int test_d3dreflect_round_trip()
{
    static const char kSource[] = "float4 main(float4 p : POSITION) : SV_POSITION { return p; }\n";
    ID3DBlobImpl* blob = nullptr;
    EXPECT_EQ(compile_source(kSource, &blob), DX_S_OK);
    ASSERT_TRUE(blob != nullptr);

    void* refl = nullptr;
    HRESULT rc = D3DReflect(blob->data, blob->size, &kIID_IUnknown, &refl);
    EXPECT_EQ(rc, DX_S_OK);
    ASSERT_TRUE(refl != nullptr);
    ID3DBlobImpl* refl_blob = (ID3DBlobImpl*)refl;
    EXPECT_EQ(refl_blob->size, blob->size);
    EXPECT_EQ(std::memcmp(refl_blob->data, blob->data, blob->size), 0);
    refl_blob->lpVtbl->Release(refl_blob);
    blob->lpVtbl->Release(blob);
    return 0;
}

static int test_d3dreflect_rejects_non_dxbc()
{
    BYTE garbage[64] = {};
    void* refl = (void*)1;
    HRESULT rc = D3DReflect(garbage, sizeof(garbage), &kIID_IUnknown, &refl);
    EXPECT_EQ(rc, DX_E_INVALIDARG);
    EXPECT_TRUE(refl == nullptr);
    return 0;
}

int main()
{
    if (test_blob_create_release())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_compile_trivial_vertex_shader())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_compile_is_deterministic())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_compile_responds_to_source_changes())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_compile_rejects_garbage())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_d3dreflect_round_trip())
        return ::duetos_host_test::finish_main(__FILE__);
    if (test_d3dreflect_rejects_non_dxbc())
        return ::duetos_host_test::finish_main(__FILE__);
    return ::duetos_host_test::finish_main(__FILE__);
}
