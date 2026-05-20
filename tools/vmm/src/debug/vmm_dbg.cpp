// vmm_dbg — implementation.
// See vmm_dbg.h for the public contract and usage notes.
#include "debug/vmm_dbg.h"

#include <cstdio>
#include <cstring>

// The LiveResolver body includes vmm.h (which drags in WHP headers).
// Gate it so the test binary (VMM_DBG_NO_LIVE) compiles without WHP.
#ifndef VMM_DBG_NO_LIVE
#include "vmm.h"
#endif

namespace duetos::vmm::vmm_dbg
{

// ---------------------------------------------------------------------------
// Resolver registry
// ---------------------------------------------------------------------------

namespace
{
Resolver* g_testResolver = nullptr;

#ifndef VMM_DBG_NO_LIVE
// Production resolver: routes through Vmm::Active().
struct LiveResolver final : Resolver
{
    bool FindSym(const char* name, uint64_t& va, uint64_t& sz) override
    {
        Vmm* v = Vmm::Active();
        if (!v)
        {
            return false;
        }

        // 1. Exact match against the mangled symbol table.
        const ElfSymbols::Sym* s = v->DbgFindSym(name);
        if (s)
        {
            va = s->addr;
            sz = s->size;
            return true;
        }

        // 2. Suffix fallback: find rightmost <len><name> in mangled names.
        s = v->DbgSymbols().FindBySuffix(name);
        if (s)
        {
            va = s->addr;
            sz = s->size;
            return true;
        }

        return false;
    }

    void* HostPtrForGva(uint64_t gva, uint64_t len) override
    {
        Vmm* v = Vmm::Active();
        if (!v)
        {
            return nullptr;
        }
        uint64_t gpa = 0;
        if (!v->DbgResolveGpa(gva, gpa))
        {
            return nullptr;
        }
        return v->DbgHostPtr(gpa, len);
    }

    const char* Symbolize(uint64_t addr) override
    {
        Vmm* v = Vmm::Active();
        if (!v)
        {
            return "<no vmm>";
        }
        // Symbolize returns std::string; we stash it in a thread-local.
        thread_local char buf[160];
        std::string s = v->DbgSymbols().Symbolize(addr);
        std::snprintf(buf, sizeof(buf), "%s", s.c_str());
        return buf;
    }
};

LiveResolver g_liveResolver;
#endif // VMM_DBG_NO_LIVE

Resolver* ActiveResolver()
{
    if (g_testResolver)
    {
        return g_testResolver;
    }
#ifndef VMM_DBG_NO_LIVE
    return &g_liveResolver;
#else
    return nullptr;
#endif
}

// Deliberately does NOT check that `len` fits within the symbol's
// ELF-recorded size (`sz` from FindSym). A debugger user legitimately
// wants to over-read past a global's nominal size when poking at
// adjacent data, and many kernel symbols have sz==0 (stripped or
// uninitialised). HostPtrForGva bounds-checks against the GPA range
// itself, so the worst case is reading zeros / garbage outside the
// intended object — never a host-side OOB.
//
// Read `len` bytes from the named symbol into `dst`. Returns true on
// success; false if the symbol is missing or the GVA is unmapped.
bool ReadRaw(const char* name, void* dst, uint64_t len)
{
    Resolver* r = ActiveResolver();
    if (!r)
    {
        return false;
    }
    uint64_t va = 0, sz = 0;
    if (!r->FindSym(name, va, sz))
    {
        return false;
    }
    void* p = r->HostPtrForGva(va, len);
    if (!p)
    {
        return false;
    }
    std::memcpy(dst, p, static_cast<size_t>(len));
    return true;
}

// Write `len` bytes from `src` to the named symbol. Silent no-op on error.
void WriteRaw(const char* name, const void* src, uint64_t len)
{
    Resolver* r = ActiveResolver();
    if (!r)
    {
        return;
    }
    uint64_t va = 0, sz = 0;
    if (!r->FindSym(name, va, sz))
    {
        return;
    }
    void* p = r->HostPtrForGva(va, len);
    if (!p)
    {
        return;
    }
    std::memcpy(p, src, static_cast<size_t>(len));
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

uint64_t ReadQ(const char* name)
{
    uint64_t v = 0;
    ReadRaw(name, &v, sizeof(v));
    return v;
}

uint32_t ReadD(const char* name)
{
    uint32_t v = 0;
    ReadRaw(name, &v, sizeof(v));
    return v;
}

uint16_t ReadW(const char* name)
{
    uint16_t v = 0;
    ReadRaw(name, &v, sizeof(v));
    return v;
}

uint8_t ReadB(const char* name)
{
    uint8_t v = 0;
    ReadRaw(name, &v, sizeof(v));
    return v;
}

void WriteQ(const char* name, uint64_t value)
{
    WriteRaw(name, &value, sizeof(value));
}

void WriteD(const char* name, uint32_t value)
{
    WriteRaw(name, &value, sizeof(value));
}

void WriteW(const char* name, uint16_t value)
{
    WriteRaw(name, &value, sizeof(value));
}

void WriteB(const char* name, uint8_t value)
{
    WriteRaw(name, &value, sizeof(value));
}

const char* Sym(uint64_t guestAddr)
{
    thread_local char buf[160];
    Resolver* r = ActiveResolver();
    if (!r)
    {
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      (unsigned long long)guestAddr);
        return buf;
    }
    const char* s = r->Symbolize(guestAddr);
    std::snprintf(buf, sizeof(buf), "%s", s ? s : "?");
    return buf;
}

const char* Dump(const char* name, size_t n)
{
    // Cap at 256 bytes → at most 256*3 = 768 hex chars + slack.
    static constexpr size_t kMaxBytes  = 256;
    static constexpr size_t kBufBytes  = kMaxBytes * 3 + 4;
    thread_local char        buf[kBufBytes];

    if (n > kMaxBytes)
    {
        n = kMaxBytes;
    }

    Resolver* r = ActiveResolver();
    if (!r || n == 0)
    {
        buf[0] = '\0';
        return buf;
    }

    uint64_t va = 0, sz = 0;
    if (!r->FindSym(name, va, sz))
    {
        std::snprintf(buf, sizeof(buf), "<symbol not found: %s>", name);
        return buf;
    }

    void* p = r->HostPtrForGva(va, n);
    if (!p)
    {
        std::snprintf(buf, sizeof(buf), "<unmapped: %s>", name);
        return buf;
    }

    const uint8_t* bytes  = static_cast<const uint8_t*>(p);
    size_t         offset = 0;
    for (size_t i = 0; i < n && offset + 3 < kBufBytes; ++i)
    {
        offset += static_cast<size_t>(
            std::snprintf(buf + offset, kBufBytes - offset,
                          "%02x ", bytes[i]));
    }
    // Trim trailing space if any was written.
    if (offset > 0 && buf[offset - 1] == ' ')
    {
        buf[offset - 1] = '\0';
    }
    return buf;
}

void SetTestResolver(Resolver* r)
{
    g_testResolver = r;
}

} // namespace duetos::vmm::vmm_dbg
