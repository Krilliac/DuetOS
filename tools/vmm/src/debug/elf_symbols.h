// Kernel ELF symbol resolver. Parses .symtab/.strtab so the
// introspection layer can map an address to the nearest symbol
// ("where is RIP?") and a name to its address+size ("dump
// g_ticks"). Deliberately NOT a DWARF type engine — symbol-level
// resolution is robust and version-independent; type-aware
// pretty-printing is a later slice.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace duetos::vmm
{

class ElfSymbols
{
public:
    struct Sym
    {
        std::string name;
        uint64_t    addr = 0;
        uint64_t    size = 0;
    };

    // Loads function/object symbols from `elfPath`. Missing symbols
    // are non-fatal (introspection just degrades to addresses).
    bool Load(const std::string& elfPath);

    // Nearest symbol at or below `addr`; formats "name+0xoff" or the
    // bare hex address if nothing covers it.
    std::string Symbolize(uint64_t addr) const;

    // Exact-name lookup. Returns nullptr if absent.
    const Sym* Find(const std::string& name) const;

    // Suffix-match lookup against mangled Itanium names. Searches for
    // `<len><query>` in each mangled name (Itanium length-prefixed
    // identifier). If multiple symbols match, prefer the one without
    // `_GLOBAL__N_` (anonymous namespace); break remaining ties by
    // smallest address. Returns nullptr if nothing matches.
    //
    // Used by both the live LiveResolver path and unit tests (the matching
    // AddSymForTest test seam below is gated; FindBySuffix is not).
    const Sym* FindBySuffix(const std::string& query) const;

    size_t count() const { return m_syms.size(); }

#ifdef VMM_DBG_NO_LIVE
    // Test-only seam: inject a synthesised symbol without loading an ELF.
    void AddSymForTest(const Sym& s) { m_syms.push_back(s); }
#endif

private:
    std::vector<Sym> m_syms; // sorted by addr
};

} // namespace duetos::vmm
