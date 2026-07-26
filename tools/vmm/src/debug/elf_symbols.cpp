#include "debug/elf_symbols.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace duetos::vmm
{

namespace
{
#pragma pack(push, 1)
struct Ehdr
{
    uint8_t  ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Shdr
{
    uint32_t name;
    uint32_t type;
    uint64_t flags, addr, offset, size;
    uint32_t link, info;
    uint64_t addralign, entsize;
};
struct Sym64
{
    uint32_t name;
    uint8_t  info, other;
    uint16_t shndx;
    uint64_t value, size;
};
#pragma pack(pop)

constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;

// True iff [off, off+len) lies inside a `size`-byte buffer.
//
// Every offset/length pair below comes straight out of the ELF and is
// therefore attacker-controlled, so the test is written as a SUBTRACTION
// against `size` rather than the natural `off + len > size`: the latter
// wraps for a hostile off/len and silently reports "in range".
bool InFile(uint64_t off, uint64_t len, size_t size)
{
    return off <= size && len <= static_cast<uint64_t>(size) - off;
}
} // namespace

bool ElfSymbols::Load(const std::string& elfPath)
{
    std::ifstream f(elfPath, std::ios::binary);
    if (!f) return false;
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
    if (b.size() < sizeof(Ehdr)) return false;

    Ehdr eh;
    std::memcpy(&eh, b.data(), sizeof(eh));
    if (std::memcmp(eh.ident, "\x7F"
                              "ELF",
                    4) != 0 ||
        static_cast<size_t>(eh.shentsize) != sizeof(Shdr))
    {
        return false;
    }

    // The WHOLE section-header table must lie inside the file before any
    // shdr() call indexes into it — e_shoff is unvalidated input. (An
    // e_shnum of 0 means "the real count lives in section 0's sh_size";
    // the kernel ELF never has >65280 sections, so declining is safe and
    // just degrades to address-only introspection.)
    if (eh.shnum == 0 ||
        !InFile(eh.shoff, uint64_t(eh.shnum) * eh.shentsize, b.size()))
    {
        return false;
    }

    auto shdr = [&](uint16_t i) { // safe for i < eh.shnum
        Shdr s;
        std::memcpy(&s, b.data() + eh.shoff + uint64_t(i) * eh.shentsize,
                    sizeof(s));
        return s;
    };

    for (uint16_t i = 0; i < eh.shnum; ++i)
    {
        Shdr s = shdr(i);
        if (s.type != SHT_SYMTAB || s.entsize != sizeof(Sym64))
        {
            continue;
        }
        // A malformed symtab is SKIPPED rather than fatal: a partially
        // parsable ELF should still yield whatever symbols it does hold.
        if (s.link >= static_cast<uint32_t>(eh.shnum) ||
            !InFile(s.offset, s.size, b.size()))
        {
            continue;
        }
        const Shdr str = shdr(static_cast<uint16_t>(s.link)); // .strtab
        if (str.type != SHT_STRTAB ||
            !InFile(str.offset, str.size, b.size()))
        {
            continue;
        }
        const char* strtab =
            reinterpret_cast<const char*>(b.data() + str.offset);
        const uint64_t strBytes = str.size;
        const uint64_t n = s.size / sizeof(Sym64);
        for (uint64_t k = 0; k < n; ++k)
        {
            Sym64 sy;
            std::memcpy(&sy, b.data() + s.offset + k * sizeof(Sym64),
                        sizeof(sy));
            const uint8_t stt = sy.info & 0xF; // STT_FUNC=2, OBJECT=1
            if ((stt != 1 && stt != 2) || sy.value == 0 ||
                sy.name == 0)
            {
                continue;
            }
            if (sy.name >= strBytes)
            {
                continue; // name offset outside .strtab
            }
            // .strtab is not guaranteed NUL-terminated, so the name ends
            // at the first NUL OR at the end of the section — whichever
            // comes first. A bare std::string(const char*) here would
            // scan past the mapping looking for a zero byte.
            const char*    p      = strtab + sy.name;
            const uint64_t maxLen = strBytes - sy.name;
            uint64_t       len    = 0;
            while (len < maxLen && p[len] != '\0')
            {
                ++len;
            }
            m_syms.push_back(
                {std::string(p, static_cast<size_t>(len)), sy.value,
                 sy.size});
        }
    }

    std::sort(m_syms.begin(), m_syms.end(),
              [](const Sym& a, const Sym& c) {
                  return a.addr < c.addr;
              });
    return !m_syms.empty();
}

std::string ElfSymbols::Symbolize(uint64_t addr) const
{
    char hex[24];
    std::snprintf(hex, sizeof(hex), "0x%llx",
                  (unsigned long long)addr);
    if (m_syms.empty())
    {
        return hex;
    }
    // Largest addr <= target.
    auto it = std::upper_bound(
        m_syms.begin(), m_syms.end(), addr,
        [](uint64_t v, const Sym& s) { return v < s.addr; });
    if (it == m_syms.begin())
    {
        return hex;
    }
    --it;
    char out[160];
    std::snprintf(out, sizeof(out), "%s+0x%llx (%s)",
                  it->name.c_str(),
                  (unsigned long long)(addr - it->addr), hex);
    return out;
}

const ElfSymbols::Sym* ElfSymbols::Find(const std::string& name) const
{
    for (const Sym& s : m_syms)
    {
        if (s.name == name)
        {
            return &s;
        }
    }
    return nullptr;
}

const ElfSymbols::Sym* ElfSymbols::FindBySuffix(const std::string& query) const
{
    if (query.empty())
    {
        return nullptr;
    }

    // Build the Itanium length-prefixed token we're looking for.
    // e.g. query="g_ticks" (7 chars) → needle="7g_ticks"
    std::string needle = std::to_string(query.size()) + query;

    const Sym* best       = nullptr;
    bool       bestIsAnon = false;

    for (const Sym& s : m_syms)
    {
        if (s.name.find(needle) == std::string::npos)
        {
            continue;
        }

        bool isAnon = (s.name.find("_GLOBAL__N_") != std::string::npos);

        if (best == nullptr)
        {
            best       = &s;
            bestIsAnon = isAnon;
            continue;
        }

        // Prefer named-namespace over anonymous-namespace.
        if (isAnon && !bestIsAnon)
        {
            continue;
        }
        if (!isAnon && bestIsAnon)
        {
            best       = &s;
            bestIsAnon = false;
            continue;
        }

        // Both have the same anon status — prefer smaller address
        // for determinism.
        if (s.addr < best->addr)
        {
            best       = &s;
            bestIsAnon = isAnon;
        }
    }

    return best;
}

} // namespace duetos::vmm
