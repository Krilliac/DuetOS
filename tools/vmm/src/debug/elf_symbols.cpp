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
        eh.shentsize != sizeof(Shdr))
    {
        return false;
    }

    auto shdr = [&](uint16_t i) {
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
        Shdr str = shdr(static_cast<uint16_t>(s.link)); // .strtab
        const char* strtab =
            reinterpret_cast<const char*>(b.data() + str.offset);
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
            m_syms.push_back(
                {std::string(strtab + sy.name), sy.value, sy.size});
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

} // namespace duetos::vmm
