#include "elf64_parse.h"

#include <cstring>

namespace duetos::vmm
{

namespace
{

#pragma pack(push, 1)
struct Elf64Ehdr
{
    uint8_t  ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

struct Elf64Phdr
{
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};
#pragma pack(pop)

constexpr uint32_t PT_LOAD = 1;

// True iff [off, off+len) lies inside a `size`-byte buffer. Written as a
// subtraction because `off` and `len` are attacker-controlled: the
// natural `off + len > size` wraps for a hostile pair and then wrongly
// reports the range as in-bounds.
bool InFile(uint64_t off, uint64_t len, size_t size)
{
    return off <= size && len <= static_cast<uint64_t>(size) - off;
}

} // namespace

bool ParseElf64(const uint8_t* buf, size_t size, ParsedElf& out,
                std::string& err)
{
    if (buf == nullptr || size < sizeof(Elf64Ehdr))
    {
        err = "ELF truncated";
        return false;
    }

    Elf64Ehdr eh;
    std::memcpy(&eh, buf, sizeof(eh));
    if (!(eh.ident[0] == 0x7F && eh.ident[1] == 'E' && eh.ident[2] == 'L' &&
          eh.ident[3] == 'F'))
    {
        err = "bad ELF magic";
        return false;
    }
    if (eh.ident[4] != 2 /*ELFCLASS64*/ || eh.ident[5] != 1 /*LE*/ ||
        eh.machine != 62 /*EM_X86_64*/)
    {
        err = "not an x86_64 LE ELF64";
        return false;
    }
    if (static_cast<size_t>(eh.phentsize) != sizeof(Elf64Phdr) ||
        eh.phnum == 0)
    {
        err = "missing/invalid program headers";
        return false;
    }

    // The whole program-header table must lie inside the image before we
    // index into it — e_phoff is unvalidated input.
    if (!InFile(eh.phoff, uint64_t(eh.phnum) * eh.phentsize, size))
    {
        err = "program header table out of file";
        return false;
    }

    out.entry     = eh.entry;
    out.lowPaddr  = UINT64_MAX;
    out.highPaddr = 0;
    out.segments.clear();

    for (uint16_t i = 0; i < eh.phnum; ++i)
    {
        Elf64Phdr ph;
        std::memcpy(&ph, buf + eh.phoff + uint64_t(i) * eh.phentsize,
                    sizeof(ph));
        if (ph.type != PT_LOAD || ph.memsz == 0)
        {
            continue;
        }
        if (!InFile(ph.offset, ph.filesz, size))
        {
            err = "PT_LOAD file range out of file";
            return false;
        }
        if (ph.filesz > ph.memsz)
        {
            err = "PT_LOAD p_filesz exceeds p_memsz";
            return false;
        }
        // p_paddr + p_memsz is the segment's end address and feeds both
        // the guest-RAM sizing preflight and highPaddr. A wrap here would
        // under-report how much RAM the image needs.
        if (ph.memsz > UINT64_MAX - ph.paddr)
        {
            err = "PT_LOAD p_paddr + p_memsz overflows";
            return false;
        }

        out.segments.push_back({ph.offset, ph.paddr, ph.filesz, ph.memsz});
        if (ph.paddr < out.lowPaddr)
        {
            out.lowPaddr = ph.paddr;
        }
        if (ph.paddr + ph.memsz > out.highPaddr)
        {
            out.highPaddr = ph.paddr + ph.memsz;
        }
    }

    if (out.segments.empty())
    {
        err = "no PT_LOAD segments";
        out.lowPaddr = 0;
        return false;
    }
    return true;
}

} // namespace duetos::vmm
