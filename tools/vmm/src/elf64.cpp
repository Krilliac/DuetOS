#include "elf64.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

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

} // namespace

LoadedImage LoadElf64(const std::string& path, GuestMemory& mem)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        throw std::runtime_error("cannot open kernel ELF: " + path);
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(Elf64Ehdr))
    {
        throw std::runtime_error("ELF truncated");
    }

    Elf64Ehdr eh;
    std::memcpy(&eh, buf.data(), sizeof(eh));
    if (!(eh.ident[0] == 0x7F && eh.ident[1] == 'E' &&
          eh.ident[2] == 'L' && eh.ident[3] == 'F'))
    {
        throw std::runtime_error("bad ELF magic");
    }
    if (eh.ident[4] != 2 /*ELFCLASS64*/ || eh.ident[5] != 1 /*LE*/ ||
        eh.machine != 62 /*EM_X86_64*/)
    {
        throw std::runtime_error("not an x86_64 LE ELF64");
    }
    if (eh.phentsize != sizeof(Elf64Phdr) || eh.phnum == 0)
    {
        throw std::runtime_error("missing/invalid program headers");
    }

    LoadedImage img;
    img.entry = eh.entry;
    img.lowPaddr = UINT64_MAX;

    for (uint16_t i = 0; i < eh.phnum; ++i)
    {
        const uint64_t off = eh.phoff + uint64_t(i) * eh.phentsize;
        if (off + sizeof(Elf64Phdr) > buf.size())
        {
            throw std::runtime_error("program header out of file");
        }
        Elf64Phdr ph;
        std::memcpy(&ph, buf.data() + off, sizeof(ph));
        if (ph.type != PT_LOAD || ph.memsz == 0)
        {
            continue;
        }
        if (ph.offset + ph.filesz > buf.size())
        {
            throw std::runtime_error("PT_LOAD file range out of file");
        }

        // Load file bytes at the segment's physical address; zero the
        // .bss tail (memsz > filesz).
        mem.Write(ph.paddr, buf.data() + ph.offset, ph.filesz);
        if (ph.memsz > ph.filesz)
        {
            void* bss = mem.HostPtr(ph.paddr + ph.filesz,
                                    ph.memsz - ph.filesz);
            if (bss == nullptr)
            {
                throw std::runtime_error("PT_LOAD bss past end of RAM");
            }
            std::memset(bss, 0,
                        static_cast<size_t>(ph.memsz - ph.filesz));
        }

        if (ph.paddr < img.lowPaddr)
        {
            img.lowPaddr = ph.paddr;
        }
        if (ph.paddr + ph.memsz > img.highPaddr)
        {
            img.highPaddr = ph.paddr + ph.memsz;
        }
    }

    if (img.lowPaddr == UINT64_MAX)
    {
        throw std::runtime_error("no PT_LOAD segments");
    }
    return img;
}

} // namespace duetos::vmm
