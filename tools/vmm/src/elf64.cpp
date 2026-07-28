#include "elf64.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "elf64_parse.h"

namespace duetos::vmm
{

LoadedImage LoadElf64(const std::string& path, GuestMemory& mem)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        throw std::runtime_error("cannot open kernel ELF: " + path);
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());

    // All header/bounds validation lives in the pure ParseElf64 (see
    // elf64_parse.h) so it can be tested against hostile inputs without a
    // WHP partition. By the time we get here every segment's file range
    // is known to lie inside `buf` and paddr+memsz is known not to wrap.
    ParsedElf   pe;
    std::string err;
    if (!ParseElf64(buf.data(), buf.size(), pe, err))
    {
        throw std::runtime_error(err);
    }

    // Pre-flight: compare the highest paddr+memsz across all PT_LOAD
    // segments to guest RAM size. Without this check, a too-small --mem
    // dies deep inside mem.Write() on the first overflowing segment with
    // a generic "past end of RAM" — a single-error message naming the
    // kernel's actual size requirement is much more useful, and firing it
    // BEFORE any partial load happens means we don't leave guest RAM in a
    // half-written state.
    if (pe.highPaddr > mem.size())
    {
        // Ceiling-divide without the `+ (1<<20) - 1` rounding step: a
        // segment ending in the top MiB of the address space (paddr +
        // memsz == UINT64_MAX is reachable — ParseElf64 only rejects a
        // strict overflow) would wrap that addition and report
        // "needs >= 0 MiB ... try --mem 0".
        const unsigned long long needMiB =
            static_cast<unsigned long long>((pe.highPaddr >> 20) +
                                            ((pe.highPaddr & 0xFFFFF) ? 1 : 0));
        const unsigned long long haveMiB =
            static_cast<unsigned long long>(mem.size() >> 20);
        char msg[256];
        std::snprintf(msg, sizeof(msg),
                      "kernel ELF needs >= %llu MiB of guest RAM "
                      "(highest paddr+memsz = 0x%llx); --mem %llu "
                      "is too small. Try --mem %llu or higher.",
                      needMiB,
                      static_cast<unsigned long long>(pe.highPaddr),
                      haveMiB, needMiB);
        throw std::runtime_error(msg);
    }

    for (const LoadSegment& seg : pe.segments)
    {
        // Load file bytes at the segment's physical address; zero the
        // .bss tail (memsz > filesz).
        mem.Write(seg.paddr, buf.data() + seg.offset, seg.filesz);
        if (seg.memsz > seg.filesz)
        {
            void* bss =
                mem.HostPtr(seg.paddr + seg.filesz, seg.memsz - seg.filesz);
            if (bss == nullptr)
            {
                throw std::runtime_error("PT_LOAD bss past end of RAM");
            }
            std::memset(bss, 0, static_cast<size_t>(seg.memsz - seg.filesz));
        }
    }

    LoadedImage img;
    img.entry     = pe.entry;
    img.lowPaddr  = pe.lowPaddr;
    img.highPaddr = pe.highPaddr;
    return img;
}

} // namespace duetos::vmm
