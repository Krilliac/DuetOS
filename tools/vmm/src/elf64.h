// Minimal ELF64 program loader. Reads PT_LOAD segments into guest
// physical memory at their physical addresses (p_paddr) — which is
// what a Multiboot2 loader does: the kernel's linker.ld places
// .text.boot at a low LMA and boot.S relocates to the higher half
// itself. We only honour LMA here.
#pragma once

#include <cstdint>
#include <string>

#include "guest_memory.h"

namespace duetos::vmm
{

struct LoadedImage
{
    uint64_t entry = 0;       // ELF e_entry (physical/low for boot.S)
    uint64_t lowPaddr = 0;    // lowest p_paddr loaded
    uint64_t highPaddr = 0;   // highest p_paddr+p_memsz loaded
};

// Loads `path` (an ELF64 little-endian x86_64 executable) into `mem`.
// Throws std::runtime_error on any malformed/unsupported input.
LoadedImage LoadElf64(const std::string& path, GuestMemory& mem);

} // namespace duetos::vmm
