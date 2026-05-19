#include "multiboot2.h"

#include <cstring>

namespace duetos::vmm
{

namespace
{

void Align8(std::vector<uint8_t>& v)
{
    while (v.size() % 8 != 0)
    {
        v.push_back(0);
    }
}

void Push32(std::vector<uint8_t>& v, uint32_t x)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&x);
    v.insert(v.end(), p, p + 4);
}

void Push64(std::vector<uint8_t>& v, uint64_t x)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&x);
    v.insert(v.end(), p, p + 8);
}

// Begins a tag, returns the offset of its size field for back-patch.
size_t BeginTag(std::vector<uint8_t>& v, uint32_t type)
{
    Align8(v);
    Push32(v, type);
    size_t sizeOff = v.size();
    Push32(v, 0); // size, patched in EndTag
    return sizeOff;
}

void EndTag(std::vector<uint8_t>& v, size_t sizeOff)
{
    uint32_t sz = static_cast<uint32_t>(v.size() - (sizeOff - 4));
    std::memcpy(v.data() + sizeOff, &sz, 4);
}

} // namespace

std::vector<uint8_t> BuildMultiboot2Info(const Mb2Params& p)
{
    std::vector<uint8_t> v;
    Push32(v, 0); // total_size, patched at end
    Push32(v, 0); // reserved

    // --- Tag 1: boot command line ---
    {
        size_t s = BeginTag(v, 1);
        v.insert(v.end(), p.cmdline.begin(), p.cmdline.end());
        v.push_back(0);
        EndTag(v, s);
    }

    // --- Tag 4: basic memory info (KiB, classic 640K/ext split) ---
    {
        size_t s = BeginTag(v, 4);
        Push32(v, 640);                                   // mem_lower
        Push32(v, static_cast<uint32_t>(
                       (p.ramBytes - 0x100000) / 1024));   // mem_upper
        EndTag(v, s);
    }

    // --- Tag 6: memory map ---
    {
        size_t s = BeginTag(v, 6);
        Push32(v, 24); // entry_size
        Push32(v, 0);  // entry_version
        auto entry = [&](uint64_t base, uint64_t len, uint32_t type) {
            Push64(v, base);
            Push64(v, len);
            Push32(v, type);
            Push32(v, 0);
        };
        // type 2 = reserved, type 1 = available RAM.
        entry(0, p.reservedEnd, 2);
        entry(p.reservedEnd, p.ramBytes - p.reservedEnd, 1);
        EndTag(v, s);
    }

    // --- Tag 15: ACPI new RSDP (verbatim 36-byte ACPI 2.0 RSDP) ---
    {
        size_t s = BeginTag(v, 15);
        v.insert(v.end(), p.rsdp.begin(), p.rsdp.end());
        EndTag(v, s);
    }

    // --- Tag 0: end ---
    {
        Align8(v);
        Push32(v, 0);
        Push32(v, 8);
    }

    uint32_t total = static_cast<uint32_t>(v.size());
    std::memcpy(v.data(), &total, 4);
    return v;
}

} // namespace duetos::vmm
