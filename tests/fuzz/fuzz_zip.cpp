// DuetOS — ZIP archive reader fuzz harness.
//
// ZipOpen finds the end-of-central-directory record, then
// ZipReadEntry walks each central-directory header and
// ZipExtractEntry chases the local-file-header and inflates the
// payload. Every offset (CD offset/size, per-entry local
// offset, compressed/uncompressed sizes, filename length) comes
// from the archive bytes — a ZIP on any USB stick. The harness
// opens the input as an archive and, on success, reads + extracts
// every entry into a bounded buffer so the CD walk, the
// local-header chase, and the stored/deflate paths all see
// hostile input.

#include "util/zip.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    duetos::util::ZipReader r{};
    if (duetos::util::ZipOpen(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size), &r) !=
        duetos::util::ZipStatus::Ok)
        return 0;

    static duetos::u8 out[256u * 1024u];
    const duetos::u32 n = r.entry_count > 4096u ? 4096u : r.entry_count;
    for (duetos::u32 i = 0; i < n; ++i)
    {
        duetos::util::ZipEntryInfo info{};
        if (duetos::util::ZipReadEntry(r, i, &info) != duetos::util::ZipStatus::Ok)
            continue;
        duetos::u32 wrote = 0;
        (void)duetos::util::ZipExtractEntry(r, i, out, sizeof(out), &wrote);
    }
    return 0;
}
