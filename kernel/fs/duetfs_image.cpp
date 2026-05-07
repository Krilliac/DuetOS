// DuetFS — synthesized self-test image builder.
//
// Produces a minimal v0 image (4 blocks × 4 KiB) holding one root
// directory and one file ("hello.txt" → "Hello, DuetFS!"). The
// layout is documented inline below; it deliberately mirrors the
// invariants the Rust crate's image.rs / lookup.rs expect.

#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "util/types.h"

namespace duetos::fs::duetfs
{

namespace
{

constexpr u32 kBlock = kBlockSize; // 4096

void Write32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v & 0xFF);
    p[1] = static_cast<u8>((v >> 8) & 0xFF);
    p[2] = static_cast<u8>((v >> 16) & 0xFF);
    p[3] = static_cast<u8>((v >> 24) & 0xFF);
}

void Write64(u8* p, u64 v)
{
    Write32(p, static_cast<u32>(v));
    Write32(p + 4, static_cast<u32>(v >> 32));
}

void WriteName(u8* node_base, const char* name, u32 name_len)
{
    // Node layout (kept in sync with kernel/fs/duetfs/src/format.rs):
    //   off  0: u32 kind
    //   off  4: u32 size_bytes
    //   off  8: u32 first_block
    //   off 12: u32 child_count
    //   off 16: u32 name_len
    //   off 20: u32 reserved
    //   off 24: u8  name[64]
    //   off 88: u8  pad[168]
    Write32(node_base + 16, name_len);
    for (u32 i = 0; i < 64; ++i)
    {
        node_base[24 + i] = (i < name_len) ? static_cast<u8>(name[i]) : 0;
    }
}

void Zero(u8* p, u32 n)
{
    for (u32 i = 0; i < n; ++i)
    {
        p[i] = 0;
    }
}

} // namespace

void BuildSelfTestImage(u8* out_buf)
{
    Zero(out_buf, kSelfTestImageBytes);

    // ---- Block 0: superblock ------------------------------------
    u8* sb = out_buf + 0 * kBlock;
    Write64(sb + 0, kMagic);  // u64 magic
    Write32(sb + 8, 1);       // u32 version
    Write32(sb + 12, kBlock); // u32 block_size
    Write32(sb + 16, 4);      // u32 total_blocks
    Write32(sb + 20, 2);      // u32 node_count (root + file)
    Write32(sb + 24, 0);      // u32 root_node
    Write32(sb + 28, 1);      // u32 node_table_start (block 1)
    Write32(sb + 32, 2);      // u32 data_start (block 2)
    // 32 bytes of reserved already zeroed.

    // ---- Block 1: node table ------------------------------------
    u8* nodes = out_buf + 1 * kBlock;

    // Node 0: root directory. No name (root has no parent).
    u8* n0 = nodes + 0 * kNodeSize;
    Write32(n0 + 0, kKindDir); // kind = dir
    Write32(n0 + 4, 4);        // size_bytes = 1 child * 4 bytes
    Write32(n0 + 8, 2);        // first_block = block 2 (child id list)
    Write32(n0 + 12, 1);       // child_count = 1
    WriteName(n0, "", 0);

    // Node 1: file "hello.txt".
    u8* n1 = nodes + 1 * kNodeSize;
    Write32(n1 + 0, kKindFile);
    Write32(n1 + 4, 14); // size_bytes = strlen("Hello, DuetFS!")
    Write32(n1 + 8, 3);  // first_block = block 3
    Write32(n1 + 12, 0);
    WriteName(n1, "hello.txt", 9);

    // ---- Block 2: root dir's child id list ----------------------
    u8* children = out_buf + 2 * kBlock;
    Write32(children + 0, 1); // child[0] = node 1 (the file)

    // ---- Block 3: file contents ---------------------------------
    u8* data = out_buf + 3 * kBlock;
    const char hello[] = "Hello, DuetFS!";
    for (u32 i = 0; i < 14; ++i)
    {
        data[i] = static_cast<u8>(hello[i]);
    }
}

} // namespace duetos::fs::duetfs
