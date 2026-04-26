#pragma once

// Private cross-TU surface for the FAT32 driver. Splits the
// implementation into two translation units that share the
// primitives below:
//
//   fat32.cpp        — read-only path (probe, list, lookup, read,
//                      stream) plus the definitions of every symbol
//                      declared in this header.
//   fat32_write.cpp  — mutating path (write-in-place, append,
//                      create, delete, truncate, mkdir, rmdir).
//
// Anything in `namespace duetos::fs::fat32::internal` is intended
// for the driver's own TUs only — never include this header from
// outside kernel/fs/. The public API lives in fat32.h.

#include "../core/types.h"
#include "fat32.h"

namespace duetos::fs::fat32::internal
{

// FAT attribute byte bits (spec §6.1). Only the ones the driver
// consults are exposed here.
inline constexpr u8 kAttrVolumeId = 0x08;
inline constexpr u8 kAttrDirectory = 0x10;
inline constexpr u8 kAttrLongName = 0x0F; // read_only | hidden | system | volume_id

// Shared scratch buffer for any single sector / cluster read. The
// driver-wide mutex (Fat32Guard) keeps concurrent ring-3 callers
// from clobbering each other's staging.
extern u8 g_scratch[4096];

// RAII recursive lock around every public Fat32 entry. Defined out
// of line so this header doesn't have to drag sched/sched.h into
// every consumer.
class Fat32Guard
{
  public:
    Fat32Guard();
    ~Fat32Guard();
    Fat32Guard(const Fat32Guard&) = delete;
    Fat32Guard& operator=(const Fat32Guard&) = delete;

  private:
    bool owns_ = false;
};

// Volatile byte zeroer / DirEntry copier. Routes around clang's
// memset/memcpy lowering that the freestanding kernel can't link.
void VZero(void* p, u64 n);
void CopyEntry(DirEntry& dst, const DirEntry& src);

// Little-endian readers off a raw byte buffer.
u16 LeU16(const u8* p);
u32 LeU32(const u8* p);

// Render an 11-byte FAT 8.3 record into "NAME.EXT\0" form.
void FormatShortName(const u8* name, char* out);

// One-sector / one-cluster reads into g_scratch.
bool ReadSector(u32 handle, u64 lba);
bool ReadCluster(const Volume& v, u32 cluster);

// Read the FAT entry for `cluster`. Returns 0x0FFFFFFF on I/O
// error so the walker terminates cleanly instead of looping.
u32 ReadFatEntry(const Volume& v, u32 cluster);

// Name predicates used by every walker.
bool IsDotEntry(const char* n);
bool NameIEqual(const char* a, const char* b);

// Decode one 32-byte on-disk record into a DirEntry.
void DecodeEntry(const u8* e, DirEntry& out);

// Pull the 13 UTF-16 codepoints out of an LFN fragment.
void DecodeLfnChars(const u8* e, char* out_chars, bool* did_terminate);

// FAT32 short-name checksum (spec §7.2). Both the LFN-validation
// and LFN-emission paths need it.
u8 ComputeLfnChecksum(const u8* sfn11);

// Visitor callback for the cluster-chain walker. Returning false
// stops the walk; the walker still reports success.
using DirVisitor = bool (*)(const DirEntry& e, void* ctx);

// Walk a directory's cluster chain, decode each in-use entry
// (stitching LFN fragments into DirEntry.name when present), and
// feed it to `visit`. Returns true on clean completion (end-of-dir,
// EOC, or visitor stop) and false on I/O error.
bool WalkDirChain(const Volume& v, u32 first_cluster, DirVisitor visit, void* ctx);

// Refill a Volume's cached root snapshot. Both the read side
// (Fat32Probe) and the write side (every mutator that touches the
// root directory) call this to keep Fat32FindInRoot's snapshot
// consistent with on-disk state.
bool WalkRootIntoSnapshot(Volume& v, u32 first_cluster);

} // namespace duetos::fs::fat32::internal
