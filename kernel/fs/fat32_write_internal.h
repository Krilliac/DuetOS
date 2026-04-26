#pragma once

// Cross-TU surface for the FAT32 driver's mutating side.
//
// fat32_write.cpp houses the file-content write/append/truncate
// path. fat32_create.cpp houses the directory-mutation publics
// (create/delete/mkdir/rmdir). Both touch a shared pool of FAT-
// allocation primitives + on-disk dir helpers — those live in
// fat32_write.cpp under `namespace duetos::fs::fat32::internal_write`
// and are declared here for the create-side TU to consume.
//
// Anything in `internal_write` is intended for the driver's own
// mutating TUs only; never include this header from outside
// kernel/fs/. The read-side primitives live in fat32_internal.h
// under `namespace internal`.

#include "../core/types.h"
#include "fat32.h"

namespace duetos::fs::fat32::internal_write
{

// FAT-table mutators. WriteFatEntry preserves the top 4 reserved
// bits and mirrors to every FAT copy; AllocateFreeCluster scans
// for the lowest free slot and marks it EOC; ZeroCluster wipes a
// freshly allocated cluster's data sectors; FreeClusterChain walks
// a chain releasing each link.
bool WriteFatEntry(const Volume& v, u32 cluster, u32 value);
u32 AllocateFreeCluster(const Volume& v);
bool ZeroCluster(const Volume& v, u32 cluster);
bool FreeClusterChain(const Volume& v, u32 first_cluster);

// On-disk SFN walker. `visit` receives the absolute sector LBA,
// the 32-byte offset inside that sector, the raw 32-byte record,
// and a decoded DirEntry. Returning false stops the walk.
using OnDiskSfnVisitor = bool (*)(u64 sector_lba, u32 off_in_sec, const u8* raw, const DirEntry& e, void* ctx);
bool WalkDirOnDisk(const Volume& v, u32 first_cluster, OnDiskSfnVisitor visit, void* ctx);

// Look up an entry by name inside `dir_cluster`'s chain (LFN-aware
// via WalkDirChain). Returns by value — `out` is caller storage.
bool FindInDirByName(const Volume& v, u32 dir_cluster, const char* want, DirEntry* out);

// Free-slot finder + run reservation, used by every dir-mutation
// path that plants a new entry.
bool FindFreeSlotInDir(const Volume& v, u32 first_cluster, u64* out_lba, u32* out_off);
bool ReserveRunInDir(const Volume& v, u32 dir_cluster, u32 count, u64* out_first_lba, u32* out_first_off);

// Path-resolution helpers used by every public *AtPath entry.
// SplitPath splits "/A/B/FILE" into parent="A/B" + base="FILE";
// ResolveParentDir then walks `parent` and reports its first
// cluster.
bool SplitPath(const char* path, char* parent_out, u32 parent_cap, char* base_out, u32 base_cap);
bool ResolveParentDir(const Volume& v, const char* path, u32* out_parent_cluster, char* base_out, u32 base_cap);

} // namespace duetos::fs::fat32::internal_write
