#pragma once

// Early boot bring-up extracted from kernel_main (core/main.cpp),
// which was well over the project size guideline. This is the
// straight-line, side-effecting prologue: serial/klog online,
// build banner, CPU/hypervisor/SMBIOS/thermal probe, utility
// self-tests, KASLR seed, GDT/IDT/TSS/syscall gate, extable +
// fault-domain registry, driver-domain registrations, and the
// Multiboot2 memory-map parse + FrameAllocator init.
//
// Pure code motion: the block crosses no kernel_main locals — its
// only inputs are the two Multiboot2 handoff parameters and every
// effect lands on global/subsystem state. kernel_main calls this
// at the exact point the block used to run.

#include "util/types.h"

namespace duetos::core
{

void BootBringupEarly(duetos::u32 multiboot_magic, duetos::uptr multiboot_info);

// Memory + paging + debug-subsystem bring-up: FrameAllocator /
// Heap / Paging phase self-tests, KernelHeapInit, RunInitArray,
// PagingInit, ProtectKernelImage, BpInit, ProbeInit,
// FixJournalInit. No inputs, no outputs — pure code motion.
void BootBringupMemPaging();

} // namespace duetos::core
