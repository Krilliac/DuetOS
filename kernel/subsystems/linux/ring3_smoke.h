#pragma once

/*
 * DuetOS — Linux-ABI ring-3 smoke test.
 *
 * Companion to core/ring3_smoke.cpp. Constructs a minimal ring-3
 * task whose payload is a raw `syscall` instruction sequence:
 *
 *   mov  eax, 231          ; SYS_EXIT_GROUP
 *   mov  edi, 0x42          ; exit code
 *   syscall
 *   ud2                     ; unreachable guard
 *
 * Sets Process::abi_flavor = kAbiLinux so the task's ring-3
 * boundary crossings reach subsystems::linux::LinuxSyscallDispatch
 * via MSR_LSTAR instead of the native int-0x80 path. Successful
 * exit (SchedExit from inside DoExitGroup) proves the whole chain:
 *   MSR_LSTAR -> entry stub -> C dispatcher -> sched::SchedExit.
 *
 * Context: kernel, boot-time. Called once from kernel_main after
 * linux::SyscallInit and SchedInit.
 */

namespace duetos::subsystems::linux
{

/// Spawn the Linux-ABI ring-3 smoke task. Returns when the task is
/// queued on the runqueue; the smoke dies once the scheduler
/// switches to it and the syscall reaches SchedExit.
void SpawnRing3LinuxSmoke();

/// Spawn the same payload wrapped in a minimal ELF64 and loaded via
/// core::SpawnElfLinux. Exercises the ElfLoader + SpawnElfLinux path
/// end-to-end, which is what a real Linux ELF off disk will use
/// once the FAT32 loader wiring lands. Prints the same "MOK\nhello
/// linux!\n" to COM1 before exit_group(0x42).
void SpawnRing3LinuxElfSmoke();

/// Open HELLO.TXT on FAT32 via sys_open, read 17 bytes into a
/// mmap'd page, echo them to COM1 via sys_write, close the fd,
/// exit. Exercises the sys_open/close/read path end-to-end.
void SpawnRing3LinuxFileSmoke();

/// Exercises file-backed mmap: opens HELLO.TXT, mmap's 17 bytes
/// PROT_READ + MAP_PRIVATE, writes the mapped region to stdout,
/// closes the fd, exits with rc 0x44. On success the operator
/// sees `hello from fat32` on the serial console plus
/// `[linux] mmap file fd=… -> …` from the kernel-side handler.
void SpawnRing3LinuxMmapSmoke();

/// Host-compiled static C binary that exercises a spread of Linux
/// syscalls and prints a pass/fail tag for each. Source lives in
/// userland/apps/synxtest/synxtest.c; the compiled ELF is embedded
/// into the kernel image via kernel/core/generated_synxtest_elf.h
/// (rebuild via tools/embed-blob.py if the source changes).
void SpawnSynxTestElf();

/// Exercises the ABI translation unit. Issues one syscall that
/// the TU fills with a no-op (sys_madvise) and one it declines
/// with a deliberate -ENOSYS (sys_rseq), then exits. Expected
/// boot-log lines:
///   [translate] linux/0x1c -> noop:advisory-hint
///   [translate] linux/0x14e -> synthetic:enosys-deliberate
void SpawnRing3LinuxTranslateSmoke();

/// Exercises the sys_write file-extend path:
/// opens HELLO.TXT, lseeks to SEEK_END, writes "EXT\n", closes.
/// On success, prints "extended\n" to stdout so success is
/// visible on every boot. Any failure (extend rejected, short
/// write, I/O error) surfaces as a missing marker.
void SpawnRing3LinuxExtendSmoke();

} // namespace duetos::subsystems::linux
