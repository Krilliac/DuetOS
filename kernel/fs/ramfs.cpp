#include "ramfs.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"

/*
 * Seed trees are declared at file scope as constinit data so the
 * whole structure lives in .rodata. Children arrays are similarly
 * constinit — each is an array of const RamfsNode* terminated by
 * nullptr, addressed by the parent's `children` field.
 *
 * Laying this out by hand (vs. generating from a manifest) is
 * appropriate for v0: three files, two directories per tree. The
 * moment a real disk backend exists, these seeds go away.
 */

namespace customos::fs
{

namespace
{

constexpr u8 kEtcVersionBytes[] = "CustomOS v0 (ramfs-seeded)\n";
constexpr u8 kBinHelloBytes[] = "Hello from /bin/hello\n";
constexpr u8 kWelcomeBytes[] = "Welcome, sandbox. This file is all you can see.\n";

// ------- Trusted tree: / -> {etc/version, bin/hello} -------

constinit RamfsNode k_trusted_etc_version = {
    .name = "version",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kEtcVersionBytes,
    .file_size = sizeof(kEtcVersionBytes) - 1, // exclude terminating NUL
};

constinit const RamfsNode* const k_trusted_etc_children[] = {
    &k_trusted_etc_version,
    nullptr,
};

constinit RamfsNode k_trusted_etc_dir = {
    .name = "etc",
    .type = RamfsNodeType::kDir,
    .children = k_trusted_etc_children,
    .file_bytes = nullptr,
    .file_size = 0,
};

constinit RamfsNode k_trusted_bin_hello = {
    .name = "hello",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kBinHelloBytes,
    .file_size = sizeof(kBinHelloBytes) - 1,
};

constinit const RamfsNode* const k_trusted_bin_children[] = {
    &k_trusted_bin_hello,
    nullptr,
};

constinit RamfsNode k_trusted_bin_dir = {
    .name = "bin",
    .type = RamfsNodeType::kDir,
    .children = k_trusted_bin_children,
    .file_bytes = nullptr,
    .file_size = 0,
};

constinit const RamfsNode* const k_trusted_root_children[] = {
    &k_trusted_etc_dir,
    &k_trusted_bin_dir,
    nullptr,
};

constinit RamfsNode k_trusted_root = {
    .name = "",
    .type = RamfsNodeType::kDir,
    .children = k_trusted_root_children,
    .file_bytes = nullptr,
    .file_size = 0,
};

// ------- Sandbox tree: / -> welcome.txt -------
//
// Deliberately minimal. A sandboxed process's `/` is THIS node, so
// its entire naming universe consists of "/welcome.txt". Paths
// referring to /etc, /bin, /anything-else will fail at lookup
// because those children do not exist in this root. The sandbox's
// abstraction over "the OS" is exactly what's reachable from here.

constinit RamfsNode k_sandbox_welcome = {
    .name = "welcome.txt",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kWelcomeBytes,
    .file_size = sizeof(kWelcomeBytes) - 1,
};

constinit const RamfsNode* const k_sandbox_root_children[] = {
    &k_sandbox_welcome,
    nullptr,
};

constinit RamfsNode k_sandbox_root = {
    .name = "",
    .type = RamfsNodeType::kDir,
    .children = k_sandbox_root_children,
    .file_bytes = nullptr,
    .file_size = 0,
};

} // namespace

void RamfsInit()
{
    // Both trees are constinit — nothing to do at runtime. The
    // function exists so (a) the boot sequence has a visible hook
    // for "filesystem is up", and (b) when mutable state lands
    // (inode cache, dentry table), it has a home without requiring
    // callers to change.
    core::Log(core::LogLevel::Info, "fs/ramfs", "ramfs trees seeded");
}

const RamfsNode* RamfsTrustedRoot()
{
    return &k_trusted_root;
}

const RamfsNode* RamfsSandboxRoot()
{
    return &k_sandbox_root;
}

bool RamfsIsDir(const RamfsNode* n)
{
    return n != nullptr && n->type == RamfsNodeType::kDir;
}

} // namespace customos::fs
