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

// Message-of-the-day shown by the shell on startup. Kept short
// so a 80x40 console has room for the banner + boot log + first
// prompt without scrolling anything important off the top.
constexpr u8 kEtcMotdBytes[] =
    "------------------------------------------------------------\n"
    "            CUSTOMOS v0 - WINDOWED DESKTOP SHELL\n"
    "------------------------------------------------------------\n"
    " Ctrl+Alt+T   toggle desktop / TTY mode\n"
    " Ctrl+Alt+F1  shell console     Ctrl+Alt+F2  kernel log\n"
    " Alt+Tab      cycle window      Alt+F4       close window\n"
    " Tab          complete          Up/Down      history\n"
    " help         command list      sysinfo      system status\n"
    "------------------------------------------------------------\n";

// Default shell profile — auto-sourced by the shell on init.
// Each line dispatches as if typed at the prompt. Lines starting
// with '#' are comments and skipped by the source command.
constexpr u8 kEtcProfileBytes[] =
    "# CustomOS default profile\n"
    "# Runs every time the shell starts.\n"
    "set PS1 customos> \n"
    "alias ll ls\n"
    "alias l ls\n"
    "alias cls clear\n";

// Man pages — plain-text per-command help. Each file here lands
// at /etc/man/<name> and is read by the shell's `man` command
// via a straight VfsLookup + cat. Keeping these as real files
// rather than inline strings lets `cat /etc/man/ls` work too,
// and makes the ramfs feel lived-in.
constexpr u8 kManLsBytes[] =
    "LS [PATH]\n"
    "  Lists the children of PATH (default /).\n"
    "  For a file, prints the filename + size.\n"
    "  /tmp is a writable namespace; other paths are read-only.\n";

constexpr u8 kManCatBytes[] =
    "CAT PATH\n"
    "  Prints the contents of PATH.\n"
    "  Works on ramfs (/etc, /bin) and tmpfs (/tmp).\n";

constexpr u8 kManEchoBytes[] =
    "ECHO ARG..  [> PATH | >> PATH]\n"
    "  Prints args separated by single spaces + newline.\n"
    "  With >, writes to /tmp/<NAME> (replaces).\n"
    "  With >>, appends. Target must be /tmp.\n";

constexpr u8 kManCpBytes[] =
    "CP SRC DST\n"
    "  Copies SRC to DST. DST must be /tmp/<NAME>.\n"
    "  SRC may be /tmp or any read-only ramfs path.\n";

constexpr u8 kManMvBytes[] =
    "MV SRC DST\n"
    "  Renames a /tmp file. Both paths must be /tmp/<NAME>.\n"
    "  Source is unlinked only after write succeeds.\n";

constexpr u8 kManGrepBytes[] =
    "GREP PATTERN PATH\n"
    "  Prints every line of PATH containing PATTERN as a substring.\n"
    "  Case-sensitive. Empty pattern matches every line.\n";

constexpr u8 kManFindBytes[] =
    "FIND NAME\n"
    "  Recursively lists paths whose leaf contains NAME.\n"
    "  Walks both the static ramfs and the writable tmpfs.\n";

constexpr u8 kManHistoryBytes[] =
    "HISTORY\n"
    "  Prints the last 8 commands (oldest first).\n"
    "  !N runs command N, !! repeats the last.\n"
    "  Up/Down arrows also cycle history in-place.\n";

constexpr u8 kManAliasBytes[] =
    "ALIAS NAME CMD   Create or redefine an alias.\n"
    "ALIAS            List all aliases.\n"
    "UNALIAS NAME     Remove an alias.\n"
    "Aliases expand once before dispatch; no recursion.\n";

constexpr u8 kManEnvBytes[] =
    "SET NAME VALUE   Store an environment variable.\n"
    "UNSET NAME       Remove a variable.\n"
    "ENV              List all variables.\n"
    "Reference a variable in args as $NAME (whole-token only).\n"
    "Set PS1 to customise the shell prompt.\n";

constexpr u8 kManTimeBytes[] =
    "TIME CMD..\n"
    "  Measure wall time of CMD at 10 ms resolution.\n"
    "  Runs through the full shell pipeline (alias / env /\n"
    "  redirect all apply).\n";

constexpr u8 kManSourceBytes[] =
    "SOURCE PATH\n"
    "  Runs each line of PATH as a shell command.\n"
    "  Blank lines and lines starting with # are skipped.\n"
    "  Used to auto-run /etc/profile at boot.\n";

// ------- Trusted tree: / -> {etc/version, bin/hello} -------

constinit RamfsNode k_trusted_etc_version = {
    .name = "version",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kEtcVersionBytes,
    .file_size = sizeof(kEtcVersionBytes) - 1, // exclude terminating NUL
};

constinit RamfsNode k_trusted_etc_motd = {
    .name = "motd",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kEtcMotdBytes,
    .file_size = sizeof(kEtcMotdBytes) - 1,
};

constinit RamfsNode k_trusted_etc_profile = {
    .name = "profile",
    .type = RamfsNodeType::kFile,
    .children = nullptr,
    .file_bytes = kEtcProfileBytes,
    .file_size = sizeof(kEtcProfileBytes) - 1,
};

// /etc/man — one RamfsNode per page. Macro-tight since the
// shape is identical for every entry.
#define MAN_NODE(name_str, bytes_sym)                                                                                  \
    constinit RamfsNode k_man_##bytes_sym = {.name = name_str,                                                         \
                                             .type = RamfsNodeType::kFile,                                             \
                                             .children = nullptr,                                                      \
                                             .file_bytes = bytes_sym,                                                  \
                                             .file_size = sizeof(bytes_sym) - 1}

MAN_NODE("ls", kManLsBytes);
MAN_NODE("cat", kManCatBytes);
MAN_NODE("echo", kManEchoBytes);
MAN_NODE("cp", kManCpBytes);
MAN_NODE("mv", kManMvBytes);
MAN_NODE("grep", kManGrepBytes);
MAN_NODE("find", kManFindBytes);
MAN_NODE("history", kManHistoryBytes);
MAN_NODE("alias", kManAliasBytes);
MAN_NODE("env", kManEnvBytes);
MAN_NODE("time", kManTimeBytes);
MAN_NODE("source", kManSourceBytes);

#undef MAN_NODE

constinit const RamfsNode* const k_trusted_etc_man_children[] = {
    &k_man_kManLsBytes,     &k_man_kManCatBytes,     &k_man_kManEchoBytes,
    &k_man_kManCpBytes,     &k_man_kManMvBytes,      &k_man_kManGrepBytes,
    &k_man_kManFindBytes,   &k_man_kManHistoryBytes, &k_man_kManAliasBytes,
    &k_man_kManEnvBytes,    &k_man_kManTimeBytes,    &k_man_kManSourceBytes,
    nullptr,
};

constinit RamfsNode k_trusted_etc_man_dir = {
    .name = "man",
    .type = RamfsNodeType::kDir,
    .children = k_trusted_etc_man_children,
    .file_bytes = nullptr,
    .file_size = 0,
};

constinit const RamfsNode* const k_trusted_etc_children[] = {
    &k_trusted_etc_version,
    &k_trusted_etc_motd,
    &k_trusted_etc_profile,
    &k_trusted_etc_man_dir,
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
