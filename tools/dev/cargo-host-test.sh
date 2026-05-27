#!/usr/bin/env bash
# tools/dev/cargo-host-test.sh — run hosted Rust unit tests.
#
# The workspace's /.cargo/config.toml pins `target = x86_64-unknown-none`
# + `unstable.build-std = ["core", "alloc"]` for kernel-target builds.
# That config applies to every `cargo` invocation under the workspace
# tree (cargo searches CWD + manifest-dir upward for .cargo/config.toml),
# so it can't be overridden by env vars or `--config` from inside the
# tree. We work around that by running each test crate against
# `rustc --test` directly — no cargo, no build-std, no workspace
# config involvement.
#
# Each entry in HOST_TEST_CRATES below is a crate root. The crate's
# `src/lib.rs` is compiled as a hosted test binary using the host
# target's pre-built libcore + libstd, then executed.

set -euo pipefail

HOST_TEST_CRATES=(
    "kernel/net/parsers_rust"
    "kernel/drivers/usb/msc_scsi_rust"
    "kernel/util/img_meta_rust"
    "kernel/loader/exec_meta_rust"
    "kernel/fs/ntfs_rust"
    "kernel/fs/exfat_rust"
    "kernel/fs/ext4_rust"
    "kernel/acpi/acpi_rust"
    "kernel/arch/x86_64/smbios_rust"
    "kernel/drivers/pci/caps_rust"
    "kernel/mm/multiboot2_rust"
    "kernel/net/wifi80211_rust"
    "kernel/net/hci_rust"
    "kernel/net/tls_rust"
    "kernel/util/vt_parser_rust"
    "kernel/drivers/gpu/nvidia_gsp_fw_rust"
    "kernel/drivers/gpu/amd_gfx_fw_rust"
    "kernel/drivers/net/bcm43xx_fw_rust"
    "kernel/drivers/net/rtl88xx_fw_rust"
    "kernel/drivers/net/iwlwifi_fw_rust"
    "kernel/drivers/iommu/dmar_rust"
    "kernel/drivers/iommu/ivrs_rust"
)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "${SCRATCH}"' EXIT

# Optional crate filter: positional arg selects a single crate path.
select_crates=()
if [[ $# -ge 1 ]]; then
    for crate in "${HOST_TEST_CRATES[@]}"; do
        if [[ "$(basename "${crate}")" == "$1" || "${crate}" == "$1" ]]; then
            select_crates+=("${crate}")
        fi
    done
    if [[ ${#select_crates[@]} -eq 0 ]]; then
        echo "cargo-host-test.sh: no crate matches '$1'" >&2
        exit 2
    fi
else
    select_crates=("${HOST_TEST_CRATES[@]}")
fi

rc=0
for crate in "${select_crates[@]}"; do
    name="$(basename "${crate}")"
    lib="${REPO_ROOT}/${crate}/src/lib.rs"
    if [[ ! -f "${lib}" ]]; then
        echo "cargo-host-test.sh: ${lib} not found — skipping ${name}" >&2
        continue
    fi
    bin="${SCRATCH}/${name}-test"
    printf '\n==> rustc --test %s\n' "${crate}"
    # `--edition 2021` matches the workspace edition; `--test` builds
    # an integration test harness around the lib's #[test] functions.
    if ! rustc --edition 2021 --test "${lib}" -o "${bin}"; then
        rc=1
        continue
    fi
    if ! "${bin}"; then
        rc=1
    fi
done
exit $rc
