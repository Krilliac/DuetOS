#!/usr/bin/env bash
# Build a DuetOS UEFI removable-media image as an ordinary host file.
#
# Safety boundary: this tool never accepts a physical-device-shaped output.
# It does not discover disks, mount partitions, elevate privileges, or copy an
# image onto removable media.  Those operations are intentionally out of scope.

set -euo pipefail

usage()
{
    cat >&2 <<'USAGE'
usage: tools/image/build-removable-media.sh \
       --kernel <duetos-kernel.elf> --output <regular-file.img> \
       [--size-mib 128] [--force]
USAGE
    exit 2
}

KERNEL=""
OUTPUT=""
SIZE_MIB=128
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
    --kernel)
        [[ $# -ge 2 ]] || usage
        KERNEL="$2"
        shift 2
        ;;
    --output)
        [[ $# -ge 2 ]] || usage
        OUTPUT="$2"
        shift 2
        ;;
    --size-mib)
        [[ $# -ge 2 ]] || usage
        SIZE_MIB="$2"
        shift 2
        ;;
    --force)
        FORCE=1
        shift
        ;;
    -h|--help)
        usage
        ;;
    *)
        echo "error: unknown argument: $1" >&2
        usage
        ;;
    esac
done

[[ -n "${KERNEL}" && -n "${OUTPUT}" ]] || usage

# This gate deliberately precedes every prerequisite check and file-opening
# operation. --force can replace a regular file, never weaken target identity.
case "${OUTPUT}" in
/dev/*|*PhysicalDrive*)
    echo "error: refusing device-like output: ${OUTPUT}" >&2
    exit 2
    ;;
esac
if [[ -b "${OUTPUT}" ]]; then
    echo "error: refusing block-device output: ${OUTPUT}" >&2
    exit 2
fi
if [[ -L "${OUTPUT}" || ( -e "${OUTPUT}" && ! -f "${OUTPUT}" ) ]]; then
    echo "error: refusing non-regular output: ${OUTPUT}" >&2
    exit 2
fi
if [[ -e "${OUTPUT}" && "${FORCE}" != 1 ]]; then
    echo "error: output already exists (use --force for a regular file): ${OUTPUT}" >&2
    exit 2
fi

if [[ ! "${SIZE_MIB}" =~ ^[0-9]+$ ]] || (( SIZE_MIB < 64 || SIZE_MIB > 4096 )); then
    echo "error: --size-mib must be an integer from 64 through 4096" >&2
    exit 2
fi
if [[ ! -f "${KERNEL}" ]]; then
    echo "error: kernel ELF not found: ${KERNEL}" >&2
    exit 2
fi

for tool in grub-mkstandalone parted mformat mmd mcopy; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: required host tool not found: ${tool}" >&2
        exit 2
    fi
done

OUTPUT_PARENT="$(dirname -- "${OUTPUT}")"
OUTPUT_NAME="$(basename -- "${OUTPUT}")"
if [[ ! -d "${OUTPUT_PARENT}" ]]; then
    echo "error: output parent directory does not exist: ${OUTPUT_PARENT}" >&2
    exit 2
fi
OUTPUT_PARENT="$(cd "${OUTPUT_PARENT}" && pwd -P)"
OUTPUT="${OUTPUT_PARENT}/${OUTPUT_NAME}"
KERNEL="$(cd "$(dirname -- "${KERNEL}")" && pwd -P)/$(basename -- "${KERNEL}")"

TMP_DIR="$(mktemp -d -p "${OUTPUT_PARENT}" .duetos-removable.XXXXXX)"
readonly TMP_DIR
readonly IMAGE_TMP="${TMP_DIR}/image.tmp"
readonly GRUB_CFG="${TMP_DIR}/grub.cfg"
readonly EFI_BINARY="${TMP_DIR}/BOOTX64.EFI"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${GRUB_CFG}" <<'GRUB'
set timeout=0
set default=0

search --no-floppy --file --set=root /boot/duetos-kernel.elf

menuentry "DuetOS removable-media smoke" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop autologin=1 smoke=bringup
    boot
}
GRUB

grub-mkstandalone \
    -O x86_64-efi \
    --modules="part_gpt fat normal search search_fs_file multiboot2" \
    -o "${EFI_BINARY}" \
    "boot/grub/grub.cfg=${GRUB_CFG}"

readonly IMAGE_BYTES=$((SIZE_MIB * 1024 * 1024))
readonly PARTITION_BYTES=$(((SIZE_MIB - 2) * 1024 * 1024))
readonly PARTITION_SECTORS=$((PARTITION_BYTES / 512))

truncate -s "${IMAGE_BYTES}" "${IMAGE_TMP}"
parted -s "${IMAGE_TMP}" mklabel gpt
parted -s "${IMAGE_TMP}" mkpart ESP fat32 1MiB "$((SIZE_MIB - 1))MiB"
parted -s "${IMAGE_TMP}" set 1 esp on

# mtools' @@ syntax exposes a filesystem at a byte offset without mounting or
# elevation. -T bounds FAT32 to the GPT partition instead of the file's tail,
# preserving the backup GPT header in the final MiB.
mformat -F -T "${PARTITION_SECTORS}" -i "${IMAGE_TMP}@@1048576" -v DUETOS ::
mmd -i "${IMAGE_TMP}@@1048576" ::/EFI
mmd -i "${IMAGE_TMP}@@1048576" ::/EFI/BOOT
mmd -i "${IMAGE_TMP}@@1048576" ::/boot
mcopy -i "${IMAGE_TMP}@@1048576" "${EFI_BINARY}" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${IMAGE_TMP}@@1048576" "${KERNEL}" ::/boot/duetos-kernel.elf

# Construction happens in a sibling temporary directory. The final rename is
# the only operation that touches OUTPUT, so a failed tool never leaves a
# half-built artifact at the requested path.
if [[ "${FORCE}" == 1 ]]; then
    mv -f -- "${IMAGE_TMP}" "${OUTPUT}"
else
    mv -- "${IMAGE_TMP}" "${OUTPUT}"
fi

echo "[removable-image] wrote ${OUTPUT} (${SIZE_MIB} MiB)"
