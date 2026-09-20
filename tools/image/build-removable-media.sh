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
       [--size-mib 128] [--boot-mode interactive|smoke] \
       [--static-ip <a.b.c.d/prefix>] [--static-iface 0..3] \
       [--gateway <a.b.c.d>] [--dns <a.b.c.d>] [--force]
USAGE
    exit 2
}

KERNEL=""
OUTPUT=""
SIZE_MIB=128
BOOT_MODE="interactive"
STATIC_IP=""
STATIC_IFACE=0
STATIC_IFACE_SET=0
GATEWAY=""
DNS=""
FORCE=0

ipv4_to_u32()
{
    local text="$1"
    [[ "${text}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
    local octet value=0
    for octet in "${a}" "${b}" "${c}" "${d}"; do
        [[ "${octet}" =~ ^[0-9]{1,3}$ ]] || return 1
        local numeric=$((10#${octet}))
        (( numeric <= 255 )) || return 1
        value=$(((value << 8) | numeric))
    done
    printf '%u\n' "${value}"
}

ipv4_is_usable_unicast()
{
    local value="$1"
    local first=$(((value >> 24) & 255))
    (( first != 0 && first != 127 && first < 224 ))
}

ipv4_is_usable_host()
{
    local value="$1"
    local prefix="$2"
    ipv4_is_usable_unicast "${value}" || return 1
    (( prefix >= 31 )) && return 0
    local host_mask=$(((1 << (32 - prefix)) - 1))
    local host=$((value & host_mask))
    (( host != 0 && host != host_mask ))
}

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
    --boot-mode)
        [[ $# -ge 2 ]] || usage
        BOOT_MODE="$2"
        shift 2
        ;;
    --static-ip)
        [[ $# -ge 2 ]] || usage
        STATIC_IP="$2"
        shift 2
        ;;
    --static-iface)
        [[ $# -ge 2 ]] || usage
        STATIC_IFACE="$2"
        STATIC_IFACE_SET=1
        shift 2
        ;;
    --gateway)
        [[ $# -ge 2 ]] || usage
        GATEWAY="$2"
        shift 2
        ;;
    --dns)
        [[ $# -ge 2 ]] || usage
        DNS="$2"
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

if [[ "${BOOT_MODE}" != "interactive" && "${BOOT_MODE}" != "smoke" ]]; then
    echo "error: --boot-mode must be interactive or smoke" >&2
    exit 2
fi

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

if [[ -z "${STATIC_IP}" ]]; then
    if [[ -n "${GATEWAY}" ]]; then
        echo "error: --gateway requires --static-ip" >&2
        exit 2
    fi
    if [[ -n "${DNS}" ]]; then
        echo "error: --dns requires --static-ip" >&2
        exit 2
    fi
    if [[ "${STATIC_IFACE_SET}" == 1 ]]; then
        echo "error: --static-iface requires --static-ip" >&2
        exit 2
    fi
else
    if [[ "${STATIC_IP}" != */* || "${STATIC_IP#*/}" == */* ]]; then
        echo "error: invalid --static-ip (expected a.b.c.d/prefix)" >&2
        exit 2
    fi
    STATIC_ADDRESS="${STATIC_IP%/*}"
    STATIC_PREFIX="${STATIC_IP#*/}"
    if [[ ! "${STATIC_PREFIX}" =~ ^[0-9]+$ ]] || (( 10#${STATIC_PREFIX} < 1 || 10#${STATIC_PREFIX} > 32 )); then
        echo "error: invalid --static-ip prefix (expected 1 through 32)" >&2
        exit 2
    fi
    STATIC_PREFIX=$((10#${STATIC_PREFIX}))
    if ! STATIC_IP_VALUE="$(ipv4_to_u32 "${STATIC_ADDRESS}")" ||
       ! ipv4_is_usable_host "${STATIC_IP_VALUE}" "${STATIC_PREFIX}"; then
        echo "error: invalid --static-ip address" >&2
        exit 2
    fi
    if [[ ! "${STATIC_IFACE}" =~ ^[0-3]$ ]]; then
        echo "error: --static-iface must be an integer from 0 through 3" >&2
        exit 2
    fi
    if [[ -n "${GATEWAY}" ]]; then
        if ! GATEWAY_VALUE="$(ipv4_to_u32 "${GATEWAY}")" ||
           ! ipv4_is_usable_host "${GATEWAY_VALUE}" "${STATIC_PREFIX}"; then
            echo "error: invalid --gateway address" >&2
            exit 2
        fi
        if (( GATEWAY_VALUE == STATIC_IP_VALUE )); then
            echo "error: --gateway must differ from --static-ip" >&2
            exit 2
        fi
        if (( STATIC_PREFIX == 32 )); then
            echo "error: --gateway is not supported with a /32 static address" >&2
            exit 2
        fi
        NETWORK_MASK=$(((0xFFFFFFFF << (32 - STATIC_PREFIX)) & 0xFFFFFFFF))
        if (( (GATEWAY_VALUE & NETWORK_MASK) != (STATIC_IP_VALUE & NETWORK_MASK) )); then
            echo "error: --gateway must be on the configured subnet" >&2
            exit 2
        fi
    fi
    if [[ -n "${DNS}" ]]; then
        if ! DNS_VALUE="$(ipv4_to_u32 "${DNS}")" || ! ipv4_is_usable_unicast "${DNS_VALUE}"; then
            echo "error: invalid --dns address" >&2
            exit 2
        fi
    fi
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

KERNEL_ARGS="boot=desktop autologin=1"
if [[ "${BOOT_MODE}" == "smoke" ]]; then
    KERNEL_ARGS+=" smoke=bringup"
fi
if [[ -n "${STATIC_IP}" ]]; then
    KERNEL_ARGS+=" net.static=${STATIC_IP} net.static-iface=${STATIC_IFACE}"
    [[ -z "${GATEWAY}" ]] || KERNEL_ARGS+=" net.gateway=${GATEWAY}"
    [[ -z "${DNS}" ]] || KERNEL_ARGS+=" net.dns=${DNS}"
fi

cat >"${GRUB_CFG}" <<GRUB
set timeout=0
set default=0

search --no-floppy --file --set=root /boot/duetos-kernel.elf

menuentry "DuetOS removable media" {
    multiboot2 /boot/duetos-kernel.elf ${KERNEL_ARGS}
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
mmd -i "${IMAGE_TMP}@@1048576" ::/boot/grub
mcopy -i "${IMAGE_TMP}@@1048576" "${EFI_BINARY}" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${IMAGE_TMP}@@1048576" "${KERNEL}" ::/boot/duetos-kernel.elf
mcopy -i "${IMAGE_TMP}@@1048576" "${GRUB_CFG}" ::/boot/grub/grub.cfg

# Construction happens in a sibling temporary directory. The final rename is
# the only operation that touches OUTPUT, so a failed tool never leaves a
# half-built artifact at the requested path.
if [[ "${FORCE}" == 1 ]]; then
    mv -f -- "${IMAGE_TMP}" "${OUTPUT}"
else
    mv -- "${IMAGE_TMP}" "${OUTPUT}"
fi

echo "[removable-image] wrote ${OUTPUT} (${SIZE_MIB} MiB)"
