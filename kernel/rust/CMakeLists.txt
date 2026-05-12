# DuetOS kernel Rust link unit.
#
# Cargo builds one staticlib containing every Rust subsystem rlib. Linking a
# single Rust-produced archive keeps core/alloc/compiler_builtins and the panic
# runtime unique in the final C++ kernel link.

include("${CMAKE_SOURCE_DIR}/cmake/DuetOSRust.cmake")

file(GLOB_RECURSE DUETOS_RUST_SUBSYSTEM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/kernel/fs/duetfs/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/fs/duetfs/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/class_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/class_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/hid_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/hid_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/net/parsers_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/net/parsers_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/msc_scsi_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/msc_scsi_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/util/img_meta_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/util/img_meta_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/loader/exec_meta_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/loader/exec_meta_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/fs/ntfs_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/fs/ntfs_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/fs/exfat_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/fs/exfat_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/fs/ext4_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/fs/ext4_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/acpi/acpi_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/acpi/acpi_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/net/wifi80211_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/net/wifi80211_rust/Cargo.toml"
    "${CMAKE_SOURCE_DIR}/kernel/net/hci_rust/src/*.rs"
    "${CMAKE_SOURCE_DIR}/kernel/net/hci_rust/Cargo.toml"
)

duetos_add_rust_staticlib(
    NAME duetos-kernel-rust
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    OUTPUT_NAME duetos_kernel_rust
    INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
    LIB_VAR DUETOS_KERNEL_RUST_STATIC_LIB
    INCLUDE_VAR DUETOS_KERNEL_RUST_INCLUDE_DIR
    TARGET_VAR DUETOS_KERNEL_RUST_TARGET
    EXTRA_DEPENDS
        ${DUETOS_RUST_SUBSYSTEM_SOURCES}
        "${CMAKE_SOURCE_DIR}/kernel/fs/duetfs/include/duetfs.h"
        "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/class_rust/include/usbclass.h"
        "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/hid_rust/include/usbhid.h"
        "${CMAKE_SOURCE_DIR}/kernel/net/parsers_rust/include/parsers_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/drivers/usb/msc_scsi_rust/include/msc_scsi_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/util/img_meta_rust/include/img_meta_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/loader/exec_meta_rust/include/exec_meta_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/fs/ntfs_rust/include/ntfs_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/fs/exfat_rust/include/exfat_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/fs/ext4_rust/include/ext4_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/acpi/acpi_rust/include/acpi_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/net/wifi80211_rust/include/wifi80211_rust.h"
        "${CMAKE_SOURCE_DIR}/kernel/net/hci_rust/include/hci_rust.h"
)

set(DUETOS_KERNEL_RUST_STATIC_LIB "${DUETOS_KERNEL_RUST_STATIC_LIB}" PARENT_SCOPE)
set(DUETOS_KERNEL_RUST_TARGET "${DUETOS_KERNEL_RUST_TARGET}" PARENT_SCOPE)
