#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// One staticlib boundary for every Rust subsystem linked into the kernel. The
// public no_mangle FFI functions live in the subsystem crates; re-exporting
// their modules here keeps the Rust linker from treating those crates as
// unrelated archives and emitting duplicate core/alloc runtime objects.

mod panic;

pub use duetfs::ffi::*;
pub use duetos_acpi::*;
pub use duetos_exec_meta::*;
pub use duetos_exfat::*;
pub use duetos_ext4::*;
pub use duetos_hci::*;
pub use duetos_img_meta::*;
pub use duetos_multiboot2::*;
pub use duetos_net_parsers::*;
pub use duetos_ntfs::*;
pub use duetos_pci_caps::*;
pub use duetos_smbios::*;
pub use duetos_tls::*;
pub use duetos_usb_msc_scsi::*;
pub use duetos_vt::*;
pub use duetos_wifi80211::*;
pub use usbclass::*;
pub use usbhid::*;
