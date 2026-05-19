# Running DuetOS on VMs (QEMU / VMware / VirtualBox / bare metal)

> **Audience:** Anyone booting DuetOS outside the canonical QEMU harness
>
> **Execution context:** Host (hypervisor config) + on-target (serial log)
>
> **Maturity:** v0 — config matrix derived from in-tree driver + hypervisor-detection coverage

> **See also:** to run/debug DuetOS on **Windows** via the bespoke
> in-house hypervisor (no QEMU, with Visual Studio source-level
> kernel debugging), see [In-House Windows VMM](Windows-VMM.md).

## TL;DR

DuetOS needs **no hypervisor-specific code** to boot — it already
classifies the CPUID hypervisor vendor (`arch/x86_64/hypervisor.cpp`:
KVM / TCG / **VMware** / VirtualBox / Hyper-V / Xen / Parallels / …).
What it *does* need is a VM configured with **virtual hardware it has
drivers for**. Pick the controllers below and it boots; pick the
hypervisor defaults and it won't find its disk.

The single hard rule: **storage must be AHCI (SATA) or NVMe, and
firmware must be UEFI.** Everything else is graceful.

## Driver coverage (what the VM may expose)

| Class | DuetOS has | DuetOS does NOT have |
|---|---|---|
| Storage | **AHCI/SATA**, **NVMe** | LSI Logic SCSI, VMware PVSCSI, virtio-blk-as-boot |
| NIC | **e1000/e1000e** (Intel) | vmxnet3, virtio-net-as-only-NIC* |
| USB | **xHCI** + USB HID; **PS/2** kbd/mouse | EHCI/UHCI-only setups |
| Display | **UEFI GOP** linear FB (always); Bochs VBE; Intel/AMD/NVIDIA (real HW) | accelerated VMware SVGA-II / VBox VBVA (classified `tier3-vm`, software FB only) |
| Firmware | **UEFI** (primary), legacy BIOS (secondary) | — |
| Entropy/mem | virtio-rng, virtio-balloon (QEMU) | (optional; absent elsewhere is harmless) |

\* virtio-net *is* driven and drained, but the boot harness pairs it
with e1000e; on a non-QEMU VM give it an e1000e for the supported path.

## Per-hypervisor config

### QEMU (canonical — `tools/qemu/run.sh`)

Already correct: q35 + OVMF (UEFI), `-device nvme` + `-device ahci`,
`-device e1000e`, `-device qemu-xhci`, `-smp 4` (default since this
branch), serial → stdout, auto `kvm:tcg`. Nothing to do. See
[QEMU Smoke Tests](QEMU-Smoke.md).

### VMware (Workstation / Fusion / ESXi)

Generate a ready `.vmx` with `tools/vm/make-vmware-vmx.sh` (see its
header). Required settings:

- **Firmware:** `firmware = "efi"`
- **Disk:** SATA (`sata0`) or NVMe (`nvme0`) — **never** the default
  `lsilogic` / `pvscsi`
- **NIC:** `ethernet0.virtualDev = "e1000e"` (not `vmxnet3`)
- **USB:** xHCI controller on (`usb_xhci.present = "TRUE"`)
- **Serial → file:** `serial0.fileType = "file"`,
  `serial0.fileName = "duetos-serial.log"` — this is the diagnostic
  channel every analysis rig consumes; without it you are blind
- **vCPUs:** `numvcpus = "4"` for real SMP scaling (VMware uses
  hardware virt, so this measures true scaling — unlike QEMU/TCG)

### VirtualBox

`VBoxManage modifyvm <vm> --firmware efi --nic1 nat
--nictype1 82540EM --storagectl "SATA" --add sata
--uartmode1 file <path>`; attach the ISO to the SATA controller.
82540EM/82545EM = the Intel e1000 the driver matches.

### Bare metal

UEFI boot the hybrid ISO. Works if the machine's storage is
AHCI/NVMe and NIC is a supported Intel part; this is the project's
actual target (commodity Intel/AMD/NVIDIA). Capture COM1 with a
USB-UART for the same post-mortem flow.

## Getting the boot log out (the part that matters for debugging)

Every triage tool keys off the COM1 serial transcript, not the
launcher. Once you have it as a file from *any* of the above:

```bash
tools/test/boot-log-analyze.sh path/to/duetos-serial.log
```

That runs the full regression scan (panics / oops / lockdep /
self-tests / phase timings / stress summary / hypervisor + SMP
banner) and exits non-zero on a non-deliberate failure, so it works
as both a human report and a CI/scripted gate — independent of
whether the log came from QEMU, VMware, VirtualBox, or real silicon.

For host-CPU profiling and SMP load scaling on QEMU specifically,
see `tools/qemu/cpu-probe.sh` and
`tools/qemu/smp-loadtest-compare.sh` (their headers document the
TCG-vs-KVM accelerator caveat — a true scaling number needs
hardware virt, which VMware/VirtualBox/KVM provide and TCG does
not).
