# DuetOS service-extraction architecture map

Status: source-only architecture plan, 2026-07-31
Snapshot: shared branch claude/audit-ps2-spsc-20260731 observed through
62c36871a8c29eb2f37d1920655c40874351c3b6 at 2026-07-31T22:24:26Z.
The worktree also contained concurrent, uncommitted claimed work, so every
implementation slice must refresh its source inventory before editing.

This document is the implementation map for extracting services in this order:

1. serviced
2. execd
3. displayd
4. registryd
5. netd

It is deliberately a plan, not an assertion that the new service and IPC
foundations are already integrated. The host was under a HARD STOP while this
map was produced because a kernel-pool trace was active. No build, compiler,
QEMU, fleet, broad filesystem scan, or source/CMake edit was used. The only
target modified by this lane is this document.

## 1. Outcome and non-negotiable decisions

The target is a small kernel that enforces identity, memory, object rights,
hardware isolation, and the final process-publication transition. Policy-rich
and parser-heavy work moves into restartable user processes. Extraction is not
complete merely because a protocol header exists: the old kernel owner must no
longer be authoritative, the new endpoint must have a revocable identity and
least-privilege object graph, and crash recovery must be demonstrated.

The following decisions are binding for the first implementation:

- The scheduler publication boundary remains in the kernel. No service may
  publish its own Process or Task directly.
- A service instance is identified by stable service slot plus nonzero,
  nonwrapping instance generation plus exact ProcessKey. A bare PID, endpoint
  number, HWND, socket index, or registry slot is never sufficient authority.
- The runtime message header is MessageAbi v1 and each method payload begins
  with VersionedPayload. Unknown required versions or flags fail closed.
- Wire data never contains trusted pointers, kernel object addresses,
  credentials, resource-domain keys, transfer metadata, or lock-bearing state.
- Large or mutable data is not inlined into the 4 KiB KMessagePort. It moves
  through typed KObjects and ObjectTransferTable references with kernel-derived
  metadata and rights narrowing.
- No compatibility phase runs two authoritative implementations over the same
  state. Shadow comparison may observe; only one side may mutate.
- Every service endpoint has an epoch. Restart closes the old endpoint,
  cancels outstanding requests, revokes transfer rows, and makes all old
  service-local references stale.
- Every extraction has a compile-time rollback path until its release gate is
  met, but rollback changes the sole owner; it does not leave dual writers.
- serviced owns manifest interpretation and restart policy. The kernel retains
  a tiny bootstrap watchdog for serviced itself and the admission/publication
  primitives needed to recover it.
- execd parses ordinary executable formats. The kernel validates and consumes
  an immutable LoadPlan and maps pages. serviced and execd themselves boot from
  build-time validated, sealed bootstrap plans, avoiding a parser cycle.
- displayd owns window/compositor policy. The kernel retains device, DMA,
  modeset/scanout, raw-input, display-master, and emergency-console authority.
- registryd owns the mutable Win32 registry and durable transaction log. Boot
  command-line, privilege, endpoint, and device-security policy remain kernel
  trusted configuration and may not be delegated through the registry.
- netd owns the ordinary network stack and socket state. The kernel retains
  NIC/DMA/IOMMU/interrupt/link primitives and packet-channel enforcement.
  Kernel DRSH cannot quietly coexist with a second live TCP stack.
- On-disk FAT32, DuetFS, exFAT, ext4, and NTFS parsers are not moved by this
  sequence. They remain an explicit residual kernel-TCB item for a later fsd
  design.

### Extraction order versus service dependencies

The requested order is also the initial activation order. displayd must be
able to start with immutable manifest defaults and an emergency font/theme; it
must not make registryd a boot prerequisite. After registryd becomes ready,
displayd may subscribe to user preferences and apply them as optional policy.
Likewise netd is last so no earlier service requires a working network.

The final boot path is therefore:

~~~
kernel bootstrap
  -> serviced ready
  -> execd ready
  -> displayd ready on boot defaults
  -> registryd ready; displayd attaches optional preference feed
  -> netd ready
  -> ordinary autostart services and desktop applications
~~~

## 2. Evidence inventory and integration reality

All scans were bounded to kernel, userland, tests, and relevant wiki paths with
rg. Counts include definitions and tests unless stated otherwise; they are
coverage aids, not size or quality metrics.

| Boundary | Observed coverage | Consequence |
| --- | ---: | --- |
| Current service-manager API | 46 matches in 5 files | Production consumers are boot_bringup.cpp and shell_service.cpp. |
| New service transition and serviced protocol | 338 matches in 6 files | All six files are the two implementations/headers and their two host tests; there is no production include site yet. |
| Exact new loader public symbols | 28 symbols, 241 matches in 12 files | Matches are confined to four implementation/header pairs and four host tests; no production spawn path consumes them yet. |
| IPC contract family | 1,421 matches in 61 files | HandleTable is already broad, but the new transport layers are much narrower than this aggregate suggests. |
| MessageAbi include sites | 7 | Used by protocol definitions, MessageRing, and its test; not yet a service endpoint path. |
| VersionedPayload include sites | 6 | Used by protocol definitions, MessageRing, and its test. |
| MessageRing include sites | 4 | Implementation, test, and KMessagePort only. |
| KMessagePort include sites | 2 | Implementation and host test only. |
| ObjectTransfer include sites | 2 | Implementation and host test only. |
| Registry public API | 59 matches in 11 files | Boot, syscall dispatch, close dispatch, and GDB monitor are the live adapters. |
| Registry syscall/client surface | 189 matches in 16 files | ntdll, advapi32_32, test app, generated NT table, syscall docs, and kernel registry code are affected. |
| CompositorLock/Unlock | 280 matches in 20 files | boot_tasks.cpp has 125, window_syscall.cpp 104, and gdi_objects.cpp 14; this is not a one-file move. |
| Socket boundary | 203 matches in 25 files, 18 source files | Linux sockets, kernel shell/network clients, DRSH, TLS, browser, process cleanup, and ws2_32 are live consumers. |
| Embedded ramfs accessors | 69 matches in 8 files | The handwritten service manifest is coupled to ramfs function pointers. |
| Kernel filesystem inventory | 72 files total; 61 parser/mount/vfs/ramfs candidates | Filesystem parsing remains a material residual TCB after these five services. |

### New foundations that are not yet live

At the snapshot, service_transition.h, serviced_protocol.h,
exec_admission.h, execd_protocol.h, kmessage_port.h, and object_transfer.h
were included only by their implementations/tests or by other protocol
definitions. load_plan.h and load_image.h likewise had no production spawn
consumer. gui_message_queue.h had entered widget.h, but gui_broker_protocol.h
remained implementation/test-only.

This changes the first milestone: integrate and prove the common substrate
before any service binary becomes the default. A protocol self-test alone does
not satisfy that milestone.

### Host-test registration snapshot

tests/host/CMakeLists.txt registered message_abi, versioned_payload,
message_ring, kmessage_port, load_plan, load_image, exec_admission,
execd_protocol, gui_message_queue, and gui_message_policy. It did not yet
register service_transition, serviced_protocol, object_transfer, or
gui_broker_protocol even though corresponding test files existed. That is an
explicit release blocker, subject to refresh after the active CMake claim
lands.

## 3. Target authority split

| Authority or policy | Kernel residual TCB | Userland owner |
| --- | --- | --- |
| Process identity and lifecycle | ProcessKey/TaskKey allocation, address spaces, credentials, ResourceDomain charging, scheduler publication, reap, kill | serviced chooses desired state and restart policy |
| Executable loading | immutable object attestation, LoadPlan validation, ExecAdmission, page mapping, W^X, final entry/stack checks | execd parses PE/ELF and constructs sealed backing plus LoadPlan |
| Service discovery | endpoint object, exact owner credential snapshot, directory CAS, epoch close/revoke | each service publishes readiness; serviced interprets dependencies |
| IPC transport | KObject refs, handle rights, bounded queues, wait/wake, transfer attestation, peer-close | service protocols and request scheduling |
| Display | GPU MMIO/DMA/IOMMU, modeset/scanout, raw input, display-master lease, panic console | displayd windows, z-order, focus, queues, composition, clipboard, GDI policy |
| Registry | boot/security configuration, credentials, VFS KFile and durability primitive | registryd key tree, transactions, WAL/snapshot, notifications, Win32 semantics |
| Network | NIC MMIO/DMA/IOMMU, interrupts, link state, bounded packet buffers/rings, NetworkMaster lease | netd ARP/IP/ICMP/UDP/TCP, routes, neighbors, DHCP/DNS, firewall/socket policy |
| Filesystems | current VFS plus FAT32/DuetFS/exFAT/ext4/NTFS parsing | no new owner in this plan; later fsd |

The split is capability based, not source-directory based. A C++ helper can be
shared as a pure library, but the kernel image must not retain a parser merely
because the same source is useful to a user process.

## 4. Common service substrate

### 4.1 Kernel object model additions

The existing KObject tags stop at MessagePort and do not represent an
authenticated service channel or the large objects required by execd,
displayd, and netd. Append, never reuse, stable tags for:

- ServiceEndpoint: one end of an authenticated, bidirectional channel.
- MemoryObject: page-backed storage with immutable or shared policy metadata.
- LoadPlan: a sealed typed plan object; not a generic mutable MemoryObject.
- Surface: pixel-buffer metadata plus a retained MemoryObject.
- PacketRing: descriptor ring plus retained packet-buffer MemoryObjects.

Do not create kernel KObjects for registry keys, windows, sockets, or service
transactions. Those are service-local references consisting of service epoch,
slot, and generation, validated by the owning service. Kernel KObjects exist
only where the kernel must enforce mapping, hardware, waiting, transfer, or
cross-process lifetime.

Add one generic handle right, Map, because mapping is distinct from reading or
writing. Reuse existing generic rights instead of creating Call/Reply bits:

| Endpoint side | Required generic rights |
| --- | --- |
| Client call/send | Write |
| Client receive reply/notification | Read |
| Server receive request | Read |
| Server reply/notify | Write |
| Either side wait | Wait |
| Attach object references | Transfer on endpoint and Transfer on source object |
| Inspect counters/peer epoch | Inspect |
| Close own endpoint | Destroy |

Protocol authority is separate. For example, ServicedRightInspect and
ServicedRightControl are installed by trusted kernel connection policy in a
channel authority snapshot. They are never inferred from message bytes.

### 4.2 Service directory and channel

Introduce a kernel ServiceDirectory with fixed, bounded storage. One stable
row contains:

- service ID and stable manifest slot;
- instance generation and exact owner ProcessKey;
- endpoint ID and endpoint generation;
- supported protocol minimum/maximum;
- state Empty, Starting, Ready, Draining, or Closed;
- boot-manifest capability profile ID;
- readiness sequence and close reason.

Resolve returns only a retained ServiceEndpoint handle. It never exposes the
directory row. Connect performs all of the following atomically with respect
to directory replacement:

1. retain the exact Ready endpoint generation;
2. snapshot the caller's ProcessKey, CredentialKey, and ResourceDomainKey;
3. intersect the caller's manifest grant with requested protocol rights;
4. allocate a channel pair with two bounded MessagePorts;
5. create client-to-server and server-to-client ObjectTransferTables;
6. bind both peer identities, endpoint epoch, limits, and trusted protocol
   authority snapshots;
7. return the client handle only after both ends are canonical.

Each direction has its own nonwrapping request sequence and replay ledger.
Validation is: copy one bounded message, validate MessageAbi, validate the
method's VersionedPayload, validate peer/authority/scope, reserve the exact
request sequence, commit that sequence, then invoke service policy. A failed
validation does not advance policy state. A successfully committed request is
never invoked twice.

KMessagePort remains the bounded waitable queue primitive; it is not by itself
an authenticated session. ServiceEndpoint composes the queue, peer identity,
authority snapshot, transfer tables, endpoint epoch, outstanding-request
ledger, and close state.

The current ObjectTransferTable has 32 slots with at most 31 live positive
references. Preserve that bounded behavior initially. If profiling later
requires more, negotiate a new endpoint profile; do not silently enlarge
per-client retained-object authority.

### 4.3 Limits and backpressure

Every limit is declared in the manifest/profile and charged to the connecting
ResourceDomain:

- maximum live channels per service and per client;
- maximum outstanding requests and notification backlog;
- MessagePort bytes and per-message bytes;
- maximum live object-transfer rows and total transferred bytes;
- maximum mapped surface, executable, and packet-buffer bytes;
- service-specific object counts and request-rate budget.

Full, Busy, QuotaExceeded, PeerClosed, StaleEndpoint, UnsupportedVersion, and
Cancelled are first-class results. No caller spins on Full; it waits on a
bounded readiness signal or returns to userland. A service must not retain an
unbounded copy of queued payloads.

### 4.4 Lock hierarchy and thread affinity

The mandatory lock/lifetime rules are:

1. Private Process, Task, address space, channel, and object construction occurs
   without scheduler, service, or directory locks.
2. Scheduler publication lock may acquire the service-transition lock for the
   exact publication commit. The reverse order is forbidden.
3. ServiceDirectory lock is never held while calling the scheduler, loader,
   a service implementation, a destructor, or KObject retain/release.
4. HandleTable lookup retains an object while holding the table lock, then
   releases the table lock before taking the ServiceEndpoint or MessagePort
   lock.
5. Endpoint/channel lock may lead to one MessagePort lock, which leads to the
   MessageRing leaf metadata lock. Never acquire the peer endpoint while
   holding the first endpoint.
6. Never hold two ObjectTransferTable locks. Object retain/release and
   destination HandleTable insertion occur outside the transfer-table lock as
   required by the existing transfer contract.
7. No service implementation lock spans a blocking RPC, user copy, VFS I/O,
   device call, wait, logging call, or destructor.

| Service | State-mutation affinity |
| --- | --- |
| serviced | one supervisor event loop; kernel lifecycle events enqueue records |
| execd | immutable per-request parse context on workers; only cache/accounting metadata is shared |
| displayd | one compositor/scene actor; input and client receivers enqueue commands |
| registryd | one ordered writer/WAL actor; read snapshots are immutable |
| netd | one protocol/control actor per interface or RSS queue, with explicit message passing; no shared TCB mutation from syscall threads |

### 4.5 Universal close and restart contract

When an owner process exits or serviced requests stop:

1. Directory CAS moves the exact endpoint epoch to Draining.
2. New resolves/connects fail.
3. Both channel directions close and wake waiters with PeerClosed.
4. Outstanding request IDs become Cancelled; no new reply may commit.
5. Both transfer tables drain and revoke retained object references.
6. Hardware-master leases are revoked before device buffers are unmapped.
7. Service-specific refs become stale because the service epoch changed.
8. Kernel process teardown releases remaining handles and ResourceDomain
   charges.
9. A replacement publishes a strictly newer, nonzero epoch or the slot becomes
   terminally GenerationExhausted.

Clients reconnect through ServiceDirectory and recreate service-local state
from idempotent descriptors. They never ask a new instance to honor an old
window/socket/key/transaction reference.

## 5. The two publication gates

Publication has two distinct meanings and both must be atomic.

### 5.1 Process/scheduler publication gate

The existing service.cpp SpawnService path constructs a child through
SpawnPeFile or SpawnElfFile, while ExecuteStart records it under
g_service_lock afterward. Because the spawn helper already scheduler-publishes
the Task, a stop can race between those actions. The new service_transition
primitive supplies the required fix and must be wired before serviced:

1. Under service lock, ServiceTransitionReserveStart returns exact
   {service_slot, generation}.
2. Construct Process, address space, ResourceDomain, credentials, Task, initial
   handles, and bootstrap channel privately and unlocked.
3. On construction failure, revalidate the ticket and call
   ServiceTransitionRecordSpawnFailure.
4. Acquire scheduler publication lock.
5. While it is held, acquire the lower-ranked service lock and call
   ServiceTransitionCommitAtSchedulerPublication(ticket, pid).
6. If Published, link the private Task into the scheduler registry/runqueue
   before releasing the scheduler lock.
7. If rejected or stale, publish nothing and destroy the private graph
   unlocked.

ServiceTransitionStop invalidates Starting or Running authority under the
service lock and returns the exact PID/ProcessKey to kill after unlock.
Unlocked liveness observations commit only through
ServiceTransitionObserveExit with exact ticket and PID.

No alternative spawn entry point may bypass this gate for a managed service.

### 5.2 Endpoint/readiness publication gate

A runnable process is not yet a Ready service. ServiceDirectory publication
requires all of:

- its exact ProcessKey and service-start ticket are still current;
- its CredentialKey and ResourceDomain profile equal the manifest row;
- the service possesses a single-use bootstrap publication token delivered in
  its initial handle table, not in argv or environment text;
- requested service ID, protocol range, and endpoint rights equal the token;
- the channel and both transfer tables are canonical and fully charged;
- the service has completed local initialization without acquiring device
  master authority it was not granted;
- directory CAS still observes Starting for the same instance generation.

The CAS replaces no live Ready epoch. Replacement first drains the old epoch.
Only after Ready commits may serviced satisfy dependencies or report health.
If the start deadline expires, serviced requests stop; kernel invalidates the
start ticket and destroys an unpublished or not-ready instance.

## 6. Boot capability manifest and packaging

### 6.1 Canonical artifact

Replace the constexpr ServiceDesc table and ramfs byte/size function pointers
with a build-generated BootServiceManifest v1. The canonical human-edited
source should be config/services.toml; tools/build/gen-service-manifest.py
produces a fixed-layout binary artifact and a generated C/C++ embed header.
The kernel parses only the bounded binary form.

Manifest header fields:

- magic, format version, header size, total size;
- entry count, dependency count, capability-grant count;
- build ID and monotonic manifest generation;
- complete manifest SHA-256;
- authentication mode and signature/key identifier;
- offsets and sizes for every fixed table/string blob.

Each entry contains:

- stable service ID, stable slot, bounded UTF-8 name and path offsets;
- executable format, architecture, binary size and SHA-256;
- sealed bootstrap LoadPlan offset/size/hash when applicable;
- protocol min/max and endpoint service ID;
- autostart, restart policy, start/stop/health timeouts, crash-loop limits;
- Credential profile ID and ResourceDomain profile ID;
- dependency and capability-grant ranges;
- failure action: continue degraded, retry, emergency fallback, or fail boot.

The parser caps entries at 64, dependency edges at 256, grants at 256, strings
at 16 KiB, and total artifact size at a build-frozen bound. It validates every
range with checked arithmetic, rejects duplicate service IDs/slots, rejects
dependency cycles, rejects unknown required flags, verifies all hashes, and
accepts no pointers.

If the manifest is embedded in an already authenticated kernel image, that
image measurement is the root of trust and the internal hash protects layout.
If it is loaded externally, a signature rooted in the boot trust store is
mandatory. The same parser must not silently downgrade external input to
embedded trust.

### 6.2 Deterministic package pipeline

The generator:

1. builds each service binary reproducibly;
2. hashes the exact binary bytes;
3. parses serviced and execd at build time with the production parser library;
4. emits sealed bootstrap LoadPlans for those two binaries;
5. verifies that each plan's source hash equals its binary hash;
6. emits the manifest in stable service-ID order;
7. re-parses the generated artifact and compares a normalized dump with the
   source manifest;
8. embeds binary objects, plans, and manifest in ramfs/kernel package;
9. fails on an unreferenced embedded service or a manifest path without bytes.

Current helpers duetos_native_app and ramfs accessors may remain as packaging
inputs during migration, but service.cpp may no longer name individual
RamfsXBytes/RamfsXSize functions after the manifest gate lands.

### 6.3 Exact bootstrap order

1. Kernel validates the complete manifest and constructs immutable credential,
   ResourceDomain, dependency, and grant tables.
2. Kernel initializes stable lifecycle slots and an empty ServiceDirectory.
3. Kernel maps the sealed serviced bootstrap LoadPlan through ExecAdmission and
   performs the process-publication gate.
4. serviced publishes its v1 endpoint and reconciles the kernel lifecycle
   table. Kernel watchdogs this exact slot/ProcessKey because serviced cannot
   supervise itself.
5. serviced starts execd from its sealed bootstrap plan through the kernel
   lifecycle broker and waits for the execd endpoint readiness gate.
6. serviced asks execd to parse displayd, then asks the kernel to admit/map and
   publish it. displayd starts with manifest defaults.
7. The same sequence starts registryd. displayd may then subscribe to
   preference notifications.
8. The same sequence starts netd only after its packet channel and
   NetworkMaster lease are prepared.
9. serviced starts ordinary autostart entries in dependency order.

On serviced restart, the kernel preserves running services but closes
serviced's old endpoint. The replacement reloads the authenticated manifest,
enumerates exact lifecycle slots and endpoint epochs from the kernel, adopts
only matching generations, and re-applies policy. It never guesses from PIDs.

## 7. Slice 1: serviced

### 7.1 Current owner and destination

Current kernel/core/service.cpp owns the manifest, runtime rows, polling,
crash-loop policy, trusted profiles, SpawnPeFile/SpawnElfFile calls, and shell
control. Its manifest has seven rows: usershell, hello_native, nat_calc,
nat_sysinfo, duet-pkg, netd, and netd_probe. Only netd uses Always.

| Current symbol/state | Live consumers | Destination | Kernel residual/adapter |
| --- | --- | --- | --- |
| ServiceManagerInit | boot_bringup.cpp | serviced manifest initialization | bootstrap slot/directory initialization |
| ServiceManagerStartAll | boot_bringup.cpp | serviced dependency scheduler | compatibility call starts serviced only, then sends StartDesired |
| ServiceManagerTick | kernel supervisor task | serviced lifecycle event loop | kernel emits exact exit/endpoint-close events; no policy poll |
| ServiceStart/Stop/Restart | shell_service.cpp | Serviced v1 control protocol | shell adapter connects with Control grant |
| ServiceCount/ServiceStatusAt | shell_service.cpp | Serviced Enumerate/Query | shell/diag adapter copies bounded replies |
| ServiceManagerSelfTest | boot_bringup.cpp | serviced host/unit tests | kernel retains transition/publication self-test |
| ServiceDesc/kManifest | service.cpp and ramfs accessors | BootServiceManifest | kernel retains parsed immutable bootstrap rows |
| SpawnService/ExecuteStart | service.cpp | serviced lifecycle request plus kernel spawn broker | exact process-publication gate |
| g_service_lock/runtime table | service.cpp | serviced desired-state database | kernel keeps minimal transition state per stable slot |
| SchedProcessAlive polling | ServiceManagerTick | kernel lifecycle/reap event stream | exact ProcessKey event source |

The existing ServicedProtocol v1 is the public control plane: Enumerate, Query,
Start, Stop, and Restart. Preserve that ABI. New boot reconciliation and
lifecycle operations belong to a separate kernel-private LifecycleBroker
contract so public Control authority cannot manufacture Process objects.

### 7.2 Kernel LifecycleBroker

LifecycleBroker is not a globally resolvable service. serviced receives its
single handle at bootstrap. It permits only manifest-scoped operations:

- EnumerateSlots: immutable service ID/slot and exact transition snapshot.
- ReserveStart: reserve one current ServiceStartTicket for an allowed slot.
- PublishPrepared: consume an admitted executable plus ticket at the scheduler
  publication gate.
- StopInstance: invalidate exact slot/generation and kill returned ProcessKey.
- ReadEvent: ordered exit, publication, endpoint-ready, endpoint-close, and
  deadline events.
- AcknowledgeEvent: commit serviced's event sequence after policy processing.

The broker derives credentials, ResourceDomain, endpoint grants, and budgets
from the authenticated manifest. serviced supplies service ID and expected
generation, never arbitrary caps or budgets. Even a compromised serviced
cannot start an unlisted image, widen a profile, publish a different service
ID, or kill a process outside a controlled slot.

### 7.3 serviced internal ownership

The process owns:

- immutable parsed manifest view;
- one DesiredState row per service;
- restart-window counters and deadlines;
- dependency graph and readiness state;
- last acknowledged kernel lifecycle sequence;
- operator-request deduplication ledger.

It does not own Process pointers, Task pointers, kernel handles belonging to
other processes, or scheduler state. DesiredState keys are stable slot plus
manifest generation. ObservedInstance keys are exact slot, instance generation,
ProcessKey, and endpoint epoch.

The supervisor event loop is the only writer. Protocol receivers validate and
enqueue commands with request IDs; replies commit after the event loop applies
or rejects them. This makes Start/Stop/Restart linearizable without a
cross-thread service-state lock.

### 7.4 Restart and recovery

- Never: leave Exited until an explicit Start.
- Always: restart on any exit, with current five-per-60-second defaults unless
  overridden by the manifest.
- OnFailure: may be added only after exact exit reason/status is present in the
  lifecycle event.
- GenerationExhausted: terminal until reboot; never wrap.
- serviced crash: kernel bootstrap watchdog applies its own bounded restart
  window. Replacement reloads manifest and reconciles exact kernel slots.
- manifest mismatch during reconciliation: drain the instance and restart from
  authenticated current bytes; do not adopt by name.
- incomplete operator request: client reconnects and queries state using its
  request ID. Mutating requests are idempotent by client identity/request ID.

### 7.5 Files and staged adapters

Proposed new files after claims clear:

- config/services.toml
- tools/build/gen-service-manifest.py
- kernel/core/boot_service_manifest.h/.cpp
- kernel/core/service_directory.h/.cpp
- kernel/core/service_endpoint.h/.cpp
- kernel/core/lifecycle_broker.h/.cpp
- userland/services/serviced/main.c
- userland/services/serviced/manifest.c
- userland/services/serviced/supervisor.c
- userland/libduet/service_client.c/.h
- tests/host/test_boot_service_manifest.cpp
- tests/host/test_service_directory.cpp
- tests/host/test_service_endpoint.cpp
- tests/host/test_lifecycle_broker.cpp
- tests/host/test_serviced_supervisor.cpp

Compatibility work in claimed existing files comes later:

- service.cpp/h become the bootstrap/lifecycle adapter and then shrink.
- boot_bringup.cpp starts only the bootstrap chain.
- shell_service.cpp becomes a Serviced v1 client.
- ramfs.cpp/h expose manifest-addressed immutable objects rather than one
  function pair per service.
- tests/host/CMakeLists.txt registers all transition/protocol tests.

### 7.6 serviced publication/release gate

serviced may become default only after:

- service_transition is integrated at the real scheduler publication lock;
- stop-vs-start exhaustive interleavings prove no runnable-but-unrecorded gap;
- endpoint readiness CAS and bootstrap-token replay tests pass;
- manifest hostile-input fuzzing and dependency-cycle tests pass;
- shell start/stop/restart/status work through the protocol;
- serviced crash/restart reconciles running exact generations without duplicate
  netd listeners or leaked ResourceDomains;
- the old constexpr manifest is no longer authoritative;
- service_transition and serviced_protocol tests are registered in CTest;
- hosted tests, kernel build/link, boot smoke, and a repeated crash-loop QEMU
  scenario pass on one immutable SHA.

Rollback keeps the old kernel manager as sole owner behind a build option and
does not start serviced.

## 8. Slice 2: execd

### 8.1 Boundary

execd accepts a sealed immutable SourceImage object, format hint, parse policy,
and request ID. It returns a sealed LoadPlan object reference plus the exact
source hash. The kernel independently checks trusted transfer metadata,
validates the complete LoadPlan once, consumes a nonwrapping ExecAdmission
token, maps the sealed backing, constructs process state privately, and reaches
the scheduler publication gate.

The existing Execd protocol already encodes Parse and Cancel and correctly
avoids inlining the maximum 18,496-byte LoadPlan into KMessagePort's 4 KiB
ring. Freeze v1 around ObjectTransfer:

- SourceImage must import as immutable MemoryObject with source policy v1,
  Read only, nonzero identity, bounded size at or below 1 GiB, and exact hash.
- LoadPlan must import as KObjectType::LoadPlan with plan policy v1, Read only,
  sealed flag, maximum 18,496 bytes, and exact content hash.
- The plan names one sealed executable backing object. Its source hash must
  equal the SourceImage metadata hash.
- Cancel binds the exact request ID and endpoint epoch. It cannot cancel a
  reused ID in another epoch.

### 8.2 Current owner and destination

| Current area | Destination | Kernel residual/adapter |
| --- | --- | --- |
| SpawnPeFile/SpawnElfFile call family | ExecdClient parse request | private process builder and publication gate |
| PE/COFF header, import, relocation, resource parsing | execd parser library | none after all consumers migrate |
| ELF header/program-header/interpreter parsing | execd parser library | none after bootstrap plans exist |
| load_image mutable staging/patch/seal | execd request-local package | KObject allocation/seal/map primitives |
| load_plan serialization | execd output | LoadPlanValidateV1 remains kernel ingress validator |
| exec_admission prepare/consume/cancel | none | remains kernel, one per private spawn |
| execd_protocol encode/validate | client/server shared ABI library | trusted endpoint/object authority remains kernel |
| current ramfs binary pointer access | immutable SourceImage object | manifest-addressed object lookup |
| shell/desktop/service spawns | ExecdClient | syscall/kernel compatibility adapter until direct client exists |

The exact new loader symbol scan found no production consumer at this snapshot.
The first execd implementation task is therefore wiring one noncritical spawn
through ExecdClient under a feature flag, not deleting the old parser.

### 8.3 Parse and admission transaction

1. Caller opens or receives an immutable SourceImage handle.
2. Kernel exports it into the caller-to-execd transfer table using
   kernel-derived identity, size, hash, sealed policy, type, and maximum rights.
3. Client sends Execd Parse v1 with request ID, source ref, format hint, and a
   manifest-selected policy ID.
4. execd imports Read only, snapshots the exact bytes once, parses into private
   LoadImage state, applies relocations/import metadata policy, and seals.
5. execd creates sealed backing and typed LoadPlan KObjects, then exports the
   plan reference with trusted metadata.
6. Client imports Read only and asks ExecAdmissionPrepare to copy and validate
   the exact plan into kernel-owned frozen storage.
7. Kernel rechecks backing identity/hash/seal against plan facts, allocates
   private Process/Task/AS/resources, and maps using consuming semantics.
8. ExecAdmissionConsume commits the exact token once. Failure calls Cancel and
   rolls back mapped pages, frames, handles, and ResourceDomain charges in
   reverse acquisition order.
9. Managed services then execute the service process-publication gate.

No userland parser decision can grant W+X, map kernel addresses, exceed the 256
region/1 GiB ceilings, forge an entry point, or substitute backing after seal.

### 8.4 Cache, cancellation, and failure

A parse cache key is source hash, format, architecture, parser build ID, policy
ID, and protocol version. Cache values are sealed objects; mutable LoadImage
state is never cached. Cache entries are ResourceDomain charged and bounded by
bytes/count/age.

Cancellation checks occur between bounded parser phases and before export.
Closing the client endpoint cancels unpublished work. Once ExecAdmission has
consumed a token, execd cancellation cannot unwind kernel state; the caller
owns process-construction rollback.

execd crash closes its endpoint and transfer tables. In-flight parses fail
PeerClosed, private userland allocations die with the process, and clients
retry only with a new endpoint epoch and a new request ID. serviced restarts
execd from its bootstrap plan.

### 8.5 Files, tests, and migration order

Proposed:

- userland/services/execd/main.c
- userland/services/execd/parser_pe.*
- userland/services/execd/parser_elf.*
- userland/services/execd/load_image.*
- userland/libduet/execd_client.*
- kernel/loader/immutable_blob.h/.cpp
- kernel/loader/load_plan_object.h/.cpp
- kernel/loader/exec_spawn_adapter.h/.cpp
- tests/fuzz/fuzz_boot_service_manifest.cpp
- tests/fuzz/fuzz_load_plan.cpp
- tests/fuzz/fuzz_execd_pe.cpp
- tests/fuzz/fuzz_execd_elf.cpp
- tests/host/test_exec_spawn_adapter.cpp
- tests/host/test_execd_object_transfer.cpp

Migration order:

1. register and pass existing LoadPlan, LoadImage, ExecAdmission, Execd
   protocol, ObjectTransfer, and KMessagePort tests;
2. add typed object/endpoint integration tests;
3. route one native test app and one PE test app through execd;
4. shadow-parse a corpus and compare normalized plans while the old parser is
   still sole publisher;
5. switch service spawns, shell exec, desktop launch, and Win32 process-create
   adapters one caller family at a time;
6. generate serviced/execd bootstrap plans;
7. remove generic PE/ELF parsing from the kernel image only after no production
   include/call site remains.

### 8.6 execd release and rollback gate

Required proof:

- adversarial size/offset/overlap/W^X/hash/seal vectors;
- transfer type confusion, rights widening, stale/replayed ref, table close,
  and endpoint-close races;
- cancel at every parse/admission/map phase with zero leaked frames/objects;
- parser crash and restart while many clients retry;
- PE64, PE32, native ELF, imports, relocations, TLS, resources, and malformed
  corpora produce expected plans;
- old/new normalized plan differential test is clean for the shipping corpus;
- kernel binary has no ordinary executable parser call path after cutover;
- full build/link, hosted/fuzz gates, and QEMU process launch pass on one SHA.

Rollback selects the kernel parser as sole plan producer. The immutable
LoadPlan validator/publication gate remains, so rollback does not regress the
new trust boundary.

## 9. Slice 3: displayd

### 9.1 Boundary and ownership

displayd owns:

- window registry, service-epoch window IDs, z-order, parent/owner relations;
- focus, capture, caret, hover, timers, animations, snap/max/min/restore;
- client GUI queues, cross-process broker policy, input routing;
- composition, damage, chrome, taskbar, wallpaper, menu, dialogs;
- clipboard and non-security user display/input preferences;
- GDI object/session policy and validated display-list interpretation.

Kernel retains:

- framebuffer/GPU device discovery, MMIO, DMA, IOMMU, interrupts;
- display mode validation, scanout buffers, vblank/fence waitables;
- raw keyboard/mouse/touch event decoding and seat assignment;
- a revocable DisplayMaster lease granting modeset/scanout;
- bounded Surface/MemoryObject mapping with per-domain quotas;
- panic/emergency console that never invokes displayd;
- credential checks for connect and raw-input/display-master grants.

The kernel emergency console may replace displayd after lease revocation. It is
not a second desktop compositor and may not mutate displayd window state.

### 9.2 Protocol v1

Use service ID DSPD and these method groups:

- OpenSession/CloseSession/QueryCapabilities
- CreateSurface/ResizeSurface/DestroySurface
- CreateWindow/UpdateWindow/DestroyWindow/SetParent
- CommitSurface/CommitScene/AckConfigure
- ReadEvents/AckEvents
- RequestFocus/SetCapture/ReleaseCapture
- SetClipboard/GetClipboard/SubscribeClipboard
- CreateGdiObject/UpdateGdiObject/DestroyGdiObject
- QueryWindow/QueryDisplay/SetPreference

Every service-local WindowRef, SurfaceRef, GdiRef, and EventQueueRef contains
displayd epoch plus slot plus generation. Payloads are fixed-size or bounded
length-prefixed records. Native callback pointers/cookies, kernel WindowHandle,
WindowChrome title pointers, framebuffer pointers, and raw message pointers do
not cross the wire.

A Surface KObject binds:

- immutable format, width, height, stride, byte size, usage, and owner
  ProcessKey;
- retained MemoryObject;
- owner rights Map|Write|Transfer;
- displayd rights Map|Read;
- optional scanout right held only by the DisplayMaster path;
- generation and fence timeline.

The client writes only its buffer. displayd reads and composes. A commit names a
surface generation, damage rectangles, and fence value; it does not transfer
ownership of client write access. Resize allocates a new generation and old
buffers drain after the last committed fence.

### 9.3 Current owner/consumer map

| Current functions/state | Important current consumers | Destination/adaptation |
| --- | --- | --- |
| WidgetRegisterButton, WidgetRouteMouse, tooltip routing | boot_tasks and kernel apps | displayd scene/input event model; temporary kernel client shim |
| WindowRegister/Close/Raise/Move/resize/snap/min/max/restore | boot_tasks, menu_dispatch, kernel apps, window_syscall | displayd Window methods |
| WindowActive/focus/capture/caret/timers/animations | input/timer tasks and Win32 syscalls | displayd compositor actor |
| WindowDraw/DrawAll/display-list/chrome | framebuffer composition | displayd renderer |
| WindowResolvePublicHandle and global window slots | window_syscall/gdi | displayd epoch refs; syscall adapter maps per-process client refs |
| GuiMessageQueue task-owned 64-entry queues | Win32 Get/Peek/Dispatch paths | displayd session event queue |
| GuiMessagePolicy/GuiBrokerProtocol | intended cross-process GUI broker | displayd protocol/policy library |
| gdi_objects side tables/surfaces | GDI syscalls and window ownership | displayd GDI refs plus Surface objects |
| CompositorLock/Unlock | 20 files, especially boot_tasks/window_syscall/gdi | retired by actor enqueue/commit |
| framebuffer/modeset/GPU driver calls | compositor and diagnostics | kernel display device service |
| raw native callbacks/cookies | kernel-native apps | move apps to userland or replace with message callbacks |

The 280 exact compositor-lock matches establish the main blocker: widget.cpp
cannot simply move while boot_tasks.cpp and native kernel apps mutate its state
directly.

### 9.4 Staged extraction

Phase D0 — freeze service-safe GUI contracts:

- complete GuiMessageQueue, policy, and broker registration/tests;
- define DSPD protocol, refs, Surface object, and DisplayMaster lease;
- forbid pointer-bearing new GUI APIs;
- create a displayd client shim behind window_syscall and gdi_objects.

Phase D1 — queue/broker authority:

- displayd owns Win32 task queues and cross-process policy;
- window_syscall remains a bounded copy/marshalling adapter;
- old queue path is sole fallback, selected at boot.

Phase D2 — surfaces and GDI:

- clients allocate Surface KObjects; gdi_objects becomes a ref adapter;
- displayd validates display lists and composes off-screen surfaces;
- no kernel global GDI side table remains authoritative.

Phase D3 — window manager:

- displayd owns window slots, z-order, focus/capture, timers, clipboard, and
  input routing;
- convert boot_tasks/menu/native apps to userland clients or a bounded kernel
  client endpoint that only sends messages;
- remove direct Window/Widget mutation outside displayd.

Phase D4 — compositor:

- transfer DisplayMaster lease after readiness;
- displayd composes and submits validated scanout;
- kernel retains emergency console and reclaims master on crash/hang.

### 9.5 Crash/restart behavior

On displayd failure the kernel revokes DisplayMaster, stops accepting scanout
buffers from the old ProcessKey, closes endpoints, and paints an emergency
console or stable diagnostic frame. Surface objects remain owned by clients,
but old WindowRefs and GdiRefs are stale.

After reconnect, clients replay idempotent descriptors:

1. OpenSession with new endpoint epoch.
2. Re-transfer existing Surface handles with narrowed rights.
3. Recreate windows and GDI resources.
4. Commit the latest complete scene serial.

displayd never attempts to recover half-applied scene mutations from old
memory. Each CommitScene is atomic at a scene serial. Clipboard may be lost on
crash until registryd-backed persistence is deliberately added; this is
preferable to kernel pointer retention.

### 9.6 Files and tests

Proposed:

- userland/services/displayd/main.*
- userland/services/displayd/protocol.*
- userland/services/displayd/scene.*
- userland/services/displayd/compositor.*
- userland/services/displayd/input.*
- userland/services/displayd/gdi.*
- userland/libduet/display_client.*
- kernel/drivers/video/display_device.h/.cpp
- kernel/drivers/video/display_master.h/.cpp
- kernel/ipc/ksurface.h/.cpp
- tests/host/test_displayd_protocol.cpp
- tests/host/test_surface_rights.cpp
- tests/host/test_display_scene.cpp
- tests/host/test_display_restart.cpp
- tests/fuzz/fuzz_displayd_protocol.cpp
- tests/fuzz/fuzz_display_list.cpp

Fault tests must inject endpoint close, stale window/surface refs, client death
during commit, displayd death during scanout, queue full, lost fence, resize
races, invalid stride/size arithmetic, excessive damage rectangles, malformed
display lists, focus/capture abuse, and clipboard size/version errors.

The release gate requires zero direct external CompositorLock/Unlock calls,
zero pointer-bearing wire fields, ownership tests for every surface mapping,
input/session isolation tests, displayd kill/restart recovery, emergency
console takeover, GUI host tests registered, and full visual/QEMU smoke on one
SHA. Rollback boots the kernel compositor as sole owner and never grants a
DisplayMaster lease to displayd.

## 10. Slice 4: registryd

### 10.1 Boundary

registryd owns the mutable Win32 registry:

- key/value tree, predefined-root views, per-user overlays;
- Open/Query/Create/Delete/Enumerate semantics;
- transactions, write-ahead log, snapshots, flush, notifications;
- service-epoch KeyRef, TxnRef, and SubscriptionRef allocation;
- schema/version migration and durable recovery.

The kernel retains immutable boot configuration, privilege configuration,
credentials, VFS/KFile enforcement, user-copy adapters, and authorization
snapshots. registryd receives a narrow durable store file/directory handle; it
never receives raw FAT32 sectors or a block-device handle.

### 10.2 Protocol and rights

Use service ID REGD. V1 methods:

- OpenKey/CreateKey/CloseKey/DeleteKey
- QueryValue/SetValue/DeleteValue
- EnumerateKey/EnumerateValue/QueryKey
- BeginTransaction/CommitTransaction/AbortTransaction
- Subscribe/Unsubscribe/ReadNotifications
- Flush/QueryStoreHealth

Connection authority fixes root scope, user/security identity, read/write/
create/delete/notify rights, and optional administrative view. HKCU is derived
from the trusted credential snapshot, not a root value supplied by the
message. A service-local KeyRef includes registryd epoch, slot, generation,
and access mask. Rights can only narrow below the channel authority.

### 10.3 Current owner/consumer map

| Current symbol/state | Consumer | Destination/adaptation |
| --- | --- | --- |
| DoRegistry | SYS_REGISTRY dispatch | bounded RegistryClient syscall adapter |
| per-Process registry slot rows | NtClose/file close dispatch | Registry session KeyRefs; close is RPC or endpoint teardown |
| static key tree and sidecar pool | registry.cpp | registryd in-memory store |
| RegistryHiveLoad/Save/SelfTest | boot and mutation paths | registryd WAL/snapshot recovery/tests |
| SidecarSnapshotAt/RestoreOne/Reset | registry_hive.cpp | registryd storage implementation |
| RegistryQuery | GDB monitor | bounded diagnostic client or cached health snapshot |
| RegistrySelfTest | boot_bringup | hosted registryd semantic tests; minimal adapter self-test |
| ntdll_reg and advapi32_32 registry calls | SYS_REGISTRY | unchanged ABI first, optional direct client later |
| privilege/config.cpp and boot cmdline | security subsystem | stays kernel; never forwarded to registryd |

The current mutable sidecar capacity is 32 and hive save is synchronous with
mutation. The custom REGISTRY.HIV path formats static buffers and replaces the
file through delete/create behavior rather than an explicit atomic WAL commit.
No registry-wide synchronization primitive was visible around the global
sidecar/hive path in this source snapshot. That persistence and concurrency
model must not be carried over as the durability contract.

### 10.4 Durable transaction model

One registryd writer assigns a nonwrapping commit sequence. A mutation
transaction:

1. validates channel authority and all key/value sizes;
2. resolves exact service-epoch refs;
3. builds an immutable transaction record privately;
4. appends length, version, sequence, previous-sequence, payload hash, and
   checksum to the WAL;
5. requests durable flush from the narrow VFS handle;
6. applies the record to a copy-on-write tree root;
7. atomically publishes the new root/commit sequence;
8. queues bounded notifications;
9. replies with committed sequence.

Recovery reads the last authenticated snapshot, replays complete contiguous WAL
records, ignores a torn tail, and rejects an interior checksum/sequence gap as
store corruption. Snapshot creation writes a new file, durably flushes it,
atomically replaces the active snapshot through a VFS primitive, then truncates
the WAL only after the new root is durable. The kernel VFS must provide or
emulate that atomic replace; registryd must not delete the only good snapshot
first.

Client request IDs and transaction IDs make retries idempotent. A reply lost
after commit can be resolved through QueryTransaction/commit sequence rather
than applying the mutation twice.

### 10.5 Crash/restart and migration

On crash, all KeyRef/TxnRef/SubscriptionRef values are stale. The new instance
recovers snapshot+WAL, publishes a new endpoint, and clients reopen paths.
Uncommitted transactions disappear; committed transactions are discoverable by
ID. Notifications resume from a committed sequence if still within the
bounded journal, otherwise the client receives ResyncRequired.

Migration order:

1. define protocol/ref/path/value bounds and WAL model;
2. run registryd in read-only shadow mode against the static tree;
3. switch Query/Open/Enumerate through DoRegistry adapter;
4. switch mutations with registryd as sole writer and preserve a rollback
   snapshot;
5. switch boot hive load/flush;
6. remove static sidecar and synchronous RegistryHiveSave authority;
7. optionally change ntdll/advapi clients to connect directly while retaining
   SYS_REGISTRY ABI compatibility.

### 10.6 Files, tests, and gate

Proposed:

- userland/services/registryd/main.*
- userland/services/registryd/store.*
- userland/services/registryd/wal.*
- userland/services/registryd/protocol.*
- userland/libduet/registry_client.*
- kernel/subsystems/win32/registry_client_adapter.*
- kernel/fs/atomic_replace.*
- tests/host/test_registryd_protocol.cpp
- tests/host/test_registryd_store.cpp
- tests/host/test_registryd_wal.cpp
- tests/host/test_registry_adapter.cpp
- tests/fuzz/fuzz_registryd_protocol.cpp
- tests/fuzz/fuzz_registry_wal.cpp

Fault injection covers every byte boundary, path normalization/case behavior,
authorization, reference generation, WAL append/flush/rename/truncate point,
disk full, torn tail, corrupt interior record, duplicate request, endpoint
close, service crash, client crash, notification overflow, and concurrent
read/write ordering.

Release requires Win32 registry conformance for existing ntdll/advapi clients,
power-loss simulation across every durable step, restart/reopen proof, no
mutable sidecar authority in kernel, no delegation of privilege/boot policy,
and full build/host/fuzz/QEMU smoke on one SHA. Rollback stops registryd and
boots from the last compatible kernel-owned snapshot as sole writer; format
versioning must preserve that escape until the next release.

## 11. Slice 5: netd

### 11.1 Boundary

The current userland netd is a TCP echo daemon on 0.0.0.0:7777 using native BSD
syscalls. It is not the network service described here. Target netd owns the
ordinary networking data/control plane:

- interface configuration, link policy, ARP/neighbor discovery;
- IPv4/IPv6, ICMP, UDP, TCP state machines and socket tables;
- routing, DHCP, DNS, firewall policy, socket options/poll state;
- optional TLS/HTTP helpers after their own parser review.

Kernel retains NIC drivers, firmware loading policy, MMIO, DMA/IOMMU, interrupt
handling, link/MTU facts, bounded PacketRing/MemoryObject objects, packet
buffer ownership transitions, credential/cap checks, and a revocable
NetworkMaster lease.

### 11.2 Packet and socket objects

Control requests use NETD MessageAbi RPC. Payload data uses two shared
PacketRing objects per interface/queue:

- kernel-to-netd RX ring: kernel produces descriptors and transfers buffer Read
  ownership; netd consumes and returns buffers;
- netd-to-kernel TX ring: netd produces validated descriptors over buffers it
  may Write; kernel consumes for the NIC and signals completion.

Each descriptor binds buffer generation, offset, length, interface generation,
flags, and sequence. Bounds are checked against trusted MemoryObject metadata.
Descriptor publish/consume uses release/acquire ordering, exact producer and
consumer roles, nonwrapping sequences, and explicit Full. Quotas cap ring
descriptors, total buffer bytes, pinned pages, and per-client backlog.

NETD socket methods:

- Open/Close/Duplicate
- Bind/Connect/Listen/Accept
- Send/Recv/SendTo/RecvFrom
- Shutdown/SetOption/GetOption
- Poll/Subscribe/AckEvents
- GetLocal/GetPeer/QueryStats

SocketRef contains netd epoch, slot, and generation. Connection authority binds
network namespace, allowed address families, raw/bind-low-port/admin rights,
and ResourceDomain limits. Payload buffers use transferred MemoryObjects or a
per-session shared data ring; large data is never inlined repeatedly into the
control port.

### 11.3 Current owner/consumer map

| Current functions/state | Consumers | Destination/adaptation |
| --- | --- | --- |
| SocketAlloc/Retain/Release/ReleaseByOwner | syscall paths and ProcessRelease | netd SocketRef lifecycle; kernel closes client endpoint on process exit |
| SocketPin/Unpin and state probes | blocking syscall paths | client request lifetime; no kernel Socket pointer |
| SocketBind/Connect/Listen/Accept variants | Linux/Win32 and kernel services | NETD control methods |
| SocketSend/Recv datagram/stream | Linux/Win32, shell, DRSH, TLS/browser | shared session buffers plus NETD methods |
| SocketShutdown/GetLocal/GetPeer/PollEvents | syscall/event adapters | NETD methods/notifications |
| SocketUdpDispatch and TCP OnSegment | kernel stack RX | netd PacketRing RX |
| socket.cpp pool and tcp/stack state | kernel/net | netd protocol state |
| syscall_socket.cpp | Linux ABI | bounded kernel client adapter initially |
| ws2_32 plus Win32 syscall dispatch | Winsock | bounded adapter, later direct client |
| shell_wget/browser/tls_socket | kernel clients | move to userland clients or narrow kernel endpoint |
| drsh_server/drsh_transport | remote recovery | must migrate or become crash-only emergency path |
| NIC/Wi-Fi drivers and DMA | network stack | kernel network-device boundary |

Do not map the current 256-entry socket pool one-for-one into kernel proxy
objects. Kernel adapters keep per-process NETD SocketRefs in an ordinary handle
object or descriptor table, while socket state lives only in netd. Process
teardown closes the endpoint/handles; it does not sweep a global kernel socket
pool after cutover.

### 11.4 DRSH and emergency networking decision

Running kernel TCP and netd TCP concurrently over one NIC creates duplicate
ARP, port, sequence, firewall, and packet ownership. It is forbidden.

Preferred decision: migrate authenticated DRSH to a userland drshd using netd
before granting NetworkMaster in normal boots. If an independent recovery
channel is required, retain a minimal kernel crash-only stack with these rules:

- inactive and unable to receive packets while netd holds NetworkMaster;
- activated only after the exact netd lease is revoked and DMA/rings drained;
- fixed loopback/management policy and bounded protocol surface;
- no adoption of netd sockets or TCP state;
- deactivated before a replacement netd receives new rings.

This choice must be made before netd implementation; silently keeping current
kernel DRSH live is a publication blocker.

### 11.5 Crash/restart

On netd failure the kernel revokes NetworkMaster, stops RX/TX delivery, drains
DMA completions, closes the old packet rings, and marks every old SocketRef
stale. Client calls return NetworkReset/PeerClosed. The new netd starts with
fresh protocol state; ordinary TCP connections are not resurrected.

Clients reconnect and recreate listeners from idempotent descriptors. serviced
orders listener restoration and health checks before dependent services are
Ready. Bind conflicts are evaluated within the new epoch only. DHCP/routes may
reload an authenticated cached lease/config, but neighbor and TCP state are
relearned.

### 11.6 Files, tests, and migration order

Proposed:

- userland/services/netd/main.*
- userland/services/netd/protocol.*
- userland/services/netd/socket_table.*
- userland/services/netd/ipv4.*, ipv6.*, udp.*, tcp.*, route.*, neighbor.*
- userland/services/drshd/* if normal DRSH migrates
- userland/libduet/net_client.*
- kernel/drivers/net/network_device.*
- kernel/ipc/kpacket_ring.*
- kernel/subsystems/linux/netd_socket_adapter.*
- kernel/subsystems/win32/netd_winsock_adapter.*
- tests/host/test_packet_ring.cpp
- tests/host/test_netd_protocol.cpp
- tests/host/test_netd_socket_refs.cpp
- tests/host/test_network_master.cpp
- tests/fuzz/fuzz_netd_protocol.cpp
- tests/fuzz/fuzz_packet_ingress.cpp

Migration:

1. freeze PacketRing, NetworkMaster, protocol, rights, and quotas;
2. mirror RX packets to a read-only netd parser oracle while the kernel stack
   remains sole consumer/mutator;
3. migrate noncritical userland UDP/TCP probes;
4. migrate Linux and Winsock syscall adapters;
5. migrate shell/browser/TLS and DRSH ownership;
6. quiesce kernel stack, drain rings, atomically grant NetworkMaster, then make
   netd sole stack;
7. remove ordinary protocol/socket state from the kernel image.

Fault tests inject malformed/truncated packets, descriptor arithmetic overflow,
generation replay, ring Full, client death with pending I/O, netd death during
DMA, lease revoke/regrant, duplicate bind/listen, half-close, timeout, packet
loss/reorder/duplication, route/neighbor exhaustion, slow readers, and restart
storms.

Release requires no dual live stack, complete syscall/Winsock semantics needed
by current consumers, DRSH decision implemented, packet ownership/refcount
proof, lease-revoke recovery, network fuzz suites, stress with all rings full,
and full build/host/QEMU network smoke on one SHA. Rollback withholds
NetworkMaster and boots the current kernel stack as sole owner.

## 12. Capability and dependency manifest

The initial manifest grant matrix is intentionally small:

| Holder | Kernel/service capability | Scope |
| --- | --- | --- |
| serviced | LifecycleBroker Inspect/Control | only stable slots in the authenticated manifest |
| serviced | Execd Call/Transfer | immutable service binaries only |
| execd | SourceImage Read/Map; LoadPlan create/seal/export | per-request ResourceDomain budget; no process publication |
| displayd | DisplayMaster; raw seat-input Read; Surface Map/Read | assigned displays/seats only |
| registryd | registry store KFile Read/Write/Wait | one configured store root; no raw block device |
| netd | NetworkMaster; PacketRing Map/Read/Write/Wait | assigned interfaces/queues only |
| shell svc client | Serviced Inspect and optionally Control | all or named service slots per credential profile |
| ordinary process | Execd Call, Displayd session, Registryd user view, Netd socket client | profile-specific, rights-narrowed connections |

No service receives Duplicate or Transfer on a master lease. Master leases are
kernel-minted, exact-ProcessKey, nontransferable, and automatically revoked on
process teardown. serviced requests a lease be prepared for a manifest slot;
it never holds or forwards the lease itself.

The activation dependencies are:

| Service | Hard dependencies | Optional late dependencies | Ready condition |
| --- | --- | --- | --- |
| serviced | kernel lifecycle broker, manifest | none | endpoint published and manifest reconciled |
| execd | serviced, object transfer, immutable memory/load-plan objects | none | endpoint published; bootstrap self-parse corpus passed |
| displayd | serviced, execd, display device/input, Surface objects | registryd preferences | endpoint published and emergency frame replaced under DisplayMaster |
| registryd | serviced, execd, durable VFS handle | displayd notification consumer | snapshot/WAL recovered and endpoint published |
| netd | serviced, execd, network device, PacketRing | registryd network preferences | rings ready, lease held, link/control endpoint published |

Readiness is a state transition, not a log line. serviced consumes the
kernel-attested directory event for the exact instance and endpoint epoch.
Health checks are protocol calls with deadlines and request IDs. A passing
health check cannot revive a stale epoch.

## 13. Cross-slice implementation sequence

### Foundation F0 — freeze contracts

Deliverables:

- finish and register MessageAbi, VersionedPayload, MessageRing, KMessagePort,
  ObjectTransfer, HandleTable/KObject, LoadPlan, LoadImage, ExecAdmission,
  ExecdProtocol, ServiceTransition, ServicedProtocol, and GUI broker tests;
- document stable enum/tag numbers and nonwrapping-generation behavior;
- resolve KObject type additions and Map right without renumbering existing
  types/rights;
- add generated hostile-input vectors shared by kernel and userland builds.

Exit: every contract is independently buildable/testable and no active claim
is overwritten.

### Foundation F1 — authenticated endpoints

Deliverables:

- ServiceEndpoint and ServiceDirectory;
- bidirectional MessagePort composition;
- exact credential/ResourceDomain authority snapshots;
- two directional transfer tables;
- replay, cancellation, close, quota, and endpoint-generation semantics.

Exit: two hosted synthetic processes can connect, exchange versioned messages
and typed objects, race close/cancel, and release every reference/charge.

### Foundation F2 — publication and manifest

Deliverables:

- integrate ServiceTransition into the real scheduler publication boundary;
- LifecycleBroker;
- generated BootServiceManifest and deterministic package audit;
- sealed serviced/execd bootstrap LoadPlans.

Exit: a stale start ticket can never produce a runnable task or Ready endpoint,
and a manifest mutation breaks hash/auth validation deterministically.

### Service cuts S1 through S5

| Slice | Shadow/read-only proof | Sole-owner cut | Kernel deletion/retirement |
| --- | --- | --- | --- |
| S1 serviced | mirror status/restart decisions | serviced owns desired state; kernel lifecycle only | constexpr manifest and policy poll |
| S2 execd | normalized plan differential | execd is sole ordinary parser | ordinary PE/ELF parser call paths |
| S3 displayd | scene/event comparison | displayd holds DisplayMaster | global window/compositor/GDI policy |
| S4 registryd | read-only tree comparison | registryd sole mutable writer | sidecar and hive-save authority |
| S5 netd | packet parser oracle | netd holds NetworkMaster | ordinary socket/TCP/IP state |

Each sole-owner cut is its own reviewed commit/PR boundary. Do not combine
display, registry, and network cutovers into one rollback unit.

## 14. Verification and fault matrix

No checks in this section were run during this source-only lane. They are
requirements for later implementation.

### 14.1 Common static/host gates

- protocol structure size/alignment and stable numeric-value assertions;
- exact version, size, flags, service ID, method, kind, and request-ID vectors;
- copy-once hostile input tests, including mutation during validation;
- sequence/generation near-exhaustion and terminal behavior;
- stale/replayed/cross-service/cross-endpoint reference rejection;
- generic-handle right and protocol-authority narrowing;
- object type/hash/size/seal substitution rejection;
- queue Full/Busy, fairness, cancellation, close, and waiter wake;
- ResourceDomain charge/release conservation under every failure path;
- destructor re-entry without lock inversion or use-after-free;
- model-based lifecycle/publication state transitions.

### 14.2 Service fault points

| Service | Mandatory injected failures |
| --- | --- |
| serviced | before/after reserve, private construct, scheduler commit, endpoint CAS, event ack, stop, manifest reload |
| execd | each parser phase, object import/export, seal, admission prepare/consume, every map/rollback step |
| displayd | command enqueue, scene commit, surface resize, fence, lease grant/revoke, input event, scanout |
| registryd | every WAL/snapshot write/flush/replace/truncate boundary, notification overflow, recovery replay |
| netd | descriptor publish/consume, DMA completion, ring exhaustion, lease revoke, protocol timer, socket close |

Every injection asserts:

- no kernel lock remains held;
- no private Task is scheduler-visible unless lifecycle state is Running;
- no Ready directory row points at a dead or different ProcessKey;
- no KObject ref, frame, pin, handle, transfer row, or domain charge leaks;
- old epoch requests cannot mutate new state;
- rollback order is the exact reverse of acquisition except for durable commits,
  whose recovery rule is tested instead.

### 14.3 Fuzz boundaries

Fuzz these independently:

- BootServiceManifest binary parser and dependency/grant graph;
- MessageAbi and each service payload version;
- ObjectTransfer references and metadata-policy combinations;
- LoadPlan validator plus PE/ELF parsers;
- display lists, GUI messages, damage geometry, surface arithmetic;
- registry path/value records, WAL, and snapshots;
- packet descriptors and all network protocol parsers.

Kernel validators must be fuzzed even when the corresponding rich parser moved
to userland. Moving a parser does not make its kernel admission seam trusted.

### 14.4 Live gates after HARD STOP clears

In order:

1. fleet preflight must return GO or an implementation-specific CAUTION plan;
2. register and run the minimum hosted tests;
3. kernel compile and full link with warnings reviewed;
4. deterministic manifest/package rebuild comparison;
5. focused QEMU boot/service smoke;
6. repeated service kill/restart and client reconnect campaign;
7. fuzz-all and relevant security/static gates;
8. authoritative CI on the exact pushed SHA.

Never call the service cut green while fuzz, link, smoke, or authoritative CI
is still pending.

### 14.5 CI, release artifact, and documentation gates

tests/host/CMakeLists.txt is the registration source for the hosted contract
tests, while tools/test/ctest-boot-smoke.sh drives the required comprehensive
debug QEMU boot and treats release-gate skips as failures. The release workflow
builds debug/release artifacts, runs required GRUB+Multiboot2 smoke, and hashes
shipping artifacts. Service extraction must extend these existing gates rather
than introduce an optional parallel truth:

- CTest must register every protocol, state machine, typed object, adapter, and
  recovery test named in this plan.
- The normal build workflow must run service fuzz targets, manifest
  determinism/authentication verification, and an include/call-site retirement
  check for the slice being cut.
- The comprehensive boot smoke must verify exact serviced, execd, displayd,
  registryd, and netd Ready epochs plus ordinary PE/native launch. A log line is
  supporting evidence; the smoke client must successfully call each endpoint.
- A separate bounded fault profile must kill/restart each service and prove
  client reconnect, lease revocation, and no duplicate publication.
- Release artifacts must include the canonical BootServiceManifest, normalized
  manifest dump, service binary/plan hashes, and their SHA256SUMS coverage.
- The release job must publish only the exact source SHA whose manifest,
  binaries, tests, smoke, and hashes were verified.

Documentation changes land with the owning code slice, not ahead of it:

| Document | Required update |
| --- | --- |
| wiki/kernel/Process-Model.md | lifecycle broker, atomic scheduler publication, serviced supervision |
| wiki/kernel/IPC.md | ServiceEndpoint, Map right, typed objects, transfer/close rules |
| wiki/kernel/Boot.md | authenticated manifest and bootstrap order |
| wiki/subsystems/Compositor.md | displayd ownership and kernel display-device residual |
| wiki/subsystems/Win32-Registry.md | registryd protocol and WAL/snapshot recovery |
| wiki/networking/Network-Stack.md | netd, PacketRing, NetworkMaster, DRSH choice |
| wiki/specifications/Syscall-ABI.md | compatibility adapters and error mapping |
| wiki/reference/Roadmap.md | slice status, residual fsd/parser work, rollback boundary |
| wiki/tooling/Build-System.md | manifest generation/reproducibility and service test targets |

README or release notes must not advertise a service as extracted until its old
kernel authority is retired and the release gate passes.

## 15. Active-claim source barrier

At the snapshot, the following implementation surfaces were owned by active
parallel claims. They are evidence inputs only until owners release them:

| Area | Active claim families |
| --- | --- |
| service manager | service-runtime-transactions |
| scheduler publication primitive | service-publication-state header/source/test |
| serviced ABI | serviced-protocol API/source/test |
| IPC object core | kobject-handle-v2 and callers |
| IPC wire/queue | ipc-message-abi, ipc-versioned-payload, ipc-message-ring, ipc-message-port |
| IPC transfer | ipc-object-transfer header/source/test |
| loader | stack-reservation-loader, immutable-load-plan, load-image-staging, exec-admission, execd-protocol |
| GUI | gui-task-message-v2, GUI surface/GDI identity, window side tables, message policy, broker protocol, send transaction |
| sockets | socket-alloc-transaction |
| boot/tests | vm-process-exit-test on boot_bringup.cpp and ipc-message-abi-host-build on tests/host/CMakeLists.txt |
| adjacent design | process-decomposition-map |

Before starting any slice:

1. rerun tools/parallel/status.sh from Git Bash;
2. inspect the landed diff and current HEAD;
3. refresh include/caller counts;
4. claim exact files, including tests and build metadata;
5. rebase or integrate in the repository's prescribed order;
6. do not edit around another owner's uncommitted change in the same file.

This document itself is claimed by service-extraction-map. No source file,
CMake file, wiki file, or adjacent design document is part of this lane.

## 16. Architecture questions and recommended answers

### Q1. Is KMessagePort itself the service endpoint?

No. It is a bounded waitable validated queue. A service endpoint additionally
needs peer identity, credential/resource-domain authority, protocol range,
bidirectional request/reply, request replay/cancel state, two object-transfer
directions, and endpoint epoch.

### Q2. Should service capabilities become new generic HandleTable bits?

No, except Map. Generic bits enforce transport/object mechanics. Inspect versus
Control and service-specific scopes belong in trusted per-protocol authority
snapshots. This avoids a global rights explosion and accidental semantic
aliasing.

### Q3. Should registryd start before displayd?

Not in the requested first chain. displayd starts from immutable boot defaults,
then late-binds registry preferences. Making user preferences a hard display
dependency would enlarge the black-screen failure domain.

### Q4. Should serviced be PID 1?

Conceptually yes, but authorization must not depend on numeric PID 1. Kernel
bootstrap binds the stable serviced slot, exact ProcessKey, bootstrap token,
and manifest profile. PID numbering may change without changing authority.

### Q5. Who restarts serviced?

A minimal kernel bootstrap watchdog, because a service cannot supervise itself.
The watchdog knows only the authenticated serviced bootstrap row, exact
transition state, and bounded restart policy. It does not regain the full
manifest supervisor.

### Q6. Does execd get permission to create processes?

No. It creates sealed parser outputs. Kernel LifecycleBroker/spawn adapters
validate, map, construct, and atomically publish. This separation is the core
security boundary.

### Q7. Can LoadPlan be a generic blob?

No. Keep a typed, sealed LoadPlan object so imports select a concrete KObject
type and immutable-policy ID. A generic byte blob would weaken type confusion
and audit guarantees.

### Q8. Where do file-format parsers run?

Executable and registry persistence parsers move as described. Current
filesystem parsers remain kernel TCB until a separate fsd/block-service design.
Services get KFile or sealed immutable-object access, not raw disk blocks.

### Q9. Can kernel DRSH remain active beside netd?

No. Migrate to drshd or constrain kernel networking to an exclusive,
crash-only mode activated after NetworkMaster revocation. This is a required
decision before netd publication.

### Q10. Should native kernel desktop apps be wrapped forever?

No. A bounded kernel display-client shim is a migration tool. Native apps with
raw callbacks and direct CompositorLock mutation must move to userland or be
retired before display policy can honestly leave the kernel.

### Q11. How is ABI evolution handled?

Never mutate v1 layouts or numeric values. Add optional fields only through a
new payload version with an exact size rule; add required semantics in a new
major protocol version. Directory resolution reports supported ranges, and
clients choose the highest mutually supported version before sending ordinary
methods. A rolling upgrade drains the old endpoint epoch rather than serving
two versions from mutable shared state.

### Q12. What is the service publication release criterion?

Runtime publication is the two-gate process/endpoint transaction in section 5.
Release publication additionally requires the per-slice proof and rollback
gate on an immutable SHA. Neither a runnable process, a PASS log line, nor a
protocol unit test alone is publication.

## 17. Completeness ledger

The requested architecture concerns are mapped as follows:

| Required concern | Section |
| --- | --- |
| serviced -> execd -> displayd -> registryd -> netd sequence | 1, 6.3, 7-11, 13 |
| kernel residual TCB versus userland | 3 and each service boundary |
| endpoint and object rights | 4.1-4.3, 12 |
| versioning | 4.2, service protocols, Q11 |
| ownership and lifetime | 4.4-4.5 and each service |
| publication and rollback | 5, each release gate, 13 |
| restart and recovery | 4.5 and each service |
| fuzz and fault injection | 14 |
| lock/lifetime rules | 4.4 |
| boot capability manifest/order | 6 and 12 |
| per-slice files/adapters/tests | 7.5, 8.5, 9.6, 10.6, 11.6 |
| active-claim blockers | 15 |
| current consumers/functions destinations | 7.1, 8.2, 9.3, 10.3, 11.3 |
| explicit service publication gate | 5 |
| filesystem parser residual | 1, 3, Q8 |
| architecture questions/improvements | 16 |

### Foundation public-symbol coverage

The exact loader-contract scan covered these 28 symbols:

- ExecAdmissionInitialize, Prepare, Consume, Cancel, and StatusName;
- Execd encode/validate ParseRequest, ParseReply, Cancel, and ErrorName;
- LoadImage Initialize, Release, ClaimRange, CopyIn, CopyOut, ReadLe, WriteLe,
  Seal, PlanBytes, BackingQuery, MapInto, Inspect, and StatusName;
- LoadPlanValidateV1, LoadPlanRegionAt, and LoadPlanValidationErrorName.

The service-manager scan covered all nine public operations:
ServiceManagerInit, ServiceManagerStartAll, ServiceManagerTick, ServiceStart,
ServiceStop, ServiceRestart, ServiceCount, ServiceStatusAt, and
ServiceManagerSelfTest.

The registry scan covered DoRegistry, ReleaseHandleForCurrentProcess,
RegistrySelfTest, RegistryHiveLoad, RegistryHiveSave, RegistryHiveSelfTest,
RegistryQuery, SidecarSnapshotAt, SidecarRestoreOne, and SidecarReset.

The socket destination table covers allocation/ref/owner cleanup, operation
pins and state probes, bind/connect/listen/accept, datagram and stream I/O,
shutdown/endpoints, UDP dispatch, poll, and stats.

The display map uses functional groups rather than attempting to freeze the
large widget.h surface as a protocol. Before D3, regenerate a declaration-level
inventory and require every public Window/Widget/GUI/GDI function to have one
of: displayd method, temporary adapter, kernel device residual, or explicit
retirement.

## 18. Source-only completion and next executable step

This map is complete when:

- this file is the only lane-owned change;
- whitespace/static document checks are clean;
- all required concern rows above are present;
- the active-claim barrier is current enough to prevent conflicting edits;
- the handoff clearly states that no build/test/live verification occurred.

The next executable step after HARD STOP clears is not “start displayd.” It is
Foundation F0: reconcile the active foundation claims, register their tests,
integrate ServiceTransition at the real scheduler lock, and prove an
authenticated ServiceEndpoint transaction. Only then should serviced be
implemented or published.
