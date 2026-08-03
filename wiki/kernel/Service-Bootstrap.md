# Service Bootstrap Package

> **Audience:** Kernel, loader, and service-lifecycle maintainers
> **Execution context:** unpublished boot task
> **Maturity:** authority-bound package with live staging, activation, and
> endpoint-readiness gates; boot activates services in topological order via
> `ServiceBootstrapLiveActivateAllV1` with real MARK_READY handshake

## Purpose

The boot service package is the trust seam between build-owned service
artifacts and future user-mode service activation. It does not reopen paths from
the manifest and it does not treat a manifest hash, transfer reference, or
`LoadPlan` handle as authority.

The build produces one immutable `ServiceObjectPackageDefinitionV1` containing
the canonical manifest, a separately configured and authenticated authority
snapshot, and the exact sealed ELF extents. A production wrapper,
`ServiceBootstrapStageGeneratedV1`, consumes that definition through the same
general `ServiceBootstrapStageInitializeV1` entry point used by hosted tests.
`BootBringupDevices` invokes it once after the frame allocator, C++ initializers,
and managed paging are online. A fixed boot-global owner retains the sealed
stage and opens `ServiceRuntimeV1` before the compatibility service manager is
initialized. This is a real live boot anchor, but it deliberately stops before
process creation, endpoint publication, or readiness.

```text
authenticated kernel-image policy
              +
canonical manifest + exact embedded ELF extents
              |
              v
ServiceObjectPackageInitializeV1
              |
              v
exact (service identity, transfer ref) resolution
              |
              v
boot-private typed backing identity (SV:registry:index)
              |
              v
ElfLoadImagePrepare -> sealed LoadImage/LoadPlan
              |
              v
ExecAdmission copy + consume against exact registry row
              |
              v
LIVE BOOT: SEALED STAGING + STATIC RUNTIME OWNER
              |
              v
exact stage receipt + dependency-aware lifecycle reserve
              |
              v
private AS + 64 KiB stack reservation + signed resource ceilings
              |
              v
LoadImageMapInto + private Process/Task construction
              |
              v
lifecycle commit inside scheduler publication lock
              |
              v
COMPILED/DORMANT, PUBLICATION-ONLY ACTIVATION SEAM
              |
              v
fixed-storage ServiceEndpoint pair + invisible handle reservations
              |
              v
COMPILED/DORMANT, AUTHENTICATED DIRECTORY-PUBLICATION SEAM
```

## Ownership and identity

The staging runtime owns no dynamic allocation. A future boot owner must supply
one manifest-row-indexed slot per service containing a zeroed `LoadImage`,
page/region/plan storage, a zeroed `ExecAdmission`, and admission storage. Frame
hooks transfer each authorized frame into the `LoadImage`; no frame reaches an
address space during staging.

Memory-object handles are minted inside the runtime registry. The high 16 bits
are the private `SV` type tag, the next 40 bits are a globally non-wrapping
runtime-registry identity, and the low 8 bits are the canonical manifest index
plus one. The row index is stable because service manifest rows are
identity-sorted; the registry identity prevents a stale handle from an earlier
or simultaneously live runtime from resolving against an otherwise-identical
row. Admission uses a scoped backing callback that accepts only the current
row's exact handle. The public registry query additionally rejects wrong-type,
unknown, cross-runtime, and corrupt rows before delegating to
`LoadImageBackingQuery`, which re-hashes live sealed frames.

No plan-authored handle is registered. The handle is installed in the
`ElfLoadImageRequest` before the loader emits the plan, and admission compares
the plan to the independently retained row and source hash.

## Failure and budget contract

All output ranges are preflighted before a frame hook runs. Slots may not alias
the runtime, the slot descriptors, manifest/authority inputs, embedded ELF
bytes, or another slot. A later parser, allocation, budget, or admission
failure releases every package-owned frame staged earlier in dependency order,
clears the loader/admission objects, removes retained package authority from
the failed runtime, and publishes no backing identity.

A per-row decorator checks the independently authorized frame budget before it
calls the underlying allocator. Once the authorized count is reached, the next
request is refused without acquiring a frame, the result remains
`ResourceBudgetExceeded`, and ordinary `LoadImage` unwind releases every prior
allocation through the original release hook. The staged present-page count is
also checked afterward as a corruption defense. Other requested authority
(capabilities, tick budget, section ceilings, and resource profile) is merely
retained at this point; it must be installed by the later unpublished-process
transaction before mapping or publication.

The underlying frame-hook callbacks and context are borrowed and retained by
the staging runtime. They must outlive it and remain callable through discard
or a later ownership-transfer unwind.

## One-shot activation transaction

Every row starts `Staged`. `ServiceBootstrapStageBeginActivationV1` mints an
exact receipt bound to the runtime registry identity, manifest row, service
identity, typed memory object, and a non-wrapping activation generation. The
row becomes `Activating`. Cancellation is accepted only while the image is
still sealed and package-owned; a retry receives a fresh generation. Once
`LoadImageMapInto` starts consuming ownership, the attempt must finish as
either `TransferredPublished` or `ConsumedFailed`. Both are terminal and stale
or replayed receipts fail closed.

`ServiceBootstrapActivateV1` is the activation consumer. Before it owns
anything, it revalidates the retained package, matches the broker's manifest
identity, authority identity, hash, extent, service/dependency counts, resolves
the exact service/transfer-reference pair again, and accepts only native or
broker services using the authenticated-service resource profile. It then:

1. reserves the lifecycle start only if every manifest dependency is `Running`,
   with dependency inspection and the selected transition under one broker
   lock;
2. creates a resource domain with the exact nonzero signed Section limits,
   never the profile maxima implicitly;
3. creates a private address space under the signed frame budget;
4. reserves the fixed 64 KiB main stack plus its guard window, commits the top
   two pages as user RW+NX, and selects initial `rsp = top - 8`;
5. transfers image frames with `LoadImageMapInto`, translating each plan
   protection to user PTE flags and exact-unmapping the expected frame during
   rollback;
6. creates a private Process with the manifest capabilities, capability
   ceiling, tick budget, trusted namespace root, and bounded resource domain;
7. attaches the exact stack reservation to the private Task; and
8. commits the broker's exact `ProcessKey` from the Process publication gate
   while the scheduler publication lock is held.

Every failure before image mapping destroys private stack/AS/domain state,
records the exact lifecycle spawn failure, and cancels the sealed stage receipt.
After mapping consumes the image, teardown destroys the unpublished AddressSpace
or Process to reclaim target-owned frames; it never calls `LoadImageRelease` on
those frames. Rollback failure is handled the same way, so residual mappings are
recovered by private address-space destruction before the stage becomes
`ConsumedFailed`. The publication-gate and Task-prepare contexts are stack-local
because `SchedCreateUserPrepared` consumes both synchronously.

## Authenticated endpoint-publication substrate

`ServiceEndpointOwner` is fixed, bounded kernel storage. Each live slot embeds
one `ChannelCore` and the paired initiator/acceptor `ServiceEndpoint` KObjects;
the exact identity is the non-wrapping slot generation, `ChannelEpoch`, and
role. Protocol authority plus the opposite peer's exact `ProcessKey` and
credential snapshot are copied by value into each endpoint. A caller cannot
borrow a `KMessagePort` direction or reserve a request from the object alone:
`ServiceEndpointAcquireOperation` retains the endpoint and pins the exact core
generation, and `ServiceEndpointReleaseOperation` drops those pins without
initiating close.

The first endpoint close, explicit outer-owner release, unregister, or exact
owner-crash notification starts one shared drain. New operations then fail
closed, existing pinned operations may finish, request cleanup is validated in
full before callbacks run, and resource/KObject cleanup occurs outside owner
and core locks. Slot reuse waits for the outer receipt, both endpoint
references, request cleanup, detached resource cleanup, and all core operation
pins to quiesce.

`ServiceDirectoryConnect` first reserves an invisible client handle, constructs
the pair privately, and enqueues an accept record as
`PendingClientPublish`. Only successful client-handle publication and one-shot
endpoint activation can make it `Ready`; every other path aborts or detaches
the exact handle and drains the private ownership graph. Accept similarly
reserves the server handle before moving a ready record into exact
`Publishing`/`Published` accepted ownership. Its explicit
`ServiceDirectoryReleaseAcceptedChannel` hook is replay-safe and callback
re-entry-safe. Unregister and owner crash detach both queued and accepted
ownership under the directory lock, then revoke/drain all channels outside it.

This substrate is deliberately not a send/receive/wait syscall implementation.
The future ingress adapter must resolve a retained `ServiceEndpoint` handle,
acquire an endpoint operation, borrow only the role-correct direction for the
duration of the `KMessagePort` call, and release the operation afterward. No
live boot path publishes an endpoint today; the live anchor stops after package
staging and static runtime initialization.

`ServiceRuntimeV1` now provides the one fixed-lifetime owner that composes the
borrowed staged package with an embedded lifecycle broker, exit observer,
endpoint owner, and directory. Its boot-only initialization first validates a
complete Ready stage and authenticated manifest view, then initializes each
component in dependency order. The production global exit route is installed
last, and the singleton is not observable until a release-store publishes the
whole owner Open. A partial failure is terminal and unpublished; component
storage is never reset or reused in place.

Runtime inspection revalidates the service count, manifest identity, authority
identity, and nonzero stage-registry identity across the independently owned
stage and broker before returning diagnostics. The owner does not itself start
a process, mint a bootstrap handle, parse a request, or publish directory
readiness. Those remain explicit authenticated activation and ingress steps.

## How the readiness markers become true

The generated header truthfully reports:

- `ArtifactsResolved = true`
- `AuthorityBound = true`
- `BootstrapPlansBound = true`
- `ProcessPublicationBound = true`
- `EndpointReadinessBound = true`
- `ActivationReady = true`

The generator now emits one canonical ELF `LoadPlan` template per service with
zeroed memory-object relocation slots, and the package binds the service hash,
transfer-reference hash, and plan hash together. Live staging must reproduce
the runtime `ElfLoadImagePrepare` result byte-for-byte against that bound
template, excepting only the exact fresh typed object-handle slots minted at
boot — a broader comparison exception would defeat the binding, so
`BootstrapPlansBound = true` is a checked promise, not an aspiration.
`ActivationReady` is the conjunction of artifacts, authority, plans, process
publication, and endpoint readiness. Process publication is bound via
`CommitLifecyclePublication` in the scheduler's first-Task gate, and endpoint
readiness is bound via the `MARK_READY` syscall op (a two-step
DESCRIBE_SELF / MARK_READY handshake) in each service binary's post-init path.
`ServiceBootstrapLiveActivateAllV1` activates each service in topological
(manifest) order, polling for dependency readiness between tiers.

## Verification

`test_service_bootstrap_stage` exercises the production package, staging,
`LoadImage`, `LoadPlan`, and `ExecAdmission` state machines with deterministic
frame hooks. It covers typed distinct identities, exact backing queries,
cross-slot alias rejection, unsupported kinds, later-service unwind, manifest
frame-budget enforcement, artifact mutation, corruption detection, and safe
discard. `test-service-bootstrap-stage-contract.py` keeps the generated wrapper,
false readiness markers, build dependencies, and no-publication boundary from
silently drifting.

`test_service_bootstrap_activation` runs the production stage, manifest,
lifecycle, load-image, and resource-domain state machines around a fault-injected
MM/Process/scheduler boundary. It covers dependency refusal, reversible pre-map
unwind, successful-transfer Process failure, rollback failure with residual
target ownership, cancellation at the publication gate, exact resource limits,
stack-before-gate preparation, and successful lifecycle/stage publication.
`test-service-bootstrap-activation-contract.py` freezes the production API
ordering, scheduler gate, exact unmap, private-graph rollback, and dormant
readiness boundary.

`test_service_endpoint` covers private publication refusal, exact activation
and owner replay, protocol/peer snapshots, role-correct direction leases,
normal-operation release, request cleanup re-entry, independent endpoint
close, slot-generation reuse, and close-vs-acquire stress.
`test_service_directory` uses the production handle table to cover client and
server handle exhaustion, queue exhaustion, accepted-owner release, queued and
accepted owner-crash revocation, and deterministic close-vs-connect/accept
publication races. `test-service-endpoint-contract.py` freezes the fixed
storage, pin-before-borrow, failure-atomic publication, and dormant-boundary
contracts.

`test-service-runtime-owner-contract.py`, plus strict hosted and freestanding
object compilation, freezes the owner composition, initialization ordering,
terminal-failure rule, global-observer-last publication, and exact cross-owner
identity inspection. It does not claim that the owner has run in QEMU.

`test-service-bootstrap-live-contract.py` freezes the fixed-capacity live
storage, frame-hook ownership, one-shot stage/runtime ordering, failure unwind,
boot-call placement before the compatibility manager, and explicit zero
process/endpoint readiness boundary. A successful compile or hosted test is not
itself evidence that a QEMU boot observed the anchor.

## Source map

| File | Responsibility |
|---|---|
| `kernel/core/service_object_package.{h,cpp}` | Immutable manifest/authority/artifact binding |
| `kernel/core/service_bootstrap_stage.{h,cpp}` | Typed registry, ELF staging, admission, failure unwind |
| `kernel/core/service_bootstrap_activation.{h,cpp}` | One-shot private construction and scheduler-gated publication |
| `kernel/core/service_bootstrap_live.{h,cpp}` | One-shot live boot staging anchor and fixed runtime lifetime |
| `kernel/core/service_lifecycle_broker.{h,cpp}` | Atomic dependency admission and exact lifecycle publication |
| `kernel/core/service_endpoint.{h,cpp}` | Fixed authenticated endpoint ownership, pinning, and shared drain |
| `kernel/core/service_directory.{h,cpp}` | Failure-atomic connect/accept handle publication and crash revocation |
| `kernel/core/service_runtime.{h,cpp}` | One-shot static owner and exact cross-component inspection |
| `kernel/proc/resource_domain.{h,cpp}` | Exact authenticated-service Section ceilings |
| `kernel/loader/elf_load_image.{h,cpp}` | Production ELF-to-`LoadImage` adapter |
| `kernel/loader/exec_admission.{h,cpp}` | Frozen plan ingress and validation |
| `config/service-authority.toml` | Independent build-owned authority policy |
| `config/services.toml` | Service requests and dependency graph |
