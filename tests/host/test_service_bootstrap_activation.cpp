// Hosted failure-atomicity coverage for the dormant authenticated service
// activation transaction. Kernel authority/state machines are real; only the
// MM/Process/scheduler boundary is fault-injected.

#include "crypto_host_shims.h"
#include "host_test_helper.h"

#include "core/service_bootstrap_activation.h"
#include "crypto/sha256.h"

#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>

namespace parser_fixture
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::core::ElfSegment;
using duetos::core::ElfStatus;

inline std::array<ElfSegment, 4> segments{};
inline u32 segment_count = 0;
inline u64 entry_point = 0x400080;

void Reset()
{
    segments = {};
    segment_count = 0;
    entry_point = 0x400080;
}

void AddSegment(u64 file_offset, u64 virtual_address, u64 file_size, u64 memory_size, u8 flags)
{
    segments[segment_count++] = ElfSegment{file_offset, virtual_address, file_size, memory_size, 4096, flags, {}};
}

void AddSingleRxSegment()
{
    AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
}

void AddTwoRxSegments()
{
    AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
    AddSegment(128, 0x402000, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
}

} // namespace parser_fixture

namespace duetos::core
{

ElfStatus ElfValidate(const u8*, u64)
{
    return ElfStatus::Ok;
}

u64 ElfEntry(const u8*)
{
    return parser_fixture::entry_point;
}

u32 ElfForEachPtLoad(const u8*, u64, ElfSegmentCb callback, void* cookie)
{
    for (u32 index = 0; callback != nullptr && index < parser_fixture::segment_count; ++index)
        callback(parser_fixture::segments[index], cookie);
    return parser_fixture::segment_count;
}

const char* ElfStatusName(ElfStatus)
{
    return "fake";
}

void ElfProgramHeaderInfo(const u8*, u64*, u16*, u16*) {}

} // namespace duetos::core

namespace
{

std::mutex g_host_spinlock;
std::mutex g_host_object_lock;

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock&)
{
    g_host_spinlock.lock();
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock&, IrqFlags)
{
    g_host_spinlock.unlock();
}

} // namespace duetos::sync

// Keep this transaction test focused on the real ServiceEndpoint owner and
// ServiceDirectory state machines.  ChannelCore's port/transfer dependencies
// are the same bounded hosted doubles used by the dedicated directory tests;
// no endpoint is opened by this activation slice.
namespace duetos::ipc
{

namespace
{

void DestroyHostedPort(KObject* object)
{
    delete reinterpret_cast<KMessagePort*>(object);
}

} // namespace

void KObjectInit(KObject* object, KObjectType type, KObjectDestroyFn destroy)
{
    object->type = type;
    object->refcount = 1;
    object->destroy = destroy;
}

bool KObjectAcquire(KObject* object)
{
    if (object == nullptr)
        return false;
    std::lock_guard<std::mutex> guard(g_host_object_lock);
    if (object->refcount == 0 || object->refcount == static_cast<u32>(-1))
        return false;
    ++object->refcount;
    return true;
}

void KObjectRelease(KObject* object)
{
    if (object == nullptr)
        return;
    KObjectDestroyFn destroy = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_host_object_lock);
        if (object->refcount == 0)
            return;
        --object->refcount;
        if (object->refcount == 0)
            destroy = object->destroy;
    }
    if (destroy != nullptr)
        destroy(object);
}

u32 KObjectRefcount(const KObject* object)
{
    if (object == nullptr)
        return 0;
    std::lock_guard<std::mutex> guard(g_host_object_lock);
    return object->refcount;
}

::duetos::core::Result<KMessagePort*> KMessagePortCreate()
{
    auto* port = new (std::nothrow) KMessagePort{};
    if (port == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    KObjectInit(&port->base, KObjectType::MessagePort, &DestroyHostedPort);
    return port;
}

void KMessagePortClose(KMessagePort* port)
{
    if (port == nullptr)
        return;
    std::lock_guard<std::mutex> guard(port->inner);
    port->closed = true;
}

ObjectTransferStatus ObjectTransferTableInitialize(ObjectTransferTable* table, u32 first_generation)
{
    if (table == nullptr || first_generation == 0 || first_generation > kObjectTransferGenerationMax)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 0)
        return ObjectTransferStatus::AlreadyInitialized;
    table->initialized = 1;
    table->state = ObjectTransferTableState::Open;
    return ObjectTransferStatus::Ok;
}

ObjectTransferStatus ObjectTransferTableClose(ObjectTransferTable* table)
{
    if (table == nullptr)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 1)
        return ObjectTransferStatus::NotInitialized;
    table->state = ObjectTransferTableState::Closed;
    return ObjectTransferStatus::Ok;
}

} // namespace duetos::ipc

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::core;
using namespace duetos::loader;
namespace mm = duetos::mm;
namespace sched = duetos::sched;

constexpr u32 kPageCapacity = 4;
constexpr u32 kRegionCapacity = 4;
constexpr u32 kFrameCapacity = 8;

ServiceEndpointCredentialSnapshot FakeServiceCredential()
{
    CredentialSecurityContext security{};
    security.real_uid = 100;
    security.effective_uid = 100;
    security.saved_uid = 100;
    security.fs_uid = 100;
    security.real_gid = 100;
    security.effective_gid = 100;
    security.saved_gid = 100;
    security.fs_gid = 100;
    security.win32_integrity = Win32IntegrityLevel::Low;
    EXPECT_TRUE(CredentialSecurityContextIsCanonical(security));
    return ServiceEndpointCredentialSnapshot{CredentialKey{1, 1}, security};
}

struct FakeFrame
{
    LoadImageFrame identity;
    std::array<u8, kLoadPlanPageSize> bytes;
    bool live;
};

struct FakeArena
{
    std::array<FakeFrame, kFrameCapacity> frames{};
    u32 count = 0;
    u32 live = 0;
    u32 releases = 0;
};

bool AllocateImageFrame(void* raw_context, LoadImageFrame* frame_out, u8** bytes_out)
{
    auto& arena = *static_cast<FakeArena*>(raw_context);
    if (arena.count >= arena.frames.size())
        return false;
    FakeFrame& frame = arena.frames[arena.count];
    ++arena.count;
    frame = FakeFrame{arena.count, {}, true};
    ++arena.live;
    *frame_out = frame.identity;
    *bytes_out = frame.bytes.data();
    return true;
}

void ReleaseImageFrame(void* raw_context, LoadImageFrame identity)
{
    auto& arena = *static_cast<FakeArena*>(raw_context);
    EXPECT_TRUE(identity != 0 && identity <= arena.count);
    if (identity == 0 || identity > arena.count)
        return;
    FakeFrame& frame = arena.frames[static_cast<u32>(identity - 1)];
    EXPECT_TRUE(frame.live);
    if (!frame.live)
        return;
    frame.live = false;
    --arena.live;
    ++arena.releases;
}

struct SlotFixture
{
    FakeArena arena{};
    LoadImage image{};
    std::array<LoadImagePage, kPageCapacity> pages{};
    std::array<LoadImageRegionAuthority, kRegionCapacity> regions{};
    std::array<u8, kLoadImageMaxPlanBytes> plan{};
    ExecAdmission admission{};
    std::array<u8, kExecAdmissionMaxPlanBytes> admission_storage{};

    ServiceBootstrapSlotStorageV1 Storage()
    {
        return ServiceBootstrapSlotStorageV1{
            &image,
            LoadImageFrameHooks{&arena, &AllocateImageFrame, &ReleaseImageFrame},
            pages.data(),
            static_cast<u32>(pages.size()),
            regions.data(),
            static_cast<u32>(regions.size()),
            plan.data(),
            static_cast<u32>(plan.size()),
            &admission,
            admission_storage.data(),
            static_cast<u32>(admission_storage.size()),
            0,
        };
    }
};

void SetText(u8* destination, u32 capacity, u8* length_out, const char* text)
{
    const u32 length = static_cast<u32>(std::strlen(text));
    EXPECT_TRUE(length <= capacity);
    for (u32 index = 0; index < capacity; ++index)
        destination[index] = index < length ? static_cast<u8>(text[index]) : 0;
    *length_out = static_cast<u8>(length);
}

ServiceManifestServiceV1 MakeService(u64 identity, u32 transfer_ref, ServiceManifestKind kind, const char* name,
                                     const char* path, const u8* bytes, u32 byte_count)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = 1;
    duetos::crypto::Sha256Hash(bytes, byte_count, service.executable_content_hash.bytes);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 8;
    service.requested_tick_budget = 10000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 64;
    service.kind = kind;
    service.restart_policy = ServiceManifestRestartPolicy::Always;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, name);
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length, path);
    return service;
}

ServiceManifestAuthoritySnapshotV1 MakeAuthority(const ServiceManifestDocumentV1& document, const u8* bytes,
                                                 u32 byte_count)
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    authority.authority_identity = 0x4455455441555448ULL;
    authority.manifest_identity = document.manifest_identity;
    authority.signer_identity = document.signer_identity;
    authority.profile_identity = document.profile_identity;
    duetos::crypto::Sha256Hash(bytes, byte_count, authority.sealed_object_hash.bytes);
    authority.sealed_object_extent = byte_count;
    authority.allowed_capabilities = kServiceManifestCapabilityMaskV1;
    authority.allowed_immutable_policies = 1ULL << 1;
    authority.maximum_frame_budget_pages = kServiceManifestFrameBudgetMaximum;
    authority.maximum_tick_budget = kServiceManifestTickBudgetMaximum;
    authority.allowed_service_kinds = kServiceManifestKnownKindMask;
    authority.allowed_resource_profiles = kServiceManifestKnownResourceProfileMask;
    authority.maximum_section_objects = kServiceManifestSectionObjectMaximum;
    authority.maximum_section_pages = kServiceManifestSectionPageMaximum;
    authority.maximum_services = static_cast<u16>(kServiceManifestMaximumServices);
    authority.maximum_dependencies = static_cast<u16>(kServiceManifestMaximumDependencies);
    authority.flags = kServiceManifestAuthoritySealed;
    return authority;
}

struct PackageFixture
{
    std::array<u8, 512> serviced_bytes{};
    std::array<u8, 512> execd_bytes{};
    ServiceManifestDocumentV1 document{};
    std::array<u8, kServiceManifestMaximumBytes> manifest_bytes{};
    u32 manifest_byte_count = 0;
    ServiceManifestAuthoritySnapshotV1 authority{};
    std::array<ServiceExecutableObjectDefinitionV1, 2> objects{};
    ServiceObjectPackageDefinitionV1 definition{};

    PackageFixture()
    {
        for (u32 index = 0; index < serviced_bytes.size(); ++index)
        {
            serviced_bytes[index] = static_cast<u8>((index * 17u + 3u) & 0xFFu);
            execd_bytes[index] = static_cast<u8>((index * 29u + 11u) & 0xFFu);
        }
        document.manifest_identity = 0x445545544D414E31ULL;
        document.signer_identity = 0x445545544255494CULL;
        document.profile_identity = 0x4455455453564331ULL;
        document.service_count = 2;
        document.dependency_count = 1;
        document.services[0] = MakeService(0x100, 1, ServiceManifestKind::Broker, "serviced", "/system/serviced",
                                           serviced_bytes.data(), static_cast<u32>(serviced_bytes.size()));
        document.services[1] = MakeService(0x200, 2, ServiceManifestKind::Native, "execd", "/system/execd",
                                           execd_bytes.data(), static_cast<u32>(execd_bytes.size()));
        document.services[1].dependency_first = 0;
        document.services[1].dependency_count = 1;
        document.dependencies[0] = ServiceManifestDependencyV1{0x200, 0x100};
        Refresh();
    }

    void Refresh()
    {
        manifest_bytes = {};
        const ServiceManifestEncodeResult encoded =
            ServiceManifestEncodeV1(manifest_bytes.data(), manifest_bytes.size(), document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        manifest_byte_count = encoded.bytes_written;
        authority = MakeAuthority(document, manifest_bytes.data(), manifest_byte_count);
        objects[0] = ServiceExecutableObjectDefinitionV1{
            1, 1, serviced_bytes.data(), serviced_bytes.size(), kServiceObjectDefinitionSealed, 0};
        objects[1] = ServiceExecutableObjectDefinitionV1{
            2, 1, execd_bytes.data(), execd_bytes.size(), kServiceObjectDefinitionSealed, 0};
        definition = ServiceObjectPackageDefinitionV1{manifest_bytes.data(),
                                                      manifest_byte_count,
                                                      &authority,
                                                      objects.data(),
                                                      static_cast<u32>(objects.size()),
                                                      0};
    }
};

struct StageFixture
{
    PackageFixture package{};
    std::array<SlotFixture, 2> slot_fixtures{};
    std::array<ServiceBootstrapSlotStorageV1, 2> slots{};
    ServiceBootstrapStageRuntimeV1 runtime{};
    // ServiceRuntime owns the fixed-capacity endpoint and directory tables.
    // Keep that production-sized authority root off the host thread's stack.
    std::unique_ptr<ServiceRuntimeV1> service_runtime_storage;
    ServiceRuntimeV1& service_runtime;

    StageFixture()
        : service_runtime_storage(std::make_unique<ServiceRuntimeV1>()), service_runtime(*service_runtime_storage)
    {
        slots[0] = slot_fixtures[0].Storage();
        slots[1] = slot_fixtures[1].Storage();
    }

    void Initialize()
    {
        EXPECT_EQ(ServiceBootstrapStageInitializeV1(&runtime, &package.definition, slots.data(),
                                                    static_cast<u32>(slots.size()))
                      .status,
                  ServiceBootstrapStageStatus::Ok);
        const ServiceRuntimeInitializeResultV1 initialized =
            ServiceRuntimeInitializeForTestV1(&service_runtime, &runtime);
        EXPECT_EQ(initialized.status, ServiceRuntimeStatusV1::Ok);
        EXPECT_EQ(initialized.exit_reap_status, ServiceExitReapStatus::Ok);

        ServiceExitReapLedgerSnapshot ledger{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&service_runtime.exit_reap_ledger, &ledger), ServiceExitReapStatus::Ok);
        EXPECT_EQ(ledger.state, ServiceExitReapLedgerState::Open);
        EXPECT_EQ(ledger.live_rows, 0U);

        ServiceRuntimeActivationAuthorityV1 authority{};
        EXPECT_EQ(ServiceRuntimeBindActivationAuthorityV1(&service_runtime, &authority), ServiceRuntimeStatusV1::Ok);
        EXPECT_TRUE(authority.exit_reap_ledger == &service_runtime.exit_reap_ledger);
    }
};

struct FakeMapping
{
    u64 virtual_address;
    duetos::mm::PhysAddr frame;
    bool image;
    bool live;
};

struct FakeAddressSpace
{
    std::array<FakeMapping, 16> mappings{};
    u32 mapping_count = 0;
    bool live = false;
};

struct FakeProcess
{
    FakeAddressSpace* address_space = nullptr;
    ResourceDomainKey domain = kInvalidResourceDomainKey;
    ProcessPublicationGate gate = nullptr;
    void* gate_context = nullptr;
    bool live = false;
};

struct FakePlatform
{
    FakeAddressSpace address_space{};
    FakeProcess process{};
    FakeArena* image_arena = nullptr;
    ServiceLifecycleBroker* broker = nullptr;
    ServiceExitObserver* exit_observer = nullptr;
    u64 service_identity = 0;
    u64 now_ns = 0;
    u32 next_stack_frame = 0x1000;
    u32 stack_allocations = 0;
    u32 stack_frees = 0;
    u32 zeroed_frames = 0;
    u32 address_space_releases = 0;
    u32 process_releases = 0;
    u32 image_map_attempts = 0;
    u32 image_maps = 0;
    u32 image_unmaps = 0;
    u32 event_counter = 0;
    u32 prepare_event = 0;
    u32 gate_event = 0;
    u32 stack_prepare_calls = 0;
    bool fail_address_space_create = false;
    bool fail_stack_reservation = false;
    bool fail_stack_frame_allocation = false;
    bool fail_stack_map = false;
    bool fail_trusted_root = false;
    bool fail_process_create = false;
    bool fail_process_configuration = false;
    bool fail_process_identity_snapshot = false;
    bool fail_resource_domain_replace = false;
    bool fail_publication_gate_install = false;
    bool fail_task_before_gate = false;
    bool cancel_before_gate = false;
    bool fail_image_second_map = false;
    bool fail_image_rollback = false;
    bool probe_stale_exit = false;
    bool publish_fast_exit = false;
    bool published = false;
    ProcessKey private_process_key{0xABCDEF, 77};
    ProcessKey publication_key{0xABCDEF, 77};
    ServiceEndpointCredentialSnapshot process_credential = FakeServiceCredential();
    u32 fast_exit_code = 0xC0000005U;
    ServiceExitObserverStatus stale_exit_status = ServiceExitObserverStatus::Busy;
    ServiceExitObserverStatus fast_exit_status = ServiceExitObserverStatus::Busy;
    UserStackRange configured_stack{};
    u64 configured_rsp = 0;
    CapSet configured_caps{};
    CapSet configured_ceiling{};
    u64 configured_ticks = 0;
    ResourceDomainKey published_domain = kInvalidResourceDomainKey;

    static FakePlatform& Self(void* context) { return *static_cast<FakePlatform*>(context); }

    static mm::AddressSpace* CreateAddressSpace(void* context, u64 budget)
    {
        auto& self = Self(context);
        EXPECT_EQ(budget, 8ULL);
        if (self.fail_address_space_create)
            return nullptr;
        self.address_space = FakeAddressSpace{};
        self.address_space.live = true;
        return reinterpret_cast<mm::AddressSpace*>(&self.address_space);
    }

    static void ReleaseAddressSpace(void* context, mm::AddressSpace* raw)
    {
        auto& self = Self(context);
        auto* address_space = reinterpret_cast<FakeAddressSpace*>(raw);
        EXPECT_TRUE(address_space == &self.address_space && address_space->live);
        for (auto& mapping : address_space->mappings)
        {
            if (!mapping.live)
                continue;
            if (mapping.image)
                ReleaseImageFrame(self.image_arena, mapping.frame);
            else
                ++self.stack_frees;
            mapping.live = false;
        }
        address_space->live = false;
        ++self.address_space_releases;
    }

    static bool ReserveRange(void* context, mm::AddressSpace* address_space, u64 lo, u64 hi,
                             mm::AddressSpaceReservationToken*)
    {
        auto& self = Self(context);
        EXPECT_TRUE(address_space != nullptr);
        EXPECT_EQ(hi - lo, kUserStackReserveMin + kUserStackGuardPages * mm::kPageSize);
        return !self.fail_stack_reservation;
    }

    static bool AllocateFrame(void* context, mm::PhysAddr* frame_out)
    {
        auto& self = Self(context);
        if (self.fail_stack_frame_allocation)
            return false;
        *frame_out = self.next_stack_frame++;
        ++self.stack_allocations;
        return true;
    }

    static void ZeroFrame(void* context, mm::PhysAddr) { ++Self(context).zeroed_frames; }

    static void FreeFrame(void* context, mm::PhysAddr) { ++Self(context).stack_frees; }

    static bool AddMapping(FakePlatform& self, u64 virtual_address, mm::PhysAddr frame, bool image)
    {
        FakeAddressSpace& address_space = self.address_space;
        if (!address_space.live || address_space.mapping_count >= address_space.mappings.size())
            return false;
        address_space.mappings[address_space.mapping_count++] = FakeMapping{virtual_address, frame, image, true};
        return true;
    }

    static bool MapReserved(void* context, mm::AddressSpace*, const mm::AddressSpaceReservationToken&, u64 va,
                            mm::PhysAddr frame, u64 flags)
    {
        auto& self = Self(context);
        EXPECT_EQ(flags, mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        if (self.fail_stack_map)
            return false;
        return AddMapping(self, va, frame, false);
    }

    static bool MapImage(void* context, mm::AddressSpace*, u64 va, mm::PhysAddr frame, u64 flags)
    {
        auto& self = Self(context);
        ++self.image_map_attempts;
        EXPECT_TRUE((flags & (mm::kPagePresent | mm::kPageUser)) == (mm::kPagePresent | mm::kPageUser));
        EXPECT_TRUE((flags & mm::kPageWritable) == 0);
        EXPECT_TRUE((flags & mm::kPageNoExecute) == 0);
        if (self.fail_image_second_map && self.image_map_attempts == 2)
            return false;
        if (!AddMapping(self, va, frame, true))
            return false;
        ++self.image_maps;
        return true;
    }

    static bool UnmapImage(void* context, mm::AddressSpace*, u64 va, mm::PhysAddr expected)
    {
        auto& self = Self(context);
        if (self.fail_image_rollback)
            return false;
        for (auto& mapping : self.address_space.mappings)
        {
            if (mapping.live && mapping.image && mapping.virtual_address == va && mapping.frame == expected)
            {
                mapping.live = false;
                ReleaseImageFrame(self.image_arena, expected);
                ++self.image_unmaps;
                return true;
            }
        }
        return false;
    }

    static const duetos::fs::RamfsNode* TrustedRoot(void* context)
    {
        return Self(context).fail_trusted_root ? nullptr : reinterpret_cast<const duetos::fs::RamfsNode*>(1);
    }

    static Process* CreateProcess(void* context, const char*, mm::AddressSpace* raw_as, CapSet caps,
                                  const duetos::fs::RamfsNode*, u64 entry, u64 stack_base, u64 ticks, CapSet ceiling)
    {
        auto& self = Self(context);
        EXPECT_EQ(entry, parser_fixture::entry_point);
        EXPECT_EQ(stack_base, kUserStackTopVa - kUserStackCommitMinPages * mm::kPageSize);
        if (self.fail_process_create)
            return nullptr;
        self.process = FakeProcess{};
        self.process.address_space = reinterpret_cast<FakeAddressSpace*>(raw_as);
        self.process.live = true;
        self.configured_caps = caps;
        self.configured_ceiling = ceiling;
        self.configured_ticks = ticks;
        return reinterpret_cast<Process*>(&self.process);
    }

    static void ReleaseProcess(void* context, Process* raw_process)
    {
        auto& self = Self(context);
        auto* process = reinterpret_cast<FakeProcess*>(raw_process);
        EXPECT_TRUE(process == &self.process && process->live);
        if (ResourceDomainKeyIsValid(process->domain))
            EXPECT_TRUE(ResourceDomainRelease(process->domain));
        ReleaseAddressSpace(context, reinterpret_cast<mm::AddressSpace*>(process->address_space));
        process->live = false;
        ++self.process_releases;
    }

    static bool SnapshotProcessIdentity(void* context, Process* raw_process, ProcessKey* process_out,
                                        ServiceEndpointCredentialSnapshot* credential_out)
    {
        auto& self = Self(context);
        auto* process = reinterpret_cast<FakeProcess*>(raw_process);
        if (self.fail_process_identity_snapshot || process_out == nullptr || credential_out == nullptr ||
            process != &self.process || !process->live)
        {
            return false;
        }
        *process_out = self.private_process_key;
        *credential_out = self.process_credential;
        return true;
    }

    static bool ConfigureStack(void* context, Process*, const UserStackRange& stack, u64 rsp)
    {
        auto& self = Self(context);
        if (self.fail_process_configuration)
            return false;
        self.configured_stack = stack;
        self.configured_rsp = rsp;
        return true;
    }

    static bool ReplaceDomain(void* context, Process* raw_process, ResourceDomainKey domain)
    {
        auto& self = Self(context);
        auto* process = reinterpret_cast<FakeProcess*>(raw_process);
        if (self.fail_resource_domain_replace)
            return false;
        if (!ResourceDomainRetain(domain))
            return false;
        process->domain = domain;
        self.published_domain = domain;
        return true;
    }

    static bool InstallGate(void* context, Process* raw_process, ProcessPublicationGate gate, void* gate_context)
    {
        if (Self(context).fail_publication_gate_install)
            return false;
        auto* process = reinterpret_cast<FakeProcess*>(raw_process);
        process->gate = gate;
        process->gate_context = gate_context;
        return true;
    }

    static void PrepareStack(void* context, sched::Task*, const UserStackRange&,
                             const mm::AddressSpaceReservationToken&)
    {
        auto& self = Self(context);
        ++self.stack_prepare_calls;
        self.prepare_event = ++self.event_counter;
    }

    static sched::TaskCreateResult CreateTask(void* context, const char*, Process* raw_process,
                                              sched::TaskPrepareFn prepare, void* prepare_context)
    {
        auto& self = Self(context);
        auto* process = reinterpret_cast<FakeProcess*>(raw_process);
        if (self.fail_task_before_gate)
        {
            ReleaseProcess(context, raw_process);
            return sched::TaskCreateResult{false, 0};
        }
        prepare(reinterpret_cast<sched::Task*>(1), prepare_context);
        if (self.cancel_before_gate)
        {
            const ServiceLifecycleStopResult stop =
                ServiceLifecycleBrokerRequestStop(self.broker, self.service_identity, 1, self.now_ns);
            EXPECT_EQ(stop.status, ServiceLifecycleStatus::StartCancelled);
        }
        self.gate_event = ++self.event_counter;
        const bool admitted = process->gate(self.publication_key, process->gate_context);
        process->gate = nullptr;
        process->gate_context = nullptr;
        if (!admitted)
        {
            ReleaseProcess(context, raw_process);
            return sched::TaskCreateResult{false, 0};
        }
        self.published = true;
        if (self.probe_stale_exit)
        {
            self.stale_exit_status = ServiceExitObserverPublishExit(
                self.exit_observer, ProcessKey{self.publication_key.identity + 1, self.publication_key.pid},
                self.fast_exit_code);
        }
        if (self.publish_fast_exit)
        {
            self.fast_exit_status =
                ServiceExitObserverPublishExit(self.exit_observer, self.publication_key, self.fast_exit_code);
        }
        return sched::TaskCreateResult{true, 700};
    }

    ServiceBootstrapActivationPlatformV1 Interface()
    {
        return ServiceBootstrapActivationPlatformV1{
            this,
            &CreateAddressSpace,
            &ReleaseAddressSpace,
            &ReserveRange,
            &AllocateFrame,
            &ZeroFrame,
            &FreeFrame,
            &MapReserved,
            &MapImage,
            &UnmapImage,
            &TrustedRoot,
            &CreateProcess,
            &ReleaseProcess,
            &SnapshotProcessIdentity,
            &ConfigureStack,
            &ReplaceDomain,
            &InstallGate,
            &PrepareStack,
            &CreateTask,
        };
    }

    void ReapPublished()
    {
        EXPECT_TRUE(published && process.live);
        ReleaseProcess(this, reinterpret_cast<Process*>(&process));
        published = false;
    }
};

ServiceBootstrapActivationRequestV1 Request(StageFixture& fixture, u64 identity, u64 generation, u64 now_ns)
{
    return ServiceBootstrapActivationRequestV1{
        kServiceBootstrapActivationVersion1, 0, &fixture.service_runtime, identity, generation, now_ns};
}

ServiceLifecycleSnapshot InspectLifecycle(ServiceLifecycleBroker& broker, u64 identity)
{
    const ServiceLifecycleInspectResult result = ServiceLifecycleBrokerInspect(&broker, identity);
    EXPECT_EQ(result.status, ServiceLifecycleStatus::Ok);
    return result.snapshot;
}

ServiceExitObserverSnapshot InspectObserver(ServiceExitObserver& observer)
{
    ServiceExitObserverSnapshot snapshot{};
    EXPECT_EQ(ServiceExitObserverInspect(&observer, &snapshot), ServiceExitObserverStatus::Ok);
    return snapshot;
}

void ExpectObserverEmpty(ServiceExitObserver& observer, u64 expected_event_sequence = 1)
{
    const ServiceExitObserverSnapshot snapshot = InspectObserver(observer);
    EXPECT_EQ(snapshot.active_count, 0U);
    EXPECT_EQ(snapshot.pending_count, 0U);
    EXPECT_EQ(snapshot.event_sequence, expected_event_sequence);
    EXPECT_EQ(ServiceExitObserverDequeue(&observer).status, ServiceExitObserverStatus::NoEvent);
}

void ExpectDirectoryUnpublished(const ServiceDirectory& directory)
{
    for (const ServiceDirectoryRow& row : directory.rows)
    {
        EXPECT_TRUE(row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired);
    }
}

} // namespace

int main()
{
    // Dependency refusal is reversible: no VM/process work begins, the stage
    // returns to Staged with a consumed receipt generation, and the broker row
    // is byte-for-byte unstarted.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        const ServiceRuntimeDeferAcceptedProcessResultV1 empty_teardown =
            ServiceRuntimeDeferAcceptedProcessForTestV1(&fixture.service_runtime, ProcessKey{0xF001, 901});
        EXPECT_EQ(empty_teardown.runtime_status, ServiceRuntimeStatusV1::Ok);
        EXPECT_EQ(empty_teardown.directory_status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(empty_teardown.newly_deferred_channels, 0U);
        EXPECT_EQ(empty_teardown.deferred_channels, 0U);
        const ServiceRuntimeDriveDeferredAcceptedResultV1 empty_maintenance =
            ServiceRuntimeDriveDeferredAcceptedForTestV1(&fixture.service_runtime);
        EXPECT_EQ(empty_maintenance.runtime_status, ServiceRuntimeStatusV1::Ok);
        EXPECT_EQ(empty_maintenance.directory_status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(empty_maintenance.endpoint_status, ServiceEndpointStatus::Ok);
        EXPECT_EQ(empty_maintenance.released_channels, 0U);
        EXPECT_EQ(empty_maintenance.pending_channels, 0U);
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[1].arena;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x200, 0, 10), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::LifecycleReserveRejected);
        EXPECT_EQ(result.lifecycle_status, ServiceLifecycleStatus::DependencyNotReady);
        EXPECT_EQ(fake.stack_allocations, 0U);
        ServiceBootstrapServiceSnapshotV1 staged{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x200, &staged),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(staged.activation_state, ServiceBootstrapActivationStateV1::Staged);
        EXPECT_EQ(staged.activation_generation, 1ULL);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x200);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Stopped);
        EXPECT_EQ(lifecycle.transition_generation, 0ULL);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // The request accepts only the one runtime authority root; a caller cannot
    // substitute a peer stage, broker, observer, or directory.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        auto platform = fake.Interface();
        ServiceBootstrapActivationRequestV1 request = Request(fixture, 0x100, 0, 15);
        request.runtime = nullptr;
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(request, &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::NullArgument);
        EXPECT_EQ(fake.stack_allocations, 0U);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Stopped);
        EXPECT_EQ(lifecycle.spawn_failures, 0U);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Failure before image consumption releases stack/AS/domain, records the
    // exact lifecycle spawn failure, and leaves the sealed stage retryable.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.fail_address_space_create = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 20), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::AddressSpaceCreateFailed);
        EXPECT_EQ(result.lifecycle_cleanup_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(fixture.slot_fixtures[0].image.state, LoadImageState::Sealed);
        ServiceBootstrapServiceSnapshotV1 staged{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &staged),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(staged.activation_state, ServiceBootstrapActivationStateV1::Staged);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Failed);
        EXPECT_EQ(lifecycle.transition_generation, 1ULL);
        EXPECT_EQ(lifecycle.spawn_failures, 1U);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Every remaining private-construction rung is independently injectable.
    // Each refusal destroys the whole unpublished graph, aborts any directory
    // reservation reached by that rung, and records exactly one spawn failure.
    {
        struct FailureCase
        {
            ServiceBootstrapActivationStatusV1 expected;
            void (*arm)(FakePlatform&);
        };
        const std::array<FailureCase, 7> cases{{
            {ServiceBootstrapActivationStatusV1::StackReservationFailed,
             +[](FakePlatform& fake) { fake.fail_stack_reservation = true; }},
            {ServiceBootstrapActivationStatusV1::StackFrameAllocationFailed,
             +[](FakePlatform& fake) { fake.fail_stack_frame_allocation = true; }},
            {ServiceBootstrapActivationStatusV1::StackMapFailed,
             +[](FakePlatform& fake) { fake.fail_stack_map = true; }},
            {ServiceBootstrapActivationStatusV1::TrustedRootUnavailable,
             +[](FakePlatform& fake) { fake.fail_trusted_root = true; }},
            {ServiceBootstrapActivationStatusV1::ProcessConfigurationFailed,
             +[](FakePlatform& fake) { fake.fail_process_configuration = true; }},
            {ServiceBootstrapActivationStatusV1::ProcessCredentialSnapshotFailed,
             +[](FakePlatform& fake) { fake.fail_process_identity_snapshot = true; }},
            {ServiceBootstrapActivationStatusV1::ResourceDomainReplaceFailed,
             +[](FakePlatform& fake) { fake.fail_resource_domain_replace = true; }},
        }};
        u64 now_ns = 21;
        for (const FailureCase& failure : cases)
        {
            parser_fixture::Reset();
            parser_fixture::AddSingleRxSegment();
            StageFixture fixture;
            fixture.Initialize();
            FakePlatform fake{};
            fake.image_arena = &fixture.slot_fixtures[0].arena;
            failure.arm(fake);
            auto platform = fake.Interface();
            const ServiceBootstrapActivationResultV1 result =
                ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, now_ns++), &platform);
            EXPECT_EQ(result.status, failure.expected);
            EXPECT_FALSE(result.task.created);
            EXPECT_FALSE(fake.published);
            const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
            EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Failed);
            EXPECT_EQ(lifecycle.spawn_failures, 1U);
            EXPECT_EQ(lifecycle.successful_publications, 0U);
            ExpectObserverEmpty(fixture.service_runtime.exit_observer);
            ExpectDirectoryUnpublished(fixture.service_runtime.directory);
        }
    }

    // Exhausting the fixed resource-domain pool fails before any address-space
    // construction and releases no authority owned by another row.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        std::array<ResourceDomainKey, kResourceDomainCapacity> occupied{};
        u32 occupied_count = 0;
        while (occupied_count < occupied.size() && ResourceDomainCreateAuthenticatedService(&occupied[occupied_count]))
            ++occupied_count;
        EXPECT_EQ(occupied_count, kResourceDomainCapacity);
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 29), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::ResourceDomainCreateFailed);
        EXPECT_EQ(fake.address_space_releases, 0U);
        for (u32 index = 0; index < occupied_count; ++index)
            EXPECT_TRUE(ResourceDomainRelease(occupied[index]));
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
    }

    // A transferred image is reclaimed by destroying the unpublished AS when
    // ProcessCreate fails. LoadImage remains Transferred metadata; activation
    // never calls LoadImageRelease on its target-owned frames.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.fail_process_create = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 30), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::ProcessCreateFailed);
        EXPECT_EQ(result.image_map_result.status, LoadImageStatus::Ok);
        EXPECT_EQ(fixture.slot_fixtures[0].image.state, LoadImageState::Transferred);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0U);
        EXPECT_EQ(fake.address_space_releases, 1U);
        EXPECT_EQ(fake.stack_frees, kUserStackCommitMinPages);
        ServiceBootstrapServiceSnapshotV1 staged{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &staged),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(staged.activation_state, ServiceBootstrapActivationStateV1::ConsumedFailed);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Exact rollback failure deliberately leaves the first image frame mapped;
    // private AS destruction then recovers that residual target owner while
    // LoadImage releases the still-package-owned second frame.
    {
        parser_fixture::Reset();
        parser_fixture::AddTwoRxSegments();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.fail_image_second_map = true;
        fake.fail_image_rollback = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 40), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::ImageMapFailed);
        EXPECT_EQ(result.image_map_result.status, LoadImageStatus::RollbackFailed);
        EXPECT_EQ(result.image_map_result.rollback_failures, 1U);
        EXPECT_EQ(fake.image_maps, 1U);
        EXPECT_EQ(fake.image_unmaps, 0U);
        EXPECT_EQ(fake.address_space_releases, 1U);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0U);
        EXPECT_EQ(fixture.slot_fixtures[0].image.state, LoadImageState::Failed);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Fixed observer capacity refusal is an ordinary pre-VM failure on the
    // exact runtime-owned observer; no mixable replacement observer exists.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        for (u32 slot = 0; slot < kServiceExitObserverCapacity; ++slot)
        {
            EXPECT_TRUE(ServiceExitObserverHostSetSlotGenerationForTest(&fixture.service_runtime.exit_observer, slot,
                                                                        kServiceExitObserverGenerationMaximum));
        }
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 43), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::ExitObserverReserveRejected);
        EXPECT_EQ(result.exit_observer_status, ServiceExitObserverStatus::CapacityExhausted);
        EXPECT_EQ(fake.stack_allocations, 0U);
        EXPECT_EQ(InspectLifecycle(fixture.service_runtime.lifecycle, 0x100).phase, ServiceTransitionPhase::Failed);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
    }

    // A name conflict at directory reservation occurs after the private
    // Process identity is fixed but before the publication gate is installed.
    // Only the pre-existing private row survives until its owner aborts it.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        ServiceDirectoryName occupied_name{};
        const ServiceManifestServiceV1& service = fixture.package.document.services[0];
        occupied_name.length = service.name_length;
        for (u32 index = 0; index < service.name_length; ++index)
            occupied_name.bytes[index] = service.name[index];
        const ServiceInstanceToken occupied_owner{ServiceStartTicket{0xF001, 1}, ServiceInstanceKey{0xF002, 902}};
        const ServiceEndpointCredentialSnapshot occupied_credential = FakeServiceCredential();
        ServiceDirectoryReserveResult occupied = ServiceDirectoryReserveRegistration(
            &fixture.service_runtime.directory, &occupied_name, 7, occupied_owner, &occupied_credential);
        EXPECT_EQ(occupied.status, ServiceDirectoryStatus::Ok);

        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 44), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::DirectoryReserveRejected);
        EXPECT_EQ(result.directory_status, ServiceDirectoryStatus::NameConflict);
        EXPECT_FALSE(result.task.created);
        EXPECT_EQ(ServiceDirectoryAbortRegistration(&fixture.service_runtime.directory, &occupied.reservation,
                                                    occupied_owner),
                  ServiceDirectoryStatus::Ok);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Gate installation refusal happens only after the exact directory row is
    // reserved; outer teardown aborts it along with every private Process edge.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.fail_publication_gate_install = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 44), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::PublicationGateInstallFailed);
        EXPECT_EQ(result.directory_cleanup_status, ServiceDirectoryStatus::Ok);
        EXPECT_FALSE(result.task.created);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Failure before the publication gate consumes the private Process but
    // never binds or emits an observer event; the still-reserved receipt is
    // aborted by the outer transaction.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.fail_task_before_gate = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 45), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::TaskCreateFailed);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(result.lifecycle_cleanup_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(fake.process_releases, 1U);
        EXPECT_FALSE(fake.published);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // The scheduler-provided ProcessKey must equal the immutable key captured
    // from the private Process. A mismatch reaches no observer/lifecycle/
    // directory publication and the invisible registration is aborted.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        ++fake.publication_key.identity;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 46), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::TaskCreateFailed);
        EXPECT_FALSE(result.task.created);
        EXPECT_FALSE(fake.published);
        EXPECT_EQ(InspectLifecycle(fixture.service_runtime.lifecycle, 0x100).phase, ServiceTransitionPhase::Failed);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // A pre-existing exact observer binding for the same ProcessKey forces the
    // gate's observer rung to reject before lifecycle or directory visibility.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        const ServiceLifecycleBrokerInspectResult broker =
            ServiceLifecycleBrokerDescribe(&fixture.service_runtime.lifecycle);
        EXPECT_EQ(broker.status, ServiceLifecycleStatus::Ok);
        const ServiceLifecycleStartTicket foreign_start{broker.snapshot.broker_epoch, ServiceStartTicket{0xF101, 1}};
        ServiceExitReservationResult foreign =
            ServiceExitObserverReserve(&fixture.service_runtime.exit_observer, foreign_start);
        EXPECT_EQ(foreign.status, ServiceExitObserverStatus::Ok);
        const ServiceRegistrationReservation foreign_directory{ServiceKey{kServiceDirectoryCapacity - 1, 1}, 1};
        EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&fixture.service_runtime.exit_observer,
                                                                foreign.registration, fake.publication_key,
                                                                foreign_directory),
                  ServiceExitObserverStatus::Ok);
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 47), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::PublicationRejected);
        EXPECT_EQ(result.exit_observer_status, ServiceExitObserverStatus::DuplicateProcess);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(InspectLifecycle(fixture.service_runtime.lifecycle, 0x100).phase, ServiceTransitionPhase::Failed);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
        EXPECT_EQ(ServiceExitObserverRollbackBound(&fixture.service_runtime.exit_observer, &foreign.registration,
                                                   fake.publication_key),
                  ServiceExitObserverStatus::Ok);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
    }

    // Cancellation racing the publication gate rejects scheduler visibility,
    // destroys the private graph, then acknowledges the exact cancelled start.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.broker = &fixture.service_runtime.lifecycle;
        fake.service_identity = 0x100;
        fake.now_ns = 50;
        fake.cancel_before_gate = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 50), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::PublicationRejected);
        EXPECT_EQ(result.exit_observer_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(result.lifecycle_cleanup_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(fake.process_releases, 1U);
        EXPECT_FALSE(fake.published);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Stopped);
        EXPECT_EQ(lifecycle.builder_state, ServiceLifecycleBuilderState::None);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
    }

    // The directory is the final fallible visibility rung. An injected refusal
    // rolls the exact lifecycle commit back while the broker lock is still
    // held, rolls back the bound observer, rejects Task publication, and lets
    // outer teardown abort the still-invisible directory reservation.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        ServiceDirectoryHostFailNextRegistrationPublicationForTest();
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 55), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::DirectoryPublicationRejected);
        EXPECT_EQ(result.directory_status, ServiceDirectoryStatus::Busy);
        EXPECT_EQ(result.directory_cleanup_status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(result.lifecycle_publication_rollback_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(result.lifecycle_cleanup_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_FALSE(result.task.created);
        EXPECT_FALSE(fake.published);
        EXPECT_EQ(fake.process_releases, 1U);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Failed);
        EXPECT_EQ(lifecycle.builder_state, ServiceLifecycleBuilderState::None);
        EXPECT_EQ(lifecycle.successful_publications, 0U);
        EXPECT_EQ(lifecycle.spawn_failures, 1U);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer);
        ExpectDirectoryUnpublished(fixture.service_runtime.directory);
    }

    // Success binds signed limits to Process/ResourceDomain, prepares the exact
    // owned stack before the publication gate, and terminally publishes both
    // the broker instance and stage receipt.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.Initialize();
        FakePlatform fake{};
        fake.image_arena = &fixture.slot_fixtures[0].arena;
        fake.broker = &fixture.service_runtime.lifecycle;
        fake.exit_observer = &fixture.service_runtime.exit_observer;
        fake.service_identity = 0x100;
        fake.now_ns = 60;
        fake.probe_stale_exit = true;
        fake.publish_fast_exit = true;
        auto platform = fake.Interface();
        const ServiceBootstrapActivationResultV1 result =
            ServiceBootstrapActivateWithPlatformForTestV1(Request(fixture, 0x100, 0, 60), &platform);
        EXPECT_EQ(result.status, ServiceBootstrapActivationStatusV1::Ok);
        EXPECT_TRUE(result.task.created);
        EXPECT_EQ(result.task.tid, 700ULL);
        EXPECT_TRUE(ServiceLifecycleInstanceTokenIsValid(result.instance));
        EXPECT_TRUE(ServiceKeyIsValid(result.directory_service));
        EXPECT_TRUE(fake.published);
        EXPECT_EQ(result.exit_observer_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(result.exit_observer_cleanup_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(fake.stale_exit_status, ServiceExitObserverStatus::NotFound);
        EXPECT_EQ(fake.fast_exit_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(fake.stack_allocations, kUserStackCommitMinPages);
        EXPECT_EQ(fake.zeroed_frames, kUserStackCommitMinPages);
        EXPECT_EQ(fake.stack_prepare_calls, 1U);
        EXPECT_TRUE(fake.prepare_event < fake.gate_event);
        EXPECT_EQ(fake.configured_rsp, kUserStackTopVa - 8);
        EXPECT_EQ(fake.configured_caps.bits, fixture.package.document.services[0].requested_capability_ceiling);
        EXPECT_EQ(fake.configured_ceiling.bits, fake.configured_caps.bits);
        EXPECT_EQ(fake.configured_ticks, fixture.package.document.services[0].requested_tick_budget);

        ResourceDomainSnapshot domain{};
        EXPECT_TRUE(ResourceDomainInspectExact(fake.published_domain, &domain));
        EXPECT_EQ(domain.profile, ResourceDomainProfile::AuthenticatedService);
        EXPECT_EQ(domain.section_object_limit, fixture.package.document.services[0].requested_section_objects);
        EXPECT_EQ(domain.section_page_limit, fixture.package.document.services[0].requested_section_pages);
        ServiceBootstrapServiceSnapshotV1 staged{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &staged),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(staged.activation_state, ServiceBootstrapActivationStateV1::TransferredPublished);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture.service_runtime.lifecycle, 0x100);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Running);
        EXPECT_EQ(lifecycle.successful_publications, 1U);
        EXPECT_FALSE(lifecycle.ready);

        const ServiceDirectoryInspectResult directory =
            ServiceDirectoryInspectExact(&fixture.service_runtime.directory, result.directory_service);
        EXPECT_EQ(directory.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(directory.snapshot.state, ServiceDirectoryEntryState::Active);
        EXPECT_FALSE(directory.snapshot.ready);
        EXPECT_EQ(directory.snapshot.manifest_slot, 0U);
        EXPECT_EQ(directory.snapshot.owner.start, result.instance.start.transition);
        EXPECT_EQ(directory.snapshot.owner.process, result.instance.process);
        EXPECT_EQ(directory.snapshot.owner_credential, fake.process_credential);
        EXPECT_EQ(directory.snapshot.name.length, fixture.package.document.services[0].name_length);

        const ServiceExitObserverSnapshot pending = InspectObserver(fixture.service_runtime.exit_observer);
        EXPECT_EQ(pending.active_count, 1U);
        EXPECT_EQ(pending.pending_count, 1U);
        EXPECT_EQ(pending.event_sequence, 2ULL);
        ServiceExitDequeueResult exit = ServiceExitObserverDequeue(&fixture.service_runtime.exit_observer);
        EXPECT_EQ(exit.status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(exit.event.receipt.process, fake.publication_key);
        EXPECT_EQ(exit.event.instance, result.instance);
        EXPECT_EQ(exit.event.exit_code, fake.fast_exit_code);
        EXPECT_EQ(exit.event.failed, 1U);
        EXPECT_EQ(ServiceExitObserverAcknowledge(&fixture.service_runtime.exit_observer, &exit.event.receipt),
                  ServiceExitObserverStatus::Ok);
        ExpectObserverEmpty(fixture.service_runtime.exit_observer, 2);

        fake.ReapPublished();
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0U);
        EXPECT_EQ(fake.address_space_releases, 1U);
    }

    EXPECT_STREQ(ServiceBootstrapActivationStatusNameV1(ServiceBootstrapActivationStatusV1::PublicationRejected),
                 "publication-rejected");
    EXPECT_STREQ(ServiceBootstrapActivationStatusNameV1(ServiceBootstrapActivationStatusV1::ExitObserverCleanupFailed),
                 "exit-observer-cleanup-failed");
    EXPECT_STREQ(ServiceBootstrapActivationStatusNameV1(static_cast<ServiceBootstrapActivationStatusV1>(0xFF)),
                 "unknown");
    return duetos_host_test::finish_main("test_service_bootstrap_activation");
}
