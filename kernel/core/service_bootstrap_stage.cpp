#include "core/service_bootstrap_stage.h"

#if !defined(DUETOS_HOST_TEST)
#include "service-package/generated_boot_service_package_data.h"
#else
#include <atomic>
#endif

namespace duetos::core
{

namespace
{

struct ByteRange
{
    const void* pointer;
    u64 byte_count;
};

struct ScopedBackingQueryContext
{
    const ServiceBootstrapStageRowV1* row;
};

u64 g_next_registry_identity = 1;

u64 AtomicLoadRegistryIdentity(u64* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
#else
    return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

bool AtomicCompareExchangeRegistryIdentity(u64* value, u64* expected, u64 desired)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
#else
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
#endif
}

u64 MintRegistryIdentity()
{
    u64 current = AtomicLoadRegistryIdentity(&g_next_registry_identity);
    while (current != 0 && current <= kServiceBootstrapMemoryObjectRegistryMaximum)
    {
        u64 expected = current;
        if (AtomicCompareExchangeRegistryIdentity(&g_next_registry_identity, &expected, current + 1u))
            return current;
        current = expected;
    }
    return 0;
}

void ZeroBytes(void* target, u64 byte_count)
{
    auto* bytes = static_cast<u8*>(target);
    for (u64 index = 0; index < byte_count; ++index)
        bytes[index] = 0;
}

bool AllZero(const void* target, u64 byte_count)
{
    const auto* bytes = static_cast<const u8*>(target);
    for (u64 index = 0; index < byte_count; ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

bool RangeIsValid(const void* pointer, u64 byte_count)
{
    if (pointer == nullptr || byte_count == 0)
        return false;
    const uptr start = reinterpret_cast<uptr>(pointer);
    return byte_count <= ~static_cast<uptr>(0) - start;
}

bool RangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    if (!RangeIsValid(left, left_bytes) || !RangeIsValid(right, right_bytes))
        return false;
    const uptr left_start = reinterpret_cast<uptr>(left);
    const uptr right_start = reinterpret_cast<uptr>(right);
    return left_start < right_start + right_bytes && right_start < left_start + left_bytes;
}

bool CheckedMultiply(u64 left, u64 right, u64* result)
{
    if (result == nullptr || (left != 0 && right > ~0ULL / left))
        return false;
    *result = left * right;
    return true;
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

bool BytesEqual(const void* left, const void* right, u64 byte_count)
{
    const auto* left_bytes = static_cast<const u8*>(left);
    const auto* right_bytes = static_cast<const u8*>(right);
    u8 difference = 0;
    for (u64 index = 0; index < byte_count; ++index)
        difference |= left_bytes[index] ^ right_bytes[index];
    return difference == 0;
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | static_cast<u32>(bytes[1]) << 8u | static_cast<u32>(bytes[2]) << 16u |
           static_cast<u32>(bytes[3]) << 24u;
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | static_cast<u64>(ReadLe32(bytes + 4)) << 32u;
}

bool BootstrapPlanMatches(const ServiceBootstrapPlanTransferSnapshotV1& expected, const u8* actual,
                          u32 actual_byte_count, loader::ObjectHandle memory_object)
{
    if (!RangeIsValid(expected.bytes, expected.byte_count) || !RangeIsValid(actual, actual_byte_count) ||
        expected.byte_count != actual_byte_count || actual_byte_count < loader::kLoadPlanV1HeaderBytes ||
        !BytesEqual(expected.bytes, actual, loader::kLoadPlanV1HeaderBytes))
    {
        return false;
    }
    const u32 region_count = ReadLe32(expected.bytes + 24);
    if (region_count == 0 || region_count > loader::kLoadPlanMaxRegions ||
        actual_byte_count != loader::kLoadPlanV1HeaderBytes + region_count * loader::kLoadRegionV1Bytes)
    {
        return false;
    }
    for (u32 index = 0; index < region_count; ++index)
    {
        const u8* expected_region =
            expected.bytes + loader::kLoadPlanV1HeaderBytes + index * loader::kLoadRegionV1Bytes;
        const u8* actual_region = actual + loader::kLoadPlanV1HeaderBytes + index * loader::kLoadRegionV1Bytes;
        if (!BytesEqual(expected_region, actual_region, 16) || ReadLe64(expected_region + 16) != 0 ||
            ReadLe64(actual_region + 16) != memory_object ||
            !BytesEqual(expected_region + 24, actual_region + 24, loader::kLoadRegionV1Bytes - 24))
        {
            return false;
        }
    }
    return true;
}

bool ActivationStateIsValid(ServiceBootstrapActivationStateV1 state)
{
    return state == ServiceBootstrapActivationStateV1::Staged ||
           state == ServiceBootstrapActivationStateV1::Activating ||
           state == ServiceBootstrapActivationStateV1::TransferredPublished ||
           state == ServiceBootstrapActivationStateV1::ConsumedFailed;
}

loader::ObjectHandle MemoryObjectForManifestIndex(u64 registry_identity, u32 manifest_index)
{
    return kServiceBootstrapMemoryObjectTypeTag |
           (static_cast<loader::ObjectHandle>(registry_identity) << kServiceBootstrapMemoryObjectRegistryShift) |
           (static_cast<loader::ObjectHandle>(manifest_index) + 1u);
}

u64 MemoryObjectRegistryIdentity(loader::ObjectHandle memory_object)
{
    return (memory_object & kServiceBootstrapMemoryObjectRegistryMask) >> kServiceBootstrapMemoryObjectRegistryShift;
}

bool MemoryObjectMatchesManifestIndex(loader::ObjectHandle memory_object, u32 manifest_index)
{
    if ((memory_object & kServiceBootstrapMemoryObjectTypeMask) != kServiceBootstrapMemoryObjectTypeTag ||
        MemoryObjectRegistryIdentity(memory_object) == 0 || manifest_index >= kServiceManifestMaximumServices)
        return false;
    return (memory_object & kServiceBootstrapMemoryObjectIndexMask) ==
           static_cast<loader::ObjectHandle>(manifest_index + 1u);
}

bool MemoryObjectHasBootType(loader::ObjectHandle memory_object)
{
    const loader::ObjectHandle index = memory_object & kServiceBootstrapMemoryObjectIndexMask;
    const loader::ObjectHandle registry =
        (memory_object & kServiceBootstrapMemoryObjectRegistryMask) >> kServiceBootstrapMemoryObjectRegistryShift;
    return (memory_object & kServiceBootstrapMemoryObjectTypeMask) == kServiceBootstrapMemoryObjectTypeTag &&
           registry != 0 && index != 0 && index <= kServiceManifestMaximumServices;
}

bool BudgetedAllocateFrame(void* raw_context, loader::LoadImageFrame* frame_out, u8** writable_page_out)
{
    if (frame_out == nullptr || writable_page_out == nullptr)
        return false;
    *frame_out = loader::kLoadImageInvalidFrame;
    *writable_page_out = nullptr;

    auto* row = static_cast<ServiceBootstrapStageRowV1*>(raw_context);
    if (row == nullptr || row->source_frame_hooks.allocate_frame == nullptr || row->frame_budget_pages == 0)
        return false;
    if (row->frame_allocations >= row->frame_budget_pages)
    {
        row->frame_budget_exhausted = 1;
        return false;
    }

    const bool allocated =
        row->source_frame_hooks.allocate_frame(row->source_frame_hooks.context, frame_out, writable_page_out);
    if (allocated)
        ++row->frame_allocations;
    return allocated;
}

void BudgetedReleaseFrame(void* raw_context, loader::LoadImageFrame frame)
{
    auto* row = static_cast<ServiceBootstrapStageRowV1*>(raw_context);
    if (row == nullptr || row->source_frame_hooks.release_frame == nullptr)
        return;
    row->source_frame_hooks.release_frame(row->source_frame_hooks.context, frame);
}

ServiceBootstrapStageResultV1 StageResult(ServiceBootstrapStageStatus status,
                                          u32 service_index = kServiceBootstrapNoServiceIndex)
{
    return ServiceBootstrapStageResultV1{
        status,
        service_index,
        ServiceObjectPackageResult{ServiceObjectPackageStatus::Ok, ServiceManifestError::Ok,
                                   kServiceObjectPackageNoObjectIndex},
        loader::ElfLoadImageResult{loader::ElfLoadImageStatus::Ok, ElfStatus::Ok, loader::LoadImageStatus::Ok, 0, 0, 0,
                                   0},
        loader::ExecAdmissionStatus::Ok,
        loader::LoadPlanValidationError::Ok,
    };
}

void MarkFailed(ServiceBootstrapStageRuntimeV1* runtime)
{
    ZeroBytes(&runtime->package, sizeof(runtime->package));
    ZeroBytes(runtime->rows, sizeof(runtime->rows));
    runtime->state = ServiceBootstrapStageState::Failed;
    ZeroBytes(runtime->reserved8, sizeof(runtime->reserved8));
    runtime->version = kServiceBootstrapStageVersion1;
    runtime->service_count = 0;
    runtime->ready_count = 0;
    runtime->registry_identity = 0;
}

u32 FindManifestIndex(const ServiceManifestDocumentV1& document, u64 service_identity)
{
    for (u32 index = 0; index < document.service_count; ++index)
    {
        if (document.services[index].service_identity == service_identity)
            return index;
    }
    return kServiceManifestMaximumServices;
}

bool SlotOutputRange(const ServiceBootstrapSlotStorageV1& slot, u32 range_index, ByteRange* output)
{
    if (output == nullptr)
        return false;
    u64 byte_count = 0;
    switch (range_index)
    {
    case 0:
        *output = ByteRange{slot.image, sizeof(loader::LoadImage)};
        return true;
    case 1:
        if (!CheckedMultiply(slot.page_storage_count, sizeof(loader::LoadImagePage), &byte_count))
            return false;
        *output = ByteRange{slot.page_storage, byte_count};
        return true;
    case 2:
        if (!CheckedMultiply(slot.region_storage_count, sizeof(loader::LoadImageRegionAuthority), &byte_count))
            return false;
        *output = ByteRange{slot.region_storage, byte_count};
        return true;
    case 3:
        *output = ByteRange{slot.plan_storage, loader::kLoadImageMaxPlanBytes};
        return true;
    case 4:
        *output = ByteRange{slot.admission, sizeof(loader::ExecAdmission)};
        return true;
    case 5:
        *output = ByteRange{slot.admission_storage, loader::kExecAdmissionMaxPlanBytes};
        return true;
    default:
        return false;
    }
}

bool SlotDescriptorShapeIsValid(const ServiceBootstrapSlotStorageV1& slot)
{
    if (slot.reserved != 0 || slot.image == nullptr || slot.page_storage == nullptr || slot.page_storage_count == 0 ||
        slot.page_storage_count > loader::kLoadPlanMaxMappedPages || slot.region_storage == nullptr ||
        slot.region_storage_count == 0 || slot.region_storage_count > loader::kLoadPlanMaxRegions ||
        slot.plan_storage == nullptr || slot.plan_storage_bytes < loader::kLoadImageMaxPlanBytes ||
        slot.admission == nullptr || slot.admission_storage == nullptr ||
        slot.admission_storage_bytes < loader::kExecAdmissionMaxPlanBytes ||
        slot.frame_hooks.allocate_frame == nullptr || slot.frame_hooks.release_frame == nullptr)
    {
        return false;
    }
    for (u32 range_index = 0; range_index < 6; ++range_index)
    {
        ByteRange range{};
        if (!SlotOutputRange(slot, range_index, &range) || !RangeIsValid(range.pointer, range.byte_count))
            return false;
    }
    return true;
}

bool SlotShapeIsValid(const ServiceBootstrapSlotStorageV1& slot)
{
    return SlotDescriptorShapeIsValid(slot) && AllZero(slot.image, sizeof(*slot.image)) &&
           AllZero(slot.admission, sizeof(*slot.admission));
}

bool FrameHooksEqual(const loader::LoadImageFrameHooks& left, const loader::LoadImageFrameHooks& right)
{
    return left.context == right.context && left.allocate_frame == right.allocate_frame &&
           left.release_frame == right.release_frame;
}

bool SlotDescriptorsEqual(const ServiceBootstrapSlotStorageV1& left, const ServiceBootstrapSlotStorageV1& right)
{
    return left.image == right.image && FrameHooksEqual(left.frame_hooks, right.frame_hooks) &&
           left.page_storage == right.page_storage && left.page_storage_count == right.page_storage_count &&
           left.region_storage == right.region_storage && left.region_storage_count == right.region_storage_count &&
           left.plan_storage == right.plan_storage && left.plan_storage_bytes == right.plan_storage_bytes &&
           left.admission == right.admission && left.admission_storage == right.admission_storage &&
           left.admission_storage_bytes == right.admission_storage_bytes && left.reserved == right.reserved;
}

void CopySlotDescriptor(ServiceBootstrapSlotStorageV1* destination, const ServiceBootstrapSlotStorageV1& source)
{
    destination->image = source.image;
    destination->frame_hooks.context = source.frame_hooks.context;
    destination->frame_hooks.allocate_frame = source.frame_hooks.allocate_frame;
    destination->frame_hooks.release_frame = source.frame_hooks.release_frame;
    destination->page_storage = source.page_storage;
    destination->page_storage_count = source.page_storage_count;
    destination->region_storage = source.region_storage;
    destination->region_storage_count = source.region_storage_count;
    destination->plan_storage = source.plan_storage;
    destination->plan_storage_bytes = source.plan_storage_bytes;
    destination->admission = source.admission;
    destination->admission_storage = source.admission_storage;
    destination->admission_storage_bytes = source.admission_storage_bytes;
    destination->reserved = source.reserved;
}

void BindBank(ServiceBootstrapStageBankBindingV1* binding, const ServiceBootstrapSlotStorageV1& slot,
              u64 runtime_registry_identity, u64 service_identity, u32 manifest_index, u64 activation_generation)
{
    CopySlotDescriptor(&binding->storage, slot);
    binding->runtime_registry_identity = runtime_registry_identity;
    binding->service_identity = service_identity;
    binding->activation_generation = activation_generation;
    binding->manifest_index = manifest_index;
    binding->registered = 1;
    for (u32 index = 0; index < sizeof(binding->reserved); ++index)
        binding->reserved[index] = 0;
}

void CopyBankBinding(ServiceBootstrapStageBankBindingV1* destination, const ServiceBootstrapStageBankBindingV1& source)
{
    CopySlotDescriptor(&destination->storage, source.storage);
    destination->runtime_registry_identity = source.runtime_registry_identity;
    destination->service_identity = source.service_identity;
    destination->activation_generation = source.activation_generation;
    destination->manifest_index = source.manifest_index;
    destination->registered = source.registered;
    for (u32 index = 0; index < sizeof(destination->reserved); ++index)
        destination->reserved[index] = source.reserved[index];
}

void CopyBankRegistry(ServiceBootstrapStageRowV1* destination, const ServiceBootstrapStageRowV1& source)
{
    for (u32 index = 0; index < kServiceBootstrapStageBankCapacityV1; ++index)
        CopyBankBinding(&destination->banks[index], source.banks[index]);
    destination->bank_count = source.bank_count;
    destination->active_bank_index = source.active_bank_index;
    for (u32 index = 0; index < sizeof(destination->reserved_banks); ++index)
        destination->reserved_banks[index] = source.reserved_banks[index];
}

ServiceBootstrapStageStatus PreflightSlots(ServiceBootstrapStageRuntimeV1* runtime,
                                           const ServiceObjectPackageDefinitionV1& definition,
                                           const ServiceBootstrapSlotStorageV1* slots, u32 service_count)
{
    u64 slots_bytes = 0;
    if (!CheckedMultiply(service_count, sizeof(ServiceBootstrapSlotStorageV1), &slots_bytes) ||
        !RangeIsValid(slots, slots_bytes))
    {
        return ServiceBootstrapStageStatus::InvalidPointerRange;
    }
    if (RangesOverlap(runtime, sizeof(*runtime), slots, slots_bytes))
        return ServiceBootstrapStageStatus::AliasedStorage;

    u64 object_definitions_bytes = 0;
    u64 plan_definitions_bytes = 0;
    if (!CheckedMultiply(definition.executable_object_count, sizeof(ServiceExecutableObjectDefinitionV1),
                         &object_definitions_bytes) ||
        !CheckedMultiply(definition.bootstrap_plan_count, sizeof(ServiceBootstrapPlanDefinitionV1),
                         &plan_definitions_bytes))
    {
        return ServiceBootstrapStageStatus::InvalidPointerRange;
    }

    for (u32 index = 0; index < service_count; ++index)
    {
        const ServiceBootstrapSlotStorageV1& slot = slots[index];
        if (!SlotShapeIsValid(slot))
            return ServiceBootstrapStageStatus::InvalidSlotStorage;

        for (u32 left_index = 0; left_index < 6; ++left_index)
        {
            ByteRange left{};
            if (!SlotOutputRange(slot, left_index, &left))
                return ServiceBootstrapStageStatus::InvalidSlotStorage;
            if (RangesOverlap(left.pointer, left.byte_count, runtime, sizeof(*runtime)) ||
                RangesOverlap(left.pointer, left.byte_count, slots, slots_bytes) ||
                RangesOverlap(left.pointer, left.byte_count, &definition, sizeof(definition)) ||
                RangesOverlap(left.pointer, left.byte_count, definition.manifest_bytes,
                              definition.manifest_byte_count) ||
                RangesOverlap(left.pointer, left.byte_count, definition.manifest_authority,
                              sizeof(*definition.manifest_authority)) ||
                RangesOverlap(left.pointer, left.byte_count, definition.executable_objects, object_definitions_bytes) ||
                (definition.bootstrap_plan_count != 0 &&
                 RangesOverlap(left.pointer, left.byte_count, definition.bootstrap_plans, plan_definitions_bytes)))
            {
                return ServiceBootstrapStageStatus::AliasedStorage;
            }

            for (u32 artifact_index = 0; artifact_index < runtime->package.executable_object_count; ++artifact_index)
            {
                const ServiceObjectPackageRowV1& artifact = runtime->package.executable_objects[artifact_index];
                if (RangesOverlap(left.pointer, left.byte_count, artifact.bytes, artifact.byte_count))
                    return ServiceBootstrapStageStatus::AliasedStorage;
            }
            for (u32 plan_index = 0; plan_index < runtime->package.bootstrap_plan_count; ++plan_index)
            {
                const ServiceBootstrapPlanRowV1& plan = runtime->package.bootstrap_plans[plan_index];
                if (RangesOverlap(left.pointer, left.byte_count, plan.bytes, plan.byte_count))
                    return ServiceBootstrapStageStatus::AliasedStorage;
            }

            for (u32 right_index = left_index + 1; right_index < 6; ++right_index)
            {
                ByteRange right{};
                if (!SlotOutputRange(slot, right_index, &right) ||
                    RangesOverlap(left.pointer, left.byte_count, right.pointer, right.byte_count))
                {
                    return ServiceBootstrapStageStatus::SlotStorageOverlap;
                }
            }

            for (u32 previous = 0; previous < index; ++previous)
            {
                for (u32 right_index = 0; right_index < 6; ++right_index)
                {
                    ByteRange right{};
                    if (!SlotOutputRange(slots[previous], right_index, &right) ||
                        RangesOverlap(left.pointer, left.byte_count, right.pointer, right.byte_count))
                    {
                        return ServiceBootstrapStageStatus::SlotStorageOverlap;
                    }
                }
            }
        }
    }
    return ServiceBootstrapStageStatus::Ok;
}

ServiceBootstrapStageStatus ResolveRestageBank(const ServiceBootstrapStageRowV1& row,
                                               const ServiceBootstrapSlotStorageV1& replacement, u32* bank_index_out,
                                               bool* newly_registered_out)
{
    if (bank_index_out == nullptr || newly_registered_out == nullptr)
        return ServiceBootstrapStageStatus::CorruptRuntime;
    *bank_index_out = kServiceBootstrapNoBankIndexV1;
    *newly_registered_out = false;

    for (u32 index = 0; index < row.bank_count; ++index)
    {
        if (!SlotDescriptorsEqual(row.banks[index].storage, replacement))
            continue;
        if (index == row.active_bank_index)
            return ServiceBootstrapStageStatus::AliasedStorage;
        *bank_index_out = index;
        return ServiceBootstrapStageStatus::Ok;
    }

    if (row.bank_count >= kServiceBootstrapStageBankCapacityV1)
        return ServiceBootstrapStageStatus::InvalidSlotStorage;
    *bank_index_out = row.bank_count;
    *newly_registered_out = true;
    return ServiceBootstrapStageStatus::Ok;
}

ServiceBootstrapStageStatus PreflightRestageSlot(const ServiceBootstrapStageRuntimeV1& runtime,
                                                 const ServiceBootstrapSlotStorageV1* replacement,
                                                 u32 selected_manifest_index, u32 replacement_bank_index,
                                                 bool replacement_is_registered)
{
    if (!RangeIsValid(replacement, sizeof(*replacement)))
        return ServiceBootstrapStageStatus::InvalidPointerRange;
    if (RangesOverlap(replacement, sizeof(*replacement), &runtime, sizeof(runtime)))
        return ServiceBootstrapStageStatus::AliasedStorage;
    if (!SlotDescriptorShapeIsValid(*replacement))
        return ServiceBootstrapStageStatus::InvalidSlotStorage;

    for (u32 object_index = 0; object_index < runtime.package.executable_object_count; ++object_index)
    {
        const ServiceObjectPackageRowV1& object = runtime.package.executable_objects[object_index];
        if (RangesOverlap(replacement, sizeof(*replacement), object.bytes, object.byte_count))
            return ServiceBootstrapStageStatus::AliasedStorage;
    }
    for (u32 plan_index = 0; plan_index < runtime.package.bootstrap_plan_count; ++plan_index)
    {
        const ServiceBootstrapPlanRowV1& plan = runtime.package.bootstrap_plans[plan_index];
        if (RangesOverlap(replacement, sizeof(*replacement), plan.bytes, plan.byte_count))
            return ServiceBootstrapStageStatus::AliasedStorage;
    }

    for (u32 left_index = 0; left_index < 6; ++left_index)
    {
        ByteRange left{};
        if (!SlotOutputRange(*replacement, left_index, &left) || !RangeIsValid(left.pointer, left.byte_count))
            return ServiceBootstrapStageStatus::InvalidSlotStorage;
        if (RangesOverlap(left.pointer, left.byte_count, &runtime, sizeof(runtime)) ||
            RangesOverlap(left.pointer, left.byte_count, replacement, sizeof(*replacement)))
        {
            return ServiceBootstrapStageStatus::AliasedStorage;
        }

        for (u32 object_index = 0; object_index < runtime.package.executable_object_count; ++object_index)
        {
            const ServiceObjectPackageRowV1& object = runtime.package.executable_objects[object_index];
            if (RangesOverlap(left.pointer, left.byte_count, object.bytes, object.byte_count))
                return ServiceBootstrapStageStatus::AliasedStorage;
        }
        for (u32 plan_index = 0; plan_index < runtime.package.bootstrap_plan_count; ++plan_index)
        {
            const ServiceBootstrapPlanRowV1& plan = runtime.package.bootstrap_plans[plan_index];
            if (RangesOverlap(left.pointer, left.byte_count, plan.bytes, plan.byte_count))
                return ServiceBootstrapStageStatus::AliasedStorage;
        }

        for (u32 right_index = left_index + 1; right_index < 6; ++right_index)
        {
            ByteRange right{};
            if (!SlotOutputRange(*replacement, right_index, &right) ||
                RangesOverlap(left.pointer, left.byte_count, right.pointer, right.byte_count))
            {
                return ServiceBootstrapStageStatus::SlotStorageOverlap;
            }
        }

        for (u32 row_index = 0; row_index < runtime.service_count; ++row_index)
        {
            const ServiceBootstrapStageRowV1& row = runtime.rows[row_index];
            for (u32 bank_index = 0; bank_index < row.bank_count; ++bank_index)
            {
                if (replacement_is_registered && row_index == selected_manifest_index &&
                    bank_index == replacement_bank_index)
                {
                    continue;
                }

                for (u32 retained_index = 0; retained_index < 6; ++retained_index)
                {
                    ByteRange retained{};
                    if (!SlotOutputRange(row.banks[bank_index].storage, retained_index, &retained) ||
                        !RangeIsValid(retained.pointer, retained.byte_count))
                    {
                        return ServiceBootstrapStageStatus::CorruptRuntime;
                    }
                    if (RangesOverlap(left.pointer, left.byte_count, retained.pointer, retained.byte_count) ||
                        RangesOverlap(replacement, sizeof(*replacement), retained.pointer, retained.byte_count))
                    {
                        return ServiceBootstrapStageStatus::AliasedStorage;
                    }
                }
            }
        }
    }
    return ServiceBootstrapStageStatus::Ok;
}

bool ResetImageAndAdmission(loader::LoadImage* image, loader::ExecAdmission* admission)
{
    if (image != nullptr)
    {
        loader::LoadImageRelease(image);
        if (loader::LoadImageResetQuiescent(image) != loader::LoadImageStatus::Ok)
            return false;
    }
    if (admission != nullptr && loader::ExecAdmissionResetQuiescent(admission) != loader::ExecAdmissionStatus::Ok)
        return false;
    return true;
}

bool RetiredSlotBindingsMatch(const ServiceBootstrapSlotStorageV1& slot)
{
    if (slot.image->state != loader::LoadImageState::Uninitialized &&
        (slot.image->pages != slot.page_storage || slot.image->page_capacity != slot.page_storage_count ||
         slot.image->regions != slot.region_storage || slot.image->region_capacity != slot.region_storage_count ||
         slot.image->plan_storage != slot.plan_storage || slot.image->plan_capacity != slot.plan_storage_bytes))
    {
        return false;
    }
    if (slot.admission->initialized != 0 && (slot.admission->storage != slot.admission_storage ||
                                             slot.admission->storage_capacity != loader::kExecAdmissionMaxPlanBytes ||
                                             slot.admission_storage_bytes < loader::kExecAdmissionMaxPlanBytes))
    {
        return false;
    }
    return true;
}

ServiceBootstrapStageStatus ResetRetiredRestageSlot(const ServiceBootstrapSlotStorageV1& slot)
{
    if (!RetiredSlotBindingsMatch(slot))
        return ServiceBootstrapStageStatus::InvalidSlotStorage;

    // Validate both halves before clearing either one. A rejected inactive
    // admission must not strand its matching terminal image in canonical-zero
    // form (or vice versa), because the caller may inspect and retry that bank.
    const loader::LoadImageStatus image_status = loader::LoadImageCanResetQuiescent(slot.image);
    if (image_status == loader::LoadImageStatus::OwnershipOutstanding)
        return ServiceBootstrapStageStatus::TerminalImageOwnsFrames;
    if (image_status != loader::LoadImageStatus::Ok)
        return ServiceBootstrapStageStatus::InvalidSlotStorage;
    if (loader::ExecAdmissionCanResetQuiescent(slot.admission) != loader::ExecAdmissionStatus::Ok)
        return ServiceBootstrapStageStatus::InvalidSlotStorage;

    if (loader::LoadImageResetQuiescent(slot.image) != loader::LoadImageStatus::Ok ||
        loader::ExecAdmissionResetQuiescent(slot.admission) != loader::ExecAdmissionStatus::Ok)
    {
        return ServiceBootstrapStageStatus::InvalidSlotStorage;
    }
    return SlotShapeIsValid(slot) ? ServiceBootstrapStageStatus::Ok : ServiceBootstrapStageStatus::InvalidSlotStorage;
}

void ResetSlotOutputs(const ServiceBootstrapSlotStorageV1* slots, u32 service_count)
{
    for (u32 index = 0; index < service_count; ++index)
        ResetImageAndAdmission(slots[index].image, slots[index].admission);
}

bool ScopedBackingQuery(loader::ObjectHandle memory_object, u64 object_offset, u64 length,
                        loader::LoadBackingInfoV1* out_info, void* raw_context)
{
    if (raw_context == nullptr || out_info == nullptr)
        return false;
    const auto& context = *static_cast<const ScopedBackingQueryContext*>(raw_context);
    if (context.row == nullptr)
        return false;
    const ServiceBootstrapStageRowV1& row = *context.row;
    if (!MemoryObjectHasBootType(memory_object) || memory_object != row.memory_object || row.image == nullptr)
        return false;
    return loader::LoadImageBackingQuery(memory_object, object_offset, length, out_info, row.image);
}

void ResetPreparedRowOrMarkCorrupt(ServiceBootstrapStageRowV1* row, ServiceBootstrapStageResultV1* result)
{
    if (result == nullptr)
        return;
    if (row == nullptr || !ResetImageAndAdmission(row->image, row->admission))
        result->status = ServiceBootstrapStageStatus::CorruptRuntime;
}

ServiceBootstrapStageResultV1 PrepareStagedRow(const ServiceManifestServiceV1& service,
                                               const ServiceExecutableTransferSnapshotV1& transfer,
                                               const ServiceBootstrapPlanTransferSnapshotV1* bootstrap_plan,
                                               u32 manifest_index, loader::ObjectHandle memory_object,
                                               const ServiceBootstrapSlotStorageV1& slot, u64 activation_generation,
                                               u64 admission_first_identity, ServiceBootstrapStageRowV1* row)
{
    ServiceBootstrapStageResultV1 result = StageResult(ServiceBootstrapStageStatus::Ok, manifest_index);
    if (row == nullptr || service.service_identity == 0 || transfer.service_identity != service.service_identity ||
        transfer.executable_transfer_ref != service.executable_transfer_ref ||
        !HashEquals(transfer.content_hash, service.executable_content_hash) ||
        !MemoryObjectMatchesManifestIndex(memory_object, manifest_index) || admission_first_identity == 0)
    {
        result.status = ServiceBootstrapStageStatus::CorruptRuntime;
        return result;
    }

    row->service_identity = service.service_identity;
    row->executable_transfer_ref = service.executable_transfer_ref;
    row->manifest_index = manifest_index;
    row->memory_object = memory_object;
    row->expected_source_hash = transfer.content_hash;
    row->source_frame_hooks = slot.frame_hooks;
    row->frame_budget_pages = service.requested_frame_budget_pages;
    row->frame_allocations = 0;
    row->frame_budget_exhausted = 0;
    row->activation_state = ServiceBootstrapActivationStateV1::Staged;
    for (u32 index = 0; index < sizeof(row->reserved_budget); ++index)
        row->reserved_budget[index] = 0;
    row->activation_generation = activation_generation;
    row->image = slot.image;
    row->admission = slot.admission;
    row->admitted_plan = loader::LoadPlanViewV1{};

    const loader::LoadImageFrameHooks budgeted_frame_hooks{row, &BudgetedAllocateFrame, &BudgetedReleaseFrame};
    const loader::ElfLoadImageRequest request{
        transfer.bytes,          transfer.byte_count,     transfer.content_hash,
        row->memory_object,      budgeted_frame_hooks,    slot.page_storage,
        slot.page_storage_count, slot.region_storage,     slot.region_storage_count,
        slot.plan_storage,       slot.plan_storage_bytes,
    };
    result.elf_result = loader::ElfLoadImagePrepare(request, row->image);
    if (row->frame_budget_exhausted != 0)
    {
        result.status = ServiceBootstrapStageStatus::ResourceBudgetExceeded;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }
    if (result.elf_result.status != loader::ElfLoadImageStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::ElfStageRejected;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }

    loader::LoadImageSnapshot image_snapshot{};
    if (loader::LoadImageInspect(row->image, &image_snapshot) != loader::LoadImageStatus::Ok ||
        image_snapshot.present_pages != row->frame_allocations)
    {
        result.status = ServiceBootstrapStageStatus::CorruptRuntime;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }
    if (image_snapshot.present_pages > service.requested_frame_budget_pages)
    {
        result.status = ServiceBootstrapStageStatus::ResourceBudgetExceeded;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }

    const u8* plan_bytes = nullptr;
    u32 plan_byte_count = 0;
    if (!loader::LoadImagePlanBytes(row->image, &plan_bytes, &plan_byte_count))
    {
        result.status = ServiceBootstrapStageStatus::PlanUnavailable;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }
    if (bootstrap_plan != nullptr &&
        !BootstrapPlanMatches(*bootstrap_plan, plan_bytes, plan_byte_count, row->memory_object))
    {
        result.status = ServiceBootstrapStageStatus::BootstrapPlanMismatch;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }

    result.admission_status = loader::ExecAdmissionInitialize(row->admission, slot.admission_storage,
                                                              slot.admission_storage_bytes, admission_first_identity);
    if (result.admission_status != loader::ExecAdmissionStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::AdmissionRejected;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }

    const loader::ExecAdmissionPrepareResult prepared =
        loader::ExecAdmissionPrepare(row->admission, plan_bytes, plan_byte_count);
    result.admission_status = prepared.status;
    if (prepared.status != loader::ExecAdmissionStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::AdmissionRejected;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }

    ScopedBackingQueryContext query_context{row};
    loader::LoadPlanViewV1 admitted{};
    const loader::ExecAdmissionConsumeResult consumed = loader::ExecAdmissionConsume(
        row->admission, prepared.token, &row->expected_source_hash, &ScopedBackingQuery, &query_context, &admitted);
    result.admission_status = consumed.status;
    result.validation_error = consumed.validation_error;
    if (consumed.status != loader::ExecAdmissionStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::AdmissionRejected;
        ResetPreparedRowOrMarkCorrupt(row, &result);
        return result;
    }
    row->admitted_plan = admitted;
    return result;
}

bool ImageOwnershipIsCanonical(const ServiceBootstrapStageRowV1& row, loader::LoadImageState image_state,
                               const loader::LoadImageSnapshot& snapshot)
{
    if (snapshot.state != image_state)
        return false;
    switch (image_state)
    {
    case loader::LoadImageState::Sealed:
        return snapshot.present_pages == row.frame_allocations &&
               snapshot.package_owned_pages == row.frame_allocations && snapshot.target_owned_pages == 0 &&
               snapshot.released_pages == 0;
    case loader::LoadImageState::Transferred:
        return snapshot.present_pages == row.frame_allocations && snapshot.package_owned_pages == 0 &&
               snapshot.target_owned_pages == row.frame_allocations && snapshot.released_pages == 0;
    case loader::LoadImageState::Failed:
        return snapshot.package_owned_pages == 0 && snapshot.present_pages == snapshot.target_owned_pages &&
               static_cast<u64>(snapshot.target_owned_pages) + snapshot.released_pages == row.frame_allocations;
    default:
        return false;
    }
}

bool RowImageStateMatchesActivation(const ServiceBootstrapStageRowV1& row, loader::LoadImageState image_state,
                                    bool require_sealed_images)
{
    switch (row.activation_state)
    {
    case ServiceBootstrapActivationStateV1::Staged:
        return image_state == loader::LoadImageState::Sealed ||
               (!require_sealed_images &&
                (image_state == loader::LoadImageState::Transferred || image_state == loader::LoadImageState::Failed));
    case ServiceBootstrapActivationStateV1::Activating:
        return !require_sealed_images &&
               (image_state == loader::LoadImageState::Sealed || image_state == loader::LoadImageState::Transferred ||
                image_state == loader::LoadImageState::Failed);
    case ServiceBootstrapActivationStateV1::TransferredPublished:
        return !require_sealed_images && image_state == loader::LoadImageState::Transferred;
    case ServiceBootstrapActivationStateV1::ConsumedFailed:
        return !require_sealed_images &&
               (image_state == loader::LoadImageState::Transferred || image_state == loader::LoadImageState::Failed);
    }
    return false;
}

bool BankRegistryIsCanonical(const ServiceBootstrapStageRowV1& row, u64 runtime_registry_identity, u32 manifest_index)
{
    if (row.bank_count == 0 || row.bank_count > kServiceBootstrapStageBankCapacityV1 ||
        row.active_bank_index >= row.bank_count || !AllZero(row.reserved_banks, sizeof(row.reserved_banks)))
    {
        return false;
    }

    for (u32 index = 0; index < row.bank_count; ++index)
    {
        const ServiceBootstrapStageBankBindingV1& binding = row.banks[index];
        if (binding.registered != 1 || !AllZero(binding.reserved, sizeof(binding.reserved)) ||
            binding.runtime_registry_identity != runtime_registry_identity ||
            binding.service_identity != row.service_identity || binding.manifest_index != manifest_index ||
            binding.activation_generation > row.activation_generation || !SlotDescriptorShapeIsValid(binding.storage) ||
            !RetiredSlotBindingsMatch(binding.storage))
        {
            return false;
        }

        if (index == row.active_bank_index)
        {
            if (binding.activation_generation != row.activation_generation || binding.storage.image != row.image ||
                binding.storage.admission != row.admission ||
                !FrameHooksEqual(binding.storage.frame_hooks, row.source_frame_hooks))
            {
                return false;
            }
        }
        else if (loader::LoadImageCanResetQuiescent(binding.storage.image) != loader::LoadImageStatus::Ok ||
                 loader::ExecAdmissionCanResetQuiescent(binding.storage.admission) != loader::ExecAdmissionStatus::Ok)
        {
            return false;
        }
    }

    for (u32 index = row.bank_count; index < kServiceBootstrapStageBankCapacityV1; ++index)
    {
        if (!AllZero(&row.banks[index], sizeof(row.banks[index])))
            return false;
    }
    return true;
}

bool RowStructureIsCanonical(const ServiceBootstrapStageRowV1& row, const ServiceManifestServiceV1& service,
                             u32 manifest_index, u64 runtime_registry_identity, bool require_sealed_image)
{
    if (row.service_identity != service.service_identity ||
        row.executable_transfer_ref != service.executable_transfer_ref || row.manifest_index != manifest_index ||
        !MemoryObjectMatchesManifestIndex(row.memory_object, manifest_index) ||
        !HashEquals(row.expected_source_hash, service.executable_content_hash) || row.image == nullptr ||
        row.source_frame_hooks.allocate_frame == nullptr || row.source_frame_hooks.release_frame == nullptr ||
        row.frame_budget_pages != service.requested_frame_budget_pages ||
        row.frame_allocations > row.frame_budget_pages || row.frame_budget_exhausted != 0 ||
        !ActivationStateIsValid(row.activation_state) ||
        row.activation_generation > kServiceBootstrapActivationGenerationMaximum ||
        (row.activation_state != ServiceBootstrapActivationStateV1::Staged && row.activation_generation == 0) ||
        !AllZero(row.reserved_budget, sizeof(row.reserved_budget)) || row.admission == nullptr ||
        !HashEquals(row.image->descriptor.source_hash, row.expected_source_hash) ||
        row.image->descriptor.memory_object != row.memory_object || row.admission->initialized != 1 ||
        row.admission->state != loader::ExecAdmissionState::Consumed || row.admitted_plan.bytes == nullptr ||
        row.admitted_plan.bytes != row.admission->storage || row.admitted_plan.size == 0 ||
        row.admitted_plan.size != row.admission->frozen_bytes ||
        row.admitted_plan.header.format != loader::ImageFormat::Elf64 ||
        !HashEquals(row.admitted_plan.header.source_hash, row.expected_source_hash) ||
        !BankRegistryIsCanonical(row, runtime_registry_identity, manifest_index))
    {
        return false;
    }

    const loader::LoadImageState image_state = row.image->state;
    if (!RowImageStateMatchesActivation(row, image_state, require_sealed_image))
        return false;

    loader::LoadImageSnapshot image_snapshot{};
    if (loader::LoadImageInspect(row.image, &image_snapshot) != loader::LoadImageStatus::Ok ||
        !ImageOwnershipIsCanonical(row, image_state, image_snapshot))
    {
        return false;
    }

    const u8* image_plan = nullptr;
    u32 image_plan_bytes = 0;
    return loader::LoadImagePlanBytes(row.image, &image_plan, &image_plan_bytes) &&
           image_plan_bytes == row.admitted_plan.size &&
           BytesEqual(image_plan, row.admitted_plan.bytes, image_plan_bytes);
}

bool RuntimeStructureIsCanonical(const ServiceBootstrapStageRuntimeV1& runtime, bool require_sealed_images)
{
    if (runtime.state != ServiceBootstrapStageState::Ready || runtime.version != kServiceBootstrapStageVersion1 ||
        runtime.service_count == 0 || runtime.service_count > kServiceManifestMaximumServices ||
        runtime.ready_count != runtime.service_count || runtime.registry_identity == 0 ||
        runtime.registry_identity > kServiceBootstrapMemoryObjectRegistryMaximum ||
        !AllZero(runtime.reserved8, sizeof(runtime.reserved8)))
    {
        return false;
    }

    ServiceObjectPackageManifestV1 manifest{};
    if (ServiceObjectPackageGetManifestV1(&runtime.package, &manifest).status != ServiceObjectPackageStatus::Ok ||
        manifest.plan == nullptr || manifest.authority == nullptr ||
        manifest.plan->document.service_count != runtime.service_count)
    {
        return false;
    }

    for (u32 index = 0; index < runtime.service_count; ++index)
    {
        const ServiceManifestServiceV1& service = manifest.plan->document.services[index];
        const ServiceBootstrapStageRowV1& row = runtime.rows[index];
        if (!RowStructureIsCanonical(row, service, index, runtime.registry_identity, require_sealed_images))
            return false;
    }

    for (u32 index = runtime.service_count; index < kServiceManifestMaximumServices; ++index)
    {
        if (!AllZero(&runtime.rows[index], sizeof(runtime.rows[index])))
            return false;
    }
    return true;
}

bool RuntimeIsCanonical(const ServiceBootstrapStageRuntimeV1& runtime)
{
    return RuntimeStructureIsCanonical(runtime, true);
}

ServiceBootstrapServiceSnapshotV1 SnapshotService(const ServiceBootstrapStageRowV1& row)
{
    ServiceBootstrapServiceSnapshotV1 snapshot{};
    snapshot.service_identity = row.service_identity;
    snapshot.executable_transfer_ref = row.executable_transfer_ref;
    snapshot.manifest_index = row.manifest_index;
    snapshot.memory_object = row.memory_object;
    snapshot.expected_source_hash = row.expected_source_hash;
    snapshot.admitted_plan = row.admitted_plan;
    snapshot.activation_state = row.activation_state;
    snapshot.activation_generation = row.activation_generation;
    return snapshot;
}

bool ReceiptIsExact(const ServiceBootstrapStageRuntimeV1& runtime, const ServiceBootstrapStageRowV1& row,
                    ServiceBootstrapActivationReceiptV1 receipt)
{
    return receipt.version == kServiceBootstrapActivationReceiptVersion1 &&
           receipt.manifest_index == row.manifest_index && receipt.manifest_index < runtime.service_count &&
           receipt.registry_identity == runtime.registry_identity && receipt.service_identity == row.service_identity &&
           receipt.activation_generation != 0 &&
           receipt.activation_generation <= kServiceBootstrapActivationGenerationMaximum &&
           receipt.activation_generation == row.activation_generation && receipt.memory_object == row.memory_object;
}

bool ImageIsSealedPackageOwned(const ServiceBootstrapStageRowV1& row)
{
    if (row.image == nullptr || row.image->state != loader::LoadImageState::Sealed)
        return false;
    loader::LoadImageSnapshot snapshot{};
    return loader::LoadImageInspect(row.image, &snapshot) == loader::LoadImageStatus::Ok &&
           ImageOwnershipIsCanonical(row, loader::LoadImageState::Sealed, snapshot);
}

bool ActivationLeaseAliasesRetainedStorage(const ServiceBootstrapStageRuntimeV1& runtime,
                                           const ServiceBootstrapActivationLeaseV1* lease_out)
{
    if (RangesOverlap(runtime.rows, sizeof(runtime.rows), lease_out, sizeof(*lease_out)))
        return true;
    for (u32 index = 0; index < runtime.service_count; ++index)
    {
        const ServiceBootstrapStageRowV1& row = runtime.rows[index];
        const loader::LoadImage& image = *row.image;
        const loader::ExecAdmission& admission = *row.admission;
        u64 page_bytes = 0;
        u64 region_bytes = 0;
        if (!CheckedMultiply(image.page_capacity, sizeof(*image.pages), &page_bytes) ||
            !CheckedMultiply(image.region_capacity, sizeof(*image.regions), &region_bytes))
        {
            return true;
        }
        if (RangesOverlap(image.pages, page_bytes, lease_out, sizeof(*lease_out)) ||
            RangesOverlap(image.regions, region_bytes, lease_out, sizeof(*lease_out)) ||
            RangesOverlap(image.plan_storage, image.plan_capacity, lease_out, sizeof(*lease_out)) ||
            RangesOverlap(admission.storage, admission.storage_capacity, lease_out, sizeof(*lease_out)))
        {
            return true;
        }
        for (u32 bank_index = 0; bank_index < row.bank_count; ++bank_index)
        {
            for (u32 range_index = 0; range_index < 6; ++range_index)
            {
                ByteRange retained{};
                if (!SlotOutputRange(row.banks[bank_index].storage, range_index, &retained) ||
                    RangesOverlap(retained.pointer, retained.byte_count, lease_out, sizeof(*lease_out)))
                {
                    return true;
                }
            }
        }
    }
    for (u32 index = 0; index < runtime.package.executable_object_count; ++index)
    {
        const ServiceObjectPackageRowV1& object = runtime.package.executable_objects[index];
        if (RangesOverlap(object.bytes, object.byte_count, lease_out, sizeof(*lease_out)))
            return true;
    }
    for (u32 index = 0; index < runtime.package.bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanRowV1& plan = runtime.package.bootstrap_plans[index];
        if (RangesOverlap(plan.bytes, plan.byte_count, lease_out, sizeof(*lease_out)))
            return true;
    }
    return false;
}

bool TerminalRowOwnsNoPackageFrames(const ServiceBootstrapStageRowV1& row)
{
    if (row.activation_state != ServiceBootstrapActivationStateV1::TransferredPublished &&
        row.activation_state != ServiceBootstrapActivationStateV1::ConsumedFailed)
    {
        return false;
    }
    loader::LoadImageSnapshot snapshot{};
    return row.image != nullptr && loader::LoadImageInspect(row.image, &snapshot) == loader::LoadImageStatus::Ok &&
           snapshot.package_owned_pages == 0 && ImageOwnershipIsCanonical(row, row.image->state, snapshot);
}

void AdoptPreparedRow(ServiceBootstrapStageRowV1* destination, ServiceBootstrapStageRowV1& prepared)
{
    // Prepare installed the budget wrapper with a temporary descriptor as its
    // context. Rebind it to the persistent runtime row before the final swap;
    // no frame callback can run while the serialized service-control owner is
    // between prepare and publication.
    prepared.image->frame_hooks.context = destination;

    destination->service_identity = prepared.service_identity;
    destination->executable_transfer_ref = prepared.executable_transfer_ref;
    destination->manifest_index = prepared.manifest_index;
    destination->memory_object = prepared.memory_object;
    destination->expected_source_hash = prepared.expected_source_hash;
    destination->source_frame_hooks = prepared.source_frame_hooks;
    destination->frame_budget_pages = prepared.frame_budget_pages;
    destination->frame_allocations = prepared.frame_allocations;
    destination->frame_budget_exhausted = prepared.frame_budget_exhausted;
    destination->activation_state = prepared.activation_state;
    for (u32 index = 0; index < sizeof(destination->reserved_budget); ++index)
        destination->reserved_budget[index] = prepared.reserved_budget[index];
    destination->activation_generation = prepared.activation_generation;
    destination->image = prepared.image;
    destination->admission = prepared.admission;
    destination->admitted_plan = prepared.admitted_plan;
    CopyBankRegistry(destination, prepared);
}

} // namespace

#if defined(DUETOS_HOST_TEST)
u64 ServiceBootstrapStageExchangeNextRegistryIdentityForTestV1(u64 next_identity)
{
    if (next_identity == 0 || next_identity > kServiceBootstrapMemoryObjectRegistryMaximum)
        return 0;
    return std::atomic_ref<u64>(g_next_registry_identity).exchange(next_identity, std::memory_order_relaxed);
}
#endif

ServiceBootstrapStageResultV1 ServiceBootstrapStageInitializeV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                const ServiceObjectPackageDefinitionV1* definition,
                                                                const ServiceBootstrapSlotStorageV1* slots,
                                                                u32 slot_capacity)
{
    if (runtime == nullptr || definition == nullptr || slots == nullptr)
        return StageResult(ServiceBootstrapStageStatus::NullArgument);
    if (!RangeIsValid(runtime, sizeof(*runtime)) || !RangeIsValid(definition, sizeof(*definition)) ||
        !RangeIsValid(slots, sizeof(*slots)))
    {
        return StageResult(ServiceBootstrapStageStatus::InvalidPointerRange);
    }
    if (RangesOverlap(runtime, sizeof(*runtime), definition, sizeof(*definition)) ||
        RangesOverlap(runtime, sizeof(*runtime), slots, sizeof(*slots)))
    {
        return StageResult(ServiceBootstrapStageStatus::AliasedStorage);
    }
    if (!AllZero(runtime, sizeof(*runtime)))
        return StageResult(ServiceBootstrapStageStatus::NonCanonicalRuntime);

    runtime->state = ServiceBootstrapStageState::Staging;
    runtime->version = kServiceBootstrapStageVersion1;
    ServiceBootstrapStageResultV1 result = StageResult(ServiceBootstrapStageStatus::Ok);
    result.package_result = ServiceObjectPackageInitializeV1(&runtime->package, definition);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::PackageRejected;
        MarkFailed(runtime);
        return result;
    }

    ServiceObjectPackageManifestV1 manifest{};
    result.package_result = ServiceObjectPackageGetManifestV1(&runtime->package, &manifest);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok || manifest.plan == nullptr ||
        manifest.authority == nullptr)
    {
        result.status = ServiceBootstrapStageStatus::ManifestUnavailable;
        MarkFailed(runtime);
        return result;
    }

    const u32 service_count = manifest.plan->document.service_count;
    if (service_count == 0 || service_count > kServiceManifestMaximumServices)
    {
        result.status = ServiceBootstrapStageStatus::CorruptRuntime;
        MarkFailed(runtime);
        return result;
    }
    if (slot_capacity < service_count)
    {
        result.status = ServiceBootstrapStageStatus::SlotCapacityTooSmall;
        MarkFailed(runtime);
        return result;
    }
    runtime->service_count = service_count;

    result.status = PreflightSlots(runtime, *definition, slots, service_count);
    if (result.status != ServiceBootstrapStageStatus::Ok)
    {
        MarkFailed(runtime);
        return result;
    }

    runtime->registry_identity = MintRegistryIdentity();
    if (runtime->registry_identity == 0)
    {
        result.status = ServiceBootstrapStageStatus::IdentityExhausted;
        MarkFailed(runtime);
        return result;
    }

    for (u32 order_index = 0; order_index < manifest.plan->topological_count; ++order_index)
    {
        const u64 service_identity = manifest.plan->topological_identities[order_index];
        const u32 manifest_index = FindManifestIndex(manifest.plan->document, service_identity);
        if (manifest_index >= service_count)
        {
            result = StageResult(ServiceBootstrapStageStatus::CorruptRuntime);
            ResetSlotOutputs(slots, service_count);
            MarkFailed(runtime);
            return result;
        }

        result.service_index = manifest_index;
        const ServiceManifestServiceV1& service = manifest.plan->document.services[manifest_index];
        if (service.kind != ServiceManifestKind::Native && service.kind != ServiceManifestKind::Broker)
        {
            result.status = ServiceBootstrapStageStatus::UnsupportedServiceKind;
            ResetSlotOutputs(slots, service_count);
            MarkFailed(runtime);
            return result;
        }

        ServiceExecutableTransferSnapshotV1 transfer{};
        result.package_result = ServiceObjectPackageResolveExecutableV1(&runtime->package, service.service_identity,
                                                                        service.executable_transfer_ref, &transfer);
        if (result.package_result.status != ServiceObjectPackageStatus::Ok)
        {
            result.status = ServiceBootstrapStageStatus::ExecutableResolveFailed;
            ResetSlotOutputs(slots, service_count);
            MarkFailed(runtime);
            return result;
        }

        ServiceBootstrapPlanTransferSnapshotV1 bootstrap_plan{};
        const ServiceBootstrapPlanTransferSnapshotV1* bootstrap_plan_ptr = nullptr;
        if (runtime->package.bootstrap_plan_count != 0)
        {
            result.package_result = ServiceObjectPackageResolveBootstrapPlanV1(
                &runtime->package, service.service_identity, service.executable_transfer_ref, &bootstrap_plan);
            if (result.package_result.status != ServiceObjectPackageStatus::Ok)
            {
                result.status = ServiceBootstrapStageStatus::BootstrapPlanResolveFailed;
                ResetSlotOutputs(slots, service_count);
                MarkFailed(runtime);
                return result;
            }
            bootstrap_plan_ptr = &bootstrap_plan;
        }

        const ServiceBootstrapSlotStorageV1& slot = slots[manifest_index];
        ServiceBootstrapStageRowV1& row = runtime->rows[manifest_index];
        result = PrepareStagedRow(service, transfer, bootstrap_plan_ptr, manifest_index,
                                  MemoryObjectForManifestIndex(runtime->registry_identity, manifest_index), slot, 0, 1,
                                  &row);
        if (result.status != ServiceBootstrapStageStatus::Ok)
        {
            ResetSlotOutputs(slots, service_count);
            MarkFailed(runtime);
            return result;
        }
        BindBank(&row.banks[0], slot, runtime->registry_identity, row.service_identity, manifest_index, 0);
        row.bank_count = 1;
        row.active_bank_index = 0;
        for (u32 index = 0; index < sizeof(row.reserved_banks); ++index)
            row.reserved_banks[index] = 0;
        ++runtime->ready_count;
    }

    runtime->state = ServiceBootstrapStageState::Ready;
    if (!RuntimeIsCanonical(*runtime))
    {
        result.status = ServiceBootstrapStageStatus::CorruptRuntime;
        ResetSlotOutputs(slots, service_count);
        MarkFailed(runtime);
        return result;
    }
    result.status = ServiceBootstrapStageStatus::Ok;
    result.service_index = kServiceBootstrapNoServiceIndex;
    return result;
}

bool ServiceBootstrapStageBackingQueryV1(loader::ObjectHandle memory_object, u64 object_offset, u64 length,
                                         loader::LoadBackingInfoV1* out_info, void* context)
{
    if (context == nullptr || out_info == nullptr || !MemoryObjectHasBootType(memory_object))
        return false;
    const auto& runtime = *static_cast<const ServiceBootstrapStageRuntimeV1*>(context);
    if (!RuntimeStructureIsCanonical(runtime, false))
        return false;
    const u64 encoded_index = memory_object & kServiceBootstrapMemoryObjectIndexMask;
    const u32 manifest_index = static_cast<u32>(encoded_index - 1u);
    if (manifest_index >= runtime.service_count)
        return false;
    const ServiceBootstrapStageRowV1& row = runtime.rows[manifest_index];
    if (!MemoryObjectMatchesManifestIndex(memory_object, manifest_index) || row.memory_object != memory_object ||
        row.image == nullptr ||
        (row.activation_state != ServiceBootstrapActivationStateV1::Staged &&
         row.activation_state != ServiceBootstrapActivationStateV1::Activating) ||
        !ImageIsSealedPackageOwned(row))
        return false;
    loader::LoadBackingInfoV1 info{};
    if (!loader::LoadImageBackingQuery(memory_object, object_offset, length, &info, row.image))
        return false;
    *out_info = info;
    return true;
}

ServiceBootstrapStageStatus ServiceBootstrapStageInspectV1(const ServiceBootstrapStageRuntimeV1* runtime,
                                                           ServiceBootstrapStageSnapshotV1* snapshot_out)
{
    if (runtime == nullptr || snapshot_out == nullptr)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    *snapshot_out = ServiceBootstrapStageSnapshotV1{runtime->state,
                                                    runtime->version,
                                                    runtime->service_count,
                                                    runtime->ready_count,
                                                    runtime->package.manifest_authority.authority_identity,
                                                    runtime->registry_identity};
    return ServiceBootstrapStageStatus::Ok;
}

ServiceBootstrapStageStatus ServiceBootstrapStageFindServiceV1(const ServiceBootstrapStageRuntimeV1* runtime,
                                                               u64 service_identity,
                                                               ServiceBootstrapServiceSnapshotV1* snapshot_out)
{
    if (runtime == nullptr || snapshot_out == nullptr || service_identity == 0)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    for (u32 index = 0; index < runtime->service_count; ++index)
    {
        const ServiceBootstrapStageRowV1& row = runtime->rows[index];
        if (row.service_identity != service_identity)
            continue;
        *snapshot_out = SnapshotService(row);
        return ServiceBootstrapStageStatus::Ok;
    }
    return ServiceBootstrapStageStatus::NotFound;
}

ServiceBootstrapStageStatus ServiceBootstrapStageBeginActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                   u64 service_identity,
                                                                   ServiceBootstrapActivationLeaseV1* lease_out)
{
    if (runtime == nullptr || lease_out == nullptr || service_identity == 0)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RangeIsValid(runtime, sizeof(*runtime)) || !RangeIsValid(lease_out, sizeof(*lease_out)))
        return ServiceBootstrapStageStatus::InvalidPointerRange;
    if (RangesOverlap(runtime, sizeof(*runtime), lease_out, sizeof(*lease_out)) ||
        RangesOverlap(runtime->rows, sizeof(runtime->rows), lease_out, sizeof(*lease_out)))
        return ServiceBootstrapStageStatus::AliasedStorage;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    if (ActivationLeaseAliasesRetainedStorage(*runtime, lease_out))
        return ServiceBootstrapStageStatus::AliasedStorage;
    ZeroBytes(lease_out, sizeof(*lease_out));

    ServiceBootstrapStageRowV1* selected = nullptr;
    for (u32 index = 0; index < runtime->service_count; ++index)
    {
        if (runtime->rows[index].service_identity == service_identity)
        {
            selected = &runtime->rows[index];
            break;
        }
    }
    if (selected == nullptr)
        return ServiceBootstrapStageStatus::NotFound;
    if (selected->activation_state == ServiceBootstrapActivationStateV1::Activating)
        return ServiceBootstrapStageStatus::ActivationInProgress;
    if (selected->activation_state != ServiceBootstrapActivationStateV1::Staged ||
        !ImageIsSealedPackageOwned(*selected))
    {
        return ServiceBootstrapStageStatus::ActivationTerminal;
    }
    if (selected->activation_generation >= kServiceBootstrapActivationGenerationMaximum)
        return ServiceBootstrapStageStatus::ActivationGenerationExhausted;

    ++selected->activation_generation;
    selected->banks[selected->active_bank_index].activation_generation = selected->activation_generation;
    selected->activation_state = ServiceBootstrapActivationStateV1::Activating;
    lease_out->receipt = ServiceBootstrapActivationReceiptV1{kServiceBootstrapActivationReceiptVersion1,
                                                             selected->manifest_index,
                                                             runtime->registry_identity,
                                                             selected->service_identity,
                                                             selected->activation_generation,
                                                             selected->memory_object};
    lease_out->service = SnapshotService(*selected);
    lease_out->image = selected->image;
    lease_out->frame_allocations = selected->frame_allocations;
    return ServiceBootstrapStageStatus::Ok;
}

ServiceBootstrapStageStatus ServiceBootstrapStageCancelActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                    ServiceBootstrapActivationReceiptV1 receipt)
{
    if (runtime == nullptr)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    if (receipt.manifest_index >= runtime->service_count)
        return ServiceBootstrapStageStatus::InvalidActivationReceipt;
    ServiceBootstrapStageRowV1& row = runtime->rows[receipt.manifest_index];
    if (!ReceiptIsExact(*runtime, row, receipt))
        return ServiceBootstrapStageStatus::InvalidActivationReceipt;
    if (row.activation_state != ServiceBootstrapActivationStateV1::Activating)
        return row.activation_state == ServiceBootstrapActivationStateV1::Staged
                   ? ServiceBootstrapStageStatus::InvalidActivationReceipt
                   : ServiceBootstrapStageStatus::ActivationTerminal;
    if (!ImageIsSealedPackageOwned(row))
        return ServiceBootstrapStageStatus::CannotCancelActivation;
    row.activation_state = ServiceBootstrapActivationStateV1::Staged;
    return ServiceBootstrapStageStatus::Ok;
}

ServiceBootstrapStageStatus ServiceBootstrapStageFinishActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                    ServiceBootstrapActivationReceiptV1 receipt,
                                                                    ServiceBootstrapActivationOutcomeV1 outcome)
{
    if (runtime == nullptr)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    if (receipt.manifest_index >= runtime->service_count)
        return ServiceBootstrapStageStatus::InvalidActivationReceipt;
    ServiceBootstrapStageRowV1& row = runtime->rows[receipt.manifest_index];
    if (!ReceiptIsExact(*runtime, row, receipt))
        return ServiceBootstrapStageStatus::InvalidActivationReceipt;
    if (row.activation_state != ServiceBootstrapActivationStateV1::Activating)
        return row.activation_state == ServiceBootstrapActivationStateV1::Staged
                   ? ServiceBootstrapStageStatus::InvalidActivationReceipt
                   : ServiceBootstrapStageStatus::ActivationTerminal;

    loader::LoadImageSnapshot image_snapshot{};
    if (loader::LoadImageInspect(row.image, &image_snapshot) != loader::LoadImageStatus::Ok)
        return ServiceBootstrapStageStatus::CorruptRuntime;
    switch (outcome)
    {
    case ServiceBootstrapActivationOutcomeV1::TransferredPublished:
        if (row.image->state != loader::LoadImageState::Transferred ||
            !ImageOwnershipIsCanonical(row, loader::LoadImageState::Transferred, image_snapshot))
        {
            return ServiceBootstrapStageStatus::InvalidActivationOutcome;
        }
        row.activation_state = ServiceBootstrapActivationStateV1::TransferredPublished;
        return ServiceBootstrapStageStatus::Ok;
    case ServiceBootstrapActivationOutcomeV1::ConsumedFailed:
        if ((row.image->state != loader::LoadImageState::Transferred &&
             row.image->state != loader::LoadImageState::Failed) ||
            !ImageOwnershipIsCanonical(row, row.image->state, image_snapshot))
        {
            return ServiceBootstrapStageStatus::InvalidActivationOutcome;
        }
        row.activation_state = ServiceBootstrapActivationStateV1::ConsumedFailed;
        return ServiceBootstrapStageStatus::Ok;
    }
    return ServiceBootstrapStageStatus::InvalidActivationOutcome;
}

ServiceBootstrapStageResultV1 ServiceBootstrapStageRestageV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                             u64 service_identity, u64 expected_activation_generation,
                                                             const ServiceBootstrapSlotStorageV1* replacement)
{
    ServiceBootstrapStageResultV1 result = StageResult(ServiceBootstrapStageStatus::Ok);
    if (runtime == nullptr || replacement == nullptr || service_identity == 0)
        return StageResult(ServiceBootstrapStageStatus::NullArgument);
    if (!RangeIsValid(runtime, sizeof(*runtime)) || !RangeIsValid(replacement, sizeof(*replacement)))
        return StageResult(ServiceBootstrapStageStatus::InvalidPointerRange);
    if (RangesOverlap(runtime, sizeof(*runtime), replacement, sizeof(*replacement)))
        return StageResult(ServiceBootstrapStageStatus::AliasedStorage);
    if (!RuntimeStructureIsCanonical(*runtime, false))
    {
        return StageResult(runtime->state == ServiceBootstrapStageState::Ready
                               ? ServiceBootstrapStageStatus::CorruptRuntime
                               : ServiceBootstrapStageStatus::NotReady);
    }

    ServiceObjectPackageManifestV1 manifest{};
    result.package_result = ServiceObjectPackageGetManifestV1(&runtime->package, &manifest);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok || manifest.plan == nullptr)
    {
        result.status = ServiceBootstrapStageStatus::ManifestUnavailable;
        return result;
    }

    ServiceBootstrapStageRowV1* selected = nullptr;
    u32 manifest_index = kServiceBootstrapNoServiceIndex;
    for (u32 index = 0; index < runtime->service_count; ++index)
    {
        if (runtime->rows[index].service_identity != service_identity)
            continue;
        selected = &runtime->rows[index];
        manifest_index = index;
        break;
    }
    if (selected == nullptr)
    {
        result.status = ServiceBootstrapStageStatus::NotFound;
        return result;
    }
    result.service_index = manifest_index;
    if (expected_activation_generation == 0 || expected_activation_generation != selected->activation_generation)
    {
        result.status = ServiceBootstrapStageStatus::StaleActivationGeneration;
        return result;
    }
    if (selected->activation_state == ServiceBootstrapActivationStateV1::Activating)
    {
        result.status = ServiceBootstrapStageStatus::ActivationInProgress;
        return result;
    }
    if (selected->activation_state != ServiceBootstrapActivationStateV1::TransferredPublished &&
        selected->activation_state != ServiceBootstrapActivationStateV1::ConsumedFailed)
    {
        result.status = ServiceBootstrapStageStatus::ActivationNotTerminal;
        return result;
    }
    if (selected->activation_generation >= kServiceBootstrapActivationGenerationMaximum)
    {
        result.status = ServiceBootstrapStageStatus::ActivationGenerationExhausted;
        return result;
    }
    if (!TerminalRowOwnsNoPackageFrames(*selected))
    {
        result.status = ServiceBootstrapStageStatus::TerminalImageOwnsFrames;
        return result;
    }

    u32 replacement_bank_index = kServiceBootstrapNoBankIndexV1;
    bool newly_registered_bank = false;
    result.status = ResolveRestageBank(*selected, *replacement, &replacement_bank_index, &newly_registered_bank);
    if (result.status != ServiceBootstrapStageStatus::Ok)
        return result;

    result.status =
        PreflightRestageSlot(*runtime, replacement, manifest_index, replacement_bank_index, !newly_registered_bank);
    if (result.status != ServiceBootstrapStageStatus::Ok)
        return result;
    // Only an ownership-free bank may enter this row's permanent registry.
    // A foreign terminal bank necessarily has noncanonical image/admission
    // objects and fails before either half is reset.
    if (newly_registered_bank && !SlotShapeIsValid(*replacement))
    {
        result.status = ServiceBootstrapStageStatus::InvalidSlotStorage;
        return result;
    }

    u64 admission_first_identity = 0;
    result.admission_status =
        loader::ExecAdmissionQuiescentSuccessorIdentity(selected->admission, &admission_first_identity);
    if (result.admission_status != loader::ExecAdmissionStatus::Ok)
    {
        result.status = ServiceBootstrapStageStatus::AdmissionRejected;
        return result;
    }

    const ServiceManifestServiceV1& service = manifest.plan->document.services[manifest_index];
    ServiceExecutableTransferSnapshotV1 transfer{};
    result.package_result = ServiceObjectPackageResolveExecutableV1(&runtime->package, selected->service_identity,
                                                                    selected->executable_transfer_ref, &transfer);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok ||
        !HashEquals(transfer.content_hash, selected->expected_source_hash))
    {
        result.status = ServiceBootstrapStageStatus::ExecutableResolveFailed;
        return result;
    }
    ServiceBootstrapPlanTransferSnapshotV1 bootstrap_plan{};
    const ServiceBootstrapPlanTransferSnapshotV1* bootstrap_plan_ptr = nullptr;
    if (runtime->package.bootstrap_plan_count != 0)
    {
        result.package_result = ServiceObjectPackageResolveBootstrapPlanV1(
            &runtime->package, selected->service_identity, selected->executable_transfer_ref, &bootstrap_plan);
        if (result.package_result.status != ServiceObjectPackageStatus::Ok)
        {
            result.status = ServiceBootstrapStageStatus::BootstrapPlanResolveFailed;
            return result;
        }
        bootstrap_plan_ptr = &bootstrap_plan;
    }

    const u64 backing_registry_identity = MintRegistryIdentity();
    if (backing_registry_identity == 0)
    {
        result.status = ServiceBootstrapStageStatus::IdentityExhausted;
        return result;
    }
    const loader::ObjectHandle replacement_memory_object =
        MemoryObjectForManifestIndex(backing_registry_identity, manifest_index);
    if (replacement_memory_object == selected->memory_object)
    {
        result.status = ServiceBootstrapStageStatus::IdentityExhausted;
        return result;
    }

    result.status = ResetRetiredRestageSlot(*replacement);
    if (result.status != ServiceBootstrapStageStatus::Ok)
        return result;

    ServiceBootstrapStageRowV1 prepared{};
    result = PrepareStagedRow(service, transfer, bootstrap_plan_ptr, manifest_index, replacement_memory_object,
                              *replacement, selected->activation_generation, admission_first_identity, &prepared);
    if (result.status != ServiceBootstrapStageStatus::Ok)
        return result;
    CopyBankRegistry(&prepared, *selected);
    if (newly_registered_bank)
    {
        BindBank(&prepared.banks[replacement_bank_index], *replacement, runtime->registry_identity,
                 selected->service_identity, manifest_index, selected->activation_generation);
        ++prepared.bank_count;
    }
    prepared.active_bank_index = static_cast<u8>(replacement_bank_index);
    prepared.banks[replacement_bank_index].activation_generation = selected->activation_generation;
    if (!RowStructureIsCanonical(prepared, service, manifest_index, runtime->registry_identity, true))
    {
        result.status = ServiceBootstrapStageStatus::CorruptRuntime;
        ResetPreparedRowOrMarkCorrupt(&prepared, &result);
        return result;
    }

    // Final commit: every fallible parser, hash, allocation, admission, and
    // quiescence check has completed. The retired active bank remains terminal
    // and is reset only if a later call supplies it as the inactive bank.
    AdoptPreparedRow(selected, prepared);
    result.status = ServiceBootstrapStageStatus::Ok;
    result.service_index = manifest_index;
    return result;
}

ServiceBootstrapStageStatus ServiceBootstrapStageDiscardV1(ServiceBootstrapStageRuntimeV1* runtime)
{
    if (runtime == nullptr)
        return ServiceBootstrapStageStatus::NullArgument;
    if (!RuntimeStructureIsCanonical(*runtime, false))
        return runtime->state == ServiceBootstrapStageState::Ready ? ServiceBootstrapStageStatus::CorruptRuntime
                                                                   : ServiceBootstrapStageStatus::NotReady;
    for (u32 index = 0; index < runtime->service_count; ++index)
    {
        if (runtime->rows[index].activation_state != ServiceBootstrapActivationStateV1::Staged ||
            !ImageIsSealedPackageOwned(runtime->rows[index]))
        {
            return ServiceBootstrapStageStatus::CannotDiscard;
        }
    }
    for (u32 index = 0; index < runtime->service_count; ++index)
    {
        ServiceBootstrapStageRowV1& row = runtime->rows[index];
        for (u32 bank_index = 0; bank_index < row.bank_count; ++bank_index)
        {
            const ServiceBootstrapSlotStorageV1& bank = row.banks[bank_index].storage;
            if (!ResetImageAndAdmission(bank.image, bank.admission))
                return ServiceBootstrapStageStatus::CorruptRuntime;
        }
    }

    ZeroBytes(&runtime->package, sizeof(runtime->package));
    ZeroBytes(runtime->rows, sizeof(runtime->rows));
    runtime->state = ServiceBootstrapStageState::Discarded;
    ZeroBytes(runtime->reserved8, sizeof(runtime->reserved8));
    runtime->version = kServiceBootstrapStageVersion1;
    runtime->service_count = 0;
    runtime->ready_count = 0;
    runtime->registry_identity = 0;
    return ServiceBootstrapStageStatus::Ok;
}

#if !defined(DUETOS_HOST_TEST)
static_assert(generated::kBootServicePackageArtifactsResolved);
static_assert(generated::kBootServicePackageAuthorityBound);
static_assert(generated::kBootServicePackageBootstrapPlansBound);
static_assert(!generated::kBootServicePackageProcessPublicationBound);
static_assert(!generated::kBootServicePackageEndpointReadinessBound);
static_assert(!generated::kBootServicePackageActivationReady);

u32 ServiceBootstrapGeneratedServiceCountV1()
{
    return generated::kBootServicePackageArtifactCount;
}

ServiceBootstrapStageResultV1 ServiceBootstrapStageGeneratedV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                               const ServiceBootstrapSlotStorageV1* slots,
                                                               u32 slot_capacity)
{
    return ServiceBootstrapStageInitializeV1(runtime, &generated::kBootServicePackageDefinition, slots, slot_capacity);
}
#endif

const char* ServiceBootstrapStageStatusName(ServiceBootstrapStageStatus status)
{
    switch (status)
    {
    case ServiceBootstrapStageStatus::Ok:
        return "ok";
    case ServiceBootstrapStageStatus::NullArgument:
        return "null-argument";
    case ServiceBootstrapStageStatus::InvalidPointerRange:
        return "invalid-pointer-range";
    case ServiceBootstrapStageStatus::AliasedStorage:
        return "aliased-storage";
    case ServiceBootstrapStageStatus::NonCanonicalRuntime:
        return "non-canonical-runtime";
    case ServiceBootstrapStageStatus::PackageRejected:
        return "package-rejected";
    case ServiceBootstrapStageStatus::ManifestUnavailable:
        return "manifest-unavailable";
    case ServiceBootstrapStageStatus::SlotCapacityTooSmall:
        return "slot-capacity-too-small";
    case ServiceBootstrapStageStatus::InvalidSlotStorage:
        return "invalid-slot-storage";
    case ServiceBootstrapStageStatus::SlotStorageOverlap:
        return "slot-storage-overlap";
    case ServiceBootstrapStageStatus::IdentityExhausted:
        return "identity-exhausted";
    case ServiceBootstrapStageStatus::UnsupportedServiceKind:
        return "unsupported-service-kind";
    case ServiceBootstrapStageStatus::ExecutableResolveFailed:
        return "executable-resolve-failed";
    case ServiceBootstrapStageStatus::BootstrapPlanResolveFailed:
        return "bootstrap-plan-resolve-failed";
    case ServiceBootstrapStageStatus::ElfStageRejected:
        return "elf-stage-rejected";
    case ServiceBootstrapStageStatus::ResourceBudgetExceeded:
        return "resource-budget-exceeded";
    case ServiceBootstrapStageStatus::PlanUnavailable:
        return "plan-unavailable";
    case ServiceBootstrapStageStatus::BootstrapPlanMismatch:
        return "bootstrap-plan-mismatch";
    case ServiceBootstrapStageStatus::AdmissionRejected:
        return "admission-rejected";
    case ServiceBootstrapStageStatus::CorruptRuntime:
        return "corrupt-runtime";
    case ServiceBootstrapStageStatus::NotReady:
        return "not-ready";
    case ServiceBootstrapStageStatus::NotFound:
        return "not-found";
    case ServiceBootstrapStageStatus::CannotDiscard:
        return "cannot-discard";
    case ServiceBootstrapStageStatus::ActivationInProgress:
        return "activation-in-progress";
    case ServiceBootstrapStageStatus::ActivationTerminal:
        return "activation-terminal";
    case ServiceBootstrapStageStatus::ActivationGenerationExhausted:
        return "activation-generation-exhausted";
    case ServiceBootstrapStageStatus::InvalidActivationReceipt:
        return "invalid-activation-receipt";
    case ServiceBootstrapStageStatus::CannotCancelActivation:
        return "cannot-cancel-activation";
    case ServiceBootstrapStageStatus::InvalidActivationOutcome:
        return "invalid-activation-outcome";
    case ServiceBootstrapStageStatus::ActivationNotTerminal:
        return "activation-not-terminal";
    case ServiceBootstrapStageStatus::StaleActivationGeneration:
        return "stale-activation-generation";
    case ServiceBootstrapStageStatus::TerminalImageOwnsFrames:
        return "terminal-image-owns-frames";
    }
    return "unknown";
}

} // namespace duetos::core
