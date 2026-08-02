#include "display_engine.h"

#include "duet/syscall.h"
#include "unistd.h"

#include <stdint.h>

static void* AllocateWritableStorage(uint64_t bytes)
{
    uint64_t out_base = 0;
    long status;

    /* Engine state cannot live in the native app image's R+X PT_LOAD. */
    __asm__ volatile("mov %[allocation_type], %%r10\n\t"
                     "mov %[protect], %%r8\n\t"
                     "mov %[out_base], %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : [syscall_number] "a"((long)DUET_SYS_VM_ALLOCATE), [process_handle] "D"(-1L), [base_hint] "S"(0L),
                       [byte_count] "d"((long)bytes), [allocation_type] "r"(0x3000L), [protect] "r"(0x04L),
                       [out_base] "r"((long)(uintptr_t)&out_base)
                     : "r10", "r8", "r9", "rcx", "r11", "memory");
    return status == 0 && out_base != 0 ? (void*)(uintptr_t)out_base : (void*)0;
}

static int InitializeDormantEngine(DisplaydEngine* engine)
{
    DisplaydEngineInstanceIdentity instance = {0};
    const int pid = getpid();

    if (pid <= 0)
        return 0;

    /*
     * Process-private self-check identity only.  No endpoint or DisplayMaster
     * lease is asserted, and the engine is terminally drained before return.
     */
    instance.service_identity = DISPLAYD_ENGINE_SERVICE_IDENTITY;
    instance.instance_generation = 1;
    instance.process.identity = UINT64_C(0x44524d4e50524f43); /* "DRMNPROC" */
    instance.process.pid = (uint64_t)pid;
    instance.published_endpoint_epoch = UINT64_C(0x44524d4e45504348); /* "DRMNEPCH" */
    instance.service_slot = 0;

    if (DisplaydEngineInitialize(engine, &instance, 1, 1, 1) != DISPLAYD_ENGINE_OK)
        return 0;
    if (DisplaydEngineBeginDrain(engine) != DISPLAYD_ENGINE_OK)
        return 0;
    return DisplaydEngineFinishDrain(engine) == DISPLAYD_ENGINE_OK;
}

static void ParkWithoutEndpoint(void)
{
    static const char kBlocked[] = "[displayd] dormant: DisplayMaster/ServiceEndpoint ingress unavailable\n";
    (void)write(STDERR_FILENO, kBlocked, sizeof(kBlocked) - 1U);

    /*
     * STUB: the native ABI cannot receive an authenticated endpoint channel,
     * transferred surfaces/input, or the revocable DisplayMaster lease yet.
     */
    for (;;)
        duet_sleep_ms(1000UL);
}

int main(void)
{
    DisplaydEngine* engine = (DisplaydEngine*)AllocateWritableStorage(sizeof(DisplaydEngine));

    if (engine == (DisplaydEngine*)0 || !InitializeDormantEngine(engine))
        return 72;

    ParkWithoutEndpoint();
    return 0;
}
