#include "supervisor.h"

#include "duet/service_control.h"
#include "duet/syscall.h"
#include "unistd.h"

#include <stdint.h>

/*
 * This manifest is a process-private dormant engine fixture, not the
 * authenticated boot manifest.  Its single non-autostart row keeps the policy
 * engine in a valid, non-reconciled state without requesting a lifecycle
 * transition.  The future endpoint adapter must replace it with the exact
 * kernel-attested manifest before serviced can own desired state.
 */
static const ServicedSupervisorManifest kDormantManifest = {
    .manifest_identity = UINT64_C(0x44524d4e54535631), /* "DRMNTSV1" */
    .manifest_generation = 1,
    .service_count = 1,
    .services = {{.service_identity = UINT64_C(0x44524d4e53564331), /* "DRMNSVC1" */
                  .service_slot = 0,
                  .restart_policy = SERVICED_RESTART_NEVER,
                  .autostart = 0}}};

static void* AllocateWritableStorage(uint64_t bytes)
{
    uint64_t out_base = 0;
    long status;

    /*
     * Native apps intentionally place their image in one R+X PT_LOAD.  Keep
     * mutable engine state in a separate RW+NX self mapping instead of trying
     * to write .bss.  SYS_VM_ALLOCATE is cap-free for the current process.
     */
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

static void ParkWithoutEndpoint(void)
{
    static const char kBlocked[] = "[serviced] dormant: authenticated lifecycle/ServiceEndpoint ingress unavailable\n";
    (void)write(STDERR_FILENO, kBlocked, sizeof(kBlocked) - 1U);

    /*
     * STUB: the native ABI has no authenticated LifecycleBroker snapshot/event
     * or ServiceEndpoint accept/receive/ack operations yet.  Sleeping keeps a
     * premature launch fail-closed without creating a supervisor restart loop.
     */
    for (;;)
        duet_sleep_ms(1000UL);
}

int main(void)
{
    ServicedSupervisor* supervisor = (ServicedSupervisor*)AllocateWritableStorage(sizeof(ServicedSupervisor));

    if (supervisor == (ServicedSupervisor*)0 ||
        ServicedSupervisorInitialize(supervisor, &kDormantManifest) != SERVICED_SUPERVISOR_OK)
        return 70;

    (void)duet_service_mark_ready();

    ParkWithoutEndpoint();
    return 0;
}
