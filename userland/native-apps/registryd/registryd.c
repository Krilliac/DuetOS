/*
 * Build/package artifact for the future registryd process.
 *
 * Registry store ownership, WAL recovery, and authenticated endpoint transfer
 * have not crossed the kernel boundary.  This binary therefore touches no
 * storage, publishes no readiness, and exits with a service-unique failure
 * code if launched.  It supplies deterministic freestanding ELF bytes only.
 */

int main(void)
{
    return 73;
}
