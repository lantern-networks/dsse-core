/* Portable security decisions; the driver supplies WFP-owned evidence. */
#ifndef DSSE_CAPTIVE_ADMISSION_H
#define DSSE_CAPTIVE_ADMISSION_H
/* Microsoft REAUTHORIZE_REASON bit values (fwptypes.h). Unknown reasons and
 * CLASSIFY_COMPLETION, even mixed with a policy-change bit, are not proof that
 * the initial connection was ever admitted. */
static int dsseCaptiveExistingReason(unsigned int reauthorize, unsigned int reason,
    unsigned long long flow, unsigned long long endpoint)
{
    const unsigned int established = 0x01u | 0x02u | 0x04u | 0x08u | 0x20u | 0x40u | 0x80u;
    return reauthorize && flow && endpoint && reason &&
        !(reason & ~established) && !(reason & 0x10u);
}
/* ALE represents ICMP type/code in the local/remote port fields. These are
 * network control, not a general ICMP, DNS, browser or bypass-app exception. */
static int dsseCaptiveNetworkControl(unsigned int family, unsigned int protocol,
    unsigned int localPort, unsigned int remotePort)
{
    if (protocol == 17) {
        if (family == 2) return (localPort == 68 && remotePort == 67) ||
            (localPort == 67 && remotePort == 68);
        if (family == 23) return (localPort == 546 && remotePort == 547) ||
            (localPort == 547 && remotePort == 546);
    }
    if (family == 23 && protocol == 58) {
        /* Errors/PMTU, MLD, router/neighbor discovery. Never echo (128/129). */
        return (localPort >= 1 && localPort <= 4) ||
            (localPort >= 130 && localPort <= 136) || localPort == 143;
    }
    return family == 2 && protocol == 1 && localPort == 3 && remotePort == 4;
}
#endif
