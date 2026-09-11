/*
 * driver.c — Dsse WFP steering callout driver (P2). Registers an ALE_CONNECT_REDIRECT callout for
 * IPv4 and IPv6; at connect-time it classifies each new connection with race-free identity (PID/app id),
 * and either lets it go direct (bypass policy) or REDIRECTS it to the local userspace proxy
 * (127.0.0.1:LocalPort / [::1]:LocalPort), stashing the ORIGINAL destination + PID in a redirect context
 * the proxy reads back via SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. Policy is pushed from userspace via
 * IOCTL. See and dsse_wfp.h (shared contract).
 *
 * STATUS: P2 = authored to compile + sign. Runtime load/redirect correctness is validated at P3 (needs
 * Secure Boot off + a self-signed test cert on this box).
 */

#include <ntddk.h>
#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>          /* NET_BUFFER_LIST etc. used by fwpsk.h prototypes */
#define INITGUID
#include <guiddef.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2ipdef.h>      /* SOCKADDR_IN / SOCKADDR_IN6 */
#include <wdmsec.h>        /* IoCreateDeviceSecure + SDDL_DEVOBJ_* (link wdmsec.lib) */
#include "dsse_wfp.h"

/* Fixed GUIDs for our sublayer + callouts (arbitrary but stable). */
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E01}
DEFINE_GUID(DSSE_SUBLAYER_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x01);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E02}
DEFINE_GUID(DSSE_CALLOUT_V4_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x02);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E03}
DEFINE_GUID(DSSE_CALLOUT_V6_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x03);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E04}  provider for FwpsRedirectHandleCreate
DEFINE_GUID(DSSE_PROVIDER_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x04);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E09}  custom device class GUID for the secure control device (no registry
// entry => the IoCreateDeviceSecure SDDL is authoritative and cannot be overridden by class security).
DEFINE_GUID(DSSE_DEVCLASS_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x09);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E05}  QUIC-gate callout (ALE_AUTH_CONNECT_V4)
DEFINE_GUID(DSSE_QUIC_CALLOUT_V4_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x05);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E06}  QUIC-gate callout (ALE_AUTH_CONNECT_V6)
DEFINE_GUID(DSSE_QUIC_CALLOUT_V6_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x06);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E07}   inbound (server-initiated) callout (ALE_AUTH_RECV_ACCEPT_V4)
DEFINE_GUID(DSSE_INBOUND_CALLOUT_V4_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x07);
// {7E1B2C40-9A3D-4E2F-9C11-0A1B2C3D4E08}   inbound (server-initiated) callout (ALE_AUTH_RECV_ACCEPT_V6)
DEFINE_GUID(DSSE_INBOUND_CALLOUT_V6_GUID, 0x7e1b2c40, 0x9a3d, 0x4e2f, 0x9c, 0x11, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x08);

#define DSSE_TAG 'ESSD'

static HANDLE g_engine = NULL;
static HANDLE g_redirectHandle = NULL;
static UINT32 g_calloutV4 = 0;
static UINT32 g_calloutV6 = 0;
static UINT32 g_quicCalloutV4 = 0;
static UINT32 g_quicCalloutV6 = 0;
static UINT32 g_inboundCalloutV4 = 0;
static UINT32 g_inboundCalloutV6 = 0;
static PDEVICE_OBJECT g_device = NULL;

static DSSE_POLICY g_policy;       /* protected by g_policyLock */
static KSPIN_LOCK g_policyLock;
static BOOLEAN g_policyValid = FALSE;

/* The handle that OWNS the redirect policy, and what its close should do. Both protected by g_policyLock.
 *
 * Before this existed, g_policyValid was cleared by exactly one thing: an explicit IOCTL_DSSE_CLEAR_POLICY
 * from userspace (plus driver unload). Every route to that IOCTL runs in the agent — its Close(), the
 * fail-open onDisarm, --mode recover — so an agent that CRASHED, was TerminateProcess'd by an installer's
 * files-in-use handling, or lost power left the redirect armed with nothing listening on the target port.
 * That is not fail-open; every connection is refused. It ends when a human arrives.
 *
 * Handle close is the one cleanup Windows performs no matter how a process dies, which is why ownership is
 * expressed as a handle rather than a heartbeat or a timer.
 *
 * g_policyDisarmOnExit is deliberately NOT hardcoded to TRUE — see DSSE_OWNER_ARM in dsse_wfp.h. A
 * fail-closed endpoint is supposed to stop passing traffic when its agent is gone. */
static PFILE_OBJECT g_policyOwner = NULL;
static BOOLEAN g_policyDisarmOnExit = FALSE;

static DSSE_STATS g_stats;         /* read-only diagnostics; counters bumped via InterlockedIncrement */
#define DSSE_BUMP(field) InterlockedIncrement((volatile LONG*)&g_stats.field)

static DSSE_OBSERVATION g_obs[DSSE_MAX_OBS]; /* ObserveOnly ring; protected by g_obsLock */
static UINT32 g_obsHead = 0;       /* next write slot */
static UINT32 g_obsCount = 0;      /* unread records */
static KSPIN_LOCK g_obsLock;

/*  inbound (server-initiated) state. Separate blob/lock from the outbound policy so the inbound path
 * never perturbs the existing connect-redirect/QUIC behaviour. */
static DSSE_INBOUND_POLICY g_inPolicy;   /* protected by g_inLock */
static KSPIN_LOCK g_inLock;
static BOOLEAN g_inPolicyValid = FALSE;

static DSSE_INBOUND_OBSERVATION g_inObs[DSSE_MAX_INBOUND_OBS]; /* inbound observe ring; g_inObsLock */
static UINT32 g_inObsHead = 0;
static UINT32 g_inObsCount = 0;
static KSPIN_LOCK g_inObsLock;

/* dsseRecordObs: append a would-be-steered flow to the observe ring (overwrites oldest when full). */
static void dsseRecordObs(const DSSE_REDIRECT_CONTEXT* c)
{
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_obsLock, &lq);
    DSSE_OBSERVATION* o = &g_obs[g_obsHead];
    o->Family = c->Family;
    o->ProcessId = c->ProcessId;
    RtlCopyMemory(o->RemoteAddr, c->OrigDstAddr, 16);
    o->RemotePort = c->OrigDstPort;
    o->_pad = 0;
    g_obsHead = (g_obsHead + 1) % DSSE_MAX_OBS;
    if (g_obsCount < DSSE_MAX_OBS) g_obsCount++;
    KeReleaseInStackQueuedSpinLock(&lq);
}

/* dsseRecordInboundObs: append an observed inbound (server-initiated) flow to the inbound observe ring. */
static void dsseRecordInboundObs(const DSSE_INBOUND_OBSERVATION* rec)
{
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_inObsLock, &lq);
    g_inObs[g_inObsHead] = *rec;
    g_inObsHead = (g_inObsHead + 1) % DSSE_MAX_INBOUND_OBS;
    if (g_inObsCount < DSSE_MAX_INBOUND_OBS) g_inObsCount++;
    KeReleaseInStackQueuedSpinLock(&lq);
}

/* --- process-creation notification --------------------------------------------------------------------
 *
 * The driver is the only component that learns of a process AT CREATION. Userspace previously discovered
 * candidates for signature-form exclusions by scanning running processes every 30 seconds, which a
 * five-second process is never present for — so `signed:winget.exe` enforced nothing while reporting itself
 * effective. These events close that gap; see dsse_wfp.h and
 * docs/2026-08-06_signature_exclusions_process_notify_design.ja.md.
 *
 * Cost when unused is one predictable branch: nothing is queued until userspace has actually asked for
 * events at least once (g_procWanted), so a deployment with no signature rules never pays for the ring. */
static DSSE_PROC_EVENT g_procEvents[DSSE_MAX_PROC_EVENTS]; /* ring; protected by g_procLock */
static UINT32 g_procHead = 0;          /* next write slot */
static UINT32 g_procCount = 0;         /* unread records */
static UINT32 g_procDropped = 0;       /* overflow counter, reported to userspace and then cleared */
static KSPIN_LOCK g_procLock;
static KEVENT g_procEvt;               /* synchronization event: signalled when a record is queued */
static BOOLEAN g_procWanted = FALSE;   /* set once userspace asks; gates the callback body */
static BOOLEAN g_procRegistered = FALSE;
static volatile LONG g_procHoldMs = 0; /* 0 = never hold. Set from the wait IOCTL by userspace. */

/* One in-flight hold. The creating thread parks on Evt until userspace releases this pid or the wait times
 * out. Slots are a fixed array rather than an allocation so the creation path cannot fail on memory. */
typedef struct _DSSE_PROC_HOLD {
    volatile LONG InUse;
    UINT32 ProcessId;
    KEVENT Evt;
} DSSE_PROC_HOLD;
static DSSE_PROC_HOLD g_procHolds[DSSE_MAX_PROC_HOLDS];
static KSPIN_LOCK g_holdLock;
/* The file object of the long-poll waiter that armed the hold. Only its CLOSE disarms; the agent opens and
 * closes this device for every policy push, so any-CLOSE would flap the hold. Guarded by g_holdLock. */
static PFILE_OBJECT g_procWaitOwner = NULL;

/* dsseAcquireHold: reserve a slot for this pid, or NULL when all are busy (then we simply do not hold —
 * fail-open, the app is still discovered from its first steered flow). */
static DSSE_PROC_HOLD* dsseAcquireHold(UINT32 pid)
{
    KLOCK_QUEUE_HANDLE lq;
    DSSE_PROC_HOLD* got = NULL;
    KeAcquireInStackQueuedSpinLock(&g_holdLock, &lq);
    for (UINT32 i = 0; i < DSSE_MAX_PROC_HOLDS; i++) {
        if (g_procHolds[i].InUse == 0) {
            g_procHolds[i].InUse = 1;
            g_procHolds[i].ProcessId = pid;
            KeClearEvent(&g_procHolds[i].Evt);
            got = &g_procHolds[i];
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lq);
    return got;
}

static void dsseReleaseHold(DSSE_PROC_HOLD* h)
{
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_holdLock, &lq);
    h->ProcessId = 0;
    h->InUse = 0;
    KeReleaseInStackQueuedSpinLock(&lq);
}

/* dsseSignalHold: userspace has finished with this pid. No-op when the hold already timed out and freed. */
static void dsseSignalHold(UINT32 pid)
{
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_holdLock, &lq);
    for (UINT32 i = 0; i < DSSE_MAX_PROC_HOLDS; i++) {
        if (g_procHolds[i].InUse != 0 && g_procHolds[i].ProcessId == pid) {
            KeSetEvent(&g_procHolds[i].Evt, IO_NO_INCREMENT, FALSE);
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lq);
}

/* dsseProcessNotify: PsSetCreateProcessNotifyRoutineEx callback. Runs at PASSIVE_LEVEL in the context of the
 * CREATING thread, so it must be short and must never block — it copies the image path and signals. It does
 * NOT delay process creation: holding every process launch behind a userspace round-trip would mean a hung
 * agent stops the machine from starting anything, which is a worse failure than the one being fixed. */
static void dsseProcessNotify(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);
    if (createInfo == NULL) return;      /* process EXIT: membership is a property of the image, not the pid */
    if (!g_procWanted) return;           /* nobody is listening */

    /* Capture the pid in a LOCAL. The ring slot below is shared state: once the lock is dropped another
     * concurrent creation may reuse that slot, so reading e->ProcessId afterwards would race and could hold
     * the wrong process. */
    const UINT32 pid = (UINT32)(ULONG_PTR)processId;

    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_procLock, &lq);
    DSSE_PROC_EVENT* e = &g_procEvents[g_procHead];
    RtlZeroMemory(e, sizeof(*e));
    e->ProcessId = pid;
    if (createInfo->ImageFileName != NULL && createInfo->ImageFileName->Buffer != NULL) {
        SIZE_T chars = createInfo->ImageFileName->Length / sizeof(WCHAR);
        if (chars > DSSE_EXACT_APP_LEN - 1) chars = DSSE_EXACT_APP_LEN - 1;
        RtlCopyMemory(e->ImagePath, createInfo->ImageFileName->Buffer, chars * sizeof(WCHAR));
        e->ImagePath[chars] = L'\0';
    }
    g_procHead = (g_procHead + 1) % DSSE_MAX_PROC_EVENTS;
    if (g_procCount < DSSE_MAX_PROC_EVENTS) {
        g_procCount++;
    } else {
        /* Overflow overwrites the OLDEST. A dropped event costs one steered flow — the userspace
         * learn-on-steer path still catches the app — and can never cause a wrong bypass. Counted, and
         * reported to userspace, because a silently lossy channel is how the original defect hid. */
        g_procDropped++;
    }
    KeReleaseInStackQueuedSpinLock(&lq);

    /* Reserve the hold BEFORE waking userspace, so a verdict can never arrive before there is a slot to
     * signal. Nothing below may fail the creation: every branch either waits briefly or returns. */
    LONG holdMs = g_procHoldMs;
    DSSE_PROC_HOLD* hold = (holdMs > 0) ? dsseAcquireHold(pid) : NULL;

    KeSetEvent(&g_procEvt, IO_NO_INCREMENT, FALSE);

    if (hold != NULL) {
        /* Hold the creating thread until userspace has pushed this image's verdict into the exact-APP_ID
         * table, so the decision exists before the process runs its first instruction — and therefore before
         * any connect can be classified. Bounded and non-alertable: a stalled agent costs holdMs of latency
         * on one launch, never the launch itself. */
        LARGE_INTEGER timeout;
        timeout.QuadPart = -((LONGLONG)holdMs * 10000); /* ms -> 100ns, relative */
        NTSTATUS w = KeWaitForSingleObject(&hold->Evt, UserRequest, KernelMode, FALSE, &timeout);
        if (w == STATUS_TIMEOUT) {
            /* No verdict in time: this image's first flow will be steered and userspace learns it from that
             * flow. Counted, because "how often does the guarantee actually hold" must be answerable — a
             * feature born from a silent failure does not get to add a silent window of its own. */
            DSSE_BUMP(ProcHoldTimeouts);
        }
        dsseReleaseHold(hold);
    }
}

/* dsseDrainProcEvents: copy up to max queued events into out, returning the count and the dropped tally
 * accumulated since the last drain. Caller must be at PASSIVE_LEVEL. */
static UINT32 dsseDrainProcEvents(DSSE_PROC_EVENT* out, UINT32 max, UINT32* dropped)
{
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_procLock, &lq);
    UINT32 n = g_procCount < max ? g_procCount : max;
    /* The ring holds g_procCount records ending at g_procHead-1; walk them oldest-first. */
    UINT32 start = (g_procHead + DSSE_MAX_PROC_EVENTS - g_procCount) % DSSE_MAX_PROC_EVENTS;
    for (UINT32 i = 0; i < n; i++) {
        out[i] = g_procEvents[(start + i) % DSSE_MAX_PROC_EVENTS];
    }
    g_procCount -= n;
    *dropped = g_procDropped;
    g_procDropped = 0;
    KeReleaseInStackQueuedSpinLock(&lq);
    return n;
}

/* inboundRuleAllows: TRUE if {srcNet (network order), localPort (host order), proto} matches an allow rule.
 * Runs under g_inLock. LocalPort/Protocol 0 in a rule = wildcard. Source match is by IP only (race-free;
 * userspace already resolved any hostname to IP before pushing). */
static BOOLEAN inboundRuleAllows(UINT32 family, const UINT8* srcNet16, UINT16 localPortHost, UINT16 proto)
{
    for (UINT32 i = 0; i < g_inPolicy.NumRules && i < DSSE_MAX_INBOUND_RULES; i++) {
        const DSSE_INBOUND_RULE* r = &g_inPolicy.Rules[i];
        if (r->Action != 1) continue;            /* only allow rules can permit */
        if (r->Family != family) continue;
        SIZE_T alen = (family == DSSE_AF_INET) ? 4 : 16;
        if (RtlCompareMemory(r->SrcAddr, srcNet16, alen) != alen) continue;
        if (r->LocalPort != 0 && r->LocalPort != localPortHost) continue;
        if (r->Protocol != 0 && r->Protocol != proto) continue;
        return TRUE;
    }
    return FALSE;
}

/* --- policy evaluation (runs inside classify) --------------------------------------------------------- */

/* asciiSubInWidePathCI: case-insensitive search for an ASCII substring inside a UTF-16 path (the WFP app
 * id is the image path in NT-device form, UTF-16). Mirrors the WinDivert backend's image-substring match. */
static BOOLEAN asciiSubInWidePathCI(const wchar_t* path, SIZE_T pathChars, const char* sub)
{
    SIZE_T subLen = 0;
    while (sub[subLen] != '\0' && subLen < DSSE_APP_SUB_LEN) subLen++;
    if (subLen == 0 || subLen > pathChars) return FALSE;
    for (SIZE_T i = 0; i + subLen <= pathChars; i++) {
        SIZE_T j = 0;
        for (; j < subLen; j++) {
            wchar_t pc = path[i + j];
            char sc = sub[j];
            /* lowercase ASCII range only */
            if (pc >= L'A' && pc <= L'Z') pc = (wchar_t)(pc - L'A' + L'a');
            if ((wchar_t)sc != pc) break;
        }
        if (j == subLen) return TRUE;
    }
    return FALSE;
}

/* isLoopbackV4/V6: TRUE for 127.0.0.0/8 and ::1. The redirect target itself is 127.0.0.1/::1, so the
 * redirected proxy hop is re-classified here with a loopback remote; it MUST fall through as a direct
 * PERMIT. Relying only on FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED is not enough -- if that flag is ever
 * missed the proxy hop gets redirected onto itself, the stack detects the redirect loop and tears the
 * ORIGINAL connect down with STATUS_ACCESS_DENIED (WSAEACCES) and no classify-drop event. */
static BOOLEAN isLoopbackV4(UINT32 remoteHostOrder)
{
    return (remoteHostOrder >> 24) == 127;
}

static BOOLEAN isLoopbackV6(const UINT8* a)
{
    if (a == NULL) return FALSE;
    for (int i = 0; i < 15; i++) {
        if (a[i] != 0) return FALSE;
    }
    return a[15] == 1;
}

/* bypassByApp: TRUE if the connecting app's image path matches any never-redirect substring. */
static BOOLEAN bypassByApp(const FWP_BYTE_BLOB* appId)
{
    if (appId == NULL || appId->data == NULL || appId->size < sizeof(wchar_t)) return FALSE;
    const wchar_t* path = (const wchar_t*)appId->data;
    SIZE_T chars = appId->size / sizeof(wchar_t);
    for (UINT32 a = 0; a < g_policy.NumApps && a < DSSE_MAX_APPS; a++) {
        if (asciiSubInWidePathCI(path, chars, (const char*)g_policy.Apps[a])) return TRUE;
    }
    return FALSE;
}

/* bypassByExactAppId: TRUE if the connecting app's ALE_APP_ID EXACTLY matches a verified NT device path that
 * userspace pushed after Authenticode-verifying the binary's signer identity (subject:/thumbprint:/...). Exact,
 * case-insensitive (proper Unicode via RtlEqualUnicodeString) — unspoofable by path substring games, and the
 * entry only exists because userspace cryptographically verified that on-disk binary. This is what gives the WFP
 * kernel backend macOS-AppID-level strength: identity verified in userspace, enforced by exact APP_ID here. */
static BOOLEAN bypassByExactAppId(const FWP_BYTE_BLOB* appId)
{
    if (appId == NULL || appId->data == NULL || appId->size < sizeof(wchar_t)) return FALSE;
    SIZE_T bytes = appId->size;
    /* drop a trailing NUL if the blob carries one, so Length is the pure string length */
    const wchar_t* p = (const wchar_t*)appId->data;
    if (bytes >= sizeof(wchar_t) && p[bytes / sizeof(wchar_t) - 1] == L'\0') bytes -= sizeof(wchar_t);
    if (bytes == 0 || bytes > 0xFFFE) return FALSE; /* UNICODE_STRING.Length is USHORT */
    UNICODE_STRING got;
    got.Buffer = (PWCH)appId->data;
    got.Length = (USHORT)bytes;
    got.MaximumLength = (USHORT)bytes;
    for (UINT32 i = 0; i < g_policy.NumExactApps && i < DSSE_MAX_EXACT_APPS; i++) {
        if (g_policy.ExactApps[i][0] == L'\0') continue;
        UNICODE_STRING want;
        RtlInitUnicodeString(&want, g_policy.ExactApps[i]); /* NUL-terminated entry */
        if (want.Length != 0 && RtlEqualUnicodeString(&got, &want, TRUE)) return TRUE;
    }
    return FALSE;
}

/* bypassByAnyApp: substring (legacy) OR exact verified-identity (strong) app bypass. */
static BOOLEAN bypassByAnyApp(const FWP_BYTE_BLOB* appId)
{
    return bypassByApp(appId) || bypassByExactAppId(appId);
}

/* bypassByDestV4 / V6: TRUE if remote addr:port matches a never-redirect dest rule. remoteV4 is host order
 * (as WFP delivers IP_REMOTE_ADDRESS for v4); rule.Addr is network order. port is host order both sides.
 * A rule Port of 0 is a wildcard = bypass ALL ports to that destination (whole-host exception, e.g. a domain
 * controller whose dynamic RPC uses ephemeral ports). */
static BOOLEAN bypassByDestV4(UINT32 remoteHostOrder, UINT16 port)
{
    for (UINT32 d = 0; d < g_policy.NumDests && d < DSSE_MAX_DESTS; d++) {
        if (g_policy.Dests[d].Family != DSSE_AF_INET) continue;
        UINT32 ruleNet = *(UINT32*)g_policy.Dests[d].Addr;       /* network order bytes */
        UINT32 ruleHost = RtlUlongByteSwap(ruleNet);             /* -> host order */
        if (ruleHost != remoteHostOrder) continue;
        if (g_policy.Dests[d].Port == 0 || g_policy.Dests[d].Port == port) return TRUE;
    }
    return FALSE;
}

static BOOLEAN bypassByDestV6(const UINT8* remoteAddr16Net, UINT16 port)
{
    for (UINT32 d = 0; d < g_policy.NumDests && d < DSSE_MAX_DESTS; d++) {
        if (g_policy.Dests[d].Family != DSSE_AF_INET6) continue;
        if (g_policy.Dests[d].Port != 0 && g_policy.Dests[d].Port != port) continue;
        if (RtlCompareMemory(g_policy.Dests[d].Addr, remoteAddr16Net, 16) == 16) return TRUE;
    }
    return FALSE;
}

/* --- the callout ------------------------------------------------------------------------------------- */

static void NTAPI DsseClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }
    DSSE_BUMP(ClassifyCalls);
    classifyOut->actionType = FWP_ACTION_PERMIT; /* default: let it through unmodified */

    BOOLEAN isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6);
    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_policyLock, &lq);

    if (!g_policyValid) {
        KeReleaseInStackQueuedSpinLock(&lq);
        DSSE_BUMP(NoPolicy);
        return; /* no policy yet: do nothing */
    }

    /* Identity (race-free at connect-time). */
    const FWP_BYTE_BLOB* appId = NULL;
    UINT16 remotePort = 0;
    UINT32 remoteV4 = 0;
    const UINT8* remoteV6 = NULL;
    UINT32 flags = 0;

    if (isV6) {
        appId = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID].value.byteBlob;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16;
        remoteV6 = (const UINT8*)inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        flags = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_FLAGS].value.uint32;
    } else {
        appId = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID].value.byteBlob;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
        remoteV4 = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        flags = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS].value.uint32;
    }

    /* Never re-redirect a flow we already redirected (loop guard), and skip reauthorize. */
    if ((flags & FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED) || (flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE)) {
        KeReleaseInStackQueuedSpinLock(&lq);
        DSSE_BUMP(SkippedRedirectedReauth);
        return;
    }

    /* Bypass policy (race-free identity). Loopback first: never steer the proxy hop back onto itself. */
    BOOLEAN bypass = isV6 ? isLoopbackV6(remoteV6) : isLoopbackV4(remoteV4);
    /* Never steer DNS (port 53). The steer/edge datapath is a TCP TLS proxy and cannot serve UDP/53, so
     * redirecting DNS there breaks all name resolution (the box can't resolve anything while steering).
     * TLS flows still expose the hostname via SNI at the edge, so DNS steering is not needed for hostname
     * policy; DNS-layer policy is the edge resolver's job (), not this connect-redirect callout. */
    if (!bypass && remotePort == 53) bypass = TRUE;
    if (!bypass) bypass = bypassByAnyApp(appId);
    if (!bypass) {
        bypass = isV6 ? bypassByDestV6(remoteV6, remotePort) : bypassByDestV4(remoteV4, remotePort);
    }
    UINT16 localPort = g_policy.LocalPort;
    UINT32 proxyPid = g_policy.ProxyPid;
    BOOLEAN observeOnly = (g_policy.ObserveOnly != 0);

    /* Snapshot original destination for the redirect context before releasing the lock. */
    DSSE_REDIRECT_CONTEXT ctxSnap;
    RtlZeroMemory(&ctxSnap, sizeof(ctxSnap));
    ctxSnap.Version = DSSE_REDIRECT_CTX_VERSION;
    ctxSnap.OrigDstPort = remotePort;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        ctxSnap.ProcessId = (UINT32)inMetaValues->processId;
    }
    if (isV6) {
        ctxSnap.Family = DSSE_AF_INET6;
        RtlCopyMemory(ctxSnap.OrigDstAddr, remoteV6, 16);
    } else {
        ctxSnap.Family = DSSE_AF_INET;
        UINT32 net = RtlUlongByteSwap(remoteV4); /* host -> network order bytes */
        RtlCopyMemory(ctxSnap.OrigDstAddr, &net, 4);
    }
    KeReleaseInStackQueuedSpinLock(&lq);

    if (bypass) {
        if (isV6 ? isLoopbackV6(remoteV6) : isLoopbackV4(remoteV4)) DSSE_BUMP(BypassLoopback);
        else DSSE_BUMP(BypassAppOrDest);
        return; /* PERMIT, no redirect */
    }

    /* Observe-only (discovery/audit): record what WOULD be steered, then PERMIT direct -- never redirect. */
    if (observeOnly) {
        dsseRecordObs(&ctxSnap);
        return;
    }
    DSSE_BUMP(RedirectAttempts);

    /* Redirect to the local proxy. Acquiring writable connect-request data at the ALE_CONNECT_REDIRECT
     * layer requires a CLASSIFY HANDLE obtained from FwpsAcquireClassifyHandle -- the raw classifyContext
     * pointer is NOT itself the handle. (Passing classifyContext directly makes
     * FwpsAcquireWritableLayerDataPointer fail, silently dropping the redirect.) */
    UINT64 classifyHandle = 0;
    NTSTATUS status = FwpsAcquireClassifyHandle((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        g_stats.LastAcquireHandleStatus = (int)status;
        DSSE_BUMP(AcquireHandleFail);
        return;
    }
    FWPS_CONNECT_REQUEST* connectRequest = NULL;
    status = FwpsAcquireWritableLayerDataPointer(
        classifyHandle, filter->filterId, 0,
        (PVOID*)&connectRequest, classifyOut);
    if (!NT_SUCCESS(status) || connectRequest == NULL) {
        g_stats.LastAcquireWritableStatus = (int)status;
        DSSE_BUMP(AcquireWritableFail);
        FwpsReleaseClassifyHandle(classifyHandle);
        return;
    }

    /* Allocate the redirect context buffer that the proxy will read back. */
    DSSE_REDIRECT_CONTEXT* ctx = (DSSE_REDIRECT_CONTEXT*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DSSE_REDIRECT_CONTEXT), DSSE_TAG);
    if (ctx == NULL) {
        DSSE_BUMP(AllocFail);
        FwpsApplyModifiedLayerData(classifyHandle, connectRequest, 0);
        FwpsReleaseClassifyHandle(classifyHandle);
        return;
    }
    *ctx = ctxSnap;

    /* Point the connection at the loopback proxy. */
    if (isV6) {
        PSOCKADDR_IN6 sin6 = (PSOCKADDR_IN6)&connectRequest->remoteAddressAndPort;
        RtlZeroMemory(sin6, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr.u.Byte[15] = 1; /* ::1 (no in6addr_loopback global in kernel) */
        sin6->sin6_port = RtlUshortByteSwap(localPort);
    } else {
        PSOCKADDR_IN sin = (PSOCKADDR_IN)&connectRequest->remoteAddressAndPort;
        RtlZeroMemory(sin, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_addr.S_un.S_addr = 0x0100007f; /* 127.0.0.1 in network order */
        sin->sin_port = RtlUshortByteSwap(localPort);
    }

    /* REQUIRED for a localhost redirect: tell the framework which local process will accept the redirected
     * connection. Without this the redirect to 127.0.0.1/::1 is not completed and the connect fails
     * STATUS_ACCESS_DENIED (IS_CONNECTION_REDIRECTED never gets set). */
    connectRequest->localRedirectTargetPID = proxyPid;
    connectRequest->localRedirectHandle = g_redirectHandle;
    connectRequest->localRedirectContext = ctx;
    connectRequest->localRedirectContextSize = sizeof(DSSE_REDIRECT_CONTEXT);

    /* Commit the redirect FIRST, then set the action. NOTE: do NOT clear FWPS_RIGHT_ACTION_WRITE here --
     * at ALE_CONNECT_REDIRECT a hard-permit that strips the write right can make the framework reject the
     * proxy redirect (original connect fails STATUS_ACCESS_DENIED, IS_CONNECTION_REDIRECTED never set).
     * Standard connect-redirect just applies the modified data and PERMITs. */
    FwpsApplyModifiedLayerData(classifyHandle, connectRequest, 0);
    FwpsReleaseClassifyHandle(classifyHandle);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    DSSE_BUMP(RedirectApplied);
}

static NTSTATUS NTAPI DsseNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* DsseQuicClassify: QUIC (UDP/443) gate at ALE_AUTH_CONNECT. Only BLOCK when we are actively steering AND
 * the connecting app is NOT on the bypass list -- so QUIC is forced to TCP (interceptable) for steered apps,
 * while bypassed apps (e.g. the agent itself) keep QUIC, and QUIC is untouched when no policy is loaded.
 * The filter conditions restrict this callout to UDP/443, so every invocation is a QUIC attempt. */
static void NTAPI DsseQuicClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    BOOLEAN isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);
    const FWP_BYTE_BLOB* appId = isV6
        ? inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob
        : inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob;

    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_policyLock, &lq);
    BOOLEAN steering = g_policyValid;
    BOOLEAN bypassed = steering ? bypassByAnyApp(appId) : FALSE;
    KeReleaseInStackQueuedSpinLock(&lq);

    if (!steering || bypassed) {
        classifyOut->actionType = FWP_ACTION_CONTINUE; /* don't interfere: let this app's QUIC through */
        return;
    }
    classifyOut->actionType = FWP_ACTION_BLOCK;        /* steered app: kill QUIC -> TCP fallback -> intercept */
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

/* DsseInboundClassify:  server-initiated (inbound) gate at ALE_AUTH_RECV_ACCEPT_V4/V6. The remote
 * address here is the INITIATING server (the lateral-movement source); the local port identifies the
 * service (service_family). Behaviour is driven by the inbound policy's Enforce flag:
 *   - no inbound policy pushed  -> PERMIT, no record (inbound path is inert; outbound is unaffected).
 *   - Enforce==0 (S3a observe)  -> record the flow, PERMIT (prove we can see inbound, traffic passes).
 *   - Enforce==1 (S3b enforce)  -> record + match allow rules; matched => PERMIT, else BLOCK (default deny).
 * Loopback inbound (local services) is always permitted and never recorded. This callout makes a PERMIT/BLOCK
 * terminating decision -- it does NOT touch the redirect handle or any outbound state. */
static void NTAPI DsseInboundClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT; /* default: pass unless we actively deny */

    BOOLEAN isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    UINT16 remotePort = 0, localPort = 0, proto = 0;
    UINT32 remoteV4 = 0;
    const UINT8* remoteV6 = NULL;

    if (isV6) {
        remoteV6   = (const UINT8*)inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
        localPort  = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        proto      = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
    } else {
        remoteV4   = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
        localPort  = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        proto      = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
    }

    BOOLEAN loopback = isV6 ? isLoopbackV6(remoteV6) : isLoopbackV4(remoteV4);

    /* Source address in NETWORK order (for rule match + observation), matching wfpInboundRule.SrcAddr. */
    UINT8 srcNet[16];
    UINT32 family;
    RtlZeroMemory(srcNet, sizeof(srcNet));
    if (isV6) {
        family = DSSE_AF_INET6;
        if (remoteV6) RtlCopyMemory(srcNet, remoteV6, 16);
    } else {
        family = DSSE_AF_INET;
        UINT32 net = RtlUlongByteSwap(remoteV4); /* host -> network order bytes */
        RtlCopyMemory(srcNet, &net, 4);
    }

    KLOCK_QUEUE_HANDLE lq;
    KeAcquireInStackQueuedSpinLock(&g_inLock, &lq);
    BOOLEAN valid = g_inPolicyValid;
    BOOLEAN enforce = valid ? (g_inPolicy.Enforce != 0) : FALSE;
    BOOLEAN block = FALSE;
    if (valid && enforce && !loopback) {
        block = !inboundRuleAllows(family, srcNet, localPort, proto);
    }
    KeReleaseInStackQueuedSpinLock(&lq);

    if (!valid) {
        return; /* no inbound policy: inbound path inert (PERMIT, no record) */
    }
    if (loopback) {
        return; /* local service traffic: always permit, never record */
    }

    /* Record the observed inbound flow (observe + enforce both record, for audit/baseline). */
    DSSE_INBOUND_OBSERVATION rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.Family = family;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        rec.ProcessId = (UINT32)inMetaValues->processId;
    }
    RtlCopyMemory(rec.RemoteAddr, srcNet, 16);
    rec.RemotePort = remotePort;
    rec.LocalPort = localPort;
    rec.Protocol = proto;
    rec.Action = block ? 1 : 0;
    dsseRecordInboundObs(&rec);

    if (block) {
        classifyOut->actionType = FWP_ACTION_BLOCK; /* default-deny: refuse the server-initiated connection */
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

/* --- WFP setup / teardown ----------------------------------------------------------------------------- */

static NTSTATUS dsseRegisterQuicCallout(PDEVICE_OBJECT device, const GUID* calloutGuid, const GUID* applicableLayer, UINT32* outId)
{
    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = *calloutGuid;
    callout.classifyFn = DsseQuicClassify;
    callout.notifyFn = DsseNotify;
    callout.flowDeleteFn = NULL;
    NTSTATUS status = FwpsCalloutRegister(device, &callout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT mCallout = { 0 };
    mCallout.calloutKey = *calloutGuid;
    mCallout.displayData.name = L"DsseQuicGateCallout";
    mCallout.applicableLayer = *applicableLayer;
    return FwpmCalloutAdd(g_engine, &mCallout, NULL, NULL);
}

/* dsseRegisterInboundCallout: register the  server-initiated callout for an ALE_AUTH_RECV_ACCEPT layer
 * (PERMIT/BLOCK classify; no redirect). Mirrors dsseRegisterQuicCallout. */
static NTSTATUS dsseRegisterInboundCallout(PDEVICE_OBJECT device, const GUID* calloutGuid, const GUID* applicableLayer, UINT32* outId)
{
    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = *calloutGuid;
    callout.classifyFn = DsseInboundClassify;
    callout.notifyFn = DsseNotify;
    callout.flowDeleteFn = NULL;
    NTSTATUS status = FwpsCalloutRegister(device, &callout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT mCallout = { 0 };
    mCallout.calloutKey = *calloutGuid;
    mCallout.displayData.name = L"DsseInboundCallout";
    mCallout.applicableLayer = *applicableLayer;
    return FwpmCalloutAdd(g_engine, &mCallout, NULL, NULL);
}

static NTSTATUS dsseRegisterCallout(PDEVICE_OBJECT device, const GUID* calloutGuid, UINT16 layerId, UINT32* outId)
{
    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = *calloutGuid;
    callout.classifyFn = DsseClassify;
    callout.notifyFn = DsseNotify;
    callout.flowDeleteFn = NULL;
    NTSTATUS status = FwpsCalloutRegister(device, &callout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT mCallout = { 0 };
    mCallout.calloutKey = *calloutGuid;
    mCallout.displayData.name = L"DsseSteerCallout";
    mCallout.applicableLayer = (layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6)
        ? FWPM_LAYER_ALE_CONNECT_REDIRECT_V6 : FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    return FwpmCalloutAdd(g_engine, &mCallout, NULL, NULL);
}

static NTSTATUS dsseAddFilter(const GUID* calloutGuid, const GUID* layerKey, const wchar_t* name)
{
    /* Scope the connect-redirect callout to TCP only. Without a protocol condition the filter matches ALL
     * protocols, so the callout fires on UDP too — including DHCP (UDP 67/68, source 0.0.0.0). A
     * connect-redirect classify on the DHCP client's send breaks the DHCP DORA exchange, leaving an interface
     * (typically a multi-homed STANDBY link) stuck on an APIPA 169.254 address with no lease — so it can never
     * take over on failover. The callout only ever redirects TCP (QUIC/UDP:443 has its own gate callout; all
     * other UDP — DHCP, NetBIOS, mDNS — must be left untouched), so UDP has no business reaching it. This
     * mirrors dsseAddInboundFilter, which is already TCP-scoped for the same reason. */
    FWPM_FILTER_CONDITION cond = { 0 };
    cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_UINT8;
    cond.conditionValue.uint8 = 6; /* IPPROTO_TCP */

    FWPM_FILTER filter = { 0 };
    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)name;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; /* callout always makes a terminating decision
        (PERMIT, or PERMIT+redirect); CALLOUT_UNKNOWN does not commit the connect-request modification as a
        registered redirect, so the framework never sets IS_CONNECTION_REDIRECTED and fails the connect. */
    filter.action.calloutKey = *calloutGuid;
    filter.subLayerKey = DSSE_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY; /* auto weight */
    filter.numFilterConditions = 1; /* TCP only — keep UDP (esp. DHCP) entirely out of the callout */
    filter.filterCondition = &cond;
    return FwpmFilterAdd(g_engine, &filter, NULL, NULL);
}

/* dsseAddQuicBlockFilter: route UDP/443 (QUIC / HTTP-3) at ALE_AUTH_CONNECT to the QUIC-gate callout, which
 * blocks only steered (non-bypassed) apps so they fall back to interceptable TCP/443. Our connect-redirect
 * callout is TCP-only, so unblocked QUIC would silently bypass steering. The conditions scope the callout to
 * UDP/443 exactly (loopback/DNS/other ports/protocols are untouched). */
static NTSTATUS dsseAddQuicBlockFilter(const GUID* calloutGuid, const GUID* layerKey, const wchar_t* name)
{
    FWPM_FILTER_CONDITION conds[2] = { 0 };
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = 17; /* IPPROTO_UDP */
    conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = 443;

    FWPM_FILTER filter = { 0 };
    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)name;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; /* the gate callout decides block vs continue */
    filter.action.calloutKey = *calloutGuid;
    filter.subLayerKey = DSSE_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY; /* auto weight */
    filter.numFilterConditions = 2;
    filter.filterCondition = conds;
    return FwpmFilterAdd(g_engine, &filter, NULL, NULL);
}

/* dsseAddInboundFilter: bind the inbound (server-initiated) callout to TCP only at ALE_AUTH_RECV_ACCEPT.
 *  governs server-initiated TCP lateral-movement protocols (SMB/RDP/WinRM/RPC/SSH/...). Scoping the
 * filter to IPPROTO_TCP keeps UDP (NetBIOS/mDNS) and ICMPv6 (neighbour discovery) entirely out of the
 * callout, so default-deny enforcement can never break IPv6 ND / name resolution. */
static NTSTATUS dsseAddInboundFilter(const GUID* calloutGuid, const GUID* layerKey, const wchar_t* name)
{
    FWPM_FILTER_CONDITION cond = { 0 };
    cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_UINT8;
    cond.conditionValue.uint8 = 6; /* IPPROTO_TCP */

    FWPM_FILTER filter = { 0 };
    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)name;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; /* callout returns PERMIT/BLOCK */
    filter.action.calloutKey = *calloutGuid;
    filter.subLayerKey = DSSE_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY; /* auto weight */
    filter.numFilterConditions = 1;
    filter.filterCondition = &cond;
    return FwpmFilterAdd(g_engine, &filter, NULL, NULL);
}

static NTSTATUS dsseWfpSetup(PDEVICE_OBJECT device)
{
    NTSTATUS status;
    FWPM_SESSION session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; /* auto-cleanup on handle close */
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engine);
    if (!NT_SUCCESS(status)) return status;

    status = FwpsRedirectHandleCreate(&DSSE_PROVIDER_GUID, 0, &g_redirectHandle);
    if (!NT_SUCCESS(status)) return status;

    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.subLayerKey = DSSE_SUBLAYER_GUID;
    sublayer.displayData.name = L"DsseSteerSublayer";
    sublayer.weight = 0x8000;
    status = FwpmSubLayerAdd(g_engine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) return status;

    status = dsseRegisterCallout(device, &DSSE_CALLOUT_V4_GUID, FWPS_LAYER_ALE_CONNECT_REDIRECT_V4, &g_calloutV4);
    if (!NT_SUCCESS(status)) return status;
    status = dsseRegisterCallout(device, &DSSE_CALLOUT_V6_GUID, FWPS_LAYER_ALE_CONNECT_REDIRECT_V6, &g_calloutV6);
    if (!NT_SUCCESS(status)) return status;

    status = dsseAddFilter(&DSSE_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, L"DsseSteerV4");
    if (!NT_SUCCESS(status)) return status;
    status = dsseAddFilter(&DSSE_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, L"DsseSteerV6");
    if (!NT_SUCCESS(status)) return status;

    /* QUIC gate: register the callouts, then bind them to UDP/443 at ALE_AUTH_CONNECT. The callout blocks
     * QUIC only for steered (non-bypassed) apps, so browsers fall back to interceptable TCP/443. */
    status = dsseRegisterQuicCallout(device, &DSSE_QUIC_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &g_quicCalloutV4);
    if (!NT_SUCCESS(status)) return status;
    status = dsseRegisterQuicCallout(device, &DSSE_QUIC_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &g_quicCalloutV6);
    if (!NT_SUCCESS(status)) return status;
    status = dsseAddQuicBlockFilter(&DSSE_QUIC_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"DsseQuicGateV4");
    if (!NT_SUCCESS(status)) return status;
    status = dsseAddQuicBlockFilter(&DSSE_QUIC_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"DsseQuicGateV6");
    if (!NT_SUCCESS(status)) return status;

    /*  inbound (server-initiated) gate: register the callouts at ALE_AUTH_RECV_ACCEPT and add an
     * all-flows filter (the callout decides PERMIT/BLOCK; it stays inert until an inbound policy is pushed). */
    status = dsseRegisterInboundCallout(device, &DSSE_INBOUND_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &g_inboundCalloutV4);
    if (!NT_SUCCESS(status)) return status;
    status = dsseRegisterInboundCallout(device, &DSSE_INBOUND_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &g_inboundCalloutV6);
    if (!NT_SUCCESS(status)) return status;
    status = dsseAddInboundFilter(&DSSE_INBOUND_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, L"DsseInboundV4");
    if (!NT_SUCCESS(status)) return status;
    status = dsseAddInboundFilter(&DSSE_INBOUND_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, L"DsseInboundV6");
    return status;
}

static void dsseWfpTeardown(void)
{
    /* Teardown order is load-bearing (gets this wrong -> 0x50 on unload):
     *  1. Close the engine FIRST. The dynamic session auto-removes our filters (+ sublayer +
     *     FwpmCallout entries), so no NEW connection can reach DsseClassify.
     *  2. THEN FwpsCalloutUnregisterById: with no filter still referencing the callout it no longer
     *     returns STATUS_DEVICE_BUSY, and it drains any in-flight classify before it returns.
     *  3. THEN destroy the redirect handle: safe only now that no classify can still be touching it.
     * (Old order unregistered callouts while filters still referenced them -> DEVICE_BUSY left the
     *  kernel callout registered against about-to-be-unloaded code = dangling classifyFn on next
     *  connect; and it freed g_redirectHandle out from under an in-flight classify.) */
    if (g_engine) { FwpmEngineClose(g_engine); g_engine = NULL; }
    if (g_calloutV4) { FwpsCalloutUnregisterById(g_calloutV4); g_calloutV4 = 0; }
    if (g_calloutV6) { FwpsCalloutUnregisterById(g_calloutV6); g_calloutV6 = 0; }
    if (g_quicCalloutV4) { FwpsCalloutUnregisterById(g_quicCalloutV4); g_quicCalloutV4 = 0; }
    if (g_quicCalloutV6) { FwpsCalloutUnregisterById(g_quicCalloutV6); g_quicCalloutV6 = 0; }
    if (g_inboundCalloutV4) { FwpsCalloutUnregisterById(g_inboundCalloutV4); g_inboundCalloutV4 = 0; }
    if (g_inboundCalloutV6) { FwpsCalloutUnregisterById(g_inboundCalloutV6); g_inboundCalloutV6 = 0; }
    if (g_redirectHandle) { FwpsRedirectHandleDestroy(g_redirectHandle); g_redirectHandle = NULL; }
}

/* --- IOCTL control channel ---------------------------------------------------------------------------- */

static NTSTATUS dsseDispatchCreateClose(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    if (sp->MajorFunction == IRP_MJ_CLOSE) {
        /* DISARM the process-creation hold when the handle that ARMED it goes away. Nothing else clears
         * g_procHoldMs, so an agent that crashes or is stopped while a signature rule is active would leave
         * every process launch on the machine paying the full timeout — nobody is left to return a verdict —
         * and nothing would say why. Bounded, but silently bounded, which is the failure mode this whole
         * feature exists to stop producing.
         *
         * It must be THAT handle specifically. The agent opens and closes this device for every policy push,
         * so disarming on any CLOSE would flap the hold off and on continuously and make the guarantee
         * depend on timing. Only the long-poll waiter's file object counts.
         *
         * Re-arming is automatic: the long-poll IOCTL carries WaitBlockMs on every call, so a live agent
         * restores the hold on its very next poll. */
        KLOCK_QUEUE_HANDLE lq;
        BOOLEAN owner = FALSE;
        KeAcquireInStackQueuedSpinLock(&g_holdLock, &lq);
        if (g_procWaitOwner != NULL && g_procWaitOwner == sp->FileObject) {
            g_procWaitOwner = NULL;
            owner = TRUE;
        }
        KeReleaseInStackQueuedSpinLock(&lq);
        if (owner) {
            InterlockedExchange(&g_procHoldMs, 0);
            for (UINT32 i = 0; i < DSSE_MAX_PROC_HOLDS; i++) {
                KeSetEvent(&g_procHolds[i].Evt, IO_NO_INCREMENT, FALSE);
            }
        }

        /* Same shape, applied to the thing whose absence actually takes the box off the network: the redirect
         * policy. When the handle that nominated itself via IOCTL_DSSE_ARM_OWNER closes — for ANY reason,
         * including a crash or a kill, because the OS closes handles unconditionally on process death — the
         * agent that was accepting the redirected connections is gone.
         *
         * Whether that clears the policy is the endpoint's install-time posture, carried in DisarmOnExit:
         *   fail-open   -> clear it. The box loses steering and keeps its network.
         *   fail-closed -> leave it armed. The box refuses connections. That is the chosen meaning of
         *                  fail-closed, not an oversight, and this driver must not quietly overrule it.
         * Ownership is always released either way, so PolicyArmed && !OwnerPresent is a truthful, readable
         * state for a watchdog and for an operator: "armed, with nobody behind it". */
        KLOCK_QUEUE_HANDLE plq;
        BOOLEAN clearPolicy = FALSE;
        KeAcquireInStackQueuedSpinLock(&g_policyLock, &plq);
        if (g_policyOwner != NULL && g_policyOwner == sp->FileObject) {
            g_policyOwner = NULL;
            clearPolicy = g_policyDisarmOnExit;
            g_policyDisarmOnExit = FALSE;
            if (clearPolicy) {
                g_policyValid = FALSE;
                RtlZeroMemory(&g_policy, sizeof(g_policy));
            }
        }
        KeReleaseInStackQueuedSpinLock(&plq);
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS dsseDispatchDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_DSSE_SET_POLICY: {
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(DSSE_POLICY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        DSSE_POLICY* in = (DSSE_POLICY*)irp->AssociatedIrp.SystemBuffer;
        if (in->Version != DSSE_POLICY_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_policyLock, &lq);
        RtlCopyMemory(&g_policy, in, sizeof(DSSE_POLICY));
        g_policyValid = TRUE;
        KeReleaseInStackQueuedSpinLock(&lq);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_CLEAR_POLICY: {
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_policyLock, &lq);
        g_policyValid = FALSE;
        RtlZeroMemory(&g_policy, sizeof(DSSE_POLICY));
        KeReleaseInStackQueuedSpinLock(&lq);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_ARM_OWNER: {
        /* Nominate THIS handle as the policy's owner. See DSSE_OWNER_ARM in dsse_wfp.h. Idempotent: the agent
         * re-arms on reconnect, and a new handle simply replaces the old owner (the old one's close then finds
         * itself no longer the owner and does nothing, which is the correct outcome — the policy now belongs
         * to the live handle). */
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(DSSE_OWNER_ARM)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        DSSE_OWNER_ARM* in = (DSSE_OWNER_ARM*)irp->AssociatedIrp.SystemBuffer;
        if (in->Version != DSSE_OWNER_ARM_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_policyLock, &lq);
        g_policyOwner = sp->FileObject;
        g_policyDisarmOnExit = (in->DisarmOnExit != 0);
        KeReleaseInStackQueuedSpinLock(&lq);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_GET_STATS: {
        if (sp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DSSE_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        /* The counters are lock-free (bumped from the classify path); the STATE block is read under
         * g_policyLock so a caller never sees "armed" together with a half-written port/pid. Filled into a
         * local copy rather than into g_stats, because g_stats is shared and this is a read. */
        DSSE_STATS out = g_stats;
        out.Version = DSSE_STATS_VERSION;
        KLOCK_QUEUE_HANDLE slq;
        KeAcquireInStackQueuedSpinLock(&g_policyLock, &slq);
        out.PolicyArmed = g_policyValid ? 1u : 0u;
        out.PolicyProxyPid = g_policyValid ? g_policy.ProxyPid : 0u;
        out.PolicyLocalPort = (unsigned short)(g_policyValid ? g_policy.LocalPort : 0);
        out.PolicyObserveOnly = (unsigned short)((g_policyValid && g_policy.ObserveOnly) ? 1 : 0);
        out.OwnerPresent = (g_policyOwner != NULL) ? 1u : 0u;
        out.OwnerDisarmOnExit = g_policyDisarmOnExit ? 1u : 0u;
        KeReleaseInStackQueuedSpinLock(&slq);
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &out, sizeof(DSSE_STATS));
        info = sizeof(DSSE_STATS);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_WAIT_PROC_EVENTS: {
        /* Long-poll, not a drain-poll: block until a process is created or the timeout expires. The 30-second
         * scan this replaces is exactly why signature exclusions missed short-lived processes. The wait is
         * BOUNDED so a stalled or killed agent never leaves a thread parked in the kernel indefinitely; on
         * timeout it returns zero events and the caller re-issues. Output: [count][dropped][events...]. */
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if (outLen < 2 * sizeof(UINT32)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        g_procWanted = TRUE; /* first call arms the callback body */
        /* Userspace declares how long it may hold a creating process. 0 (or no input) = never hold, which is
         * the posture whenever no signature-form rule is active — an ordinary deployment then pays nothing at
         * process creation. */
        if (sp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(DSSE_PROC_WAIT_REQUEST)) {
            DSSE_PROC_WAIT_REQUEST* req = (DSSE_PROC_WAIT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
            LONG ms = (LONG)req->WaitBlockMs;
            if (ms < 0) ms = 0;
            if (ms > 1000) ms = 1000; /* hard ceiling: never let a policy value stall launches for seconds */
            InterlockedExchange(&g_procHoldMs, ms);
            /* Remember WHO armed it, so only this handle's CLOSE disarms (see dsseDispatchCreateClose). */
            KLOCK_QUEUE_HANDLE olq;
            KeAcquireInStackQueuedSpinLock(&g_holdLock, &olq);
            g_procWaitOwner = sp->FileObject;
            KeReleaseInStackQueuedSpinLock(&olq);
        }
        UINT8* out = (UINT8*)irp->AssociatedIrp.SystemBuffer;
        UINT32 cap = (UINT32)((outLen - 2 * sizeof(UINT32)) / sizeof(DSSE_PROC_EVENT));

        BOOLEAN empty;
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_procLock, &lq);
        empty = (g_procCount == 0);
        KeReleaseInStackQueuedSpinLock(&lq);
        if (empty && cap > 0) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -20000000; /* 2s, relative */
            (void)KeWaitForSingleObject(&g_procEvt, UserRequest, KernelMode, FALSE, &timeout);
        }

        UINT32 dropped = 0;
        UINT32 n = (cap > 0) ? dsseDrainProcEvents((DSSE_PROC_EVENT*)(out + 2 * sizeof(UINT32)), cap, &dropped) : 0;
        RtlCopyMemory(out, &n, sizeof(UINT32));
        RtlCopyMemory(out + sizeof(UINT32), &dropped, sizeof(UINT32));
        info = 2 * sizeof(UINT32) + (ULONG_PTR)n * sizeof(DSSE_PROC_EVENT);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_SET_APP_VERDICT: {
        /* Userspace has finished deciding this pid and (if it matched) has already pushed the exact-APP_ID
         * table. Releasing the creating thread here is what makes the decision precede the process's first
         * instruction — and therefore precede any connect. */
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(DSSE_APP_VERDICT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        DSSE_APP_VERDICT* v = (DSSE_APP_VERDICT*)irp->AssociatedIrp.SystemBuffer;
        dsseSignalHold(v->ProcessId); /* unknown pid = already timed out; a no-op, not an error */
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_GET_OBSERVATIONS: {
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if (outLen < sizeof(UINT32)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        UINT8* out = (UINT8*)irp->AssociatedIrp.SystemBuffer;
        UINT32 cap = (UINT32)((outLen - sizeof(UINT32)) / sizeof(DSSE_OBSERVATION));
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_obsLock, &lq);
        UINT32 n = (g_obsCount < cap) ? g_obsCount : cap;
        UINT32 idx = (g_obsHead + DSSE_MAX_OBS - g_obsCount) % DSSE_MAX_OBS; /* oldest unread */
        for (UINT32 i = 0; i < n; i++) {
            RtlCopyMemory(out + sizeof(UINT32) + i * sizeof(DSSE_OBSERVATION), &g_obs[idx], sizeof(DSSE_OBSERVATION));
            idx = (idx + 1) % DSSE_MAX_OBS;
        }
        g_obsCount -= n; /* drained the oldest n */
        KeReleaseInStackQueuedSpinLock(&lq);
        *(UINT32*)out = n;
        info = sizeof(UINT32) + n * sizeof(DSSE_OBSERVATION);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_SET_INBOUND_POLICY: {
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(DSSE_INBOUND_POLICY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        DSSE_INBOUND_POLICY* in = (DSSE_INBOUND_POLICY*)irp->AssociatedIrp.SystemBuffer;
        if (in->Version != DSSE_INBOUND_POLICY_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_inLock, &lq);
        RtlCopyMemory(&g_inPolicy, in, sizeof(DSSE_INBOUND_POLICY));
        if (g_inPolicy.NumRules > DSSE_MAX_INBOUND_RULES) g_inPolicy.NumRules = DSSE_MAX_INBOUND_RULES;
        g_inPolicyValid = TRUE;
        KeReleaseInStackQueuedSpinLock(&lq);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_CLEAR_INBOUND_POLICY: {
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_inLock, &lq);
        g_inPolicyValid = FALSE;
        RtlZeroMemory(&g_inPolicy, sizeof(DSSE_INBOUND_POLICY));
        KeReleaseInStackQueuedSpinLock(&lq);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DSSE_GET_INBOUND_OBSERVATIONS: {
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if (outLen < sizeof(UINT32)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        UINT8* out = (UINT8*)irp->AssociatedIrp.SystemBuffer;
        UINT32 cap = (UINT32)((outLen - sizeof(UINT32)) / sizeof(DSSE_INBOUND_OBSERVATION));
        KLOCK_QUEUE_HANDLE lq;
        KeAcquireInStackQueuedSpinLock(&g_inObsLock, &lq);
        UINT32 n = (g_inObsCount < cap) ? g_inObsCount : cap;
        UINT32 idx = (g_inObsHead + DSSE_MAX_INBOUND_OBS - g_inObsCount) % DSSE_MAX_INBOUND_OBS; /* oldest unread */
        for (UINT32 i = 0; i < n; i++) {
            RtlCopyMemory(out + sizeof(UINT32) + i * sizeof(DSSE_INBOUND_OBSERVATION), &g_inObs[idx], sizeof(DSSE_INBOUND_OBSERVATION));
            idx = (idx + 1) % DSSE_MAX_INBOUND_OBS;
        }
        g_inObsCount -= n;
        KeReleaseInStackQueuedSpinLock(&lq);
        *(UINT32*)out = n;
        info = sizeof(UINT32) + n * sizeof(DSSE_INBOUND_OBSERVATION);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* --- DriverEntry / Unload ----------------------------------------------------------------------------- */

static void DsseUnload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    /* Unregister FIRST: the callback touches g_proc* state, so it must be provably quiescent before anything
     * else is torn down. PsSetCreateProcessNotifyRoutineEx(Remove=TRUE) waits for in-flight callbacks. */
    /* Stop holding first, and release anyone already parked: a thread waiting on a hold must never be left
     * behind by an unload. Clearing the interval before unregistering means no NEW hold can start. */
    InterlockedExchange(&g_procHoldMs, 0);
    for (UINT32 i = 0; i < DSSE_MAX_PROC_HOLDS; i++) {
        KeSetEvent(&g_procHolds[i].Evt, IO_NO_INCREMENT, FALSE);
    }
    if (g_procRegistered) {
        PsSetCreateProcessNotifyRoutineEx(dsseProcessNotify, TRUE);
        g_procRegistered = FALSE;
    }
    dsseWfpTeardown();
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, DSSE_WFP_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g_device) { IoDeleteDevice(g_device); g_device = NULL; }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver, _In_ PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    NTSTATUS status;

    KeInitializeSpinLock(&g_policyLock);
    KeInitializeSpinLock(&g_obsLock);
    KeInitializeSpinLock(&g_inLock);
    KeInitializeSpinLock(&g_inObsLock);
    KeInitializeSpinLock(&g_procLock);
    KeInitializeSpinLock(&g_holdLock);
    KeInitializeEvent(&g_procEvt, SynchronizationEvent, FALSE);
    for (UINT32 i = 0; i < DSSE_MAX_PROC_HOLDS; i++) {
        KeInitializeEvent(&g_procHolds[i].Evt, NotificationEvent, FALSE);
        g_procHolds[i].InUse = 0;
        g_procHolds[i].ProcessId = 0;
    }
    RtlZeroMemory(&g_inPolicy, sizeof(g_inPolicy));
    RtlZeroMemory(&g_policy, sizeof(g_policy));
    RtlZeroMemory(&g_stats, sizeof(g_stats));
    g_stats.Version = DSSE_STATS_VERSION;

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DSSE_WFP_DEVICE_NAME);
    /* Pin the device DACL in code: only NT AUTHORITY\SYSTEM and BUILTIN\Administrators get GENERIC_ALL; the
     * management IOCTL surface (policy push/clear, observation drain) is never exposed to standard users.
     * Defense-in-depth vs relying on the IoCreateDevice default SD. SDDL_DEVOBJ_SYS_ALL_ADM_ALL =
     * "D:P(A;;GA;;;SY)(A;;GA;;;BA)". The custom class GUID has no registry entry, so this SDDL is authoritative. */
    UNICODE_STRING deviceSddl;
    RtlInitUnicodeString(&deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); /* SDDL_DEVOBJ_SYS_ALL_ADM_ALL */
    status = IoCreateDeviceSecure(driver, 0, &devName, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &deviceSddl, (LPCGUID)&DSSE_DEVCLASS_GUID, &g_device);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, DSSE_WFP_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_device); g_device = NULL; return status; }

    driver->MajorFunction[IRP_MJ_CREATE] = dsseDispatchCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = dsseDispatchCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dsseDispatchDeviceControl;
    driver->DriverUnload = DsseUnload;

    /* Process-creation notification. Registration failure is NOT fatal: this feature only sharpens signature
     * exclusions, and steering itself must never be held hostage to it. The usual cause of failure is the
     * image not being linked /INTEGRITYCHECK, which PsSetCreateProcessNotifyRoutineEx requires — in that case
     * the driver still loads and userspace falls back to learning from steered flows. */
    if (NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(dsseProcessNotify, FALSE))) {
        g_procRegistered = TRUE;
    }

    status = dsseWfpSetup(g_device);
    if (!NT_SUCCESS(status)) {
        if (g_procRegistered) {
            PsSetCreateProcessNotifyRoutineEx(dsseProcessNotify, TRUE);
            g_procRegistered = FALSE;
        }
        dsseWfpTeardown();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}
