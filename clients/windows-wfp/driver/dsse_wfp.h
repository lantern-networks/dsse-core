/*
 * dsse_wfp.h — shared driver<->userspace contract for the production WFP steering backend
 * (). These structs and IOCTL codes MUST stay byte-for-byte in
 * lockstep with the Go side: cmd/windivert-steer/capture_wfp.go (wfpRedirectContext) and
 * capture_wfp_policy.go (wfpPolicy / wfpDestRule / IOCTL codes / device path). Both sides run on the same
 * little-endian host, so scalar fields are native order; IP addresses are network order (as in the header).
 */
#pragma once

/* Device the userspace proxy opens to push policy: \\.\DsseWfp */
#define DSSE_WFP_DEVICE_NAME    L"\\Device\\DsseWfp"
#define DSSE_WFP_SYMLINK_NAME   L"\\DosDevices\\DsseWfp"

/* Address families (match Winsock AF_INET / AF_INET6 and the Go afInet/afInet6). */
#define DSSE_AF_INET     2
#define DSSE_AF_INET6   23

/* Fixed caps — keep identical to the Go side (wfpMaxApps / wfpMaxDests / wfpAppSubLen). */
#define DSSE_MAX_APPS    16
#define DSSE_APP_SUB_LEN 64
#define DSSE_MAX_DESTS   32
#define DSSE_MAX_INBOUND_RULES 64 /* server-initiated (inbound) allow rules; keep == Go wfpMaxInboundRules */

/* Exact verified-APP_ID bypass table: full NT device paths (\device\harddiskvolumeN\...) of processes whose
 * Authenticode identity USERSPACE verified against a signature exclusion (subject:/thumbprint:/publisher:/signed:).
 * The kernel matches the connecting flow's ALE_APP_ID EXACTLY (case-insensitive) against these — strong identity
 * (the macOS-Team-ID analog) on the WFP backend, with identity owned by userspace and enforced by the kernel.
 * Keep identical to the Go side (wfpMaxExactApps / wfpExactAppLen). */
#define DSSE_MAX_EXACT_APPS 16
#define DSSE_EXACT_APP_LEN  260 /* wchar_t count incl. NUL terminator */

#define DSSE_POLICY_VERSION   2
#define DSSE_REDIRECT_CTX_VERSION 1
#define DSSE_INBOUND_POLICY_VERSION 1

#include <pshpack1.h> /* no implicit padding: layout must match Go's struct exactly */

/* A never-redirect destination (race-free, no process lookup). Addr is network order; Port is native. */
typedef struct _DSSE_DEST_RULE {
    unsigned int   Family;     /* DSSE_AF_INET / DSSE_AF_INET6 */
    unsigned char  Addr[16];   /* network order; first 4 bytes for IPv4 */
    unsigned short Port;       /* native order */
    unsigned short _pad;
} DSSE_DEST_RULE;

/* The connect-time bypass/redirect policy pushed from userspace via IOCTL_DSSE_SET_POLICY. The callout
 * evaluates this in its ALE_CONNECT_REDIRECT classify; identity is known at connect-time so the bypass is
 * race-free (fail-closed is safe). */
typedef struct _DSSE_POLICY {
    unsigned int   Version;                          /* DSSE_POLICY_VERSION */
    unsigned short LocalPort;                         /* proxy port to redirect steered flows to */
    unsigned short _pad;
    unsigned int   NumApps;
    unsigned int   NumDests;
    unsigned char  Apps[DSSE_MAX_APPS][DSSE_APP_SUB_LEN]; /* lowercased ASCII image-path substrings, NUL-term */
    DSSE_DEST_RULE Dests[DSSE_MAX_DESTS];
    unsigned int   ProxyPid;  /* PID of the local proxy that accepts redirected connections. REQUIRED for a
                                 localhost connect-redirect: the framework needs localRedirectTargetPID to
                                 complete the redirect, else the connect fails STATUS_ACCESS_DENIED. */
    unsigned int   ObserveOnly; /* discovery/audit: when non-zero the callout RECORDS each would-be-steered
                                   flow (PID + dest) and PERMITs it (no redirect) instead of steering. Drain
                                   the records via IOCTL_DSSE_GET_OBSERVATIONS. Mirrors the NE observe mode. */
    unsigned int   NumExactApps; /* count of valid entries in ExactApps */
    wchar_t        ExactApps[DSSE_MAX_EXACT_APPS][DSSE_EXACT_APP_LEN]; /* verified NT device paths (NUL-term),
                                   exact case-insensitive match against the connecting flow's ALE_APP_ID */
} DSSE_POLICY;

/* One observed (would-be-steered) flow recorded in ObserveOnly mode; race-free connect-time identity. */
#define DSSE_MAX_OBS 256
typedef struct _DSSE_OBSERVATION {
    unsigned int   Family;      /* DSSE_AF_INET / DSSE_AF_INET6 */
    unsigned int   ProcessId;   /* connect-time PID (resolve to image in userspace) */
    unsigned char  RemoteAddr[16]; /* original destination, network order */
    unsigned short RemotePort;  /* native order */
    unsigned short _pad;
} DSSE_OBSERVATION;

/* --- : server-initiated (inbound) classification + enforcement --------------------------------- *
 * A second WFP layer (ALE_AUTH_RECV_ACCEPT_V4/V6) classifies INBOUND connections (a server initiating to
 * this endpoint = the lateral-movement vector). The existing connect-redirect path (outbound) is untouched.
 * Edge is the policy authority ( section 1); userspace fetches the S2 export (server_initiated_export.v1),
 * resolves source_server hostnames to IPs, filters to this device's group, and pushes the resulting allow
 * rules + default-deny here. The driver matches inline (no per-flow kernel->userspace->Edge round-trip). */

/* One server-initiated allow rule. SrcAddr is network order (userspace resolves hostname->IP; the kernel
 * never does name resolution -> race-free). LocalPort/Protocol 0 = wildcard. Action: 0=deny, 1=allow
 * (export's log/log_alert map to allow + userspace-side audit; deny rules are redundant under default-deny). */
typedef struct _DSSE_INBOUND_RULE {
    unsigned int   Family;      /* DSSE_AF_INET / DSSE_AF_INET6 */
    unsigned char  SrcAddr[16]; /* source_server, network order; first 4 bytes for IPv4 */
    unsigned short LocalPort;   /* native; 0 = wildcard (service_family is derived from local port) */
    unsigned short Protocol;    /* IP protocol (6=TCP); 0 = wildcard */
    unsigned int   Action;      /* 0=deny, 1=allow */
} DSSE_INBOUND_RULE;

/* The inbound policy blob pushed via IOCTL_DSSE_SET_INBOUND_POLICY. Enforce selects the  S-slice:
 *   Enforce==0 (S3a observe): record every would-be-governed inbound flow, then PERMIT (no enforcement).
 *   Enforce==1 (S3b enforce): record + match {SrcAddr, LocalPort, Protocol} against Rules; allow=>PERMIT,
 *                             no match => BLOCK (DefaultDeny). DefaultDeny is 1 (fixed; the  default). */
typedef struct _DSSE_INBOUND_POLICY {
    unsigned int      Version;     /* DSSE_INBOUND_POLICY_VERSION */
    unsigned int      DefaultDeny; /* 1 fixed (default deny for unmatched inbound) */
    unsigned int      Enforce;     /* 0 = observe-only (S3a), 1 = enforce (S3b) */
    unsigned int      NumRules;
    DSSE_INBOUND_RULE Rules[DSSE_MAX_INBOUND_RULES];
} DSSE_INBOUND_POLICY;

/* One observed inbound flow (recorded in both observe and enforce modes; connect-time identity). Distinct
 * from DSSE_OBSERVATION (outbound) -- carries the source server + the local receive port (=> service_family). */
#define DSSE_MAX_INBOUND_OBS 256
typedef struct _DSSE_INBOUND_OBSERVATION {
    unsigned int   Family;      /* DSSE_AF_INET / DSSE_AF_INET6 */
    unsigned int   ProcessId;   /* accepting local PID (resolve to image in userspace) */
    unsigned char  RemoteAddr[16]; /* source server (initiator), network order */
    unsigned short RemotePort;  /* source ephemeral port, native */
    unsigned short LocalPort;   /* our receive port (=> service_family), native */
    unsigned short Protocol;    /* IP protocol */
    unsigned short Action;      /* what the callout did: 0=permit(observe/allow), 1=blocked(default-deny) */
} DSSE_INBOUND_OBSERVATION;

/* The per-flow redirect context the callout writes (and the proxy reads back via
 * SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT). Carries the original destination (so userspace needs no
 * conntrack) and the connect-time PID. Layout matches Go's wfpRedirectContext. */
typedef struct _DSSE_REDIRECT_CONTEXT {
    unsigned int   Version;        /* DSSE_REDIRECT_CTX_VERSION */
    unsigned int   Family;         /* DSSE_AF_INET / DSSE_AF_INET6 */
    unsigned char  OrigDstAddr[16];/* network order */
    unsigned short OrigDstPort;    /* native order */
    unsigned short _pad;
    unsigned int   ProcessId;
} DSSE_REDIRECT_CONTEXT;

/* Read-only diagnostic counters (P3 debugging of the redirect path) AND the driver's current arming STATE.
 * Read via IOCTL_DSSE_GET_STATS. LastAcquire*Status carry the raw NTSTATUS from the last failure (0 = none).
 *
 * VERSION 3 added the state block at the end. Until then nothing could ask this driver the one question that
 * matters operationally: "are you redirecting right now?" Only counters were exposed, and userspace never even
 * parsed them (the Go side used the IOCTL purely as a driver-responsive liveness probe). That gap is why an
 * armed driver with no agent behind it — every connection refused, see the note on IRP_MJ_CLOSE in driver.c —
 * could not be detected by anything, including by the code whose job is to recover from it. A disarm that is
 * "best effort" and unverifiable is indistinguishable from a disarm that did not happen.
 *
 * Growth is append-only and Version-guarded: an older consumer asking for a smaller buffer still gets its
 * prefix, and a newer consumer checks Version before reading the state block. */
#define DSSE_STATS_VERSION 3
typedef struct _DSSE_STATS {
    unsigned int Version;
    /* Process-creation holds that expired without a verdict. The design promised this counter and the B1
     * pivot quietly dropped it — leaving the feature with a silent window of exactly the kind it exists to
     * remove. A hold that times out means the first flow of that image gets steered (safe direction, and
     * stage-0 learning converges), but if timeouts are the NORM — e.g. WinVerifyTrust doing a cold CRL fetch
     * on every unknown image — nothing else would ever say so. This is also the measurement of how often the
     * "decided before the first instruction" guarantee actually holds. */
    unsigned int ProcHoldTimeouts;
    unsigned int ClassifyCalls;            /* DsseClassify entered (had WRITE right) */
    unsigned int NoPolicy;                 /* returned: policy not valid yet */
    unsigned int SkippedRedirectedReauth;  /* returned: IS_CONNECTION_REDIRECTED|IS_REAUTHORIZE */
    unsigned int BypassLoopback;
    unsigned int BypassAppOrDest;
    unsigned int RedirectAttempts;         /* reached the redirect block (non-bypass) */
    unsigned int AcquireHandleFail;
    unsigned int AcquireWritableFail;
    unsigned int AllocFail;
    unsigned int RedirectApplied;          /* FwpsApplyModifiedLayerData reached on the redirect path */
    int          LastAcquireHandleStatus;  /* NTSTATUS of last FwpsAcquireClassifyHandle failure */
    int          LastAcquireWritableStatus;/* NTSTATUS of last FwpsAcquireWritableLayerDataPointer failure */

    /* --- state block, DSSE_STATS_VERSION 3 and later ------------------------------------------------- */
    unsigned int   PolicyArmed;      /* non-zero: a redirect policy is in force RIGHT NOW (g_policyValid) */
    unsigned int   PolicyProxyPid;   /* the PID the redirect targets; 0 when not armed */
    unsigned short PolicyLocalPort;  /* the port the redirect targets; 0 when not armed */
    unsigned short PolicyObserveOnly;/* non-zero: recording only, never redirecting (not an outage risk) */
    /* OwnerPresent: an IOCTL_DSSE_ARM_OWNER handle is currently open. When PolicyArmed is set and this is
     * NOT, the agent that armed the redirect is gone and the box is refusing connections — the single state
     * a watchdog exists to find. */
    unsigned int   OwnerPresent;
    unsigned int   OwnerDisarmOnExit;/* non-zero: closing the owner handle will clear the policy (fail-open) */
} DSSE_STATS;

/* --- process-creation notification (stage 1 of docs/2026-08-06_signature_exclusions_process_notify_design.ja.md)
 *
 * WHY THIS EXISTS. Signature-form steer exclusions (signed:/publisher:/subject:/thumbprint:) cannot be
 * evaluated in-kernel — the callout matches image paths, it has no Authenticode. So userspace verifies and
 * pushes exact NT paths into ExactApps. Discovery used to be a 30-SECOND SCAN OF RUNNING PROCESSES, which a
 * five-second process is simply never present for: `signed:winget.exe` was distributed, verified, and
 * self-reported as effective while enforcing nothing (measured 2026-08-06). The driver is the only component
 * that learns of a process at the instant it is created, so it is the only place the gap can actually close.
 *
 * The channel is a bounded ring plus a blocking wait, NOT a drain-poll like GET_OBSERVATIONS: userspace parks
 * one thread in IOCTL_DSSE_WAIT_PROC_EVENTS and the driver wakes it the moment a process appears. The wait has
 * a timeout so a stalled or killed agent leaves nothing stuck in the kernel; it returns zero events and
 * userspace simply re-issues. Overflow drops OLDEST and bumps ProcEventsDropped — a dropped event costs one
 * steered flow (the userspace learn-on-steer path still catches it), never a wrong bypass. */
#define DSSE_MAX_PROC_EVENTS 128

typedef struct _DSSE_PROC_EVENT {
    unsigned int ProcessId;
    unsigned int _pad;
    wchar_t      ImagePath[DSSE_EXACT_APP_LEN]; /* NT device path, NUL-terminated; "" if unavailable */
} DSSE_PROC_EVENT;

/* --- bounded hold at process creation (stage 2) ------------------------------------------------------
 *
 * Notification alone does NOT close the race, which was measured rather than assumed: with signed:curl.exe on
 * a cold store the FIRST flow was still steered, because Authenticode verification plus the policy IOCTL do
 * not finish before curl connects. Being told early is not the same as having decided.
 *
 * So the driver HOLDS the creating thread until userspace answers — briefly, and only when userspace says it
 * has signature rules to evaluate (WaitBlockMs > 0 on the wait IOCTL). The hold happens at process creation,
 * NOT in the connect path: a mistake here delays a process start, whereas a mistake in the classify path
 * would hang every flow on the machine. The verdict lands before the process runs its first instruction, so
 * it is in the kernel's table before any connect can be classified.
 *
 * Fail-open by construction: if userspace does not answer within WaitBlockMs, or no hold slot is free, or the
 * agent is gone, the process starts normally and the app is discovered from its first steered flow as before.
 * A hold can cost latency; it can never cost a launch. */
#define DSSE_MAX_PROC_HOLDS 8   /* concurrent creations that may be held; beyond this, do not block */

/* Input to IOCTL_DSSE_WAIT_PROC_EVENTS. WaitBlockMs = 0 disables holding entirely (the default posture when
 * no signature-form rule is active, so an ordinary deployment never pays a microsecond at process creation). */
typedef struct _DSSE_PROC_WAIT_REQUEST {
    unsigned int WaitBlockMs;
} DSSE_PROC_WAIT_REQUEST;

/* Input to IOCTL_DSSE_SET_APP_VERDICT: userspace has finished deciding this pid. The bypass path itself is
 * still the exact-APP_ID table pushed by IOCTL_DSSE_SET_POLICY — this only releases the held thread, after
 * that push, so the table is authoritative before the process can connect. */
typedef struct _DSSE_APP_VERDICT {
    unsigned int ProcessId;
} DSSE_APP_VERDICT;

/* Input to IOCTL_DSSE_ARM_OWNER: the agent nominates THIS open handle as the owner of the redirect policy,
 * and says what should happen to that policy when the handle closes.
 *
 * Why a handle and not a heartbeat: closing a process's handles is the ONE cleanup Windows performs
 * unconditionally on process death. A crash, TerminateProcess, an installer's files-in-use kill and a power
 * loss all reach it; none of them reach the agent's own shutdown path. Every existing route that clears the
 * redirect policy (the agent's Close(), --mode recover, onDisarm) runs in user mode, so all of them are
 * unavailable in exactly the situations that need them.
 *
 * DisarmOnExit is NOT a hardcoded behaviour, because "the agent died, so traffic flows" IS fail-open, and
 * whether this endpoint may fail open is an INSTALL-TIME decision carried in the signed install profile —
 * not something an update mechanism, a control plane, or this driver gets to choose. A fail-CLOSED endpoint
 * keeps refusing connections when its agent dies; that is not a bug to be fixed here, it is what fail-closed
 * was chosen to mean. It opens no new bypass either: an agent that stops cleanly already disarms, and
 * --mode recover already exists, so what changes is black hole versus passthrough, not exposure.
 *
 * A second ARM_OWNER on a different handle REPLACES the owner. The agent opens and closes this device once
 * per policy push, so ownership must be tied to one nominated handle rather than to any close — the same
 * reasoning as g_procWaitOwner (see dsseDispatchCreateClose). */
#define DSSE_OWNER_ARM_VERSION 1
typedef struct _DSSE_OWNER_ARM {
    unsigned int Version;      /* DSSE_OWNER_ARM_VERSION */
    unsigned int DisarmOnExit; /* non-zero: clear the redirect policy when this handle closes */
} DSSE_OWNER_ARM;

#include <poppack.h>

/*
 * IOCTL codes. CTL_CODE(FILE_DEVICE_NETWORK=0x12, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0).
 * Must equal the Go wfpCtlCode(0x800)/wfpCtlCode(0x801).
 */
#ifndef CTL_CODE
#include <winioctl.h>
#endif
#define IOCTL_DSSE_SET_POLICY   CTL_CODE(0x12, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DSSE_CLEAR_POLICY CTL_CODE(0x12, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DSSE_GET_STATS    CTL_CODE(0x12, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* GET_OBSERVATIONS output: [UINT32 count][DSSE_OBSERVATION x count]; drains (clears) the returned records. */
#define IOCTL_DSSE_GET_OBSERVATIONS CTL_CODE(0x12, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
/*  inbound (server-initiated) control channel. Func numbers continue from the outbound set (0x804+). */
#define IOCTL_DSSE_SET_INBOUND_POLICY   CTL_CODE(0x12, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DSSE_CLEAR_INBOUND_POLICY CTL_CODE(0x12, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* GET_INBOUND_OBSERVATIONS output: [UINT32 count][DSSE_INBOUND_OBSERVATION x count]; drains the records. */
#define IOCTL_DSSE_GET_INBOUND_OBSERVATIONS CTL_CODE(0x12, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Process-creation notification. Output: [UINT32 count][DSSE_PROC_EVENT x count]. BLOCKS until at least one
 * event is queued or the driver's internal timeout expires (then count = 0 and the caller re-issues). Drains
 * what it returns. One waiter is expected; a second concurrent caller is served whatever is queued and does
 * not wait. */
#define IOCTL_DSSE_WAIT_PROC_EVENTS CTL_CODE(0x12, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Release a held process once its verdict is in the exact-APP_ID table. Input: DSSE_APP_VERDICT. Unknown or
 * already-released pids are a no-op success — the hold may simply have timed out first. */
#define IOCTL_DSSE_SET_APP_VERDICT CTL_CODE(0x12, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Nominate the calling handle as the redirect policy's owner. Input: DSSE_OWNER_ARM. See that struct for why
 * this exists and why DisarmOnExit is a posture input rather than a fixed behaviour. */
#define IOCTL_DSSE_ARM_OWNER CTL_CODE(0x12, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
