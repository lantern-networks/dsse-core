/* The deadline decision is shared by the WDK driver and a native C fault model.
 * All calls hold g_policyLock in the driver. Time is KeQueryInterruptTime's
 * monotonic 100 ns clock, including sleep; no userspace timer/DPC is required.
 * This is a captive onboarding security deadline, not a traffic quota. */
#ifndef DSSE_CAPTIVE_DEADLINE_H
#define DSSE_CAPTIVE_DEADLINE_H

typedef struct _DSSE_CAPTIVE_STATE {
    unsigned long long Deadline100ns;
    unsigned long long Generation;
    unsigned int Active;
} DSSE_CAPTIVE_STATE;

static int dsseCaptiveArm(DSSE_CAPTIVE_STATE* s, unsigned long long now,
    unsigned long long duration, int owner, int policyArmed, int failOpen)
{
    if (!owner || !policyArmed || failOpen || duration == 0 || duration > ~0ULL - now)
        return 0;
    /* Reconnect/adoption may retain the window, never renew its deadline. */
    if (s->Active) return 1;
    if (s->Generation == ~0ULL) return 0; /* no generation wrap/reuse */
    s->Generation++;
    s->Deadline100ns = now + duration;
    s->Active = 1;
    return 1;
}

static int dsseCaptiveExpired(const DSSE_CAPTIVE_STATE* s, unsigned long long now)
{
    return s->Active && now >= s->Deadline100ns;
}

static int dsseCaptiveFinish(DSSE_CAPTIVE_STATE* s, unsigned long long generation,
    int owner, int policyArmed)
{
    if (!owner || !policyArmed || generation == 0 || generation != s->Generation)
        return 0;
    s->Active = 0;
    s->Deadline100ns = 0;
    return 1;
}

/* Only the explicit elevated RECOVER IOCTL calls this; normal CLEAR/SET and
 * owner close must never release an unfinished captive window. */
static void dsseCaptiveRecover(DSSE_CAPTIVE_STATE* s)
{
    s->Active = 0;
    s->Deadline100ns = 0;
}

#endif
