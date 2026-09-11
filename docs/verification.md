# Verification and release limits

This page describes how to evaluate a build. It is **not a report that the checks below
have passed**. DSSE is experimental; a successful build or installation does not establish
production readiness, an independent audit, or long-duration reliability.

## Match the evidence to the claim

| Check | What a successful result supports | What it does not establish |
|---|---|---|
| Build, vet, unit tests | The tested revision compiled and passed those automated checks | Signed installation, real traffic, or operational endurance |
| `dsse-install -verify` | The named fleet answered the checks reported by that run | Untested devices, unanswered checks, or sustained recovery behavior |
| Endpoint local verifier | The local installation and runtime checks reported by that tool | Every application, guest VM, network condition, or future renewal |
| Allowed and denied traffic | The tested identity, policy, destination, and path behaved as observed | Other tenants, routes, regions, or protocols |
| Certificate-renewal test | The tested certificate transition completed on the measured path | All authority tiers or later rotations |
| Region-loss test | The measured workload recovered from that specific failure | A fixed failover time, arbitrary concurrent failures, or no data loss |
| Restore exercise | That backup restored with the tested revision and trust material | All later backups or a general recovery-time commitment |

## First-use acceptance

Complete [Deployment](deployment.md), [First use](after-verify.md), and the relevant
platform guide. Keep the full output and resolve failed checks. For every `n/a` or
unanswered result, record whether the check is inapplicable or still outstanding.
The fleet verifier performs active probes, including enrolment where permitted; plan
the run accordingly instead of treating it as a passive health read.

At minimum, establish these observations in the intended customer organization:

- administrator sign-in with MFA and the correct delegation;
- a verified profile with intended organization, posture, transport names, and CA pins;
- active endpoint steering, current device reports, and accepted HTTPS in the actual client programs;
- an allowed flow succeeds and a deliberately denied flow is blocked;
- the corresponding decisions arrive in the customer's audit view;
- if required, a private app is reachable through its connector and unauthorized access is denied;
- if required, a synthetic DLP match is blocked while a normal upload succeeds.

Record the initial allow rule and Connector OBSERVE posture before changing them. An
observation-mode success is not a denial test. Do not use real secrets as DLP test data.

## Endurance and recovery

Run these exercises on recoverable lab devices and a topology whose failure domains
match the claim. Record actual observations instead of assigning a result in advance.

| Exercise | Record |
|---|---|
| Sustained ordinary traffic | Workload, duration, errors, resource/spool growth, gaps in audit ingestion |
| Default-lifetime certificate renewal | Which certificates renewed, old/new validity, renewal time, traffic and trust before/after |
| Endpoint sleep/wake and restart | OS approvals, resumed steering, identity continuity, allowed/denied behavior |
| One region unavailable and restored | Failure start, detection, recovery time, surviving quorum, device and connector traffic, convergence after return |
| Policy change during normal operation | Authored value, each Edge's application, observed policy result, and audit record |
| Signed agent update | Actual installed/running version, policy/identity retained, verifier result, and traffic after update |
| State restoration | Backup identity, matching keys/revision, restored data, measured time and loss |

An accelerated certificate test is useful but does not prove a default-lifetime run.
A restart, configuration change, or manual intervention must appear in the timeline.
Name the affected scope if a run mixes revisions; it cannot establish uninterrupted
behavior of one unchanged revision. Three region labels on one machine do not prove
resilience to a physical region failure.

## Result record template

Keep raw evidence privately; publish only reviewed, sanitized summaries. A useful record is:

```text
Source revision and build/image identifiers:
Agent versions, OS versions, architectures:
Topology and tested failure domains:
Configuration and policy scope (no secrets):
Start / end timestamps and time zone:
Workload and expected allowed / denied behavior:
Certificate lifetimes and transitions observed:
Faults introduced and manual interventions:
Observed result and evidence location:
Failed checks:
Unanswered / not applicable checks and reasons:
Untested paths and remaining limitations:
Reviewer and next action:
```

Use explicit results such as **passed**, **failed**, **not run**, or **not applicable**
with a reason. An in-progress endurance test remains **in progress**. A release summary
should identify the exact tested revision, duration, topology, and unresolved findings.
Release availability, a successful CI run, and publication of this guide do not change
the [experimental status](../README.md) or [threat-model limits](threat-model.md).

Record release-wide scope and remaining evidence alongside the [Release overview](release-overview.md).
