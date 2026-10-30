"""Compile the real gate registration/classify functions behind a WFP boundary stub.

No driver is loaded. The stub applies Microsoft's FWPS_ACTION0 action contract
to the registered filter and the actual callback result, rather than treating
CONTINUE as permission regardless of registration type. It is not a Windows
filter-arbitration or live-network test.

Run with Python -B in a developer shell (cl.exe), or with cc/clang/gcc on PATH.
Contract: https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
"""

import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = (ROOT / "driver.c").read_text(encoding="utf-8")


def function_source(name):
    match = re.search(r"(?m)^static\s+[^;{}]*\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", SOURCE)
    if not match:
        raise AssertionError("missing function: " + name)
    # Ignore braces in comments and literals while retaining the original text.
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(SOURCE, match.end() - 1):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():token.end()]
    raise AssertionError("unclosed function: " + name)


FUNCTION_NAMES = ("DsseCaptiveClassify", "DsseQuicClassify", "dsseRegisterCaptiveGate",
                  "dsseRegisterQuicCallout", "dsseAddQuicBlockFilter")


def setup_calls():
    setup = function_source("dsseWfpSetup")
    calls = []
    for name, count in (("dsseRegisterCaptiveGate", 6), ("dsseRegisterQuicCallout", 2),
                        ("dsseAddQuicBlockFilter", 2)):
        found = re.findall(r"\b" + name + r"\([^;]*\);", setup)
        if len(found) != count:
            raise AssertionError("unexpected setup call count for " + name)
        calls.extend("CHECK(" + call[:-1] + " == 0, \"setup registration\");" for call in found)
    return "\n".join(calls)


SHIM = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "captive_deadline.h"
#define NTAPI
#ifndef _In_
#define _In_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(x) ((x) == 0)
#define FWPS_RIGHT_ACTION_WRITE 1u
#define OTHER_RIGHT 0x40u
#define FWP_CONDITION_FLAG_IS_LOOPBACK 1u
#define FWP_ACTION_BLOCK 0x1001u
#define FWP_ACTION_PERMIT 0x1002u
#define FWP_ACTION_CALLOUT_TERMINATING 0x5003u
#define FWP_ACTION_CALLOUT_INSPECTION 0x6004u
#define FWP_ACTION_CALLOUT_UNKNOWN 0x4005u
#define FWP_ACTION_CONTINUE 0x2006u
#define FWP_EMPTY 0
#define FWP_UINT8 1
#define FWP_UINT16 2
#define FWP_MATCH_EQUAL 0
#define FWPS_LAYER_OUTBOUND_IPPACKET_V4 1
#define FWPS_LAYER_OUTBOUND_IPPACKET_V6 2
#define FWPS_LAYER_INBOUND_IPPACKET_V4 3
#define FWPS_LAYER_INBOUND_IPPACKET_V6 4
#define FWPS_LAYER_ALE_AUTH_CONNECT_V4 1
#define FWPS_LAYER_ALE_AUTH_CONNECT_V6 2
#define FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 3
#define FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6 4
#define FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS 0
#define FWPS_FIELD_OUTBOUND_IPPACKET_V6_FLAGS 0
#define FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS 0
#define FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS 0
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID 1
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID 2
typedef unsigned int UINT32;
typedef unsigned short UINT16;
typedef unsigned long long UINT64;
typedef int BOOLEAN;
typedef int NTSTATUS;
typedef int GUID;
typedef int KLOCK_QUEUE_HANDLE;
typedef void* PDEVICE_OBJECT;
typedef struct { UINT64 processId; } FWPS_INCOMING_METADATA_VALUES;
typedef struct { unsigned int size; const unsigned char* data; } FWP_BYTE_BLOB;
typedef struct { UINT32 flags; } FWPS_FILTER;
typedef struct { UINT32 layerId; struct { struct { UINT32 uint32; const FWP_BYTE_BLOB* byteBlob; } value; } incomingValue[3]; } FWPS_INCOMING_VALUES;
typedef struct { UINT32 actionType; UINT32 rights; UINT32 flags; } FWPS_CLASSIFY_OUT;
typedef void (*CLASSIFY_FN)(const FWPS_INCOMING_VALUES*, const FWPS_INCOMING_METADATA_VALUES*, void*, const void*, const FWPS_FILTER*, UINT64, FWPS_CLASSIFY_OUT*);
typedef struct { GUID calloutKey; CLASSIFY_FN classifyFn; void (*notifyFn)(void); void (*flowDeleteFn)(UINT16,UINT32,UINT64); } FWPS_CALLOUT;
typedef struct { GUID calloutKey; GUID applicableLayer; struct { const wchar_t* name; } displayData; } FWPM_CALLOUT;
typedef struct { GUID fieldKey; int matchType; struct { int type; unsigned char uint8; UINT16 uint16; } conditionValue; } FWPM_FILTER_CONDITION;
typedef struct { GUID layerKey; struct { const wchar_t* name; } displayData; GUID subLayerKey; struct { UINT32 type; GUID calloutKey; } action; struct { int type; } weight; UINT32 flags; UINT32 numFilterConditions; FWPM_FILTER_CONDITION* filterCondition; } FWPM_FILTER;
static const GUID DSSE_SUBLAYER_GUID = 100, DSSE_CAPTIVE_SUBLAYER_GUID = 101;
static const GUID DSSE_CAPTIVE_OUT_V4_GUID = 1, DSSE_CAPTIVE_OUT_V6_GUID = 2;
static const GUID DSSE_CAPTIVE_IN_V4_GUID = 3, DSSE_CAPTIVE_IN_V6_GUID = 4;
static const GUID DSSE_QUIC_CALLOUT_V4_GUID = 5, DSSE_QUIC_CALLOUT_V6_GUID = 6;
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = 1, FWPM_LAYER_ALE_AUTH_CONNECT_V6 = 2;
static const GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = 3, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = 4;
static const GUID FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 = 5, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6 = 6;
static const GUID DSSE_CAPTIVE_FLOW_V4_GUID=7,DSSE_CAPTIVE_FLOW_V6_GUID=8;
#define IsEqualGUID(a,b) (*(a)==*(b))
static const GUID FWPM_CONDITION_IP_PROTOCOL = 201, FWPM_CONDITION_IP_REMOTE_PORT = 202;
static void* g_engine;
static DSSE_CAPTIVE_STATE g_captive;
static int g_policyLock;
static BOOLEAN g_policyValid;
static UINT32 g_captiveFlowCallouts[2], g_captiveCallouts[4], g_quicCalloutV4, g_quicCalloutV6;
static UINT64 clock100ns;
static int bypassCalls;
static unsigned int checks;
static FWPS_CALLOUT registered[9];
static FWPM_CALLOUT management[9];
static FWPM_FILTER filters[9];
static FWPM_FILTER_CONDITION savedConditions[9][2];
static unsigned int filterCount;
#define CHECK(expr, message) do { checks++; if (!(expr)) { fprintf(stderr, "CONTRACT FAIL: %s at line %d\n", message, __LINE__); return 1; } } while (0)
static void DsseNotify(void) {}
static UINT64 KeQueryInterruptTime(void) { return clock100ns; }
static void KeAcquireInStackQueuedSpinLock(int* lock, KLOCK_QUEUE_HANDLE* q) { (void)lock; *q = 0; }
static void KeReleaseInStackQueuedSpinLock(KLOCK_QUEUE_HANDLE* q) { (void)q; }
static BOOLEAN bypassByAnyApp(const FWP_BYTE_BLOB* app) { bypassCalls++; return app && app->size == 1; }
static NTSTATUS FwpsCalloutRegister(PDEVICE_OBJECT device, const FWPS_CALLOUT* c, UINT32* id) {
    (void)device;
    if (c->calloutKey < 1 || c->calloutKey > 8 || registered[c->calloutKey].classifyFn) return -1;
    registered[c->calloutKey] = *c; *id = (UINT32)c->calloutKey; return 0;
}
static NTSTATUS FwpmCalloutAdd(void* engine, const FWPM_CALLOUT* c, void* security, void* id) {
    (void)engine; (void)security; (void)id;
    if (c->calloutKey < 1 || c->calloutKey > 8) return -1;
    management[c->calloutKey] = *c; return 0;
}
static NTSTATUS FwpmFilterAdd(void* engine, const FWPM_FILTER* f, void* security, void* id) {
    UINT32 i; int key = f->action.calloutKey;
    (void)engine; (void)security; (void)id;
    if (key < 1 || key > 8 || filters[key].action.type || f->numFilterConditions > 2) return -1;
    filters[key] = *f;
    for (i = 0; i < f->numFilterConditions; i++) savedConditions[key][i] = f->filterCondition[i];
    filters[key].filterCondition = savedConditions[key]; filterCount++; return 0;
}

/* Registration/action tests substitute the evidence boundary. Exact tuple,
 * lifetime, allocation, protocol and owner evidence run in test_captive_deadline. */
#define FWP_CONDITION_FLAG_IS_REAUTHORIZE 2
#define FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION 16
#define IPPROTO_TCP 6
#define FWPS_METADATA_FIELD_PROCESS_ID 1
#define FWPS_IS_METADATA_FIELD_PRESENT(m,b) ((m)!=NULL && (b)==0)
typedef struct { UINT64 Flow,Endpoint;UINT32 Family;unsigned char Protocol,Remote[16];UINT16 LocalPort,RemotePort; } DSSE_CAPTIVE_KEY;
typedef struct { UINT32 Family;unsigned char Addr[16];UINT16 Port; } DSSE_DEST_RULE;
static DSSE_DEST_RULE g_captiveEdges[32];
static UINT32 g_captiveEdgeCount;
static UINT64 g_captiveAgentPid;
static int g_captiveUntracked;
static int InterlockedExchange(int* p,int v){int old=*p;*p=v;return old;}
static size_t RtlCompareMemory(const void* a,const void* b,size_t n){return memcmp(a,b,n)==0?n:0;}
static BOOLEAN dsseCaptiveKey(const FWPS_INCOMING_VALUES* v,const FWPS_INCOMING_METADATA_VALUES* m,DSSE_CAPTIVE_KEY* k,UINT32* flags,UINT32* reason){
    (void)m;memset(k,0,sizeof(*k));*flags=v->incomingValue[0].value.uint32;*reason=0;return FALSE;
}
static BOOLEAN dsseCaptiveTracked(const DSSE_CAPTIVE_KEY* k,BOOLEAN mark,BOOLEAN native){(void)k;(void)mark;(void)native;return FALSE;}
static BOOLEAN dsseCaptiveUntrackedExisting(const DSSE_CAPTIVE_KEY* k,UINT32 flags,UINT32 reason){(void)k;(void)flags;(void)reason;return FALSE;}
static BOOLEAN dsseCaptiveNativeReauth(const FWPS_INCOMING_VALUES* v,const FWPS_INCOMING_METADATA_VALUES* m){(void)v;(void)m;return FALSE;}
static BOOLEAN dsseCaptiveNetworkControl(UINT32 f,UINT32 p,UINT32 l,UINT32 r){(void)f;(void)p;(void)l;(void)r;return FALSE;}
static void NTAPI DsseCaptiveFlowDelete(UINT16 l,UINT32 c,UINT64 f){(void)l;(void)c;(void)f;}
static void NTAPI DsseCaptiveFlowClassify(const FWPS_INCOMING_VALUES* v,const FWPS_INCOMING_METADATA_VALUES* m,void* d,const void* c,const FWPS_FILTER* f,UINT64 flow,FWPS_CLASSIFY_OUT* out){(void)v;(void)m;(void)d;(void)c;(void)f;(void)flow;(void)out;}
/* Independent API boundary contract, not the driver's policy implementation. */
static UINT32 effectiveAction(UINT32 registration, UINT32 returned) {
    if (registration == FWP_ACTION_CALLOUT_TERMINATING)
        return returned == FWP_ACTION_PERMIT || returned == FWP_ACTION_BLOCK ? returned : FWP_ACTION_BLOCK;
    if (registration == FWP_ACTION_CALLOUT_INSPECTION) return FWP_ACTION_CONTINUE;
    if (registration == FWP_ACTION_CALLOUT_UNKNOWN) return returned;
    return FWP_ACTION_BLOCK;
}
'''


HARNESS = r'''
static int captivePacket(int key, int loopback, int blocked) {
    FWPS_INCOMING_VALUES values = {0};
    FWPS_CLASSIFY_OUT out = {FWP_ACTION_PERMIT, FWPS_RIGHT_ACTION_WRITE | OTHER_RIGHT, 0};
    FWPS_FILTER runtimeFilter = {0};
    values.layerId = (UINT32)filters[key].layerKey;
    values.incomingValue[0].value.uint32 = loopback ? FWP_CONDITION_FLAG_IS_LOOPBACK : 0;
    registered[key].classifyFn(&values, NULL, NULL, NULL, &runtimeFilter, 0, &out);
    CHECK(effectiveAction(filters[key].action.type, out.actionType) == (blocked ? FWP_ACTION_BLOCK : FWP_ACTION_CONTINUE), "Captive registered action + classify disposition");
    CHECK(out.rights == (blocked ? OTHER_RIGHT : FWPS_RIGHT_ACTION_WRITE | OTHER_RIGHT), "Captive action rights");
    CHECK(out.flags == 0, "Captive does not absorb packets");
    return 0;
}
static int noWrite(int key) {
    FWPS_INCOMING_VALUES values = {0};
    FWPS_FILTER runtimeFilter = {0};
    UINT32 actions[] = {FWP_ACTION_PERMIT, FWP_ACTION_BLOCK, FWP_ACTION_CONTINUE};
    int i;
    values.layerId = (UINT32)filters[key].layerKey;
    for (i = 0; i < 3; i++) {
        FWPS_CLASSIFY_OUT out = {0};
        out.actionType = actions[i]; out.rights = OTHER_RIGHT; out.flags = 0x80u;
        registered[key].classifyFn(&values, NULL, NULL, NULL, &runtimeFilter, 0, &out);
        CHECK(out.actionType == actions[i] && out.rights == OTHER_RIGHT && out.flags == 0x80u, "No ACTION_WRITE preserves previous decision and all flags");
    }
    return 0;
}
/* WFP arbitration: a terminating permit skips remaining filters only in the
 * SAME sublayer; a block from another sublayer still wins soft-permit. */
static UINT32 inboundThenCaptive(GUID inboundSub,GUID captiveSub,UINT32 gateAction) {
    if (inboundSub==captiveSub) return FWP_ACTION_PERMIT;
    return gateAction==FWP_ACTION_BLOCK ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
}
static int captiveCases(void) {
    int key, state;
    for (key = 1; key <= 4; key++) {
        CHECK(registered[key].classifyFn == DsseCaptiveClassify, "Captive callback binding");
        CHECK(filters[key].layerKey == key && management[key].applicableLayer == key, "Captive four layer bindings");
        CHECK(filters[key].numFilterConditions == 0 && filters[key].flags == 0, "Captive has no protocol exemptions or extra flags");
        CHECK(filters[key].subLayerKey == DSSE_CAPTIVE_SUBLAYER_GUID && filters[key].subLayerKey != DSSE_SUBLAYER_GUID, "Captive has independent sublayer arbitration");
        for (state = 0; state < 6; state++) {
            int blocked = state == 2 || state == 3;
            memset(&g_captive, 0, sizeof(g_captive)); clock100ns = 300;
            if (state != 0) {
                CHECK(dsseCaptiveArm(&g_captive, 100, 100, 1, 1, 0), "Arm valid window");
                clock100ns = state == 1 ? 199 : state == 2 ? 200 : 201;
                if (state == 4) CHECK(dsseCaptiveFinish(&g_captive, g_captive.Generation, 1, 1), "Finish valid generation");
                if (state == 5) dsseCaptiveRecover(&g_captive);
            }
            CHECK(captivePacket(key, 0, blocked) == 0, "Captive six state matrix");
            CHECK(captivePacket(key, 1, 0) == 0, "Loopback remains delegated in every state");
            CHECK(noWrite(key) == 0, "Captive no-write state matrix");
        }
        CHECK(inboundThenCaptive(DSSE_SUBLAYER_GUID,filters[key].subLayerKey,FWP_ACTION_BLOCK)==FWP_ACTION_BLOCK,"Captive independent sublayer defeats earlier inbound terminating permit");
        CHECK(inboundThenCaptive(DSSE_SUBLAYER_GUID,DSSE_SUBLAYER_GUID,FWP_ACTION_BLOCK)==FWP_ACTION_PERMIT,"Boundary model catches same-sublayer short circuit");
        memset(&g_captive, 0, sizeof(g_captive)); clock100ns = 201;
        CHECK(dsseCaptiveArm(&g_captive, 100, 100, 1, 1, 0), "Arm before expired adoption");
        CHECK(dsseCaptiveArm(&g_captive, 201, 9999, 1, 1, 0), "Adopt active window");
        CHECK(g_captive.Deadline100ns == 200, "Adoption must not extend deadline");
        CHECK(!dsseCaptiveFinish(&g_captive, g_captive.Generation + 1, 1, 1), "Reject stale generation");
        CHECK(captivePacket(key, 0, 1) == 0, "Failed finish retains blocking");
    }
    return 0;
}
static int quicCases(void) {
    int key, steering, bypass;
    for (key = 5; key <= 6; key++) {
        CHECK(registered[key].classifyFn == DsseQuicClassify, "QUIC callback binding");
        CHECK(filters[key].layerKey == key-4 && management[key].applicableLayer == key-4, "QUIC two family bindings");
        CHECK(filters[key].flags == 0 && filters[key].numFilterConditions == 2, "QUIC condition count and flags");
        CHECK(savedConditions[key][0].fieldKey == FWPM_CONDITION_IP_PROTOCOL && savedConditions[key][0].matchType == FWP_MATCH_EQUAL && savedConditions[key][0].conditionValue.type == FWP_UINT8 && savedConditions[key][0].conditionValue.uint8 == 17, "QUIC remains UDP only");
        CHECK(savedConditions[key][1].fieldKey == FWPM_CONDITION_IP_REMOTE_PORT && savedConditions[key][1].matchType == FWP_MATCH_EQUAL && savedConditions[key][1].conditionValue.type == FWP_UINT16 && savedConditions[key][1].conditionValue.uint16 == 443, "QUIC remains remote port 443 only");
        for (steering = 0; steering <= 1; steering++) for (bypass = 0; bypass <= 1; bypass++) {
            FWPS_INCOMING_VALUES values = {0};
            FWPS_CLASSIFY_OUT out = {FWP_ACTION_PERMIT, FWPS_RIGHT_ACTION_WRITE | OTHER_RIGHT, 0};
            FWPS_FILTER runtimeFilter = {0};
            FWP_BYTE_BLOB app = {0}, wrongFamily = {0};
            int blocked = steering && !bypass;
            app.size = bypass ? 1u : 0u; wrongFamily.size = bypass ? 0u : 1u;
            values.layerId = (UINT32)filters[key].layerKey;
            values.incomingValue[key == 5 ? 1 : 2].value.byteBlob = &app;
            values.incomingValue[key == 5 ? 2 : 1].value.byteBlob = &wrongFamily;
            g_policyValid = steering; bypassCalls = 0;
            registered[key].classifyFn(&values, NULL, NULL, NULL, &runtimeFilter, 0, &out);
            CHECK(effectiveAction(filters[key].action.type, out.actionType) == (blocked ? FWP_ACTION_BLOCK : FWP_ACTION_CONTINUE), "QUIC registered action + classify disposition");
            CHECK(out.rights == (blocked ? OTHER_RIGHT : FWPS_RIGHT_ACTION_WRITE | OTHER_RIGHT) && out.flags == 0, "QUIC rights and flags");
            CHECK(bypassCalls == (steering ? 1 : 0), "QUIC bypass lookup only while steering");
            CHECK(noWrite(key) == 0, "QUIC no-write state matrix");
        }
    }
    return 0;
}
int main(int argc, char** argv) {
    PDEVICE_OBJECT device = NULL;
    if (argc != 2) return 2;
    /* ACTUAL_SETUP_CALLS */
    CHECK(filterCount == 8, "Four Captive, two lifetime and two QUIC filters");
    if (strcmp(argv[1], "captive") == 0) { if (captiveCases()) return 1; }
    else if (strcmp(argv[1], "quic") == 0) { if (quicCases()) return 1; }
    else return 2;
    printf("%s registration/classify contract passed (%u assertions)\n", argv[1], checks);
    return 0;
}
'''


class CalloutContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        explicit = os.environ.get("CC")
        cls.compiler = shlex.split(explicit, posix=os.name != "nt") if explicit else None
        if not cls.compiler:
            executable = next((shutil.which(c) for c in ("cl.exe", "cc", "clang", "gcc") if shutil.which(c)), None)
            if executable:
                cls.compiler = [executable]
        if not cls.compiler:
            raise AssertionError("MSVC developer shell or cc/clang/gcc is required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory(prefix="dsse-callout-contract-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.functions = {name: function_source(name) for name in FUNCTION_NAMES}
        cls.normal = cls.compile_case("normal", cls.functions)

    @classmethod
    def compile_case(cls, label, functions):
        folder = pathlib.Path(cls.temp.name) / label
        folder.mkdir()
        src = folder / "contract.c"
        exe = folder / ("contract.exe" if os.name == "nt" else "contract")
        src.write_text(SHIM + "\n" + "\n".join(functions[name] for name in FUNCTION_NAMES)
                       + HARNESS.replace("/* ACTUAL_SETUP_CALLS */", setup_calls()), encoding="utf-8")
        is_msvc = pathlib.Path(cls.compiler[0].strip('"')).name.lower() in ("cl", "cl.exe", "clang-cl", "clang-cl.exe")
        if is_msvc:
            args = ["/nologo", "/TC", "/std:c11", "/utf-8", "/W4", "/WX", "/I" + str(ROOT), str(src), "/Fe:" + str(exe)]
        else:
            args = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT), str(src), "-o", str(exe)]
        compiler_env = dict(os.environ, VSLANG="1033")
        result = subprocess.run(cls.compiler + args, cwd=folder, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", env=compiler_env, timeout=90)
        if result.returncode:
            raise AssertionError("C harness compilation failed:\n" + result.stdout + result.stderr)
        return exe

    def test_captive_registration_and_six_states_all_four_layers(self):
        result = subprocess.run([str(self.normal), "captive"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout.strip())

    def test_quic_registration_and_policy_bypass_both_families(self):
        result = subprocess.run([str(self.normal), "quic"], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout.strip())

    def mutation_must_fail(self, function, family):
        functions = dict(self.functions)
        self.assertEqual(functions[function].count("FWP_ACTION_CALLOUT_UNKNOWN"), 1,
                         "mutation must target exactly the fixed registration")
        functions[function] = functions[function].replace("FWP_ACTION_CALLOUT_UNKNOWN", "FWP_ACTION_CALLOUT_TERMINATING", 1)
        exe = self.compile_case("old-" + family, functions)
        result = subprocess.run([str(exe), family], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0, "old registration unexpectedly passed")
        self.assertIn(family.capitalize() if family == "captive" else "QUIC", result.stderr)
        self.assertIn("registered action + classify disposition", result.stderr)
        print("old " + family + " TERMINATING mutation rejected by disposition assertion")

    def test_old_captive_terminating_registration_is_rejected(self):
        self.mutation_must_fail("dsseRegisterCaptiveGate", "captive")

    def test_same_sublayer_permit_short_circuit_is_rejected(self):
        functions=dict(self.functions)
        functions["dsseRegisterCaptiveGate"]=functions["dsseRegisterCaptiveGate"].replace("f.subLayerKey = DSSE_CAPTIVE_SUBLAYER_GUID;","f.subLayerKey = DSSE_SUBLAYER_GUID;")
        exe=self.compile_case("same-sublayer",functions)
        result=subprocess.run([str(exe),"captive"],capture_output=True,text=True,timeout=30)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("independent sublayer",result.stderr)

    def test_old_quic_terminating_registration_is_rejected(self):
        self.mutation_must_fail("dsseAddQuicBlockFilter", "quic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
