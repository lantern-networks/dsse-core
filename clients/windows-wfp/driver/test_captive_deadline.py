"""Run actual admission/flow-lifetime C with WFP boundary shims.

This is not a WDK build or WFP runtime/IRQL/arbitration acceptance test.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parent
SOURCE = (ROOT / "driver.c").read_text()


class CaptiveDeadlineTest(unittest.TestCase):
    def test_actual_admission_and_flow_lifetime(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        shim = (ROOT / "test_captive_shim.h").read_text()
        body = SOURCE.split("/* Flow contexts live at ALE_FLOW_ESTABLISHED", 1)[1].split("/* DsseQuicClassify:", 1)[0]
        body = "/* Flow contexts live at ALE_FLOW_ESTABLISHED" + body
        teardown=SOURCE.split("static void dsseWfpTeardown",1)[1]
        drain=teardown[teardown.index("    ExWaitForRundownProtectionRelease"):teardown.index("    for (UINT32 i=0;i<2;i++)")]
        body += "\nstatic void drainContexts(void) {\n" + drain + "\n}\n"
        main = (ROOT / "test_captive_cases.c").read_text()
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = pathlib.Path(tmp)/"admission.c", pathlib.Path(tmp)/"admission"
            src.write_text(shim+body+main)
            subprocess.run([compiler,"-std=c11","-Wall","-Wextra","-Werror","-Wno-multichar","-I",str(ROOT),str(src),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)

    def test_guard_is_not_cleared_by_normal_policy_or_owner_operations(self):
        for name, following in [("SET_POLICY", "CLEAR_POLICY"), ("CLEAR_POLICY", "ARM_CAPTIVE"), ("ARM_OWNER", "GET_STATS")]:
            body = SOURCE.split("case IOCTL_DSSE_" + name + ":", 1)[1].split("case IOCTL_DSSE_" + following + ":", 1)[0]
            self.assertNotIn("dsseCaptiveRecover", body)
            self.assertNotIn("dsseCaptiveFinish", body)
            self.assertNotIn("g_captive.Active =", body)
        close = SOURCE.split("if (sp->MajorFunction == IRP_MJ_CLOSE)", 1)[1].split("static NTSTATUS dsseDispatchDeviceControl", 1)[0]
        self.assertNotIn("dsseCaptiveRecover", close)
        self.assertNotIn("dsseCaptiveFinish", close)
        self.assertNotIn("g_captive.Active =", close)

    def test_ale_layers_and_lifetime_unload_contract(self):
        for layer in ("ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6", "ALE_AUTH_RECV_ACCEPT_V4", "ALE_AUTH_RECV_ACCEPT_V6", "ALE_FLOW_ESTABLISHED_V4", "ALE_FLOW_ESTABLISHED_V6"):
            self.assertIn("&FWPM_LAYER_" + layer, SOURCE)
        self.assertNotIn("&FWPM_LAYER_OUTBOUND_IPPACKET", SOURCE)
        teardown=SOURCE.split("static void dsseWfpTeardown",1)[1].split("/* --- IOCTL",1)[0]
        self.assertLess(teardown.index("ExWaitForRundownProtectionRelease"),teardown.index("FwpsFlowRemoveContext"))
        self.assertLess(teardown.index("FwpsFlowRemoveContext"),teardown.index("FwpsCalloutUnregisterById(g_captiveFlowCallouts"))
        self.assertIn("removed != STATUS_PENDING",teardown)


if __name__ == "__main__":
    unittest.main()
