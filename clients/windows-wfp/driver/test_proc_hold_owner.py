"""Source contract for the WDK-only process-hold owner transition.

This is not a substitute for running the driver on Windows. It catches the
specific interleaving where an old handle closes after a new waiter arms.
"""

import os
import pathlib
import unittest


SOURCE = pathlib.Path(os.environ.get("DSSE_DRIVER_SOURCE_OVERRIDE", pathlib.Path(__file__).with_name("driver.c")))


class HoldOwnerOrderingTest(unittest.TestCase):
    def test_close_clears_owner_interval_and_old_holds_under_one_lock(self):
        source = SOURCE.read_text()
        close = source.split("if (sp->MajorFunction == IRP_MJ_CLOSE)", 1)[1].split("/* Same shape", 1)[0]
        acquire = close.index("KeAcquireInStackQueuedSpinLock(&g_holdLock")
        owner = close.index("g_procWaitOwner = NULL")
        interval = close.index("InterlockedExchange(&g_procHoldMs, 0)")
        release_old = close.index("KeSetEvent(&g_procHolds[i].Evt")
        unlock = close.index("KeReleaseInStackQueuedSpinLock")
        self.assertLess(acquire, owner)
        self.assertLess(owner, interval)
        self.assertLess(interval, release_old)
        self.assertLess(release_old, unlock)

    def test_new_waiter_sets_owner_and_interval_under_same_lock(self):
        source = SOURCE.read_text()
        wait = source.split("case IOCTL_DSSE_WAIT_PROC_EVENTS", 1)[1].split("UINT8* out", 1)[0]
        acquire = wait.index("KeAcquireInStackQueuedSpinLock(&g_holdLock")
        interval = wait.index("InterlockedExchange(&g_procHoldMs, ms)")
        owner = wait.index("g_procWaitOwner = sp->FileObject")
        unlock = wait.index("KeReleaseInStackQueuedSpinLock")
        self.assertLess(acquire, interval)
        self.assertLess(interval, owner)
        self.assertLess(owner, unlock)


if __name__ == "__main__":
    unittest.main()
