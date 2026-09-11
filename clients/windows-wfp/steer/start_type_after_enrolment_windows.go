//go:build windows

package main

// start_type_after_enrolment_windows.go — raise DsseSteer to auto-start at the one moment the installer cannot.
//
// ★★ THE RECONCILE HAD NO TRIGGER AFTER ENROLMENT, SO A FRESH INSTALL COULD NEVER REACH AUTO-START
// (2026-09-07, measured on this box: enrolled, steering, healthy, and still START_TYPE 3 DEMAND_START).
//
// The pieces were all correct and none of them met. The MSI installs DsseSteer demand-start deliberately:
// before enrolment the agent cannot build a transport, and auto-starting it would black-hole the box on its
// first boot. profileapply --reconcile-start-type raises demand -> auto once the box is enrolled, and the MSI
// runs it on every install and upgrade. But the install does not enrol — the agent enrols itself on its first
// service start — so at the moment the reconcile runs, deviceIsEnrolled() is false and it correctly declines:
//
//	profileapply: no device identity at %ProgramData%\DSSE\enroll — this box is not enrolled yet,
//	              leaving DsseSteer on demand-start
//
// and nothing ever asks again. The result is a device that steers today and silently stops steering after its
// next reboot — the same delayed failure the reconcile was written to end, arriving by a different road.
//
// The fix belongs here rather than in the installer because THIS is where the missing condition becomes true.
// The agent is the only thing that knows the instant it acquired an identity.
//
// It keeps the reconcile's two rules exactly:
//   - it only ever raises demand -> auto, never the reverse. An operator who parked the service is making a
//     decision this has no business overruling, and "the agent turned itself on" is a worse surprise than a
//     stale demand-start.
//   - a failure is reported, never fatal. Steering that works today must not be refused because the start type
//     for the next boot could not be written.

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// raiseOwnStartTypeAfterEnrolment moves DsseSteer from demand-start to auto-start now that this device holds
// an identity. Called on the enrolment path only, after the identity is on disk and loadable.
//
// Silent when there is nothing to do: a box that is already auto-start says nothing, because an agent that
// announces a no-op on every start teaches its operator to skip the line that matters.
func raiseOwnStartTypeAfterEnrolment(serviceRun bool, justEnrolled bool) {
	// Run by hand rather than under the SCM there is no service to reconfigure, and the process may not even
	// hold the privilege. Saying so beats a permission error that looks like a fault.
	if !serviceRun {
		return
	}
	current, err := ownStartType()
	if err != nil {
		fmt.Printf("steer: could not read DsseSteer's start type (%v) — this device is enrolled and steering, "+
			"but whether it steers after the next reboot is now unknown\n", err)
		return
	}
	if current == windows.SERVICE_AUTO_START {
		return
	}
	if err := setOwnStartTypeAuto(); err != nil {
		fmt.Printf("steer: could not raise DsseSteer to auto-start (%v) — this device is enrolled and steering "+
			"NOW, and will NOT steer after the next reboot until somebody runs "+
			"`sc config DsseSteer start= auto`\n", err)
		return
	}
	// The two paths reach here for different reasons and an operator reading the log needs to know which:
	// one is a device that has just joined, the other is a device that joined long ago and was left on
	// demand-start by an installer that ran before it had an identity. Printing the same sentence for both is
	// how a repair gets read as a fresh enrolment.
	why := "this device has just enrolled, and the installer could not set it: at install time there was no " +
		"identity to derive it from"
	if !justEnrolled {
		why = "this device was already enrolled before this start, and nothing had raised it since — the " +
			"installer that put it here ran before the identity existed"
	}
	fmt.Printf("steer: DsseSteer start type raised to auto (was %d) — %s\n", current, why)
}

// ownStartType reads DsseSteer's configured start type.
func ownStartType() (uint32, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := m.OpenService("DsseSteer")
	if err != nil {
		return 0, err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return 0, err
	}
	return cfg.StartType, nil
}

// setOwnStartTypeAuto flips ONLY the start type, via ChangeServiceConfig with SERVICE_NO_CHANGE everywhere
// else — so the ImagePath, which contains the agent's arguments and spaces, is left exactly as installed.
// Rewriting it here is how a service ends up with a truncated command line that only shows up at the next boot.
func setOwnStartTypeAuto() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("DsseSteer")
	if err != nil {
		return err
	}
	defer s.Close()
	return windows.ChangeServiceConfig(s.Handle,
		windows.SERVICE_NO_CHANGE,  // service type
		windows.SERVICE_AUTO_START, // start type -> auto
		windows.SERVICE_NO_CHANGE,  // error control
		nil, nil, nil, nil, nil, nil, nil)
}
