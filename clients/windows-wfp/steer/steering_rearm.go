package main

import (
	"errors"
	"fmt"
)

// rearmSteering keeps the intentional native-network posture until every
// configured steering component has been restored. WFP is published last so
// a failed DNS or QUIC setup cannot leave a partly armed endpoint reported as
// recovered. Callers retain their disarmed flag until this returns nil.
func rearmSteering(addQUIC func() error, removeQUIC func() error, convergeDNS func() error, restoreDNS func() error, resumeWFP func() error, clearWFP func() error) error {
	quicAttempted := false
	rollback := func() error {
		var err error
		if restoreDNS != nil {
			err = restoreDNS()
		}
		if quicAttempted && removeQUIC != nil {
			err = errors.Join(err, removeQUIC())
		}
		return err
	}
	if addQUIC != nil {
		quicAttempted = true
		if err := addQUIC(); err != nil {
			return errors.Join(fmt.Errorf("QUIC block: %w", err), rollback())
		}
	}
	if convergeDNS != nil {
		if err := convergeDNS(); err != nil {
			return errors.Join(fmt.Errorf("DNS takeover: %w", err), rollback())
		}
	}
	if resumeWFP != nil {
		if err := resumeWFP(); err != nil {
			var clearErr error
			if clearWFP != nil {
				clearErr = clearWFP() // SET outcome may be uncertain; verify a final CLEAR.
			}
			return errors.Join(fmt.Errorf("WFP policy: %w", err), clearErr, rollback())
		}
	}
	return nil
}
