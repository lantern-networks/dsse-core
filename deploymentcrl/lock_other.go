//go:build !darwin && !linux && !freebsd

package deploymentcrl

import (
	"fmt"
	"os"
)

func lockIssuerLedger(_ *os.File) error {
	return fmt.Errorf("deployment CRL issuer operations require an OS file lock")
}
func unlockIssuerLedger(_ *os.File) {}
