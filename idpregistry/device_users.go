package idpregistry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// OS identifiers are opaque, case-sensitive principals. Display names and email
// addresses are not substitutes. The endpoint supplies these over device mTLS.
func ValidOSPrincipal(s string) bool {
	if len(s) > 160 {
		return false
	}
	if strings.HasPrefix(s, "windows:S-") {
		parts := strings.Split(strings.TrimPrefix(s, "windows:S-"), "-")
		if len(parts) < 3 || len(parts) > 17 || parts[0] != "1" {
			return false
		}
		for i, part := range parts[1:] {
			bits := 32
			if i == 0 {
				bits = 48
			}
			n, err := strconv.ParseUint(part, 10, bits)
			if err != nil || strconv.FormatUint(n, 10) != part {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(s, "macos:") {
		u := strings.TrimPrefix(s, "macos:")
		if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' || u != strings.ToLower(u) {
			return false
		}
		b, e := hex.DecodeString(strings.ReplaceAll(u, "-", ""))
		return e == nil && len(b) == 16
	}
	return false
}

func ValidOSSession(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

func validateDeviceUserBindings(rows []DeviceUserBinding) error {
	if len(rows) > 10000 {
		return fmt.Errorf("too many device user bindings")
	}
	seen := map[string]bool{}
	for _, b := range rows {
		key := b.DeviceID + "\x00" + b.OSPrincipal
		if b.DeviceID == "" || len(b.DeviceID) > 256 || strings.ContainsAny(b.DeviceID, "\x00\r\n") || !ValidOSPrincipal(b.OSPrincipal) || (b.Revision != "" && !ValidOSSession(b.Revision)) || b.Subject == "" || len(b.Subject) > 512 || strings.TrimSpace(b.Subject) != b.Subject || strings.ContainsAny(b.Subject, "\x00\r\n") || seen[key] {
			return fmt.Errorf("invalid or duplicate device user binding")
		}
		seen[key] = true
	}
	return nil
}

// AssignedSubject does not fall back to domain membership, enrollment admin,
// device.UserID, a display name, or the first person who opens a leaked URL.
func (c Connection) AssignedBinding(device, principal string) (DeviceUserBinding, bool) {
	if !ValidOSPrincipal(principal) || device == "" {
		return DeviceUserBinding{}, false
	}
	var found DeviceUserBinding
	for _, b := range c.DeviceUserBindings {
		if b.DeviceID == device && b.OSPrincipal == principal {
			if found.Subject != "" || b.Subject == "" || !ValidOSSession(b.Revision) {
				return DeviceUserBinding{}, false
			}
			found = b
		}
	}
	return found, found.Subject != ""
}
func (c Connection) AssignedSubject(device, principal string) (string, bool) {
	binding, ok := c.AssignedBinding(device, principal)
	return binding.Subject, ok
}

// A caller cannot pick or restore a revision. Reassignment or removal and
// recreation permanently invalidates previously minted owner evidence.
func renewDeviceUserBindings(next *Connection, previous Connection) error {
	for i, b := range next.DeviceUserBindings {
		old, ok := previous.AssignedBinding(b.DeviceID, b.OSPrincipal)
		if ok && old.Subject == b.Subject {
			next.DeviceUserBindings[i].Revision = old.Revision
		} else {
			var revision [32]byte
			if _, err := rand.Read(revision[:]); err != nil {
				return fmt.Errorf("create device user assignment revision: %w", err)
			}
			next.DeviceUserBindings[i].Revision = hex.EncodeToString(revision[:])
		}
	}
	return nil
}
