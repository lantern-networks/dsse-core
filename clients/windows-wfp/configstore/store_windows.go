//go:build windows

package configstore

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// DefaultKeyPath is the production config-store key. It lives under HKLM and its ACL must be
// SYSTEM/Admin-only so a non-admin cannot edit it (the MSI sets that ACL at install time).
const DefaultKeyPath = `SOFTWARE\DSSE\Agent`

// RegistryBackend persists config-store values under a registry key. The root (LOCAL_MACHINE in production,
// CURRENT_USER in tests to avoid needing admin) and path are parameterized.
type RegistryBackend struct {
	root registry.Key
	path string
}

// OpenRegistryBackend returns a Backend over root\path, creating the key if absent. Writing needs the key to be
// writable (HKLM => admin); reading needs only QUERY_VALUE.
func OpenRegistryBackend(root registry.Key, path string) (*RegistryBackend, error) {
	k, _, err := registry.CreateKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	_ = k.Close()
	return &RegistryBackend{root: root, path: path}, nil
}

// ProductionRegistryBackend opens the default HKLM config-store key (requires admin to write).
func ProductionRegistryBackend() (*RegistryBackend, error) {
	return OpenRegistryBackend(registry.LOCAL_MACHINE, DefaultKeyPath)
}

func (b *RegistryBackend) Get(name string) (string, bool, error) {
	k, err := registry.OpenKey(b.root, b.path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if err == registry.ErrNotExist {
			return "", false, nil
		}
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		if err == registry.ErrNotExist {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (b *RegistryBackend) Set(name, value string) error {
	k, err := registry.OpenKey(b.root, b.path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

// hardenedDACL is the config-store key's target DACL: LocalSystem (SY) and Administrators (BA) get full
// control, Users (BU) get read-only, and "P" makes it PROTECTED so the parent HKLM\SOFTWARE ACL cannot
// re-widen it by inheritance. This is defense-in-depth against a non-admin editing the persisted profile
// envelope. It is NOT the primary tamper protection — a local admin can rewrite any DACL, so the real guard
// stays verify-on-read against the baked trust anchor (the S1 mitigation). SY keeps full control so the
// SYSTEM service and installer can still read/write.
const hardenedDACL = "D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)"

// regObjectName maps a registry root+path to the object name SetNamedSecurityInfo expects for SE_REGISTRY_KEY.
func regObjectName(root registry.Key, path string) (string, error) {
	switch root {
	case registry.LOCAL_MACHINE:
		return `MACHINE\` + path, nil
	case registry.CURRENT_USER:
		return `CURRENT_USER\` + path, nil
	default:
		return "", fmt.Errorf("configstore: unsupported registry root %v for ACL hardening", root)
	}
}

// HardenKeyACL applies hardenedDACL to root\path. It needs WRITE_DAC on the key (the installer runs the
// harden step as SYSTEM). Idempotent — safe to re-run on every install/upgrade. The key must already exist.
func HardenKeyACL(root registry.Key, path string) error {
	name, err := regObjectName(root, path)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(hardenedDACL)
	if err != nil {
		return fmt.Errorf("configstore: parse hardened DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("configstore: extract DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("configstore: set DACL on %s: %w", name, err)
	}
	return nil
}

// HardenProductionKeyACL hardens the production HKLM config-store key. The caller must have created it first
// (ProductionRegistryBackend does) and must run with WRITE_DAC (SYSTEM/admin).
func HardenProductionKeyACL() error {
	return HardenKeyACL(registry.LOCAL_MACHINE, DefaultKeyPath)
}

func (b *RegistryBackend) Clear() error {
	// Delete the values we own (leave the key itself; the MSI owns key lifecycle + ACL).
	k, err := registry.OpenKey(b.root, b.path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	defer k.Close()
	for _, name := range []string{valEnvelope, valPin, valSource, valAppliedAt, valVersion, valTenant} {
		if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			return err
		}
	}
	return nil
}
