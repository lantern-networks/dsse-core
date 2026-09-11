package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ★★★ THE PRINTED PROCEDURE FAILED AT ITS SECOND LINE (2026-09-03, walked on a customer-site machine with
// nothing but what the Console hands out).
//
// The Console's "Add connector" screen prints exactly two commands:
//
//	tar xzf dsse-connector-linux-arm64.tar.gz
//	./dsse-connector-install --profile dsse-connector-hq.json
//
// and the archive extracts BOTH programs side by side into the current directory. The installer then refused:
//
//	there is no connector program at /usr/local/bin/dsse-connector, so the service this would install could
//	never start one. Put the connector there (or name it with -connector-binary). Nothing was written
//
// The refusal is right — a service pointing at a program that is not there is worse than no service, which is
// why it exists. What was wrong is that the installer would not look in the one place the download lane had
// just put the program: next to itself. Nobody following the screen could get past this without inventing a
// step the screen does not mention.
//
// So the sibling is now found and PUT where the service will look, rather than merely used from where it sits:
// the extracted directory is somebody's home directory or /tmp, and a service that starts from there breaks
// the first time the directory is tidied away. -connector-binary still overrides everything, and a machine
// that already has the program keeps it — this never overwrites.
func adoptTheProgramShippedBesideThisOne(want string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find this installer's own location: %w", err)
	}
	sibling := filepath.Join(filepath.Dir(self), filepath.Base(want))
	info, err := os.Stat(sibling)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("no connector program next to this installer either (looked at %s)", sibling)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(want), err)
	}
	// Written to a temporary name and renamed, so a machine that loses power mid-copy has either the whole
	// program at that path or nothing at it — never half a binary the service would try to start.
	tmp := want + ".installing"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}
	src, err := os.Open(sibling)
	if err != nil {
		dst.Close()
		os.Remove(tmp)
		return "", fmt.Errorf("read %s: %w", sibling, err)
	}
	_, cerr := io.Copy(dst, src)
	src.Close()
	if err := dst.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("copy the connector program to %s: %w", want, cerr)
	}
	if err := os.Rename(tmp, want); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("put the connector program at %s: %w", want, err)
	}
	return sibling, nil
}

// ★★★ AND THE CHECK THE OPERATOR IS TOLD TO RUN AFTERWARDS WAS NOT THERE EITHER (2026-09-05, walked on a
// customer-site machine with nothing but what the Console hands out).
//
// The screen hands over three things, and the third is "a way to check it — run on the machine afterwards,
// because the Console cannot see what the machine ended up with". Both connector.md and the screen write it
// as a plain command:
//
//	dsse-connector-install --verify
//	sudo: dsse-connector-install: command not found
//
// This installer puts the CONNECTOR where the service will look for it and then leaves ITSELF in whatever
// directory the archive was extracted into — somebody's home directory, or /tmp. The check is the one thing
// meant to be run later, when that directory is long gone, and it is the only one of the three that was not
// installed anywhere.
//
// So it installs itself beside the program it installs. Never overwriting: a machine that already has a
// newer installer keeps it, for the same reason the connector program is never overwritten.
func installThisInstallerBesideTheProgram(programPath string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find this installer's own location: %w", err)
	}
	want := filepath.Join(filepath.Dir(programPath), filepath.Base(self))
	if strings.EqualFold(self, want) {
		return "", nil // already running from where it belongs
	}
	if _, err := os.Stat(want); err == nil {
		return "", nil // this machine already has one; never overwrite
	}
	tmp := want + ".installing"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}
	src, err := os.Open(self)
	if err != nil {
		dst.Close()
		os.Remove(tmp)
		return "", fmt.Errorf("read %s: %w", self, err)
	}
	_, cerr := io.Copy(dst, src)
	src.Close()
	if err := dst.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("copy this installer to %s: %w", want, cerr)
	}
	if err := os.Rename(tmp, want); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("put this installer at %s: %w", want, err)
	}
	return want, nil
}

// ★★★ AND IT DID NOT START (2026-09-03, same walk, one line further on).
//
// The Console's "Add connector" screen says of these two commands: "It starts on its own and starts again
// after a restart." The installer wrote the unit and then printed
//
//	start it with: systemctl enable --now dsse-connector
//
// so the screen promised something the program left to the operator. Either sentence could have been the one
// to change; this changes the program, because the screen is describing the product a customer was sold — a
// connector that is installed is a connector that is running — and because the failure of the other choice is
// silent. A site whose connectors are installed but not started reads as "Down" in the Console with nothing
// to say why, which is the same shape as the unit-pointing-at-a-missing-program this file already refuses.
//
// -no-service is still how a machine says it will run this itself.
func startTheServiceThatWasJustInstalled(serviceName string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("no systemctl on this machine")
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", serviceName}} {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
