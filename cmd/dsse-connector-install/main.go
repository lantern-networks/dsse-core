// Command dsse-connector-install puts a connector on a machine inside a customer's network.
//
// ★★★ THE ONLY PATH A CUSTOMER HAD WAS A COMMAND LINE TO KEEP (operator's instruction, 2026-08-26). The
// Console hands out one long `dsse-connector --token … --state-dir …`. Run it and you have a process: not a
// service, not something that comes back after a reboot, and nothing that says whether it worked. Everything
// beyond "it printed no error" — did it enrol, did it get an identity, can it reach more than one region —
// was left to whoever typed it.
//
// This is the connector's half of what dsse-install is for the deployment: it takes the ONE thing the
// customer carries in (the token), leaves the machine with a connector that survives a reboot, and then says
// what is true rather than what was attempted.
//
// ★ IT MINTS NOTHING AND DECIDES NOTHING. A connector's identity comes from the deployment's PKI through
// enrolment; its configuration comes from the deployment's profile. This installer places files and a
// service, and every value in them came out of the token or out of the deployment.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	token := flag.String("token", "",
		"the one-time enrolment token from the Console's Add connector. It carries which deployment, which "+
			"site, the address(es) to reach it on, and the certificate authority to pin — so nothing else "+
			"here has to be typed")
	stateDir := flag.String("state-dir", "/var/lib/dsse-connector",
		"where this connector keeps its identity and what it has learned. It must survive a reboot: a "+
			"connector that loses this enrols again as a DIFFERENT connector, and the routes an operator "+
			"authored for the old one do not follow it")
	binary := flag.String("connector-binary", "/usr/local/bin/dsse-connector",
		"the connector program this machine runs")
	serviceName := flag.String("service-name", "dsse-connector", "the system service to install")
	noService := flag.Bool("no-service", false,
		"write the start script but install no service. The connector then runs only while somebody runs it")
	// ★★★ THE INSTALL RUN CANNOT ANSWER THE QUESTIONS THIS INSTALLER EXISTS FOR. At install time the
	// connector has not started: whether it enrolled, whether the deployment issued it an identity, and
	// whether it can reach more than one region all become true on the FIRST RUN. -verify asks the machine
	// afterwards, from what the connector persisted and from the doors themselves. See verify.go.
	// ★★★ THE FILE A CUSTOMER CARRIES (operator's instruction, 2026-08-26): a connector gets what an agent
	// gets — a token AND a profile, downloaded from the Console rather than selected out of a browser as a
	// wall of base64 and pasted into a terminal on another machine. See profile.go.
	profile := flag.String("profile", "",
		"the connector install profile downloaded from the Console's Add connector. It carries the one-time "+
			"token and this connector's durable configuration, so -token is not needed as well")
	verify := flag.Bool("verify", false,
		"check what this machine ended up with, after the connector has run at least once: whether it "+
			"enrolled, whether its identity came from this deployment, whether every door it knows answers "+
			"it, and whether it survives a reboot")
	flag.Parse()

	// ★ THE PROFILE MAY CHOOSE THE STATE DIRECTORY, BUT ONLY IF THE OPERATOR DID NOT. -state-dir has a
	// default, so "was it given" cannot be read off its value; flag.Visit is what actually distinguishes an
	// operator who typed the default from one who typed nothing. Getting this backwards would silently move a
	// connector's identity somewhere the operator did not choose.
	chosen := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { chosen[f.Name] = true })

	if strings.TrimSpace(*profile) != "" {
		if strings.TrimSpace(*token) != "" {
			fmt.Fprintf(os.Stderr, "dsse-connector-install: give -profile or -token, not both: they are two "+
				"forms of the same issue, and a second issue invalidates the first. Nothing was written\n")
			os.Exit(1)
		}
		profileToken, profileStateDir, err := readInstallProfile(*profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dsse-connector-install: %v\n", err)
			os.Exit(1)
		}
		*token = profileToken
		if profileStateDir != "" && !chosen["state-dir"] {
			*stateDir = profileStateDir
		}
	}

	if *verify {
		if err := reportVerify(*stateDir, verifyConnector(*stateDir, *binary, *serviceName, time.Now())); err != nil {
			os.Exit(1)
		}
		return
	}

	if err := run(*token, *stateDir, *binary, *serviceName, *noService); err != nil {
		fmt.Fprintf(os.Stderr, "dsse-connector-install: %v\n", err)
		os.Exit(1)
	}
}

// enrolmentToken is the part of the token this installer reads. It never uses the bootstrap secret: that is
// the connector's to spend, once, and copying it anywhere else is a second place it can leak from.
type enrolmentToken struct {
	Version       int    `json:"v"`
	EdgeURL       string `json:"edge_url"`
	EdgeEndpoints string `json:"edge_endpoints"`
	TenantID      string `json:"tenant_id"`
	Site          string `json:"site"`
	EdgeCAPEM     string `json:"edge_ca"`
	// OrgServerName / OrgAnchorsPEM are the organization's own door and the authority that signs it. Read
	// here only to SAY so: the connector takes them from the same token, and an operator who cannot see
	// which certificate this machine will pin cannot tell the two cases apart.
	OrgServerName string `json:"org_server_name"`
	OrgAnchorsPEM string `json:"org_anchors"`
}

func run(token, stateDir, binary, serviceName string, noService bool) error {
	parsed, err := readToken(token)
	if err != nil {
		return err
	}
	// ★★★ REFUSE RATHER THAN INSTALL SOMETHING THAT CANNOT WORK. A connector with no address to dial is a
	// service that starts, retries for ever and fronts nothing, and the machine it is on looks configured.
	// The deployment has already been made to refuse issuing such a token; this refuses to install one too,
	// because a token can also be pasted in by hand.
	if strings.TrimSpace(parsed.EdgeURL) == "" && strings.TrimSpace(parsed.EdgeEndpoints) == "" {
		return fmt.Errorf("this token names no address to reach the deployment on, so the connector it " +
			"installs could never connect. Nothing was written")
	}
	if strings.TrimSpace(parsed.Site) == "" {
		return fmt.Errorf("this token names no site, so an operator would have nothing to author routes " +
			"against. Nothing was written")
	}
	// ★★★ AND REFUSE WHEN THE PROGRAM IT WOULD START IS NOT HERE. Measured 2026-08-26 by running this
	// installer on a machine with no connector on it: it wrote a start script and a service pointing at
	// /usr/local/bin/dsse-connector, said nothing, and exited 0. That is a unit systemd restarts for ever on
	// a machine that looks configured — the same failure this installer refuses a door-less token to avoid,
	// arrived at from the other side. It is checked BEFORE anything is written, so a refusal leaves nothing
	// behind. -connector-binary is how a machine that keeps it elsewhere says so.
	if _, err := os.Stat(binary); err != nil {
		// The download lane hands out one archive holding both programs, and the Console tells the operator to
		// run this one from where it was extracted — so look there before refusing. See
		// the_program_ships_beside_this_one.go for what the screen printed and what happened.
		from, aerr := adoptTheProgramShippedBesideThisOne(binary)
		if aerr != nil {
			return fmt.Errorf("there is no connector program at %s, so the service this would install could "+
				"never start one: %v. Put the connector there (or name it with -connector-binary). Nothing "+
				"was written", binary, aerr)
		}
		fmt.Printf("dsse-connector-install: the connector program shipped beside this installer, so it is now "+
			"at %s where the service will look for it (from %s)\n", binary, from)
	}
	// ★ AND THIS PROGRAM GOES BESIDE IT, because --verify is meant to be run later — see
	// the_program_ships_beside_this_one.go. A failure here is said and not fatal: the connector is what the
	// site needs, and refusing to install it because the check could not be copied would be the wrong trade.
	if at, ierr := installThisInstallerBesideTheProgram(binary); ierr != nil {
		fmt.Printf("dsse-connector-install: could not put this installer beside the connector (%v) — run "+
			"--verify from wherever you extracted it\n", ierr)
	} else if at != "" {
		fmt.Printf("dsse-connector-install: this installer is now at %s, so `dsse-connector-install --verify` "+
			"works on this machine after the extracted copy is gone\n", at)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", stateDir, err)
	}

	scriptPath := filepath.Join(stateDir, "start-connector.sh")
	if err := os.WriteFile(scriptPath, []byte(startScript(token, stateDir, binary)), 0o700); err != nil {
		return fmt.Errorf("write %s: %w", scriptPath, err)
	}

	fmt.Printf("dsse-connector-install: %s\n", stateDir)
	fmt.Printf("  site        %s\n", parsed.Site)
	fmt.Printf("  organization %s\n", parsed.TenantID)
	for i, door := range doorsOf(parsed) {
		fmt.Printf("  door %d      %s\n", i+1, door.display())
	}
	fmt.Printf("  %s\n", doorsNote(len(doorsOf(parsed))))
	// ★ WHOSE CERTIFICATE THIS CONNECTOR WILL ACCEPT, in the same block as where it will dial. These are the
	// two halves of "did it reach the right place", and only one of them used to be printed.
	if n := strings.TrimSpace(parsed.OrgServerName); n != "" && strings.TrimSpace(parsed.OrgAnchorsPEM) != "" {
		fmt.Printf("  name        %s — this organization's own; verified against its own authority\n", n)
	} else if strings.TrimSpace(parsed.EdgeCAPEM) != "" {
		fmt.Printf("  name        the address above — this organization has no door of its own, so the\n")
		fmt.Printf("              deployment's shared certificate is what this connector verifies\n")
	}
	if strings.TrimSpace(parsed.EdgeCAPEM) == "" && strings.TrimSpace(parsed.OrgAnchorsPEM) == "" {
		fmt.Printf("  ★ this token pins no certificate authority, so this connector's FIRST connection — the\n")
		fmt.Printf("    one carrying its request for an identity — would trust anything that answers.\n")
	}

	if noService {
		fmt.Printf("  wrote %s. No service was installed, so this connector runs only while somebody runs it.\n", scriptPath)
		return nil
	}
	unitPath, err := installService(serviceName, scriptPath, stateDir)
	if err != nil {
		// ★ NOT FATAL. The machine is left with everything it needs; what is missing is the part that brings
		// it back after a reboot, and saying so is more use than failing after having written the rest.
		fmt.Printf("  ★ no service was installed (%v). This connector will NOT come back after a reboot:\n", err)
		fmt.Printf("    run %s from whatever this machine uses to keep services running.\n", scriptPath)
		return nil
	}
	fmt.Printf("  installed %s — this connector comes back after a reboot.\n", unitPath)
	if serr := startTheServiceThatWasJustInstalled(serviceName); serr != nil {
		fmt.Printf("  ★ it is NOT running: %v\n", serr)
		fmt.Printf("    start it with: systemctl enable --now %s\n", serviceName)
		return nil
	}
	fmt.Printf("  started %s — it appears in the Console as Connected within a few seconds.\n", serviceName)
	return nil
}

func readToken(token string) (enrolmentToken, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return enrolmentToken{}, fmt.Errorf("-token is required: it is what the Console's Add connector hands out")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return enrolmentToken{}, fmt.Errorf("this does not look like an enrolment token (%w). Copy the whole "+
			"of what the Console showed, including any trailing characters", err)
	}
	var parsed enrolmentToken
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return enrolmentToken{}, fmt.Errorf("this token cannot be read (%w)", err)
	}
	return parsed, nil
}

// doorsOf is every address this connector will try, in order.
//
// ★ IT READS THE LIST THE WAY THE CONNECTOR READS IT. parseDoors is the connector's own rule (';' ',' or a
// newline, "region=URL", trailing slash trimmed). Splitting only on ';' here — which is what this did — made
// a comma-separated pair print as ONE door under the "★ one address" warning, while the connector was quietly
// failing over between two. A screen that miscounts the doors is worse than one that shows none.
func doorsOf(t enrolmentToken) []door {
	if doors := parseDoors(t.EdgeEndpoints); len(doors) > 0 {
		return doors
	}
	return parseDoors(t.EdgeURL)
}

func doorsNote(n int) string {
	if n > 1 {
		return "tried in this order; losing one does not take this location off the network"
	}
	return "★ one address: if it stops answering, everything behind this connector is unreachable until it comes back"
}

func startScript(token, stateDir, binary string) string {
	return strings.Join([]string{
		"#!/bin/sh",
		"# Generated by dsse-connector-install. This is the whole of how this connector starts.",
		"#",
		"# ★ THE TOKEN IS SPENT ONCE. After the first successful start this connector has its own identity and",
		"# its own runtime secret in the state directory, and the token in this file is inert — the deployment",
		"# rotated the site's bootstrap secret when it issued it. Keep the file 0700 all the same: until that",
		"# first start, it is a credential.",
		"#",
		"# ★ THE STATE DIRECTORY IS THIS CONNECTOR'S IDENTITY. Delete it and this machine enrols again as a",
		"# DIFFERENT connector: the routes an operator authored for the old one do not follow it, and the old",
		"# one lingers in their list until they remove it.",
		"set -e",
		"exec " + shellQuote(binary) + " \\",
		"  --token " + shellQuote(token) + " \\",
		"  --state-dir " + shellQuote(stateDir),
		"",
	}, "\n")
}

// installService writes a systemd unit. Other init systems are not attempted: writing a unit a machine will
// never read, and reporting success, is worse than saying which part was not done.
func installService(name, scriptPath, stateDir string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("this installer only knows systemd, and this machine is %s", runtime.GOOS)
	}
	dir := "/etc/systemd/system"
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("%s is not there, so this machine does not use systemd", dir)
	}
	unit := strings.Join([]string{
		"[Unit]",
		"Description=DSSE connector",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"ExecStart=" + scriptPath,
		"WorkingDirectory=" + stateDir,
		// A connector that exits has lost its way to the deployment, and everything behind it is unreachable
		// until it is back. Restarting for ever is the correct answer for a thing whose absence is an outage.
		"Restart=always",
		"RestartSec=5",
		"# The state directory holds this connector's identity: nothing else on the machine needs to read it.",
		"UMask=0077",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
	path := filepath.Join(dir, name+".service")
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// shellQuote makes a value safe inside the generated script. A token is base64url and a path is a path, but
// this file is executed by a shell and a value carrying a metacharacter would be RUN — the same defect the
// deployment's own env file carries a warning about.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
