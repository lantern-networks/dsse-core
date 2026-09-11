package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// provision_from_the_installers_own_folder.go — doing what the folder's own README says the installer does.
//
// ★★★ THE README PROMISED SOMETHING THE PACKAGE DID NOT DO (2026-09-07, measured on a Windows box by
// following the published instructions exactly).
//
// The Console writes one README into the device folder and sends it to every platform:
//
//	"The installer takes install_profile.json, profile_signing_key.txt and enrolment_token.txt from the
//	 folder it is opened from. Nothing has to be typed, and nothing has to be copied into a system folder."
//
// True on macOS. On Windows the provisioning action is conditioned on the CONFIG property, which has no
// default, so `msiexec /i` from that folder never scheduled it. The install returned 0, the services started,
// and nothing was provisioned — and it was not even logged as skipped, because an action whose condition is
// false is not mentioned at all. A green install that configured nothing and said nothing.
//
// It is worse than "unconfigured" on a box that has been used before. The measured case came up bound to a
// deployment that had been destroyed the previous day, because %ProgramData%\DSSE\ still held that
// deployment's profile and nothing had replaced it.
//
// ★ THE EXPLICIT PATH KEEPS ITS STRICTNESS. CONFIG passed on the command line still means "provision from
// exactly this, and fail the install if it is not there" — a path an operator typed and got wrong is a typo in
// the act they are performing right now, and installing anyway hands them a device that looks installed and
// steers nothing. That is the existing ProvisionFromConsole action and it is unchanged.
//
// This is the other case: nobody typed anything, so the absence of the files is not a mistake — it is a
// package being installed by MDM, or one that carries its own bundled profile, or one that will be configured
// later. Absent means do nothing and say so. Present means provision, and a profile that is present and bad
// still fails loudly, because that IS a mistake somebody made.
// installerFolderArtefacts names the three files the README promises, next to the package being installed.
// msiPath is the MSI's own path (MSI's OriginalDatabase); a directory is accepted too.
func installerFolderArtefacts(msiPath string) (config, token, pin string, ok bool) {
	base := strings.TrimSpace(msiPath)
	if base == "" {
		return "", "", "", false
	}
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		base = filepath.Dir(base)
	}
	config = filepath.Join(base, "install_profile.json")
	token = filepath.Join(base, "enrolment_token.txt")
	pin = filepath.Join(base, "profile_signing_key.txt")
	if _, err := os.Stat(config); err != nil {
		// The README's own file is not here. Not an error: see the note above.
		return config, token, pin, false
	}
	// The token and the key are allowed to be absent independently — a fleet enrolled by MDM spends no token,
	// and a package built for one deployment may carry its own key. doProvision says so for each.
	if _, err := os.Stat(token); err != nil {
		token = ""
	}
	if _, err := os.Stat(pin); err != nil {
		pin = ""
	}
	return config, token, pin, true
}

// describeInstallerFolder is what gets printed when there is nothing to do, so that "did nothing" is a
// statement in the log rather than an absence in it. The whole defect this file exists for was an action that
// was skipped without being mentioned.
func describeInstallerFolder(msiPath, config string) string {
	return fmt.Sprintf("profileapply: no %s beside the installer (%s) — this package was installed without the "+
		"Console's device folder, so nothing was provisioned from it. Pass CONFIG=/TOKEN=/PIN= to provision "+
		"from elsewhere.", filepath.Base(config), filepath.Dir(config))
}
