package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// carry.go — the deployment directory, packed for a machine that is not the one that minted it.
//
// ★★★ THE INSTRUCTION WAS "CARRY THE DEPLOYMENT DIRECTORY", AND THE DIRECTORY HOLDS THE ROOT KEY
// (2026-08-27, measured while standing up the AWS lab with one component per machine). region.go tells an
// operator to carry the directory "as privately as it was created" and points -dir at the copy. That is
// correct about privacy and silent about extent — so what arrives on the Edge's machine is everything,
// including authority/, which is the deployment's root CA private key and the three beside it.
//
// the_authority_is_not_a_runtime_possession.go moved those out of reach of every running process, precisely
// so a split deployment does not put the root key on an Edge box. The carry put it back, one directory at a
// time, by hand — on the lab it was noticed and deleted afterwards, which is not a property of the product.
//
// ★★ WHAT A RECEIVING MACHINE ACTUALLY NEEDS is the certificates, the leaves and their keys, the deployment's
// description and the signing key an Edge's policy loader would otherwise MINT ITS OWN of (region.go refuses
// without it, for a reason worth reading). None of that is under authority/. A machine that is not minting
// never opens it, so it never needs to hold it — and holding what you never open is the whole of this defect.
//
// ★ IT IS A TARBALL AND NOT A COPY COMMAND. The modes travel: a private key that arrives 0644 because it went
// through scp on a machine with a friendly umask is a different failure with the same cause, and a tar header
// carries the mode the installer set.

// carryDeploymentFor writes, for ONE machine, exactly what that machine's services mount and name.
//
// ★★★ THE SHAPE IS THE QUESTION. Every component is its own hardware and its own operating system, so what a
// machine may hold is what ITS compose says it runs — not what the region holds. The compose for that machine
// is rendered here, in memory, and everything else follows from it: the files are the paths its services
// mount, and deployment.env is filtered to the values its services and their start scripts name.
//
// ★ IT RETURNS THE TWO LISTS RATHER THAN PRINTING THEM. What was withheld is the whole point of this command,
// and a test that re-derives it from the directory would pass while this function answered something else.
// ★★★ AND THE REGION IT IS BEING CARRIED FOR (2026-08-28, measured standing up a second site). -carry
// -region region-b names the region, and the file that arrived said DSSE_EDGE_REGION='region-a' — the name of
// the region it was packed FROM. It is the name devices use to choose a region and the name every record from
// there carries, so a second site that started as carried would have reported itself as the first one, and the
// region map devices are handed would have had two entries pointing at the same name.
//
// The installer's closing note tells an operator to change it by hand. It did not need to be told: the flag
// that packs the machine already says which region it is for.
// planValues, when a plan decided this machine's answers, are written into the deployment.env it carries —
// here, where the region rename and the address blanking already happen, so a machine is packed correct
// rather than corrected afterwards.
func carryDeploymentFor(dir, dest string, shape machineShape, region string, planValues map[string]string) (carried, withheld []string, err error) {
	if _, serr := os.Stat(filepath.Join(dir, "deployment-anchor.pem")); serr != nil {
		return nil, nil, fmt.Errorf("%s does not look like a deployment directory (no deployment-anchor.pem): %w", dir, serr)
	}
	if _, serr := os.Stat(dest); serr == nil {
		// ★ NEVER OVER AN EXISTING FILE. The thing being written holds private keys; silently replacing
		// something is how the wrong deployment ends up on a machine.
		return nil, nil, fmt.Errorf("%s already exists — name a path that does not, so nothing is overwritten", dest)
	}
	compose, cerr := composeBodyFor(dir, shape)
	if cerr != nil {
		return nil, nil, cerr
	}
	envBody, rerr := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if rerr != nil {
		return nil, nil, rerr
	}
	env, envWithheld := deploymentEnvFor(string(envBody), valuesThisMachineReads(dir, compose))
	if r := strings.TrimSpace(region); r != "" {
		env = renameRegionIn(env, r)
		env = blankThisMachinesAddresses(env)
	}
	if len(planValues) > 0 {
		env = PlanEnvironmentFor(env, planValues)
	}

	needed := map[string]bool{}
	for _, m := range filesThisMachineReads(compose) {
		needed[m] = true
	}
	// ★ THE ANCHOR AND THE TWO FILES THE MACHINE IS STARTED FROM. The anchor is what every certificate here is
	// verified against and what -verify reads first; neither it nor the compose nor the environment file is
	// mounted INTO a service, so none of them appears in the mount list — and a machine without them holds
	// material it has no way to use.
	needed["deployment.env"] = true
	needed["docker-compose.yml"] = true
	// ★ AND WHAT THIS PROGRAM READS ON THAT MACHINE. See installerReadsFromDeploymentDir: without root.crt a
	// carried machine reads as an EMPTY directory, and -region refuses it as the second deployment it is not.
	for _, f := range installerReadsFromDeploymentDir {
		needed[f] = true
	}

	out, oerr := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if oerr != nil {
		return nil, nil, oerr
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	// ★ REPLACED RATHER THAN COPIED. The compose is the one rendered for THIS machine, and the environment is
	// the filtered copy — the files on the operator's disk describe the machine the installer is standing on.
	replaced := map[string]string{"docker-compose.yml": compose, "deployment.env": env}
	// ★★★ THIS MACHINE'S OWN MEMBER MATERIAL, AND NOBODY ELSE'S (2026-08-31). The two paths are the same on
	// every machine and the bytes are not: the packing machine's copies are in this directory, and shipping
	// those would put the founding member's private key on every other machine. Substituting them here is the
	// same act as substituting the compose file and the environment, for the same reason.
	if len(planValues) > 0 {
		cert, key, serr := storeMemberMaterialFor(dir, planValues, time.Now().UTC(), storeMemberYears)
		if serr != nil {
			return nil, nil, serr
		}
		if cert != nil {
			replaced[storeMemberFile] = string(cert)
			replaced[storeMemberKeyFile] = string(key)
		}
	}

	carried, withheld = []string{}, []string{}
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		// ★★★ THE MINTING MATERIAL, STRUCTURALLY. Not a list of key names to keep in step with authorityFiles,
		// and not a --exclude an operator has to remember: the directory that exists to hold what only the
		// installer reads is the directory that does not travel.
		if rel == authorityDirName || strings.HasPrefix(rel, authorityDirName+string(filepath.Separator)) {
			if d.IsDir() {
				// ★ NAMED BEFORE IT IS SKIPPED. Skipping the directory means never walking its files, so
				// asking the walk what was withheld answers "nothing" — and the one sentence this command
				// exists to print is the one that then does not appear. Read here instead.
				if entries, derr := os.ReadDir(path); derr == nil {
					for _, e := range entries {
						withheld = append(withheld, filepath.ToSlash(filepath.Join(rel, e.Name())))
					}
				}
				return filepath.SkipDir
			}
			withheld = append(withheld, filepath.ToSlash(rel))
			return nil
		}
		// ★★★ AND EVERYTHING THIS MACHINE DOES NOT READ. Its compose named what its services mount; a file
		// outside that set belongs to another component, and handing it over is the shared directory this
		// exists to end.
		if d.IsDir() {
			if underNeeded(needed, rel) || leadsToNeeded(needed, rel) {
				return writeTarDir(tw, d, rel)
			}
			return filepath.SkipDir
		}
		if !needed[rel] && !underNeeded(needed, rel) {
			withheld = append(withheld, filepath.ToSlash(rel))
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		content, has := replaced[filepath.ToSlash(rel)]
		var data []byte
		if has {
			data = []byte(content)
		} else {
			b, oerr := os.ReadFile(path)
			if oerr != nil {
				return oerr
			}
			data = b
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		carried = append(carried, filepath.ToSlash(rel))
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}
	if cerr := tw.Close(); cerr != nil {
		return nil, nil, cerr
	}
	if cerr := gz.Close(); cerr != nil {
		return nil, nil, cerr
	}
	// The credentials that were dropped OUT OF deployment.env are withheld too, and they are the ones that
	// matter most — a reader scanning this list is looking for exactly them.
	for _, v := range envWithheld {
		withheld = append(withheld, "deployment.env:"+v)
	}
	sort.Strings(carried)
	sort.Strings(withheld)
	return carried, withheld, nil
}

// underNeeded reports whether rel is inside a directory this machine mounts whole (schemas/, clickhouse-init/,
// runtime/).
func underNeeded(needed map[string]bool, rel string) bool {
	for n := range needed {
		if strings.HasPrefix(filepath.ToSlash(rel), n+"/") {
			return true
		}
	}
	return false
}

// leadsToNeeded reports whether rel is a parent of something this machine mounts, so the walk descends into it.
func leadsToNeeded(needed map[string]bool, rel string) bool {
	for n := range needed {
		if strings.HasPrefix(n+"/", filepath.ToSlash(rel)+"/") {
			return true
		}
	}
	return false
}

func writeTarDir(tw *tar.Writer, d fs.DirEntry, rel string) error {
	info, err := d.Info()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = filepath.ToSlash(rel) + "/"
	return tw.WriteHeader(hdr)
}

// reportCarry says what is in the file and what is not, because the operator is about to move private keys
// between machines and should be able to say which ones.
func reportCarry(dest, dir string, carried, withheld []string) {
	fmt.Printf("dsse-install: %s holds %d file(s) of %s.\n\n", dest, len(carried), dir)
	fmt.Printf("  ★★★ IT STILL HOLDS PRIVATE KEYS — the leaves this deployment presents, its device CA and the\n")
	fmt.Printf("  key its Edges sign steer policy with. Move it as privately as the directory it came from, and\n")
	fmt.Printf("  delete it from wherever it passed through afterwards.\n\n")
	if len(withheld) > 0 {
		fmt.Printf("  ★★★ WHAT IS NOT IN IT: %s/ — %s.\n", authorityDirName, strings.Join(withheld, ", "))
		fmt.Printf("  That is what this installer SIGNS with, including the deployment's root CA private key. No\n")
		fmt.Printf("  running process reads any of it, so a machine that is not minting never needs to hold it —\n")
		fmt.Printf("  and a machine that holds what it never opens is one break-in away from being the authority.\n")
		fmt.Printf("  Issue from the machine that minted this deployment: -add-host, another region's material,\n")
		fmt.Printf("  and any re-issue all happen there.\n\n")
	}
	fmt.Printf("  On the receiving machine:\n\n")
	fmt.Printf("    mkdir -p /opt/dsse/<region> && tar -xzf %s -C /opt/dsse/<region>\n", filepath.Base(dest))
	fmt.Printf("    dsse-install -dir /opt/dsse/<region> -region <region-name> [-holds-state|-with-standby-control-plane]\n\n")
	fmt.Printf("  ★ Or, for a machine that runs ONE component of a region this deployment already has, untar it\n")
	fmt.Printf("  and start only that component's services — the directory is the same on every machine of a\n")
	fmt.Printf("  region, and what differs is which services are brought up.\n")
}

// renameRegionIn sets DSSE_EDGE_REGION to the region this machine is being carried for. See the note on
// carryDeploymentFor: the value packed is the name of the region it was packed FROM, which is never right for
// a machine that is joining.
func renameRegionIn(env, region string) string {
	lines := strings.Split(env, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "DSSE_EDGE_REGION=") {
			lines[i] = "DSSE_EDGE_REGION='" + region + "'"
			return strings.Join(lines, "\n")
		}
	}
	return env
}

// blankThisMachinesAddresses empties the values that name THIS machine, when packing for another region.
//
// ★★★ A JOINING REGION AROSE HOLDING THE FOUNDING REGION'S ADDRESSES (2026-08-28, measured: docker refused to
// start with "listen tcp4 10.20.1.104:18009: bind: cannot assign requested address", which is region-a's
// address on a machine in Osaka). Docker refusing is the lucky case. The ADVERTISE values fail the other way:
// they are what a member tells the cluster to reach it at, so a Postgres member in the second region would
// have announced itself at the FIRST region's address — two members claiming one address, in the component
// that holds the deployment's state.
//
// Blank rather than guessed. This installer cannot know what the receiving machine's addresses are, and a
// value that is empty stops with a message about a value; a value that is another machine's does not stop.
func blankThisMachinesAddresses(env string) string {
	perMachine := []string{
		"DSSE_REGION_BIND_A",
		"DSSE_PG_A_MEMBER_PUBLISH", "DSSE_PG_A_ADVERTISE", "DSSE_PG_A_API_PUBLISH", "DSSE_PG_A_API_ADVERTISE",
		"DSSE_PG_B_MEMBER_PUBLISH", "DSSE_PG_B_ADVERTISE", "DSSE_PG_B_API_PUBLISH", "DSSE_PG_B_API_ADVERTISE",
		"DSSE_PG_A_NAME", "DSSE_PG_B_NAME",
		// ★ AND THE CONSENSUS STORE'S OWN ADDRESSES (2026-08-28, caught by asserting that no machine holds
		// another's). Only the FOUNDING region's control plane publishes one; every other machine carried
		// these from the directory it was packed from, so an Edge held the address of a control plane in
		// another region. Nothing reads them there, which is why it would never have been noticed — and
		// "nothing reads it today" is how a wrong value waits.
		"DSSE_ETCD_A_PUBLISH", "DSSE_ETCD_B_PUBLISH", "DSSE_ETCD_C_PUBLISH",
		"DSSE_ETCD_A_ADVERTISE", "DSSE_ETCD_B_ADVERTISE", "DSSE_ETCD_C_ADVERTISE",
	}
	blank := map[string]bool{}
	for _, k := range perMachine {
		blank[k] = true
	}
	lines := strings.Split(env, "\n")
	for i, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && blank[key] {
			lines[i] = key + "=''"
		}
	}
	return withTrailingNewline(strings.Join(lines, "\n"))
}
