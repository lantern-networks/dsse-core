package main

import (
	"regexp"
	"strings"
	"testing"
)

// ★★★ THE DOORWAY EXITED ON A DEFAULT LINUX HOST (2026-08-27, measured on the first deployment with one
// component per machine):
//
//	[ALERT] (1) : [haproxy.main()] Cannot raise FD limit to 131109, limit is 32768.
//
// haproxy reserves descriptors for maxconn across every proxy in its file and asks the kernel for them at
// start-up; an ordinary host allows far fewer. The region's doorway is the one service whose absence looks
// like the entire deployment being down.
//
// ★ IT NEVER APPEARED ON THE DEVELOPMENT MACHINE, because Docker Desktop and colima hand containers a very
// large limit. That is what a one-host lab certifies: that it works on the machine it was written on.
func TestEveryFrontDoorDeclaresTheDescriptorsItNeeds(t *testing.T) {
	compose := composeTemplateForTest(t)
	lines := strings.Split(compose, "\n")

	imageLine := regexp.MustCompile(`^\s+image: \$\{DSSE_HAPROXY_IMAGE`)
	svcDecl := regexp.MustCompile(`^  ([a-z0-9-]+):`)

	current := ""
	var doorways []string
	declares := map[string]bool{}
	for i, l := range lines {
		if m := svcDecl.FindStringSubmatch(l); m != nil {
			current = m[1]
		}
		if imageLine.MatchString(l) {
			doorways = append(doorways, current)
			// The limit must be declared within this service's block, before the next service starts.
			for j := i; j < len(lines); j++ {
				if j > i && svcDecl.MatchString(lines[j]) {
					break
				}
				if strings.Contains(lines[j], "nofile:") {
					declares[current] = true
					break
				}
			}
		}
	}
	if len(doorways) == 0 {
		t.Fatal("no front door was found, so this check measured nothing")
	}
	for _, d := range doorways {
		if !declares[d] {
			t.Fatalf("%q is a front door and declares no descriptor limit — on an ordinary host it exits at "+
				"start-up, and the region looks entirely down", d)
		}
	}
}
