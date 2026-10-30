package main

// verify_the_store_can_lose_a_place.go — asking the consensus store how many votes it has, and where.
//
// ★★★ "GREEN BUT NOT REDUNDANT" IS THE STATE THIS EXISTS TO REFUSE TO CALL GREEN (2026-08-31).
//
// A store grows by joining: the founding member starts a cluster of one, each later region is added as a
// learner and promoted when it has caught up. Every stop along the way is a working deployment. Two voting
// members is a working deployment that cannot lose one — and a deployment that has been told it is redundant
// and is not will find out during the failure it was built for.
//
// ★ AND IT IS ASKED, NOT READ. The number of members this deployment MEANT to have is in its own environment
// file, and reporting that would say "configured" while measuring nothing. A member that was added and never
// started, or promoted and then lost, is exactly the case worth catching, and only the cluster knows.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type storeMemberReport struct {
	Name      string   `json:"name"`
	PeerURLs  []string `json:"peerURLs"`
	IsLearner bool     `json:"isLearner"`
}

type storeQuorumSurvival struct {
	voting, learners, places, quorum, worstRemaining int
	survives                                         bool
}

// A lost place removes every voting member located there, not merely one vote.
func storeSurvivalByPlace(members []storeMemberReport) (storeQuorumSurvival, error) {
	var result storeQuorumSurvival
	votesByPlace := map[string]int{}
	for _, member := range members {
		if member.IsLearner {
			result.learners++
			continue
		}
		placeNames := map[string]bool{}
		for _, peerURL := range member.PeerURLs {
			if place := hostOfURL(peerURL); place != "" {
				placeNames[place] = true
			}
		}
		if len(placeNames) != 1 {
			return result, fmt.Errorf("voting member %q does not have exactly one identifiable place", member.Name)
		}
		for place := range placeNames {
			votesByPlace[place]++
		}
		result.voting++
	}
	result.places = len(votesByPlace)
	result.quorum = result.voting/2 + 1
	result.worstRemaining = result.voting
	for _, votes := range votesByPlace {
		if remaining := result.voting - votes; remaining < result.worstRemaining {
			result.worstRemaining = remaining
		}
	}
	result.survives = result.places >= 3 && result.worstRemaining >= result.quorum
	return result, nil
}

// verifyTheStoreCanLoseAPlace asks each member it can reach for the cluster's membership, and reports whether
// losing one of the places those members sit in leaves a quorum.
func verifyTheStoreCanLoseAPlace(dir string, env map[string]string) []verifyResult {
	hosts := storeClientHosts(env["DSSE_ETCD_HOSTS"])
	if !strings.EqualFold(strings.TrimSpace(env["DSSE_ETCD_CLIENT_SCHEME"]), "https") || len(hosts) == 0 {
		// ★ A ONE-HOST DEPLOYMENT HAS NOTHING TO SAY HERE, and saying nothing is the honest answer: its store
		// is three members on the machine that is the deployment, and losing that machine loses everything
		// either way. This check is about a store whose members are in different places.
		return []verifyResult{{
			ok:   true,
			name: "the consensus store spans places",
			note: "this deployment keeps state in one place, so there is no place it can lose — the question " +
				"this asks does not apply to it",
		}}
	}
	client, err := storeClient(dir)
	if err != nil {
		return []verifyResult{{
			name: "the consensus store was asked how many votes it has",
			note: fmt.Sprintf("could not present this deployment's store material: %v", err),
		}}
	}
	var members []storeMemberReport
	var asked, reachedFrom string
	for _, h := range hosts {
		got, aerr := askStoreForItsMembers(client, h)
		if aerr != nil {
			asked += fmt.Sprintf("  %s: %v\n", h, aerr)
			continue
		}
		members, reachedFrom = got, h
		break
	}
	if members == nil {
		return []verifyResult{{
			name: "the consensus store was asked how many votes it has",
			note: "no member answered, so nothing here knows whether the deployment's authority can survive " +
				"anything:\n" + asked,
		}}
	}

	quorumState, quorumErr := storeSurvivalByPlace(members)
	if quorumErr != nil {
		return []verifyResult{{name: "the consensus store can lose one place", note: quorumErr.Error()}}
	}
	names := []string{}
	for _, m := range members {
		label := m.Name
		if m.IsLearner {
			label += " (learner, no vote)"
		}
		names = append(names, label)
	}
	// A quorum is more than half the voting members. The worst place to lose may hold more than one vote.
	note := fmt.Sprintf("%d voting member(s) in %d place(s)", quorumState.voting, quorumState.places)
	if quorumState.learners > 0 {
		note += fmt.Sprintf(", and %d learner(s) that do not vote yet", quorumState.learners)
	}
	note += fmt.Sprintf(" — %s. Asked at %s.", strings.Join(names, ", "), reachedFrom)
	if !quorumState.survives {
		note += fmt.Sprintf(" ★ LOSING ONE LEAVES %d OF A QUORUM OF %d: promotion would be MANUAL, and until "+
			"it happened the deployment would enforce and could not be authored. Distribute voting members "+
			"so the loss of any one place still leaves quorum.", quorumState.worstRemaining, quorumState.quorum)
	}
	return []verifyResult{{ok: quorumState.survives, name: "the consensus store can lose one place", note: note}}
}

// storeClientHosts turns Patroni's host list — 'a:2379','b:2379' — into addresses.
func storeClientHosts(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		h := strings.Trim(strings.TrimSpace(part), "'\"")
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func hostOfURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	return s
}

// storeClient presents this machine's own member material, because the store is configured to ask for one.
func storeClient(dir string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, storeMemberFile), filepath.Join(dir, storeMemberKeyFile))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, storeCAFile))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no certificate", storeCAFile)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		}},
	}, nil
}

// askStoreForItsMembers uses etcd's HTTP gateway, so this needs no client library and no shelling out.
func askStoreForItsMembers(client *http.Client, hostPort string) ([]storeMemberReport, error) {
	resp, err := client.Post("https://"+hostPort+"/v3/cluster/member/list", "application/json",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	var body struct {
		Members []storeMemberReport `json:"members"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&body); derr != nil {
		return nil, derr
	}
	if len(body.Members) == 0 {
		return nil, fmt.Errorf("answered with no members")
	}
	return body.Members, nil
}
