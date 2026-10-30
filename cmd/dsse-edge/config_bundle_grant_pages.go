package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
)

const (
	grantPageProtocol = "grant-pages-v2"
	// A bound on a single management response protects the HTTP decoder. It is
	// not a limit on the number of grants a deployment may hold.
	grantPageRowsBytes = 240 << 10
	grantPageBodyBytes = 512 << 10
)

type grantBundleReference struct {
	Protocol   string `json:"protocol"`
	Epoch      string `json:"epoch"`
	Generation uint64 `json:"generation"`
}

type grantBundlePage struct {
	Protocol   string       `json:"protocol"`
	Epoch      string       `json:"epoch"`
	Generation uint64       `json:"generation"`
	Offset     int          `json:"offset"`
	NextOffset int          `json:"next_offset"`
	Total      int          `json:"total"`
	Grants     *grantBundle `json:"grants"`
}

// A single HTTP response owns one immutable snapshot. Signed, bounded NDJSON
// pages avoid both a whole-response size limit and retained per-generation
// caches. Grants minted during the response cannot invalidate its later pages.
func makeGrantBundlePage(rows []grantstore.Grant, ref grantBundleReference, offset int) (grantBundlePage, error) {
	if offset < 0 || offset > len(rows) {
		return grantBundlePage{}, fmt.Errorf("invalid grant page offset")
	}
	page := grantBundlePage{Protocol: grantPageProtocol, Epoch: ref.Epoch, Generation: ref.Generation,
		Offset: offset, NextOffset: offset, Total: len(rows), Grants: &grantBundle{Complete: true}}
	used := 0
	for _, row := range rows[offset:] {
		encoded, err := json.Marshal(row)
		if err != nil || len(encoded)+1 > grantPageRowsBytes {
			return grantBundlePage{}, fmt.Errorf("grant row cannot be encoded within a page")
		}
		if used+len(encoded)+1 > grantPageRowsBytes {
			break
		}
		if row.RequiresModernReader() {
			page.Grants.ProtectedGrants = append(page.Grants.ProtectedGrants, row)
		} else {
			page.Grants.Grants = append(page.Grants.Grants, row)
		}
		used += len(encoded) + 1
		page.NextOffset++
	}
	return page, nil
}

func registerGrantBundlePages(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	store func() *grantstore.Store, signer *agentpolicy.Signer, epoch, operatorTenant string, controlPlane bool) {
	mux.HandleFunc("GET /admin/grant-bundle-page", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if !controlPlane {
			http.NotFound(w, r)
			return
		}
		if !authorizeFleetConfigurationRead(w, r, operatorTenant) || configBundleRefusedOnAStandby(w) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		authority := store()
		if signer == nil || authority == nil || r.URL.Query().Get("protocol") != grantPageProtocol ||
			r.URL.Query().Get("epoch") != epoch {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("signed grant authority unavailable"))
			return
		}
		minimum, genErr := strconv.ParseUint(r.URL.Query().Get("generation"), 10, 64)
		offset, offsetErr := strconv.Atoi(r.URL.Query().Get("offset"))
		if genErr != nil || offsetErr != nil || offset != 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid grant snapshot request"))
			return
		}
		rows, generation, err := authority.SnapshotAllChecked()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("grant snapshot cannot be read"))
			return
		}
		if generation < minimum {
			writeError(w, http.StatusConflict, fmt.Errorf("grant authority predates the configuration reference"))
			return
		}
		ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: epoch, Generation: generation}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for {
			if r.Context().Err() != nil {
				return
			}
			page, err := makeGrantBundlePage(rows, ref, offset)
			if err != nil {
				if offset == 0 {
					writeError(w, http.StatusServiceUnavailable, err)
				}
				return // A truncated stream is never a complete snapshot.
			}
			envelope, err := signer.Sign(page, time.Now())
			if err != nil {
				if offset == 0 {
					writeError(w, http.StatusServiceUnavailable, fmt.Errorf("grant page signing unavailable"))
				}
				return
			}
			body, err := json.Marshal(envelope)
			if err != nil || len(body)+1 > grantPageBodyBytes {
				if offset == 0 {
					writeError(w, http.StatusServiceUnavailable, fmt.Errorf("grant page exceeds response bound"))
				}
				return
			}
			if _, err := w.Write(append(body, '\n')); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if page.NextOffset == page.Total {
				return
			}
			offset = page.NextOffset
		}
	}))
}

// fetchGrantPages verifies an entire immutable stream before returning anything
// that can be applied. Its first signed generation may be newer than the bundle
// reference; every later page must carry exactly that same generation.
func (s configBundleSource) fetchGrantPages(ctx context.Context, ref grantBundleReference) (*grantBundle, error) {
	if ref.Protocol != grantPageProtocol || strings.TrimSpace(ref.Epoch) == "" || len(s.acceptedVerifyKeys()) == 0 {
		return nil, fmt.Errorf("invalid or unverified grant page reference")
	}
	base := s.baseURL()
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("no in-boundary control plane for grant pages")
	}
	query := url.Values{"protocol": {grantPageProtocol}, "epoch": {ref.Epoch},
		"generation": {strconv.FormatUint(ref.Generation, 10)}, "offset": {"0"}}
	// The ordinary client timeout bounds one management response. Here one
	// response can contain arbitrarily many bounded pages, so retain that wait
	// budget per verified page instead of turning it into a fleet-size limit.
	// A stalled peer and parent cancellation still terminate the request. Copy
	// only this request's client; TLS, redirect policy and other calls are intact.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := *s.client
	pageWait := client.Timeout
	client.Timeout = 0
	var progress *time.Timer
	if pageWait > 0 {
		progress = time.AfterFunc(pageWait, cancel)
		defer progress.Stop()
	}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, strings.TrimRight(base, "/")+"/admin/grant-bundle-page?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, grantPageBodyBytes+1))
		if resp.StatusCode == http.StatusConflict || strings.Contains(strings.ToLower(string(body)), "does not hold leadership") {
			s.client.CloseIdleConnections()
		}
		return nil, fmt.Errorf("grant page authority returned status %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), grantPageBodyBytes)
	all := &grantBundle{Complete: true}
	offset, total := 0, -1
	for scanner.Scan() {
		if total >= 0 && offset == total {
			return nil, fmt.Errorf("grant snapshot has trailing pages")
		}
		var envelope agentpolicy.Envelope
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			return nil, fmt.Errorf("decode signed grant page: %w", err)
		}
		signed, err := agentpolicy.VerifyAny(envelope, s.acceptedVerifyKeys())
		if err != nil {
			return nil, fmt.Errorf("grant page signature verification failed: %w", err)
		}
		var page grantBundlePage
		if err := json.Unmarshal(signed, &page); err != nil {
			return nil, fmt.Errorf("decode grant page: %w", err)
		}
		if page.Protocol != ref.Protocol || page.Epoch != ref.Epoch || page.Generation < ref.Generation ||
			(total >= 0 && page.Generation != all.generation) ||
			page.Offset != offset || page.Total < 0 || (total >= 0 && page.Total != total) ||
			page.NextOffset < offset || page.NextOffset > page.Total || page.Grants == nil || !page.Grants.Complete ||
			len(page.Grants.Grants)+len(page.Grants.ProtectedGrants) != page.NextOffset-offset ||
			(page.NextOffset == offset && offset != page.Total) {
			return nil, fmt.Errorf("grant page sequence is incomplete or inconsistent")
		}
		total, all.generation = page.Total, page.Generation
		all.Grants = append(all.Grants, page.Grants.Grants...)
		all.ProtectedGrants = append(all.ProtectedGrants, page.Grants.ProtectedGrants...)
		offset = page.NextOffset
		if progress != nil {
			progress.Reset(pageWait)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("grant page exceeds response bound or cannot be read: %w", err)
	}
	if total < 0 || offset != total {
		return nil, fmt.Errorf("grant snapshot ended before completion")
	}
	return all, nil
}
