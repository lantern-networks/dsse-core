package hotstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManualDeleteDistinguishesDefiniteRejectionFromLostResponse(t *testing.T) {
	for _, mode := range []string{"rejected", "lost-response"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				query := string(body)
				if strings.HasPrefix(query, "ALTER TABLE") {
					if r.URL.Query().Get("query_id") != "hot_delete_test1" || r.URL.Query().Get("replace_running_query") != "0" {
						t.Error("ALTER must retain the job query ID without replacing a running query")
					}
					if mode == "rejected" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte("access denied"))
						return
					}
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Error("HTTP hijack unavailable")
						return
					}
					conn, _, err := hijacker.Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				switch {
				case strings.Contains(query, "system.columns"):
					_, _ = w.Write([]byte("1"))
				case strings.Contains(query, "system.parts"):
					_, _ = w.Write([]byte("0"))
				}
			}))
			defer server.Close()
			store := NewClickHouseStore(server.URL, "", "", "dsse", "events")
			err := store.ManualDeleteStart(context.Background(), "hot_delete_test1", "tenant", "access", time.Now().Add(-time.Hour), time.Now())
			var notSubmitted *ManualDeleteNotSubmitted
			if errors.As(err, &notSubmitted) != (mode == "rejected") {
				t.Fatalf("not-submitted classification for %s: %v", mode, err)
			}
		})
	}
}

func TestManualDeleteQueryRunningRequiresExactIdentityAndValidObservation(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		status         int
		wantRunning    bool
		wantError      bool
	}{
		{name: "absent", response: "0\n"},
		{name: "active", response: "1\n", wantRunning: true},
		{name: "invalid", response: "-1\n", wantError: true},
		{name: "empty", wantError: true},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(body), "FROM system.processes WHERE query_id={job:String}") || r.URL.Query().Get("param_job") != "hot_delete_test1" {
					t.Error("running query lookup did not bind the exact job ID")
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()
			store := NewClickHouseStore(server.URL, "", "", "dsse", "events")
			running, err := store.ManualDeleteQueryRunning(context.Background(), "hot_delete_test1")
			if running != tc.wantRunning || (err != nil) != tc.wantError {
				t.Fatalf("running=%v err=%v", running, err)
			}
		})
	}
	store := NewClickHouseStore("http://unused.invalid", "", "", "dsse", "events")
	if _, err := store.ManualDeleteQueryRunning(context.Background(), "invalid-job"); err == nil {
		t.Fatal("invalid job ID accepted")
	}
}
