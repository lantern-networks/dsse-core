package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTheShippedHeartbeatSaysWhatItRunsAndForHowLong — C3-R4-1: the real sendHeartbeat, its JSON as the Edge
// receives it. Earlier tests gave the Edge a heartbeat they wrote themselves, with both fields filled in.
func TestTheShippedHeartbeatSaysWhatItRunsAndForHowLong(t *testing.T) {
	savedVersion, savedCommit, savedStart := buildVersion, buildCommit, processStarted
	defer func() { buildVersion, buildCommit, processStarted = savedVersion, savedCommit, savedStart }()
	buildVersion, buildCommit = "0.4.1", "source-7bcf53da"
	processStarted = time.Now().Add(-42 * time.Minute)

	var got map[string]any
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer edge.Close()
	if err := sendHeartbeat(edge.Client(), edge.URL, "conn-h1", "secret", "org-1", "", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if got["version"] != "0.4.1+source-7bcf53da" {
		t.Fatalf("heartbeat version = %v; the Console would read unknown", got["version"])
	}
	up, _ := got["uptime_seconds"].(float64)
	if up < 42*60 || up > 43*60 {
		t.Fatalf("heartbeat uptime_seconds = %v, want about 2520", got["uptime_seconds"])
	}

	// Unstamped: nothing invented.
	buildVersion, buildCommit = "", ""
	got = nil
	if err := sendHeartbeat(edge.Client(), edge.URL, "conn-h1", "secret", "org-1", "", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, present := got["version"]; present {
		t.Fatalf("an unstamped build reported version %v", got["version"])
	}
}

// TestTheImageStampsTheConnector: a stamp the linker drops for want of a variable is the defect this file fixes;
// the build must keep passing it to this binary.
func TestTheImageStampsTheConnector(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "-X main.buildVersion=") || !strings.Contains(src, `go build -trimpath -ldflags "$LD" -o /out/dsse-connector ./cmd/dsse-connector`) {
		t.Fatal("the image no longer stamps dsse-connector with main.buildVersion")
	}
}
