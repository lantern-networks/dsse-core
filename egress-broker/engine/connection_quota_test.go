package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Each subprocess initializes the actual curl_multi engine with its own service
// environment. The HTTP/1 fixture holds every request before sending a response,
// so earlier requests cannot conceal the old 256-active-connection ceiling.
func TestActiveConnectionQuotaOnlyWhenOperatorChoosesOne(t *testing.T) {
	for _, quota := range []int{0, 3} {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActiveConnectionQuotaWorker$")
		cmd.Env = append(os.Environ(), "DSSE_QUOTA_TEST_WORKER=1", "DSSE_EGRESS_ENGINE_WORKERS=1", "DSSE_EGRESS_MAX_CONNECTIONS_PER_ENGINE="+strconv.Itoa(quota))
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("operator quota %d: %v\n%s", quota, err, output)
		}
	}
}

func TestActiveConnectionQuotaWorker(t *testing.T) {
	if os.Getenv("DSSE_QUOTA_TEST_WORKER") != "1" {
		t.Skip("isolated engine initialization is required")
	}
	quota, _ := strconv.Atoi(os.Getenv("DSSE_EGRESS_MAX_CONNECTIONS_PER_ENGINE"))
	n, first := 300, 300
	if quota > 0 {
		n, first = 7, quota
	}
	entered := make(chan struct{}, n)
	release := make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte("ok"))
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer resume()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	results := make(chan *httptest.ResponseRecorder, n)
	for i := 0; i < n; i++ {
		go func() {
			w := httptest.NewRecorder()
			Reoriginate(w, ctx, Request{Method: http.MethodGet, URL: srv.URL})
			results <- w
		}()
	}
	for i := 0; i < first; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatalf("only %d/%d concurrent requests reached the held origin", i, first)
		}
	}
	if quota > 0 {
		select {
		case <-entered:
			t.Fatal("explicit engine connection quota was exceeded")
		case <-time.After(200 * time.Millisecond):
		}
	}
	resume()
	for i := 0; i < n; i++ {
		select {
		case w := <-results:
			if w.Code != http.StatusOK || w.Body.String() != "ok" {
				t.Fatalf("held transfer failed with HTTP %d", w.Code)
			}
		case <-ctx.Done():
			t.Fatal("completed connections did not release queued transfers")
		}
	}
}
