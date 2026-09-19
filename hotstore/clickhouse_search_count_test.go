package hotstore

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClickHouseSearchRejectsInvalidCountBeforeReadingRows(t *testing.T) {
	for _, count := range []string{"", "oops-private-detail", "1.5", "-1", "999999999999999999999999999999", "1\n2", "0\n", " 2\n"} {
		t.Run(fmt.Sprintf("count_%q", count), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					fmt.Fprint(w, count)
					return
				}
				fmt.Fprint(w, "")
			}))
			defer server.Close()
			store := NewClickHouseStore(server.URL, "", "", "dsse", "events")
			result, err := store.Search(context.Background(), SearchQuery{TenantID: "acme", Stream: "audit", Limit: 10})
			valid := count == "0\n" || count == " 2\n"
			if !valid {
				if err == nil {
					t.Fatal("invalid count accepted")
				}
				if calls.Load() != 1 {
					t.Fatalf("read rows after invalid count: %d requests", calls.Load())
				}
				if strings.Contains(err.Error(), "private-detail") {
					t.Fatal("raw response leaked in error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				expected := 0
				if count == " 2\n" {
					expected = 2
				}
				if result.TotalMatches != expected || calls.Load() != 2 {
					t.Fatalf("result=%+v requests=%d", result, calls.Load())
				}
			}
		})
	}
}
