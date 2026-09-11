package agentpolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ★ THE LAST RESORT WAS ALIVE FOR ONE ORGANIZATION AND DEAD FOR EVERY OTHER (2026-08-20, measured on the lab
// by the Edge side). This endpoint cannot authenticate the caller — that is what it is for — so with no name
// it answers with the bundle of the organization the NODE belongs to. Every agent asked without saying, so a
// device of any other organization was handed anchors that cannot verify the certificate it is served,
// refused them correctly, and never returned. A single-organization lab cannot see it.
//
// The name is a SELECTOR, not a credential: it proves nothing, exactly as the SNI proves nothing on the
// connection this stands in for.

func capturingBundleServer(t *testing.T, seen chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.URL.RawQuery:
		default:
		}
		w.WriteHeader(http.StatusNotFound) // the fetch fails after the URL is recorded; the URL is the subject
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTheFetchNamesTheOrganizationItWants(t *testing.T) {
	seen := make(chan string, 1)
	srv := capturingBundleServer(t, seen)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = FetchVerifiedTrustBundleForName(ctx, srv.Client(), srv.URL, "northwind.dsse.invalid",
		[]string{"00"}, 0)

	select {
	case q := <-seen:
		if q != "server_name=northwind.dsse.invalid" {
			t.Fatalf("query = %q, want the adopted name as server_name", q)
		}
	default:
		t.Fatalf("the server was never asked")
	}
}

// A device that has adopted no name asks exactly as it always did — that is every agent built before this,
// and the server must go on answering them.
func TestTheFetchSaysNothingWhenNoNameIsAdopted(t *testing.T) {
	seen := make(chan string, 1)
	srv := capturingBundleServer(t, seen)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = FetchVerifiedTrustBundleWithKeys(ctx, srv.Client(), srv.URL, []string{"00"}, 0)

	select {
	case q := <-seen:
		if q != "" {
			t.Fatalf("query = %q, want none", q)
		}
	default:
		t.Fatalf("the server was never asked")
	}
}

// A name with characters that would otherwise change the URL is escaped, not concatenated.
func TestTheNameIsEscaped(t *testing.T) {
	seen := make(chan string, 1)
	srv := capturingBundleServer(t, seen)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = FetchVerifiedTrustBundleForName(ctx, srv.Client(), srv.URL, "a b&tenant=other", []string{"00"}, 0)

	select {
	case q := <-seen:
		if q != "server_name=a+b%26tenant%3Dother" {
			t.Fatalf("query = %q, want the name escaped so it cannot add parameters", q)
		}
	default:
		t.Fatalf("the server was never asked")
	}
}
