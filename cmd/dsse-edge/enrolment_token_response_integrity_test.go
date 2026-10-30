package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type incompleteTokenResponse struct{ io.Reader }

func (r incompleteTokenResponse) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func TestRemoteEnrollmentRequiresCompleteBoundTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		incomplete bool
	}{
		{"empty", `{}`, false},
		{"null", `null`, false},
		{"no_token", `{"token":null}`, false},
		{"no_id", `{"token":{"tenant_id":"tenant-a"}}`, false},
		{"no_tenant", `{"token":{"id":"token-a"}}`, false},
		{"wrong_id", `{"token":{"id":"token-b","tenant_id":"tenant-a"}}`, false},
		{"wrong_tenant", `{"token":{"id":"token-a","tenant_id":"tenant-b"}}`, false},
		{"interrupted", `{"token":{"id":"token-a","tenant_id":"tenant-a"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader = strings.NewReader(tc.body)
			if tc.incomplete {
				body = incompleteTokenResponse{body}
			}
			a := newRemoteEnrolmentTokenAuthority("https://authority.invalid", "test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(body), Header: make(http.Header)}, nil
			})})
			_, err := a.call(context.Background(), "/admin/fleet/enrolment-token/spend", enrolmentTokenRemoteRequest{ID: "token-a", TenantID: "tenant-a"})
			if err == nil {
				t.Fatal("invalid authority response accepted as eligibility/spend success")
			}
		})
	}
}
