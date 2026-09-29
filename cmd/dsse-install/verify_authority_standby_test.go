package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorityRosterComparisonHandlesStandbyReadRefusal(t *testing.T) {
	const refusal = `{"error":"this control plane does not hold leadership; admission state is not authoritative here. Retry through the active management server"}`
	cases := []struct {
		name        string
		codes       []int
		bodies      []string
		roles       []int
		skipped, ok bool
	}{
		{"standby cannot be compared", []int{200, 409}, []string{`{"devices":[]}`, refusal}, []int{200, 503}, true, false},
		{"other conflict remains failure", []int{200, 409}, []string{`{"devices":[]}`, `{"error":"unrelated conflict"}`}, []int{200, 503}, false, false},
		{"leader conflict remains failure", []int{200, 409}, []string{`{"devices":[]}`, refusal}, []int{200, 200}, false, false},
		{"unreachable role remains failure", []int{200, 409}, []string{`{"devices":[]}`, refusal}, []int{200, 500}, false, false},
		{"auth failure cannot hide behind standby", []int{401, 409}, []string{`{}`, refusal}, []int{200, 503}, false, false},
		{"all standby is failure", []int{409, 409}, []string{refusal, refusal}, []int{503, 503}, false, false},
		{"disagreement cannot hide behind standby", []int{200, 200, 409}, []string{`{"devices":[]}`, `{"devices":[{"identity":"a"}]}`, refusal}, []int{200, 200, 503}, false, false},
		{"readable peers still compare", []int{200, 200}, []string{`{"devices":[{"identity":"a"}]}`, `{"devices":[{"identity":"a"}]}`}, []int{200, 200}, false, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			peers := []string{}
			for i := range tt.codes {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/leader" {
						w.WriteHeader(tt.roles[i])
						return
					}
					w.WriteHeader(tt.codes[i])
					_, _ = w.Write([]byte(tt.bodies[i]))
				}))
				defer srv.Close()
				peers = append(peers, srv.URL)
			}
			got := verifyAuthorityPeersAgree(http.DefaultClient, peers, "synthetic-token")
			if len(got) != 1 || got[0].skipped != tt.skipped || got[0].ok != tt.ok {
				t.Fatalf("unexpected result: %+v", got)
			}
		})
	}
}
