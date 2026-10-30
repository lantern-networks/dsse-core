package main

import (
	"errors"
	"net/http"
	"testing"
)

func TestVerificationRequiresAnExplicitSpentTokenRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		err  error
		want bool
	}{
		{"spent token refused", http.StatusForbidden, nil, true},
		{"token reused", http.StatusOK, nil, false},
		{"transport failed", 0, errors.New("connection reset"), false},
		{"server failed", http.StatusInternalServerError, nil, false},
		{"not found", http.StatusNotFound, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenReuseWasRefused(tc.code, tc.err); got != tc.want {
				t.Fatalf("code=%d err=%v: verified=%v, want %v", tc.code, tc.err, got, tc.want)
			}
		})
	}
}
