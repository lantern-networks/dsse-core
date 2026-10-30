package runtimequota

import (
	"math"
	"testing"
	"time"
)

func TestSecurityDefaultsRequireAnExplicitOverride(t *testing.T) {
	const name = "DSSE_TEST_SECURITY_SETTING"
	t.Setenv(name, "")
	if CountDefault(name, 4096) != 4096 || SecondsDefault(name, 120*time.Second) != 120*time.Second || HTTP2StreamsDefault(name, 250) != 250 || HTTP2StreamsDefault(name, 10000) != 10000 {
		t.Fatal("omitted security setting disabled an existing protection")
	}
	t.Setenv(name, "0")
	if CountDefault(name, 4096) != 0 || SecondsDefault(name, 120*time.Second) != 0 || HTTP2StreamsDefault(name, 250) != math.MaxUint32 {
		t.Fatal("explicit operator override was ignored")
	}
	t.Setenv(name, "17000")
	if CountDefault(name, 4096) != 17000 || SecondsDefault(name, time.Minute) != 17000*time.Second || HTTP2StreamsDefault(name, 250) != 17000 {
		t.Fatal("operator security setting was clamped")
	}
}

func TestExplicitQuotasHaveNoDefaultOrHiddenNumericCeiling(t *testing.T) {
	const name = "DSSE_TEST_RUNTIME_QUOTA"
	for _, raw := range []string{"", "0"} {
		t.Setenv(name, raw)
		if Count(name) != 0 || Bytes(name) != 0 || Seconds(name) != 0 || HTTP2Streams(name) != math.MaxUint32 {
			t.Fatal("unconfigured quota became a hidden limit")
		}
	}
	t.Setenv(name, "100000")
	if Count(name) != 100000 || Seconds(name) != 100000*time.Second || HTTP2Streams(name) != 100000 {
		t.Fatal("operator count was clamped")
	}
	t.Setenv(name, "8589934592")
	if Bytes(name) != 8<<30 {
		t.Fatal("operator byte quota was clamped to old 1 GiB bound")
	}
	for _, raw := range []string{"-1", "wrong", "9999999999999999999999"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(name, raw)
			defer func() {
				if recover() == nil {
					t.Fatal("bad configuration was silently ignored")
				}
			}()
			Count(name)
		})
	}
}

func TestRateAndRepresentationValidation(t *testing.T) {
	const name = "DSSE_TEST_RUNTIME_QUOTA"
	t.Setenv(name, "0.5")
	if Rate(name) != 0.5 {
		t.Fatal("fractional operator rate was rounded or clamped")
	}
	for _, parse := range []struct {
		value string
		read  func()
	}{
		{"NaN", func() { Rate(name) }},
		{"Inf", func() { Rate(name) }},
		{"4294967296", func() { HTTP2Streams(name) }},
		{"9223372037", func() { Seconds(name) }},
	} {
		t.Run(parse.value, func(t *testing.T) {
			t.Setenv(name, parse.value)
			defer func() {
				if recover() == nil {
					t.Fatal("invalid/unrepresentable operator value was accepted")
				}
			}()
			parse.read()
		})
	}
}
