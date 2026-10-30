// Package runtimequota reads explicit operator resource budgets. An absent or
// zero value never invents a performance quota. Protocol and parsing bounds are
// separate from these settings.
package runtimequota

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

func Count(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		panic(fmt.Sprintf("%s must be a non-negative integer (0 disables the quota)", name))
	}
	return n
}

// CountDefault preserves a security admission default unless the operator
// explicitly configures this setting. It must not be used to invent data quotas.
func CountDefault(name string, fallback int) int {
	if fallback < 0 {
		panic("negative resource protection default")
	}
	if strings.TrimSpace(os.Getenv(name)) == "" {
		return fallback
	}
	return Count(name)
}

func SecondsDefault(name string, fallback time.Duration) time.Duration {
	if fallback < 0 {
		panic("negative resource protection timeout")
	}
	if strings.TrimSpace(os.Getenv(name)) == "" {
		return fallback
	}
	return Seconds(name)
}

func HTTP2StreamsDefault(name string, fallback uint32) uint32 {
	if strings.TrimSpace(os.Getenv(name)) == "" {
		return fallback
	}
	return HTTP2Streams(name)
}

func Bytes(name string) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		panic(fmt.Sprintf("%s must be a non-negative byte count (0 disables the quota)", name))
	}
	return n
}

func Seconds(name string) time.Duration {
	n := Count(name)
	if int64(n) > math.MaxInt64/int64(time.Second) {
		panic(name + " exceeds the representable duration")
	}
	return time.Duration(n) * time.Second
}

// HTTP/2 represents its advertised stream count as uint32. Zero is the library's
// small default, so an unconfigured quota must explicitly advertise the protocol
// maximum rather than silently selecting that default.
func HTTP2Streams(name string) uint32 {
	n := Count(name)
	if n == 0 {
		return math.MaxUint32
	}
	if uint64(n) > math.MaxUint32 {
		panic(name + " exceeds HTTP/2's uint32 stream-count representation")
	}
	return uint32(n)
}

func Rate(name string) float64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		panic(name + " must be a finite non-negative rate (0 disables the quota)")
	}
	return n
}
