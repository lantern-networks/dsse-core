package runtimequota

import (
	"fmt"
	"math"
	"time"
)

// ValidateEnvironment checks every supported resource setting before a service
// accepts work. Lazy reads must not turn a configuration typo into a later crash.
func ValidateEnvironment() (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("invalid resource configuration: %v", e)
		}
	}()
	for _, name := range []string{"DSSE_CONNECTOR_MAX_TCP_CONNECTIONS", "DSSE_NE_MAX_SESSIONS", "DSSE_SWG_MAX_CONNECTIONS_PER_HOST", "CONSOLE_MAX_CONNECTIONS", "DSSE_EGRESS_MAX_CONNECTIONS_PER_ENGINE", "DSSE_EGRESS_ENGINE_WORKERS", "DSSE_HAPROXY_MAX_CONNECTIONS", "DSSE_REAUTHENTICATION_FENCE_COMPACTION_THRESHOLD"} {
		Count(name)
	}
	for _, name := range []string{"DSSE_TCP_STREAM_MAX_LIFETIME_SECONDS", "DSSE_TCP_STREAM_IDLE_TIMEOUT_SECONDS", "DSSE_NE_SESSION_IDLE_TIMEOUT_SECONDS", "DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS", "DSSE_HTTP_IDLE_TIMEOUT_SECONDS", "DSSE_HAPROXY_SESSION_IDLE_TIMEOUT_SECONDS"} {
		Seconds(name)
	}
	Bytes("DSSE_TCP_STREAM_MAX_BYTES")
	HTTP2Streams("DSSE_HTTP2_MAX_CONCURRENT_STREAMS")
	Milliseconds("DSSE_NE_ABANDONED_HALF_CLOSE_LINGER_MILLISECONDS")
	Rate("DSSE_ENROL_REQUESTS_PER_SECOND")
	if burst := Rate("DSSE_ENROL_BURST"); burst > 0 && burst < 1 {
		return fmt.Errorf("DSSE_ENROL_BURST must hold at least one request or be 0")
	}
	return nil
}

func Milliseconds(name string) time.Duration {
	n := Count(name)
	if int64(n) > math.MaxInt64/int64(time.Millisecond) {
		panic(name + " exceeds the representable duration")
	}
	return time.Duration(n) * time.Millisecond
}
