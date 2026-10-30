package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// verifyOneRegionThreeNodesSync asks Patroni's live DCS configuration. The
// install-order command alone is not evidence that it took effect.
func verifyOneRegionThreeNodesSync(env map[string]string) verifyResult {
	address := strings.TrimSpace(env["DSSE_PG_A_API_PUBLISH"])
	if address == "" {
		return verifyResult{name: "strict synchronous database writes", note: "this Node has no Patroni API address"}
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://" + address + "/config")
	if err != nil {
		return verifyResult{name: "strict synchronous database writes", note: fmt.Sprintf("could not read Patroni's live configuration: %v", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return verifyResult{name: "strict synchronous database writes", note: fmt.Sprintf("Patroni returned HTTP %d for its configuration", resp.StatusCode)}
	}
	var config struct {
		Mode      bool `json:"synchronous_mode"`
		Strict    bool `json:"synchronous_mode_strict"`
		NodeCount int  `json:"synchronous_node_count"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&config); err != nil {
		return verifyResult{name: "strict synchronous database writes", note: fmt.Sprintf("could not read Patroni's live configuration: %v", err)}
	}
	ok := config.Mode && config.Strict && config.NodeCount == 1
	return verifyResult{ok: ok, name: "strict synchronous database writes",
		note: fmt.Sprintf("Patroni DCS reports synchronous_mode=%t, synchronous_mode_strict=%t, synchronous_node_count=%d; failover durability still needs a fault test", config.Mode, config.Strict, config.NodeCount)}
}
