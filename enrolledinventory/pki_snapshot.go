package enrolledinventory

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ListForPKI reads the shared durable population, returning errors instead of an
// empty population. It does not alter the ledger's writable in-memory snapshot.
func (l *Ledger) ListForPKI() ([]Entry, error) {
	if l == nil {
		return nil, fmt.Errorf("no enrolled inventory")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	shared, ok := l.persister.(interface{ Shared() bool })
	if !ok || !shared.Shared() {
		return nil, fmt.Errorf("enrolled inventory is not a shared store")
	}
	raw, err := l.persister.Load()
	if err != nil {
		return nil, err
	}
	return DecodePKIPopulation(raw)
}

// DecodePKIPopulation validates a durable population read inside a PKI transaction.
func DecodePKIPopulation(raw []byte) ([]Entry, error) {
	var state stateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("read PKI population: %w", err)
	}
	if state.Entries == nil {
		return nil, fmt.Errorf("shared inventory has no complete entry set")
	}
	out := make([]Entry, 0, len(state.Entries))
	for _, entry := range state.Entries {
		if !entry.isTombstone() {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out, nil
}
