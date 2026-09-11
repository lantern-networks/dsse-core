package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lantern-networks/dsse-core/model"
)

func Load(path string) (model.Policy, error) {
	var p model.Policy

	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read policy: %w", err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse policy: %w", err)
	}
	if p.ID == "" {
		return p, fmt.Errorf("policy id is required")
	}
	if p.TenantID == "" {
		return p, fmt.Errorf("policy tenant_id is required")
	}
	if p.Status != "active" {
		return p, fmt.Errorf("policy %s is not active: %s", p.ID, p.Status)
	}
	if p.Action.Decision == "" {
		return p, fmt.Errorf("policy %s action.decision is required", p.ID)
	}

	return p, nil
}

func LoadMany(paths []string) ([]model.Policy, error) {
	policies := make([]model.Policy, 0, len(paths))
	for _, path := range paths {
		p, err := Load(path)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("policy path is required")
	}
	return policies, nil
}
