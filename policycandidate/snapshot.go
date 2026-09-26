package policycandidate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"reflect"
	"strings"
	"time"
)

// Keep errors independent of saved names, hosts and observation evidence: startup
// logs can be less restricted than the candidate snapshot itself.
var errInvalidSnapshot = errors.New("invalid policy candidate snapshot")

func decodeCandidateSnapshot(data []byte) (map[string]map[string]Candidate, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := candidateJSONValue(decoder); err != nil {
		return nil, errInvalidSnapshot
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errInvalidSnapshot
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, errInvalidSnapshot
	}
	fields := map[string]bool{}
	typ := reflect.TypeOf(Candidate{})
	for i := 0; i < typ.NumField(); i++ {
		fields[strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	snapshot := make(map[string]map[string]Candidate, len(raw))
	for tenant, rows := range raw {
		if tenant == "" || strings.TrimSpace(tenant) != tenant || rows == nil {
			return nil, errInvalidSnapshot
		}
		snapshot[tenant] = make(map[string]Candidate, len(rows))
		for id, body := range rows {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(body, &object); err != nil || object == nil {
				return nil, errInvalidSnapshot
			}
			// encoding/json matches struct field names without regard to case. Do not
			// accept alternate spellings which can overwrite an earlier identity field.
			for name := range object {
				if !fields[name] {
					return nil, errInvalidSnapshot
				}
			}
			var c Candidate
			if err := json.Unmarshal(body, &c); err != nil {
				return nil, errInvalidSnapshot
			}
			if id == "" || strings.TrimSpace(id) != id || c.CandidateID != id || c.TenantID != tenant || !validSource(c.Source) || !validType(c.CandidateType) || !validAction(c.ProposedAction) || !validStatus(c.Status) {
				return nil, errInvalidSnapshot
			}
			// Reuse admission checks without adopting normalization or regenerating a
			// timestamp. Historical decisions and evidence must remain byte-equivalent.
			if _, err := normalizeWithEvidenceValidation(c, tenant, time.Unix(0, 0), false); err != nil {
				return nil, errInvalidSnapshot
			}
			// Previous API writers accepted free-form review reasons and timestamps.
			// Keep that history; only new writes must meet the evidence contract.
			if err := validateCandidateEvidence(c); err != nil {
				log.Printf("policy candidate: retained legacy evidence for tenant %q candidate %q", tenant, id)
			}
			snapshot[tenant][id] = c
		}
	}
	return snapshot, nil
}

// Reject duplicate keys before decoding into maps or structs can discard them.
// Names in tenant and candidate maps remain case-sensitive.
func candidateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errInvalidSnapshot
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return errInvalidSnapshot
			}
			seen[name] = true
		}
		if err := candidateJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func validateCandidateEvidence(candidate Candidate) error {
	if candidate.Port < 0 || candidate.Port > 65535 || candidate.FailureCount < 0 {
		return errors.New("candidate observation count or port is invalid")
	}
	if candidate.ReviewReasonCode != "" && !safeAdminCatalogRef(candidate.ReviewReasonCode) {
		return errors.New("review_reason_code is invalid")
	}
	for _, value := range []*string{candidate.LastObserved, candidate.ReviewedAt, candidate.UpdatedAt} {
		if value != nil {
			if _, err := time.Parse(time.RFC3339, *value); err != nil {
				return errors.New("candidate timestamp is invalid")
			}
		}
	}
	return nil
}
