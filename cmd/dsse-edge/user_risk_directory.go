package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

func directoryRiskMark(person model.HumanIdentity) revocation.UserRisk {
	subjects := []string{person.ID, person.Subject}
	if person.Email != nil {
		subjects = append(subjects, *person.Email)
	}
	return revocation.UserRisk{TenantID: person.TenantID, ID: person.ID, Subjects: subjects}
}

// Resolve within the selected tenant even for an operator. An unscoped user ID
// cannot identify which organization should receive a risk mark.
func resolveRiskPerson(ctx context.Context, store humanidentity.HumanIdentityDirectoryRuntimeStore, tenant, id string) (model.HumanIdentity, int, error) {
	if store == nil {
		return model.HumanIdentity{}, 503, fmt.Errorf("human identity directory is unavailable")
	}
	people, err := store.List(ctx, tenant)
	if err != nil {
		return model.HumanIdentity{}, 503, fmt.Errorf("human identity directory is unavailable")
	}
	// A canonical ID wins over another person's alias. IDs and authenticated subjects
	// are opaque and case-sensitive; case-folded authorization may name another user.
	for _, person := range people {
		if person.ID == id {
			return person, 0, nil
		}
	}
	var matches []model.HumanIdentity
	for _, person := range people {
		if person.Subject == id || (person.Email != nil && *person.Email == id) {
			matches = append(matches, person)
		}
	}
	if len(matches) != 1 {
		return model.HumanIdentity{}, 404, fmt.Errorf("no uniquely identified person in this organization")
	}
	return matches[0], 0, nil
}

// prepareUserRiskState runs before serving. No persisted v1 mark is discarded or
// assigned by guessing. Unknown or ambiguous IDs require operator review of the
// old snapshot; the process refuses startup until that attribution is resolved.
func prepareUserRiskState(ctx context.Context, overlay *revocation.HighRiskOverlay, ledger *enrolledinventory.Ledger, directory humanidentity.HumanIdentityDirectoryRuntimeStore) error {
	if overlay == nil {
		return nil
	}
	if !overlay.NeedsMigration() {
		return overlay.Health()
	}
	all, ok := directory.(interface {
		RiskIdentitySnapshot(context.Context) ([]model.HumanIdentity, error)
	})
	if !ok {
		return fmt.Errorf("legacy risk migration requires a complete identity directory")
	}
	people, err := all.RiskIdentitySnapshot(ctx)
	if err != nil {
		return fmt.Errorf("legacy risk migration cannot read directory: %w", err)
	}
	return overlay.MigrateLegacy(func(id string) (*revocation.UserRisk, error) {
		var matches []model.HumanIdentity
		for _, person := range people {
			if person.ID == id || person.Subject == id || (person.Email != nil && *person.Email == id) {
				matches = append(matches, person)
			}
		}
		device := false
		if ledger != nil {
			_, device = ledger.EntryFor(id)
		}
		if device && len(matches) == 0 {
			return nil, nil
		}
		if !device && len(matches) == 1 {
			mark := directoryRiskMark(matches[0])
			return &mark, nil
		}
		return nil, fmt.Errorf("legacy risk entry %q is ambiguous or unattributable; review the saved mark before upgrading", id)
	})
}

func writeUserRisk(w http.ResponseWriter, r *http.Request, config serverConfig, sig model.RiskSignal) (adminRiskSignalResponse, string, bool) {
	tenant := adminTenantIDFromRequest(r)
	id := strings.TrimSpace(sig.EntityID)
	person, status, err := resolveRiskPerson(r.Context(), config.HumanIdentities, tenant, id)
	if err != nil {
		writeError(w, status, err)
		return adminRiskSignalResponse{}, "", false
	}
	sig.EntityID = person.ID
	sig.EntityType = "user"
	resp, err := applyAdminRiskSignal(nil, tenant, sig, time.Now())
	if err != nil {
		writeError(w, 400, err)
		return resp, "", false
	}
	resp.TenantID = person.TenantID
	mark := directoryRiskMark(person)
	mark.Severity = resp.Severity
	warning, err := config.HighRiskOverlay.SetUserRiskContext(r.Context(), mark)
	if err != nil {
		writeError(w, 503, fmt.Errorf("user risk save was not confirmed; the live risk state was not changed"))
		return resp, "", false
	}
	if warning {
		resp.NotStoredDurably = "The user risk is applied, but durable saving is not confirmed. Reapply after the storage is healthy."
	}
	return resp, person.TenantID, true
}

// Follow the current directory's aliases by canonical ID. Saved aliases remain in
// the overlay for sessions issued before a rename; this read does not clear them
// or introduce a second durable write into directory synchronization.
func enrichDecisionRequestWithDirectoryRisk(ctx context.Context, req model.DecisionRequest, directory humanidentity.HumanIdentityDirectoryRuntimeStore, overlay *revocation.HighRiskOverlay) (model.DecisionRequest, error) {
	if overlay == nil || req.UserID == "" || req.TenantID == "" {
		return req, nil
	}
	marks := overlay.UserSeverities(req.TenantID)
	if len(marks) == 0 {
		return req, nil
	}
	if directory == nil {
		return req, fmt.Errorf("user risk directory is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var ids []string
	var err error
	if resolver, ok := directory.(humanidentity.RiskIdentityResolver); ok {
		ids, err = resolver.RiskIdentityIDs(ctx, req.TenantID, req.UserID)
	} else {
		var people []model.HumanIdentity
		people, err = directory.List(ctx, req.TenantID)
		for _, person := range people {
			if person.TenantID == req.TenantID && (person.ID == req.UserID || person.Subject == req.UserID || (person.Email != nil && *person.Email == req.UserID)) {
				ids = append(ids, person.ID)
			}
		}
	}
	if err != nil {
		return req, fmt.Errorf("user risk directory could not be read")
	}
	for _, id := range ids {
		severity := marks[id]
		req.RiskStateSeverity = maxRiskSeverity(req.RiskStateSeverity, severity)
		if severity == "high" || severity == "critical" {
			req.AdminHighRisk = true
		}
	}
	return req, nil
}
