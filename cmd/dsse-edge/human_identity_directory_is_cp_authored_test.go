package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

// ★ MEASURED FIRST (2026-08-19): the control plane held 90 directory identities for the lab tenant and BOTH
// enforcing Edges held zero, because no bundle section ever carried them. Everything an Edge answers about
// people was therefore drawn from an empty list, and nothing said so — the seat meter quietly fell back to a
// proxy count and recorded a different number than the control plane did for the same tenant and month.
//
// This gate holds the three halves of the fix together, because any one of them alone leaves it broken:
// the bundle CARRIES the directory, the version CHANGES when the directory does, and a pulling Edge REFUSES
// to be written to directly.
func TestDirectoryReachesAPullingEdge(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	source := configBundleSource{tenantID: "tenant_northwind"}
	local := humanidentity.NewHumanIdentityDirectoryStore()

	payload := configBundlePayload{HumanIdentities: &humanIdentityBundle{
		Identities: []model.HumanIdentity{
			{TenantID: "tenant_northwind", ID: "hi_carried_1", Subject: "a@northwind.example", Status: "active", Source: "scim"},
			{TenantID: "tenant_northwind", ID: "hi_carried_2", Subject: "b@northwind.example", Status: "active", Source: "scim"},
		},
		SourcePolicies: []humanidentity.HumanIdentitySourcePolicy{
			{TenantID: "tenant_northwind", Source: "scim", ConnectorType: "scim", Enabled: true},
		},
	}}
	if _, err := source.apply(payload, configApplyTargets{humanIdentities: local}); err != nil {
		t.Fatalf("apply bundle: %v", err)
	}

	got, err := local.List(context.Background(), "tenant_northwind")
	if err != nil {
		t.Fatalf("list directory: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("the bundle carried 2 identities and the Edge holds %d — the directory did not reach the Edge", len(got))
	}
	policies, err := local.ListSourcePolicies(context.Background(), "tenant_northwind")
	if err != nil || len(policies) != 1 {
		t.Fatalf("source policies did not reach the Edge: %d, err=%v", len(policies), err)
	}
	_ = now
}

// The lockout-safe half, and it is the reason this section is additive: a control plane that is not the
// directory's authority sends an empty section, and an empty section must not erase an organization's people.
func TestAnEmptyDirectorySectionDoesNotEraseThePeople(t *testing.T) {
	source := configBundleSource{tenantID: "tenant_northwind"}
	local := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := local.Upsert(context.Background(), model.HumanIdentity{
		TenantID: "tenant_northwind", ID: "hi_local", Subject: "local@northwind.example", Status: "active", Source: "scim",
	}, "tenant_northwind", time.Now()); err != nil {
		t.Fatalf("seed local: %v", err)
	}

	if _, err := source.apply(configBundlePayload{HumanIdentities: &humanIdentityBundle{}}, configApplyTargets{humanIdentities: local}); err != nil {
		t.Fatalf("apply empty bundle: %v", err)
	}

	got, _ := local.List(context.Background(), "tenant_northwind")
	if len(got) != 1 {
		t.Fatalf("an empty directory section left %d local identity(ies), want 1 — one bad publish must not "+
			"empty an organization's people list", len(got))
	}
	// Counting is not enough: an identity that is still listed but marked gone is erased in every way that
	// matters to a reader, so the gate holds the record itself rather than the length of the list.
	if got[0].ID != "hi_local" || !strings.EqualFold(got[0].Status, "active") {
		t.Fatalf("an empty directory section changed the local identity: %+v", got[0])
	}
}

// The version has to move with the contents. Without this the bundle would carry a new person and claim the
// same generation, and no Edge would ever pull for them — the defect the tenant registry already had once.
func TestAddingSomebodyChangesTheDirectoryVersion(t *testing.T) {
	store := humanidentity.NewHumanIdentityDirectoryStore()
	carrier, ok := humanIdentityDirectoryCarrier(store)
	if !ok {
		t.Fatal("the in-memory directory store cannot carry the directory to the fleet")
	}
	before := carrier.ConfigGeneration()
	if _, err := store.Upsert(context.Background(), model.HumanIdentity{
		TenantID: "tenant_northwind", ID: "hi_version", Subject: "v@northwind.example", Status: "active", Source: "scim",
	}, "tenant_northwind", time.Now()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if after := carrier.ConfigGeneration(); after == before {
		t.Fatalf("adding somebody left the directory version at %d, so the bundle's contents would change and "+
			"its version would not, and no Edge would re-pull", after)
	}

	// The control: a READ must not move the version. A generation that ticks on reads makes every Edge re-pull
	// the whole fleet's configuration on a schedule set by whoever happens to be looking at a screen.
	quiet := carrier.ConfigGeneration()
	if _, err := store.List(context.Background(), "tenant_northwind"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := store.Stats(context.Background(), "tenant_northwind", time.Now()); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if moved := carrier.ConfigGeneration(); moved != quiet {
		t.Fatalf("reading the directory moved its version from %d to %d", quiet, moved)
	}
}

// Count the doors, don't trust the intent — but the doors do not all have the same answer, and that is the
// point of reading them one at a time.
//
// The three ADMIN doors are refused on an Edge that pulls its configuration: a person authoring the directory
// can be sent to the control plane, and the Console already routes them there.
//
// The CONNECTOR's door is not, and must not be. A connector lives inside the customer's network and reaches
// the Edge and nothing else, so refusing there removes the only channel a customer has for syncing their own
// directory. It is RELAYED instead: applied locally so it takes effect, and carried to the control plane so
// the authority — and through it the rest of the fleet — holds the same people.
func TestEveryDirectoryWriteDoorIsEitherRefusedOrRelayed(t *testing.T) {
	data, err := os.ReadFile("human_identity.go")
	if err != nil {
		t.Fatalf("read directory routes: %v", err)
	}
	source := stripGoComments(string(data))

	refused := []string{
		`mux.HandleFunc("POST /admin/human-identities"`,
		`mux.HandleFunc("POST /admin/human-identities/sources/policies"`,
		`mux.HandleFunc("POST /admin/human-identities/import"`,
	}
	const connectorDoor = `mux.HandleFunc("POST /identity-sources/import"`
	all := append(append([]string{}, refused...), connectorDoor)

	body := func(door string) string {
		start := strings.Index(source, door)
		if start < 0 {
			return ""
		}
		end := len(source)
		for _, next := range all {
			if next == door {
				continue
			}
			if at := strings.Index(source, next); at > start && at < end {
				end = at
			}
		}
		return source[start:end]
	}

	for _, door := range refused {
		handler := body(door)
		if handler == "" {
			t.Errorf("%s is gone — this gate no longer checks it", door)
			continue
		}
		if !strings.Contains(handler, "configWriteRejectedWhenSourced(") {
			t.Errorf("%s writes the people directory and does not refuse on an Edge that pulls its "+
				"configuration, so a write there is answered by a node that is not the authority", door)
		}
	}

	connector := body(connectorDoor)
	if connector == "" {
		t.Fatalf("%s is gone — the only channel a customer has for syncing their directory", connectorDoor)
	}
	if strings.Contains(connector, "configWriteRejectedWhenSourced(") {
		t.Fatalf("%s refuses on a config-pulling Edge. A connector lives inside the customer's network and "+
			"cannot be pointed at the control plane, so this removes the customer's only directory-sync channel",
			connectorDoor)
	}
	if !strings.Contains(connector, "directoryReporter.Report(") {
		t.Fatalf("%s accepts the import and does not carry it to the control plane, so the authority — and "+
			"every other Edge, and the Console, and the seat count — never learns about these people",
			connectorDoor)
	}
}

// stripGoComments removes // and /* */ comments so a gate that reads source cannot be satisfied by prose.
// Two gates written last night were passed by their own explanatory comments; this is the fix for that.
func stripGoComments(source string) string {
	var out strings.Builder
	for i := 0; i < len(source); {
		switch {
		case strings.HasPrefix(source[i:], "//"):
			nl := strings.IndexByte(source[i:], '\n')
			if nl < 0 {
				return out.String()
			}
			i += nl
		case strings.HasPrefix(source[i:], "/*"):
			end := strings.Index(source[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			i += end + 4
		default:
			out.WriteByte(source[i])
			i++
		}
	}
	return out.String()
}

// One Edge serves several organizations, so a bundle that carries only the tenant it pulled as leaves every
// other organization's people missing on the node that enforces for them — the defect the authored-rule
// section already carries a warning about. Operator decision 2026-08-19: carry them all.
//
// The control is in the same test and is the thing that would be catastrophic rather than merely incomplete:
// carrying several organizations must not MERGE them. Each record keeps its own organization, and a read for
// one never returns another's people.
func TestTheBundleCarriesEveryOrganizationsDirectoryWithoutMergingThem(t *testing.T) {
	source := configBundleSource{tenantID: "tenant_reference_lab"}
	local := humanidentity.NewHumanIdentityDirectoryStore()

	payload := configBundlePayload{HumanIdentities: &humanIdentityBundle{
		Identities: []model.HumanIdentity{
			{TenantID: "tenant_reference_lab", ID: "hi_lab", Subject: "lab@lab.example", Status: "active", Source: "scim"},
			{TenantID: "tenant_northwind", ID: "hi_nw", Subject: "nw@northwind.example", Status: "active", Source: "scim"},
			{TenantID: "tenant_acme", ID: "hi_acme", Subject: "acme@acme.example", Status: "active", Source: "scim"},
		},
		SourcePolicies: []humanidentity.HumanIdentitySourcePolicy{
			{TenantID: "tenant_northwind", Source: "scim", ConnectorType: "scim", Enabled: true},
		},
	}}
	if _, err := source.apply(payload, configApplyTargets{humanIdentities: local}); err != nil {
		t.Fatalf("apply bundle: %v", err)
	}

	for _, tenant := range []string{"tenant_reference_lab", "tenant_northwind", "tenant_acme"} {
		got, err := local.List(context.Background(), tenant)
		if err != nil {
			t.Fatalf("list %s: %v", tenant, err)
		}
		if len(got) != 1 {
			t.Fatalf("%s has %d identity(ies) on this Edge, want 1 — an Edge that enforces for an organization "+
				"holds none of its people", tenant, len(got))
		}
		if got[0].TenantID != tenant {
			t.Fatalf("%s's directory returned a record belonging to %s", tenant, got[0].TenantID)
		}
	}

	// The source policy landed under its own organization, not under the tenant this Edge pulled as.
	if policies, err := local.ListSourcePolicies(context.Background(), "tenant_northwind"); err != nil || len(policies) != 1 {
		t.Fatalf("northwind source policies = %d, err=%v — the policy was filed under the pulling tenant", len(policies), err)
	}
	if policies, _ := local.ListSourcePolicies(context.Background(), "tenant_reference_lab"); len(policies) != 0 {
		t.Fatalf("the pulling tenant received another organization's source policy: %+v", policies)
	}
}
