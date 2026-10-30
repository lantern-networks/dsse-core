package humanapproval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestApprovalSnapshotRejectsDuplicateAuthorizationKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approval.json")
	raw := `{"Acme\u0000one":{"id":"one","tenant_id":"Acme","approval_result":"revoked"},"Acme\u0000one":{"id":"one","tenant_id":"Acme","approval_result":"approved"}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(0)
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err == nil {
		t.Fatal("duplicate approval key accepted; last-wins would revive a revoked approval")
	}
}

func TestApprovalSnapshotRejectsCaseAliasForAuthorizationField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approval.json")
	raw := `{"Acme\u0000one":{"id":"one","tenant_id":"Acme","approval_result":"revoked","Approval_Result":"approved"}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(0)
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err == nil {
		t.Fatal("case alias revived a revoked approval")
	}
}
