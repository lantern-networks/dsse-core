package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type credentialAuditPersister struct {
	base blobstore.FilePersister
	fail atomic.Bool
}

func (p *credentialAuditPersister) Load() ([]byte, error) { return p.base.Load() }
func (p *credentialAuditPersister) Save(b []byte) error {
	if p.fail.Load() {
		return errors.New("private-runtime-location failure")
	}
	return p.base.Save(b)
}

func assertStandbyAudit(t *testing.T, a model.AuditLog, permission string) {
	t.Helper()
	if a.EventType != "admin_write_refused_on_standby" || a.TenantID != testEvaluator().PolicyBundle.TenantID ||
		a.ActorUserID != nil || a.ActorNHIID != nil || a.TargetID != nil || a.SourceIP != nil || a.SessionID != nil ||
		stringPtrValue(a.TargetType) != "admin_endpoint" || stringPtrValue(a.Action) != "admin_route" ||
		stringPtrValue(a.Result) != "refused" || stringPtrValue(a.Reason) != "not_leader" || a.ID == "" || a.Timestamp == "" {
		t.Fatalf("untruthful routing audit: %+v", a)
	}
	want := map[string]any{"audit_scope": "node", "authentication": "not_evaluated", "request_tenant": "not_evaluated", "required_permission": permission, "http_status": float64(409)}
	metadata := make(map[string]any)
	for k, v := range a.Metadata {
		metadata[k] = v
	}
	if metadata["aggregation"] != "permission_window" || metadata["interval_seconds"] != float64(60) {
		t.Fatalf("missing aggregation contract: %#v", metadata)
	}
	count, ok := metadata["request_count"].(float64)
	if !ok || count < 1 {
		t.Fatal("invalid count", metadata)
	}
	first, err := time.Parse(time.RFC3339Nano, metadata["first_seen"].(string))
	if err != nil {
		t.Fatal(err)
	}
	last, err := time.Parse(time.RFC3339Nano, metadata["last_seen"].(string))
	if err != nil || last.Before(first) {
		t.Fatal("invalid observation interval", metadata)
	}
	for _, k := range []string{"aggregation", "interval_seconds", "request_count", "first_seen", "last_seen"} {
		delete(metadata, k)
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("unexpected metadata: %#v", a.Metadata)
	}
}
