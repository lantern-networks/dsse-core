package agentupdate

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func BenchmarkOpenOneEnvelope(b *testing.B) {
	signer, err := agentpolicy.LoadOrGenerateSigner(b.TempDir()+"/k.hex", true)
	if err != nil {
		b.Fatal("no signer:", err)
	}
	m := Manifest{Schema: "1", Version: "0.2.1+abc", Platform: "windows", Arch: "amd64", Channel: "stable",
		Delivery: "dsse", ArtifactKind: "msi", ArtifactURL: "https://example/x", ArtifactSHA256: "fbcfe6e0027d67bfc4b57ba78e3b62fc1a115f23a7fe7afd2d9edb5d6bc3c669", ArtifactSize: 1,
		NotAfter:   time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		ReleasedAt: time.Now().UTC().Format(time.RFC3339)}
	env, err := Sign(signer, m, time.Now())
	if err != nil {
		b.Fatal("sign:", err)
	}
	keys := []string{signer.PublicKeyHex()}
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Open(env, keys, now); err != nil {
			b.Fatal(err)
		}
	}
}
