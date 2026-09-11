package archive

import "testing"

func TestNewValidatesConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"missing endpoint", Config{Bucket: "b"}, true},
		{"missing bucket", Config{Endpoint: "minio:9000"}, true},
		{"endpoint is a URL (must be host:port, vendor-neutral)", Config{Endpoint: "https://minio:9000", Bucket: "b"}, true},
		{"valid host:port", Config{Endpoint: "minio:9000", Bucket: "dsse-cold-archive", AccessKey: "k", SecretKey: "s"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if a.Backend() == "" {
					t.Fatal("Backend() must describe the endpoint/bucket")
				}
			}
		})
	}
}
