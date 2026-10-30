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
		{"endpoint is a URL (must be a host, vendor-neutral)", Config{Endpoint: "https://minio:9000", Bucket: "b"}, true},
		{"plaintext refused", Config{Endpoint: "store.example:9000", Bucket: "dsse-cold-archive", AccessKey: "k", SecretKey: "s", AuthMode: "static"}, true},
		{"missing credentials refused", Config{Endpoint: "store.example:443", Bucket: "dsse-cold-archive", UseSSL: true, AuthMode: "static"}, true},
		{"valid static", Config{Endpoint: "store.example:443", Bucket: "dsse-cold-archive", AccessKey: "k", SecretKey: "s", UseSSL: true, AuthMode: "static"}, false},
		{"static with IAM inputs refused", Config{Endpoint: "store.example:443", Bucket: "dsse-cold-archive", AccessKey: "k", SecretKey: "s", WorkloadAccessKey: "other", WorkloadSecretKey: "other", UseSSL: true, AuthMode: "static"}, true},
		{"valid IAM", Config{Endpoint: "s3.ap-northeast-1.amazonaws.com", Bucket: "dsse-cold-archive", Region: "ap-northeast-1", UseSSL: true, AuthMode: "iam"}, false},
		{"incomplete IAM workload refused", Config{Endpoint: "store.example:443", Bucket: "dsse-cold-archive", WorkloadAccessKey: "partial", IgnoreEnvCredentials: true, UseSSL: true, AuthMode: "iam"}, true},
		{"dedicated IAM workload accepted", Config{Endpoint: "store.example:443", Bucket: "dsse-cold-archive", WorkloadAccessKey: "dedicated", WorkloadSecretKey: "dedicated-secret", WorkloadSessionToken: "session", IgnoreEnvCredentials: true, UseSSL: true, AuthMode: "iam"}, false},
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

func TestWorkloadCredentialsAcceptSessionAndRejectPartialEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "temporary-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "temporary-secret")
	t.Setenv("AWS_SESSION_TOKEN", "temporary-session")
	creds, err := workloadCredentials()
	if err != nil {
		t.Fatal(err)
	}
	v, err := creds.Get()
	if err != nil || v.AccessKeyID != "temporary-key" || v.SecretAccessKey != "temporary-secret" || v.SessionToken != "temporary-session" {
		t.Fatal("temporary workload credentials were not selected")
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, err := workloadCredentials(); err == nil {
		t.Fatal("partial environment credentials fell back to a role")
	}
}
