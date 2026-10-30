// Package archive is the pluggable, S3-compatible cold-archive backend for aged log segments.
//
// The object store is supplied and operated outside DSSE. AWS S3 and compatible
// providers use the same API; the deployment chooses its data location and retention.
package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config points the archive at an operator-managed S3-compatible endpoint.
type Config struct {
	Endpoint  string // host or host:port of the S3-compatible endpoint
	Bucket    string // target bucket (should be object-lock-enabled if WORM is used)
	AccessKey string
	SecretKey string
	Region    string // optional; many self-hosted stores ignore it
	UseSSL    bool   // TLS to the endpoint; required for external archives
	AuthMode  string // "static" or "iam" (workload identity)
	// Workload credentials are used by installer preflight to inspect the bucket
	// with the exact CP-only IAM inputs in deployment.env, without inheriting
	// unrelated AWS credentials from the operator's shell.
	WorkloadAccessKey    string
	WorkloadSecretKey    string
	WorkloadSessionToken string
	IgnoreEnvCredentials bool
}

// PutOptions carries per-object write options.
type PutOptions struct {
	ContentType string
	// RetainUntil, when non-zero, applies an object-lock (WORM) retention in COMPLIANCE mode: the object
	// cannot be deleted or overwritten until this time, not even by an admin. Requires an object-lock-enabled
	// bucket. Zero = no lock. This is the mechanism behind the audit stream's tamper-proof retention.
	RetainUntil time.Time
}

// PutResult is the outcome of a Put.
type PutResult struct {
	Key  string
	ETag string
	Size int64
}

// ObjectInfo describes one archived object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// ColdArchive is the backend interface the retention lifecycle writes aged segments to. Any S3-compatible
// store can back it; DSSE does not run an object-storage server.
type ColdArchive interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, opts PutOptions) (PutResult, error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string, limit int) ([]ObjectInfo, error)
	// Backend returns a non-secret description for logs (endpoint + bucket, never credentials).
	Backend() string
}

type s3Archive struct {
	client   *minio.Client
	bucket   string
	endpoint string
}

// New builds an S3-compatible cold archive from cfg. It validates the config and constructs the client but
// does NOT create the bucket — the bucket (ideally object-lock-enabled) is provisioned out of band so the
// archive credentials need not carry bucket-creation rights.
func New(cfg Config) (ColdArchive, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	bucket := strings.TrimSpace(cfg.Bucket)
	if endpoint == "" {
		return nil, fmt.Errorf("archive: endpoint is required")
	}
	if bucket == "" {
		return nil, fmt.Errorf("archive: bucket is required")
	}
	// Reject an accidental URL — the endpoint is a host with an optional port.
	if strings.Contains(endpoint, "://") {
		return nil, fmt.Errorf("archive: endpoint must be a host with an optional port, not a URL (%q)", endpoint)
	}
	if !cfg.UseSSL {
		return nil, fmt.Errorf("archive: TLS is required for external object storage")
	}
	var creds *credentials.Credentials
	var err error
	switch cfg.AuthMode {
	case "static":
		if cfg.WorkloadAccessKey != "" || cfg.WorkloadSecretKey != "" || cfg.WorkloadSessionToken != "" {
			return nil, fmt.Errorf("archive: static mode must not contain IAM workload credentials")
		}
		if strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
			return nil, fmt.Errorf("archive: static credentials require both access and secret keys")
		}
		creds = credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	case "iam":
		if cfg.AccessKey != "" || cfg.SecretKey != "" {
			return nil, fmt.Errorf("archive: IAM mode must not also contain static keys")
		}
		if cfg.WorkloadAccessKey != "" || cfg.WorkloadSecretKey != "" || cfg.WorkloadSessionToken != "" {
			if cfg.WorkloadAccessKey == "" || cfg.WorkloadSecretKey == "" {
				return nil, fmt.Errorf("archive: incomplete IAM workload credentials")
			}
			creds = credentials.NewStaticV4(cfg.WorkloadAccessKey, cfg.WorkloadSecretKey, cfg.WorkloadSessionToken)
		} else if cfg.IgnoreEnvCredentials {
			creds = credentials.NewIAM("")
		} else {
			creds, err = workloadCredentials()
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("archive: auth mode must be static or iam")
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  creds,
		Secure: true,
		Region: strings.TrimSpace(cfg.Region),
	})
	if err != nil {
		return nil, fmt.Errorf("archive: build S3 client: %w", err)
	}
	return &s3Archive{client: client, bucket: bucket, endpoint: endpoint}, nil
}

// Workload credentials may be injected as short-lived environment credentials
// (including an STS session token), or supplied by the host's IAM role. The
// minio-go IAM provider does not inspect AWS_ACCESS_KEY_ID, so selecting it
// unconditionally silently breaks non-EC2 workloads and local SSO sessions.
func workloadCredentials() (*credentials.Credentials, error) {
	id := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secret := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	token := strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN"))
	if id != "" || secret != "" || token != "" {
		if id == "" || secret == "" {
			return nil, fmt.Errorf("archive: incomplete AWS workload credentials")
		}
		return credentials.NewEnvAWS(), nil
	}
	return credentials.NewIAM(""), nil
}

// CheckBucket verifies the externally provisioned bucket without mutating it.
// Write permission is exercised by the first archive batch; that batch retains
// its local hot rows if Put fails. The installer requires both versioning and
// Object Lock for every configured external archive before CP startup.
func CheckBucket(ctx context.Context, cfg Config) error {
	backend, err := New(cfg)
	if err != nil {
		return err
	}
	a := backend.(*s3Archive)
	exists, err := a.client.BucketExists(ctx, a.bucket)
	if err != nil {
		return fmt.Errorf("archive: inspect bucket: %w", err)
	}
	if !exists {
		return fmt.Errorf("archive: bucket does not exist")
	}
	versioning, err := a.client.GetBucketVersioning(ctx, a.bucket)
	if err != nil {
		return fmt.Errorf("archive: inspect bucket versioning: %w", err)
	}
	if !versioning.Enabled() {
		return fmt.Errorf("archive: bucket versioning must be enabled")
	}
	lock, _, _, _, err := a.client.GetObjectLockConfig(ctx, a.bucket)
	if err != nil {
		return fmt.Errorf("archive: inspect bucket Object Lock: %w", err)
	}
	if lock != "Enabled" {
		return fmt.Errorf("archive: bucket Object Lock must be enabled")
	}
	for obj := range a.client.ListObjects(ctx, a.bucket, minio.ListObjectsOptions{Prefix: "hot_events/", Recursive: true, MaxKeys: 1}) {
		if obj.Err != nil {
			return fmt.Errorf("archive: list objects: %w", obj.Err)
		}
		break
	}
	return nil
}

func (a *s3Archive) Put(ctx context.Context, key string, r io.Reader, size int64, opts PutOptions) (PutResult, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return PutResult{}, fmt.Errorf("archive: key is required")
	}
	po := minio.PutObjectOptions{ContentType: opts.ContentType}
	if !opts.RetainUntil.IsZero() {
		// COMPLIANCE-mode object lock = true WORM: nobody (incl. root) can delete/overwrite before the date.
		// S3 requires a Content-MD5 or checksum header when Object Lock is set.
		po.SendContentMd5 = true
		po.Mode = minio.Compliance
		po.RetainUntilDate = opts.RetainUntil.UTC()
	}
	info, err := a.client.PutObject(ctx, a.bucket, key, r, size, po)
	if err != nil {
		return PutResult{}, fmt.Errorf("archive: put %q: %w", key, err)
	}
	return PutResult{Key: info.Key, ETag: info.ETag, Size: info.Size}, nil
}

func (a *s3Archive) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := a.client.GetObject(ctx, a.bucket, strings.TrimSpace(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("archive: get %q: %w", key, err)
	}
	// GetObject is lazy; probe with Stat so a missing key errors here rather than on first Read.
	if _, serr := obj.Stat(); serr != nil {
		obj.Close()
		return nil, fmt.Errorf("archive: stat %q: %w", key, serr)
	}
	return obj, nil
}

func (a *s3Archive) List(ctx context.Context, prefix string, limit int) ([]ObjectInfo, error) {
	out := []ObjectInfo{}
	for obj := range a.client.ListObjects(ctx, a.bucket, minio.ListObjectsOptions{Prefix: strings.TrimSpace(prefix), Recursive: true}) {
		if obj.Err != nil {
			return out, fmt.Errorf("archive: list %q: %w", prefix, obj.Err)
		}
		out = append(out, ObjectInfo{Key: obj.Key, Size: obj.Size, LastModified: obj.LastModified})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (a *s3Archive) Backend() string {
	return fmt.Sprintf("s3-compatible endpoint=%s bucket=%s", a.endpoint, a.bucket)
}
