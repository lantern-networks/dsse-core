// Package archive is the pluggable, S3-compatible cold-archive backend for aged log segments.
//
// It is deliberately VENDOR-NEUTRAL: the endpoint and credentials are configurable, so it runs against
// self-hosted MinIO / Ceph (the default, strongest-sovereignty target), an in-country provider
// (Sakura / IIJ / IDCF / NIFCLOUD in Japan, their equivalents elsewhere), or any S3-compatible store — NEVER hardcoded to AWS. Sovereignty is a
// deployment choice; the code is identical across targets, only the endpoint + credentials differ.
// See docs/logs_audit_ui_and_volume_design.md and the "sovereign storage, no hyperscaler" principle.
package archive

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config points the archive at an S3-compatible endpoint. Endpoint + Bucket are required; the rest is optional.
// Endpoint is a host:port (e.g. "minio:9000"), NOT a URL and NOT an AWS ARN — this backend never assumes AWS.
type Config struct {
	Endpoint  string // host:port of the S3-compatible endpoint
	Bucket    string // target bucket (should be object-lock-enabled if WORM is used)
	AccessKey string
	SecretKey string
	Region    string // optional; many self-hosted stores ignore it
	UseSSL    bool   // TLS to the endpoint
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
// store can back it; the default is self-hosted MinIO/Ceph.
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
	// Reject an accidental URL — the endpoint is host:port, keeping the backend vendor-neutral.
	if strings.Contains(endpoint, "://") {
		return nil, fmt.Errorf("archive: endpoint must be host:port, not a URL (%q)", endpoint)
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: strings.TrimSpace(cfg.Region),
	})
	if err != nil {
		return nil, fmt.Errorf("archive: build S3 client: %w", err)
	}
	return &s3Archive{client: client, bucket: bucket, endpoint: endpoint}, nil
}

func (a *s3Archive) Put(ctx context.Context, key string, r io.Reader, size int64, opts PutOptions) (PutResult, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return PutResult{}, fmt.Errorf("archive: key is required")
	}
	po := minio.PutObjectOptions{ContentType: opts.ContentType}
	if !opts.RetainUntil.IsZero() {
		// COMPLIANCE-mode object lock = true WORM: nobody (incl. root) can delete/overwrite before the date.
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
