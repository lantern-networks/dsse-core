package hotstore

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Grouping is served by the database instead of by loading rows: the caller names the payload fields to group
// on and the measures to compute, and gets back one row per distinct combination. It is an OPTIONAL capability,
// like TrendsCapable — only backends that can group cheaply implement it, callers type-assert and fall back to
// row-loading otherwise, and the base Store interface stays minimal.
//
// The caller names the fields rather than the store knowing them: what a report groups on is the report's
// business (an identity ladder, a service classification), and encoding that here would put the same knowledge
// in two places, where drift between them changes results silently.
type FieldGroupCapable interface {
	GroupRowsByFields(ctx context.Context, query FieldGroupQuery) (FieldGroupResult, error)
}

// fieldNamePattern is the injection guard. Field names are interpolated into SQL (they cannot be bound as
// parameters inside a JSON path operator), so they are restricted to a shape no SQL syntax can hide in.
var fieldNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// FieldSpec names a value and says WHERE to find it: a list of payload paths tried in order, first non-null
// wins. Paths, not a single name, because the caller's row-reading code does not look at one depth for every
// field — some values are top-level, some live under "metadata", and some are top-level with a metadata
// fallback. A store that guesses (say, always COALESCE both depths) is more permissive than the caller and will
// count values the caller's own reader would never see. That divergence is silent and only shows up on rows
// shaped unusually enough that no ordinary test contains one.
//
// A path is dot-separated: "user_id" is the top level, "metadata.ai_app" is one level in.
type FieldSpec struct {
	Name  string
	Paths []string
}

type FieldGroupQuery struct {
	TenantID string
	Stream   string
	From     *time.Time
	To       *time.Time
	// Fields to group by, each with the paths to look in.
	Fields []FieldSpec
	// Measure fields, all optional. Bytes are summed from a JSON NUMBER only — a value stored as a string is
	// not a number and counts zero, and a fractional one truncates toward zero, because that is what a caller
	// decoding JSON into Go sees. Guessing more generously here would make the two paths disagree.
	BytesSent     FieldSpec
	BytesReceived FieldSpec
	// MatchCount/MatchValue count rows whose field equals the value, case-insensitively (the report's
	// "messages" measure is POSTs). An unnamed spec disables the measure.
	MatchCount FieldSpec
	MatchValue string
	// BucketSeconds, when > 0, collects the DISTINCT time buckets each group's rows fell in — as a set, not a
	// count. A caller that unions bucket sets at a coarser level than it grouped at cannot use per-group counts:
	// a bucket spanning two groups is one bucket, and summing counts it twice.
	BucketSeconds int
	// MaxGroups bounds the result. Hitting it sets Truncated: a partial grouping reported as complete would be
	// the same lie as a row-capped read reported as a full window.
	MaxGroups int
	// IncludeOldestMatched also reports the earliest event held for this tenant+stream, ignoring From/To — the
	// same fact ExportRows can return. A caller that states how far its data reaches must be able to state it on
	// EITHER path, or the honesty disappears when the backend changes.
	IncludeOldestMatched bool
}

type FieldGroup struct {
	// Fields holds the grouped values, keyed by the requested field name. A field absent from the payload is an
	// empty string — the same thing the row-loading path sees, so the caller's logic does not branch on source.
	Fields        map[string]string
	Rows          int
	MatchedRows   int
	BytesSent     int64
	BytesReceived int64
	Buckets       []int64
}

type FieldGroupResult struct {
	Groups    []FieldGroup
	TotalRows int
	Truncated bool
	// OldestMatchedAt mirrors ExportResult.OldestMatchedAt: the earliest event held for this tenant+stream,
	// ignoring the window, and only when IncludeOldestMatched asked for it. Zero when unknown.
	OldestMatchedAt time.Time
}

func (q FieldGroupQuery) validate() error {
	if q.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if q.Stream == "" {
		return fmt.Errorf("stream is required")
	}
	if len(q.Fields) == 0 {
		return fmt.Errorf("at least one group field is required")
	}
	specs := append(append([]FieldSpec{}, q.Fields...), q.BytesSent, q.BytesReceived, q.MatchCount)
	for _, spec := range specs {
		if spec.Name == "" && len(spec.Paths) == 0 {
			continue
		}
		if !fieldNamePattern.MatchString(spec.Name) {
			return fmt.Errorf("invalid field name %q", spec.Name)
		}
		if len(spec.Paths) == 0 {
			return fmt.Errorf("field %q needs at least one path", spec.Name)
		}
		for _, path := range spec.Paths {
			for _, segment := range strings.Split(path, ".") {
				if !fieldNamePattern.MatchString(segment) {
					return fmt.Errorf("invalid path %q on field %q", path, spec.Name)
				}
			}
		}
	}
	return nil
}
