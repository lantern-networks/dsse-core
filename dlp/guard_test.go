package dlp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// The core prevention property: a blocking secret is NEVER released to the destination, even though the
// upload streams at constant memory.
func TestGuardReaderBlocksBeforeSecretLeaves(t *testing.T) {
	secret := "123456789018" // valid My Number
	body := strings.Repeat("safe-", 3000) + " " + secret + " " + strings.Repeat("tail-", 3000)
	g := NewGuardReader(strings.NewReader(body), map[IdentifierType]int{MyNumber: 1})

	var sink bytes.Buffer
	_, err := io.Copy(&sink, g)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("io.Copy err = %v, want ErrBlocked", err)
	}
	if strings.Contains(sink.String(), secret) {
		t.Errorf("secret leaked into forwarded bytes")
	}
	if findingCount(g.Findings(), MyNumber) < 1 {
		t.Errorf("guard did not record the my_number finding")
	}
}

// Definition-1: a benign prefix streamed before the secret's chunk may reach the destination, but the secret
// itself never does.
func TestGuardReaderReleasesBenignPrefixButNotSecret(t *testing.T) {
	secret := "123456789018"
	prefix := strings.Repeat("a", 5000) // > windowSize so it is released before the secret arrives
	chunks := [][]byte{[]byte(prefix), []byte(" " + secret + " tail")}
	g := NewGuardReader(&sliceReader{chunks: chunks}, map[IdentifierType]int{MyNumber: 1})

	var sink bytes.Buffer
	_, err := io.Copy(&sink, g)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("io.Copy err = %v, want ErrBlocked", err)
	}
	if strings.Contains(sink.String(), secret) {
		t.Errorf("secret leaked into forwarded bytes")
	}
	if sink.Len() == 0 {
		t.Errorf("expected the benign prefix to be released (definition-1)")
	}
	if strings.Trim(sink.String(), "a ") != "" {
		t.Errorf("released bytes were not the benign prefix: %q", sink.String())
	}
}

// A body with no governed identifier streams through unchanged.
func TestGuardReaderPassesBenignBodyUnchanged(t *testing.T) {
	body := strings.Repeat("no secrets here just words ", 5000)
	g := NewGuardReader(strings.NewReader(body), map[IdentifierType]int{MyNumber: 1})

	var sink bytes.Buffer
	if _, err := io.Copy(&sink, g); err != nil {
		t.Fatalf("io.Copy err = %v, want nil", err)
	}
	if sink.String() != body {
		t.Errorf("benign body was altered or truncated (got %d bytes, want %d)", sink.Len(), len(body))
	}
}

// Threshold semantics: trip only when the count reaches the threshold.
func TestGuardReaderThreshold(t *testing.T) {
	body := "x 123456789018 y 123456789018 z" // two valid My Numbers

	blocked := NewGuardReader(strings.NewReader(body), map[IdentifierType]int{MyNumber: 2})
	if _, err := io.Copy(io.Discard, blocked); !errors.Is(err, ErrBlocked) {
		t.Errorf("threshold 2 with two occurrences: err = %v, want ErrBlocked", err)
	}

	passed := NewGuardReader(strings.NewReader(body), map[IdentifierType]int{MyNumber: 3})
	var sink bytes.Buffer
	if _, err := io.Copy(&sink, passed); err != nil {
		t.Errorf("threshold 3 with two occurrences: err = %v, want nil (pass)", err)
	}
	if sink.String() != body {
		t.Errorf("threshold 3: body altered")
	}
}
