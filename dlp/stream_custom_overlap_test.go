package dlp

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func overlapClassifierSet(t *testing.T) *ClassifierSet {
	t.Helper()
	set, errs := NewClassifierSet([]ClassifierSpec{
		{Name: "alpha", Kind: ClassifierKeyword, Keywords: []string{"abc"}},
		{Name: "beta", Kind: ClassifierKeyword, Keywords: []string{"bca"}},
		{Name: "gamma", Kind: ClassifierKeyword, Keywords: []string{"cab"}},
	})
	if len(errs) != 0 {
		t.Fatalf("compile classifiers: %v", errs)
	}
	return set
}

func TestStreamingCustomOverlapRetainsOnlyWindowAndPreservesCounts(t *testing.T) {
	set := overlapClassifierSet(t)
	body := strings.Repeat("abc", 16384)
	want := DetectWith([]byte(body), "text/plain", set)
	for _, chunk := range []int{4097, 5000, 32768, len(body)} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			s := NewScannerWith(set)
			for pos := 0; pos < len(body); pos += chunk {
				end := pos + chunk
				if end > len(body) {
					end = len(body)
				}
				if _, err := s.Write([]byte(body[pos:end])); err != nil {
					t.Fatal(err)
				}
				if got := len(s.buf); got > chunkSize+windowSize {
					t.Fatalf("custom overlap retained %d bytes after %d bytes of input", got, end)
				}
			}
			if got := s.Findings(); !reflect.DeepEqual(got, want) {
				t.Fatalf("streamed findings %v, buffered %v", got, want)
			}
		})
	}
}

func TestStreamingCustomRegexAndKeywordKeepNonoverlapPhase(t *testing.T) {
	set, errs := NewClassifierSet([]ClassifierSpec{
		{Name: "regex_aaa", Kind: ClassifierRegex, Pattern: "aaa"},
		{Name: "keyword_aaa", Kind: ClassifierKeyword, Keywords: []string{"aa", "aaa"}},
	})
	if len(errs) != 0 {
		t.Fatalf("compile classifiers: %v", errs)
	}
	body := strings.Repeat("a", 10003)
	want := DetectWith([]byte(body), "text/plain", set)
	for _, chunk := range []int{1, 4097, 5000} {
		s := NewScannerWith(set)
		for pos := 0; pos < len(body); pos += chunk {
			end := pos + chunk
			if end > len(body) {
				end = len(body)
			}
			s.Write([]byte(body[pos:end]))
		}
		if got := s.Findings(); !reflect.DeepEqual(got, want) {
			t.Fatalf("chunk %d: streamed %v, buffered %v", chunk, got, want)
		}
		g := NewGuardReaderWithOptions(strings.NewReader(body), nil, Options{Classifiers: set})
		gotBody, err := io.ReadAll(g)
		if err != nil || string(gotBody) != body {
			t.Fatalf("chunk %d: guard changed allowed body: err=%v", chunk, err)
		}
		if got := g.Findings(); !reflect.DeepEqual(got, want) {
			t.Fatalf("chunk %d: guard findings %v, buffered %v", chunk, got, want)
		}
	}
}

func TestGuardCustomOverlapBlocksBeforeReleaseAndAllowlistPasses(t *testing.T) {
	set := overlapClassifierSet(t)
	prefix := strings.Repeat(" ", windowSize+20)
	body := prefix + strings.Repeat("abc", 16384)
	g := NewGuardReaderWith(strings.NewReader(body), map[IdentifierType]int{"alpha": 1}, set)
	var sink bytes.Buffer
	if _, err := io.Copy(&sink, g); !errors.Is(err, ErrBlocked) {
		t.Fatalf("guard err=%v, want block", err)
	}
	if strings.Contains(sink.String(), "abc") {
		t.Fatal("blocking custom classifier bytes were released")
	}
	if got := len(g.hold); got > chunkSize+windowSize {
		t.Fatalf("guard held %d bytes after trip", got)
	}

	allow := NewAllowlist("test", []string{"abc"})
	pass := NewGuardReaderWithOptions(strings.NewReader(body), map[IdentifierType]int{"alpha": 1}, Options{Classifiers: set, Allowlist: allow})
	sink.Reset()
	if _, err := io.Copy(&sink, pass); err != nil {
		t.Fatalf("allowlisted guard: %v", err)
	}
	if sink.String() != body {
		t.Fatal("allowlisted custom overlap changed the body")
	}
	want := DetectWithOptions([]byte(body), "text/plain", Options{Classifiers: set, Allowlist: allow})
	if got := pass.Findings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("guard allowlist findings %v, buffered %v", got, want)
	}
}
