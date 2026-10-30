package dlp

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func emailStreamIndices(body []byte, chunk int) [][2]int {
	state := newEmailStream(nil)
	var got [][2]int
	appendMatches := func(matches []emailStreamMatch) {
		for _, m := range matches {
			got = append(got, [2]int{int(m.start), int(m.end)})
		}
	}
	for off := 0; off < len(body); off += chunk {
		end := off + chunk
		if end > len(body) {
			end = len(body)
		}
		appendMatches(state.write(body[off:end]))
	}
	appendMatches(state.finish())
	return got
}

func bufferedEmailIndices(body []byte) [][2]int {
	locs := emailRE.FindAllIndex(body, -1)
	var out [][2]int
	for _, loc := range locs {
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}

func TestStreamingEmailMatchesExistingBufferedRegex(t *testing.T) {
	bodies := []string{
		"a@b.cc",
		"Ka@b.cc ſb@c.dd and a@b.ccK",
		"a@b..cc a@b.-.dd a@b.ccK@d.ee",
		"user@b.cc.abc.123 and a@b.cc.foo",
		"prefix.a@b.cc and b@c.dd",
		"a@b.cd.foo123@bar.ee",
		"a@b.abcdefghijklmnopqrstuvwxyz and a@b.cc.foo",
		strings.Repeat("x", 80) + "@b.cc x@b.cc",
		"a@b." + strings.Repeat("abc.", 5000) + "com end",
		"a@b." + strings.Repeat("abc.", 5000) + "com@d.ee",
		"a@b." + strings.Repeat("a", 80) + "@c.dd",
	}
	const alphabet = "abcXYZ012-._%+@ /!"
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 1200; n++ {
		var body strings.Builder
		for i := 0; i < 256; i++ {
			body.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		body.WriteString(" a@b.")
		for i := 0; i < 1+rng.Intn(5); i++ {
			body.WriteString("abc.")
		}
		body.WriteString("com ")
		bodies = append(bodies, body.String())
	}
	for i, body := range bodies {
		want := bufferedEmailIndices([]byte(body))
		for _, chunk := range []int{1, 7, 64, 4097, 5000, 32768} {
			if got := emailStreamIndices([]byte(body), chunk); !reflect.DeepEqual(got, want) {
				t.Fatalf("case %d chunk %d: streamed indices %v, buffered %v", i, chunk, got, want)
			}
		}
	}
}

func TestStreamingEmailLongExactAllowlistAndScannerParity(t *testing.T) {
	address := "a@b." + strings.Repeat("abc.", 20000) + "com"
	allow := NewAllowlist("test", []string{address})
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "exact", body: address + " "},
		{name: "changed", body: address + "x "},
		{name: "repeated", body: address + " " + address + "!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := DetectWithOptions([]byte(tc.body), "text/plain", Options{Allowlist: allow})
			for _, chunk := range []int{1, 4097, 5000, len(tc.body)} {
				s := NewScannerWithOptions(Options{Allowlist: allow})
				for off := 0; off < len(tc.body); off += chunk {
					end := off + chunk
					if end > len(tc.body) {
						end = len(tc.body)
					}
					_, _ = s.Write([]byte(tc.body[off:end]))
					if got := len(s.buf); got > chunkSize+windowSize {
						t.Fatalf("chunk %d: scanner retained %d bytes", chunk, got)
					}
				}
				if got := s.Findings(); !reflect.DeepEqual(got, want) {
					t.Fatalf("chunk %d: streamed %v, buffered %v", chunk, got, want)
				}
			}
		})
	}
}
