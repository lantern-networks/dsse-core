package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// emailStream matches the existing emailRE across arbitrarily split input
// without retaining the matched bytes. emailRE has a bounded local part and
// bounded individual labels, but an unbounded number of dotted labels. A
// candidate's last accepting end is retained because a later label can fail
// and RE2 then selects the preceding complete TLD.
type emailStream struct {
	position     int64
	lastMatchEnd int64
	local        []byte // the last at most 64 permitted local-part bytes
	localStart   int64
	candidate    *emailCandidate
	allowlist    *Allowlist
}

type emailCandidate struct {
	start           int64
	hash            hash.Hash
	firstDomainByte bool
	segmentLen      int // bytes in the repeated [A-Za-z0-9-]{0,62} portion
	segmentAlpha    bool
	hadDot          bool
	acceptedEnd     int64
	acceptedHash    [sha256.Size]byte
}

type emailStreamMatch struct {
	start, end int64
	allowed    bool
}

func newEmailStream(allowlist *Allowlist) *emailStream {
	return &emailStream{allowlist: allowlist}
}

func emailLocalByte(b byte) bool {
	return asciiAlpha(b) || asciiDigit(b) || b == '.' || b == '_' || b == '%' || b == '+' || b == '-'
}

func asciiAlpha(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func asciiDigit(b byte) bool { return b >= '0' && b <= '9' }

func emailLabelByte(b byte) bool { return asciiAlpha(b) || asciiDigit(b) || b == '-' }

func lowerASCIIByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func (s *emailStream) startCandidate() {
	if len(s.local) == 0 {
		return
	}
	start := s.localStart
	if start < s.lastMatchEnd {
		start = s.lastMatchEnd
	}
	localOffset := int(start - s.localStart)
	if localOffset >= len(s.local) {
		return
	}
	h := sha256.New()
	if s.allowlist != nil {
		_, _ = h.Write([]byte(s.allowlist.salt))
	}
	_, _ = h.Write([]byte("\x00email\x00"))
	for _, b := range s.local[localOffset:] {
		_, _ = h.Write([]byte{lowerASCIIByte(b)})
	}
	_, _ = h.Write([]byte{'@'})
	s.candidate = &emailCandidate{start: start, hash: h}
}

func (s *emailStream) finishCandidate() (emailStreamMatch, bool) {
	c := s.candidate
	s.candidate = nil
	if c == nil || c.acceptedEnd <= c.start {
		return emailStreamMatch{}, false
	}
	s.lastMatchEnd = c.acceptedEnd
	allowed := s.allowlist != nil && s.allowlist.hashes[hex.EncodeToString(c.acceptedHash[:])]
	return emailStreamMatch{start: c.start, end: c.acceptedEnd, allowed: allowed}, true
}

// write appends bytes in stream order and reports finalized, non-overlapping
// matches. The match is finalized only when no later input can lengthen it.
func (s *emailStream) write(p []byte) []emailStreamMatch {
	var out []emailStreamMatch
	for _, b := range p {
		if c := s.candidate; c != nil {
			if !c.feedDomainByte(b, s.position) {
				if m, ok := s.finishCandidate(); ok {
					out = append(out, m)
				}
			}
		}
		if b == '@' && s.candidate == nil {
			s.startCandidate()
		}
		if emailLocalByte(b) {
			if len(s.local) == 64 {
				copy(s.local, s.local[1:])
				s.local = s.local[:63]
				s.localStart++
			}
			if len(s.local) == 0 {
				s.localStart = s.position
			}
			s.local = append(s.local, b)
		} else {
			s.local = s.local[:0]
			s.localStart = s.position + 1
		}
		s.position++
	}
	return out
}

func (c *emailCandidate) feedDomainByte(b byte, position int64) bool {
	if !c.firstDomainByte {
		if !asciiAlpha(b) && !asciiDigit(b) {
			return false
		}
		c.firstDomainByte = true
		_, _ = c.hash.Write([]byte{lowerASCIIByte(b)})
		return true
	}
	if b == '.' {
		// The existing regex permits an empty repeated segment after
		// the first domain byte, including consecutive dots.
		c.hadDot = true
		c.segmentLen = 0
		c.segmentAlpha = true
		_, _ = c.hash.Write([]byte{b})
		return true
	}
	if !emailLabelByte(b) || c.segmentLen >= 62 {
		return false
	}
	c.segmentLen++
	if c.segmentLen == 1 {
		c.segmentAlpha = asciiAlpha(b)
	} else {
		c.segmentAlpha = c.segmentAlpha && asciiAlpha(b)
	}
	_, _ = c.hash.Write([]byte{lowerASCIIByte(b)})
	if c.hadDot && c.segmentAlpha && c.segmentLen >= 2 && c.segmentLen <= 24 {
		c.acceptedEnd = position + 1
		copy(c.acceptedHash[:], c.hash.Sum(nil))
	}
	return true
}

func (s *emailStream) finish() []emailStreamMatch {
	if m, ok := s.finishCandidate(); ok {
		return []emailStreamMatch{m}
	}
	return nil
}

func (s *emailStream) pendingStart() (int64, bool) {
	if s.candidate == nil {
		return 0, false
	}
	return s.candidate.start, true
}
