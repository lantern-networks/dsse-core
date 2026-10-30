package dlp

import "bytes"

// customStreamState keeps the non-overlapping FindAll phase of each custom
// regex and each keyword independently. A compacted byte window must not let
// a matcher start again inside a match it already consumed.
type customStreamState struct {
	set     *ClassifierSet
	nextEnd [][]int64
}

type stableCustomMatch struct {
	match
	classifier  int
	keyword     int // -1 for a regex; otherwise the literal's index.
	absoluteEnd int64
	allowed     bool
}

func newCustomStreamState(set *ClassifierSet) *customStreamState {
	state := &customStreamState{set: set}
	if set == nil {
		return state
	}
	state.nextEnd = make([][]int64, len(set.classifiers))
	for i, c := range set.classifiers {
		if c.kind == ClassifierKeyword {
			state.nextEnd[i] = make([]int64, len(c.lits))
		} else {
			state.nextEnd[i] = make([]int64, 1)
		}
	}
	return state
}

// stable returns complete matches whose start precedes dropTo. Custom matches
// have a validated maximum width below windowSize, so bytes more than one
// window behind the end cannot be extended by a future write. The caller
// commits each returned match before dropping that prefix.
func (s *customStreamState) stable(data []byte, origin int64, dropTo int, allowlist *Allowlist) []stableCustomMatch {
	if s == nil || s.set == nil || dropTo <= 0 {
		return nil
	}
	var out []stableCustomMatch
	for ci, c := range s.set.classifiers {
		if !c.gate(data) {
			continue
		}
		appendMatch := func(start, end, ki int) {
			if start >= dropTo {
				return
			}
			mt := stableCustomMatch{
				match:      match{typ: c.typ, start: start, end: end},
				classifier: ci, keyword: ki, absoluteEnd: origin + int64(end),
			}
			mt.allowed = allowlist.Allowed(c.typ, data[start:end])
			out = append(out, mt)
		}
		switch c.kind {
		case ClassifierRegex:
			from := int(s.nextEnd[ci][0] - origin)
			if from < 0 {
				from = 0
			}
			if from >= len(data) {
				continue
			}
			for _, loc := range c.re.FindAllIndex(data[from:], -1) {
				start, end := from+loc[0], from+loc[1]
				if start >= dropTo {
					break
				}
				// A compiled regex cannot exceed this width; keep the
				// buffered detector's defensive drop if this changes.
				if end-start <= maxCustomMatchLen {
					appendMatch(start, end, -1)
				}
			}
		case ClassifierKeyword:
			for ki, kw := range c.lits {
				from := int(s.nextEnd[ci][ki] - origin)
				if from < 0 {
					from = 0
				}
				for from < len(data) {
					rel := bytes.Index(data[from:], kw)
					if rel < 0 {
						break
					}
					start := from + rel
					if start >= dropTo {
						break
					}
					end := start + len(kw)
					appendMatch(start, end, ki)
					from = end
				}
			}
		}
	}
	return out
}

func (s *customStreamState) commit(mt stableCustomMatch) {
	ki := mt.keyword
	if ki < 0 {
		ki = 0
	}
	s.nextEnd[mt.classifier][ki] = mt.absoluteEnd
}
