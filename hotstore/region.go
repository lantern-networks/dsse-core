package hotstore

import "sync/atomic"

// region.go — counting the records that arrive without a region.
//
// ★★★ WHY A COUNTER AND NOT A REFUSAL (2026-08-24). A record whose producer did not say which region it came
// from is a defect, and the store is the wrong place to fail on it: refusing the write would lose the record
// to protect a field, which is the wrong trade for an audit log. But writing it with an empty region and
// saying nothing is how 29,859 rows accumulated unnoticed in the first place — nobody was counting, so nobody
// looked.
//
// So it is written, and it is counted, and the count is reported. A number that should be zero and is not is
// a question somebody can ask; an empty string in a column nobody queries is not.
var (
	ingestedWithRegion    atomic.Uint64
	ingestedWithoutRegion atomic.Uint64
)

// noteIngestedRegion records whether one ingested record could say which region it came from.
func noteIngestedRegion(region string) {
	if region == "" {
		ingestedWithoutRegion.Add(1)
		return
	}
	ingestedWithRegion.Add(1)
}

// IngestRegionCounts reports how many records this process has ingested with and without a region.
func IngestRegionCounts() (withRegion, withoutRegion uint64) {
	return ingestedWithRegion.Load(), ingestedWithoutRegion.Load()
}

// noteAndReturnRegion is EventRegion with the counting, used by every ingest path so the count covers all of
// them rather than whichever one somebody remembered.
func noteAndReturnRegion(row map[string]any) string {
	region := EventRegion(row)
	noteIngestedRegion(region)
	return region
}
