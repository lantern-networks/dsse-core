package main

import (
	"strings"
	"sync"
	"testing"
)

// The bookkeeping that decides whether a connector keeps a connection or drops it and dials again. Getting
// this wrong in either direction is silent: too eager and the connector holds two tunnels on one node while a
// sibling has none (the bug this exists to end); too strict and it drops the only tunnel it has.
func TestAConnectorClaimsEachEdgeNodeOnce(t *testing.T) {
	a := newConnectorFleetAttachments()

	edgeA, ok := a.claim("edge-a", "region-a", nil)
	if !ok {
		t.Fatal("the first attachment to a node must be kept")
	}
	if _, ok := a.claim("edge-a", "region-a", nil); ok {
		t.Fatal("a second connection landing on the SAME node must be dropped — that node is already covered")
	}
	if _, ok := a.claim("edge-b", "region-a", nil); !ok {
		t.Fatal("a connection landing on a node nobody holds must be kept")
	}
	if got := a.nodes(); len(got) != 2 || got[0] != "edge-a" || got[1] != "edge-b" {
		t.Fatalf("expected both nodes held and sorted, got %v", got)
	}

	// ★ A WORKER MAY ONLY RELEASE ITS OWN. Releasing with somebody else's token must do nothing — that is the
	// guard against a displaced worker deleting the claim of the one that displaced it.
	a.release("edge-a", edgeA+999)
	if got := a.nodes(); len(got) != 2 {
		t.Fatalf("a release with the wrong token must change nothing, got %v", got)
	}

	// The tunnel to edge-a ends: that node is uncovered again and the next connection to it must be kept.
	a.release("edge-a", edgeA)
	if got := a.nodes(); len(got) != 1 || got[0] != "edge-b" {
		t.Fatalf("expected only edge-b held, got %v", got)
	}
	if _, ok := a.claim("edge-a", "region-a", nil); !ok {
		t.Fatal("a node whose tunnel ended must be re-claimable, or the connector never reconnects to it")
	}
}

// ★ An Edge too old to name itself must never lock this connector out of connecting at all.
func TestAnUnnamedEdgeNodeNeverCollides(t *testing.T) {
	a := newConnectorFleetAttachments()
	for i := 0; i < 3; i++ {
		if _, ok := a.claim("", "region-a", nil); !ok {
			t.Fatalf("attempt %d: an Edge that does not name its node must still be attachable", i+1)
		}
	}
	if got := a.nodes(); len(got) != 0 {
		t.Fatalf("an unnamed node is not something this connector can claim to cover: %v", got)
	}
}

// The search for the rest of the fleet must start on a node seen for the FIRST time, and not again when an
// existing attachment merely reconnects — otherwise every Edge restart adds a worker for ever.
func TestOnlyAGenuinelyNewNodeStartsTheSearchForTheNext(t *testing.T) {
	a := newConnectorFleetAttachments()
	var mu sync.Mutex
	var announced []string
	a.onNewNode = func(node string) {
		mu.Lock()
		defer mu.Unlock()
		announced = append(announced, node)
	}

	_, _ = a.claim("edge-a", "region-a", nil)
	a.release("edge-a", 0)
	_, _ = a.claim("edge-a", "region-a", nil) // a reconnect to a node already known
	_, _ = a.claim("edge-b", "region-a", nil)

	mu.Lock()
	defer mu.Unlock()
	if len(announced) != 2 || announced[0] != "edge-a" || announced[1] != "edge-b" {
		t.Fatalf("expected one announcement per DISTINCT node, got %v", announced)
	}
}

func TestTheWorkerCountHasARunawayStop(t *testing.T) {
	a := newConnectorFleetAttachments()
	for i := 0; i < connectorFleetMaxNodes; i++ {
		if !a.addWorker() {
			t.Fatalf("worker %d refused below the stop", i+1)
		}
	}
	if a.addWorker() {
		t.Fatal("the runaway stop must refuse the worker past the limit")
	}
	a.dropWorker()
	if !a.addWorker() {
		t.Fatal("a slot freed by a retiring worker must be reusable")
	}
}

// ★★ THE DENOMINATOR IS THE POINT. "on 2 Edge nodes" and "on 2 of the region's 2 Edge nodes" are different
// facts, and only the second one means everything behind this connector is reachable wherever a flow lands.
// A connector that has not been told the size must SAY so rather than let the reader infer completeness.
func TestCoverageNeverClaimsCompletenessFromAnUnknownDenominator(t *testing.T) {
	a := newConnectorFleetAttachments()
	_, _ = a.claim("edge-a", "region-a", nil)

	got := a.coverage()
	if !strings.Contains(got, "unknown") {
		t.Fatalf("with no denominator the answer must say so: %q", got)
	}
	if strings.Contains(got, "of the region's") {
		t.Fatalf("with no denominator nothing may be reported as a fraction: %q", got)
	}

	// A denominator that is not known must not be readable as zero, or "1 of 0" would read as complete.
	a.noteFleetSize(0)
	if !strings.Contains(a.coverage(), "unknown") {
		t.Fatalf("a zero size is 'not told', not a fleet of none: %q", a.coverage())
	}

	a.noteFleetSize(2)
	got = a.coverage()
	if !strings.Contains(got, "only 1 of the 2 Edge node(s) the deployment knows of") {
		t.Fatalf("a partly-covered fleet must say which part: %q", got)
	}
	if !strings.Contains(got, "cannot reach") {
		t.Fatalf("the consequence is the reason to read the line: %q", got)
	}

	_, _ = a.claim("edge-b", "region-a", nil)
	got = a.coverage()
	if !strings.Contains(got, "all 2 of the 2 Edge node(s) the deployment knows of") {
		t.Fatalf("a fully covered fleet must say so plainly: %q", got)
	}
	if strings.Contains(got, "only") || strings.Contains(got, "cannot reach") {
		t.Fatalf("a covered fleet must not carry the warning: %q", got)
	}
}

// ★★★ A report that says "not covered" and a search that has stopped cannot both be right. Where the
// deployment has said how many nodes the region has, that number decides when the search is finished — the
// four-duplicates guess is for the case where nothing else is known, and a least-connections door can hand
// out the same node four times while a sibling sits idle.
func TestAKnownFleetSizeDecidesWhenTheSearchIsFinished(t *testing.T) {
	a := newConnectorFleetAttachments()
	a.noteFleetSize(2)
	_, _ = a.claim("edge-a", "region-a", nil)

	for _, duplicates := range []int{1, 4, 40} {
		if a.searchIsDone(duplicates) {
			t.Fatalf("held 1 of 2: the search must continue no matter how many duplicates (%d) it has seen", duplicates)
		}
	}

	edgeB, _ := a.claim("edge-b", "region-a", nil)
	if !a.searchIsDone(0) {
		t.Fatal("held 2 of 2: the search is finished with no duplicates needed at all")
	}

	// Losing a node re-opens the search: the fleet is no longer covered.
	a.release("edge-b", edgeB)
	if a.searchIsDone(9) {
		t.Fatal("a lost node must re-open the search — that node can no longer reach anything behind this connector")
	}
}

// With no denominator the guess is all there is, and it must still work.
func TestWithoutAFleetSizeTheDuplicateGuessStillEndsTheSearch(t *testing.T) {
	a := newConnectorFleetAttachments()
	_, _ = a.claim("edge-a", "region-a", nil)
	if a.searchIsDone(connectorFleetDuplicateGiveUp - 1) {
		t.Fatal("below the threshold the search continues")
	}
	if !a.searchIsDone(connectorFleetDuplicateGiveUp) {
		t.Fatal("at the threshold an unmeasured fleet is treated as covered — there is nothing else to go on")
	}
}

// ★ "Covered" is a claim about a fleet whose size is known. Without a denominator there is nothing to be
// short of, so neither the impatient re-probe nor the repeated warning may switch on — they would fire for
// ever against a deployment that simply never said.
func TestCoveredIsOnlyClaimableAgainstAKnownFleetSize(t *testing.T) {
	a := newConnectorFleetAttachments()
	_, _ = a.claim("edge-a", "region-a", nil)
	_, _ = a.claim("edge-b", "region-a", nil)

	if a.knowsItsFleetSize() {
		t.Fatal("no denominator has arrived")
	}
	if a.covered() {
		t.Fatal("an unmeasured fleet must never be declared covered, however many nodes are held")
	}

	a.noteFleetSize(3)
	if !a.knowsItsFleetSize() {
		t.Fatal("the denominator arrived")
	}
	if a.covered() {
		t.Fatal("2 of 3 is not covered")
	}

	_, _ = a.claim("edge-c", "region-a", nil)
	if !a.covered() {
		t.Fatal("3 of 3 is covered")
	}

	// A fleet that grew leaves this connector short again, and it must notice.
	a.noteFleetSize(4)
	if a.covered() {
		t.Fatal("a node added to the region leaves this connector short until it reaches it")
	}
}

// ★★★ A CONNECTOR LIVES IN ONE REGION AT A TIME. Measured on a real failover: the home region came back while
// the connector was working in the next one, a worker dialled the returning door, and the connector held
// tunnels in BOTH. Each node terminating a tunnel then told the authority a different region, so the
// deployment's answer to "where is this connector" flapped — and every Edge holding no tunnel of its own
// followed whichever answer it saw last.
func TestAConnectorLetsGoOfTheRegionItMovedAwayFrom(t *testing.T) {
	a := newConnectorFleetAttachments()
	a.noteFleetSize(2)

	letGoCalled := map[string]bool{}
	_, _ = a.claim("b-1", "region-b", func() { letGoCalled["b-1"] = true })
	_, _ = a.claim("b-2", "region-b", func() { letGoCalled["b-2"] = true })
	a.belongsTo("region-b")
	if !a.covered() {
		t.Fatalf("2 of region-b's 2: %s", a.coverage())
	}

	// It fails over. The attachment made through region-a is the only one that counts now...
	_, _ = a.claim("a-1", "region-a", func() { letGoCalled["a-1"] = true })
	letGo := a.belongsTo("region-a")
	if len(letGo) != 2 || letGo[0] != "b-1" || letGo[1] != "b-2" {
		t.Fatalf("expected both region-b attachments to be let go, got %v", letGo)
	}
	if !letGoCalled["b-1"] || !letGoCalled["b-2"] {
		t.Fatalf("letting go must actually end those tunnels: %v", letGoCalled)
	}
	if letGoCalled["a-1"] {
		t.Fatal("the attachment in the region it moved TO must be kept")
	}

	// ...and the coverage arithmetic must not mix the two. Before this, holding 3 nodes across two regions
	// against a one-region denominator of 2 printed "all 3 of the region's 2".
	if a.covered() {
		t.Fatalf("1 of region-a's 2 is not covered: %s", a.coverage())
	}
	if got := a.coverage(); !strings.Contains(got, "only 1 of the 2 Edge node(s) the deployment knows of") {
		t.Fatalf("coverage must count the region it is in: %q", got)
	}

	// The worker whose tunnel was cancelled releases it, and nothing else changes.
	a.release("b-1", 0)
	a.release("b-2", 0)
	if got := a.coverage(); !strings.Contains(got, "only 1 of the 2 Edge node(s) the deployment knows of") {
		t.Fatalf("after release: %q", got)
	}
}

// Re-declaring the same region is not a move, so a settled connector is not disturbed on every reconnect.
func TestDeclaringTheSameRegionAgainLetsGoOfNothing(t *testing.T) {
	a := newConnectorFleetAttachments()
	_, _ = a.claim("a-1", "region-a", func() { t.Fatal("a settled attachment must not be cancelled") })
	a.belongsTo("region-a")
	if letGo := a.belongsTo("region-a"); len(letGo) != 0 {
		t.Fatalf("expected nothing let go, got %v", letGo)
	}
	if letGo := a.belongsTo("  "); len(letGo) != 0 {
		t.Fatalf("an unnamed region says nothing and must move nothing, got %v", letGo)
	}
}

// ★ The denominator is how many Edge nodes have REPORTED, which is a floor and not a census. The line must
// never read as "there are exactly N": a node that has never reported is not counted and still accepts flows
// for everything this connector fronts.
func TestCoverageNeverPromisesACensus(t *testing.T) {
	a := newConnectorFleetAttachments()
	a.noteFleetSize(2)
	_, _ = a.claim("a-1", "region-a", nil)
	_, _ = a.claim("a-2", "region-a", nil)
	a.belongsTo("region-a")

	got := a.coverage()
	if !strings.Contains(got, "the deployment knows of") {
		t.Fatalf("the line must say where its denominator came from: %q", got)
	}
	if strings.Contains(got, "the region's") {
		t.Fatalf("phrasing that reads as a census of the region: %q", got)
	}
}

// ★★★ THE RACE THE DECLARATION CANNOT CLOSE, AND WHAT IT COST. The held set a worker declares is a snapshot
// taken before it dials, so two of this connector's own workers can still land on one node — and an Edge keeps
// ONE session per connector, so the newcomer's upgrade ends the incumbent's tunnel. Measured: the primary's
// tunnel was replaced two seconds after it formed, "did not hold", and the connector failed over — then out of
// the next region too, cycling the whole door list in two seconds, on evidence it had manufactured itself.
func TestASiblingDisplacementIsVisibleAndDoesNotStealTheClaim(t *testing.T) {
	a := newConnectorFleetAttachments()
	first, ok := a.claim("edge-a", "region-a", nil)
	if !ok {
		t.Fatal("the first worker holds it")
	}
	if a.stillHeldByAnother("edge-a", first) {
		t.Fatal("nobody has displaced this worker")
	}

	// The incumbent's tunnel ends (the Edge replaced it) and it releases. The displacer then claims.
	a.release("edge-a", first)
	second, ok := a.claim("edge-a", "region-a", nil)
	if !ok {
		t.Fatal("the displacing worker takes the node")
	}
	if !a.stillHeldByAnother("edge-a", first) {
		t.Fatal("the displaced worker must be able to see that a SIBLING holds this node — otherwise it reads " +
			"the end of its tunnel as the region failing and fails the whole connector over")
	}
	if a.stillHeldByAnother("edge-a", second) {
		t.Fatal("the holder is not displaced by itself")
	}

	// And a late release from the displaced worker must not delete the live claim.
	a.release("edge-a", first)
	if got := a.nodes(); len(got) != 1 || got[0] != "edge-a" {
		t.Fatalf("a displaced worker's release deleted the live attachment: %v", got)
	}

	// An unnamed node has no owner to compare, so it is never "held by another".
	if a.stillHeldByAnother("", 0) {
		t.Fatal("an unnamed node cannot be displaced")
	}
}
