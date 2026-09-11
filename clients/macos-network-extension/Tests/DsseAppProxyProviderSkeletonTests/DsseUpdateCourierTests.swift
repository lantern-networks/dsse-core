import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

// The courier's decisions, exercised without a network: what it writes, what it refuses, and above all what it
// never removes.
final class DsseUpdateCourierTests: XCTestCase {
    private func tempPath(_ name: String) -> String {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + "-" + name).path
    }

    // ★ NOTHING IN THIS FILE DELETES, and it is asserted as an absence because that is how the Windows side's
    // first version went wrong. On the Edge a manifest is a file in a directory, so "withdrawn", "never
    // published" and "the operator pointed at the wrong path" are all one 404 — clearing on it lets a single
    // misconfiguration disarm the update path across a fleet, in the direction that looks healthy.
    //
    // For the PLAN it is worse: an absent plan falls back to an UNFROZEN default, so a courier that deleted on
    // a transient failure would lift an operator's halt.
    func testTheCourierHasNoDeletePath() throws {
        let source = try XCTUnwrap(courierSource())
        for forbidden in ["removeItem", "unlinkItem"] {
            XCTAssertFalse(source.contains(forbidden),
                           "the courier contains \(forbidden); no response may remove a couriered document — "
                           + "an absent plan falls back to an unfrozen default, so a delete lifts a freeze")
        }
    }

    // The write must be atomic. The updater re-reads these files on its own schedule with no coordination, and
    // a torn read of the manifest is not a retry — it is ErrManifestRejected, which by the updater's design
    // means "artefacts are being substituted, look tonight". Torn writes manufacture security alarms.
    func testTheWriteIsAtomicAndCreatesItsDirectory() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let path = dir.appendingPathComponent("nested/update-manifest.json").path
        let payload = Data("{\"type\":\"x\"}".utf8)

        XCTAssertTrue(DsseUpdateCourier.writeAtomically(payload, to: path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), payload)

        // Overwriting leaves the file complete, never truncated-then-filled.
        let second = Data("{\"type\":\"y\",\"more\":true}".utf8)
        XCTAssertTrue(DsseUpdateCourier.writeAtomically(second, to: path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), second)
    }

    // The paths are a contract with clients/macos/updateplatform. Asserted so a move has to be a deliberate
    // edit on both sides rather than a silent one here.
    func testThePathsAreTheOnesTheUpdaterReads() {
        XCTAssertEqual(DsseUpdateCourier.manifestPath, "/Library/Application Support/Dsse/update-manifest.json")
        XCTAssertEqual(DsseUpdateCourier.planPath, "/Library/Application Support/Dsse/update-plan.json")
    }

    // ★ The plan's envelope type must NOT be the steer policy's. It borrowed that type at first, and while the
    // payload's schema field would still have caught a substitution, that left the type check doing no work on
    // the one document whose purpose is to carry a freeze.
    func testThePlanAndTheManifestHaveDistinctEnvelopeTypes() {
        XCTAssertEqual(DsseUpdateManifest.envelopeType, "dsse_agent_update_manifest.v1")
        XCTAssertEqual(DsseRolloutPlan.envelopeType, "dsse_agent_update_plan.v1")
        XCTAssertNotEqual(DsseRolloutPlan.envelopeType, DsseSignedAgentPolicy.envelopeType,
                          "the plan is signed by the same key as the steer policy; if they share an envelope "
                          + "type nothing distinguishes a freeze from an exclusion set")
    }

    // The arch asked for is what this BINARY is, not what the machine could run: a translated x86_64 build
    // asking for arm64 would be handed a package it cannot install.
    func testTheArchIsTheBinarysOwn() {
        #if arch(arm64)
        XCTAssertEqual(DsseUpdateCourier.currentArch, "arm64")
        #else
        XCTAssertEqual(DsseUpdateCourier.currentArch, "amd64")
        #endif
    }

    private func courierSource() -> String? {
        // Read the implementation from the package source tree so the assertion is about the shipped file.
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("Sources/DsseAppProxyProviderSkeleton/DsseUpdateCourier.swift")
        return try? String(contentsOf: path, encoding: .utf8)
    }
}

// ★ The installer's stash key and the updater's lookup key must be the SAME string, and this is where that is
// pinned on this platform.
//
// The postinstall script asks the just-installed binary (`DsseAgent --version`), and the updater looks material
// up under the version the LIVE extension recorded in its runtime marker. Both are
// DsseDeviceHeartbeat.agentVersion(). If they ever diverge the symptom is ErrNoMaterial on every device
// forever — an updater refusing every update while looking correct, on a fleet where all the code is present
// and running — so the shape is asserted rather than assumed.
extension DsseUpdateCourierTests {
    func testTheVersionKeyIsUsableAsAFilenameAndComesFromOnePlace() {
        let v = DsseDeviceHeartbeat.agentVersion()
        XCTAssertFalse(v.isEmpty, "the agent version is empty; the installer would store rollback material "
                       + "under a name no lookup can produce")
        // The Go side's rollbackstore.FileName refuses anything outside this set, because the version reaches a
        // filesystem path and arrives from a signed manifest — a traversal must never become one.
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+-_")
        XCTAssertTrue(v.unicodeScalars.allSatisfy { allowed.contains($0) },
                      "agentVersion() produced \(v), which rollbackstore.FileName would refuse — the installer "
                      + "would then store nothing and every update would refuse for lack of rollback material")
        XCTAssertFalse(v.hasPrefix("."), "a leading dot is refused by the store's name rules")
        XCTAssertFalse(v.hasPrefix("-"), "a leading hyphen is refused by the store's name rules")
    }
}

// ★★ "IT PARSED AS JSON" WAS NOT A CHECK (2026-08-13, thirtieth review #13). The unsigned form the courier
// accepts is a ROLLOUT PLAN, served bare by an Edge with no agent-policy signer. Accepting any JSON meant a
// proxy's error page — or an envelope whose signature was missing — was written over a plan this device had
// verified, and on a signed deployment the updater answers ErrPlanUnverifiable, which is a FREEZE. One
// mis-routed response stopped updates on this platform.
final class DsseUpdateCourierUnsignedFormTests: XCTestCase {
    func testTheBarePlanAnUnsignedEdgeServesIsAccepted() {
        let body = Data(#"{"schema_version":"dsse.agent-update-plan.v1","frozen":false}"#.utf8)
        XCTAssertTrue(DsseUpdateCourier.namesItself(body, schema: DsseRolloutPlan.schemaVersion))
    }

    func testAnErrorPageIsNotAPlanEvenWhenItIsValidJSON() {
        for body in [
            #"{"error":"forbidden","code":403}"#,           // a proxy or portal answering 200 with JSON
            #"{"type":"dsse_steer_policy.v1","payload":""}"#, // an envelope for another document, unsigned
            #"[]"#,                                          // valid JSON, not an object
            #"{"schema_version":"dsse.agent-update-manifest.v1"}"#, // the right shape, the wrong document
        ] {
            XCTAssertFalse(DsseUpdateCourier.namesItself(Data(body.utf8), schema: DsseRolloutPlan.schemaVersion),
                           "accepted \(body) as an unsigned plan — it would overwrite a verified one and freeze this device")
        }
    }

    // ★ AND A DIFFERENT ENDPOINT ASKS FOR ITS OWN SCHEMA, which is the point of passing the name rather than a
    // flag: the manifest's unsigned form, if one ever existed, would not be satisfied by a rollout plan.
    func testTheExpectedSchemaIsTheCallersNotThisFunctions() {
        let plan = Data(#"{"schema_version":"dsse.agent-update-plan.v1"}"#.utf8)
        XCTAssertFalse(DsseUpdateCourier.namesItself(plan, schema: "dsse.agent-update-manifest.v1"),
                       "a rollout plan satisfied a caller expecting a different document")
    }

    // The constant has to equal agentupdate.RolloutPlanSchema, or every unsigned Edge stops being able to
    // deliver a plan to a Mac and nothing says why.
    func testTheSchemaMatchesTheOneTheEdgeSends() {
        XCTAssertEqual(DsseRolloutPlan.schemaVersion, "dsse.agent-update-plan.v1")
    }
}

// ★★ THE STAGED NAME IS A CONTRACT WITH THE UPDATER (2026-08-13). updateplatform.StagedPath asks
// rollbackstore for "dsse-agent-<version>.pkg" and looks nowhere else, so a courier writing any other name
// would download the package on every pass and install nothing — silently, for ever. And the version arrives
// from the network, so it must never be able to become a path.
final class DsseUpdateCourierStagedNameTests: XCTestCase {
    func testItMatchesTheNameTheUpdaterLooksFor() {
        XCTAssertEqual(DsseUpdateCourier.stagedFileName(forVersion: "0.2.1+3f8f2b02"),
                       "dsse-agent-0.2.1+3f8f2b02.pkg")
    }

    func testAVersionThatCouldBecomeAPathIsRefusedRatherThanRepaired() {
        for hostile in ["../../etc/cron.d/x", "0.2.1/../../x", "", ".hidden", "-flag", "a b", "0.2.1\u{0000}"] {
            XCTAssertNil(DsseUpdateCourier.stagedFileName(forVersion: hostile),
                         "accepted \(hostile) — a name that had to be repaired is a name nobody meant")
        }
    }

    func testAnAbsurdlyLongVersionIsRefused() {
        XCTAssertNil(DsseUpdateCourier.stagedFileName(forVersion: String(repeating: "9", count: 500)))
    }
}

// ★★ AN UP-TO-DATE DEVICE MUST NOT RE-DOWNLOAD ITS OWN PACKAGE (2026-08-13, found by win-dev-1 while writing
// the Windows twin). This courier runs on the manifest's refresh interval, so without a check a device that is
// already staged pulled tens of megabytes every fifteen minutes, for ever, off the Edge's uplink — the fleet
// paying for its own idleness, and nothing about it would have looked wrong in a log.
//
// These exercise the DECISION, not the network: alreadyStaged reads the couriered manifest as a hint and
// compares the size on disk. Whether the bytes are RIGHT is the updater's question, asked with a digest.
final class DsseUpdateCourierStagedSkipTests: XCTestCase {
    // Nothing on disk at all: there is a manifest path that does not exist, and "cannot tell" must not skip.
    func testWithNoManifestItDoesNotSkip() {
        XCTAssertFalse(DsseUpdateCourier.alreadyStaged(),
                       "a device that cannot read its manifest skipped the fetch — cannot-tell is not up-to-date")
    }

    // A size that cannot be established must not be read as a match, or a truncated staged file would be kept
    // for ever and the updater would refuse it on every pass with nothing re-fetching it.
    func testAZeroSizeIsNotAMatch() {
        let dir = NSTemporaryDirectory() + "dsse-skip-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let staged = dir + "/dsse-agent-1.2.3.pkg"
        FileManager.default.createFile(atPath: staged, contents: Data())
        let attrs = try? FileManager.default.attributesOfItem(atPath: staged)
        XCTAssertEqual((attrs?[.size] as? NSNumber)?.int64Value, 0,
                       "fixture: the staged file should be empty, so a zero declared size must not match it")
    }
}
