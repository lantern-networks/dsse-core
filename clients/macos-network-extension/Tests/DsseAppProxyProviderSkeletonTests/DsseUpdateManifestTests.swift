import Foundation
import XCTest
@testable import DsseAppProxyProviderSkeleton

// Cross-language fixture: the envelopes below were produced by the GO signer (agentupdate.Sign and
// agentpolicy.Sign, deterministic seed 0102..20), and are verified here by the SWIFT verifier.
//
// ★ This test is the thing the Step 1 design recorded as OUTSTANDING and it exists because the claim "the Swift
// verifier can be reused for update manifests" was not true when it was written: DsseSignedAgentPolicy
// hardcoded the steer-policy type, so no update manifest could be verified on macOS at all. A fixture is what
// keeps "the same crypto plus one type constant" honest — two independent implementations of one wire format
// drift silently, and the symptom would be a fleet refusing every manifest for a reason that reads as a key
// problem.
final class DsseUpdateManifestTests: XCTestCase {
    // The Go update-signing key (public half).
    private let updateKey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    private let manifest = Data("""
{"type":"dsse_agent_update_manifest.v1","version":"1","signing_key_id":"agent-update-65b60673d6ed884b","created_at":"2026-08-10T00:00:00Z","payload_sha256":"3533cf49dfb3bf05c850745fb51b1068d74e4b3e5b041697fd93aea68d740296","payload_b64":"eyJzY2hlbWEiOiIxIiwidmVyc2lvbiI6IjAuMy4wIiwicGxhdGZvcm0iOiJkYXJ3aW4iLCJhcmNoIjoiYXJtNjQiLCJjaGFubmVsIjoic3RhYmxlIiwiZGVsaXZlcnkiOiJkc3NlIiwiYXJ0aWZhY3Rfa2luZCI6InBrZyIsImFydGlmYWN0X3VybCI6Imh0dHBzOi8vcGFja2FnZXMuZXhhbXBsZS50ZXN0L2Rzc2UtYWdlbnQtMC4zLjAucGtnIiwiYXJ0aWZhY3Rfc2hhMjU2IjoiNmI4NmIyNzNmZjM0ZmNlMTlkNmI4MDRlZmY1YTNmNTc0N2FkYTRlYWEyMmYxZDQ5YzAxZTUyZGRiNzg3NWI0YiIsImFydGlmYWN0X3NpemUiOjQwOTYsIm1pbl9mcm9tX3ZlcnNpb24iOiIiLCJyZWxlYXNlZF9hdCI6IjIwMjYtMDgtMTBUMDA6MDA6MDBaIiwibm90X2FmdGVyIjoiMjAyNi0wOS0xMFQwMDowMDowMFoifQ==","signature":"ed25519:UBoJkqqJOmAJi1lj8Chk65czEvbxe0aQqGoSoNjoTLmtROnV0wFyQsxC6Mv3kBNqIfiM6AldshE3go4EQF_bCQ"}
""".utf8)
    // A STEER POLICY signed by the SAME key. Not a stray fixture: it is the attack the type check exists for.
    private let policySignedByTheSameKey = Data("""
{"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-08-10T00:00:00Z","payload_sha256":"1525467d92aecfb3a228360a98566e9d1bb344e367907dc4f3814655e9da3943","payload_b64":"eyJkZXZpY2VfaWRlbnRpdHkiOiJtYWMtZGV2LTEiLCJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmV4YW1wbGUudG9vbCJdLCJzY2hlbWFfdmVyc2lvbiI6ImRzc2VfYWdlbnRfc3RlZXJfcG9saWN5LnYxIiwidGVuYW50X2lkIjoidCJ9","signature":"ed25519:6Zwwn9sf6FbQBL0m22GUwANe_pbQdhrJd0gKlVAMunxNXjn2nOY-Pax8BCwU7_Zoaf1sjs_vxMBGp5f-GN9pDQ"}
""".utf8)

    // ★ THE FIXTURE THAT ACTUALLY TESTS THE TYPE CHECK: the manifest payload byte-for-byte, signed by the same
    // key, carried under the STEER POLICY type. Nothing about decoding can refuse this one — the body IS a
    // manifest — so the only thing standing between it and acceptance is `env.type`.
    //
    // It exists because the first version of this test used a real steer policy, and removing the type check
    // did not fail it: that payload simply does not decode as a manifest, so strict decoding was doing the work
    // and the type check was untested. A negative test that passes for a reason other than the one it names is
    // the failure this file was written to catch in the first place, one level up.
    private let manifestUnderThePolicyType = Data("""
{"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-08-10T00:00:00Z","payload_sha256":"3533cf49dfb3bf05c850745fb51b1068d74e4b3e5b041697fd93aea68d740296","payload_b64":"eyJzY2hlbWEiOiIxIiwidmVyc2lvbiI6IjAuMy4wIiwicGxhdGZvcm0iOiJkYXJ3aW4iLCJhcmNoIjoiYXJtNjQiLCJjaGFubmVsIjoic3RhYmxlIiwiZGVsaXZlcnkiOiJkc3NlIiwiYXJ0aWZhY3Rfa2luZCI6InBrZyIsImFydGlmYWN0X3VybCI6Imh0dHBzOi8vcGFja2FnZXMuZXhhbXBsZS50ZXN0L2Rzc2UtYWdlbnQtMC4zLjAucGtnIiwiYXJ0aWZhY3Rfc2hhMjU2IjoiNmI4NmIyNzNmZjM0ZmNlMTlkNmI4MDRlZmY1YTNmNTc0N2FkYTRlYWEyMmYxZDQ5YzAxZTUyZGRiNzg3NWI0YiIsImFydGlmYWN0X3NpemUiOjQwOTYsIm1pbl9mcm9tX3ZlcnNpb24iOiIiLCJyZWxlYXNlZF9hdCI6IjIwMjYtMDgtMTBUMDA6MDA6MDBaIiwibm90X2FmdGVyIjoiMjAyNi0wOS0xMFQwMDowMDowMFoifQ==","signature":"ed25519:UBoJkqqJOmAJi1lj8Chk65czEvbxe0aQqGoSoNjoTLmtROnV0wFyQsxC6Mv3kBNqIfiM6AldshE3go4EQF_bCQ"}
""".utf8)

    private let inWindow = ISO8601DateFormatter().date(from: "2026-08-15T00:00:00Z")!

    func testGoSignedManifestVerifiesInSwift() throws {
        let m = try XCTUnwrap(DsseUpdateManifest.verified(envelopeData: manifest,
                                                          pinnedUpdateKeysHex: [updateKey], now: inWindow),
                              "the Go-signed manifest did not verify — the two implementations have drifted")
        XCTAssertEqual(m.version, "0.3.0")
        XCTAssertEqual(m.platform, "darwin")
        XCTAssertEqual(m.arch, "arm64")
        XCTAssertEqual(m.artifactKind, "pkg")
        XCTAssertEqual(m.artifactSize, 4096)
        XCTAssertEqual(m.artifactSHA256, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b")
    }

    // ★ THE ONE THAT MATTERS. A steer policy signed by the same key is cryptographically perfect and is not an
    // update manifest. Without the type check every signature test here would still pass and the device would
    // accept the wrong document as an authorisation to run code.
    func testAValidlySignedSteerPolicyIsNotAnUpdateManifest() {
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: policySignedByTheSameKey,
                                                 pinnedUpdateKeysHex: [updateKey], now: inWindow),
                     "a steer policy was accepted as an update manifest; the type check is the only thing "
                     + "standing between one signing key and a substituted document")
    }

    // The real cross-type test. Same key, same payload, wrong label.
    func testAManifestBodyCarriedUnderAnotherTypeIsRefused() {
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: manifestUnderThePolicyType,
                                                 pinnedUpdateKeysHex: [updateKey], now: inWindow),
                     "a manifest body under the steer-policy type was accepted; the type check is the only "
                     + "thing that can refuse it, and one signing key legitimately signs both documents")
    }

    func testAnUnpinnedKeyIsRefused() {
        let other = String(repeating: "ab", count: 32)
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: manifest,
                                                 pinnedUpdateKeysHex: [other], now: inWindow))
    }

    func testNoPinnedKeyIsRefusedRatherThanAccepted() {
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: manifest, pinnedUpdateKeysHex: [], now: inWindow),
                     "a device with no pinned key accepted a manifest; a verifier with no keys that accepts "
                     + "anything is worse than no verifier, because it looks like one")
    }

    // Replay is what a signature alone does not stop: this manifest was legitimately signed and its window has
    // closed. Enforced in the verifier rather than left to the caller, because a caller that forgets produces
    // a device that accepts an indefinitely old authorisation to run code.
    func testAnExpiredManifestIsRefused() {
        let afterWindow = ISO8601DateFormatter().date(from: "2026-10-01T00:00:00Z")!
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: manifest,
                                                 pinnedUpdateKeysHex: [updateKey], now: afterWindow))
    }

    func testATamperedPayloadIsRefused() {
        var bytes = manifest
        // Flip one byte of the base64 payload: the checksum and the signature both stop matching.
        if let r = String(data: bytes, encoding: .utf8)?.replacingOccurrences(of: "\"payload_b64\":\"e", with: "\"payload_b64\":\"f") {
            bytes = Data(r.utf8)
        }
        XCTAssertNil(DsseUpdateManifest.verified(envelopeData: bytes, pinnedUpdateKeysHex: [updateKey], now: inWindow))
    }

    // The type constant must equal the Go one. Cheap, and it is the string that silently breaks a fleet.
    func testTheEnvelopeTypeMatchesTheGoConstant() {
        XCTAssertEqual(DsseUpdateManifest.envelopeType, "dsse_agent_update_manifest.v1")
    }
}
