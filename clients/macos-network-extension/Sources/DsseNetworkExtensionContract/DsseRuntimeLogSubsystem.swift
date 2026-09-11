import Foundation

// The subsystem every one of this agent's processes logs under.
//
// ★★★ IT IS DERIVED, BECAUSE A LITERAL HERE IS A NAME NO SHIPPED PRODUCT CARRIES. The source's placeholder
// is `example.dsse.agent`; a build sets its own bundle id (`DSSE_APP_BUNDLE_ID`), and the two have never
// matched in any distributed package. So the predicate an operator forms from the product's bundle id
// matches nothing, and the predicate the source suggests matches nothing either — which is exactly how
// "I checked the logs and there was nothing" became this project's most repeated wrong conclusion.
//
// One name covers both processes: the container app logs under its own bundle id, and the system extension —
// whose bundle id is that id plus `.networkextension` — logs under the container's, so a single predicate
// shows the agent and its provider interleaved. That is the order they have to be read in; separating them
// was never useful.
//
//     /usr/bin/log show --predicate 'subsystem == "<the app's bundle id>"' --info --last 1h
//
// `log` is a zsh builtin — the absolute path is not decoration.
public enum DsseRuntimeLogSubsystem {
    static let extensionSuffix = ".networkextension"
    static let fallback = "example.dsse.agent"

    /// The container app's bundle id, whichever process asks.
    public static let name: String = resolve(bundleIdentifier: Bundle.main.bundleIdentifier)

    static func resolve(bundleIdentifier: String?) -> String {
        guard let id = bundleIdentifier?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty else {
            return fallback
        }
        guard id.hasSuffix(extensionSuffix) else { return id }
        let container = String(id.dropLast(extensionSuffix.count))
        return container.isEmpty ? fallback : container
    }
}
