import Foundation

/// Credential-free routing policy, shared with local policy tests.
enum FirebaseRegion {
    static func projectID(for region: String) -> String? {
        switch region {
        case "CA": return "crossiva-dev-ca"
        case "US": return "crossiva-dev-us"
        case "IN": return "crossiva-dev-in"
        default: return nil
        }
    }
    static func appName(for region: String) -> String? {
        switch region {
        case "CA": return "__FIRAPP_DEFAULT"
        case "US": return "CrossivaUS"
        case "IN": return "CrossivaIN"
        default: return nil
        }
    }
    static func forCountry(_ country: String) -> String {
        switch country.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "canada", "ca": return "CA"
        case "india", "in": return "IN"
        default: return "US"
        }
    }
}
