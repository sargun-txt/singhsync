# Canada primary Firebase readiness

Verified read-only on 2026-10-03 for `crossiva-dev-ca`.

## Remote status

- Project access confirmed.
- Existing Android registration: `com.singheverything.crossiva`; Firebase app ID `1:396960243483:android:15f1549586b8ee8cd6bdbe`.
- Existing Apple/macOS registration: `com.singheverything.crossiva`; Firebase app ID `1:396960243483:ios:3ef2e83549a84defd6bdbe`.
- Anonymous Auth enabled; email/password and phone disabled; no enabled federated, OIDC, or SAML providers.
- Automatic anonymous cleanup disabled (`autodeleteAnonymousUsers` omitted/default false).
- `(default)` Firestore: `STANDARD`, `FIRESTORE_NATIVE`, location `northamerica-northeast2` (Toronto).
- Published rules are recursive deny-all (`allow read, write: if false`). No cloud pairing/sync can work under these rules; deployment of reviewed membership rules requires separate authorization.

## Real config storage

Downloaded from the existing registrations, validated project/package/bundle IDs and nonempty API keys:

- `.firebase/ca-primary/google-services.json`
- `.firebase/ca-primary/GoogleService-Info.plist`
- `.firebase/ca-primary/firestore.published.rules` (read-only snapshot)

Directory permissions 0700; files 0600; all gitignored. API keys are contained only in private config files, not this report.
Project number / GCM sender ID: `396960243483`.
Configured storage bucket: `crossiva-dev-ca.firebasestorage.app` (bucket access/existence not separately verified).

## Upcoming implementation

Canada must become the default FirebaseApp and shared Android FCM issuer. US/India remain named secondary apps for Auth/Firestore only. This is the required target architecture, not yet the current source behavior.

Future default file destinations:
- `android/app/google-services.json`
- `mac/ClipSync/GoogleService-Info.plist`

Runtime migration still needs Android `CloudAuth.kt`, `FcmTokenPolicy.kt`, regional options/token routing, Mac `FirebaseManager.swift`, `RegionConfig.swift`, `ProductIdentity.swift`, regional Auth/Firestore consumers, Functions routing, and rule issuer/project checks with associated tests/templates. This pass does not change runtime wiring or default files.

No registrations created, remote settings modified, APIs enabled, resources provisioned, rules deployed, service-account private keys generated, or production resources changed. No deployment performed.
