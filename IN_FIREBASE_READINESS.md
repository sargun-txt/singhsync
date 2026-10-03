## Reverification — 2026-10-03

These read-only results supersede the earlier provisioning blockers below.

- Project access confirmed for `crossiva-dev-in`.
- Anonymous Auth enabled; email/password and phone disabled; no enabled federated, OIDC, or SAML providers.
- Automatic anonymous cleanup disabled: `autodeleteAnonymousUsers` omitted/default false.
- `(default)` Firestore exists: `STANDARD`, `FIRESTORE_NATIVE`, location `nam5` (US multi-region, not India).
- Published rules retrieved: recursive deny-all (`allow read, write: if false`). Locked, but Crossiva cloud pairing/sync remains blocked until a separately authorized reviewed rules deployment.
- Existing India secondary config files remain separate and unchanged.
- No remote settings, resources, rules, or deployments changed during this reverification.

# Crossiva India Firebase verification — 2026-10-03

Applied installed Firebase basics, Auth, Firestore and rules-auditor skills.
Target crossiva-dev-in only. Canada crossiva-dev-ca must remain default FirebaseApp
and shared Android FCM issuer. No runtime source changes in this verification pass.

## Verified and collected

Project access verified through authenticated apps:list. No registrations existed.
Registered both requested development apps with com.singheverything.crossiva:

- Android Crossiva Android IN:
  1:372513932946:android:ac583d43d573c75f87c84b.
- Apple/macOS Crossiva macOS IN:
  1:372513932946:ios:fb567378523d344487c84b.

Real SDK configs downloaded separately, gitignored and chmod 0600:

- .firebase/in-secondary/google-services-in.json
- .firebase/in-secondary/GoogleService-Info-IN.plist

Project ID crossiva-dev-in. Project number/gcmSenderId 372513932946.
Both configs declare storageBucket crossiva-dev-in.firebasestorage.app; bucket
existence/access was not tested. API keys are present and retained only in these
private files; not printed. Android JSON client package and Apple BUNDLE_ID match
com.singheverything.crossiva. Platform Firebase app IDs are distinct.

Android options use project_info.project_id/project_number/storage_bucket and the
matching client's client_info.mobilesdk_app_id/api_key[].current_key. Apple options
use PROJECT_ID/GOOGLE_APP_ID/API_KEY/GCM_SENDER_ID/STORAGE_BUCKET/BUNDLE_ID.
These India sender fields are configuration metadata, not permission to initialize
India Messaging or replace Canada's shared issuer.

## Provisioning blockers

- Auth configuration read returned HTTP 404 CONFIGURATION_NOT_FOUND. Anonymous
  enablement, other-provider state and cleanup setting cannot be certified; Auth
  appears not initialized. No Auth settings changed.
- Firestore database list returned HTTP 403: Firestore API disabled or never used.
  Database existence, mode/edition and location are therefore NOT VERIFIED.
- Official Firebase MCP read-only rules handler found no active Firestore rules.
  No rules changed or deployed. Do not assume a locked usable database exists.

## Manual Console actions

In crossiva-dev-in only:

1. Authentication -> Get started -> Sign-in method -> Anonymous: initialize Auth
   and enable Anonymous only. Leave email/password, Google, Apple, phone and all
   other providers disabled. Leave automatic anonymous cleanup disabled; do not
   upgrade Identity Platform just to expose a cleanup option.
2. Firestore Database: confirm whether setup exists. If absent, review database
   location/edition before creating it. Crossiva currently uses Native Firestore
   SDK behavior; choose Standard/Native with production/locked initial rules.
   Location must be explicitly selected, not guessed by the agent.
3. Firestore API availability must be resolved before database metadata can be
   verified. A newly enabled API may require propagation time.
4. Re-run authenticated checks. Later, separately approve deployment of reviewed
   membership rules adapted to the Canada issuer; initial deny-all rules cannot
   support pairing/sync. Do not weaken rules or deploy automatically.

No additional app registration or manual config download is required.

## Code changes still needed

The earlier migration still has India-default assumptions. Subsequent implementation
must update Android FcmTokenPolicy/CloudAuth/RegionConfig and regional selection:
Canada default, named US and India apps for regional Auth/Firestore, default Canada
Messaging only. Mac ProductIdentity/RegionConfig/FirebaseManager must keep Canada
default and bind regional Auth/Firestore to named apps. Token registration, QR UID
selection, Functions routing, Firestore project allowlists and associated tests
must follow the same CA/US/IN model. See US_FIREBASE_READINESS.md for detailed list.

Canadian default paths android/app/google-services.json and
mac/ClipSync/GoogleService-Info.plist were not replaced. India exports are inputs
for programmatic secondary options, not default config substitutes.

No default-project switch, provider mutation, API enablement, database creation,
rule publication, deployment, production-resource modification, IAM grant,
service-account key generation, Git staging/commit or UI change performed.
Only remote mutations were the two explicitly requested India app registrations.
