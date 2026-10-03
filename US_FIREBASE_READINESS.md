# Crossiva US Firebase verification — 2026-10-03

## Authenticated verification completed

After user login, project access verified. Existing Android registration verified
against its real SDK configuration: package com.singheverything.crossiva,
app ID 1:829146500278:android:377c25e7dc21e74bddea17.
No Apple registration existed; registered Crossiva macOS US with bundle
com.singheverything.crossiva. New app ID:
1:829146500278:ios:834bf4ac135c16abddea17.

Both SDK configs downloaded separately into ignored .firebase/us-secondary:
google-services-us.json and GoogleService-Info-US.plist (permissions 0600).
Project ID crossiva-dev-us, sender/project number 829146500278, configured bucket
crossiva-dev-us.firebasestorage.app. Both contain real API keys retained only in
private config files; no API key printed. Android/Apple app IDs are distinct.
Neither Canadian default config was overwritten; both default paths are currently
absent from the working tree. No runtime source/config wiring performed.

Anonymous Auth is enabled. Email/password and phone are disabled. No enabled
default federated, custom OIDC or SAML providers returned by the authenticated
configuration reads. autodeleteAnonymousUsers is absent (not enabled/default
false); no cleanup or provider settings changed. Read using the official Firebase
CLI's authenticated configuration client; no Auth configuration-read MCP tool exists.

Firestore database (default) exists: STANDARD, FIRESTORE_NATIVE, location nam5.
Published rules retrieved through the official MCP read-only handler: all document
reads/writes denied with `allow read, write: if false;`. These are locked, not test
mode. Crossiva clients cannot pair/sync through them until a separately reviewed
membership rules deployment is explicitly authorized. No rules deployed or weakened.

The standalone MCP server did not accept --project; used its official read-only
rules handler with explicit project context instead. No firebase use/default alias
change, IAM mutation, production modification, private-key generation or deployment.
Only remote mutation: the requested missing US Apple app registration.

No manual Console action is needed for US app registration or Anonymous Auth.
Remaining work: Canada-default source migration and Canadian config prerequisites;
review membership rules adapted for CA issuer and authorize deployment separately.
Historical unauthenticated observations below are superseded by this section.

Target: crossiva-dev-us. Canada crossiva-dev-ca remains the default FirebaseApp
and shared Android FCM issuer. US and India are named secondary Auth/Firestore
apps. This supersedes the earlier India-default plan in CROSSIVA_MIGRATION.md;
the code has NOT yet been updated to the Canada model in this verification pass.

## Evidence

Firebase agent skills installed globally for Codex and verified with skills list.
Applied firebase-basics, firebase-auth-basics and firebase-firestore guidance.
Firebase CLI 15.32.1 is available through npx. Read-only apps:list targeting
crossiva-dev-us failed: "Failed to authenticate, have you run firebase login?"
No usable authenticated project access or Firebase MCP tools were available in
this session. No remote state can therefore be certified.

Project existence/access, Android/Apple registrations, Anonymous Auth, cleanup
setting, database existence/location/edition and deployed rules are UNVERIFIED.
No app registration, provider change, rules publication, deployment, IAM change
or service-account private-key generation was performed. No runtime source edits,
Canadian default config replacement, UI change or Git staging/commit performed.

## Next authenticated read-only commands

Authenticate in a local terminal; do not send tokens:

```sh
npx -y firebase-tools@latest login
npx -y firebase-tools@latest apps:list --project crossiva-dev-us
npx -y firebase-tools@latest firestore:databases:list --project crossiva-dev-us
npx -y firebase-tools@latest firestore:databases:get '(default)' --project crossiva-dev-us
```

Select the actual database returned by list if it differs; do not create one or
change project defaults. Verify the two registrations match
com.singheverything.crossiva. Firebase Apple apps are listed as IOS even for a
macOS client. Android and Apple Firebase app IDs are different; neither is the
package/bundle ID. Obtain their actual app IDs from apps:list, then use CLI's
supported --out option to avoid displaying API keys:

```sh
umask 077
mkdir -p /private/tmp/crossiva-us-configs
npx -y firebase-tools@latest apps:sdkconfig ANDROID "$US_ANDROID_APP_ID" --project crossiva-dev-us --out /private/tmp/crossiva-us-configs/google-services-us.json
npx -y firebase-tools@latest apps:sdkconfig IOS "$US_APPLE_APP_ID" --project crossiva-dev-us --out /private/tmp/crossiva-us-configs/GoogleService-Info-US.plist
```

The shell variables must contain actual listed app IDs, not invented values.
These files are secondary-options input only. NEVER copy the US files over
android/app/google-services.json or mac/ClipSync/GoogleService-Info.plist: those
default filenames are reserved for Canadian registrations. No files downloaded
by this pass. Do not place raw US config exports in tracked paths.

## Real secondary option values

| Option | Android US JSON source | Apple US plist source | Current value |
|---|---|---|---|
| project ID | project_info.project_id | PROJECT_ID | crossiva-dev-us supplied by user; not remotely verified |
| application/google app ID | matching client's client_info.mobilesdk_app_id | GOOGLE_APP_ID | unknown |
| API key | matching client's api_key[].current_key | API_KEY | unknown; retain privately |
| sender ID | project_info.project_number | GCM_SENDER_ID | unknown |
| bucket, if configured | project_info.storage_bucket | STORAGE_BUCKET | unknown; omit if absent |
| package/bundle | client_info.android_client_info.package_name | BUNDLE_ID | expected com.singheverything.crossiva; unverified |

Do not derive a bucket name from the project ID or manufacture an app ID.
Use setGcmSenderId in Android options and googleAppID/gcmSenderID plus projectID,
apiKey and matching bundleID in Apple options. These US sender metadata values do
not authorize US Messaging initialization or replacing Canada's push issuer.
Configure named US app; Auth/Firestore APIs must reference that specific app.

## Manual Console verification if authenticated tools remain unavailable

Open https://console.firebase.google.com/project/crossiva-dev-us/overview and
confirm project identity/access before any action.

- Project settings (gear) -> General -> Your apps: verify Android package and
  Apple bundle com.singheverything.crossiva. If absent, registration is a pending
  setup action; verify existing registrations before creating duplicates.
- Authentication -> Sign-in method -> Anonymous: verify enabled. All other
  providers must remain disabled. Do not follow generic skills' Google/email
  examples. Anonymous provider settings: automatic cleanup must be disabled;
  if Identity Platform has not been enabled, record that cleanup option's absence
  rather than upgrade the project. Do not delete accounts.
- Firestore Database: record database ID, location, edition and existence.
  Rules tab: inspect actual published rules. Verify unauthenticated/non-member
  access is denied, UID membership is enforced and secrets cannot be stored.
  A historical "production mode" label is not proof of current deployed rules.
  Do not publish or weaken rules. If missing, database creation/location/rule
  deployment requires a separately reviewed setup step; this pass does not do it.
- Project settings -> General -> Your apps -> select each registration: its
  config file contains the fields above. CLI retrieval remains the preferred
  method once authenticated; Console retrieval is a manual fallback.

No changes to other providers, production resources or rules were performed.

## Files requiring a subsequent Canada-default implementation pass

- Android FcmTokenPolicy.kt: add CA Auth project; push issuer pinned to CA.
- Android CloudAuth.kt: Canadian default; named US and IN apps; no default fallbacks
  for region mismatch. RegionConfig.kt (missing) supplies real regional options.
- Android ClipSyncApp.kt, DeviceManager.kt, FirestoreManager.kt,
  FCMTokenManager.kt and region selection helpers/callers: keep selected regional
  identity/database while token retrieval remains default Canada Messaging.
- Mac ProductIdentity.swift and RegionConfig.swift (missing): three-region mapping.
- Mac FirebaseManager.swift: initialize Canada as default once; US/IN as named
  secondary apps; bind Auth and Firestore explicitly to selected regional app.
  Current code configures the selected region as default, contrary to new policy.
- Mac FCMTokenManager.swift and QRCodeGenerator.swift: verify issuer metadata and
  selected regional UID/QR identity. Do not initialize US Messaging. Mac routing
  must be checked against the Canada-default model rather than assume the old
  regional Mac issuer design remains correct.
- functions/routing.js and firebase/firestore.rules: allow CA/US/IN Auth context;
  Android issuer must be CA. US wake-up routing, if used, sends through CA with the
  actual authorized runtime identity, never guessed private-key credentials.
- Related Android, Functions and Firestore tests, templates and migration docs:
  replace outdated India-default expectations and add CA/US/IN cases.

Actual runtime destinations remain Android
android/app/src/main/java/com/singheverything/crossiva/RegionConfig.kt and Mac
mac/ClipSync/RegionConfig.swift. Missing Canadian default configs are a separate
prerequisite; US exports cannot substitute for them.

Official references:
https://firebase.google.com/docs/projects/multiprojects
https://firebase.google.com/docs/auth/android/anonymous-auth
https://firebase.google.com/docs/firestore/security/get-started
https://support.google.com/firebase/answer/7015592
