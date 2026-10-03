# ClipSync live validation — 2026-10-02

## Xcode/config recheck — 2026-10-03

Full Xcode blocker cleared: active developer directory is
/Applications/Xcode.app/Contents/Developer; Xcode 27.0 (27A266a) responds.
Ignored-file-inclusive searches of the repository still found none of the four
required real config files. The two RegionConfig examples exist; no Firebase
JSON/plist template or region-specific plist was found. No build attempted under
this phase because configs are missing. Earlier no-Xcode observations below are
historical, not current blockers. Shared ClipSync scheme targets ClipSync.app;
project also contains ClipSyncShare extension target. xcodebuild -list completed
successfully after package resolution, listing ClipSync and ClipSyncShare as both
schemes and targets, with Debug/Release configurations. Firebase resolved to
12.19.2; this is dependency resolution evidence, not build compatibility evidence.
The main synchronized
ClipSync folder owns source/resources; no explicit GoogleService-Info.plist entry
is present in project.pbxproj. Place the India plist in mac/ClipSync and confirm
its inclusion in the built app bundle once build inputs are restored.

## Local-only continuation — 2026-10-03

User confirmed no approved non-production Firebase project and no real regional
config paths/IDs are available. No deployment, cloud-project creation or project
configuration is authorized. `demo-clipsync` is solely an offline emulator
namespace, not an invented/configured Firebase project. Deployment/signing
commands below are documentation only and must not be executed under this scope.

Fresh local results: Functions 13/13; Firestore emulator 21/21; Android standalone
JVM CloudPairingAuth/FcmTokenPolicy suites 23/23 (cached Kotlin compiler/JUnit,
actual sources, no Firebase configs or stubs); Mac production Swift parse 43/43;
Mac policy checks
345/345 (three ad-hoc signing fixture checks omitted in temporary test copies,
two Developer ID checks skipped). Three protocol fixtures regenerated in a
temporary directory and matched repository bytes. No real app signing performed.
Mac policy tests use real protocol/policy sources, not Firebase stubs; they still
do not constitute an application build. Temporary npm dependencies warned that
Node 25 is outside one dependency's supported 20/22/24 range; emulator tests passed
using JBR 21. Use Node 24 for future reproducible deployment validation.

### Inputs checklist (paths/metadata only; do not paste secrets)

- Confirm approved existing India and US project IDs. Code currently expects
  clipsyncind and clipsync1-c3c3c; these are source expectations, not independently
  verified deployment IDs or approved rehearsal environments.
- Android default India file: android/app/google-services.json; registered package
  com.bunty.clipsync; actual project_id, project_number and mobilesdk_app_id.
- Android US file: android/app/src/main/java/com/bunty/clipsync/RegionConfig.kt;
  matching US Android registration/options. Provide secure source path for real
  values, including API key/storage bucket, without printing them.
- Mac default India file: mac/ClipSync/GoogleService-Info.plist; registered bundle
  com.OP.ClipSync; actual PROJECT_ID, GOOGLE_APP_ID and GCM_SENDER_ID.
- Mac regional implementation: mac/ClipSync/RegionConfig.swift; actual US options,
  plus getOptimalServer(for:) and sortedCountryNames required by current source.
- Both deployed Functions: actual project/location/name, runtime service account,
  issuer environment metadata and authenticated read access. Never guess an email.
- A separately approved existing test-project ID and saved prior rules/functions
  artifacts are needed before any deployment rehearsal can be reconsidered.
- Full Xcode and a physical Android phone are required for real app/device checks.

Live Firebase/device validation remains BLOCKED. Prior placeholder assembly is
local regression evidence only. No placeholder config used in this continuation.
Full Android Gradle suite was not rerun: application compilation requires the
missing regional config implementation. Direct compilation of all protocol suites
also requires app-integrated ClipSyncSender/WakeupPing dependencies; the isolated
23-test subset above passed. Mac policy suites exercised TCP/BLE vectors locally.
This pass does not replace the historical 69/69 full Android regression result.

Status: BLOCKED. Existing uncommitted implementation preserved. No staging,
commit, push, cloud deployment, IAM change, release signing or notarization performed.

## Observed environment

- Active developer directory: `/Library/Developer/CommandLineTools`; xcodebuild
  reports that full Xcode is required. No Xcode in /Applications or ~/Applications.
  Mac package resolution/build/run stopped here. Stub checks are not builds.
- Java: Temurin 25.0.1; JBR 21.0.11 also installed. Node 25.2.1/npm 11.6.2.
  Functions declare Node 24; use Node 24 for deployment validation.
- Android SDK: ~/Library/Android/sdk, platforms 33, 34, 36, 37.0.
- ADB 36.0.0 available by absolute path. Elevated read-only device check sees
  emulator-5554 only, no physical phone. No APK installed by this pass.
- security find-identity: zero valid code-signing identities.
- firebase/gcloud absent from PATH and checked Homebrew, /usr/local and
  ~/google-cloud-sdk locations. Runtime service account cannot be determined here.
- git diff --check passes; index empty. Function routing tests rerun: 13/13 pass.
- Earlier Android 69/69 and placeholder assemble, rules emulator 21/21 and Mac
  stub checks remain historical regression evidence, not real-build evidence.

## Required real configuration

Absent: android/app/google-services.json,
android/app/src/main/java/com/bunty/clipsync/RegionConfig.kt,
mac/ClipSync/RegionConfig.swift and Mac GoogleService-Info.plist.
Do not copy the example placeholder values for this validation.

| Client | Auth/Firestore project | Messaging issuer |
|---|---|---|
| Android IN | clipsyncind/default app | clipsyncind/default app |
| Android US | clipsync1-c3c3c/named ClipSyncUS | clipsyncind/default app |
| Mac IN | clipsyncind/default configured app | same regional app |
| Mac US | clipsync1-c3c3c/default configured app | same regional app |

Android India JSON must register com.bunty.clipsync. Read actual project_number
(sender ID) and mobilesdk_app_id from it without logging API keys/tokens. Real
RegionConfig.kt must supply the US project's Android application ID, API key,
project ID and storage bucket. Mac RegionConfig.swift must supply actual regional
options and every helper used by production sources; the example is not a full
build-ready substitute. India uses the bundled GoogleService-Info.plist fallback;
US options include its actual Google app ID and GCM sender ID. Verify bundle
registration for com.OP.ClipSync. Enable regional anonymous Auth and verify
Firestore and Messaging availability. Do not modify production configuration.

Source inspection reconfirms FcmTokenPolicy guards authProjectId, issuer projectId,
numeric senderId, sender-consistent applicationId, UID and pairing binding.
Functions compare Android metadata against regional project and server-configured
ANDROID_PUSH_SENDER_ID/ANDROID_PUSH_APP_ID, routing only to India. See FCM_ROUTING.md.

## Execute once prerequisites are supplied

From repository root, with real files restored securely:

```sh
cd android
ANDROID_HOME="$HOME/Library/Android/sdk" ./gradlew :app:testDebugUnitTest :app:assembleDebug
"$HOME/Library/Android/sdk/platform-tools/adb" -s "$ANDROID_SERIAL" install -r app/build/outputs/apk/debug/app-debug.apk
"$HOME/Library/Android/sdk/platform-tools/adb" -s "$ANDROID_SERIAL" shell am start -W -n com.bunty.clipsync/.MainActivity
```

ANDROID_SERIAL must identify a physical phone, not emulator-5554. Inspect logcat
privately for launch/Firebase failures; retain redacted errors only. Record actual
region, package version and no immediate crash. Do not clear user data implicitly.

```sh
xcodebuild -resolvePackageDependencies -project mac/ClipSync.xcodeproj -scheme ClipSync
xcodebuild -project mac/ClipSync.xcodeproj -scheme ClipSync -configuration Debug -derivedDataPath /private/tmp/clipsync-live-debug build
open /private/tmp/clipsync-live-debug/Build/Products/Debug/ClipSync.app
```

Run only after full Xcode selected and real regional configs present. Record
compile/link/package/Firebase/entitlement/sandbox errors separately. No archive.

## Minimum device evidence matrix

Every row below is NOT RUN. Use a fresh test pairing and explicitly selected
region; retain timestamps, versions, redacted event IDs and success/failure.
Never retain pairing secrets, clipboard content, OTPs, Firebase tokens or API keys.

1. Fresh pairing in IN, then fresh pairing in US: unpaired Mac QR, Android regional
   anonymous identity, v2 document, proof validation, Mac joins, exactly two
   correct member UIDs, one active pairing, BLE and TCP success. Inspect documents
   with authorized administrative tooling; token reads are forbidden to clients.
2. Both directions: short text, >4 KiB text, very large text, image, small file,
   large file and Ultra-Fast file. Use synthetic fixtures and compare SHA-256
   before/after files and exact text length/content. Observe authenticated v2
   encrypted frames, no 0x04 plaintext, correct totalSize and rejected replay.
3. BLE: ping/ack, IP update, tcp_ready, file_incoming, text_incoming, settings,
   Bluetooth interruption/reconnect. Correlate request IDs and prove state changes
   occur only after valid authenticated envelopes.
4. Cloud separately in IN and US: disable shared LAN while retaining internet,
   relay synthetic clipboard and synthetic OTP, test wake-up and pairing state.
   US proof requires India-issued device token stored in US Firestore with both
   project identities, US Function successful India endpoint send, and matching
   device receipt. Code/unit tests alone do not satisfy this row.
5. Restart app, phone and Mac; change network; Wi-Fi/Bluetooth off/on; region
   change; unpair/re-pair; explicit consent before reinstall/new anonymous UID;
   hybrid→local and local→hybrid. Verify old registrations cannot route, stale
   pairing prompts re-pair, and fresh local process makes no Firebase requests.
6. Isolated test pairing only: wrong key, stale replay, legacy peer, permission
   denied, malformed TCP/BLE, bad MAC, tampered ciphertext and wrong Firebase
   identity. Verify rejection, no unauthorized clipboard/file/settings mutation,
   no plaintext/legacy fallback and recovery without deleting unrelated state.

## Cloud identity and rollout rehearsal — commands NOT executed

No confirmed non-production project or prior deployed rules artifact was supplied.
Do not infer that clipsyncind or clipsync1-c3c3c is safe for rehearsal.
After installing authenticated gcloud, read actual US deployment metadata:

```sh
gcloud functions list --project=clipsync1-c3c3c --format='table(name,environment,region)'
gcloud functions describe notifyPairedDevice --gen2 --project=clipsync1-c3c3c --region="$US_FUNCTION_REGION" --format='value(serviceConfig.serviceAccountEmail)'
```

Use the actual location/function name from list; do not assume a default account.
Save only the resulting email as US_RUNTIME_SA. Required IAM operation, explicitly
NOT authorized/executed by this pass:

```sh
gcloud projects add-iam-policy-binding clipsyncind --member="serviceAccount:$US_RUNTIME_SA" --role=roles/firebasecloudmessaging.admin
```

Verify FCM API enabled in sending/target projects and credentials use ADC; no
cross-project Firestore grant is required. Official procedure:
https://firebase.google.com/docs/cloud-messaging/send/v1-api

For an explicitly confirmed existing test project, export its current deployed
rules to reviewed firestore.previous.rules before deployment. Set TEST_PROJECT
to that actual approved ID. No fictitious ID or permissive rollback rules.

```sh
firebase deploy --project "$TEST_PROJECT" --config firebase/firebase.json --only firestore:rules
```

Rollback config firebase/rollback.json must contain exactly:
`{"firestore":{"rules":"firestore.previous.rules"}}` and reference the saved
previous rules alongside it. Then:

```sh
firebase deploy --project "$TEST_PROJECT" --config firebase/rollback.json --only firestore:rules
```

Existing firebase/firebase.json has no Functions deployment entry. Before any
authorized deployment create/review firebase/deploy.json with
`{"firestore":{"rules":"firestore.rules"},"functions":{"source":"../functions"}}`.
Provide real issuer metadata in the appropriate functions/.env.<project-id> file,
use Node 24, install locked dependencies and rerun tests. Deployment command:

```sh
firebase deploy --project "$TEST_PROJECT" --config firebase/deploy.json --only functions
```

The current fixed project allowlist blocks arbitrary test-project Android routing;
rules rehearsal is possible, but full cloud rehearsal requires deliberately
configured existing regional environments. Do not silently change allowlists.
Functions rollback requires a separately reviewed checkout of the last deployed
source/config/lockfile and its deployment config, redeployed to the SAME confirmed
project. No known-good previous deployment was available, so no concrete source
rollback can yet be certified.

Order: snapshot rules/functions/config; rehearse v2 rules; validate new clients
against rules; configure issuer/API/IAM and deploy hardened Functions; deploy v2
rules as coordinated enforcement; release compatible clients in controlled cohort,
requiring legacy re-pair. Expect old clients to fail closed after enforcement;
announce that compatibility break. Never roll back to permissive rules to revive
legacy clients. Production deployment remains unauthorized.

## Developer ID preparation — NOT executed

App bundle com.OP.ClipSync; share extension com.OP.ClipSync.ClipSyncShare.
Manual signing, empty development team, macOS identity override '-' (ad hoc).
App sandbox and hardened runtime enabled. Entitlements: network client/server,
Bluetooth, Apple events, downloads/user-selected files and group.com.OP.ClipSync;
extension has sandbox/app group. Verify distribution provisioning/registered app
group for BOTH targets and actual capability behavior on a signed app.
Updater requires validated Apple signature, same team, same bundle, newer version.
Ad hoc builds have no update trust anchor; first Developer ID install is manual.

After explicit release-signing authorization, obtain a valid Developer ID
Application identity/profiles and real TEAM_ID. Use Xcode archive/export to sign
nested extension and app, preserving separate entitlements; do not deep-sign.
Create reviewed ExportOptions.plist specifying method developer-id, signingStyle
manual, signingCertificate Developer ID Application, teamID and required
provisioningProfiles mapping. Verify supported export keys with installed Xcode.

```sh
xcodebuild -project mac/ClipSync.xcodeproj -scheme ClipSync -configuration Release -archivePath /private/tmp/clipsync-release/ClipSync.xcarchive DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_IDENTITY='Developer ID Application' 'CODE_SIGN_IDENTITY[sdk=macosx*]=Developer ID Application' archive
xcodebuild -exportArchive -archivePath /private/tmp/clipsync-release/ClipSync.xcarchive -exportPath /private/tmp/clipsync-release/export -exportOptionsPlist "$EXPORT_OPTIONS"
codesign --verify --deep --strict --verbose=2 /private/tmp/clipsync-release/export/ClipSync.app
codesign -d --verbose=4 /private/tmp/clipsync-release/export/ClipSync.app
ditto -c -k --sequesterRsrc --keepParent /private/tmp/clipsync-release/export/ClipSync.app /private/tmp/clipsync-release/ClipSync-submit.zip
xcrun notarytool submit /private/tmp/clipsync-release/ClipSync-submit.zip --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple /private/tmp/clipsync-release/export/ClipSync.app
xcrun stapler validate /private/tmp/clipsync-release/export/ClipSync.app
spctl --assess --type execute --verbose=4 /private/tmp/clipsync-release/export/ClipSync.app
ditto -c -k --sequesterRsrc --keepParent /private/tmp/clipsync-release/export/ClipSync.app /private/tmp/clipsync-release/ClipSync.zip
unzip -l /private/tmp/clipsync-release/ClipSync.zip
```

Proceed past submit only after Accepted; inspect notarytool log if rejected.
NOTARY_PROFILE is a securely stored authenticated keychain profile; do not print
credentials. Inspect nested extension signature/entitlements and runtime flags.
Final ZIP contains ClipSync.app (plus ditto resource metadata), no installer script.
Never package or execute Install ClipSync.command. Verify extraction/updater on a
fresh Mac and same-team update before distribution. These steps cannot be proven
on this host until Xcode, signing identity and provisioning are available.
Apple references: https://developer.apple.com/developer-id/ and
https://developer.apple.com/documentation/security/customizing-the-notarization-workflow

## Verdict

US FCM: CODE READY, LIVE CONFIG BLOCKED.
Release readiness: BLOCKED. No actual Mac/Android configured build, physical-device
pairing/local/cloud/lifecycle/negative test or test-project rules deployment has
passed in this pass. Required inputs: full Xcode, real regional configs, physical
Android phone, authenticated Firebase/gcloud access, known US runtime SA, confirmed
test project and previous deployment artifacts; Developer ID identity/profiles
and notary profile are later release-preparation prerequisites.
