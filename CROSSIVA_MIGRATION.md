> Superseded Firebase architecture: the Canada-default runtime migration is implemented.
> See CROSSIVA_FIREBASE_IMPLEMENTATION.md for current config, builds, tests and pending deployments.
> Historical India-default requirements below are retained only as the earlier checkpoint record.

# Crossiva software migration — 2026-10-03

Company: SinghEverything. Product: Crossiva. Namespace: com.singheverything.crossiva.
Security checkpoint: 9be61c4d1538efc679f1b35d2970886132998a57.
Migration changes remain uncommitted and unstaged. No deployment/signing/release.

## Software identity

- Android applicationId/namespace/packages: com.singheverything.crossiva.
  Sources/tests moved into matching package directories; relative component class
  names remain stable. FileProvider and removed Firebase provider authorities use
  ${applicationId}. Intent actions, component checks, notification channels and
  application strings use owned identity.
- Mac main bundle com.singheverything.crossiva; extension
  com.singheverything.crossiva.share; app group group.com.singheverything.crossiva.
  Keychain service com.singheverything.crossiva.encryption. Products Crossiva.app
  and CrossivaShare.appex. Xcode project/scheme/target names remain ClipSync and
  ClipSyncShare; build with the existing ClipSync scheme.
- Bonjour namespace _crossiva._tcp on both peers. TCP ports and BLE UUIDs retained.
- Android/Mac ProductIdentity constants contain empty update endpoints until the
  owned GitHub owner/repo is supplied. Empty configuration prevents update discovery
  requests; Android support link is also inactive until configured. No guessed URL.
- Updater expects Crossiva.app and owned bundle identity, retaining same-team
  signature/version/archive checks. Share XIB module follows CrossivaShare product.
- MIT notice retained. Artwork, animations, colors, fonts and layout unchanged.
  Documentation removes upstream distribution/contact links and script-install flow.
- Old bundle/app sandbox and keychain state is not silently imported. Use fresh
  installation/pairing for validation. This is a new application identity, not an
  in-place update to the old app.

## Firebase inputs required (do not paste credentials)

The IDs crossiva-dev-in and crossiva-dev-us are intended development IDs supplied
by the user, now pinned consistently in Android, Mac, Function routing and local
rules. Their existence/ownership has NOT been verified. Confirm actual IDs before
supplying configuration; if different, update all matching policy allowlists.

| Destination | Region/source | Required values |
|---|---|---|
| android/app/google-services.json | India Firebase Console Android download | project_id, project_number, matching com.singheverything.crossiva client, mobilesdk_app_id, real API key |
| android/app/src/main/java/com/singheverything/crossiva/RegionConfig.kt | US project-specific Kotlin options; example beside it | real US project/application ID/API key/storage bucket; IN returns default options; REGION_INDIA/REGION_US/getOptionsForRegion API |
| mac/ClipSync/GoogleService-Info.plist | India Firebase Console Apple download | matching com.singheverything.crossiva registration; PROJECT_ID, GOOGLE_APP_ID, GCM_SENDER_ID, API_KEY and optional bucket |
| mac/ClipSync/RegionConfig.swift | US project-specific Swift options; existing example beside it | real US project/googleAppID/gcmSenderID/API key/bucket; getOptions(for:), getOptimalServer(for:), sortedCountryNames |

Both RegionConfig examples already existed and are not real configs. No placeholder
runtime configs created. The Swift example lacks the last two helper APIs; it is
not a complete build-ready implementation. Secure exported US Console configuration
can be supplied as input instead of hand-authoring code; do not add it to Git.
Default Mac plist must be copied into the main app bundle by the synchronized group.
All real config basenames remain gitignored.

Enable/confirm anonymous Auth and Firestore in both owned projects. Android default
India app owns Messaging; US Auth/Firestore use named CrossivaUS. Mac uses its chosen
regional default app for Auth, Firestore and Messaging. Mac now rejects a project
that does not match the selected regional policy.

Functions require real ANDROID_PUSH_SENDER_ID and ANDROID_PUSH_APP_ID from the India
Android registration, configured for both regional deployments. Determine actual
US notifyPairedDevice location/runtime service account through authenticated cloud
metadata. Cross-project send requires that account's FCM send permission in the
owned India project; do not guess the account or grant IAM without authorization.
Confirm FCM API availability and regional function trigger/database locations.
No cloud access, actual runtime identity or approved deployment project was supplied.
Firestore rules were validated only against the local emulator namespace demo-clipsync;
that namespace is an offline test ID, not a cloud project or deployed ruleset.

## Validation results

- Function routing: 13/13, with intended Crossiva project allowlists.
- Firestore emulator: 21/21, with migrated project metadata constraints.
- Standalone Android pairing/FCM policy JVM subset: 23/23; no configs or stubs.
- Mac policy checks: 345/345; three signing-fixture checks omitted in temporary
  copies and two Developer ID checks skipped. No signing performed.
- Swift parsing: 45 files (main application plus share extension).
- TCP/BLE/membership codecs byte-identical to checkpoint except Kotlin package
  declarations. Shared vectors/generators and transfer security policy unchanged.
- Xcode Debug settings resolve Crossiva.app/com.singheverything.crossiva with
  sandbox enabled. Project retains hardened-runtime settings; Xcode reported NO
  in resolved Debug settings, so release/runtime behavior is not certified here.
- Cocoa framework reference now uses SDKROOT rather than nonexistent MacOSX26.0
  under the installed Xcode 27 SDK. No application build has yet validated linking.

Full Android Gradle tests/assemble and real Mac Debug build are BLOCKED by the four
real config files above. No placeholder build is represented as real. Once supplied:

```sh
cd android
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

From repository root, after configs are supplied (unsigned Debug because signing
is not authorized):

```sh
xcodebuild -project mac/ClipSync.xcodeproj -scheme ClipSync -configuration Debug -derivedDataPath /private/tmp/crossiva-debug CODE_SIGNING_ALLOWED=NO build
```

Unsigned sandboxed app launch may require separately authorized development
signing; do not weaken sandbox/security to make it run.

## Remaining order

1. Supply real config paths and confirm owned IDs/registrations; configure actual
   repository endpoints and support destination when available.
2. Run full Android tests/assemble and real Xcode Debug build; fix actual integration
   errors. Inspect merged manifest, app bundle resources and extension identity.
3. On a physical Android phone and running Mac app: fresh pairing, authenticated
   BLE controls, TCP v2, short/long text, image/file/Ultra-Fast, restart/reconnect and
   legacy rejection. Retain existing negative and replay fixtures.
4. Only after local functionality succeeds, validate India and US cloud paths with
   authorized owned projects, real runtime credentials and device receipt evidence.
   No deployment is authorized by this migration pass; retain emulator evidence.

Local device functionality NOT RUN. Live India/US cloud validation NOT RUN.
US FCM remains CODE READY, LIVE CONFIG BLOCKED. Overall migration is partial until
real configurations and build/device prerequisites are supplied.
