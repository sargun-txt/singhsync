# Crossiva Canada-default runtime migration — 2026-10-03

## Implementation

Canada is the default FirebaseApp on both platforms. Android default config is `android/app/google-services.json`; Mac default config is `mac/ClipSync/GoogleService-Info.plist`. Both are real Canadian exports, gitignored and private. No API keys were transcribed into tracked source.

US and India are named `CrossivaUS` / `CrossivaIN` apps for Auth/Firestore. Android loads real ignored regional JSON assets. Mac loads real ignored regional plist resources. Each loader verifies the selected project and package/bundle identifier; unknown or mismatched configs fail closed. Canadian Auth/Firestore use the default app explicitly. Mac region remains fixed until relaunch, preserving existing selection/restart behavior. Saved regional selections are preserved; a fresh installation defaults to Canada.

Android messaging uses `FirebaseMessaging.getInstance()` for the Canadian default app only. Mac messaging also remains on the default Canadian app. Token records distinguish the regional `authProjectId`/UID from the Canada `projectId` issuer. Regional Functions route push through a named Canada Admin app using ADC; regional Firestore stays on the deployment project. No secondary Messaging instance is created.

Country mapping: Canada -> CA, United States -> US, India -> IN; other countries retain the non-India US mapping. Existing country-picker layout/assets are unchanged; Canada status/flag is now correct.

## Files changed for this pass

- `.gitignore`; `tools/prepare_firebase_configs.py`
- Android owned package: `FirebaseRegion.kt`, `CloudAuth.kt`, `FcmTokenPolicy.kt`, `FCMTokenManager.kt`, `DeviceManager.kt`, `FirestoreManager.kt`, `MainActivity.kt`, `ClipSyncApp.kt`, `LocationHelper.kt`, `RegionConfig.kt.example`
- Android tests: `FirebaseRegionTest.kt`, `FcmTokenPolicyTest.kt`
- Mac: `FirebaseRegion.swift`, `FirebaseManager.swift`, `FCMTokenManager.swift`, `ProductIdentity.swift`, `QRGen.swift`, `RegionConfig.swift.example`, `PolicyTests/main.swift`
- `firebase/firestore.rules`, `firebase/rules-tests/firestore.rules.test.mjs`
- `functions/routing.js`, `functions/test/routing.test.js`
- `CROSSIVA_MIGRATION.md`, this report
- Private runtime copies: Canadian default exports, regional JSON assets/plists, `RegionConfig.kt`, `RegionConfig.swift` (all ignored).

`python3 tools/prepare_firebase_configs.py` validates the private exports and prepares runtime copies/loader sources. `--check` verifies equality without writing. Credentials remain in ignored config files, never in tracked loader code. Original private exports remain intact.

## Validation

- Real Android `:app:testDebugUnitTest`: 73 tests, zero failures/errors, including regional selection, FCM policy, TCP/BLE v2, pairing proof and OTP tests.
- Real Android `:app:assembleDebug`: succeeded with Canadian default and real US/IN assets.
- Real Xcode Debug build: ClipSync scheme/target; Crossiva.app and share extension compiled/linked successfully. `CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO`; no app/release signing. Real CA/US/IN plists present in built resources.
- Mac standalone policy/security/regional checks: 354/354 passed. Three ad-hoc signing fixture checks omitted because signing is outside scope; positive real-signature verification exercised an existing Android Studio.app without modifying/signing it.
- Functions routing: 14/14 passed.
- Firestore local emulator: 23/23 passed using demo-crossiva; no live data operations/deployment.
- Real config validator passed; bundled US/IN Android assets and all Mac plist project IDs verified.
- TCP/BLE codecs, pairing-proof code and Mac file-receiving policy match security checkpoint byte-for-byte (Android package declaration excepted).
- `git diff --check` passed; index unchanged/empty. Collected API keys absent from tracked working files; all runtime credential paths are gitignored.

No device pairing/transfers, live Auth sign-in, Firestore writes, or FCM delivery were exercised. Builds and emulator/unit checks are not live functionality certification.

## Rules and approval-only deployment commands

The repository retains authenticated membership, addressed proof-based joining, no stored pairing secret, member-only clipboard/notification access, user-owned token writes and no client token reads/enumeration. The token validator runs for both create/update and pins the Canada issuer, known regional Auth project and server timestamp. Admin SDK access is validated separately by Functions routing.

I've set up prototype Security Rules to keep the data in Firestore safe. They are designed to be secure for authenticated pairing membership, proof-based joins, user-owned token writes, and denied token reads. However, you should review and verify them before broadly sharing your app. If you'd like, I can help you harden these rules.

All live project rules remain deny-all. The following commands are prepared, NOT executed. Run from the repository root only after explicit approval:

```sh
npx -y firebase-tools@latest deploy --only firestore:rules --project crossiva-dev-ca --config firebase/firebase.json
npx -y firebase-tools@latest deploy --only firestore:rules --project crossiva-dev-us --config firebase/firebase.json
npx -y firebase-tools@latest deploy --only firestore:rules --project crossiva-dev-in --config firebase/firebase.json
```

## Exact remaining IAM / Functions work

The caller is the runtime service account for `notifyPairedDevice` in each regional deployment, not a user account, deployer or guessed project service agent. The actual US/IN account emails cannot yet be identified: read-only Functions v2 API queries returned HTTP403 API disabled/never used for both projects. No API was enabled. Confirm the actual `serviceConfig.serviceAccountEmail` after separately approved provisioning, or explicitly select owned runtime accounts before deployment.

Grant only those confirmed senders permission in the target project `crossiva-dev-ca`. Minimum send permission: `cloudmessaging.messages.create`; a custom role containing only that permission is the minimum scope. The documented predefined FCM role is `roles/firebasecloudmessaging.admin`. Review existing CA runtime permissions separately before adding a grant. Never grant Owner/Editor or generate private keys.

Official references: https://firebase.google.com/docs/cloud-messaging/send/admin-sdk ; https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages/send ; https://docs.cloud.google.com/iam/docs/roles-permissions/firebasecloudmessaging

Each Function deployment needs these server environment values from the real Canada Android registration:
- `ANDROID_PUSH_SENDER_ID=396960243483`
- `ANDROID_PUSH_APP_ID=1:396960243483:android:15f1549586b8ee8cd6bdbe`

No Functions deployment, IAM mutation, API enablement, billing change or service-account key generation occurred.

## Remaining blockers / follow-ups

- Live deny-all rules block cloud pairing/sync until the reviewed deployment is approved.
- Functions APIs/provisioning, actual runtime account selection and CA send permission remain pending approval. Functions are not deployed by this pass.
- Physical Android + Mac local sync validation still required before cloud validation.
- Mac device push validation needs appropriate Apple signing/APNs setup; this build is unsigned and is not a release.
- India project database remains `nam5` (US multi-region). This is a data-residency/deployment follow-up only; database not recreated/migrated.
- No deployments, production mutations, publishing, notarization, credential commits, or new commits/staging in this pass.

## Working-tree diff and status

The snapshot includes the earlier uncommitted software-identity migration. Deleted old Android paths and untracked owned paths represent source moves; ordinary `git diff --stat` does not include untracked replacements/new files, so its deletion total is not net source removal.

```text
 .gitignore                                         |    5 +
 CODE_OF_CONDUCT.md                                 |    2 +-
 README.md                                          |   57 +-
 android/app/build.gradle.kts                       |    4 +-
 .../example/clipsync/ExampleInstrumentedTest.kt    |   31 -
 android/app/src/main/AndroidManifest.xml           |    8 +-
 .../main/java/com/bunty/clipsync/AesGcmCipher.kt   |   96 --
 .../java/com/bunty/clipsync/AndroidTcpReceiver.kt  |  489 -------
 .../java/com/bunty/clipsync/AppFloatingToolbar.kt  |  197 ---
 .../java/com/bunty/clipsync/AppUpdateInstaller.kt  |  170 ---
 .../main/java/com/bunty/clipsync/BLEConnector.kt   |  252 ----
 .../src/main/java/com/bunty/clipsync/BLEScanner.kt |  195 ---
 .../java/com/bunty/clipsync/BleControlProtocol.kt  |  314 -----
 .../java/com/bunty/clipsync/BluetoothScreen.kt     |  497 -------
 .../java/com/bunty/clipsync/CameraQRScanner.kt     |  284 ----
 .../com/bunty/clipsync/CancelTransferReceiver.kt   |   26 -
 .../main/java/com/bunty/clipsync/ClipSyncApp.kt    |  118 --
 .../main/java/com/bunty/clipsync/ClipSyncNavBar.kt |  164 ---
 .../main/java/com/bunty/clipsync/ClipSyncSender.kt |  233 ---
 .../clipsync/ClipboardAccessibilityService.kt      |  483 -------
 .../com/bunty/clipsync/ClipboardGhostActivity.kt   |  450 ------
 .../src/main/java/com/bunty/clipsync/CloudAuth.kt  |  115 --
 .../java/com/bunty/clipsync/CloudPairingAuth.kt    |   99 --
 .../src/main/java/com/bunty/clipsync/Connection.kt |  279 ----
 .../com/bunty/clipsync/ConnectionDiagnostics.kt    |  309 ----
 .../java/com/bunty/clipsync/ConnectionRouteCard.kt |  105 --
 .../java/com/bunty/clipsync/DashboardScreen.kt     |  307 ----
 .../main/java/com/bunty/clipsync/DashboardState.kt |   15 -
 .../java/com/bunty/clipsync/DashboardViewModel.kt  |   86 --
 .../src/main/java/com/bunty/clipsync/DeviceCard.kt |  136 --
 .../main/java/com/bunty/clipsync/DeviceManager.kt  |  618 --------
 .../com/bunty/clipsync/DiagnosticConsoleScreen.kt  |  207 ---
 .../com/bunty/clipsync/EmailOTPListenerService.kt  |  362 -----
 .../java/com/bunty/clipsync/FCMTokenManager.kt     |  108 --
 .../main/java/com/bunty/clipsync/FcmTokenPolicy.kt |   54 -
 .../java/com/bunty/clipsync/FirestoreManager.kt    |  681 ---------
 .../java/com/bunty/clipsync/GithubUpdateChecker.kt |  182 ---
 .../src/main/java/com/bunty/clipsync/HapticUtil.kt |   16 -
 .../main/java/com/bunty/clipsync/HelperUtils.kt    |   92 --
 .../main/java/com/bunty/clipsync/HistoryScreen.kt  |  307 ----
 .../src/main/java/com/bunty/clipsync/Homescreen.kt | 1222 ----------------
 .../main/java/com/bunty/clipsync/LandingScreen.kt  |  469 -------
 .../main/java/com/bunty/clipsync/LocalNetwork.kt   |  443 ------
 .../java/com/bunty/clipsync/LocalSyncManager.kt    |  857 -----------
 .../main/java/com/bunty/clipsync/LocationHelper.kt |   88 --
 .../com/bunty/clipsync/MacPushForegroundService.kt |  122 --
 .../java/com/bunty/clipsync/MacPushReceiver.kt     |  385 -----
 .../main/java/com/bunty/clipsync/MainActivity.kt   |  556 --------
 .../main/java/com/bunty/clipsync/MeshBackground.kt |  194 ---
 .../bunty/clipsync/MyFirebaseMessagingService.kt   |  184 ---
 .../main/java/com/bunty/clipsync/NavigationTab.kt  |    9 -
 .../java/com/bunty/clipsync/NotificationHelper.kt  |  162 ---
 .../java/com/bunty/clipsync/OTPListeningService.kt |  285 ----
 .../com/bunty/clipsync/OTPNotificationService.kt   |  155 --
 .../main/java/com/bunty/clipsync/PairingPage.kt    |  454 ------
 .../src/main/java/com/bunty/clipsync/Permission.kt |  650 ---------
 .../java/com/bunty/clipsync/PermissionHelper.kt    |   82 --
 .../main/java/com/bunty/clipsync/Permissionpage.kt |  592 --------
 .../main/java/com/bunty/clipsync/QRScanScreen.kt   |  462 ------
 .../java/com/bunty/clipsync/QuickActionsGrid.kt    |   88 --
 .../java/com/bunty/clipsync/RecentActivityList.kt  |  159 ---
 .../com/bunty/clipsync/RegionConfig.kt.example     |   34 -
 .../java/com/bunty/clipsync/Secrets.kt.example     |    5 -
 .../java/com/bunty/clipsync/SettingsRepository.kt  |   38 -
 .../main/java/com/bunty/clipsync/ShareActivity.kt  |  128 --
 .../com/bunty/clipsync/ShareTransferService.kt     |  209 ---
 .../java/com/bunty/clipsync/SyncControlsCard.kt    |  164 ---
 .../src/main/java/com/bunty/clipsync/SyncMode.kt   |  813 -----------
 .../java/com/bunty/clipsync/TcpFrameProtocol.kt    |  410 ------
 .../app/src/main/java/com/bunty/clipsync/Theme.kt  |  127 --
 .../main/java/com/bunty/clipsync/ToolbarItem.kt    |    8 -
 .../bunty/clipsync/UpdateNotificationManager.kt    |  390 -----
 .../java/com/bunty/clipsync/UrlAllowlistManager.kt |  130 --
 .../src/main/java/com/bunty/clipsync/WakeupPing.kt |  412 ------
 .../java/com/bunty/clipsync/db/HistoryEntity.kt    |   12 -
 .../com/bunty/clipsync/db/HistoryRepository.kt     |   78 -
 .../main/java/com/bunty/clipsync/newhomescreen.kt  | 1485 --------------------
 android/app/src/main/res/values-night/themes.xml   |    2 +-
 android/app/src/main/res/values/strings.xml        |    4 +-
 android/app/src/main/res/values/themes.xml         |    6 +-
 .../main/res/xml/accessibility_service_config.xml  |    2 +-
 .../com/bunty/clipsync/BleControlProtocolTest.kt   |  227 ---
 .../bunty/clipsync/ClipSyncSenderTransferTest.kt   |  112 --
 .../com/bunty/clipsync/CloudPairingAuthTest.kt     |   82 --
 .../java/com/bunty/clipsync/FcmTokenPolicyTest.kt  |   80 --
 .../bunty/clipsync/OTPNotificationServiceTest.kt   |   94 --
 .../com/bunty/clipsync/TcpFrameProtocolTest.kt     |  315 -----
 .../test/java/com/bunty/clipsync/TcpTestSupport.kt |  101 --
 .../java/com/example/clipsync/ExampleUnitTest.kt   |   22 -
 android/settings.gradle.kts                        |    2 +-
 firebase/firestore.rules                           |   25 +-
 firebase/rules-tests/firestore.rules.test.mjs      |   24 +-
 functions/routing.js                               |   18 +-
 functions/test/routing.test.js                     |   47 +-
 mac/ClipSync.xcodeproj/project.pbxproj             |   48 +-
 .../xcshareddata/xcschemes/ClipSync.xcscheme       |    6 +-
 mac/ClipSync/BLEDiscover.swift                     |    2 +-
 mac/ClipSync/ClipSync.entitlements                 |    2 +-
 mac/ClipSync/ClipSyncApp.swift                     |    6 +-
 mac/ClipSync/ClipSyncServer.swift                  |   16 +-
 mac/ClipSync/ClipboardManager.swift                |    2 +-
 mac/ClipSync/FCMTokenManager.swift                 |    5 +-
 mac/ClipSync/Final.swift                           |    8 +-
 mac/ClipSync/FirebaseManager.swift                 |   42 +-
 mac/ClipSync/HomeScreen.swift                      |    2 +-
 mac/ClipSync/KeychainHelper.swift                  |    2 +-
 mac/ClipSync/LandingScreen.swift                   |    2 +-
 mac/ClipSync/MacDiagnosticConsole.swift            |    2 +-
 mac/ClipSync/MacUpdateManager.swift                |   13 +-
 mac/ClipSync/PairingManager.swift                  |    4 +-
 mac/ClipSync/QRCodeGenerator.swift                 |    2 +-
 mac/ClipSync/QRGen.swift                           |   10 +-
 mac/ClipSync/RegionConfig.swift.example            |   38 +-
 mac/ClipSync/SecurityScopedResourceManager.swift   |    2 +-
 mac/ClipSync/SplashScreen.swift                    |    2 +-
 mac/ClipSync/UpdatePolicy.swift                    |   10 +-
 mac/ClipSync/UpdateStager.swift                    |    4 +-
 mac/ClipSync/UpdateWindow.swift                    |    8 +-
 mac/ClipSync/WakeupReceiver.swift                  |   10 +-
 mac/ClipSync/history.swift                         |    2 +-
 .../Base.lproj/ShareViewController.xib             |    2 +-
 mac/ClipSyncShare/ClipSyncShare.entitlements       |    2 +-
 mac/ClipSyncShare/Info.plist                       |    2 +-
 mac/ClipSyncShare/SharedViewController.swift       |    8 +-
 mac/PolicyTests/UpdatePolicyTests.swift            |   82 +-
 mac/PolicyTests/main.swift                         |   11 +-
 126 files changed, 310 insertions(+), 21424 deletions(-)
```

```text
 M .gitignore
 M CODE_OF_CONDUCT.md
 M README.md
 M android/app/build.gradle.kts
 D android/app/src/androidTest/java/com/example/clipsync/ExampleInstrumentedTest.kt
 M android/app/src/main/AndroidManifest.xml
 D android/app/src/main/java/com/bunty/clipsync/AesGcmCipher.kt
 D android/app/src/main/java/com/bunty/clipsync/AndroidTcpReceiver.kt
 D android/app/src/main/java/com/bunty/clipsync/AppFloatingToolbar.kt
 D android/app/src/main/java/com/bunty/clipsync/AppUpdateInstaller.kt
 D android/app/src/main/java/com/bunty/clipsync/BLEConnector.kt
 D android/app/src/main/java/com/bunty/clipsync/BLEScanner.kt
 D android/app/src/main/java/com/bunty/clipsync/BleControlProtocol.kt
 D android/app/src/main/java/com/bunty/clipsync/BluetoothScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/CameraQRScanner.kt
 D android/app/src/main/java/com/bunty/clipsync/CancelTransferReceiver.kt
 D android/app/src/main/java/com/bunty/clipsync/ClipSyncApp.kt
 D android/app/src/main/java/com/bunty/clipsync/ClipSyncNavBar.kt
 D android/app/src/main/java/com/bunty/clipsync/ClipSyncSender.kt
 D android/app/src/main/java/com/bunty/clipsync/ClipboardAccessibilityService.kt
 D android/app/src/main/java/com/bunty/clipsync/ClipboardGhostActivity.kt
 D android/app/src/main/java/com/bunty/clipsync/CloudAuth.kt
 D android/app/src/main/java/com/bunty/clipsync/CloudPairingAuth.kt
 D android/app/src/main/java/com/bunty/clipsync/Connection.kt
 D android/app/src/main/java/com/bunty/clipsync/ConnectionDiagnostics.kt
 D android/app/src/main/java/com/bunty/clipsync/ConnectionRouteCard.kt
 D android/app/src/main/java/com/bunty/clipsync/DashboardScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/DashboardState.kt
 D android/app/src/main/java/com/bunty/clipsync/DashboardViewModel.kt
 D android/app/src/main/java/com/bunty/clipsync/DeviceCard.kt
 D android/app/src/main/java/com/bunty/clipsync/DeviceManager.kt
 D android/app/src/main/java/com/bunty/clipsync/DiagnosticConsoleScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/EmailOTPListenerService.kt
 D android/app/src/main/java/com/bunty/clipsync/FCMTokenManager.kt
 D android/app/src/main/java/com/bunty/clipsync/FcmTokenPolicy.kt
 D android/app/src/main/java/com/bunty/clipsync/FirestoreManager.kt
 D android/app/src/main/java/com/bunty/clipsync/GithubUpdateChecker.kt
 D android/app/src/main/java/com/bunty/clipsync/HapticUtil.kt
 D android/app/src/main/java/com/bunty/clipsync/HelperUtils.kt
 D android/app/src/main/java/com/bunty/clipsync/HistoryScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/Homescreen.kt
 D android/app/src/main/java/com/bunty/clipsync/LandingScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/LocalNetwork.kt
 D android/app/src/main/java/com/bunty/clipsync/LocalSyncManager.kt
 D android/app/src/main/java/com/bunty/clipsync/LocationHelper.kt
 D android/app/src/main/java/com/bunty/clipsync/MacPushForegroundService.kt
 D android/app/src/main/java/com/bunty/clipsync/MacPushReceiver.kt
 D android/app/src/main/java/com/bunty/clipsync/MainActivity.kt
 D android/app/src/main/java/com/bunty/clipsync/MeshBackground.kt
 D android/app/src/main/java/com/bunty/clipsync/MyFirebaseMessagingService.kt
 D android/app/src/main/java/com/bunty/clipsync/NavigationTab.kt
 D android/app/src/main/java/com/bunty/clipsync/NotificationHelper.kt
 D android/app/src/main/java/com/bunty/clipsync/OTPListeningService.kt
 D android/app/src/main/java/com/bunty/clipsync/OTPNotificationService.kt
 D android/app/src/main/java/com/bunty/clipsync/PairingPage.kt
 D android/app/src/main/java/com/bunty/clipsync/Permission.kt
 D android/app/src/main/java/com/bunty/clipsync/PermissionHelper.kt
 D android/app/src/main/java/com/bunty/clipsync/Permissionpage.kt
 D android/app/src/main/java/com/bunty/clipsync/QRScanScreen.kt
 D android/app/src/main/java/com/bunty/clipsync/QuickActionsGrid.kt
 D android/app/src/main/java/com/bunty/clipsync/RecentActivityList.kt
 D android/app/src/main/java/com/bunty/clipsync/RegionConfig.kt.example
 D android/app/src/main/java/com/bunty/clipsync/Secrets.kt.example
 D android/app/src/main/java/com/bunty/clipsync/SettingsRepository.kt
 D android/app/src/main/java/com/bunty/clipsync/ShareActivity.kt
 D android/app/src/main/java/com/bunty/clipsync/ShareTransferService.kt
 D android/app/src/main/java/com/bunty/clipsync/SyncControlsCard.kt
 D android/app/src/main/java/com/bunty/clipsync/SyncMode.kt
 D android/app/src/main/java/com/bunty/clipsync/TcpFrameProtocol.kt
 D android/app/src/main/java/com/bunty/clipsync/Theme.kt
 D android/app/src/main/java/com/bunty/clipsync/ToolbarItem.kt
 D android/app/src/main/java/com/bunty/clipsync/UpdateNotificationManager.kt
 D android/app/src/main/java/com/bunty/clipsync/UrlAllowlistManager.kt
 D android/app/src/main/java/com/bunty/clipsync/WakeupPing.kt
 D android/app/src/main/java/com/bunty/clipsync/db/HistoryEntity.kt
 D android/app/src/main/java/com/bunty/clipsync/db/HistoryRepository.kt
 D android/app/src/main/java/com/bunty/clipsync/newhomescreen.kt
 M android/app/src/main/res/values-night/themes.xml
 M android/app/src/main/res/values/strings.xml
 M android/app/src/main/res/values/themes.xml
 M android/app/src/main/res/xml/accessibility_service_config.xml
 D android/app/src/test/java/com/bunty/clipsync/BleControlProtocolTest.kt
 D android/app/src/test/java/com/bunty/clipsync/ClipSyncSenderTransferTest.kt
 D android/app/src/test/java/com/bunty/clipsync/CloudPairingAuthTest.kt
 D android/app/src/test/java/com/bunty/clipsync/FcmTokenPolicyTest.kt
 D android/app/src/test/java/com/bunty/clipsync/OTPNotificationServiceTest.kt
 D android/app/src/test/java/com/bunty/clipsync/TcpFrameProtocolTest.kt
 D android/app/src/test/java/com/bunty/clipsync/TcpTestSupport.kt
 D android/app/src/test/java/com/example/clipsync/ExampleUnitTest.kt
 M android/settings.gradle.kts
 M firebase/firestore.rules
 M firebase/rules-tests/firestore.rules.test.mjs
 M functions/routing.js
 M functions/test/routing.test.js
 M mac/ClipSync.xcodeproj/project.pbxproj
 M mac/ClipSync.xcodeproj/xcshareddata/xcschemes/ClipSync.xcscheme
 M mac/ClipSync/BLEDiscover.swift
 M mac/ClipSync/ClipSync.entitlements
 M mac/ClipSync/ClipSyncApp.swift
 M mac/ClipSync/ClipSyncServer.swift
 M mac/ClipSync/ClipboardManager.swift
 M mac/ClipSync/FCMTokenManager.swift
 M mac/ClipSync/Final.swift
 M mac/ClipSync/FirebaseManager.swift
 M mac/ClipSync/HomeScreen.swift
 M mac/ClipSync/KeychainHelper.swift
 M mac/ClipSync/LandingScreen.swift
 M mac/ClipSync/MacDiagnosticConsole.swift
 M mac/ClipSync/MacUpdateManager.swift
 M mac/ClipSync/PairingManager.swift
 M mac/ClipSync/QRCodeGenerator.swift
 M mac/ClipSync/QRGen.swift
 M mac/ClipSync/RegionConfig.swift.example
 M mac/ClipSync/SecurityScopedResourceManager.swift
 M mac/ClipSync/SplashScreen.swift
 M mac/ClipSync/UpdatePolicy.swift
 M mac/ClipSync/UpdateStager.swift
 M mac/ClipSync/UpdateWindow.swift
 M mac/ClipSync/WakeupReceiver.swift
 M mac/ClipSync/history.swift
 M mac/ClipSyncShare/Base.lproj/ShareViewController.xib
 M mac/ClipSyncShare/ClipSyncShare.entitlements
 M mac/ClipSyncShare/Info.plist
 M mac/ClipSyncShare/SharedViewController.swift
 M mac/PolicyTests/UpdatePolicyTests.swift
 M mac/PolicyTests/main.swift
?? CA_FIREBASE_READINESS.md
?? CROSSIVA_FIREBASE_IMPLEMENTATION.md
?? CROSSIVA_MIGRATION.md
?? IN_FIREBASE_READINESS.md
?? US_FIREBASE_READINESS.md
?? android/app/src/androidTest/java/com/singheverything/crossiva/ExampleInstrumentedTest.kt
?? android/app/src/main/java/com/singheverything/crossiva/AesGcmCipher.kt
?? android/app/src/main/java/com/singheverything/crossiva/AndroidTcpReceiver.kt
?? android/app/src/main/java/com/singheverything/crossiva/AppFloatingToolbar.kt
?? android/app/src/main/java/com/singheverything/crossiva/AppUpdateInstaller.kt
?? android/app/src/main/java/com/singheverything/crossiva/BLEConnector.kt
?? android/app/src/main/java/com/singheverything/crossiva/BLEScanner.kt
?? android/app/src/main/java/com/singheverything/crossiva/BleControlProtocol.kt
?? android/app/src/main/java/com/singheverything/crossiva/BluetoothScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/CameraQRScanner.kt
?? android/app/src/main/java/com/singheverything/crossiva/CancelTransferReceiver.kt
?? android/app/src/main/java/com/singheverything/crossiva/ClipSyncApp.kt
?? android/app/src/main/java/com/singheverything/crossiva/ClipSyncNavBar.kt
?? android/app/src/main/java/com/singheverything/crossiva/ClipSyncSender.kt
?? android/app/src/main/java/com/singheverything/crossiva/ClipboardAccessibilityService.kt
?? android/app/src/main/java/com/singheverything/crossiva/ClipboardGhostActivity.kt
?? android/app/src/main/java/com/singheverything/crossiva/CloudAuth.kt
?? android/app/src/main/java/com/singheverything/crossiva/CloudPairingAuth.kt
?? android/app/src/main/java/com/singheverything/crossiva/Connection.kt
?? android/app/src/main/java/com/singheverything/crossiva/ConnectionDiagnostics.kt
?? android/app/src/main/java/com/singheverything/crossiva/ConnectionRouteCard.kt
?? android/app/src/main/java/com/singheverything/crossiva/DashboardScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/DashboardState.kt
?? android/app/src/main/java/com/singheverything/crossiva/DashboardViewModel.kt
?? android/app/src/main/java/com/singheverything/crossiva/DeviceCard.kt
?? android/app/src/main/java/com/singheverything/crossiva/DeviceManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/DiagnosticConsoleScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/EmailOTPListenerService.kt
?? android/app/src/main/java/com/singheverything/crossiva/FCMTokenManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/FcmTokenPolicy.kt
?? android/app/src/main/java/com/singheverything/crossiva/FirebaseRegion.kt
?? android/app/src/main/java/com/singheverything/crossiva/FirestoreManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/GithubUpdateChecker.kt
?? android/app/src/main/java/com/singheverything/crossiva/HapticUtil.kt
?? android/app/src/main/java/com/singheverything/crossiva/HelperUtils.kt
?? android/app/src/main/java/com/singheverything/crossiva/HistoryScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/Homescreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/LandingScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/LocalNetwork.kt
?? android/app/src/main/java/com/singheverything/crossiva/LocalSyncManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/LocationHelper.kt
?? android/app/src/main/java/com/singheverything/crossiva/MacPushForegroundService.kt
?? android/app/src/main/java/com/singheverything/crossiva/MacPushReceiver.kt
?? android/app/src/main/java/com/singheverything/crossiva/MainActivity.kt
?? android/app/src/main/java/com/singheverything/crossiva/MeshBackground.kt
?? android/app/src/main/java/com/singheverything/crossiva/MyFirebaseMessagingService.kt
?? android/app/src/main/java/com/singheverything/crossiva/NavigationTab.kt
?? android/app/src/main/java/com/singheverything/crossiva/NotificationHelper.kt
?? android/app/src/main/java/com/singheverything/crossiva/OTPListeningService.kt
?? android/app/src/main/java/com/singheverything/crossiva/OTPNotificationService.kt
?? android/app/src/main/java/com/singheverything/crossiva/PairingPage.kt
?? android/app/src/main/java/com/singheverything/crossiva/Permission.kt
?? android/app/src/main/java/com/singheverything/crossiva/PermissionHelper.kt
?? android/app/src/main/java/com/singheverything/crossiva/Permissionpage.kt
?? android/app/src/main/java/com/singheverything/crossiva/ProductIdentity.kt
?? android/app/src/main/java/com/singheverything/crossiva/QRScanScreen.kt
?? android/app/src/main/java/com/singheverything/crossiva/QuickActionsGrid.kt
?? android/app/src/main/java/com/singheverything/crossiva/RecentActivityList.kt
?? android/app/src/main/java/com/singheverything/crossiva/RegionConfig.kt.example
?? android/app/src/main/java/com/singheverything/crossiva/Secrets.kt.example
?? android/app/src/main/java/com/singheverything/crossiva/SettingsRepository.kt
?? android/app/src/main/java/com/singheverything/crossiva/ShareActivity.kt
?? android/app/src/main/java/com/singheverything/crossiva/ShareTransferService.kt
?? android/app/src/main/java/com/singheverything/crossiva/SyncControlsCard.kt
?? android/app/src/main/java/com/singheverything/crossiva/SyncMode.kt
?? android/app/src/main/java/com/singheverything/crossiva/TcpFrameProtocol.kt
?? android/app/src/main/java/com/singheverything/crossiva/Theme.kt
?? android/app/src/main/java/com/singheverything/crossiva/ToolbarItem.kt
?? android/app/src/main/java/com/singheverything/crossiva/UpdateNotificationManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/UrlAllowlistManager.kt
?? android/app/src/main/java/com/singheverything/crossiva/WakeupPing.kt
?? android/app/src/main/java/com/singheverything/crossiva/db/HistoryEntity.kt
?? android/app/src/main/java/com/singheverything/crossiva/db/HistoryRepository.kt
?? android/app/src/main/java/com/singheverything/crossiva/newhomescreen.kt
?? android/app/src/test/java/com/singheverything/crossiva/BleControlProtocolTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/ClipSyncSenderTransferTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/CloudPairingAuthTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/ExampleUnitTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/FcmTokenPolicyTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/FirebaseRegionTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/OTPNotificationServiceTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/TcpFrameProtocolTest.kt
?? android/app/src/test/java/com/singheverything/crossiva/TcpTestSupport.kt
?? mac/ClipSync/FirebaseRegion.swift
?? mac/ClipSync/ProductIdentity.swift
?? tools/prepare_firebase_configs.py
```
