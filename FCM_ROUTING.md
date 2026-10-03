# Regional FCM wake-up routing

Status: source implementation complete; runtime configuration, IAM, deployment and real-device delivery remain unverified. No Firebase projects or credentials were changed.

## SDK evidence

The project uses Firebase BoM 32.7.0. The locally resolved Messaging artifact is `com.google.firebase:firebase-messaging:23.4.0`, with Firebase Common 20.4.2, Installations 17.2.0 and Crashlytics 18.6.0.

Inspection used the installed AAR's `classes.jar` and `javap -p -c`, rather than current SDK source:

```java
public static synchronized FirebaseMessaging getInstance();
static synchronized FirebaseMessaging getInstance(FirebaseApp app);
```

The public method calls `FirebaseApp.getInstance()` (the default app). The overload taking an app is package-private. The Java and Kotlin `MessagingKt` extensions expose only default-app Messaging access; the legacy KTX artifact adds no secondary-app overload. There is no supported public secondary-app Messaging/token API in this version. Reflection or obtaining the internal Messaging component through generic component access is not a supported integration.

The installed `Metadata.getDefaultSenderId` reads `FirebaseOptions.gcmSenderId`; if absent, it derives the project number from `applicationId`. `GmsRpc` requests use that sender ID, the app's Google application ID, and the injected Firebase Installations ID/auth token. The token cache uses app subtype plus sender ID; the default-app subtype is empty, and secondary app subtypes use the Firebase persistence key. Tokens are installation/app/sender scoped opaque strings. Their issuing project cannot be inferred by parsing the token. Project/sender authorization is enforced by FCM on the server.

References: [Messaging API](https://firebase.google.com/docs/reference/android/com/google/firebase/messaging/FirebaseMessaging), [secondary-app API request](https://github.com/firebase/firebase-android-sdk/issues/2285), [sender mismatch](https://firebase.google.com/docs/cloud-messaging/error-codes).

## Architecture decision

Option A is unavailable through supported public APIs in the installed SDK.

Option B is feasible as a separate migration, but would change the default app's project and app name used by Auth/Installations. Firebase persistence keys include both app name and Google application ID. Existing `ClipSyncUS` anonymous identities cannot simply be moved to `[DEFAULT]`. Provider removal alone does not prove safe migration of identities, token caches, Crashlytics pending reports, or generated project-specific Crashlytics release artifacts. This pass does not attempt that migration.

Option C is implemented using the existing India/default project as Android's shared wake-up issuer. No new Firebase project or regional Auth migration is introduced. Only opaque device tokens and wake-up signals use this issuer; clipboard/OTP documents stay in their regional Firestore project.

| Client/selection | Auth and Firestore | FCM issuer/endpoint |
|---|---|---|
| Android IN | default app, `clipsyncind` | default app, `clipsyncind` |
| Android US | named `ClipSyncUS`, `clipsync1-c3c3c` | default app, `clipsyncind` |
| Mac IN | configured default app, India | India |
| Mac US | configured default app, US | US |

Android defaults come from `google-services.json`: project ID, Google app ID, API key and sender/project number. US options come from the gitignored `RegionConfig.kt`; its example derives the sender number from the Google app ID if no sender ID is explicitly supplied. QR `server` determines the regional selection. Missing, unknown or inconsistent project configuration fails closed.

Mac selects its default project through `RegionConfig` at launch, fixes `configuredRegion` for that process, and relaunches for region changes. Its Auth, Firestore, Messaging and token `projectId` remain regional. Mac source is unchanged by this FCM pass.

## Registration and authorization

Android's regional anonymous UID owns `fcmTokens/{uid}` in regional Firestore. Token documents remain unreadable to clients. Android registrations require pairing membership and a server timestamp.

`projectId` always means the actual FCM issuer. New Android records also contain `authProjectId`, `senderId`, `applicationId`, `pairingId`, platform/device/version metadata and `lastUpdated`. For US Android, `projectId` is `clipsyncind` and `authProjectId` is `clipsync1-c3c3c`. This is an explicit shared-issuer registration, never a token labeled as US-issued.

The Function first resolves the other authenticated member of a complete v2 pairing. It then validates:

- Actual Function deployment project is one of the two supported regional projects.
- Android regional identity project and pairing match the triggering pairing.
- Android issuer is the pinned India project, with sender/app IDs matching server configuration.
- Mac issuer matches its regional Function deployment project.
- Registration has a valid token and timestamp no more than 30 days old.

Only after those checks does it select the FCM endpoint. A named Admin app for the shared issuer uses ADC; the default Admin app/database remains regional. Client metadata cannot select arbitrary endpoints. The payload remains `data: {type: "wake_up"}` plus Android priority/APNs background-delivery settings. It contains no clipboard content, pairing ID or UID.

FCM remains responsible for proving the opaque token belongs to the selected issuer. Client metadata alone is not token cryptographic attestation.

## Initialization and lifecycle

`FirebaseInitProvider` is removed in the merged manifest. `firebase_messaging_auto_init_enabled` is false. Hybrid startup manually initializes the same India/default options and only the selected regional app; local-only startup initializes neither. Crashlytics continues to use the same default app/options and existing generated resources; the provider timing change still needs device smoke testing.

First pairing, app launch with a saved pairing, and default-app token refresh trigger registration. Authentication finishes before explicit token retrieval. Registrations are serialized, and delayed results must still match mode, region, pairing, UID and issuer before writing.

Region, mode and pairing changes enqueue removal of the old UID's registration before persisting the new routing state. Write enqueueing and those transitions share a short lock; no lock is held across a network await. Cleanup never signs in or reads token documents. New registrations replace old metadata rather than merge it.

Android region changes do not mutate the default push app, so this solution requires no region restart or UID migration. In-flight Firebase work started while hybrid cannot be retroactively canceled by changing preferences. When the user switches an already cloud-initialized process to local mode, the UI commits the mode, shows an instruction to reopen/rescan, and closes that process before continuing pairing. Reopening starts local mode without any Firebase app. No live deletion/reconfiguration of the default SDK app is attempted. This process boundary and the instruction need device UX validation.

Reinstall/new UID creates a new regional owner. Old pairing membership is never transferred to it; secure re-pair remains required. Old unreachable registrations expire after 30 days. The Function rejects expired registrations immediately, and daily cleanup deletes up to 100 expired records while checking they were not refreshed concurrently. Permanently unregistered tokens are removed conditionally after send failure. Transient failures, IAM errors and sender mismatches never fall back to another project or sender.

Offline unpair/region cleanup is best effort. A queued old registration or an unreachable old UID can remain on the server until cleanup succeeds or expiry applies. It cannot be relabeled or reused for a different pairing by the new registration path.

## Required external configuration — not performed

The repository has one shared Functions source directory. `admin.initializeApp()` uses deployment ADC and regional Firestore. The repository does not establish which projects/functions/service accounts are currently deployed. `firebase/firebase.json` currently configures rules/emulators only, not Functions deployment. Confirm real deployments separately; do not infer them from these sources.

Before rollout:

1. Confirm real default Android config is `clipsyncind`, and US config is `clipsync1-c3c3c`, with valid app IDs and sender numbers. Do not use build placeholders.
2. Configure both regional Function deployments with `ANDROID_PUSH_SENDER_ID` and `ANDROID_PUSH_APP_ID` from the real default Android app. These are public issuer identifiers, not service-account keys. For Firebase CLI dotenv configuration these belong in the deployment-specific Functions environment files, managed by the release operator. Missing/inconsistent identifiers make Android routing fail closed.
3. Identify the **actual runtime service account** for each regional Function; do not assume a service-account name. Enable the FCM API as required. In `clipsyncind`, grant the US Function runtime service account the **Firebase Cloud Messaging API Admin** role (`roles/firebasecloudmessaging.admin`). Ensure the India runtime can send in India and the US runtime can send US Mac tokens in US. These FCM grants do not grant cross-project Firestore access.
4. Use ADC/attached runtime identities. No downloadable private service-account keys are needed in clients or this repository. The US Function targets the India FCM project using its explicitly authorized ADC identity; same-project credentials alone are insufficient.
5. Prepare a deployment config that explicitly points Functions source to `functions` and Firestore rules to `firebase/firestore.rules`, then deploy the shared source/rules separately to each intended project in a later authorized release operation. Preserve project-specific trigger locations/runtime service accounts. The package requires Node 24.
6. Roll out Functions issuer validation and rules before releasing the updated Android registration schema. Existing Android records lacking issuer/pairing metadata are rejected and must be refreshed by updated clients; no legacy fallback is provided. Existing valid Mac records retain the same-project route.
7. Verify the expiry query in both projects. Legacy records lacking `lastUpdated` are rejected but are not selected by the expiry query; identify and remove them during release preparation with an authorized admin operation.

[Firebase's cross-project authorization procedure](https://firebase.google.com/docs/cloud-messaging/send/v1-api#authorize_with_a_service_account_from_a_different_project) requires an explicit target-project FCM IAM grant and the correct target-project endpoint. This code does not assume an arbitrary project's credentials can send to another project's tokens.

## Validation and remaining device checks

Source validation on this pass:

- Android: 69 unit tests passed, including 17 FCM policy tests; debug assemble succeeded with temporary config.
- Functions routing: 13 tests passed, including shared-issuer US/IN routes, regional Mac routes, arbitrary-project rejection, pairing/issuer/expiry checks and wake-up-only payload.
- Firestore emulator: 21 tests passed, including new Android binding checks and retained token read denial.
- Merged manifest: FirebaseInitProvider absent; FCM auto-init disabled.

Option C tests intentionally assert US **Auth/Firestore** selection plus the shared default FCM issuer. A US-issued Android token would require Option A or B; this implementation does not claim to create one.

Live validation remains required: both regional anonymous identities and membership joins; actual default-app token issuance/refresh; US ADC-to-India FCM permission; IN and US Mac/Android delivery; background/doze wake-up and current-regional fetch; local cold start and hybrid/local transition; offline region/unpair ordering; reinstall/re-pair; Crashlytics startup/report ownership; permanent-token cleanup and scheduled expiry. Real credentials/devices are necessary for these checks.
