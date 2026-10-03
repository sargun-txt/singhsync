# Crossiva working-tree verification — 2026-10-03

Verified against checkpoint `9be61c4d1538efc679f1b35d2970886132998a57` without staging, committing, signing, or deploying.

## File preservation

- All 80 deleted tracked paths have corresponding owned-namespace replacements: 71 main-source/template files, 8 unit-test/support files, and 1 instrumentation-test file.
- Migrations: `com/bunty/clipsync` and test `com/example/clipsync` -> `com/singheverything/crossiva`; filenames and source-set roles retained.
- 51 replacements are identical after package/import normalization. The other 29 contain intentional identity, Firebase routing/config, or associated test changes.
- 21,171 original lines belong to the 80 moved files. No deleted path is unmatched; no additional tracked source, resource, test or security module is missing.
- Git snapshot rename detection (`--find-renames=20%`) finds 79 probable renames. The rewritten `RegionConfig.kt.example` is manually matched as the 80th move.
- Ordinary `git diff --summary` lists deletions because replacement paths are untracked; it cannot compare them until included in a comparison. Verification used private before/after snapshots, without touching the real index.

## Correction made during verification

An earlier product-name replacement also renamed the QR payload key-derivation label on both clients. Restored the original label in Android `FirestoreManager.kt` and Mac `QRCodeGenerator.swift`. This preserves the existing cryptographic identifier, with no protocol/security redesign. Mac's QR generator now matches the checkpoint exactly.

TCP/BLE v2 codecs, pairing-proof implementation, Android AES/OTP security code, Mac file-security policy and code-signature verifier remain unchanged apart from Android package/import declarations. Ultra-Fast changes are naming/discovery identity changes; authenticated encrypted transfer logic remains present.

## Validation

- Android: 73 unit tests passed, zero failures/errors; real-config Debug assembly succeeded.
- Mac: real-config Xcode Debug build succeeded with signing disabled; 354/354 standalone security/regional policy checks passed. Three ad-hoc-signing fixture checks omitted; test source retained. Positive signature verification used an already installed app.
- Functions: 14/14 routing tests passed.
- Firestore: 23/23 local demo-project emulator tests passed.
- Real CA/US/IN config preparation/equality check passed.
- `git diff --check` passed; real index remains empty.
- Pattern scans of tracked working content, HEAD snapshot and all proposed new files found no Google API keys, private keys, service-account JSON credentials, AWS access keys, GitHub tokens or literal access/refresh tokens. Exact collected Firebase API-key values are absent from all staging candidates.
- No real Firebase runtime config/secret file is tracked. All default/regional exports and runtime loader copies remain gitignored.

These checks establish source preservation and successful local builds/tests; they do not certify physical-device pairing or live cloud sync.

## Prepared staging set and local review artifacts

The exact proposed staging paths, including old-path deletions and replacement additions, are in `.firebase/git-review/stage-paths.txt` and its NUL-delimited counterpart `stage-paths.nul`. Both are ignored local review artifacts, not files to commit. The set includes identity/runtime source, tests, templates, setup tooling and migration/readiness/verification documentation. It excludes all private Firebase exports/runtime configs, runtime loader copies, caches, build outputs, machine config, logs and agent files.

Full initial/final status, ordinary diff summary, all 80 old/new mappings and normalized diff stat are saved in `.firebase/git-review/`. Normalization maps old paths to their verified replacements for line-count comparison and includes proposed new files; it does not alter Git's index or working directories.

Recommended commit message: `Migrate Crossiva identity and Firebase runtime to Canada default`.

Nothing staged or committed. No deployment, IAM mutation, billing/API enablement, release signing, publishing or notarization performed.
