const {test} = require("node:test");
const assert = require("node:assert/strict");
const {resolveWakeupTarget, isUsableToken} = require("../routing");

const pairing = (overrides = {}) => ({
  pairingId: "P", version: 2, members: ["A", "M"], ...overrides,
});
const item = (overrides = {}) => ({pairingId: "P", sourceUid: "A", ...overrides});

test("routes to the other member of a complete v2 pairing", () => {
  assert.equal(resolveWakeupTarget(item(), pairing(), "P"), "M");
  assert.equal(resolveWakeupTarget(item({sourceUid: "M"}), pairing(), "P"), "A");
});

test("ignores items whose author is not a member", () => {
  assert.equal(resolveWakeupTarget(item({sourceUid: "S"}), pairing(), "P"), null);
  assert.equal(resolveWakeupTarget(item({sourceUid: undefined}), pairing(), "P"), null);
});

test("ignores pending, legacy, and malformed pairings", () => {
  assert.equal(resolveWakeupTarget(item(), pairing({members: ["A"]}), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({version: undefined}), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({members: undefined}), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({members: ["A", "A"]}), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({members: ["A", "M", "S"]}), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({members: ["A", 7]}), "P"), null);
  // Legacy shape: device IDs are never used for routing.
  assert.equal(resolveWakeupTarget(
      {pairingId: "P", sourceDeviceId: "dev-A"},
      {macDeviceId: "dev-M", androidDeviceId: "dev-A"}, "P"), null);
});

test("ignores pairingId mismatches", () => {
  assert.equal(resolveWakeupTarget(item({pairingId: "Q"}), pairing(), "P"), null);
  assert.equal(resolveWakeupTarget(item(), pairing({pairingId: "Q"}), "P"), null);
});

test("validates tokens", () => {
  assert.equal(isUsableToken("tok"), true);
  assert.equal(isUsableToken(""), false);
  assert.equal(isUsableToken(null), false);
  assert.equal(isUsableToken({token: "x"}), false);
  assert.equal(isUsableToken("x".repeat(5000)), false);
});

const {resolveTokenRoute, wakeupMessage, TOKEN_MAX_AGE_MS} = require("../routing");
const issuer = {senderId: "123456789012", applicationId: "1:123456789012:android:abcdef"};
const now = 1700000000000;
const registration = (overrides = {}) => ({
  token: "token", platform: "android", projectId: "clipsyncind",
  authProjectId: "clipsync1-c3c3c", pairingId: "P",
  senderId: issuer.senderId, applicationId: issuer.applicationId, lastUpdatedMs: now,
  ...overrides,
});

test("US Android uses the explicitly authorized default push endpoint", () => {
  assert.deepEqual(resolveTokenRoute(registration(), "P", "clipsync1-c3c3c", issuer, now),
      {token: "token", projectId: "clipsyncind"});
});
test("India Android uses its default project's endpoint", () => {
  assert.deepEqual(resolveTokenRoute(registration({authProjectId: "clipsyncind"}), "P", "clipsyncind", issuer, now),
      {token: "token", projectId: "clipsyncind"});
});
test("Mac continues to use its own regional project's endpoint", () => {
  assert.deepEqual(resolveTokenRoute(registration({platform: "mac", projectId: "clipsync1-c3c3c"}),
      "P", "clipsync1-c3c3c", {}, now), {token: "token", projectId: "clipsync1-c3c3c"});
  assert.equal(resolveTokenRoute(registration({platform: "mac"}), "P", "clipsync1-c3c3c", issuer, now), null);
});
test("cannot choose an arbitrary project or mislabel an Android token", () => {
  for (const projectId of ["clipsync1-c3c3c", "attacker-project", undefined]) {
    assert.equal(resolveTokenRoute(registration({projectId}), "P", "clipsync1-c3c3c", issuer, now), null);
  }
  assert.equal(resolveTokenRoute(registration(), "P", "attacker-project", issuer, now), null);
});
test("region and pairing transitions cannot reuse old registrations", () => {
  assert.equal(resolveTokenRoute(registration(), "P", "clipsyncind", issuer, now), null);
  assert.equal(resolveTokenRoute(registration(), "new-pair", "clipsync1-c3c3c", issuer, now), null);
});
test("unknown issuer configuration and inconsistent sender IDs fail closed", () => {
  assert.equal(resolveTokenRoute(registration(), "P", "clipsync1-c3c3c", {}, now), null);
  assert.equal(resolveTokenRoute(registration({senderId: "999"}), "P", "clipsync1-c3c3c", issuer, now), null);
  assert.equal(resolveTokenRoute(registration({applicationId: "another-app"}), "P", "clipsync1-c3c3c", issuer, now), null);
});
test("expired, future and unversioned Android registrations fail closed", () => {
  for (const lastUpdatedMs of [null, now + 1, now - TOKEN_MAX_AGE_MS - 1]) {
    assert.equal(resolveTokenRoute(registration({lastUpdatedMs}), "P", "clipsync1-c3c3c", issuer, now), null);
  }
  assert.equal(resolveTokenRoute({token: "old"}, "P", "clipsync1-c3c3c", issuer, now), null);
});
test("push payload carries only a wake-up signal", () => {
  const message = wakeupMessage("token");
  assert.deepEqual(message.data, {type: "wake_up"});
  assert.equal(message.notification, undefined);
  assert.deepEqual(Object.keys(message).sort(), ["android", "apns", "data", "token"]);
});
