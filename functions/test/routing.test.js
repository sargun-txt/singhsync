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
  token: "token", platform: "android", projectId: "crossiva-dev-ca",
  authProjectId: "crossiva-dev-us", pairingId: "P",
  senderId: issuer.senderId, applicationId: issuer.applicationId, lastUpdatedMs: now,
  ...overrides,
});

test("US Android uses the explicitly authorized default push endpoint", () => {
  assert.deepEqual(resolveTokenRoute(registration(), "P", "crossiva-dev-us", issuer, now),
      {token: "token", projectId: "crossiva-dev-ca"});
});
test("India Android uses Canada's shared endpoint", () => {
  assert.deepEqual(resolveTokenRoute(registration({authProjectId: "crossiva-dev-in"}), "P", "crossiva-dev-in", issuer, now),
      {token: "token", projectId: "crossiva-dev-ca"});
});
test("Mac uses Canada issuer with regional Auth", () => {
  assert.deepEqual(resolveTokenRoute(registration({platform: "mac", projectId: "crossiva-dev-ca"}),
      "P", "crossiva-dev-us", {}, now), {token: "token", projectId: "crossiva-dev-ca"});
  assert.equal(resolveTokenRoute(registration({platform: "mac", authProjectId: "crossiva-dev-in"}), "P", "crossiva-dev-us", issuer, now), null);
});
test("cannot choose an arbitrary project or mislabel an Android token", () => {
  for (const projectId of ["crossiva-dev-us", "attacker-project", undefined]) {
    assert.equal(resolveTokenRoute(registration({projectId}), "P", "crossiva-dev-us", issuer, now), null);
  }
  assert.equal(resolveTokenRoute(registration(), "P", "attacker-project", issuer, now), null);
});
test("region and pairing transitions cannot reuse old registrations", () => {
  assert.equal(resolveTokenRoute(registration(), "P", "crossiva-dev-in", issuer, now), null);
  assert.equal(resolveTokenRoute(registration(), "new-pair", "crossiva-dev-us", issuer, now), null);
});
test("unknown issuer configuration and inconsistent sender IDs fail closed", () => {
  assert.equal(resolveTokenRoute(registration(), "P", "crossiva-dev-us", {}, now), null);
  assert.equal(resolveTokenRoute(registration({senderId: "999"}), "P", "crossiva-dev-us", issuer, now), null);
  assert.equal(resolveTokenRoute(registration({applicationId: "another-app"}), "P", "crossiva-dev-us", issuer, now), null);
});
test("expired, future and unversioned Android registrations fail closed", () => {
  for (const lastUpdatedMs of [null, now + 1, now - TOKEN_MAX_AGE_MS - 1]) {
    assert.equal(resolveTokenRoute(registration({lastUpdatedMs}), "P", "crossiva-dev-us", issuer, now), null);
  }
  assert.equal(resolveTokenRoute({token: "old"}, "P", "crossiva-dev-us", issuer, now), null);
});
test("push payload carries only a wake-up signal", () => {
  const message = wakeupMessage("token");
  assert.deepEqual(message.data, {type: "wake_up"});
  assert.equal(message.notification, undefined);
  assert.deepEqual(Object.keys(message).sort(), ["android", "apns", "data", "token"]);
});

test("all regional Auth backends route Android through Canada", () => {
  for (const authProjectId of ["crossiva-dev-ca", "crossiva-dev-us", "crossiva-dev-in"]) {
    assert.deepEqual(resolveTokenRoute(registration({authProjectId}), "P", authProjectId, issuer, now),
      {token: "token", projectId: "crossiva-dev-ca"});
  }
});
