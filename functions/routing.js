/**
 * Pure routing/validation helpers for Cloud Functions (no Firebase imports, so
 * they can be unit tested with `node --test`).
 *
 * Cloud Functions use the Admin SDK and bypass Firestore security rules, so
 * anything they read from client-written documents must be re-validated here.
 */

const UID_MAX = 128;
const TOKEN_MAX = 4096;

/**
 * @param {*} v - value to check
 * @param {number} max - maximum length
 * @return {boolean} whether v is a non-empty string no longer than max
 */
function isShortString(v, max) {
  return typeof v === "string" && v.length > 0 && v.length <= max;
}

/**
 * Picks the pairing member that should receive a wake-up push for a new
 * clipboard item. Only a v2 pairing with exactly two members qualifies, and
 * the item's author must be one of them; the other member is the target.
 * Device IDs and other free-form fields are never used for routing.
 *
 * @param {Object} item - the clipboardItems document data
 * @param {Object} pairing - the pairings document data
 * @param {string} pairingDocId - the pairing document ID
 * @return {?string} the destination UID, or null if nothing should be sent
 */
function resolveWakeupTarget(item, pairing, pairingDocId) {
  if (!item || !pairing) return null;
  if (!isShortString(item.pairingId, UID_MAX)) return null;
  if (!isShortString(item.sourceUid, UID_MAX)) return null;
  if (item.pairingId !== pairingDocId) return null;
  if (pairing.version !== 2 || pairing.pairingId !== pairingDocId) {
    return null;
  }
  const members = pairing.members;
  if (!Array.isArray(members) || members.length !== 2) return null;
  if (!members.every((m) => isShortString(m, UID_MAX))) return null;
  if (members[0] === members[1]) return null;
  if (!members.includes(item.sourceUid)) return null;
  return members.find((m) => m !== item.sourceUid);
}

/**
 * @param {*} token - the stored FCM registration token
 * @return {boolean} whether it looks like a usable token
 */
function isUsableToken(token) {
  return isShortString(token, TOKEN_MAX);
}

module.exports = {resolveWakeupTarget, isUsableToken};

const CANADA_PROJECT = "crossiva-dev-ca";
const INDIA_PROJECT = "crossiva-dev-in";
const US_PROJECT = "crossiva-dev-us";
const TOKEN_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Selects only a known FCM issuer. Android has a shared default-app issuer;
 * Mac tokens also originate from the Canada default app. Client metadata never chooses arbitrary projects.
 * @param {Object} record token document plus numeric lastUpdatedMs
 * @param {string} pairingId pairing whose other member is the destination
 * @param {string} regionalProjectId actual Function deployment project
 * @param {Object} androidIssuer server-configured senderId/applicationId
 * @param {number} nowMs current time
 * @return {?Object} validated token and target FCM project
 */
function resolveTokenRoute(record, pairingId, regionalProjectId,
    androidIssuer, nowMs = Date.now()) {
  if (![CANADA_PROJECT, INDIA_PROJECT, US_PROJECT].includes(regionalProjectId)) return null;
  if (!record || !isUsableToken(record.token)) return null;
  if (!Number.isFinite(record.lastUpdatedMs) ||
      record.lastUpdatedMs > nowMs ||
      nowMs - record.lastUpdatedMs > TOKEN_MAX_AGE_MS) return null;
  if (record.platform === "android") {
    if (record.authProjectId !== regionalProjectId ||
        record.projectId !== CANADA_PROJECT || record.pairingId !== pairingId) return null;
    if (!androidIssuer || !isShortString(androidIssuer.senderId, 32) ||
        !/^\d+$/.test(androidIssuer.senderId) ||
        !isShortString(androidIssuer.applicationId, 256) ||
        !androidIssuer.applicationId.startsWith(`1:${androidIssuer.senderId}:android:`)) return null;
    if (record.senderId !== androidIssuer.senderId ||
        record.applicationId !== androidIssuer.applicationId) return null;
    return {token: record.token, projectId: CANADA_PROJECT};
  }
  if (record.platform === "mac" && record.projectId === CANADA_PROJECT &&
      record.authProjectId === regionalProjectId) {
    return {token: record.token, projectId: CANADA_PROJECT};
  }
  return null;
}

/** @param {string} token destination token @return {Object} wake-up-only FCM message */
function wakeupMessage(token) {
  return {
    token,
    data: {type: "wake_up"},
    android: {priority: "high"},
    apns: {payload: {aps: {"content-available": 1}}},
  };
}

module.exports.resolveTokenRoute = resolveTokenRoute;
module.exports.wakeupMessage = wakeupMessage;
module.exports.TOKEN_MAX_AGE_MS = TOKEN_MAX_AGE_MS;
