const { onSchedule } = require("firebase-functions/v2/scheduler");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const admin = require("firebase-admin");
const {resolveWakeupTarget, resolveTokenRoute, wakeupMessage, TOKEN_MAX_AGE_MS} = require("./routing");

admin.initializeApp();
const db = admin.firestore();

/**
 * Recursively delete a document and all its subcollections
 * @param {admin.firestore.DocumentReference} docRef - The document reference
 */
async function deleteDocumentWithSubcollections(docRef) {
  const subcollections = await docRef.listCollections();

  for (const subcollection of subcollections) {
    const subcollectionDocs = await subcollection.get();
    for (const doc of subcollectionDocs.docs) {
      await deleteDocumentWithSubcollections(doc.ref);
    }
  }

  await docRef.delete();
}

/**
 * Delete clipboard items older than 2 hours.
 * M5 fix: reduced from 8 hours to limit the exposure window for clipboard data.
 */
exports.cleanupClipboardItems = onSchedule({
  schedule: "every 60 minutes",
  memory: "512MiB",
  timeoutSeconds: 540,
}, async () => {
  console.log("Cleaning clipboardItems");

  const now = admin.firestore.Timestamp.now();
  const twoHoursAgo = admin.firestore.Timestamp.fromMillis(
    now.toMillis() - 2 * 60 * 60 * 1000,
  );

  const snapshot = await db
    .collection("clipboardItems")
    .where("timestamp", "<", twoHoursAgo)
    .limit(100)
    .get();

  if (snapshot.empty) {
    console.log("No old clipboard items");
    return null;
  }

  // Delete in smaller batches to avoid memory issues
  const batchSize = 10;
  for (let i = 0; i < snapshot.docs.length; i += batchSize) {
    const batch = snapshot.docs.slice(i, i + batchSize);
    const deletePromises = batch.map((doc) =>
      deleteDocumentWithSubcollections(doc.ref),
    );
    await Promise.all(deletePromises);
  }

  console.log(
    `Deleted ${snapshot.size} clipboard items with subcollections`,
  );

  return null;
});

/**
 * Delete notifications older than 30 minutes.
 * OTPs are short-lived credentials — keeping them in Firestore for 8 hours
 * is an unnecessary exposure window. 30 minutes is a generous upper bound
 * for any legitimate OTP lifetime.
 */
exports.cleanupNotifications = onSchedule({
  schedule: "every 30 minutes",
  memory: "512MiB",
  timeoutSeconds: 540,
}, async () => {
  console.log("Cleaning notifications");

  const now = admin.firestore.Timestamp.now();
  const thirtyMinutesAgo = admin.firestore.Timestamp.fromMillis(
    now.toMillis() - 30 * 60 * 1000,
  );

  const snapshot = await db
    .collection("notifications")
    .where("timestamp", "<", thirtyMinutesAgo)
    .limit(100)
    .get();

  if (snapshot.empty) {
    console.log("No old notifications");
    return null;
  }

  // Delete in smaller batches to avoid memory issues
  const batchSize = 10;
  for (let i = 0; i < snapshot.docs.length; i += batchSize) {
    const batch = snapshot.docs.slice(i, i + batchSize);
    const deletePromises = batch.map((doc) =>
      deleteDocumentWithSubcollections(doc.ref),
    );
    await Promise.all(deletePromises);
  }

  console.log(
    `Deleted ${snapshot.size} notifications with subcollections`,
  );

  return null;
});

/**
 * Triggers when a new clipboard item is created in Firestore.
 * This happens when BLE/TCP fails and the device falls back to Cloud Sync.
 * The function sends a silent `wake_up` push to the other member of the
 * pairing so it knows to fetch the new clipboard item.
 *
 * Runs with the Admin SDK, which bypasses Firestore security rules, so the
 * client-written item and pairing are re-validated here (see routing.js):
 * routing uses only the pairing's authenticated `members` UIDs, never
 * client-supplied device IDs, and tokens are read from fcmTokens/{uid}.
 */
exports.notifyPairedDevice = onDocumentCreated("clipboardItems/{docId}", async (event) => {
  const snapshot = event.data;
  if (!snapshot) return;

  const item = snapshot.data();
  if (typeof item.pairingId !== "string" || item.pairingId.length === 0 ||
      item.pairingId.length > 128) {
    console.log("Invalid pairingId on clipboard item. Skipping push.");
    return;
  }

  const pairingDoc = await db.collection("pairings").doc(item.pairingId).get();
  if (!pairingDoc.exists) {
    console.log("Pairing document not found. Skipping push.");
    return;
  }

  const destinationUid =
    resolveWakeupTarget(item, pairingDoc.data(), pairingDoc.id);
  if (!destinationUid) {
    console.log("Item is not from a member of a complete v2 pairing. Skipping push.");
    return;
  }

  const tokenDoc = await db.collection("fcmTokens").doc(destinationUid).get();
  const record = tokenDoc.exists ? tokenDoc.data() : null;
  const regionalProjectId = admin.app().options.projectId ||
    process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT;
  const route = resolveTokenRoute(record && {
    ...record,
    lastUpdatedMs: record.lastUpdated && typeof record.lastUpdated.toMillis === "function" ?
      record.lastUpdated.toMillis() : null,
  }, item.pairingId, regionalProjectId, {
    senderId: process.env.ANDROID_PUSH_SENDER_ID,
    applicationId: process.env.ANDROID_PUSH_APP_ID,
  });
  if (!route) {
    console.log("No current, correctly scoped FCM registration for the destination.");
    return;
  }

  // ADC must be explicitly granted FCM send permission in route.projectId.
  // This named app changes only the FCM endpoint; regional Firestore remains `db`.
  const sender = route.projectId === regionalProjectId ? admin.app() :
    (admin.apps.find((app) => app && app.name === `push-${route.projectId}`) ||
      admin.initializeApp({
        credential: admin.credential.applicationDefault(),
        projectId: route.projectId,
      }, `push-${route.projectId}`));
  try {
    await admin.messaging(sender).send(wakeupMessage(route.token));
    console.log("Sent wake_up push to the other pairing member.");
  } catch (error) {
    console.error("Error sending wake_up push.", error.code || "");
    if (error.code === "messaging/registration-token-not-registered") {
      // Do not remove a newer refreshed token that arrived during this send.
      await db.runTransaction(async (transaction) => {
        const latest = await transaction.get(tokenDoc.ref);
        if (latest.exists && latest.data().token === route.token &&
            latest.data().projectId === route.projectId) transaction.delete(tokenDoc.ref);
      });
    }
  }
});

// Offline cleanup/reinstall can leave unreachable identities. Expire their registrations.
exports.cleanupFCMTokens = onSchedule("every 24 hours", async () => {
  const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - TOKEN_MAX_AGE_MS);
  const old = await db.collection("fcmTokens").where("lastUpdated", "<", cutoff).limit(100).get();
  await Promise.all(old.docs.map((doc) => db.runTransaction(async (transaction) => {
    const latest = await transaction.get(doc.ref);
    if (latest.exists && latest.data().lastUpdated &&
        latest.data().lastUpdated.toMillis() < cutoff.toMillis()) transaction.delete(doc.ref);
  })));
});
