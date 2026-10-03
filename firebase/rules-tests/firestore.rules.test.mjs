// Firestore security-rules tests for ../firestore.rules. Runs only against the local emulator:
//
//   cd firebase/rules-tests && npm install && npm test
//
// (npm test wraps `firebase emulators:exec --only firestore --project demo-clipsync`.)
// The "demo-" project prefix keeps the emulator fully offline; nothing touches production.

import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, it } from "node:test";
import {
  assertFails, assertSucceeds, initializeTestEnvironment,
} from "@firebase/rules-unit-testing";
import {
  collection, deleteDoc, doc, getDoc, getDocs, limit, orderBy, query, serverTimestamp,
  setDoc, updateDoc, where, arrayUnion,
} from "firebase/firestore";

const RULES = process.env.FIRESTORE_RULES ?? new URL("../firestore.rules", import.meta.url);
const A = "androidUid_A";       // phone
const M = "macUid_M";           // Mac
const S = "strangerUid_S";      // unrelated authenticated user
const P = "pairingDocP";
const P2 = "otherPairingQ";

let env;

const pending = (overrides = {}) => ({
  pairingId: P, version: 2, members: [A], androidUid: A, macUid: M,
  proof: "a".repeat(64), proofNonce: "b".repeat(32),
  androidDeviceId: "Pixel_1", androidDeviceName: "Pixel", macDeviceId: "MAC-1", macId: "MAC-1",
  macDeviceName: "Mac", createdAt: 1, timestamp: serverTimestamp(), status: "pending",
  ...overrides,
});

const clip = (overrides = {}) => ({
  content: "BASE64CIPHERTEXT==", pairingId: P, sourceDeviceId: "Pixel_1", sourceUid: A,
  timestamp: serverTimestamp(), type: "text", ...overrides,
});

const otp = (overrides = {}) => ({
  type: "OTP_NOTIFICATION", encryptedOTP: "BASE64CIPHERTEXT==", pairingId: P,
  sourceDeviceId: "Pixel_1", sourceDeviceName: "Pixel", sourceUid: A,
  timestamp: serverTimestamp(), ...overrides,
});

const token = (overrides = {}) => ({
  token: "fcm-token", platform: "android", projectId: "crossiva-dev-ca", deviceId: "Pixel_1",
  authProjectId: "crossiva-dev-us", pairingId: P, senderId: "123456789012",
  applicationId: "1:123456789012:android:abcdef",
  deviceName: "Pixel", appVersion: "1", lastUpdated: serverTimestamp(), ...overrides,
});

const db = (uid) => (uid ? env.authenticatedContext(uid) : env.unauthenticatedContext()).firestore();

/** Seeds data with rules disabled (as an already-established state). */
async function seed(fn) {
  await env.withSecurityRulesDisabled(async (ctx) => fn(ctx.firestore()));
}

const activePairing = (id, members) => ({
  pairingId: id, version: 2, members, androidUid: members[0], macUid: members[1] ?? M,
  proof: "a".repeat(64), proofNonce: "b".repeat(32), timestamp: new Date(), status: "active",
});

before(async () => {
  env = await initializeTestEnvironment({
    projectId: "demo-crossiva",
    firestore: { rules: readFileSync(RULES, "utf8") },
  });
});
after(async () => env?.cleanup());
beforeEach(async () => env.clearFirestore());

describe("authentication", () => {
  it("rejects every unauthenticated operation", async () => {
    await seed(async (f) => {
      await setDoc(doc(f, "pairings", P), activePairing(P, [A, M]));
      await setDoc(doc(f, "clipboardItems", "c1"), { ...clip(), timestamp: new Date() });
      await setDoc(doc(f, "notifications", "n1"), { ...otp(), timestamp: new Date() });
      await setDoc(doc(f, "fcmTokens", A), { ...token(), lastUpdated: new Date() });
    });
    const anon = db(null);
    await assertFails(getDoc(doc(anon, "pairings", P)));
    await assertFails(getDocs(query(collection(anon, "pairings"), where("macUid", "==", M))));
    await assertFails(setDoc(doc(anon, "pairings", "new"), pending({ pairingId: "new" })));
    await assertFails(updateDoc(doc(anon, "pairings", P), { status: "active" }));
    await assertFails(deleteDoc(doc(anon, "pairings", P)));
    await assertFails(getDocs(query(collection(anon, "clipboardItems"), where("pairingId", "==", P))));
    await assertFails(setDoc(doc(anon, "clipboardItems", "c2"), clip()));
    await assertFails(deleteDoc(doc(anon, "clipboardItems", "c1")));
    await assertFails(getDocs(query(collection(anon, "notifications"), where("pairingId", "==", P))));
    await assertFails(setDoc(doc(anon, "fcmTokens", A), token()));
    await assertFails(getDoc(doc(anon, "fcmTokens", A)));
  });
});

describe("pairing creation", () => {
  it("lets the phone create a pending pairing as its only member", async () => {
    await assertSucceeds(setDoc(doc(db(A), "pairings", P), pending()));
  });

  it("rejects creations that claim other members, identities, or state", async () => {
    const a = db(A);
    const bad = {
      "both members up front": pending({ members: [A, M] }),
      "someone else as member": pending({ members: [S] }),
      "spoofed androidUid": pending({ androidUid: S }),
      "pairingId != doc id": pending({ pairingId: "other" }),
      "self as macUid": pending({ macUid: A }),
      "already active": pending({ status: "active" }),
      "client timestamp": pending({ timestamp: new Date() }),
      "missing proof": (() => { const p = pending(); delete p.proof; return p; })(),
      "short proof": pending({ proof: "abc" }),
      "extra field": pending({ admin: true }),
      "legacy v1 shape": { androidDeviceId: "x", macId: M, timestamp: serverTimestamp(), status: "active" },
    };
    for (const [label, data] of Object.entries(bad)) {
      await assertFails(setDoc(doc(a, "pairings", P), data), label);
    }
  });

  it("does not let anyone overwrite or claim an existing pairing", async () => {
    await seed(async (f) => setDoc(doc(f, "pairings", P), activePairing(P, [A, M])));
    await assertFails(setDoc(doc(db(S), "pairings", P), pending({ members: [S], androidUid: S, macUid: M })));
    await assertFails(setDoc(doc(db(A), "pairings", P), pending()));
  });
});

describe("pairing read / list", () => {
  beforeEach(async () => seed(async (f) => {
    await setDoc(doc(f, "pairings", P), { ...pending(), timestamp: new Date() });
    await setDoc(doc(f, "pairings", P2), activePairing(P2, ["otherA", "otherM"]));
  }));

  it("members and the addressed Mac can read; strangers cannot", async () => {
    await assertSucceeds(getDoc(doc(db(A), "pairings", P)));
    await assertSucceeds(getDoc(doc(db(M), "pairings", P)));
    await assertSucceeds(getDocs(query(collection(db(M), "pairings"), where("macUid", "==", M))));
    await assertSucceeds(getDocs(query(collection(db(A), "pairings"), where("members", "array-contains", A))));
    await assertFails(getDoc(doc(db(S), "pairings", P)));
  });

  it("strangers cannot discover pairings", async () => {
    const s = db(S);
    await assertFails(getDocs(collection(s, "pairings")));
    await assertFails(getDocs(query(collection(s, "pairings"), where("macUid", "==", M))));
    await assertFails(getDocs(query(collection(s, "pairings"), where("macId", "==", "MAC-1"))));
    await assertFails(getDocs(query(collection(db(M), "pairings"), where("macId", "==", "MAC-1"))));
  });
});

describe("pairing membership changes", () => {
  beforeEach(async () => seed(async (f) => setDoc(doc(f, "pairings", P), { ...pending(), timestamp: new Date() })));

  it("lets only the addressed Mac join, exactly once", async () => {
    await assertFails(updateDoc(doc(db(S), "pairings", P), { members: [A, S], status: "active" }));
    await assertFails(updateDoc(doc(db(A), "pairings", P), { members: [A, S], status: "active" }));
    await assertFails(updateDoc(doc(db(M), "pairings", P), { members: [A, M, S], status: "active" }));
    await assertFails(updateDoc(doc(db(M), "pairings", P), { members: [M, M], status: "active" }));
    await assertFails(updateDoc(doc(db(M), "pairings", P), { members: [A, M], status: "active", macUid: S }));
    await assertSucceeds(updateDoc(doc(db(M), "pairings", P), { members: arrayUnion(M), status: "active" }));
    await assertFails(updateDoc(doc(db(M), "pairings", P), { members: [A, M, M], status: "active" }));
  });

  it("lets the Mac join after the phone already marked the pairing active", async () => {
    await assertSucceeds(updateDoc(doc(db(A), "pairings", P), { status: "active" }));
    await assertSucceeds(updateDoc(doc(db(M), "pairings", P), { members: arrayUnion(M), status: "active" }));
  });

  it("members may only mark the pairing active, and may unpair", async () => {
    await assertSucceeds(updateDoc(doc(db(A), "pairings", P), { status: "active" }));
    await assertFails(updateDoc(doc(db(A), "pairings", P), { macUid: S }));
    await assertFails(updateDoc(doc(db(A), "pairings", P), { members: [A, S] }));
    await assertFails(updateDoc(doc(db(A), "pairings", P), { status: "hijacked" }));
    await assertFails(deleteDoc(doc(db(S), "pairings", P)));
    await assertFails(deleteDoc(doc(db(M), "pairings", P)), "not yet a member");
    await assertSucceeds(deleteDoc(doc(db(A), "pairings", P)));
  });
});

describe("clipboardItems", () => {
  beforeEach(async () => seed(async (f) => {
    await setDoc(doc(f, "pairings", P), activePairing(P, [A, M]));
    await setDoc(doc(f, "pairings", P2), activePairing(P2, [S, "otherM"]));
    await setDoc(doc(f, "clipboardItems", "existing"), { ...clip(), timestamp: new Date() });
  }));

  it("members create, read, and delete their pairing's items", async () => {
    await assertSucceeds(setDoc(doc(db(A), "clipboardItems", "c1"), clip()));
    await assertSucceeds(setDoc(doc(db(M), "clipboardItems", "c2"), clip({ sourceUid: M, sourceDeviceId: "MAC-1" })));
    await assertSucceeds(getDocs(query(collection(db(M), "clipboardItems"),
      where("pairingId", "==", P), orderBy("timestamp", "desc"), limit(1))));
    await assertSucceeds(deleteDoc(doc(db(A), "clipboardItems", "existing")));
  });

  it("denies non-members, pairingId substitution, spoofing, and malformed items", async () => {
    await assertFails(setDoc(doc(db(S), "clipboardItems", "x"), clip({ sourceUid: S })));
    await assertFails(setDoc(doc(db(S), "clipboardItems", "x"), clip({ sourceUid: S, pairingId: P })));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ pairingId: P2 })), "pairingId substitution");
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ pairingId: "missing" })));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ sourceUid: M })), "sourceUid spoof");
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ type: "file" })));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ content: 42 })));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ timestamp: new Date() })));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ plaintext: "secret" })));
    const noContent = clip(); delete noContent.content;
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), noContent));
    await assertFails(getDocs(query(collection(db(S), "clipboardItems"), where("pairingId", "==", P))));
    await assertFails(getDocs(collection(db(A), "clipboardItems")), "unfiltered listing");
    await assertFails(getDoc(doc(db(S), "clipboardItems", "existing")));
    await assertFails(deleteDoc(doc(db(S), "clipboardItems", "existing")));
    await assertFails(updateDoc(doc(db(A), "clipboardItems", "existing"), { content: "x" }));
  });

  it("denies everything for a legacy pairing without members", async () => {
    await seed(async (f) => setDoc(doc(f, "pairings", "legacy"), {
      androidDeviceId: "Pixel_1", macId: "MAC-1", status: "active", timestamp: new Date(),
    }));
    await assertFails(getDoc(doc(db(A), "pairings", "legacy")));
    await assertFails(setDoc(doc(db(A), "clipboardItems", "x"), clip({ pairingId: "legacy" })));
  });
});

describe("notifications", () => {
  beforeEach(async () => seed(async (f) => {
    await setDoc(doc(f, "pairings", P), activePairing(P, [A, M]));
    await setDoc(doc(f, "pairings", P2), activePairing(P2, [S, "otherM"]));
  }));

  it("allows correctly scoped member operations", async () => {
    await assertSucceeds(setDoc(doc(db(A), "notifications", "n1"), otp()));
    await assertSucceeds(getDocs(query(collection(db(M), "notifications"),
      where("pairingId", "==", P), where("type", "==", "OTP_NOTIFICATION"))));
  });

  it("rejects cross-pairing and malformed operations", async () => {
    await assertFails(setDoc(doc(db(A), "notifications", "n1"), otp({ pairingId: P2 })));
    await assertFails(setDoc(doc(db(S), "notifications", "n1"), otp({ sourceUid: S })));
    await assertFails(setDoc(doc(db(A), "notifications", "n1"), otp({ type: "OTHER" })));
    await assertFails(setDoc(doc(db(A), "notifications", "n1"), otp({ encryptedOTP: "" })));
    await assertFails(setDoc(doc(db(A), "notifications", "n1"), otp({ otp: "123456" })), "plaintext field");
    await assertFails(getDocs(query(collection(db(S), "notifications"),
      where("pairingId", "==", P), where("type", "==", "OTP_NOTIFICATION"))));
  });
});

describe("fcmTokens", () => {
  beforeEach(async () => seed(async (f) => {
    await setDoc(doc(f, "pairings", P), activePairing(P, [A, M]));
    await setDoc(doc(f, "fcmTokens", A), { ...token(), lastUpdated: new Date() });
  }));

  it("lets a client register and remove only its own token", async () => {
    await assertSucceeds(setDoc(doc(db(M), "fcmTokens", M), token({ platform: "mac" }), { merge: true }));
    await assertSucceeds(setDoc(doc(db(A), "fcmTokens", A), token({ token: "rotated" }), { merge: true }));
    await assertSucceeds(deleteDoc(doc(db(A), "fcmTokens", A)));
  });

  it("never exposes or lets others overwrite tokens", async () => {
    await assertFails(getDoc(doc(db(A), "fcmTokens", A)), "even the owner cannot read back");
    await assertFails(getDoc(doc(db(S), "fcmTokens", A)));
    await assertFails(getDocs(collection(db(S), "fcmTokens")));
    await assertFails(getDocs(query(collection(db(S), "fcmTokens"), where("deviceId", "==", "Pixel_1"))));
    await assertFails(setDoc(doc(db(S), "fcmTokens", A), token({ token: "attacker" })));
    await assertFails(deleteDoc(doc(db(S), "fcmTokens", A)));
    await assertFails(setDoc(doc(db(S), "fcmTokens", S), token({ platform: "web" })));
    await assertFails(setDoc(doc(db(S), "fcmTokens", S), token({ extra: 1 })));
  });

  it("permits truthful shared-issuer registration for a US authenticated member", async () => {
    await assertSucceeds(setDoc(doc(db(A), "fcmTokens", A), token()));
  });

  it("rejects mislabeled or unknown Android push projects", async () => {
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), token({projectId: "crossiva-dev-us"})));
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), token({authProjectId: "unknown"})));
  });

  it("rejects Android registration bound to a nonmember pairing", async () => {
    await assertFails(setDoc(doc(db(S), "fcmTokens", S), token()));
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), token({pairingId: "missing"})));
  });

  it("requires Android issuer metadata and a server registration timestamp", async () => {
    const missing = token(); delete missing.senderId;
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), missing));
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), token({lastUpdated: new Date()})));
  });

});

describe("everything else", () => {
  it("denies the unused fileTransfers collection and unknown paths", async () => {
    await assertFails(getDocs(collection(db(A), "fileTransfers")));
    await assertFails(setDoc(doc(db(A), "fileTransfers", "f"), { pairingId: P }));
    await assertFails(setDoc(doc(db(A), "anything", "x"), { a: 1 }));
  });
});


describe("Canada shared FCM issuer", () => {
  it("accepts all regional Auth projects while pinning the Canada issuer", async () => {
    await seed(async f => setDoc(doc(f, "pairings", P), activePairing(P, [A, M])));
    for (const authProjectId of ["crossiva-dev-ca", "crossiva-dev-us", "crossiva-dev-in"]) {
      await assertSucceeds(setDoc(doc(db(A), "fcmTokens", A), token({authProjectId})));
    }
    await assertFails(setDoc(doc(db(A), "fcmTokens", A), token({projectId: "crossiva-dev-in"})));
  });
  it("Mac tokens also require a Canada issuer and known regional identity", async () => {
    await assertSucceeds(setDoc(doc(db(M), "fcmTokens", M), token({platform: "mac"})));
    await assertFails(setDoc(doc(db(M), "fcmTokens", M), token({platform: "mac", projectId: "crossiva-dev-us"})));
    await assertFails(setDoc(doc(db(M), "fcmTokens", M), token({platform: "mac", authProjectId: "foreign"})));
  });
});
