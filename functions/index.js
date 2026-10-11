"use strict";

/**
 * Anonymous Messaging Platform
 * Backend: Firebase Cloud Functions v2
 * Database: Cloud Firestore
 * Authentication: Firebase Authentication
 *
 * Node.js: 20
 *
 * IMPORTANT:
 * - Never trust a UID or role supplied by the client.
 * - Admin privileges must be assigned by a trusted administrator.
 * - Anonymous sender tokens are pseudonymous, not proof of identity.
 * - Client uploads must also be restricted by Storage Security Rules.
 */

const crypto = require("node:crypto");

const admin = require("firebase-admin");

const {
  onCall,
  HttpsError
} = require("firebase-functions/v2/https");

const {
  setGlobalOptions
} = require("firebase-functions/v2");

const {
  FieldValue,
  Timestamp
} = require("firebase-admin/firestore");

const {
  getAuth
} = require("firebase-admin/auth");

const {
  getStorage
} = require("firebase-admin/storage");

if (!admin.apps.length) {
  admin.initializeApp();
}

setGlobalOptions({
  region: "asia-southeast1",
  maxInstances: 10
});

const db = admin.firestore();
const auth = getAuth();
const storage = getStorage();

/* =========================================================
   CONFIGURATION
========================================================= */

const CONFIG = Object.freeze({
  APP_NAME: "Anonymous Messaging Platform",

  USERNAME_MIN_LENGTH: 3,
  USERNAME_MAX_LENGTH: 24,

  DISPLAY_NAME_MAX_LENGTH: 60,
  BIO_MAX_LENGTH: 300,

  MESSAGE_MAX_LENGTH: 2000,
  REPLY_MAX_LENGTH: 2000,

  MAX_REPORT_REASON_LENGTH: 500,

  MAX_BLOCKED_TOKENS: 1000,

  // Anonymous message limits.
  ANON_MESSAGES_PER_MINUTE: 5,
  ANON_MESSAGES_PER_HOUR: 30,

  // Authenticated user limits.
  USER_ACTIONS_PER_MINUTE: 30,

  // Public reactions.
  REACTIONS_PER_MINUTE: 20,

  // Default public-wall page size.
  WALL_PAGE_SIZE: 20,

  // Maximum analytics range.
  ANALYTICS_MAX_DAYS: 90,

  // Retention settings must be aligned with the published privacy policy.
  RATE_LIMIT_WINDOW_SECONDS: 60,

  ALLOWED_THEMES: [
    "minimal-light",
    "midnight-dark",
    "gradient-modern",
    "soft-pastel"
  ],

  ALLOWED_REACTIONS: [
    "heart",
    "like",
    "smile",
    "support"
  ],

  ALLOWED_HINT_DEVICES: [
    "Android",
    "iOS",
    "Desktop",
    "Unknown"
  ],

  ALLOWED_HINT_BROWSERS: [
    "Chrome",
    "Safari",
    "Firefox",
    "Edge",
    "Other",
    "Unknown"
  ]
});

/* =========================================================
   COMMON HELPERS
========================================================= */

function fail(code, message) {
  throw new HttpsError(code, message);
}

function requireAuth(request) {
  if (!request.auth || !request.auth.uid) {
    fail(
      "unauthenticated",
      "กรุณาเข้าสู่ระบบก่อนใช้งาน"
    );
  }

  return request.auth.uid;
}

function requireVerifiedEmail(request) {
  const uid = requireAuth(request);

  if (request.auth.token.email_verified !== true) {
    fail(
      "failed-precondition",
      "กรุณายืนยันอีเมลก่อนดำเนินการ"
    );
  }

  return uid;
}

function requireAdmin(request) {
  const uid = requireAuth(request);

  // This claim must be assigned by trusted server-side tooling.
  // Never accept request.data.role or a Firestore field
  // controlled by the client as proof of admin privileges.
  if (request.auth.token.admin !== true) {
    fail(
      "permission-denied",
      "คุณไม่มีสิทธิ์ดำเนินการนี้"
    );
  }

  return uid;
}

function cleanString(value, maxLength, fieldName) {
  if (typeof value !== "string") {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ไม่ถูกต้อง`
    );
  }

  const result = value.trim();

  if (!result || result.length > maxLength) {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ต้องมีความยาวไม่เกิน ${maxLength} ตัวอักษร`
    );
  }

  return result;
}

function optionalString(value, maxLength, fieldName) {
  if (value === undefined || value === null) {
    return "";
  }

  if (typeof value !== "string") {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ไม่ถูกต้อง`
    );
  }

  const result = value.trim();

  if (result.length > maxLength) {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ยาวเกินกำหนด`
    );
  }

  return result;
}

function requireBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ต้องเป็น true หรือ false`
    );
  }

  return value;
}

function requirePlainObject(value, fieldName) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    fail(
      "invalid-argument",
      `ข้อมูล ${fieldName} ไม่ถูกต้อง`
    );
  }

  return value;
}

function requireDocumentId(value, fieldName) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]{1,150}$/.test(value)
  ) {
    fail(
      "invalid-argument",
      `รหัส ${fieldName} ไม่ถูกต้อง`
    );
  }

  return value;
}

function normalizeUsername(value) {
  const username = cleanString(
    value,
    CONFIG.USERNAME_MAX_LENGTH,
    "username"
  );

  if (
    username.length < CONFIG.USERNAME_MIN_LENGTH ||
    !/^[A-Za-z0-9_]+$/.test(username)
  ) {
    fail(
      "invalid-argument",
      "Username ต้องมี 3-24 ตัวอักษร และใช้ได้เฉพาะภาษาอังกฤษ ตัวเลข และ _"
    );
  }

  return {
    username,
    usernameLower: username.toLowerCase()
  };
}

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function randomId() {
  return crypto.randomBytes(24).toString("hex");
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function timestampToMillis(value) {
  if (!value) {
    return 0;
  }

  if (typeof value.toMillis === "function") {
    return value.toMillis();
  }

  if (value instanceof Date) {
    return value.getTime();
  }

  return 0;
}

function assertNotSelf(uid, recipientUid) {
  if (uid === recipientUid) {
    fail(
      "invalid-argument",
      "ไม่สามารถดำเนินการกับบัญชีของตนเองในขั้นตอนนี้ได้"
    );
  }
}

async function getActiveUser(uid) {
  const ref = db.collection("users").doc(uid);
  const snap = await ref.get();

  if (!snap.exists) {
    fail(
      "not-found",
      "ไม่พบบัญชีผู้ใช้งาน"
    );
  }

  const user = snap.data();

  if (user.accountStatus === "suspended") {
    fail(
      "permission-denied",
      "บัญชีนี้ถูกระงับการใช้งาน"
    );
  }

  if (user.accountStatus === "deleted") {
    fail(
      "permission-denied",
      "บัญชีนี้ไม่สามารถใช้งานได้"
    );
  }

  return {
    ref,
    data: user
  };
}

async function getPublicProfileByUsername(usernameLower) {
  const usernameRef = db
    .collection("usernames")
    .doc(usernameLower);

  const usernameSnap = await usernameRef.get();

  if (!usernameSnap.exists) {
    fail(
      "not-found",
      "ไม่พบผู้ใช้งานนี้"
    );
  }

  const uid = usernameSnap.get("uid");

  if (typeof uid !== "string" || !uid) {
    fail(
      "not-found",
      "ไม่พบผู้ใช้งานนี้"
    );
  }

  const userRef = db.collection("users").doc(uid);
  const userSnap = await userRef.get();

  if (!userSnap.exists) {
    fail(
      "not-found",
      "ไม่พบผู้ใช้งานนี้"
    );
  }

  const user = userSnap.data();

  if (
    user.accountStatus !== "active" ||
    user.profileVisibility === "private"
  ) {
    fail(
      "not-found",
      "ไม่พบโปรไฟล์นี้"
    );
  }

  return {
    uid,
    ref: userRef,
    data: user
  };
}

/* =========================================================
   AUDIT LOGS
========================================================= */

async function writeAuditLog({
  actorUid,
  action,
  targetUid = null,
  targetType = null,
  targetId = null,
  reason = null,
  metadata = {}
}) {
  const safeMetadata = {};

  // Keep metadata small and do not put message bodies,
  // passwords, access tokens, IP addresses or API secrets here.
  if (
    metadata &&
    typeof metadata === "object" &&
    !Array.isArray(metadata)
  ) {
    for (const [key, value] of Object.entries(metadata)) {
      if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        safeMetadata[key] = value;
      }
    }
  }

  await db.collection("adminAuditLogs").add({
    actorUid,
    action,
    targetUid,
    targetType,
    targetId,
    reason,
    metadata: safeMetadata,
    createdAt: FieldValue.serverTimestamp()
  });
}

/* =========================================================
   RATE LIMITING
========================================================= */

/**
 * Atomic rate-limit counter.
 *
 * This is a basic fixed-window limiter. It is suitable as one
 * layer of protection, but it is not a replacement for App Check,
 * abuse monitoring or a dedicated distributed rate-limiting service.
 *
 * The document ID is a hash to avoid storing the original token
 * in the rate-limit collection.
 */
async function enforceRateLimit({
  key,
  limit,
  windowSeconds,
  errorMessage = "ดำเนินการบ่อยเกินไป กรุณาลองใหม่ภายหลัง"
}) {
  const currentWindow = Math.floor(
    nowSeconds() / windowSeconds
  );

  const docId = hashToken(
    `${key}:${currentWindow}`
  );

  const ref = db
    .collection("rateLimits")
    .doc(docId);

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);

    const count = snap.exists
      ? Number(snap.get("count") || 0)
      : 0;

    if (count >= limit) {
      fail(
        "resource-exhausted",
        errorMessage
      );
    }

    tx.set(
      ref,
      {
        count: count + 1,
        window: currentWindow,
        windowSeconds,
        updatedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );
  });
}

/* =========================================================
   SENDER TOKEN VALIDATION
========================================================= */

/**
 * The client generates a cryptographically random token and keeps
 * it locally. The server stores only a SHA-256 hash.
 *
 * This is a pseudonymous block mechanism. A sender can reset local
 * storage or change browsers, so it cannot guarantee identity.
 */
function validateSenderToken(value) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(value)
  ) {
    fail(
      "invalid-argument",
      "ข้อมูลผู้ส่งไม่ถูกต้อง กรุณาลองใหม่"
    );
  }

  return hashToken(value);
}

/* =========================================================
   1. RESERVE USERNAME
========================================================= */

exports.reserveUsername = onCall(
  {
    enforceAppCheck: true
  },
  async (request) => {
    const uid = requireVerifiedEmail(request);

    const input = requirePlainObject(
      request.data,
      "ข้อมูล"
    );

    const {
      username,
      usernameLower
    } = normalizeUsername(input.username);

    await enforceRateLimit({
      key: `username:${uid}`,
      limit: 5,
      windowSeconds: 3600,
      errorMessage: "เปลี่ยน Username บ่อยเกินไป กรุณาลองใหม่ภายหลัง"
    });

    const userRef = db.collection("users").doc(uid);

    const newUsernameRef = db
      .collection("usernames
