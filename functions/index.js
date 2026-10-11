const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

// Initialize Firebase Admin SDK
admin.initializeApp();
const db = admin.firestore();

// ----------------------------------------------------------------------
// Helper Functions: การตรวจสอบสิทธิ์และความปลอดภัย
// ----------------------------------------------------------------------

/**
 * ตรวจสอบว่าผู้ใช้เข้าสู่ระบบหรือยัง
 */
const requireAuth = (request) => {
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "ต้องเข้าสู่ระบบก่อนใช้งานฟังก์ชันนี้");
    }
};

/**
 * ตรวจสอบว่าเป็นผู้ดูแลระบบ (Admin) หรือไม่
 */
const requireAdmin = (request) => {
    requireAuth(request);
    // ตรวจสอบ Custom Claims ว่ามีสิทธิ์ admin หรือไม่ (ต้องถูกกำหนดผ่าน Backend ก่อน)
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "ปฏิเสธการเข้าถึง: สำหรับผู้ดูแลระบบเท่านั้น");
    }
};

// ----------------------------------------------------------------------
// 1. sendAnonymousMessage : ส่งข้อความนิรนาม (ตรวจสอบสแปมและ Rate Limit)
// ----------------------------------------------------------------------
exports.sendAnonymousMessage = onCall(async (request) => {
    const { receiverUid, content, imageUrl, voiceUrl, voiceEffect, senderToken, hint } = request.data;
    
    // Validate Input
    if (!receiverUid) {
        throw new HttpsError("invalid-argument", "ไม่พบข้อมูลผู้รับข้อความ");
    }
    if (!content && !imageUrl && !voiceUrl) {
        throw new HttpsError("invalid-argument", "ต้องมีข้อความ รูปภาพ หรือข้อความเสียงอย่างใดอย่างหนึ่ง");
    }
    if (content && content.length > 1000) {
        throw new HttpsError("invalid-argument", "ความยาวข้อความเกิน 1000 ตัวอักษร");
    }

    // Rate Limit (ป้องกัน Spam ด้วย IP Address และ Token)
    const ip = request.rawRequest.ip || "unknown_ip";
    const tokenToBlock = senderToken || "anonymous";
    const ipSafeId = ip.replace(/[^a-zA-Z0-9]/g, '_');
    
    const rateLimitRef = db.collection("rateLimits").doc(ipSafeId);
    
    await db.runTransaction(async (t) => {
        const doc = await t.get(rateLimitRef);
        const now = Date.now();
        if (doc.exists) {
            const data = doc.data();
            // จำกัด 5 ข้อความ ภายใน 1 นาที
            if (now - data.timestamp < 60000 && data.count >= 5) {
                throw new HttpsError("resource-exhausted", "คุณส่งข้อความเร็วเกินไป กรุณารอสักครู่");
            }
            if (now - data.timestamp >= 60000) {
                t.set(rateLimitRef, { count: 1, timestamp: now }); // รีเซ็ตเวลา
            } else {
                t.update(rateLimitRef, { count: admin.firestore.FieldValue.increment(1) });
            }
        } else {
            t.set(rateLimitRef, { count: 1, timestamp: now });
        }
    });

    // ตรวจสอบ Block List (ผู้รับบล็อก Token นี้ไว้หรือไม่)
    const blockRef = db.collection("blocks").where("uid", "==", receiverUid).where("token", "==", tokenToBlock);
    const blockSnap = await blockRef.get();
    if (!blockSnap.empty) {
        // หากถูกบล็อก ให้ทำทีว่าส่งสำเร็จ เพื่อไม่ให้สแปมเมอร์รู้ตัวว่าถูกบล็อก
        return { success: true, status: "dropped_silently" };
    }

    // ตรวจสอบสถานะรับข้อความของผู้รับ
    const userRef = db.collection("users").doc(receiverUid);
    const userSnap = await userRef.get();
    if (!userSnap.exists || userSnap.data().acceptsMessages === false) {
        throw new HttpsError("failed-precondition", "ผู้ใช้รายนี้ปิดรับข้อความชั่วคราว");
    }

    // บันทึกข้อความลง Database
    const msgRef = await db.collection("messages").add({
        receiverUid: receiverUid,
        content: content ? content.trim() : "",
        imageUrl: imageUrl || null,
        voiceUrl: voiceUrl || null,
        voiceEffect: voiceEffect || "none",
        senderToken: tokenToBlock,
        hint: hint || "ไม่ทราบอุปกรณ์",
        isRead: false,
        isPublic: false,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true, messageId: msgRef.id };
});

// ----------------------------------------------------------------------
// 2. reserveUsername : จองชื่อผู้ใช้ (ป้องกันการแย่งชื่อซ้ำพร้อมกันด้วย Transaction)
// ----------------------------------------------------------------------
exports.reserveUsername = onCall(async (request) => {
    requireAuth(request);
    const { username } = request.data;
    const uid = request.auth.uid;
    
    // ตรวจสอบรูปแบบ (อังกฤษ/ตัวเลข 3-15 ตัว)
    if (!/^[a-z0-9_]{3,15}$/.test(username)) {
        throw new HttpsError("invalid-argument", "รูปแบบ Username ไม่ถูกต้อง");
    }

    const unameRef = db.collection("usernames").doc(username);
    const userRef = db.collection("users").doc(uid);

    await db.runTransaction(async (t) => {
        const doc = await t.get(unameRef);
        if (doc.exists && doc.data().uid !== uid) {
            throw new HttpsError("already-exists", "Username นี้ถูกใช้งานแล้ว");
        }
        // บันทึกการจองและอัปเดตโปรไฟล์
        t.set(unameRef, { uid: uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });
        t.set(userRef, { username: username, usernameLower: username.toLowerCase() }, { merge: true });
    });

    return { success: true };
});

// ----------------------------------------------------------------------
// 3. blockSenderToken : บล็อกผู้ส่งนิรนาม
// ----------------------------------------------------------------------
exports.blockSenderToken = onCall(async (request) => {
    requireAuth(request);
    const { token } = request.data;
    
    if (!token) {
        throw new HttpsError("invalid-argument", "ไม่พบ Token สำหรับการบล็อก");
    }

    await db.collection("blocks").add({
        uid: request.auth.uid,
        token: token,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    return { success: true };
});

// ----------------------------------------------------------------------
// 4. submitReport : รายงานเนื้อหาไม่เหมาะสม
// ----------------------------------------------------------------------
exports.submitReport = onCall(async (request) => {
    requireAuth(request);
    const { messageId, reason } = request.data;
    
    if (!messageId || !reason) {
        throw new HttpsError("invalid-argument", "ข้อมูลการรายงานไม่ครบถ้วน");
    }

    await db.collection("reports").add({
        reporterUid: request.auth.uid,
        messageId: messageId,
        reason: reason,
        status: "pending",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    return { success: true };
});

// ----------------------------------------------------------------------
// 5. publishWallMessage : นำข้อความขึ้นกระดานสาธารณะ
// ----------------------------------------------------------------------
exports.publishWallMessage = onCall(async (request) => {
    requireAuth(request);
    const { messageId } = request.data;
    const uid = request.auth.uid;

    const msgRef = db.collection("messages").doc(messageId);
    const msgSnap = await msgRef.get();

    // ตรวจสอบสิทธิ์ว่าเจ้าของข้อความคือคนสั่งหรือไม่
    if (!msgSnap.exists || msgSnap.data().receiverUid !== uid) {
        throw new HttpsError("permission-denied", "คุณไม่มีสิทธิ์เผยแพร่ข้อความนี้");
    }

    await db.collection("publicWall").doc(messageId).set({
        uid: uid,
        content: msgSnap.data().content,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        reactions: 0
    });

    // อัปเดตสถานะที่ต้นฉบับ
    await msgRef.update({ isPublic: true });
    return { success: true };
});

// ----------------------------------------------------------------------
// 6. toggleReaction : กดรีแอคชันบนกระดาน (อนุญาตทุกคน ไม่ต้อง Auth)
// ----------------------------------------------------------------------
exports.toggleReaction = onCall(async (request) => {
    const { messageId } = request.data;
    if (!messageId) {
        throw new HttpsError("invalid-argument", "ไม่พบข้อมูลข้อความ");
    }

    // ในระบบจริงอาจใช้ Cookie/IP ป้องกันการรัวปุ่ม แต่เพื่อความรวดเร็วใช้ FieldValue Increment
    const wallRef = db.collection("publicWall").doc(messageId);
    await wallRef.update({
        reactions: admin.firestore.FieldValue.increment(1)
    });
    
    return { success: true };
});

// ----------------------------------------------------------------------
// 7. submitReply : ตอบกลับข้อความ
// ----------------------------------------------------------------------
exports.submitReply = onCall(async (request) => {
    requireAuth(request);
    const { messageId, content } = request.data;
    const uid = request.auth.uid;

    if (!content) {
        throw new HttpsError("invalid-argument", "ไม่พบเนื้อหาการตอบกลับ");
    }

    const msgRef = db.collection("messages").doc(messageId);
    const msgSnap = await msgRef.get();
    
    if (!msgSnap.exists || msgSnap.data().receiverUid !== uid) {
        throw new HttpsError("permission-denied", "คุณไม่มีสิทธิ์ตอบกลับข้อความนี้");
    }

    await db.collection("replies").add({
        messageId: messageId,
        uid: uid,
        content: content,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    
    return { success: true };
});

// ----------------------------------------------------------------------
// 8. getUserAnalytics : ดึงข้อมูลสถิติรวมฝั่งเซิร์ฟเวอร์ (ประหยัด Read Operations)
// ----------------------------------------------------------------------
exports.getUserAnalytics = onCall(async (request) => {
    requireAuth(request);
    const uid = request.auth.uid;

    // ใช้ Aggregation Query (นับจำนวนโดยไม่ต้องโหลดเอกสารทั้งหมด)
    const msgsRef = db.collection("messages").where("receiverUid", "==", uid);
    
    const [totalSnap, unreadSnap] = await Promise.all([
        msgsRef.count().get(),
        msgsRef.where("isRead", "==", false).count().get()
    ]);
    
    return {
        totalMessages: totalSnap.data().count,
        unreadMessages: unreadSnap.data().count
    };
});

// ----------------------------------------------------------------------
// 9. Admin: อัปเดตสถานะบัญชี (ระงับ/ยกเลิก)
// ----------------------------------------------------------------------
exports.adminUpdateUserStatus = onCall(async (request) => {
    requireAdmin(request);
    const { uid, status } = request.data;
    
    if (!uid || !status) {
        throw new HttpsError("invalid-argument", "ข้อมูลไม่ครบถ้วน");
    }

    await db.collection("users").doc(uid).update({ accountStatus: status });
    
    // บันทึก Log การทำงานของแอดมิน
    await db.collection("adminAuditLogs").add({
        adminUid: request.auth.uid,
        action: "UPDATE_USER_STATUS",
        targetUid: uid,
        details: { status: status },
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true };
});

// ----------------------------------------------------------------------
// 10. Admin: จัดการเนื้อหา/รายงาน
// ----------------------------------------------------------------------
exports.adminModerateContent = onCall(async (request) => {
    requireAdmin(request);
    const { collectionName, docId, action } = request.data;
    
    if (!collectionName || !docId || !action) {
        throw new HttpsError("invalid-argument", "ข้อมูลไม่ครบถ้วน");
    }

    const docRef = db.collection(collectionName).doc(docId);

    if (action === "delete") {
        await docRef.delete();
    } else if (action === "resolve_report") {
        await db.collection("reports").doc(docId).update({ status: "resolved" });
    }

    await db.collection("adminAuditLogs").add({
        adminUid: request.auth.uid,
        action: "MODERATE_CONTENT",
        target: `${collectionName}/${docId}`,
        details: { action: action },
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true };
});

// ----------------------------------------------------------------------
// 11. Admin: ลบบัญชีผู้ใช้ออกจากระบบถาวร (รวม Auth)
// ----------------------------------------------------------------------
exports.adminDeleteAccount = onCall(async (request) => {
    requireAdmin(request);
    const { uid } = request.data;
    if (!uid) throw new HttpsError("invalid-argument", "ระบุ UID ไม่ถูกต้อง");
    
    // 1. ลบจาก Firebase Authentication
    try {
        await admin.auth().deleteUser(uid);
    } catch (e) {
        console.error("Auth delete error:", e);
    }
    
    // 2. ลบเอกสาร User Profile
    await db.collection("users").doc(uid).delete();
    
    // หมายเหตุ: ระบบขนาดใหญ่ควรสร้าง Background Trigger เพื่อไล่ลบข้อความ (messages) หรือไฟล์ (storage)
    // แต่สำหรับการทำงานเบื้องต้น การลบ Auth ป้องกันการเข้าสู่ระบบแล้ว
    
    await db.collection("adminAuditLogs").add({
        adminUid: request.auth.uid,
        action: "DELETE_ACCOUNT",
        targetUid: uid,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true };
});
