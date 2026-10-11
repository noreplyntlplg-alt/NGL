const { onRequest, onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
admin.initializeApp();
const db = admin.firestore();

// 1. Reserve Username (ระบบจองชื่อผู้ใช้แบบ Transaction ป้องกันการซ้ำ)
exports.reserveUsername = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError('unauthenticated', 'กรุณาเข้าสู่ระบบก่อนดำเนินการ');
    }
    const { username, displayName } = request.data;
    const uid = request.auth.uid;
    
    if (!username || typeof username !== 'string') {
        throw new HttpsError('invalid-argument', 'กรุณาระบุ Username ให้ถูกต้อง');
    }

    const usernameLower = username.toLowerCase().trim();

    if (!/^[a-z0-9_]{3,20}$/.test(usernameLower)) {
        throw new HttpsError('invalid-argument', 'Username ต้องเป็นตัวอักษรภาษาอังกฤษ ตัวเลข หรือขีดล่าง ความยาว 3-20 ตัวอักษร');
    }

    const usernameRef = db.collection('usernames').doc(usernameLower);
    const userRef = db.collection('users').doc(uid);

    return db.runTransaction(async (transaction) => {
        const usernameDoc = await transaction.get(usernameRef);
        if (usernameDoc.exists) {
            throw new HttpsError('already-exists', 'Username นี้ถูกใช้งานไปแล้ว');
        }

        const currentUserDoc = await transaction.get(userRef);
        if (currentUserDoc.exists && currentUserDoc.data().usernameLower) {
            const oldUsernameLower = currentUserDoc.data().usernameLower;
            if (oldUsernameLower !== usernameLower) {
                transaction.delete(db.collection('usernames').doc(oldUsernameLower));
            }
        }

        transaction.set(usernameRef, { uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });
        transaction.set(userRef, {
            uid,
            username: username.trim(),
            usernameLower,
            displayName: (displayName || 'Vortex User').trim(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return { success: true, message: 'จอง Username สำเร็จ' };
    });
});

// 2. Send Anonymous Message (ระบบส่งข้อความนิรนามพร้อมตรวจสอบการบล็อกและสถานะผู้รับ)
exports.sendAnonymousMessage = onCall(async (request) => {
    const { recipientUid, content, imageUrl, senderToken, userAgent } = request.data;

    if (!recipientUid || !content || typeof content !== 'string') {
        throw new HttpsError('invalid-argument', 'ข้อมูลไม่ครบถ้วน');
    }

    const trimmedContent = content.trim();
    if (trimmedContent.length === 0 || trimmedContent.length > 1000) {
        throw new HttpsError('invalid-argument', 'ความยาวข้อความต้องอยู่ระหว่าง 1 ถึง 1000 ตัวอักษร');
    }

    const recipientRef = db.collection('users').doc(recipientUid);
    const recipientSnap = await recipientRef.get();

    if (!recipientSnap.exists) {
        throw new HttpsError('not-found', 'ไม่พบผู้รับข้อความนี้');
    }

    const recipientData = recipientSnap.data();
    if (recipientData.acceptsMessages === false) {
        throw new HttpsError('failed-precondition', 'ผู้ใช้นี้ปิดรับข้อความชั่วคราว');
    }

    if (senderToken && typeof senderToken === 'string') {
        const blockSnap = await db.collection('blocks')
            .where('recipientUid', '==', recipientUid)
            .where('senderToken', '==', senderToken)
            .get();
        
        if (!blockSnap.empty) {
            throw new HttpsError('permission-denied', 'คุณถูกบล็อกไม่ให้ส่งข้อความถึงผู้ใช้นี้');
        }
    }

    let deviceHint = 'อุปกรณ์ทั่วไป';
    if (userAgent && typeof userAgent === 'string') {
        if (userAgent.includes('Android')) deviceHint = 'Android Device';
        else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) deviceHint = 'iOS Device';
        else if (userAgent.includes('Chrome')) deviceHint = 'Chrome Browser';
        else if (userAgent.includes('Safari')) deviceHint = 'Safari Browser';
    }

    const messageData = {
        recipientUid,
        content: trimmedContent,
        imageUrl: imageUrl && typeof imageUrl === 'string' ? imageUrl : '',
        hintDevice: deviceHint,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        isRead: false,
        isArchived: false,
        isReported: false
    };

    const messageRef = await db.collection('messages').add(messageData);

    return { success: true, messageId: messageRef.id };
});

// 3. Submit Reply (ตอบกลับข้อความนิรนาม)
exports.submitReply = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError('unauthenticated', 'กรุณาเข้าสู่ระบบก่อนตอบกลับ');
    }
    const { messageId, content } = request.data;
    const uid = request.auth.uid;

    if (!messageId || !content || typeof content !== 'string') {
        throw new HttpsError('invalid-argument', 'ข้อมูลไม่ครบถ้วน');
    }

    const msgRef = db.collection('messages').doc(messageId);
    const msgSnap = await msgRef.get();

    if (!msgSnap.exists) {
        throw new HttpsError('not-found', 'ไม่พบข้อความต้นฉบับ');
    }

    if (msgSnap.data().recipientUid !== uid) {
        throw new HttpsError('permission-denied', 'คุณไม่มีสิทธิ์ตอบกลับข้อความนี้');
    }

    const replyData = {
        messageId,
        recipientUid: uid,
        content: content.trim(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const replyRef = await db.collection('replies').add(replyData);

    return { success: true, replyId: replyRef.id };
});

// 4. Publish Wall Message (เผยแพร่ข้อความลง Public Wall)
exports.publishWallMessage = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError('unauthenticated', 'กรุณาเข้าสู่ระบบ');
    }
    const { messageId } = request.data;
    const uid = request.auth.uid;

    if (!messageId) {
        throw new HttpsError('invalid-argument', 'กรุณาระบุรหัสข้อความ');
    }

    const msgRef = db.collection('messages').doc(messageId);
    const msgSnap = await msgRef.get();

    if (!msgSnap.exists) {
        throw new HttpsError('not-found', 'ไม่พบข้อความ');
    }

    const msgData = msgSnap.data();
    if (msgData.recipientUid !== uid) {
        throw new HttpsError('permission-denied', 'ไม่มีสิทธิ์เผยแพร่ข้อความของผู้อื่น');
    }

    const wallData = {
        recipientUid: uid,
        content: msgData.content,
        imageUrl: msgData.imageUrl || '',
        publishedAt: admin.firestore.FieldValue.serverTimestamp(),
        reactionsCount: 0
    };

    const wallRef = await db.collection('publicWall').add(wallData);

    return { success: true, wallId: wallRef.id };
});

// 5. Toggle Reaction (กดหัวใจ/Reaction บน Public Wall)
exports.toggleReaction = onCall(async (request) => {
    const { wallId } = request.data;
    if (!wallId) {
        throw new HttpsError('invalid-argument', 'กรุณาระบุรหัสโพสต์');
    }

    const wallRef = db.collection('publicWall').doc(wallId);

    return db.runTransaction(async (transaction) => {
        const docSnap = await transaction.get(wallRef);
        if (!docSnap.exists) {
            throw new HttpsError('not-found', 'ไม่พบโพสต์บน Public Wall');
        }

        const currentCount = docSnap.data().reactionsCount || 0;
        const newCount = currentCount + 1;
        transaction.update(wallRef, { reactionsCount: newCount });

        return { success: true, reactionsCount: newCount };
    });
});

// 6. Block Sender Token (บล็อกผู้ส่งด้วย Token)
exports.blockSenderToken = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError('unauthenticated', 'กรุณาเข้าสู่ระบบ');
    }
    const { senderToken } = request.data;
    const uid = request.auth.uid;

    if (!senderToken) {
        throw new HttpsError('invalid-argument', 'ไม่พบ Token ผู้ส่ง');
    }

    await db.collection('blocks').add({
        recipientUid: uid,
        senderToken,
        blockedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true, message: 'บล็อกผู้ส่งเรียบร้อยแล้ว' };
});

// 7. Submit Report (รายงานเนื้อหา/ข้อความไม่เหมาะสม)
exports.submitReport = onCall(async (request) => {
    const { targetId, targetType, reason } = request.data;
    if (!targetId || !targetType || !reason) {
        throw new HttpsError('invalid-argument', 'ข้อมูลการรายงานไม่ครบถ้วน');
    }

    await db.collection('reports').add({
        targetId,
        targetType, // 'message', 'wall', 'user'
        reason,
        reportedAt: admin.firestore.FieldValue.serverTimestamp(),
        status: 'pending'
    });

    return { success: true, message: 'ส่งรายงานเรียบร้อยแล้ว เจ้าหน้าที่กำลังตรวจสอบ' };
});

// 8. Get User Analytics (ดึงสถิติภาพรวมของผู้ใช้)
exports.getUserAnalytics = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError('unauthenticated', 'กรุณาเข้าสู่ระบบ');
    }
    const uid = request.auth.uid;

    const messagesSnap = await db.collection('messages').where('recipientUid', '==', uid).get();
    const totalMessages = messagesSnap.size;
    let unreadMessages = 0;
    let withImages = 0;

    messagesSnap.forEach(doc => {
        const data = doc.data();
        if (!data.isRead) unreadMessages++;
        if (data.imageUrl) withImages++;
    });

    const wallSnap = await db.collection('publicWall').where('recipientUid', '==', uid).get();
    const totalWallPosts = wallSnap.size;

    return {
        totalMessages,
        unreadMessages,
        withImages,
        totalWallPosts
    };
});

// 9. Admin Update User Status (ผู้ดูแลระบบ: ระงับหรือเปิดใช้งานบัญชีผู้ใช้)
exports.adminUpdateUserStatus = onCall(async (request) => {
    if (!request.auth || !request.auth.token.admin) {
        throw new HttpsError('permission-denied', 'เฉพาะผู้ดูแลระบบเท่านั้น');
    }
    const { targetUid, accountStatus } = request.data;
    if (!targetUid || !accountStatus) {
        throw new HttpsError('invalid-argument', 'ข้อมูลไม่ครบถ้วน');
    }

    await db.collection('users').doc(targetUid).update({
        accountStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await db.collection('adminAuditLogs').add({
        adminUid: request.auth.uid,
        action: 'UPDATE_USER_STATUS',
        targetUid,
        accountStatus,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true };
});

// 10. Admin Moderate Content (ผู้ดูแลระบบ: จัดการเนื้อหารายงานหรือลบข้อความ)
exports.adminModerateContent = onCall(async (request) => {
    if (!request.auth || !request.auth.token.admin) {
        throw new HttpsError('permission-denied', 'เฉพาะผู้ดูแลระบบเท่านั้น');
    }
    const { collectionName, docId, action } = request.data;
    if (!collectionName || !docId || !action) {
        throw new HttpsError('invalid-argument', 'ข้อมูลไม่ครบถ้วน');
    }

    const docRef = db.collection(collectionName).doc(docId);
    if (action === 'delete') {
        await docRef.delete();
    } else if (action === 'approve') {
        await docRef.update({ status: 'approved' });
    }

    await db.collection('adminAuditLogs').add({
        adminUid: request.auth.uid,
        action: `MODERATE_${action.toUpperCase()}`,
        collectionName,
        docId,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true };
});

// 11. Admin Delete Account (ผู้ดูแลระบบ: ลบบัญชีผู้ใช้และข้อมูลที่เกี่ยวข้อง)
exports.adminDeleteAccount = onCall(async (request) => {
    if (!request.auth || !request.auth.token.admin) {
        throw new HttpsError('permission-denied', 'เฉพาะผู้ดูแลระบบเท่านั้น');
    }
    const { targetUid } = request.data;
    if (!targetUid) {
        throw new HttpsError('invalid-argument', 'กรุณาระบุ UID ของผู้ใช้');
    }

    await admin.auth().deleteUser(targetUid);
    await db.collection('users').doc(targetUid).delete();

    await db.collection('adminAuditLogs').add({
        adminUid: request.auth.uid,
        action: 'DELETE_USER_ACCOUNT',
        targetUid,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true, message: 'ลบบัญชีเรียบร้อยแล้ว' };
});
