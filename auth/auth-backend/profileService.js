// profileService.js
// Universal profile management, status enforcement & account erasure for LANZAR ID

const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('./auditService');

class ProfileService {
    constructor(db, authAdmin, sessionService) {
        this.db = db;
        this.authAdmin = authAdmin;
        this.sessionService = sessionService;
    }

    /**
     * Retrieves the complete user profile view, merging Auth status, Firestore profile,
     * derived badges, and MFA factor flags (without revealing sensitive secrets).
     */
    async getUserProfile(uid) {
        const userDocRef = this.db.collection('users').doc(uid);
        const [userSnap, authRecord, mfaDoc] = await Promise.all([
            userDocRef.get(),
            this.authAdmin.getUser(uid).catch(() => null),
            this.db.collection('mfa_factors').doc(uid).get()
        ]);

        if (!userSnap.exists && !authRecord) {
            return null;
        }

        const userData = userSnap.exists ? userSnap.data() : {};
        const mfaData = mfaDoc.exists ? mfaDoc.data() : null;

        return {
            uid,
            tenantId: userData.tenantId || 'lanzar',
            email: authRecord?.email || userData.email || null,
            emailVerified: Boolean(authRecord?.emailVerified),
            phoneNumber: authRecord?.phoneNumber || userData.phoneNumber || null,
            phoneVerified: Boolean(userData.phoneVerified),
            displayName: userData.displayName || authRecord?.displayName || '',
            bio: userData.bio || '',
            avatarUrl: userData.avatarUrl || authRecord?.photoURL || null,
            role: userData.role || 'customer',
            status: userData.status || (authRecord?.disabled ? 'suspended' : 'active'),
            statusReason: userData.statusReason || null,
            tokenVersion: userData.tokenVersion || 1,
            derivedBadges: Array.isArray(userData.derivedBadges) ? userData.derivedBadges : [],
            notificationPreferences: userData.notificationPreferences || {
                newsletter: false,
                productUpdates: false,
                securityAlerts: true
            },
            mfa: {
                enabled: Boolean(mfaData && mfaData.enabled),
                totp: Boolean(mfaData && mfaData.totpSecret),
                passkeyCount: Array.isArray(mfaData?.passkeys) ? mfaData.passkeys.length : 0
            },
            createdAt: userData.createdAt || authRecord?.metadata?.creationTime || null,
            updatedAt: userData.updatedAt || null
        };
    }

    /**
     * Updates user-editable attributes.
     * INVARIANT: Never allows client modification of derivedBadges, role, status, or tokenVersion.
     */
    async updateUserProfile(uid, updates, ipAddress = null) {
        const allowedUpdates = {};

        if (typeof updates.displayName === 'string') {
            allowedUpdates.displayName = updates.displayName.trim().slice(0, 100);
        }
        if (typeof updates.bio === 'string') {
            allowedUpdates.bio = updates.bio.trim().slice(0, 280);
        }
        if (typeof updates.avatarUrl === 'string' && updates.avatarUrl.startsWith('https://')) {
            allowedUpdates.avatarUrl = updates.avatarUrl.trim().slice(0, 500);
        }
        if (updates.notificationPreferences && typeof updates.notificationPreferences === 'object' && !Array.isArray(updates.notificationPreferences)) {
            const validPrefs = {};
            const allowedPrefKeys = ['newsletter', 'productUpdates', 'securityAlerts'];
            for (const key of allowedPrefKeys) {
                if (typeof updates.notificationPreferences[key] === 'boolean') {
                    validPrefs[key] = updates.notificationPreferences[key];
                }
            }
            if (Object.keys(validPrefs).length > 0) {
                allowedUpdates.notificationPreferences = validPrefs;
            }
        }

        if (Object.keys(allowedUpdates).length === 0) {
            return await this.getUserProfile(uid);
        }

        allowedUpdates.updatedAt = FieldValue.serverTimestamp();

        await this.db.collection('users').doc(uid).set(allowedUpdates, { merge: true });

        // Synchronize displayName to Firebase Auth if changed
        if (allowedUpdates.displayName) {
            await this.authAdmin.updateUser(uid, { displayName: allowedUpdates.displayName }).catch(() => {});
        }

        await recordSecurityEvent(this.db, {
            actorUid: uid,
            action: 'profile.updated',
            targetUid: uid,
            ipAddress,
            details: { updatedFields: Object.keys(allowedUpdates) }
        });

        return await this.getUserProfile(uid);
    }

    async updateProfile(uid, updates, ipAddress = null) {
        return this.updateUserProfile(uid, updates, ipAddress);
    }

    /**
     * Administrative account status control (suspend / reactivate).
     */
    async setAccountStatus(uid, status, reason, adminUid, ipAddress = null) {
        if (!['active', 'suspended'].includes(status)) {
            throw new Error('Invalid status. Must be "active" or "suspended".');
        }

        const isSuspended = status === 'suspended';

        // 1. Disable in Firebase Auth
        await this.authAdmin.updateUser(uid, { disabled: isSuspended });

        // 2. If suspended, execute global session revocation immediately
        if (isSuspended && this.sessionService) {
            await this.sessionService.revokeAllSessions(uid, adminUid, ipAddress);
        }

        // 3. Update Firestore status
        await this.db.collection('users').doc(uid).set({
            status,
            statusReason: String(reason || '').slice(0, 255),
            statusUpdatedBy: adminUid,
            statusUpdatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        await recordSecurityEvent(this.db, {
            actorUid: adminUid,
            action: isSuspended ? 'admin.account.suspended' : 'admin.account.restored',
            targetUid: uid,
            ipAddress,
            details: { status, reason }
        });

        return { success: true, uid, status };
    }

    /**
     * GDPR / CCPA Full Account Erasure.
     */
    async eraseUserAccount(uid, actorUid, ipAddress = null) {
        // 1. Delete from Firebase Auth
        await this.authAdmin.deleteUser(uid).catch(err => {
            console.warn('[ERASURE] Firebase user delete warning:', err.message);
        });

        // 2. Wipe /mfa_factors
        await this.db.collection('mfa_factors').doc(uid).delete().catch(() => {});

        // 3. Purge sessions
        const sessionsSnap = await this.db.collection('users').doc(uid).collection('sessions').get();
        const batch = this.db.batch();
        sessionsSnap.forEach(d => batch.delete(d.ref));

        // 4. Purge founders
        const foundersSnap = await this.db.collection('users').doc(uid).collection('founders').get();
        foundersSnap.forEach(d => batch.delete(d.ref));

        // 5. Delete users doc
        batch.delete(this.db.collection('users').doc(uid));
        await batch.commit();

        await recordSecurityEvent(this.db, {
            actorUid,
            action: 'account.erased',
            targetUid: uid,
            ipAddress,
            details: { erasedAt: new Date().toISOString() }
        });

        return { success: true, uid };
    }
}

module.exports = { ProfileService };
