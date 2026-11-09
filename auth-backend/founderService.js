// founderService.js
// Authoritative product-specific Founder Programs management for LANZAR ID

const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('./auditService');

const VALID_FOUNDER_PROGRAMS = {
    'lanzar_id_founder': {
        product: 'lanzar_id',
        title: 'LANZAR ID Pioneer',
        badgeIconUrl: '/assets/badges/badge-lanzar-id-founder.svg'
    },
    'pythos_founder': {
        product: 'pythos',
        title: 'Pythos Founding Scholar',
        badgeIconUrl: '/assets/badges/badge-pythos-founder.svg'
    },
    'portal_founder': {
        product: 'portal',
        title: 'Portal Operations Founder',
        badgeIconUrl: '/assets/badges/badge-portal-founder.svg'
    },
    'traveling_founder': {
        product: 'traveling',
        title: 'Traveling Systems Founder',
        badgeIconUrl: '/assets/badges/badge-traveling-founder.svg'
    },
    'threadline_founder': {
        product: 'threadline',
        title: 'Threadline Intelligence Founder',
        badgeIconUrl: '/assets/badges/badge-threadline-founder.svg'
    }
};

class FounderService {
    constructor(db) {
        this.db = db;
    }

    /**
     * Recalculates derivedBadges array from the authoritative /users/{uid}/founders subcollection
     * and atomically writes it to /users/{uid}.
     * INVARIANT: derivedBadges on the profile is strictly read-only and derived.
     */
    async recalculateDerivedBadges(uid) {
        const foundersSnap = await this.db.collection('users').doc(uid)
            .collection('founders')
            .where('active', '==', true)
            .get();

        const activeBadges = [];
        foundersSnap.forEach(doc => {
            const data = doc.data();
            if (data.programId) {
                activeBadges.push(data.programId);
            }
        });

        await this.db.collection('users').doc(uid).set({
            derivedBadges: activeBadges,
            updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        return activeBadges;
    }

    /**
     * Authoritatively grants or updates a product-specific Founder designation.
     */
    async grantFounderDesignation({
        uid,
        programId,
        founderNumber = null,
        title = null,
        grantReason,
        grantedBy,
        ipAddress = null
    }) {
        if (!uid || !programId || !grantReason || !grantedBy) {
            throw new Error('uid, programId, grantReason, and grantedBy are required.');
        }

        const programConfig = VALID_FOUNDER_PROGRAMS[programId];
        if (!programConfig) {
            throw new Error(`Invalid founder programId: ${programId}. Valid programs: ${Object.keys(VALID_FOUNDER_PROGRAMS).join(', ')}`);
        }

        const founderRef = this.db.collection('users').doc(uid)
            .collection('founders').doc(programId);

        const nowIso = new Date().toISOString();
        const record = {
            programId,
            product: programConfig.product,
            founderNumber: founderNumber ? Number(founderNumber) : null,
            title: title ? String(title).trim() : programConfig.title,
            badgeIconUrl: programConfig.badgeIconUrl,
            active: true,
            grantReason: String(grantReason).trim(),
            grantedBy: String(grantedBy),
            grantedAt: nowIso,
            revokedAt: null,
            revokedBy: null,
            revocationReason: null
        };

        await founderRef.set(record);
        const derivedBadges = await this.recalculateDerivedBadges(uid);

        await recordSecurityEvent(this.db, {
            actorUid: grantedBy,
            action: 'admin.founder.granted',
            targetUid: uid,
            ipAddress,
            details: { programId, founderNumber, grantReason }
        });

        return {
            success: true,
            record,
            derivedBadges
        };
    }

    /**
     * Authoritatively revokes a product-specific Founder designation.
     */
    async revokeFounderDesignation({
        uid,
        programId,
        revocationReason,
        revokedBy,
        ipAddress = null
    }) {
        if (!uid || !programId || !revocationReason || !revokedBy) {
            throw new Error('uid, programId, revocationReason, and revokedBy are required.');
        }

        const founderRef = this.db.collection('users').doc(uid)
            .collection('founders').doc(programId);

        const snap = await founderRef.get();
        if (!snap.exists || !snap.data().active) {
            throw new Error('Founder designation does not exist or is already inactive.');
        }

        const nowIso = new Date().toISOString();
        await founderRef.update({
            active: false,
            revokedAt: nowIso,
            revokedBy: String(revokedBy),
            revocationReason: String(revocationReason).trim()
        });

        const derivedBadges = await this.recalculateDerivedBadges(uid);

        await recordSecurityEvent(this.db, {
            actorUid: revokedBy,
            action: 'admin.founder.revoked',
            targetUid: uid,
            ipAddress,
            details: { programId, revocationReason }
        });

        return {
            success: true,
            programId,
            derivedBadges
        };
    }

    /**
     * Lists all authoritative founder records for a user.
     */
    async listUserFounders(uid) {
        const snap = await this.db.collection('users').doc(uid)
            .collection('founders')
            .get();

        return snap.docs.map(doc => doc.data());
    }
}

module.exports = { FounderService, VALID_FOUNDER_PROGRAMS };
