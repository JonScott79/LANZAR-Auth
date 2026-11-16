// tenantService.js
// Multi-Tenant Organization & Entitlement Lifecycle Service for LANZAR ID
// Collections:
//   - /tenants/{tenantId}
//   - /tenants/{tenantId}/members/{uid}
//   - /users/{uid}/tenants/{tenantId}

const { FieldValue } = require('firebase-admin/firestore');

const TENANT_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const VALID_TENANT_STATUSES = new Set(['active', 'suspended', 'deleted']);
const VALID_MEMBER_ROLES = new Set(['owner', 'admin', 'developer', 'member']);

const PLAN_ENTITLEMENTS = {
  developer: {
    planId: 'developer',
    displayName: 'Developer',
    priceMonthlyUsd: 0,
    maxApps: 3,
    maxMau: 1000,
    smsMfaEnabled: false,
    customDomainEnabled: false
  },
  launch: {
    planId: 'launch',
    displayName: 'Launch',
    priceMonthlyUsd: 29,
    maxApps: 10,
    maxMau: 10000,
    smsMfaEnabled: true,
    customDomainEnabled: false
  },
  growth: {
    planId: 'growth',
    displayName: 'Growth',
    priceMonthlyUsd: 99,
    maxApps: 25,
    maxMau: 50000,
    smsMfaEnabled: true,
    customDomainEnabled: true
  },
  scale: {
    planId: 'scale',
    displayName: 'Scale',
    priceMonthlyUsd: 299,
    maxApps: 100,
    maxMau: 250000,
    smsMfaEnabled: true,
    customDomainEnabled: true
  },
  enterprise: {
    planId: 'enterprise',
    displayName: 'Enterprise',
    priceMonthlyUsd: null,
    maxApps: 1000,
    maxMau: 10000000,
    smsMfaEnabled: true,
    customDomainEnabled: true
  }
};

function getEntitlementsForPlan(planId = 'developer') {
  const key = String(planId || 'developer').toLowerCase();
  return { ...(PLAN_ENTITLEMENTS[key] || PLAN_ENTITLEMENTS.developer) };
}

class TenantService {
  constructor(db) {
    if (!db || typeof db.collection !== 'function') {
      throw new Error('TenantService requires a valid Firestore db instance.');
    }
    this.db = db;
  }

  _tenantRef(tenantId) {
    return this.db.collection('tenants').doc(tenantId);
  }

  _memberRef(tenantId, uid) {
    return this._tenantRef(tenantId).collection('members').doc(uid);
  }

  _userTenantRef(uid, tenantId) {
    return this.db.collection('users').doc(uid).collection('tenants').doc(tenantId);
  }

  async createTenant({ ownerUid, ownerEmail, name, tenantId }) {
    if (!ownerUid) throw new Error('ownerUid is required.');
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName || cleanName.length < 2 || cleanName.length > 100) {
      throw new Error('Organization name must be between 2 and 100 characters.');
    }

    const slug = (typeof tenantId === 'string' && tenantId.trim()
      ? tenantId.trim().toLowerCase()
      : cleanName.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48));

    if (!TENANT_ID_REGEX.test(slug) || slug === 'lanzar') {
      throw new Error('Invalid or reserved tenantId. Use 2-64 lowercase alphanumeric, "_" or "-" characters.');
    }

    const tenantRef = this._tenantRef(slug);
    const memberRef = this._memberRef(slug, ownerUid);
    const userTenantRef = this._userTenantRef(ownerUid, slug);
    const entitlements = getEntitlementsForPlan('developer');
    const nowIso = new Date().toISOString();

    const tenantRecord = {
      tenantId: slug,
      name: cleanName,
      ownerUid,
      status: 'active',
      plan: 'developer',
      entitlements,
      billing: {
        stripeCustomerId: null,
        stripeSubscriptionId: null,
        subscriptionStatus: 'free',
        currentPeriodEnd: null
      },
      createdAt: nowIso,
      updatedAt: nowIso,
      serverUpdatedAt: FieldValue.serverTimestamp()
    };

    const memberRecord = {
      uid: ownerUid,
      email: ownerEmail || null,
      role: 'owner',
      status: 'active',
      joinedAt: nowIso
    };

    const userTenantSummary = {
      tenantId: slug,
      name: cleanName,
      role: 'owner',
      status: 'active',
      plan: 'developer',
      joinedAt: nowIso
    };

    await this.db.runTransaction(async (tx) => {
      const existing = await tx.get(tenantRef);
      if (existing.exists) {
        const err = new Error(`Tenant "${slug}" already exists.`);
        err.code = 'TENANT_ALREADY_EXISTS';
        throw err;
      }
      tx.set(tenantRef, tenantRecord);
      tx.set(memberRef, memberRecord);
      tx.set(userTenantRef, userTenantSummary);
    });

    return tenantRecord;
  }

  async getTenant(tenantId) {
    if (!tenantId || !TENANT_ID_REGEX.test(tenantId)) return null;
    const snap = await this._tenantRef(tenantId).get();
    return snap.exists ? snap.data() : null;
  }

  async listUserTenants(uid) {
    if (!uid) return [];
    const snap = await this.db.collection('users').doc(uid).collection('tenants').get();
    const results = [];
    snap.forEach((doc) => results.push(doc.data()));
    return results;
  }

  async getMembership(tenantId, uid) {
    if (!tenantId || !uid) return null;
    const snap = await this._memberRef(tenantId, uid).get();
    return snap.exists ? snap.data() : null;
  }

  async requireTenantRole(tenantId, uid, allowedRoles = ['owner', 'admin', 'developer']) {
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      const err = new Error(`Tenant "${tenantId}" not found.`);
      err.status = 404;
      err.code = 'TENANT_NOT_FOUND';
      throw err;
    }
    if (tenant.status === 'deleted') {
      const err = new Error(`Tenant "${tenantId}" has been deleted.`);
      err.status = 403;
      err.code = 'TENANT_DELETED';
      throw err;
    }
    const member = await this.getMembership(tenantId, uid);
    if (!member || member.status !== 'active' || !allowedRoles.includes(member.role)) {
      const err = new Error('Forbidden: insufficient tenant permissions.');
      err.status = 403;
      err.code = 'TENANT_FORBIDDEN';
      throw err;
    }
    return { tenant, member };
  }

  async isTenantActive(tenantId) {
    if (!tenantId || tenantId === 'lanzar') return true;
    const tenant = await this.getTenant(tenantId);
    if (!tenant) return true; // Backwards compatible for legacy implicit tenants unless explicitly suspended
    return tenant.status === 'active';
  }

  async updateTenantStatus(tenantId, status, actorUid, reason = '') {
    if (!VALID_TENANT_STATUSES.has(status)) {
      throw new Error(`Invalid tenant status: ${status}`);
    }
    const tenantRef = this._tenantRef(tenantId);
    const snap = await tenantRef.get();
    if (!snap.exists) {
      const err = new Error(`Tenant "${tenantId}" not found.`);
      err.status = 404;
      throw err;
    }
    await tenantRef.update({
      status,
      statusReason: reason || null,
      statusUpdatedBy: actorUid || null,
      updatedAt: new Date().toISOString(),
      serverUpdatedAt: FieldValue.serverTimestamp()
    });
    return { tenantId, status };
  }

  async updateTenantPlan(tenantId, planId, billingPatch = {}) {
    const entitlements = getEntitlementsForPlan(planId);
    const tenantRef = this._tenantRef(tenantId);
    const snap = await tenantRef.get();
    if (!snap.exists) {
      const err = new Error(`Tenant "${tenantId}" not found.`);
      err.status = 404;
      throw err;
    }
    const current = snap.data();
    const updatedBilling = {
      ...(current.billing || {}),
      ...billingPatch
    };
    await tenantRef.update({
      plan: entitlements.planId,
      entitlements,
      billing: updatedBilling,
      updatedAt: new Date().toISOString(),
      serverUpdatedAt: FieldValue.serverTimestamp()
    });
    return { tenantId, plan: entitlements.planId, entitlements, billing: updatedBilling };
  }

  async listMembers(tenantId) {
    const snap = await this._tenantRef(tenantId).collection('members').get();
    const members = [];
    snap.forEach((d) => members.push(d.data()));
    return members;
  }

  async upsertMember(tenantId, { uid, email, role = 'developer' }) {
    if (!uid) throw new Error('uid is required.');
    if (!VALID_MEMBER_ROLES.has(role)) throw new Error(`Invalid role: ${role}`);
    const tenant = await this.getTenant(tenantId);
    if (!tenant) throw new Error(`Tenant "${tenantId}" not found.`);

    const nowIso = new Date().toISOString();
    const memberRecord = {
      uid,
      email: email || null,
      role,
      status: 'active',
      joinedAt: nowIso
    };
    await this._memberRef(tenantId, uid).set(memberRecord, { merge: true });
    await this._userTenantRef(uid, tenantId).set({
      tenantId,
      name: tenant.name,
      role,
      status: 'active',
      plan: tenant.plan || 'developer',
      joinedAt: nowIso
    }, { merge: true });
    return memberRecord;
  }

  async removeMember(tenantId, targetUid) {
    const members = await this.listMembers(tenantId);
    const owners = members.filter((m) => m.role === 'owner' && m.status === 'active');
    const target = members.find((m) => m.uid === targetUid);
    if (!target) return { removed: false };
    if (target.role === 'owner' && owners.length <= 1) {
      const err = new Error('Cannot remove the last active owner of a tenant.');
      err.status = 400;
      throw err;
    }
    await this._memberRef(tenantId, targetUid).delete();
    await this._userTenantRef(targetUid, tenantId).delete();
    return { removed: true, uid: targetUid };
  }
}

module.exports = {
  TenantService,
  PLAN_ENTITLEMENTS,
  getEntitlementsForPlan,
  TENANT_ID_REGEX,
  VALID_TENANT_STATUSES,
  VALID_MEMBER_ROLES
};
