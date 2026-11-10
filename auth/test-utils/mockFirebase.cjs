// mockFirebase.cjs
// Shared In-Memory High-Fidelity Mock Implementations of Firestore & Firebase Auth Admin
// For Level 1 Unit & Service Testing without external network or production credential access.

const crypto = require('crypto');

class MockFirestore {
  constructor() {
    this.store = new Map();
  }

  _key(pathStr) {
    return pathStr.replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
  }

  collection(name) {
    return new MockCollectionReference(this, name);
  }

  batch() {
    return new MockBatch(this);
  }

  async runTransaction(updateFunction) {
    if (!this._txQueue) this._txQueue = Promise.resolve();
    let release;
    const lock = new Promise((resolve) => { release = resolve; });
    const prev = this._txQueue;
    this._txQueue = prev.then(() => lock);

    await prev;
    try {
      const tx = new MockTransaction(this);
      return await updateFunction(tx);
    } finally {
      release();
    }
  }
}

class MockCollectionReference {
  constructor(db, pathStr) {
    this.db = db;
    this.path = pathStr;
  }

  doc(id) {
    return new MockDocumentReference(this.db, `${this.path}/${id}`);
  }

  where(field, op, value) {
    return new MockQuery(this.db, this.path, [{ field, op, value }]);
  }

  orderBy(field, direction = 'asc') {
    return new MockQuery(this.db, this.path, [], Infinity, { field, direction });
  }

  limit(count) {
    return new MockQuery(this.db, this.path, [], count);
  }

  async get() {
    return new MockQuery(this.db, this.path, []).get();
  }
}

class MockQuery {
  constructor(db, pathStr, filters = [], limitCount = Infinity, order = null) {
    this.db = db;
    this.path = pathStr;
    this.filters = filters;
    this.limitCount = limitCount;
    this.order = order;
  }

  where(field, op, value) {
    return new MockQuery(this.db, this.path, [...this.filters, { field, op, value }], this.limitCount, this.order);
  }

  orderBy(field, direction = 'asc') {
    return new MockQuery(this.db, this.path, this.filters, this.limitCount, { field, direction });
  }

  limit(count) {
    return new MockQuery(this.db, this.path, this.filters, count, this.order);
  }

  async get() {
    const prefix = `${this.path}/`;
    const docs = [];

    for (const [key, val] of this.db.store.entries()) {
      if (key.startsWith(prefix)) {
        const subPath = key.slice(prefix.length);
        if (!subPath.includes('/')) {
          let matches = true;
          for (const f of this.filters) {
            const docVal = val[f.field];
            if (f.op === '==') {
              if (docVal !== f.value) matches = false;
            } else if (f.op === '!=') {
              if (docVal === f.value) matches = false;
            } else if (f.op === '<') {
              if (!(docVal < f.value)) matches = false;
            } else if (f.op === '<=') {
              if (!(docVal <= f.value)) matches = false;
            } else if (f.op === '>') {
              if (!(docVal > f.value)) matches = false;
            } else if (f.op === '>=') {
              if (!(docVal >= f.value)) matches = false;
            } else if (f.op === 'in') {
              if (!Array.isArray(f.value) || !f.value.includes(docVal)) matches = false;
            }
          }
          if (matches) {
            docs.push(new MockDocumentSnapshot(this.db, key, val));
          }
        }
      }
    }

    if (this.order) {
      docs.sort((a, b) => {
        const valA = a.data()[this.order.field];
        const valB = b.data()[this.order.field];
        if (valA < valB) return this.order.direction === 'desc' ? 1 : -1;
        if (valA > valB) return this.order.direction === 'desc' ? -1 : 1;
        return 0;
      });
    }

    const limitedDocs = docs.slice(0, this.limitCount);
    return {
      docs: limitedDocs,
      empty: limitedDocs.length === 0,
      size: limitedDocs.length,
      forEach(cb) { limitedDocs.forEach(cb); }
    };
  }
}

class MockDocumentReference {
  constructor(db, pathStr) {
    this.db = db;
    this.path = pathStr;
  }

  collection(subName) {
    return new MockCollectionReference(this.db, `${this.path}/${subName}`);
  }

  async get() {
    const data = this.db.store.get(this.path);
    return new MockDocumentSnapshot(this.db, this.path, data);
  }

  async set(data, options = {}) {
    const existing = this.db.store.get(this.path) || {};
    const sanitized = this._sanitizeData(data, existing);
    const merged = options.merge ? { ...existing, ...sanitized } : sanitized;
    this.db.store.set(this.path, merged);
  }

  async update(data) {
    const existing = this.db.store.get(this.path);
    if (!existing) {
      const err = new Error(`No document to update: ${this.path}`);
      err.code = 5; // NOT_FOUND
      throw err;
    }
    const sanitized = this._sanitizeData(data, existing);
    this.db.store.set(this.path, { ...existing, ...sanitized });
  }

  async delete() {
    this.db.store.delete(this.path);
  }

  _sanitizeData(data, existing = {}) {
    const out = {};
    for (const [k, v] of Object.entries(data)) {
      if (v && typeof v === 'object' && v.constructor && v.constructor.name === 'ServerTimestampTransform') {
        const d = new Date();
        d.toDate = () => d;
        out[k] = d;
      } else if (v && typeof v === 'object' && v.constructor && v.constructor.name === 'NumericIncrementTransform') {
        const current = (existing && typeof existing[k] === 'number') ? existing[k] : 0;
        out[k] = current + (v.operand !== undefined ? v.operand : 1);
      } else if (v instanceof Date) {
        v.toDate = () => v;
        out[k] = v;
      } else {
        out[k] = v;
      }
    }
    return out;
  }
}

class MockDocumentSnapshot {
  constructor(db, pathStr, data) {
    this.db = db;
    this.path = pathStr;
    this._data = data;
    this.exists = data !== undefined;
    this.id = pathStr.split('/').pop();
    this.ref = new MockDocumentReference(db, pathStr);
  }

  data() {
    return this._data ? JSON.parse(JSON.stringify(this._data)) : undefined;
  }
}

class MockTransaction {
  constructor(db) {
    this.db = db;
  }

  async get(docRef) {
    return await docRef.get();
  }

  set(docRef, data, options = {}) {
    const existing = this.db.store.get(docRef.path) || {};
    const sanitized = docRef._sanitizeData(data, existing);
    const merged = options.merge ? { ...existing, ...sanitized } : sanitized;
    this.db.store.set(docRef.path, merged);
  }

  update(docRef, data) {
    const existing = this.db.store.get(docRef.path);
    if (!existing) {
      const err = new Error(`No document to update: ${docRef.path}`);
      err.code = 5;
      throw err;
    }
    const sanitized = docRef._sanitizeData(data, existing);
    this.db.store.set(docRef.path, { ...existing, ...sanitized });
  }

  delete(docRef) {
    this.db.store.delete(docRef.path);
  }
}

class MockBatch {
  constructor(db) {
    this.db = db;
    this.ops = [];
  }

  set(docRef, data, options = {}) {
    this.ops.push(() => docRef.set(data, options));
  }

  update(docRef, data) {
    this.ops.push(() => docRef.update(data));
  }

  delete(docRef) {
    this.ops.push(() => docRef.delete());
  }

  async commit() {
    for (const op of this.ops) await op();
  }
}

class MockAuthAdmin {
  constructor() {
    this.users = new Map(); // uid -> userRecord
    this.revokedAfterTimes = new Map(); // uid -> timestamp
    this.tokens = new Map(); // tokenStr -> decoded
  }

  async createUser({ uid, email, displayName, password }) {
    if (this.users.has(uid)) {
      const err = new Error('The user with the provided uid already exists.');
      err.code = 'auth/uid-already-exists';
      throw err;
    }
    const userRecord = {
      uid,
      email: email || `${uid}@lanzar.me`,
      displayName: displayName || 'Test Cadet',
      emailVerified: true,
      metadata: { creationTime: new Date().toISOString() }
    };
    this.users.set(uid, userRecord);
    return userRecord;
  }

  async getUser(uid) {
    const u = this.users.get(uid);
    if (!u) {
      const err = new Error(`No user record found for uid: ${uid}`);
      err.code = 'auth/user-not-found';
      throw err;
    }
    return JSON.parse(JSON.stringify(u));
  }

  async getUserByEmail(email) {
    for (const u of this.users.values()) {
      if (u.email.toLowerCase() === email.toLowerCase()) {
        return JSON.parse(JSON.stringify(u));
      }
    }
    const err = new Error(`No user record found for email: ${email}`);
    err.code = 'auth/user-not-found';
    throw err;
  }

  async updateUser(uid, updates) {
    const u = this.users.get(uid);
    if (!u) {
      const err = new Error(`No user record found for uid: ${uid}`);
      err.code = 'auth/user-not-found';
      throw err;
    }
    Object.assign(u, updates);
    return JSON.parse(JSON.stringify(u));
  }

  async deleteUser(uid) {
    this.users.delete(uid);
    this.revokedAfterTimes.delete(uid);
  }

  async createCustomToken(uid, developerClaims = {}) {
    const raw = `${uid}:${JSON.stringify(developerClaims)}:${Date.now()}`;
    return `mock_custom_token_${Buffer.from(raw).toString('base64url')}`;
  }

  async revokeRefreshTokens(uid) {
    this.revokedAfterTimes.set(uid, Math.floor(Date.now() / 1000));
  }

  async mintIdToken(uid, extraClaims = {}) {
    const user = this.users.get(uid) || { uid, email: `${uid}@lanzar.me`, displayName: 'Test Cadet' };
    const nowSec = Math.floor(Date.now() / 1000);
    const revokedAt = this.revokedAfterTimes.get(uid);
    const iat = Math.max(nowSec, (revokedAt || 0) + 1);

    const payload = {
      uid,
      sub: uid,
      email: user.email,
      name: user.displayName,
      email_verified: true,
      auth_time: iat,
      iat,
      exp: iat + 3600,
      iss: 'https://securetoken.google.com/lanzar-test',
      aud: 'lanzar-test',
      ...extraClaims
    };

    const tokenStr = `mock_id_token_${uid}_${crypto.randomBytes(8).toString('hex')}`;
    this.tokens.set(tokenStr, payload);
    return tokenStr;
  }

  async verifyIdToken(token, checkRevoked = false) {
    const decoded = this.tokens.get(token);
    if (!decoded) {
      const err = new Error('Decoding Firebase ID token failed. Invalid token.');
      err.code = 'auth/argument-error';
      throw err;
    }

    if (checkRevoked) {
      const revokedAt = this.revokedAfterTimes.get(decoded.uid);
      if (revokedAt && decoded.iat <= revokedAt) {
        const err = new Error('Firebase ID token has been revoked.');
        err.code = 'auth/id-token-revoked';
        throw err;
      }
    }

    return decoded;
  }
}

module.exports = {
  MockFirestore,
  MockAuthAdmin,
  MockCollectionReference,
  MockQuery,
  MockDocumentReference,
  MockDocumentSnapshot,
  MockTransaction,
  MockBatch
};
