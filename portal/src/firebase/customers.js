/*
    customers.js

    LANZAR Support Tickets customer service.

    Responsibilities

    - Connect authenticated users to LANZAR customer/user records
    - Retrieve customer authorization data with dual-read fallback
    - Validate active customer status
    - Resolve account-level service authorization
*/

import {
  doc,
  getDoc,
  setDoc,
  getFirestore,
} from 'firebase/firestore'

import app from './config.js'

// ==========================
// Firestore
// ==========================

const db = getFirestore(app)

// ==========================
// Customer Lookup
// ==========================

// Dual-read: Try users/ first (new model), fall back to customers/ (legacy model)
export async function getCustomer(uid) {
  if (!uid) {
    return null
  }

  // 1. Try the new users collection
  try {
    const userRef = doc(db, 'users', uid)
    const userSnapshot = await getDoc(userRef)

    if (userSnapshot.exists()) {
      const userData = userSnapshot.data()

      // Inactive user handling (supports both status: 'active' and legacy active: true)
      const isActive = userData.active === true || userData.status === 'active'
      if (!isActive) {
        return {
          id: userSnapshot.id,
          active: false,
        }
      }

      // Resolve account-level services if the user has an accountId
      let services = userData.services || []

      if (userData.accountId) {
        try {
          const accountRef = doc(db, 'accounts', userData.accountId)
          const accountSnapshot = await getDoc(accountRef)

          if (accountSnapshot.exists()) {
            const accountData = accountSnapshot.data()
            services = accountData.services || services
          }
        } catch (accountError) {
          console.log('[AUTH] Account lookup skipped:', accountError.message)
        }
      }

      return {
        id: userSnapshot.id,
        // Provide backward-compatible fields
        customerId: userSnapshot.id,
        customerName: userData.displayName,
        displayName: userData.displayName,
        customerEmail: userData.email,
        authEmail: userData.email,
        accountId: userData.accountId || null,
        role: userData.role || 'USER',
        services: services,
        active: isActive,
      }
    }
  } catch (userLookupError) {
    console.warn('[AUTH WARN] users/{uid} lookup failed or missing:', userLookupError.message)
  }

  // 2. Fall back to legacy customers collection
  try {
    const customerRef = doc(db, 'customers', uid)
    const customerSnapshot = await getDoc(customerRef)

    if (!customerSnapshot.exists()) {
      return null
    }

    return {
      id: customerSnapshot.id,
      ...customerSnapshot.data(),
    }
  } catch (customerLookupError) {
    console.error('[AUTH ERROR] customers/{uid} lookup failed:', customerLookupError.message)
    return null
  }
}

// ==========================
// Customer Authorization
// ==========================

export async function getAuthorizedCustomer(uid) {
  const customer = await getCustomer(uid)

  if (!customer) {
    return null
  }

  if (customer.active !== true) {
    return null
  }

  return customer
}

export async function getOrCreateAuthorizedCustomer(firebaseUser, options = {}) {
  if (!firebaseUser?.uid) return null;

  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 12000;
  let readTimer;
  const existingCustomer = await Promise.race([
    getCustomer(firebaseUser.uid),
    new Promise((_, reject) => {
      readTimer = setTimeout(() => {
        const err = new Error('Timed out loading customer workspace profile.');
        err.code = 'ERR_TIMEOUT';
        err.stage = 'profile_resolve';
        reject(err);
      }, timeoutMs);
    })
  ]).finally(() => {
    if (readTimer !== undefined) clearTimeout(readTimer);
  });

  if (existingCustomer) {
    // A profile exists: honor its status. Suspended / inactive accounts must never be auto-provisioned.
    return existingCustomer.active === true ? existingCustomer : null;
  }

  // Auto-provision initial customer profile so new users never hit an access denied loop
  const displayName = firebaseUser.displayName || (firebaseUser.email ? firebaseUser.email.split('@')[0] : 'Customer');
  const email = firebaseUser.email || '';

  const newProfile = {
    displayName,
    email,
    active: true,
    role: 'USER',
    services: [],
    createdAt: new Date().toISOString()
  };

  let writeTimer;
  try {
    const userRef = doc(db, 'users', firebaseUser.uid);
    await Promise.race([
      setDoc(userRef, newProfile, { merge: true }),
      new Promise((_, reject) => {
        writeTimer = setTimeout(() => {
          reject(new Error('Profile provisioning write timed out'));
        }, timeoutMs);
      })
    ]);
  } catch (err) {
    console.warn('[AUTH] Could not write users collection:', err.message);
  } finally {
    if (writeTimer !== undefined) clearTimeout(writeTimer);
  }

  return {
    id: firebaseUser.uid,
    customerId: firebaseUser.uid,
    customerName: displayName,
    displayName: displayName,
    customerEmail: email,
    authEmail: email,
    accountId: null,
    role: 'USER',
    services: [],
    active: true
  };
}