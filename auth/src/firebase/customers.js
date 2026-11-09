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

      // Inactive user handling
      if (userData.active !== true) {
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
        active: userData.active === true,
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