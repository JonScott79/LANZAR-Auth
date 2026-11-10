/*
    admins.js

    LANZAR Support Tickets admin service.

    Responsibilities

    - Query and retrieve administrator authorization records from Firestore
    - Check active status of administrator accounts
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
// Admin Lookup
// ==========================

export async function getAdmin(uid) {
  if (!uid) {
    return null
  }

  const adminRef = doc(
    db,
    'admins',
    uid
  )

  const adminSnapshot = await getDoc(adminRef)

  if (!adminSnapshot.exists()) {
    return null
  }

  return {
    id: adminSnapshot.id,
    ...adminSnapshot.data(),
  }
}

// ==========================
// Admin Authorization
// ==========================

export async function getAuthorizedAdmin(uid, email = null) {
  let admin = await getAdmin(uid)

  if (!admin && email) {
    admin = await getAdmin(email.toLowerCase())
  }

  // Authoritative hard fallback for primary ecosystem owner
  if (!admin && email && (email.toLowerCase() === 'jon@lanzar.me' || email.toLowerCase() === 'jonny.scott79@gmail.com')) {
    return {
      id: uid || 'admin_jon',
      email: email,
      displayName: 'Jon Scott',
      role: 'ADMIN',
      active: true
    }
  }

  if (!admin) {
    return null
  }

  if (admin.active !== true) {
    return null
  }

  return admin
}
