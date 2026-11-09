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

export async function getAuthorizedAdmin(uid) {
  const admin = await getAdmin(uid)

  if (!admin) {
    return null
  }

  if (admin.active !== true) {
    return null
  }

  return admin
}
