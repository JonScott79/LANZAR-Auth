/*
    accountResources.js

    LANZAR Support Tickets — Account Resources Service

    Responsibilities
    - Retrieve active locations for a specific customer account from Firestore
    - Retrieve active assets for a specific customer account from Firestore
    - Enforce database-level path scoping (accounts/{accountId}/assets & locations)
*/

import {
  collection,
  query,
  where,
  getDocs,
  getFirestore,
} from 'firebase/firestore'

import app from './config.js'

const db = getFirestore(app)

/**
 * Fetch active assets for a specific account.
 */
export async function getAccountAssets(accountId) {
  if (!accountId) {
    return []
  }

  try {
    const assetsRef = collection(db, 'accounts', accountId, 'assets')
    const q = query(assetsRef, where('active', '==', true))
    const snapshot = await getDocs(q)

    const assets = []
    snapshot.forEach((docSnap) => {
      assets.push({
        id: docSnap.id,
        assetId: docSnap.id,
        ...docSnap.data(),
      })
    })

    return assets
  } catch (error) {
    console.error(`[ACCOUNT RESOURCES] Failed to fetch assets for account ${accountId}:`, error.message)
    return []
  }
}

/**
 * Fetch active locations for a specific account.
 */
export async function getAccountLocations(accountId) {
  if (!accountId) {
    return []
  }

  try {
    const locsRef = collection(db, 'accounts', accountId, 'locations')
    const q = query(locsRef, where('active', '==', true))
    const snapshot = await getDocs(q)

    const locations = []
    snapshot.forEach((docSnap) => {
      locations.push({
        id: docSnap.id,
        locationId: docSnap.id,
        ...docSnap.data(),
      })
    })

    return locations
  } catch (error) {
    console.error(`[ACCOUNT RESOURCES] Failed to fetch locations for account ${accountId}:`, error.message)
    return []
  }
}
