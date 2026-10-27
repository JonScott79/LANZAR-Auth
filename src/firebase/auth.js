/*
    auth.js

    LANZAR Support Tickets authentication service.

    Responsibilities

    - Configure Google authentication
    - Sign users in with Google
    - Sign users in / register with Email & Password
    - Sign users out
    - Expose Firebase authentication state
*/

import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  sendEmailVerification,
  sendPasswordResetEmail,
} from 'firebase/auth'

import app from './config.js'

// ==========================
// Firebase Authentication
// ==========================

const auth = getAuth(app)

// ==========================
// Google Provider
// ==========================

const googleProvider = new GoogleAuthProvider()

googleProvider.setCustomParameters({
  prompt: 'select_account',
})

// ==========================
// Sign In with Google
// ==========================

export async function signInWithGoogle() {
  const result = await signInWithPopup(
    auth,
    googleProvider
  )

  return result.user
}

// ==========================
// Sign Out
// ==========================

export function signOutUser() {
  return signOut(auth)
}

// ==========================
// Email Sign In
// ==========================

export async function signInWithEmail(email, password) {
  const result = await signInWithEmailAndPassword(auth, email, password)
  return result.user
}

// ==========================
// Email Registration
// ==========================

export async function registerWithEmail(email, password, displayName) {
  const result = await createUserWithEmailAndPassword(auth, email, password)
  if (displayName && result.user) {
    try {
      await updateProfile(result.user, { displayName })
    } catch (e) {
      console.warn('Failed to update display name profile:', e.message)
    }
  }
  return result.user
}

// ==========================
// Email Verification
// ==========================

export async function sendEmailVerificationToUser(user) {
  if (user) {
    await sendEmailVerification(user)
  }
}

// ==========================
// Password Reset
// ==========================

export async function sendPasswordReset(email) {
  await sendPasswordResetEmail(auth, email)
}

// ==========================
// Authentication Instance
// ==========================

export { auth }
