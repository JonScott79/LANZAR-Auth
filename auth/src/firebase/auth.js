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
  connectAuthEmulator,
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

// Connect Auth Emulator in development if configured
const appEnv = (import.meta.env.VITE_APP_ENV || (import.meta.env.DEV ? 'development' : 'production')).toLowerCase()
const authEmuHost = import.meta.env.VITE_FIREBASE_AUTH_EMULATOR_HOST

if (appEnv === 'development' || authEmuHost) {
  const hostStr = authEmuHost || '127.0.0.1:9099'
  const emuUrl = hostStr.startsWith('http://') || hostStr.startsWith('https://')
    ? hostStr
    : `http://${hostStr}`
  try {
    if (!auth.emulatorConfig) {
      connectAuthEmulator(auth, emuUrl, { disableWarnings: true })
      console.log(`[FIREBASE] Auth connected to local emulator at ${emuUrl}`)
    }
  } catch (e) {
    // connectAuthEmulator throws if already connected; ignore in HMR
  }
}

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
