/*
    auth.js

    LANZAR Portal Authentication Service & Emulator Binding.

    Responsibilities:
    - Configure Firebase Authentication
    - Connect to local Auth emulator in development
    - Expose sign-in with custom token and sign-out helpers
    - Expose Firebase authentication instance
*/

import {
  getAuth,
  connectAuthEmulator,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  signInWithEmailAndPassword,
  sendPasswordResetEmail,
  signInWithCustomToken as fbSignInWithCustomToken,
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
    // Already connected or HMR re-eval
  }
}

// ==========================
// Google Provider (Legacy)
// ==========================

const googleProvider = new GoogleAuthProvider()
googleProvider.setCustomParameters({
  prompt: 'select_account',
})

export async function signInWithGoogle() {
  const result = await signInWithPopup(auth, googleProvider)
  return result.user
}

// ==========================
// Sign Out
// ==========================

export function signOutUser() {
  return signOut(auth)
}

// ==========================
// Email Sign In (Legacy / Fallback)
// ==========================

export async function signInWithEmail(email, password) {
  const result = await signInWithEmailAndPassword(auth, email, password)
  return result.user
}

// ==========================
// Token Sign In & Password Reset
// ==========================

export async function signInWithCustomToken(token) {
  return await fbSignInWithCustomToken(auth, token)
}

export async function sendPasswordReset(email) {
  await sendPasswordResetEmail(auth, email)
}

// ==========================
// Authentication Instance
// ==========================

export { auth }
