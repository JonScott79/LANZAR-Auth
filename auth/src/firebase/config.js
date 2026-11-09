/*
    config.js

    LANZAR Support Tickets & Auth Hub Firebase configuration.

    Responsibilities:
    - Initialize the LANZAR Firebase project
    - Fail-closed environment isolation (reject production project in development)
    - Automatically connect Firestore emulator in development
*/

import { initializeApp, getApps, getApp } from 'firebase/app'
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore'

// ==========================
// Environment & Project Isolation
// ==========================

const appEnv = (import.meta.env.VITE_APP_ENV || (import.meta.env.DEV ? 'development' : 'production')).toLowerCase()
const projectId = (import.meta.env.VITE_FIREBASE_PROJECT_ID || (appEnv === 'development' ? 'demo-lanzar-dev' : '')).trim()

// CRITICAL ISOLATION RULE: In development, connecting to production project is strictly forbidden
const FORBIDDEN_DEV_PROJECTS = ['lanzar-95ae3', 'production', 'prod']
if (appEnv === 'development' && FORBIDDEN_DEV_PROJECTS.includes(projectId.toLowerCase())) {
  throw new Error(`[SECURITY FATAL] Production project ID "${projectId}" cannot be used in development environment. Configure a demo/emulator project.`)
}

// ==========================
// Firebase Configuration
// ==========================

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || (appEnv === 'development' ? 'fake-emulator-api-key' : ''),
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || (appEnv === 'development' ? 'localhost:9099' : ''),
  projectId: projectId || 'demo-lanzar-dev',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || (appEnv === 'development' ? '1:000000000000:web:emulator' : ''),
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || '',
}

// ==========================
// Firebase Application
// ==========================

const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig)

// Connect Firestore Emulator in development if configured
const firestoreEmuHost = import.meta.env.VITE_FIRESTORE_EMULATOR_HOST
if (appEnv === 'development' || firestoreEmuHost) {
  const hostStr = firestoreEmuHost || '127.0.0.1:8080'
  const [host, portStr] = hostStr.split(':')
  const port = parseInt(portStr || '8080', 10)
  try {
    const db = getFirestore(app)
    connectFirestoreEmulator(db, host, port)
    console.log(`[FIREBASE] Firestore connected to local emulator at ${host}:${port}`)
  } catch (e) {
    // connectFirestoreEmulator throws if already called; ignore in HMR
  }
}

export default app
