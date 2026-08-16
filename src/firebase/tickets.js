/*
    tickets.js

    LANZAR Support Tickets ticket service.

    Responsibilities

    - Submit customer support tickets using atomic Firestore transactions
    - Manage and increment service-specific ticket counters
    - Formulate uniform ticket records with full customer and auth metadata
*/

import {
  doc,
  getDoc,
  runTransaction,
  getFirestore,
  serverTimestamp,
} from 'firebase/firestore'

import app from './config.js'

// ==========================
// Firestore
// ==========================

const db = getFirestore(app)

// ==========================
// Ticket Creation Transaction
// ==========================

export async function createTicket(
  selectedService,
  customer,
  user,
  problemType,
  description,
  structuredData = {}
) {
  if (
    !selectedService ||
    !customer ||
    !user
  ) {
    throw new Error(
      'Missing required arguments for ticket creation.'
    )
  }

  return await runTransaction(
    db,
    async (transaction) => {
      // 1. Get the current counter document
      const counterRef = doc(
        db,
        'counters',
        selectedService
      )

      const counterDoc = await transaction.get(
        counterRef
      )

      if (!counterDoc.exists()) {
        throw new Error(
          `Counter for service "${selectedService}" does not exist.`
        )
      }

      const nextNumber =
        counterDoc.data().nextNumber

      if (
        typeof nextNumber !== 'number'
      ) {
        throw new Error(
          `Counter nextNumber for "${selectedService}" is invalid.`
        )
      }

      // 2. Format the ticket number
      const ticketNumber = `LZ-${selectedService.toUpperCase()}-${nextNumber}`

      // 3. Create the ticket document reference with the ticket number as ID
      const ticketRef = doc(
        db,
        'tickets',
        ticketNumber
      )

      // 4. Set the ticket details
      const ticketData = {
        ticketNumber,
        accountId: customer.accountId || null,
        userId: customer.id,
        userName: customer.displayName || 'Unknown Customer',
        userEmail: customer.customerEmail || user.email,
        // Legacy compatibility fields
        customerId: customer.id,
        customerEmail: customer.customerEmail || user.email,
        customerName: customer.displayName || 'Unknown Customer',
        authEmail: user.email,
        authUid: user.uid,
        service: selectedService,
        category: problemType,
        // New structured fields
        subcategory: structuredData.issueType || structuredData.subcategory || null,
        issueType: structuredData.issueType || structuredData.subcategory || null,
        locationId: structuredData.locationId || null,
        locationName: structuredData.locationName || null,
        assetId: structuredData.assetId || null,
        assetName: structuredData.assetName || null,
        answers: structuredData.answers || {},
        description: description,
        status: 'PENDING',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        history: [],
      }

      transaction.set(
        ticketRef,
        ticketData
      )

      // 5. Increment the counter
      transaction.update(counterRef, {
        nextNumber: nextNumber + 1,
      })

      return ticketNumber
    }
  )
}

// ==========================
// Proposed Ticket Number
// ==========================

export async function getProposedTicketNumber(serviceId) {
  if (!serviceId) {
    return null
  }

  const counterRef = doc(
    db,
    'counters',
    serviceId
  )
  const counterSnapshot = await getDoc(counterRef)

  if (!counterSnapshot.exists()) {
    return null
  }

  const nextNumber =
    counterSnapshot.data().nextNumber
  return `LZ-${serviceId.toUpperCase()}-${nextNumber}`
}
