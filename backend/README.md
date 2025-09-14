# Backend

This folder contains Firestore configuration for the project:

- Firestore security rules (`firestore/firestore.rules`)
- Firebase CLI configuration (`firebase.json`, `.firebaserc`)

## Firestore rules

Deploy with the Firebase CLI for updated rules including settings updates:

1. Ensure Firebase CLI is installed (`npm i -g firebase-tools` or use npx)
2. From `backend/`, run:

	npx firebase deploy --only firestore:rules --project zecx-hpot

The rules allow:
- Public read of honeypot docs and subcollections
- Pairing transition (set isPaired=true and pairingCode=null)
- Dashboard-controlled updates to `settings` only, with port validation

After deploying, you can toggle listeners from the dashboard UI (Listener Controls card).

Note: The rules allow public create and read on honeypot documents, events, and traffic; updates are only allowed to set `pairingCode` to null. Deletions are denied.
