## Deploying the Dashboard to Vercel

This folder contains a static dashboard (`public/`) that can be deployed to Vercel.

### Prerequisites
- A Firebase project (Firestore + Authentication enabled)
- Google sign-in enabled in Firebase Console → Authentication → Sign-in method
- Your dashboard domain added to Firebase → Authentication → Settings → Authorized domains

### Steps
1. Push this repo to GitHub/GitLab/Bitbucket or use Vercel CLI.
2. In Vercel, import the `dashboard/` directory as a new project.
3. Use the included `vercel.json` for static hosting.
4. Ensure `public/config.js` has your Firebase Web config (or paste it into the UI on first load).

### Notes
- The app uses Firestore client SDK directly; no server runtime is required.
- Geolocation calls use an HTTPS endpoint to avoid mixed-content in production.
- Pairing and settings updates require an authenticated user and will be enforced by Firestore rules.
