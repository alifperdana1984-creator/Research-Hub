// auth-guard.js — Research Hub (modular SDK v10)
// ─────────────────────────────────────────────────────────────────
// Include on every protected page (NOT on index.html — it handles
// auth inline).
//
// PLATFORM_KEY : role_researchhub
// ALLOWED_ROLES: research_user, research_admin
//
// Exposes globals after authReady fires:
//   window.firebaseApp   — FirebaseApp instance
//   window.auth          — Auth instance
//   window.db            — Firestore instance
//   window.currentUser   — firebase.User object
//   window.userProfile   — Firestore users/{uid} document data
//
// Dispatches CustomEvent 'authReady' on document with
//   detail: { user, profile }
// ─────────────────────────────────────────────────────────────────

import { initializeApp, getApps }
  from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getAuth, onAuthStateChanged, signOut }
  from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, serverTimestamp,
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js";

// ── Platform identity ─────────────────────────────────────────────
const PLATFORM_KEY  = 'role_researchhub';
const DEFAULT_ROLE  = 'research_user';
const ALLOWED_ROLES = ['research_user', 'research_admin'];

// Hide page content until auth is confirmed (prevents flash)
document.body.style.visibility = 'hidden';

// ── Initialise Firebase (guard against double-init) ───────────────
const firebaseConfig = {
  apiKey:            window.ENV.FIREBASE_API_KEY,
  authDomain:        window.ENV.FIREBASE_AUTH_DOMAIN,
  projectId:         window.ENV.FIREBASE_PROJECT_ID,
  storageBucket:     window.ENV.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: window.ENV.FIREBASE_MESSAGING_SENDER_ID,
  appId:             window.ENV.FIREBASE_APP_ID,
};

const app  = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

window.firebaseApp  = app;
window.auth         = auth;
window.db           = db;
window.firestoreOps = { doc, getDoc, setDoc, serverTimestamp };

// ── Auth state listener ───────────────────────────────────────────
onAuthStateChanged(auth, async (user) => {

  // 1. Not signed in → redirect to login
  if (!user) {
    window.location.replace('index.html');
    return;
  }

  // 2. Fetch (or create) Firestore profile
  let profile;
  const userRef = doc(db, 'users', user.uid);
  try {
    const snap = await getDoc(userRef);

    if (!snap.exists()) {
      const newProfile = {
        uid:            user.uid,
        email:          user.email,
        displayName:    user.displayName || '',
        photoURL:       user.photoURL    || '',
        [PLATFORM_KEY]: DEFAULT_ROLE,
        createdAt:      serverTimestamp(),
      };
      await setDoc(userRef, newProfile);
      profile = newProfile;
    } else {
      profile = snap.data();
      if (profile[PLATFORM_KEY] == null) {
        await setDoc(userRef, { [PLATFORM_KEY]: DEFAULT_ROLE }, { merge: true });
        profile = { ...profile, [PLATFORM_KEY]: DEFAULT_ROLE };
      }
    }
  } catch (err) {
    console.error('auth-guard: could not fetch user profile', err);
    await signOut(auth);
    window.location.replace('index.html?error=profile');
    return;
  }

  // 3. Role check
  const platformRole = profile[PLATFORM_KEY];
  if (!ALLOWED_ROLES.includes(platformRole)) {
    await signOut(auth);
    window.location.replace('index.html?error=access');
    return;
  }

  // 4. Expose globals
  window.currentUser = user;
  window.userProfile = profile;

  // 5. Show page and notify
  document.body.style.visibility = 'visible';
  document.dispatchEvent(new CustomEvent('authReady', {
    detail: { user, profile },
  }));
});
