import firebase from 'firebase/app';
import 'firebase/firestore';

const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_AUTH_DOMAIN",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_STORAGE_BUCKET",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID"
};

firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();

export const getHoneypots = async () => {
    try {
        const snapshot = await db.collection('honeypots').get();
        const honeypots = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        return honeypots;
    } catch (error) {
        console.error("Error fetching honeypots: ", error);
        throw error;
    }
};

export const addHoneypot = async (honeypotData) => {
    try {
        const docRef = await db.collection('honeypots').add(honeypotData);
        return docRef.id;
    } catch (error) {
        console.error("Error adding honeypot: ", error);
        throw error;
    }
};