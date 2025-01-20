const express = require('express');
const router = express.Router();
const { encrypt, decrypt } = require('../utils/encryption.utils');
const { auth } = require('../firebaseAdmin');

router.post('/messages/encrypt', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { message } = req.body;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split('Bearer ')[1];
    
    try {
        await auth.verifyIdToken(token);
        const encryptedMessage = encrypt(message);
        res.json({ encryptedMessage });
    } catch (error) {
        res.status(403).json({ error: 'Authentication failed' });
    }
});

router.post('/messages/decrypt', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { encryptedMessage } = req.body;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split('Bearer ')[1];
    
    try {
        await auth.verifyIdToken(token);
        const decryptedMessage = decrypt(encryptedMessage);
        res.json({ decryptedMessage });
    } catch (error) {
        res.status(403).json({ error: 'Authentication failed' });
    }
});

module.exports = router;
