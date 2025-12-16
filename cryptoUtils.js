// Server-side decryption utility for encrypted prompts
// Matches the client-side encryption in BeaconBlocker-Dashboard/src/cryptoUtils.js
const crypto = require('crypto');

const SALT = 'BeaconBlockerPresetSalt_v1';
const ITERATIONS = 100000;
const KEY_LENGTH = 32; // 256 bits for AES-256
const IV_LENGTH = 12; // 96 bits for AES-GCM

// Derive encryption key from user ID using PBKDF2
function deriveKeyFromUserId(userId) {
    return crypto.pbkdf2Sync(
        userId,
        SALT,
        ITERATIONS,
        KEY_LENGTH,
        'sha256'
    );
}

// Decrypt an encrypted prompt
function decryptPrompt(encryptedPrompt, userId) {
    console.log('[DECRYPT] Starting decryption...');
    console.log('[DECRYPT] Prompt starts with ENC:', encryptedPrompt?.startsWith('ENC:'));
    console.log('[DECRYPT] UserId provided:', !!userId);

    // If not encrypted (no ENC: prefix), return as-is
    if (!encryptedPrompt || !encryptedPrompt.startsWith('ENC:')) {
        console.log('[DECRYPT] Not encrypted, returning as-is');
        return encryptedPrompt;
    }

    if (!userId) {
        console.error('[DECRYPT] Cannot decrypt without userId');
        return encryptedPrompt;
    }

    try {
        // Remove the ENC: prefix and decode base64
        const base64Data = encryptedPrompt.substring(4);
        console.log('[DECRYPT] Base64 data length:', base64Data.length);

        const combined = Buffer.from(base64Data, 'base64');
        console.log('[DECRYPT] Combined buffer length:', combined.length);

        // Extract IV (first 12 bytes) and encrypted data (rest)
        const iv = combined.slice(0, IV_LENGTH);
        const encryptedData = combined.slice(IV_LENGTH);
        console.log('[DECRYPT] IV length:', iv.length, 'Encrypted length:', encryptedData.length);

        // Derive the key from userId
        const key = deriveKeyFromUserId(userId);
        console.log('[DECRYPT] Key derived, length:', key.length);

        // Create decipher with AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

        // AES-GCM includes auth tag in the last 16 bytes
        const authTagLength = 16;
        const authTag = encryptedData.slice(-authTagLength);
        const actualEncrypted = encryptedData.slice(0, -authTagLength);
        console.log('[DECRYPT] AuthTag length:', authTag.length, 'Actual encrypted length:', actualEncrypted.length);

        decipher.setAuthTag(authTag);

        // Decrypt
        let decrypted = decipher.update(actualEncrypted, null, 'utf8');
        decrypted += decipher.final('utf8');

        console.log('[DECRYPT] SUCCESS! Decrypted to:', decrypted);
        return decrypted;
    } catch (error) {
        console.error('[DECRYPT] FAILED:', error.message);
        console.error('[DECRYPT] Full error:', error);
        return encryptedPrompt; // Return encrypted version on error
    }
}

module.exports = { decryptPrompt };
