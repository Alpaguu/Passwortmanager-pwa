const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT) || 57321;
const ENCRYPTION_SCHEME = 'dataKey-v1';

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.static('public')); // Serve static files

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        // In Electron desktop (http://localhost) we must NOT require secure cookies
        secure: process.env.ELECTRON === 'true' ? false : process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Global variables
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'passwords.json');
const MASTER_PASSWORDS_FILE = path.join(DATA_DIR, 'master_passwords.json');
const FOLDERS_FILE = path.join(DATA_DIR, 'folders.json');

// Session management
const getMasterPassword = (req) => {
    return req.session.masterPassword || null;
};

const setMasterPassword = (req, password) => {
    req.session.masterPassword = password;
    req.session.authenticated = true;
    req.session.lastActivity = new Date().toISOString();
};

const clearSession = (req) => {
    req.session.destroy();
};

// Encryption utilities
class EncryptionManager {
    static deriveKey(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    }

    static generateSalt() {
        return crypto.randomBytes(16);
    }

    static encrypt(text, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return {
            encrypted,
            iv: iv.toString('hex')
        };
    }

    static decrypt(encryptedData, key) {
        try {
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(encryptedData.iv, 'hex'));
            let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            throw new Error('Decryption failed - wrong master password');
        }
    }
}

// File operations
class FileManager {
    static wrapDataKeyForPassword(password, salt, dataKeyHex) {
        const wrapperKey = EncryptionManager.deriveKey(password, salt);
        const { encrypted, iv } = EncryptionManager.encrypt(dataKeyHex, wrapperKey);
        return { wrappedDataKey: encrypted, wrapIv: iv };
    }

    static unwrapDataKeyWithPassword(password, masterPasswordEntry) {
        const salt = Buffer.from(masterPasswordEntry.salt, 'hex');
        const wrapperKey = EncryptionManager.deriveKey(password, salt);
        const dataKeyHex = EncryptionManager.decrypt({ encrypted: masterPasswordEntry.wrappedDataKey, iv: masterPasswordEntry.wrapIv }, wrapperKey);
        return dataKeyHex;
    }
    static async ensureDataDirectory() {
        try {
            await fs.access(DATA_DIR);
        } catch {
            await fs.mkdir(DATA_DIR, { recursive: true });
        }
    }

    static async readPasswords() {
        try {
            await this.ensureDataDirectory();
            const data = await fs.readFile(DATA_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            if (error.code === 'ENOENT') {
                // File doesn't exist, return empty array
                return [];
            }
            throw error;
        }
    }

    static async writePasswords(passwords) {
        await this.ensureDataDirectory();
        await fs.writeFile(DATA_FILE, JSON.stringify(passwords, null, 2));
    }

    static async readFolders() {
        try {
            await this.ensureDataDirectory();
            const data = await fs.readFile(FOLDERS_FILE, 'utf8');
            const parsed = JSON.parse(data);
            const folders = Array.isArray(parsed) ? parsed : [];
            // Deduplicate by normalized name (first wins)
            const seen = new Set();
            const unique = [];
            for (const f of folders) {
                const key = String(f.name || '').trim().toLowerCase();
                if (seen.has(key)) continue;
                seen.add(key);
                unique.push(f);
            }
            if (unique.length !== folders.length) {
                await this.writeFolders(unique).catch(() => {});
            }
            return unique;
        } catch (error) {
            if (error.code === 'ENOENT') {
                return [];
            }
            throw error;
        }
    }

    static async writeFolders(folders) {
        await this.ensureDataDirectory();
        const arr = Array.isArray(folders) ? folders : [];
        const seen = new Set();
        const unique = [];
        for (const f of arr) {
            const key = String(f.name || '').trim().toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            unique.push(f);
        }
        await fs.writeFile(FOLDERS_FILE, JSON.stringify(unique, null, 2));
    }

    static async loadMasterPasswords() {
        try {
            const data = await fs.readFile(MASTER_PASSWORDS_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            if (error.code === 'ENOENT') {
                return []; // No master passwords set yet
            }
            throw error;
        }
    }

    static async saveMasterPasswords(masterPasswords) {
        await this.ensureDataDirectory();
        await fs.writeFile(MASTER_PASSWORDS_FILE, JSON.stringify(masterPasswords, null, 2));
    }

    static async migrateVaultToDataKey(confirmingPassword) {
        // If already migrated, just return existing datakey via unwrap
        const masterPasswords = await this.loadMasterPasswords();
        const match = await (async () => {
            for (const mp of masterPasswords) {
                const salt = Buffer.from(mp.salt, 'hex');
                const hashed = crypto.pbkdf2Sync(confirmingPassword, salt, 100000, 64, 'sha256').toString('hex');
                if (hashed === mp.hashedPassword) return mp;
            }
            return null;
        })();
        if (!match) {
            throw new Error('Invalid master password');
        }

        // If wrapped already present, just unwrap and return
        if (match.wrappedDataKey && match.wrapIv) {
            return this.unwrapDataKeyWithPassword(confirmingPassword, match);
        }

        // Create a new random data key and wrap it with the confirming password
        const dataKeyHex = crypto.randomBytes(32).toString('hex');
        const { wrappedDataKey, wrapIv } = this.wrapDataKeyForPassword(confirmingPassword, Buffer.from(match.salt, 'hex'), dataKeyHex);

        // Write wrapped data key to the matching entry; ensure a primary exists
        let hasPrimary = masterPasswords.some(mp => mp.isPrimary === true);
        const updated = masterPasswords.map(mp => {
            if (mp.id === match.id) {
                return { ...mp, wrappedDataKey, wrapIv, isPrimary: hasPrimary ? (mp.isPrimary === true) : true };
            }
            return mp;
        });

        if (!hasPrimary) {
            hasPrimary = true;
        }

        await this.saveMasterPasswords(updated);

        // Re-encrypt vault with data key if there is data in legacy format
        const legacyPasswords = await this.readPasswords();
        if (Array.isArray(legacyPasswords) && legacyPasswords.length > 0 && !legacyPasswords[0].encryptionScheme) {
            // Decrypt with legacy password (confirmingPassword). If this fails, migration cannot proceed.
            const decrypted = await this.loadAndDecryptPasswords(confirmingPassword);
            await this.encryptAndSavePasswords(decrypted, dataKeyHex);
        }

        return dataKeyHex;
    }

    static async getDataKeyUsingMasterPassword(password) {
        const masterPasswords = await this.loadMasterPasswords();
        for (const mp of masterPasswords) {
            const salt = Buffer.from(mp.salt, 'hex');
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
            if (hashedPassword === mp.hashedPassword) {
                if (mp.wrappedDataKey && mp.wrapIv) {
                    return this.unwrapDataKeyWithPassword(password, mp);
                }
                // Not migrated yet – perform migration using this password
                return await this.migrateVaultToDataKey(password);
            }
        }
        return null;
    }

    static async addMasterPassword(password, name = 'Master Password', hint = '') {
        const masterPasswords = await this.loadMasterPasswords();
        
        // Check if password already exists
        for (const mp of masterPasswords) {
            const salt = Buffer.from(mp.salt, 'hex');
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
            if (hashedPassword === mp.hashedPassword) {
                throw new Error('This password already exists');
            }
        }

        const salt = EncryptionManager.generateSalt();
        const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
        
        const newMasterPassword = {
            id: require('uuid').v4(),
            name,
            hint: String(hint || ''),
            hashedPassword,
            salt: salt.toString('hex'),
            createdAt: new Date().toISOString(),
            isPrimary: masterPasswords.length === 0 // first becomes primary by default
        };
        
        masterPasswords.push(newMasterPassword);
        await this.saveMasterPasswords(masterPasswords);
        
        return newMasterPassword;
    }

    static async removeMasterPassword(id, confirmingPassword) {
        const masterPasswords = await this.loadMasterPasswords();
        const mp = masterPasswords.find(m => m.id === id);
        if (!mp) {
            throw new Error('Master password not found');
        }

        if (!confirmingPassword || String(confirmingPassword).length === 0) {
            throw new Error('Confirmation password is required');
        }

        const salt = Buffer.from(mp.salt, 'hex');
        const hashedPassword = crypto.pbkdf2Sync(confirmingPassword, salt, 100000, 64, 'sha256').toString('hex');
        if (hashedPassword !== mp.hashedPassword) {
            throw new Error('Invalid master password confirmation');
        }

        const filteredPasswords = masterPasswords.filter(m => m.id !== id);
        await this.saveMasterPasswords(filteredPasswords);
        return true;
    }

    static async verifyMasterPassword(password) {
        const masterPasswords = await this.loadMasterPasswords();
        
        for (const mp of masterPasswords) {
            const salt = Buffer.from(mp.salt, 'hex');
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
            
            if (hashedPassword === mp.hashedPassword) {
                return { success: true, masterPassword: mp };
            }
        }
        
        return { success: false };
    }

    static async isMasterPasswordSet() {
        const masterPasswords = await this.loadMasterPasswords();
        return masterPasswords.length > 0;
    }

    static async getMasterPasswords() {
        const masterPasswords = await this.loadMasterPasswords();
        return masterPasswords.map(mp => ({
            id: mp.id,
            name: mp.name,
            hint: mp.hint || '',
            createdAt: mp.createdAt
        }));
    }

    static async encryptAndSavePasswords(passwords, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        const encryptedPasswords = passwords.map(pwd => {
            const salt = EncryptionManager.generateSalt();
            const key = EncryptionManager.deriveKey(keyString, salt);
            
            const encryptedPassword = EncryptionManager.encrypt(pwd.password, key);
            const encryptedUsername = EncryptionManager.encrypt(pwd.username, key);
            
            return {
                ...pwd,
                password: encryptedPassword.encrypted,
                passwordIv: encryptedPassword.iv,
                passwordSalt: salt.toString('hex'),
                username: encryptedUsername.encrypted,
                usernameIv: encryptedUsername.iv,
                usernameSalt: salt.toString('hex'),
                encryptionScheme: ENCRYPTION_SCHEME
            };
        });

        await this.writePasswords(encryptedPasswords);
    }

    static async loadAndDecryptPasswords(keyString) {
        const encryptedPasswords = await this.readPasswords();
        
        if (!keyString) {
            throw new Error('Master password not set');
        }

        return encryptedPasswords.map(pwd => {
            try {
                // Use stored salt for decryption
                const salt = Buffer.from(pwd.passwordSalt || pwd.usernameSalt || '00000000000000000000000000000000', 'hex');
                const key = EncryptionManager.deriveKey(keyString, salt);
                
                return {
                    ...pwd,
                    password: EncryptionManager.decrypt({ encrypted: pwd.password, iv: pwd.passwordIv }, key),
                    username: EncryptionManager.decrypt({ encrypted: pwd.username, iv: pwd.usernameIv }, key)
                };
            } catch (error) {
                console.error('Error decrypting password:', error);
                throw new Error('Decryption failed - wrong master password');
            }
        });
    }
}

// Authentication middleware
const requireMasterPassword = (req, res, next) => {
    const currentMasterPassword = getMasterPassword(req);
    if (!currentMasterPassword || !req.session.authenticated) {
        return res.status(401).json({ 
            error: 'Not authenticated. Please login with your master password.' 
        });
    }
    next();
};

// API Routes

// Add new master password
app.post('/api/add-master-password', async (req, res) => {
    try {
        const { password, name, hint, confirmingPassword } = req.body;
        
        if (!password || password.length < 8) {
            return res.status(400).json({ 
                error: 'Master password must be at least 8 characters long' 
            });
        }

        const existingSet = await FileManager.isMasterPasswordSet();
        if (existingSet) {
            // Require primary/any existing password confirmation to add new one
            if (!confirmingPassword) {
                return res.status(400).json({ error: 'Confirmation with an existing master password is required' });
            }
            const dataKey = await FileManager.getDataKeyUsingMasterPassword(confirmingPassword);
            if (!dataKey) {
                return res.status(401).json({ error: 'Invalid confirmation master password' });
            }
            // Wrap datakey for the new password
            const salt = EncryptionManager.generateSalt();
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
            const { wrappedDataKey, wrapIv } = FileManager.wrapDataKeyForPassword(password, salt, dataKey);
            const newMasterPassword = {
                id: require('uuid').v4(),
                name: name || 'Master Password',
                hint: String(hint || ''),
                hashedPassword,
                salt: salt.toString('hex'),
                createdAt: new Date().toISOString(),
                wrappedDataKey,
                wrapIv,
                isPrimary: false
            };
            const list = await FileManager.loadMasterPasswords();
            list.push(newMasterPassword);
            await FileManager.saveMasterPasswords(list);
            // Important: set session to DataKey, not plaintext password
            setMasterPassword(req, dataKey);
        } else {
            // First password: create datakey and wrap it
            const created = await FileManager.addMasterPassword(password, name || 'Master Password', hint || '');
            const dataKeyHex = crypto.randomBytes(32).toString('hex');
            const { wrappedDataKey, wrapIv } = FileManager.wrapDataKeyForPassword(password, Buffer.from(created.salt, 'hex'), dataKeyHex);
            const list = await FileManager.loadMasterPasswords();
            const updated = list.map(mp => mp.id === created.id ? { ...mp, wrappedDataKey, wrapIv } : mp);
            await FileManager.saveMasterPasswords(updated);
            // Important: set session to DataKey so all subsequent ops use it
            setMasterPassword(req, dataKeyHex);
        }
        
        res.json({ 
            message: 'Master password added successfully',
            masterPassword: { name: name || 'Master Password' }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Remove master password
app.delete('/api/remove-master-password/:id', async (req, res) => {
    try {
        const { id } = req.params;
        // Accept confirmation password from body, header or query for robustness
        const confirmingPassword = (req.body && req.body.confirmingPassword) ||
            req.headers['x-confirming-password'] ||
            req.query.confirmingPassword;

        if (!confirmingPassword) {
            return res.status(400).json({ error: 'Confirmation password is required' });
        }

        try {
            await FileManager.removeMasterPassword(id, confirmingPassword);
        } catch (err) {
            if (String(err.message).includes('Invalid master password')) {
                return res.status(401).json({ error: 'Invalid master password' });
            }
            throw err;
        }

        // If the removed password matches the current session password or no master passwords remain, clear the session
        try {
            const current = getMasterPassword(req);
            const removedCurrent = current && String(current) === String(confirmingPassword);
            const anyLeft = await FileManager.isMasterPasswordSet();
            if (removedCurrent || !anyLeft) {
                clearSession(req);
            }
        } catch (_) {
            // Best-effort session cleanup; ignore secondary errors
            try { clearSession(req); } catch (_) {}
        }
        
        res.json({ message: 'Master password removed successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all master passwords (names only, no sensitive data)
app.get('/api/master-passwords', async (req, res) => {
    try {
        const masterPasswords = await FileManager.getMasterPasswords();
        res.json(masterPasswords);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify master password (login)
app.post('/api/verify-master-password', async (req, res) => {
    try {
        const { password, confirmingPassword } = req.body;
        
        if (!password) {
            return res.status(400).json({ 
                error: 'Password is required' 
            });
        }

        // Check if any master password is set
        const isSet = await FileManager.isMasterPasswordSet();
        if (!isSet) {
            return res.status(400).json({ 
                error: 'No master passwords set. Please add one first.' 
            });
        }

        // Verify the password and get the matching entry
        const result = await FileManager.verifyMasterPassword(password);
        if (!result.success) {
            return res.status(401).json({ 
                error: 'Invalid master password' 
            });
        }

        // If this master password entry has no wrapped key but the vault is already in dataKey mode,
        // require a confirming existing master password to link (wrap) the DataKey for this password.
        const allMasters = await FileManager.loadMasterPasswords();
        const thisEntry = allMasters.find(m => m.id === result.masterPassword.id);

        let dataKey;
        const currentPasswords = await FileManager.readPasswords();
        const vaultIsDataKey = Array.isArray(currentPasswords) && currentPasswords.length > 0 && currentPasswords[0].encryptionScheme === ENCRYPTION_SCHEME;

        if (!thisEntry.wrappedDataKey || !thisEntry.wrapIv) {
            if (vaultIsDataKey) {
                // Need to use an already-linked password to obtain DataKey
                if (!confirmingPassword) {
                    return res.status(412).json({ error: 'Linking required: please confirm with an existing master password', code: 'LINK_REQUIRED' });
                }
                const dk = await FileManager.getDataKeyUsingMasterPassword(confirmingPassword);
                if (!dk) {
                    return res.status(401).json({ error: 'Invalid confirmation master password' });
                }
                // Wrap for thisEntry using the provided password
                const salt = Buffer.from(thisEntry.salt, 'hex');
                const { wrappedDataKey, wrapIv } = FileManager.wrapDataKeyForPassword(password, salt, dk);
                const updated = allMasters.map(mp => mp.id === thisEntry.id ? { ...mp, wrappedDataKey, wrapIv } : mp);
                await FileManager.saveMasterPasswords(updated);
                dataKey = dk;
            } else {
                // Legacy vault: try migrating using this password directly; if fail, require confirming existing password
                try {
                    dataKey = await FileManager.migrateVaultToDataKey(password);
                } catch (e) {
                    if (!confirmingPassword) {
                        return res.status(412).json({ error: 'Migration requires confirmation with an existing master password', code: 'MIGRATION_CONFIRM_REQUIRED' });
                    }
                    const dk = await FileManager.migrateVaultToDataKey(confirmingPassword);
                    // Also wrap for thisEntry using the provided (new) password
                    const salt = Buffer.from(thisEntry.salt, 'hex');
                    const { wrappedDataKey, wrapIv } = FileManager.wrapDataKeyForPassword(password, salt, dk);
                    const updated = (await FileManager.loadMasterPasswords()).map(mp => mp.id === thisEntry.id ? { ...mp, wrappedDataKey, wrapIv } : mp);
                    await FileManager.saveMasterPasswords(updated);
                    dataKey = dk;
                }
            }
        } else {
            // Already linked
            dataKey = await FileManager.getDataKeyUsingMasterPassword(password);
            if (!dataKey) {
                return res.status(401).json({ error: 'Invalid master password' });
            }
        }

        // Set current session
        setMasterPassword(req, dataKey);

        res.json({ 
            message: 'Login successful',
            masterPassword: {
                id: result.masterPassword.id,
                name: result.masterPassword.name
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all passwords
app.get('/api/all', requireMasterPassword, async (req, res) => {
    try {
        const dataKey = getMasterPassword(req); // now stores DataKey
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        res.json(passwords);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const normalizeUrl = (raw) => {
    const input = String(raw || '').trim();
    if (!input) return '';
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input)) return input;
    if (input.startsWith('www.')) return `https://${input}`;
    if (/^(localhost(?::\d+)?|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)/.test(input)) {
        return `http://${input}`;
    }
    if (/^[^\s@]+\.[^\s@]{2,}/.test(input)) return `https://${input}`;
    return input;
};

// Add new password
app.post('/api/add', requireMasterPassword, async (req, res) => {
    try {
        const { title, username, password, url, notes, folderId } = req.body;
        
        if (!title || !username || !password) {
            return res.status(400).json({ 
                error: 'Title, username, and password are required' 
            });
        }

        const newPassword = {
            id: uuidv4(),
            title,
            username,
            password,
            url: normalizeUrl(url || ''),
            notes: notes || '',
            folderId: folderId || null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        passwords.push(newPassword);
        await FileManager.encryptAndSavePasswords(passwords, dataKey);

        res.status(201).json(newPassword);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update password
app.put('/api/update/:id', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, username, password, url, notes, folderId } = req.body;
        
        if (!title || !username || !password) {
            return res.status(400).json({ 
                error: 'Title, username, and password are required' 
            });
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const index = passwords.findIndex(pwd => pwd.id === id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Password not found' });
        }

        passwords[index] = {
            ...passwords[index],
            title,
            username,
            password,
            url: normalizeUrl(url || ''),
            notes: notes || '',
            folderId: folderId ?? passwords[index].folderId ?? null,
            updatedAt: new Date().toISOString()
        };

        await FileManager.encryptAndSavePasswords(passwords, dataKey);
        res.json(passwords[index]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete password
app.delete('/api/delete/:id', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const filteredPasswords = passwords.filter(pwd => pwd.id !== id);
        
        if (filteredPasswords.length === passwords.length) {
            return res.status(404).json({ error: 'Password not found' });
        }

        await FileManager.encryptAndSavePasswords(filteredPasswords, dataKey);
        res.json({ message: 'Password deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Export passwords
app.get('/api/export', requireMasterPassword, async (req, res) => {
    try {
        const dataKey = getMasterPassword(req);
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const exportData = {
            version: '1.0',
            exportDate: new Date().toISOString(),
            passwords
        };
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="passwords_backup_${new Date().toISOString().split('T')[0]}.json"`);
        res.json(exportData);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import passwords
app.post('/api/import', requireMasterPassword, async (req, res) => {
    try {
        const { passwords } = req.body;
        
        if (!Array.isArray(passwords)) {
            return res.status(400).json({ error: 'Invalid import data format' });
        }

        // Validate password structure
        for (const pwd of passwords) {
            if (!pwd.title || !pwd.username || !pwd.password) {
                return res.status(400).json({ 
                    error: 'Invalid password entry: title, username, and password are required' 
                });
            }
        }

        // Add IDs to imported passwords if missing
        const processedPasswords = passwords.map(pwd => ({
            ...pwd,
            id: pwd.id || uuidv4(),
            createdAt: pwd.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString()
        }));

        const dataKey = getMasterPassword(req);
        await FileManager.encryptAndSavePasswords(processedPasswords, dataKey);
        res.json({ message: 'Passwords imported successfully', count: processedPasswords.length });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Check if master passwords are set
app.get('/api/master-password-status', async (req, res) => {
    try {
        const isSet = await FileManager.isMasterPasswordSet();
        const masterPasswords = await FileManager.getMasterPasswords();
        res.json({ 
            masterPasswordSet: isSet,
            masterPasswordCount: masterPasswords.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    try {
        clearSession(req);
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Check session status
app.get('/api/session-status', async (req, res) => {
    try {
        let isAuthenticated = Boolean(req.session.authenticated && getMasterPassword(req));

        if (isAuthenticated) {
            // Extra validation: ensure a master password still exists and the session password is valid
            try {
                const anySet = await FileManager.isMasterPasswordSet();
                // We now store the DataKey in session, so just ensure that master passwords still exist
                if (!anySet) {
                    clearSession(req);
                    isAuthenticated = false;
                }
            } catch (_) {
                // On any error, consider session invalid
                clearSession(req);
                isAuthenticated = false;
            }
        }

        res.json({ 
            authenticated: isAuthenticated,
            lastActivity: req.session?.lastActivity || null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        sessionActive: req.session.authenticated || false
    });
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Folder management endpoints
// Get all folders
app.get('/api/folders', requireMasterPassword, async (req, res) => {
    try {
        const folders = await FileManager.readFolders();
        res.json(folders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create folder
app.post('/api/folders', requireMasterPassword, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || String(name).trim().length === 0) {
            return res.status(400).json({ error: 'Folder name is required' });
        }
        const folders = await FileManager.readFolders();
        const normalized = String(name).trim().toLowerCase();
        const existing = folders.find(f => String(f.name || '').trim().toLowerCase() === normalized);
        if (existing) {
            // Idempotent behavior: return existing folder (handles double-submit)
            return res.json(existing);
        }
        const newFolder = {
            id: uuidv4(),
            name: String(name).trim(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        folders.push(newFolder);
        await FileManager.writeFolders(folders);
        res.status(201).json(newFolder);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update folder (rename)
app.put('/api/folders/:id', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;
        if (!name || String(name).trim().length === 0) {
            return res.status(400).json({ error: 'Folder name is required' });
        }
        const folders = await FileManager.readFolders();
        const index = folders.findIndex(f => f.id === id);
        if (index === -1) {
            return res.status(404).json({ error: 'Folder not found' });
        }
        folders[index].name = String(name).trim();
        folders[index].updatedAt = new Date().toISOString();
        await FileManager.writeFolders(folders);
        res.json(folders[index]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete folder (optionally migrate passwords to another folder or null)
app.delete('/api/folders/:id', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { migrateTo } = req.query; // optional destination folder id or 'null'
        let folders = await FileManager.readFolders();
        const folderExists = folders.some(f => f.id === id);
        if (!folderExists) {
            return res.status(404).json({ error: 'Folder not found' });
        }
        folders = folders.filter(f => f.id !== id);
        await FileManager.writeFolders(folders);

        // Reassign passwords
        const dataKey = getMasterPassword(req);
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const targetFolderId = migrateTo === 'null' || !migrateTo ? null : String(migrateTo);
        const updated = passwords.map(p => p.folderId === id ? { ...p, folderId: targetFolderId, updatedAt: new Date().toISOString() } : p);
        await FileManager.encryptAndSavePasswords(updated, dataKey);

        res.json({ message: 'Folder deleted', migratedTo: targetFolderId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Move password to folder
app.put('/api/passwords/:id/move', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { folderId } = req.body; // can be null
        const dataKey = getMasterPassword(req);
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const index = passwords.findIndex(p => p.id === id);
        if (index === -1) {
            return res.status(404).json({ error: 'Password not found' });
        }
        passwords[index] = { ...passwords[index], folderId: folderId || null, updatedAt: new Date().toISOString() };
        await FileManager.encryptAndSavePasswords(passwords, dataKey);
        res.json(passwords[index]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server (HTTP by default; optional HTTPS for LAN access from iPhone)
const startServer = () => {
    const useHttpsForce = process.env.USE_HTTPS_FORCE === '1' || process.env.USE_HTTPS_FORCE === 'true';
    const useHttps = useHttpsForce || (process.env.ELECTRON === 'true' ? false : (process.env.USE_HTTPS === '1' || process.env.USE_HTTPS === 'true'));
    if (useHttps) {
        try {
            const keyPath = process.env.HTTPS_KEY_PATH || path.join(__dirname, 'certs', 'server.key');
            const certPath = process.env.HTTPS_CERT_PATH || path.join(__dirname, 'certs', 'server.crt');
            const caPath = process.env.HTTPS_CA_PATH; // optional chain
            const options = {
                key: fsSync.readFileSync(keyPath),
                cert: fsSync.readFileSync(certPath),
            };
            if (caPath && fsSync.existsSync(caPath)) {
                options.ca = fsSync.readFileSync(caPath);
            }
            https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
                console.log(`🔐 HTTPS Password Manager Backend running on https://localhost:${PORT}`);
                console.log(`   Tip: Use your LAN hostname or IP instead of localhost on iPhone.`);
                console.log(`📁 Data will be stored in: ${DATA_FILE}`);
            });
        } catch (e) {
            console.error('Failed to start HTTPS server. Falling back to HTTP. Reason:', e.message);
            http.createServer(app).listen(PORT, '0.0.0.0', () => {
                console.log(`🚀 Password Manager Backend running on http://localhost:${PORT}`);
                console.log(`📁 Data will be stored in: ${DATA_FILE}`);
            });
        }
    } else {
        http.createServer(app).listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Password Manager Backend running on http://localhost:${PORT}`);
            console.log(`📁 Data will be stored in: ${DATA_FILE}`);
        });
    }
};

startServer();

module.exports = app; 