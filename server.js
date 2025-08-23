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
const FileStore = require('session-file-store')(session);
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT) || 57321;
const ENCRYPTION_SCHEME = 'dataKey-v1';

// Rate limiting for large requests
const rateLimit = require('express-rate-limit');

const largeDataLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // limit each IP to 10 requests per windowMs for large data endpoints
    message: 'Too many requests for large data, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.static('public')); // Serve static files from /public at root (/icon-192.png)
app.use('/public', express.static(path.join(__dirname, 'public'))); // Also serve with /public prefix for manifest paths
// Also serve root-level assets like manifest and service worker
app.get('/manifest.webmanifest', (req, res) => {
    res.sendFile(path.join(__dirname, 'manifest.webmanifest'));
});
app.get('/service-worker.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this-in-production',
    resave: true, // Force resave to handle file store issues
    saveUninitialized: false,
    rolling: true, // refresh expiration on each request
    store: new FileStore({
        retries: 10, // More retries for distributed app
        path: process.env.ELECTRON === 'true' 
            ? path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'sessions')
            : path.join(__dirname, 'data', 'sessions'),
        ttl: 5 * 60, // 5 minutes in seconds
        reapInterval: 60 * 60, // Clean up expired sessions every hour
        logFn: (message) => {
            // Log all session messages in distributed app for debugging
            if (process.env.ELECTRON === 'true' || process.env.NODE_ENV === 'development') {
                console.log('Session:', message);
            }
        },
        // Fix for file store issues
        encoding: 'utf8',
        fileExtension: '.json',
        // Additional options for distributed app
        secret: process.env.SESSION_SECRET || 'your-secret-key-change-this-in-production',
        // Better error handling for distributed app
        reapAsync: true,
        reapInterval: 60 * 60, // Clean up expired sessions every hour
        // Ensure proper file permissions
        fileMode: 0o600,
        dirMode: 0o755
    }),
    cookie: {
        // In Electron desktop (http://localhost) we must NOT require secure cookies
        secure: process.env.ELECTRON === 'true' ? false : process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 5 * 60 * 1000, // 5 minutes for auto-logout
        // Better cookie handling for Electron
        domain: process.env.ELECTRON === 'true' ? 'localhost' : undefined
    }
}));

// Ensure sessions directory exists
const sessionsDir = path.join(__dirname, 'data', 'sessions');
if (!fsSync.existsSync(sessionsDir)) {
    fsSync.mkdirSync(sessionsDir, { recursive: true });
    console.log('Created sessions directory:', sessionsDir);
}

// Global variables
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'passwords.json');
const MASTER_PASSWORDS_FILE = path.join(DATA_DIR, 'master_passwords.json');
const FOLDERS_FILE = path.join(DATA_DIR, 'folders.json');

// Performance-Optimierung: Memory-Cache für Passwörter
const passwordCache = new Map();
const cacheTimestamps = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 Minuten Cache-TTL

// Performance-Optimierung: Index für schnelle Suche
const searchIndex = new Map();
const indexTimestamps = new Map();
const INDEX_TTL = 10 * 60 * 1000; // 10 Minuten Index-TTL

// Cache-Management
const getCachedPasswords = (dataKey) => {
    const cacheKey = `passwords_${dataKey}`;
    const cached = passwordCache.get(cacheKey);
    const timestamp = cacheTimestamps.get(cacheKey);
    
    if (cached && timestamp && (Date.now() - timestamp) < CACHE_TTL) {
        performanceMetrics.cacheHits++;
        return cached;
    }
    
    performanceMetrics.cacheMisses++;
    return null;
};

const setCachedPasswords = (dataKey, passwords) => {
    const cacheKey = `passwords_${dataKey}`;
    passwordCache.set(cacheKey, passwords);
    cacheTimestamps.set(cacheKey, Date.now());
};

const invalidateCache = (dataKey) => {
    const cacheKey = `passwords_${dataKey}`;
    passwordCache.delete(cacheKey);
    cacheTimestamps.delete(cacheKey);
    
    // Auch den Index invalidieren
    const indexKey = `index_${dataKey}`;
    searchIndex.delete(indexKey);
    indexTimestamps.delete(indexKey);
};

const clearAllCaches = () => {
    passwordCache.clear();
    cacheTimestamps.clear();
    searchIndex.clear();
    indexTimestamps.clear();
};

// Cache-Cleanup-Mechanismus
const cleanupExpiredCaches = () => {
    const now = Date.now();
    
    // Lösche abgelaufene Passwort-Caches
    for (const [key, timestamp] of cacheTimestamps.entries()) {
        if (now - timestamp > CACHE_TTL) {
            passwordCache.delete(key);
            cacheTimestamps.delete(key);
        }
    }
    
    // Lösche abgelaufene Such-Indizes
    for (const [key, timestamp] of indexTimestamps.entries()) {
        if (now - timestamp > INDEX_TTL) {
            searchIndex.delete(key);
            indexTimestamps.delete(key);
        }
    }
    
    // Log Cache-Status
    if (process.env.NODE_ENV === 'development') {
        console.log(`Cache cleanup: ${passwordCache.size} password caches, ${searchIndex.size} search indices`);
    }
};

// Cache-Cleanup alle 2 Minuten
setInterval(cleanupExpiredCaches, 2 * 60 * 1000);

// Performance-Monitoring
const performanceMetrics = {
    operations: new Map(),
    cacheHits: 0,
    cacheMisses: 0,
    totalOperations: 0
};

const trackOperation = (operation, startTime) => {
    const duration = Date.now() - startTime;
    if (!performanceMetrics.operations.has(operation)) {
        performanceMetrics.operations.set(operation, []);
    }
    performanceMetrics.operations.get(operation).push(duration);
    
    // Behalte nur die letzten 100 Messungen
    if (performanceMetrics.operations.get(operation).length > 100) {
        performanceMetrics.operations.get(operation).shift();
    }
    
    performanceMetrics.totalOperations++;
};

const getPerformanceStats = () => {
    const stats = {};
    for (const [operation, durations] of performanceMetrics.operations.entries()) {
        if (durations.length > 0) {
            const avg = durations.reduce((a, b) => a + b, 0) / durations.length;
            const min = Math.min(...durations);
            const max = Math.max(...durations);
            stats[operation] = { avg: Math.round(avg), min, max, count: durations.length };
        }
    }
    
    return {
        operations: stats,
        cache: {
            hits: performanceMetrics.cacheHits,
            misses: performanceMetrics.cacheMisses,
            hitRate: performanceMetrics.totalOperations > 0 ? 
                (performanceMetrics.cacheHits / performanceMetrics.totalOperations * 100).toFixed(2) + '%' : '0%'
        },
        totalOperations: performanceMetrics.totalOperations
    };
};

// Index-basierte Suche für alle Eintragstypen
const buildSearchIndex = (entries, dataKey) => {
    const indexKey = `index_${dataKey}`;
    const index = new Map();
    
    entries.forEach((entry, idx) => {
        // Index für Titel (case-insensitive) - alle Eintragstypen haben einen Titel
        const titleLower = entry.title.toLowerCase();
        const titleWords = titleLower.split(/\s+/);
        titleWords.forEach(word => {
            if (word.length > 2) { // Nur Wörter mit mehr als 2 Zeichen indexieren
                if (!index.has(word)) index.set(word, new Set());
                index.get(word).add(idx);
            }
        });
        
        const entryType = entry.type || 'password';
        
        // Typ-spezifische Indexierung
        switch(entryType) {
            case 'password':
                // Index für Benutzername (case-insensitive)
                if (entry.username) {
                    const usernameLower = entry.username.toLowerCase();
                    if (usernameLower.length > 2) {
                        if (!index.has(usernameLower)) index.set(usernameLower, new Set());
                        index.get(usernameLower).add(idx);
                    }
                }
                
                // Index für URL (case-insensitive)
                if (entry.url) {
                    const urlLower = entry.url.toLowerCase();
                    const urlWords = urlLower.split(/[\/\.\-\?=&]/);
                    urlWords.forEach(word => {
                        if (word.length > 2) {
                            if (!index.has(word)) index.set(word, new Set());
                            index.get(word).add(idx);
                        }
                    });
                }
                break;
                
            case 'note':
                // Index für Notizinhalt (case-insensitive)
                if (entry.content) {
                    const contentLower = entry.content.toLowerCase();
                    const contentWords = contentLower.split(/\s+/);
                    contentWords.forEach(word => {
                        if (word.length > 2) {
                            if (!index.has(word)) index.set(word, new Set());
                            index.get(word).add(idx);
                        }
                    });
                }
                break;
                
            case 'website':
            case 'link':
                // Index für URL (case-insensitive)
                if (entry.url) {
                    const urlLower = entry.url.toLowerCase();
                    const urlWords = urlLower.split(/[\/\.\-\?=&]/);
                    urlWords.forEach(word => {
                        if (word.length > 2) {
                            if (!index.has(word)) index.set(word, new Set());
                            index.get(word).add(idx);
                        }
                    });
                }
                break;
        }
        
        // Index für Notizen (alle Eintragstypen können Notizen haben)
        if (entry.notes) {
            const notesLower = entry.notes.toLowerCase();
            const notesWords = notesLower.split(/\s+/);
            notesWords.forEach(word => {
                if (word.length > 2) {
                    if (!index.has(word)) index.set(word, new Set());
                    index.get(word).add(idx);
                }
            });
        }
    });
    
    searchIndex.set(indexKey, index);
    indexTimestamps.set(indexKey, Date.now());
    
    return index;
};

const getSearchIndex = (dataKey) => {
    const indexKey = `index_${dataKey}`;
    const index = searchIndex.get(indexKey);
    const timestamp = indexTimestamps.get(indexKey);
    
    if (index && timestamp && (Date.now() - timestamp) < INDEX_TTL) {
        return index;
    }
    
    return null;
};

// Session management
const getMasterPassword = (req) => {
    try {
        return req.session?.masterPassword || null;
    } catch (error) {
        console.error('Error getting master password from session:', error);
        return null;
    }
};

// Session recovery function - try to restore session from stored data
const tryRecoverSession = async (req) => {
    try {
        // If session is already valid, no need to recover
        if (req.session?.authenticated && req.session?.masterPassword) {
            return true;
        }
        
        // Check if we have any stored passwords to recover from
        const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
        const passwordsFile = path.join(dataDir, 'passwords.json');
        const masterPasswordsFile = path.join(dataDir, 'master_passwords.json');
        
        if (!fsSync.existsSync(passwordsFile) || !fsSync.existsSync(masterPasswordsFile)) {
            return false; // No data to recover from
        }
        
        // Try to read master passwords to see if any exist
        const masterPasswords = JSON.parse(fsSync.readFileSync(masterPasswordsFile, 'utf8'));
        if (!Array.isArray(masterPasswords) || masterPasswords.length === 0) {
            return false; // No master passwords stored
        }
        
        // Session recovery is possible - user needs to re-enter master password
        // but their data is still there
        return 'RECOVERABLE';
    } catch (error) {
        console.error('Error during session recovery check:', error);
        return false;
    }
};

const setMasterPassword = (req, password) => {
    try {
        req.session.masterPassword = password;
        req.session.authenticated = true;
        req.session.lastActivity = new Date().toISOString();
        
        // Force session save to ensure it's written to disk
        return new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session:', err);
                    
                    // For distributed app, try to diagnose the issue
                    if (process.env.ELECTRON === 'true') {
                        const fs = require('fs');
                        const path = require('path');
                        const sessionsDir = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'sessions');
                        
                        try {
                            // Check if directory exists and is writable
                            if (!fs.existsSync(sessionsDir)) {
                                console.error('Sessions directory does not exist:', sessionsDir);
                            } else {
                                // Test write permissions
                                const testFile = path.join(sessionsDir, '.test-write-' + Date.now());
                                fs.writeFileSync(testFile, 'test');
                                fs.unlinkSync(testFile);
                                console.log('Write permissions OK, session save error may be temporary');
                            }
                        } catch (permError) {
                            console.error('Permission test failed:', permError.message);
                        }
                    }
                    
                    // Don't reject immediately, try to continue
                    // The session might still work in memory
                    resolve();
                } else {
                    console.log('Session saved successfully');
                    resolve();
                }
            });
        });
    } catch (error) {
        console.error('Error setting master password in session:', error);
        // Continue even if session save fails
        // The session might still work in memory
        return Promise.resolve();
    }
};

const clearSession = (req) => {
    try {
        if (req.session) {
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
            });
        }
    } catch (error) {
        console.error('Error clearing session:', error);
    }
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

    // Optimierte Version mit Cache
    static async readPasswordsCached(dataKey) {
        // Versuche Cache zu verwenden
        const cached = getCachedPasswords(dataKey);
        if (cached) {
            return cached;
        }
        
        // Cache miss - lade von Disk
        const passwords = await this.readPasswords();
        
        // Cache setzen
        setCachedPasswords(dataKey, passwords);
        
        return passwords;
    }

    static async writePasswords(passwords) {
        await this.ensureDataDirectory();
        await fs.writeFile(DATA_FILE, JSON.stringify(passwords, null, 2));
    }

    // Optimierte Version mit Cache-Invalidierung
    static async writePasswordsCached(passwords, dataKey) {
        await this.ensureDataDirectory();
        await fs.writeFile(DATA_FILE, JSON.stringify(passwords, null, 2));
        
        // Cache invalidieren
        invalidateCache(dataKey);
    }

    static async readFolders() {
        try {
            await this.ensureDataDirectory();
            const data = await fs.readFile(FOLDERS_FILE, 'utf8');
            const parsed = JSON.parse(data);
            const folders = Array.isArray(parsed) ? parsed : [];
            
            // Validate and clean folder objects
            const validFolders = folders.filter(f => {
                return f && 
                       typeof f === 'object' && 
                       typeof f.id === 'string' && 
                       f.id.trim().length > 0 &&
                       typeof f.name === 'string' && 
                       f.name.trim().length > 0;
            });
            
            // Deduplicate by normalized name (first wins)
            const seen = new Set();
            const unique = [];
            for (const f of validFolders) {
                const key = String(f.name || '').trim().toLowerCase();
                if (seen.has(key)) continue;
                seen.add(key);
                unique.push(f);
            }
            
            // Ensure all folders have required fields
            const normalizedFolders = unique.map(f => ({
                id: f.id.trim(),
                name: String(f.name).trim(),
                order: typeof f.order === 'number' ? f.order : 0,
                createdAt: f.createdAt || new Date().toISOString(),
                updatedAt: f.updatedAt || new Date().toISOString()
            }));
            
            // Sort by order
            normalizedFolders.sort((a, b) => a.order - b.order);
            
            // Update order indices to be sequential
            normalizedFolders.forEach((folder, index) => {
                folder.order = index;
            });
            
            // Save normalized data if changes were made
            if (JSON.stringify(normalizedFolders) !== JSON.stringify(folders)) {
                await this.writeFolders(normalizedFolders).catch(() => {});
            }
            
            return normalizedFolders;
        } catch (error) {
            if (error.code === 'ENOENT') {
                // File doesn't exist, create empty folders file
                await this.writeFolders([]).catch(() => {});
                return [];
            }
            console.error('Error reading folders:', error);
            // Return empty array on error, but try to create the file
            try {
                await this.writeFolders([]);
            } catch (writeError) {
                console.error('Error creating empty folders file:', writeError);
            }
            return [];
        }
    }

    static async writeFolders(folders) {
        try {
            await this.ensureDataDirectory();
            const arr = Array.isArray(folders) ? folders : [];
            
            // Validate and clean folder objects before writing
            const validFolders = arr.filter(f => {
                return f && 
                       typeof f === 'object' && 
                       typeof f.id === 'string' && 
                       f.id.trim().length > 0 &&
                       typeof f.name === 'string' && 
                       f.name.trim().length > 0;
            });
            
            // Deduplicate by normalized name (first wins)
            const seen = new Set();
            const unique = [];
            for (const f of validFolders) {
                const key = String(f.name || '').trim().toLowerCase();
                if (seen.has(key)) continue;
                seen.add(key);
                unique.push(f);
            }
            
            // Ensure all folders have required fields
            const normalizedFolders = unique.map(f => ({
                id: f.id.trim(),
                name: String(f.name).trim(),
                order: typeof f.order === 'number' ? f.order : 0,
                createdAt: f.createdAt || new Date().toISOString(),
                updatedAt: f.updatedAt || new Date().toISOString()
            }));
            
            // Sort by order
            normalizedFolders.sort((a, b) => a.order - b.order);
            
            // Update order indices to be sequential
            normalizedFolders.forEach((folder, index) => {
                folder.order = index;
            });
            
            // Write to file
            await fs.writeFile(FOLDERS_FILE, JSON.stringify(normalizedFolders, null, 2));
            
            return normalizedFolders;
        } catch (error) {
            console.error('Error writing folders:', error);
            throw error;
        }
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

    // Neue optimierte Methoden für einzelne Passwort-Operationen
    static async encryptSinglePassword(passwordData, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        const salt = EncryptionManager.generateSalt();
        const key = EncryptionManager.deriveKey(keyString, salt);
        
        const encryptedPassword = EncryptionManager.encrypt(passwordData.password, key);
        const encryptedUsername = EncryptionManager.encrypt(passwordData.username, key);
        
        return {
            ...passwordData,
            password: encryptedPassword.encrypted,
            passwordIv: encryptedPassword.iv,
            passwordSalt: salt.toString('hex'),
            username: encryptedUsername.encrypted,
            usernameIv: encryptedUsername.iv,
            usernameSalt: salt.toString('hex'),
            encryptionScheme: ENCRYPTION_SCHEME
        };
    }

    static async addSinglePassword(passwordData, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade alle Passwörter
        const passwords = await this.readPasswords();
        
        // Verschlüssele nur das neue Passwort
        const encryptedPassword = await this.encryptSinglePassword(passwordData, keyString);
        
        // Füge es zur Liste hinzu
        passwords.push(encryptedPassword);
        
        // Speichere die aktualisierte Liste mit Cache-Invalidierung
        await this.writePasswordsCached(passwords, keyString);
        
        return encryptedPassword;
    }

    static async updateSinglePassword(id, passwordData, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade alle Passwörter
        const passwords = await this.readPasswords();
        
        // Finde den Index des zu aktualisierenden Passworts
        const index = passwords.findIndex(pwd => pwd.id === id);
        if (index === -1) {
            throw new Error('Password not found');
        }

        // Verschlüssele nur das aktualisierte Passwort
        const encryptedPassword = await this.encryptSinglePassword(passwordData, keyString);
        
        // Aktualisiere den Eintrag
        passwords[index] = {
            ...encryptedPassword,
            id: id, // Stelle sicher, dass die ID erhalten bleibt
            createdAt: passwords[index].createdAt // Behalte das ursprüngliche Erstellungsdatum
        };
        
        // Speichere die aktualisierte Liste mit Cache-Invalidierung
        await this.writePasswordsCached(passwords, keyString);
        
        return passwords[index];
    }

    static async deleteSinglePassword(id, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade alle Passwörter
        const passwords = await this.readPasswords();
        
        // Filtere das zu löschende Passwort heraus
        const filteredPasswords = passwords.filter(pwd => pwd.id !== id);
        
        if (filteredPasswords.length === passwords.length) {
            throw new Error('Password not found');
        }
        
        // Speichere die gefilterte Liste mit Cache-Invalidierung
        await this.writePasswordsCached(filteredPasswords, keyString);
        
        return true;
    }

    // Optimierte Methode für das Verschieben von Passwörtern (keine Neuverschlüsselung nötig)
    static async movePasswordsToFolder(passwordIds, targetFolderId, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade alle Passwörter
        const passwords = await this.readPasswords();
        
        // Aktualisiere nur die folderId für die angegebenen Passwörter
        let updated = false;
        const updatedPasswords = passwords.map(pwd => {
            if (passwordIds.includes(pwd.id) && pwd.folderId !== targetFolderId) {
                updated = true;
                return { ...pwd, folderId: targetFolderId, updatedAt: new Date().toISOString() };
            }
            return pwd;
        });
        
        if (!updated) {
            return false; // Keine Änderungen
        }
        
        // Speichere die aktualisierte Liste mit Cache-Invalidierung
        await this.writePasswordsCached(updatedPasswords, keyString);
        
        return true;
    }

    // Optimierte Methode für das Batch-Erstellen von Passwörtern
    static async addMultiplePasswords(passwordsData, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        if (!Array.isArray(passwordsData) || passwordsData.length === 0) {
            throw new Error('Passwords data array is required');
        }

        // Lade alle bestehenden Passwörter
        const existingPasswords = await this.readPasswords();
        
        // Verschlüssele alle neuen Passwörter auf einmal
        const encryptedPasswords = await Promise.all(
            passwordsData.map(async (passwordData) => {
                return await this.encryptSinglePassword(passwordData, keyString);
            })
        );
        
        // Füge sie zur bestehenden Liste hinzu
        const allPasswords = [...existingPasswords, ...encryptedPasswords];
        
        // Speichere alle Passwörter auf einmal mit Cache-Invalidierung
        await this.writePasswordsCached(allPasswords, keyString);
        
        return encryptedPasswords;
    }

    // Optimierte Methode für das Batch-Aktualisieren von Passwörtern
    static async updateMultiplePasswords(updates, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        if (!Array.isArray(updates) || updates.length === 0) {
            throw new Error('Updates array is required and must not be empty');
        }

        // Lade alle bestehenden Passwörter
        const passwords = await this.readPasswords();
        
        // Erstelle eine Map für schnellen Zugriff
        const passwordMap = new Map(passwords.map(p => [p.id, p]));
        
        // Aktualisiere die Passwörter
        let hasUpdates = false;
        const updatedPasswords = passwords.map(pwd => {
            const update = updates.find(u => u.id === pwd.id);
            if (update) {
                hasUpdates = true;
                return {
                    ...pwd,
                    ...update,
                    updatedAt: new Date().toISOString()
                };
            }
            return pwd;
        });
        
        if (!hasUpdates) {
            return []; // Keine Änderungen
        }
        
        // Verschlüssele alle aktualisierten Passwörter
        const encryptedPasswords = await Promise.all(
            updatedPasswords.map(async (pwd) => {
                const update = updates.find(u => u.id === pwd.id);
                if (update) {
                    // Nur aktualisierte Passwörter neu verschlüsseln
                    return await this.encryptSinglePassword(pwd, keyString);
                }
                return pwd; // Nicht aktualisierte Passwörter bleiben unverändert
            })
        );
        
        // Speichere alle Passwörter mit Cache-Invalidierung
        await this.writePasswordsCached(encryptedPasswords, keyString);
        
        return encryptedPasswords.filter(pwd => {
            return updates.some(u => u.id === pwd.id);
        });
    }

    // Optimierte Methode für das Batch-Löschen von Passwörtern
    static async deleteMultiplePasswords(passwordIds, keyString) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        if (!Array.isArray(passwordIds) || passwordIds.length === 0) {
            throw new Error('Password IDs array is required and must not be empty');
        }

        // Lade alle bestehenden Passwörter
        const passwords = await this.readPasswords();
        
        // Filtere die zu löschenden Passwörter heraus
        const filteredPasswords = passwords.filter(pwd => !passwordIds.includes(pwd.id));
        
        if (filteredPasswords.length === passwords.length) {
            return 0; // Keine Passwörter gelöscht
        }
        
        // Speichere die gefilterte Liste mit Cache-Invalidierung
        await this.writePasswordsCached(filteredPasswords, keyString);
        
        return passwords.length - filteredPasswords.length; // Anzahl der gelöschten Passwörter
    }

    static async loadAndDecryptPasswords(keyString) {
        const encryptedPasswords = await this.readPasswords();
        
        if (!keyString) {
            throw new Error('Master password not set');
        }

        return encryptedPasswords.map(pwd => {
            try {
                // Use stored salt for decryption
                const salt = Buffer.from(pwd.passwordSalt || pwd.passwordSalt || '00000000000000000000000000000000', 'hex');
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

    // Optimierte Version mit Cache
    static async loadAndDecryptPasswordsCached(keyString) {
        try {
            // Versuche Cache zu verwenden
            const cached = getCachedPasswords(keyString);
            if (cached) {
                console.log(`Cache hit: returning ${cached.length} cached passwords`);
                return cached;
            }
            
            console.log('Cache miss: loading and decrypting passwords...');
            
            // Cache miss - lade und entschlüssele
            const encryptedPasswords = await this.readPasswords();
            console.log(`Loaded ${encryptedPasswords.length} encrypted passwords`);
            
            if (!keyString) {
                throw new Error('Master password not set');
            }

            // Process passwords in batches to avoid memory issues
            const batchSize = 100; // Increased batch size for better performance
            const decryptedPasswords = [];
            
            console.log(`Starting batch processing of ${encryptedPasswords.length} passwords with batch size ${batchSize}`);
            
            for (let i = 0; i < encryptedPasswords.length; i += batchSize) {
                const batch = encryptedPasswords.slice(i, i + batchSize);
                const batchNumber = Math.floor(i/batchSize) + 1;
                const totalBatches = Math.ceil(encryptedPasswords.length/batchSize);
                
                console.log(`Processing batch ${batchNumber}/${totalBatches} (${batch.length} passwords)`);
                
                const decryptedBatch = batch.map((pwd, index) => {
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
                        console.error(`Error decrypting password ${index + 1} in batch ${batchNumber}:`, error);
                        throw new Error(`Decryption failed for password ${index + 1} in batch ${batchNumber}: ${error.message}`);
                    }
                });
                
                decryptedPasswords.push(...decryptedBatch);
                console.log(`Completed batch ${batchNumber}/${totalBatches}`);
            }
            
            console.log(`Successfully decrypted ${decryptedPasswords.length} passwords`);
            
            // Cache setzen
            setCachedPasswords(keyString, decryptedPasswords);
            
            // Index für Suche aufbauen
            buildSearchIndex(decryptedPasswords, keyString);
            
            return decryptedPasswords;
        } catch (error) {
            console.error('Error in loadAndDecryptPasswordsCached:', error);
            throw error;
        }
    }

    // Optimierte Suche mit Index für alle Eintragstypen
    static async searchPasswords(query, keyString, limit = 50) {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade alle Einträge (mit Cache)
        const entries = await this.loadAndDecryptPasswordsCached(keyString);
        
        if (!query || query.trim().length === 0) {
            return entries.slice(0, limit);
        }

        // Versuche Index zu verwenden
        let index = getSearchIndex(keyString);
        if (!index) {
            // Index neu aufbauen für alle Eintragstypen
            index = buildSearchIndex(entries, keyString);
        }

        const queryLower = query.toLowerCase();
        const queryWords = queryLower.split(/\s+/).filter(word => word.length > 2);
        
        if (queryWords.length === 0) {
            return entries.slice(0, limit);
        }

        // Suche mit Index über alle Eintragstypen
        const resultIndices = new Map();
        
        queryWords.forEach(word => {
            const matches = index.get(word);
            if (matches) {
                matches.forEach(idx => {
                    resultIndices.set(idx, (resultIndices.get(idx) || 0) + 1);
                });
            }
        });

        // Sortiere nach Relevanz (Anzahl der Übereinstimmungen)
        const sortedIndices = Array.from(resultIndices.entries())
            .sort((a, b) => b[1] - a[1])
            .map(([idx]) => idx)
            .slice(0, limit);

        return sortedIndices.map(idx => entries[idx]);
    }

    // Pagination für große Datenmengen
    static async getPasswordsPaginated(keyString, page = 1, pageSize = 50, sortBy = 'title', sortOrder = 'asc') {
        if (!keyString) {
            throw new Error('Master password not set');
        }

        // Lade Passwörter (mit Cache)
        const passwords = await this.loadAndDecryptPasswordsCached(keyString);
        
        // Sortierung
        const sortedPasswords = [...passwords].sort((a, b) => {
            let aVal = a[sortBy] || '';
            let bVal = b[sortBy] || '';
            
            // Fallback für numerische Felder
            if (sortBy === 'createdAt' || sortBy === 'updatedAt') {
                aVal = new Date(aVal).getTime();
                bVal = new Date(bVal).getTime();
            } else {
                aVal = String(aVal).toLowerCase();
                bVal = String(bVal).toLowerCase();
            }
            
            if (sortOrder === 'desc') {
                return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
            } else {
                return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
            }
        });
        
        // Pagination
        const totalCount = sortedPasswords.length;
        const totalPages = Math.ceil(totalCount / pageSize);
        const currentPage = Math.max(1, Math.min(page, totalPages));
        const startIndex = (currentPage - 1) * pageSize;
        const endIndex = startIndex + pageSize;
        
        const paginatedPasswords = sortedPasswords.slice(startIndex, endIndex);
        
        return {
            passwords: paginatedPasswords,
            pagination: {
                currentPage,
                pageSize,
                totalCount,
                totalPages,
                hasNextPage: currentPage < totalPages,
                hasPrevPage: currentPage > 1
            }
        };
    }

    static async updatePasswordFolderIds(oldFolderId, newFolderId) {
        try {
            const passwords = await this.readPasswords();
            let updatedCount = 0;
            
            // Debug: Log what we're looking for
            console.log(`Looking for passwords with folderId "${oldFolderId}" to move to "${newFolderId || 'null'}"`);
            console.log(`Total passwords found: ${passwords.length}`);
            
            // Log all passwords for debugging
            passwords.forEach(p => {
                console.log(`Password ${p.id}: folderId="${p.folderId}" (type: ${typeof p.folderId})`);
            });
            
            const updated = passwords.map(p => {
                // Handle null/undefined folderId correctly
                if (p.folderId === oldFolderId || (p.folderId === null && oldFolderId === null) || (p.folderId === undefined && oldFolderId === undefined)) {
                    updatedCount++;
                    console.log(`MATCH FOUND! Moving password ${p.id} from folder ${oldFolderId} to ${newFolderId || 'null'}`);
                    return { ...p, folderId: newFolderId, updatedAt: new Date().toISOString() };
                }
                return p;
            });
            
            if (updatedCount > 0) {
                await this.writePasswords(updated);
                // Clear all caches to ensure consistency
                clearAllCaches();
                console.log(`Updated ${updatedCount} passwords from folder ${oldFolderId} to ${newFolderId || 'null'}`);
            } else {
                console.log(`No passwords found with folderId "${oldFolderId}"`);
            }
            
            return updatedCount;
        } catch (error) {
            console.error('Error updating password folder IDs:', error);
            throw error;
        }
    }

    static async cleanupOrphanedPasswordFolders() {
        try {
            const passwords = await this.readPasswords();
            const folders = await this.readFolders();
            const validFolderIds = new Set(folders.map(f => f.id));
            
            let cleanedCount = 0;
            const cleaned = passwords.map(p => {
                // If password has a folderId but that folder doesn't exist, set to null
                if (p.folderId && !validFolderIds.has(p.folderId)) {
                    cleanedCount++;
                    return { ...p, folderId: null, updatedAt: new Date().toISOString() };
                }
                return p;
            });
            
            if (cleanedCount > 0) {
                await this.writePasswords(cleaned);
                clearAllCaches();
                console.log(`Cleaned up ${cleanedCount} orphaned password folder references`);
            }
            
            return cleanedCount;
        } catch (error) {
            console.error('Error cleaning up orphaned password folders:', error);
            throw error;
        }
    }
}

// Activity tracking middleware - extends session on any activity
const trackActivity = (req, res, next) => {
    if (req.session && req.session.authenticated) {
        // Update last activity timestamp
        req.session.lastActivity = new Date().toISOString();
        
        // Extend cookie expiration by 5 minutes on any activity
        req.session.cookie.maxAge = 5 * 60 * 1000; // 5 minutes
        
        // Force session save to persist the updated timestamp
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session activity:', err);
            }
        });
    }
    next();
};

// Session timeout check middleware
const checkSessionTimeout = (req, res, next) => {
    if (req.session && req.session.authenticated && req.session.lastActivity) {
        const now = new Date();
        const lastActivity = new Date(req.session.lastActivity);
        const timeDiff = now - lastActivity;
        const timeoutMs = 5 * 60 * 1000; // 5 minutes in milliseconds
        
        if (timeDiff > timeoutMs) {
            // Session has timed out
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying timed-out session:', err);
                }
            });
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
            return res.status(401).json({ 
                error: 'Session expired due to inactivity. Please login again.',
                code: 'SESSION_TIMEOUT'
            });
        }
    }
    next();
};

// Authentication middleware
const requireMasterPassword = (req, res, next) => {
    try {
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
            return res.status(401).json({ 
                error: 'Not authenticated. Please login with your master password.',
                code: 'AUTH_REQUIRED'
            });
        }
        next();
    } catch (error) {
        console.error('Authentication middleware error:', error);
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        return res.status(401).json({ 
            error: 'Session error. Please login again.',
            code: 'SESSION_ERROR'
        });
    }
};

// Apply activity tracking and session timeout to all API routes
app.use('/api', trackActivity);
app.use('/api', checkSessionTimeout);

// API Routes

// Get app version from package.json
app.get('/api/version', (req, res) => {
    try {
        const packageJson = require('./package.json');
        res.json({ 
            version: packageJson.version,
            name: packageJson.name,
            description: packageJson.description
        });
    } catch (error) {
        console.error('Error reading package.json:', error);
        res.status(500).json({ error: 'Could not read version information' });
    }
});

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
            try {
                await setMasterPassword(req, dataKey);
            } catch (sessionError) {
                console.error('Failed to set session for new master password:', sessionError);
                return res.status(500).json({ 
                    error: 'Failed to create session. Please try again.',
                    code: 'SESSION_CREATION_FAILED'
                });
            }
        } else {
            // First password: create datakey and wrap it
            const created = await FileManager.addMasterPassword(password, name || 'Master Password', hint || '');
            const dataKeyHex = crypto.randomBytes(32).toString('hex');
            const { wrappedDataKey, wrapIv } = FileManager.wrapDataKeyForPassword(password, Buffer.from(created.salt, 'hex'), dataKeyHex);
            const list = await FileManager.loadMasterPasswords();
            const updated = list.map(mp => mp.id === created.id ? { ...mp, wrappedDataKey, wrapIv } : mp);
            await FileManager.saveMasterPasswords(updated);
            // Important: set session to DataKey so all subsequent ops use it
            try {
                await setMasterPassword(req, dataKeyHex);
            } catch (sessionError) {
                console.error('Failed to set session for new master password:', sessionError);
                return res.status(500).json({ 
                    error: 'Failed to create session. Please try again.',
                    code: 'SESSION_CREATION_FAILED'
                });
            }
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
        
        // Fix for ERR_CONTENT_LENGTH_MISMATCH with large JSON responses
        const jsonString = JSON.stringify(masterPasswords);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', Buffer.byteLength(jsonString, 'utf8'));
        res.end(jsonString);
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

        // Set current session to DataKey
        await setMasterPassword(req, dataKey);
        // Explicitly save the session before responding to avoid race conditions on immediate next request
        try {
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Error saving session after login:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        } catch (sessionError) {
            console.error('Failed to save session after login:', sessionError);
            // Clear the session and return error
            clearSession(req);
            return res.status(500).json({ 
                error: 'Failed to create session. Please try again.',
                code: 'SESSION_CREATION_FAILED'
            });
        }

        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
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
    const startTime = Date.now();
    try {
        const dataKey = getMasterPassword(req); // now stores DataKey
        
        // Set timeout and headers for large responses
        res.setTimeout(60000); // 60 seconds timeout for large datasets
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-cache');
        
        console.log(`Starting to load passwords for dataKey: ${dataKey ? 'set' : 'not set'}`);
        
        const passwords = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        
        // Log response size for debugging
        const responseSize = JSON.stringify(passwords).length;
        console.log(`Successfully loaded ${passwords.length} passwords, response size: ${responseSize} bytes`);
        
        trackOperation('getAllPasswords', startTime);
        
        // Ensure response is sent properly
        res.status(200).json(passwords);
        
    } catch (error) {
        trackOperation('getAllPasswords_error', startTime);
        console.error('Error in /api/all:', error);
        
        // Ensure error response is sent
        if (!res.headersSent) {
            res.status(500).json({ error: error.message });
        }
    }
});

// Optimierte Suche nach allen Eintragstypen (Passwörter, Notizen, Links, Webseiten)
app.get('/api/search', requireMasterPassword, async (req, res) => {
    try {
        const { q: query, limit = 50, type = 'all' } = req.query;
        const dataKey = getMasterPassword(req);
        
        if (!dataKey) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const searchLimit = Math.min(parseInt(limit) || 50, 100); // Max 100 Ergebnisse
        
        const results = await FileManager.searchPasswords(query, dataKey, searchLimit);
        
        // Filter by entry type if specified
        const filteredResults = type !== 'all' 
            ? results.filter(entry => (entry.type || 'password') === type)
            : results;
        
        res.json({
            query: query || '',
            type: type,
            results: filteredResults,
            count: filteredResults.length,
            limit: searchLimit,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get entries by type
app.get('/api/entries/type/:type', requireMasterPassword, async (req, res) => {
    try {
        const { type } = req.params;
        const validTypes = ['password', 'website', 'link', 'note'];
        
        if (!validTypes.includes(type)) {
            return res.status(400).json({ 
                error: `Invalid entry type. Valid types are: ${validTypes.join(', ')}` 
            });
        }
        
        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        const entries = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        const filteredEntries = entries.filter(entry => (entry.type || 'password') === type);
        
        res.json(filteredEntries);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Paginierte Passwort-Liste für große Datenmengen
app.get('/api/passwords', largeDataLimiter, requireMasterPassword, async (req, res) => {
    try {
        const { page = 1, pageSize = 50, sortBy = 'title', sortOrder = 'asc' } = req.query;
        const dataKey = getMasterPassword(req);
        
        if (!dataKey) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const pageNum = Math.max(1, parseInt(page) || 1);
        const pageSizeNum = Math.min(Math.max(1, parseInt(pageSize) || 50), 200); // Max 200 pro Seite
        
        const result = await FileManager.getPasswordsPaginated(
            dataKey, 
            pageNum, 
            pageSizeNum, 
            sortBy, 
            sortOrder
        );
        
        // Fix for ERR_CONTENT_LENGTH_MISMATCH with large JSON responses
        const jsonString = JSON.stringify(result);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', Buffer.byteLength(jsonString, 'utf8'));
        res.end(jsonString);
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

// Add new password (legacy endpoint - backward compatibility)
app.post('/api/add', requireMasterPassword, async (req, res) => {
    const startTime = Date.now();
    try {
        const { title, username, password, url, notes, folderId } = req.body;
        
        if (!title || !username || !password) {
            return res.status(400).json({ 
                error: 'Title, username, and password are required' 
            });
        }

        const newPassword = {
            id: uuidv4(),
            type: 'password', // Default type for backward compatibility
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
        
        // Verwende die optimierte Methode für einzelne Passwörter
        const encryptedPassword = await FileManager.addSinglePassword(newPassword, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedPassword = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        const addedPassword = decryptedPassword.find(p => p.id === encryptedPassword.id);

        trackOperation('addPassword', startTime);
        res.status(201).json(addedPassword);
    } catch (error) {
        trackOperation('addPassword_error', startTime);
        res.status(500).json({ error: error.message });
    }
});

// Add new entry (supports different entry types)
app.post('/api/entries', requireMasterPassword, async (req, res) => {
    const startTime = Date.now();
    try {
        const { type, title, content, url, notes, folderId, username, password } = req.body;
        
        if (!title || !type) {
            return res.status(400).json({ 
                error: 'Title and type are required' 
            });
        }

        // Validate required fields based on entry type
        if (type === 'password' && (!username || !password)) {
            return res.status(400).json({ 
                error: 'Username and password are required for password entries' 
            });
        }

        const newEntry = {
            id: uuidv4(),
            type, // 'password', 'website', 'link', 'note'
            title,
            content: content || '', // For notes and generic content
            url: normalizeUrl(url || ''),
            notes: notes || '',
            folderId: folderId || null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        // Add password-specific fields if type is password
        if (type === 'password') {
            newEntry.username = username;
            newEntry.password = password;
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        // Verwende die optimierte Methode für einzelne Passwörter
        const encryptedEntry = await FileManager.addSinglePassword(newEntry, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedEntries = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        const addedEntry = decryptedEntries.find(p => p.id === encryptedEntry.id);

        trackOperation('addEntry', startTime);
        res.status(201).json(addedEntry);
    } catch (error) {
        trackOperation('addEntry_error', startTime);
        res.status(500).json({ error: error.message });
    }
});

// Add multiple passwords (optimized)
app.post('/api/add-multiple', requireMasterPassword, async (req, res) => {
    try {
        const { passwords } = req.body;
        
        if (!Array.isArray(passwords) || passwords.length === 0) {
            return res.status(400).json({ 
                error: 'Passwords array is required and must not be empty' 
            });
        }

        // Validiere alle Passwörter
        for (const pwd of passwords) {
            if (!pwd.title || !pwd.username || !pwd.password) {
                return res.status(400).json({ 
                    error: 'All passwords must have title, username, and password' 
                });
            }
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        // Bereite die Passwörter vor
        const preparedPasswords = passwords.map(pwd => ({
            id: uuidv4(),
            title: pwd.title.trim(),
            username: pwd.username.trim(),
            password: pwd.password,
            url: normalizeUrl(pwd.url || ''),
            notes: pwd.notes || '',
            folderId: pwd.folderId || null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        }));
        
        // Verwende die optimierte Batch-Methode
        const encryptedPasswords = await FileManager.addMultiplePasswords(preparedPasswords, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedPasswords = await FileManager.loadAndDecryptPasswords(dataKey);
        const addedPasswords = encryptedPasswords.map(encrypted => {
            return decryptedPasswords.find(p => p.id === encrypted.id);
        });

        res.status(201).json({
            message: `Successfully created ${addedPasswords.length} password(s)`,
            passwords: addedPasswords,
            count: addedPasswords.length
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update password (legacy endpoint - backward compatibility)
app.put('/api/update/:id', requireMasterPassword, async (req, res) => {
    const startTime = Date.now();
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
        
        // Verwende die optimierte Methode für einzelne Passwörter
        const updatedPasswordData = {
            title,
            username,
            password,
            url: normalizeUrl(url || ''),
            notes: notes || '',
            folderId: folderId ?? null,
            type: 'password', // Ensure backward compatibility
            updatedAt: new Date().toISOString()
        };

        const encryptedPassword = await FileManager.updateSinglePassword(id, updatedPasswordData, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedPassword = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        const updatedPassword = decryptedPassword.find(p => p.id === id);

        trackOperation('updatePassword', startTime);
        res.json(updatedPassword);
    } catch (error) {
        trackOperation('updatePassword_error', startTime);
        res.status(500).json({ error: error.message });
    }
});

// Update entry (supports different entry types)
app.put('/api/entries/:id', requireMasterPassword, async (req, res) => {
    const startTime = Date.now();
    try {
        const { id } = req.params;
        const { type, title, content, url, notes, folderId, username, password } = req.body;
        
        if (!title || !type) {
            return res.status(400).json({ 
                error: 'Title and type are required' 
            });
        }

        // Validate required fields based on entry type
        if (type === 'password' && (!username || !password)) {
            return res.status(400).json({ 
                error: 'Username and password are required for password entries' 
            });
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        const updatedEntryData = {
            type,
            title,
            content: content || '',
            url: normalizeUrl(url || ''),
            notes: notes || '',
            folderId: folderId ?? null,
            updatedAt: new Date().toISOString()
        };

        // Add password-specific fields if type is password
        if (type === 'password') {
            updatedEntryData.username = username;
            updatedEntryData.password = password;
        }

        const encryptedEntry = await FileManager.updateSinglePassword(id, updatedEntryData, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedEntries = await FileManager.loadAndDecryptPasswordsCached(dataKey);
        const updatedEntry = decryptedEntries.find(p => p.id === id);

        if (!updatedEntry) {
            return res.status(404).json({ error: 'Entry not found' });
        }

        trackOperation('updateEntry', startTime);
        res.json(updatedEntry);
    } catch (error) {
        trackOperation('updateEntry_error', startTime);
        res.status(500).json({ error: error.message });
    }
});

// Update multiple passwords (optimized)
app.put('/api/update-multiple', requireMasterPassword, async (req, res) => {
    try {
        const { updates } = req.body;
        
        if (!Array.isArray(updates) || updates.length === 0) {
            return res.status(400).json({ 
                error: 'Updates array is required and must not be empty' 
            });
        }

        // Validiere alle Updates
        for (const update of updates) {
            if (!update.id || !update.title || !update.username || !update.password) {
                return res.status(400).json({ 
                    error: 'All updates must have id, title, username, and password' 
                });
            }
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        // Bereite die Updates vor
        const preparedUpdates = updates.map(update => ({
            id: update.id,
            title: update.title.trim(),
            username: update.username.trim(),
            password: update.password,
            url: normalizeUrl(update.url || ''),
            notes: update.notes || '',
            folderId: update.folderId ?? null
        }));
        
        // Verwende die optimierte Batch-Methode
        const encryptedPasswords = await FileManager.updateMultiplePasswords(preparedUpdates, dataKey);
        
        if (encryptedPasswords.length === 0) {
            return res.json({ message: 'No passwords were updated' });
        }
        
        // Entschlüssele für die Antwort
        const decryptedPasswords = await FileManager.loadAndDecryptPasswords(dataKey);
        const updatedPasswords = encryptedPasswords.map(encrypted => {
            return decryptedPasswords.find(p => p.id === encrypted.id);
        });

        res.json({
            message: `Successfully updated ${updatedPasswords.length} password(s)`,
            passwords: updatedPasswords,
            count: updatedPasswords.length
        });
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
        
        // Verwende die optimierte Methode für einzelne Passwörter
        await FileManager.deleteSinglePassword(id, dataKey);
        
        res.json({ message: 'Password deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete multiple passwords (optimized)
app.delete('/api/delete-multiple', requireMasterPassword, async (req, res) => {
    try {
        const { passwordIds } = req.body;
        
        if (!Array.isArray(passwordIds) || passwordIds.length === 0) {
            return res.status(400).json({ 
                error: 'Password IDs array is required and must not be empty' 
            });
        }

        const dataKey = getMasterPassword(req);
        if (!dataKey) return res.status(401).json({ error: 'Not authenticated' });
        
        // Verwende die optimierte Batch-Methode
        const deletedCount = await FileManager.deleteMultiplePasswords(passwordIds, dataKey);
        
        if (deletedCount === 0) {
            return res.json({ message: 'No passwords were deleted' });
        }
        
        res.json({ 
            message: `Successfully deleted ${deletedCount} password(s)`,
            deletedCount: deletedCount
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Export passwords and folders
app.get('/api/export', requireMasterPassword, async (req, res) => {
    try {
        const dataKey = getMasterPassword(req);
        const passwords = await FileManager.loadAndDecryptPasswords(dataKey);
        const folders = await FileManager.readFolders();
        // Sort folders by order index for export
        const sortedFolders = folders.sort((a, b) => {
            const orderA = typeof a.order === 'number' ? a.order : Number.MAX_SAFE_INTEGER;
            const orderB = typeof b.order === 'number' ? b.order : Number.MAX_SAFE_INTEGER;
            return orderA - orderB;
        });
        
        const exportData = {
            version: '1.4',
            exportDate: new Date().toISOString(),
            entries: passwords, // Alle Eintragstypen (passwords, websites, links, notes)
            passwords, // Für Rückwärtskompatibilität
            folders: sortedFolders
        };
        
        // Fix for ERR_CONTENT_LENGTH_MISMATCH with large JSON responses
        const jsonString = JSON.stringify(exportData);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="passwords_backup_${new Date().toISOString().split('T')[0]}.json"`);
        res.setHeader('Content-Length', Buffer.byteLength(jsonString, 'utf8'));
        res.end(jsonString);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import passwords and folders
app.post('/api/import', requireMasterPassword, async (req, res) => {
    try {
        const { entries, passwords, folders } = req.body;
        
        // Unterstütze sowohl das neue 'entries' als auch das alte 'passwords' Format
        const entriesToImport = entries || passwords;
        
        if (!Array.isArray(entriesToImport)) {
            return res.status(400).json({ error: 'Invalid import data format' });
        }

        // Validate entry structure (unterschiedlich je nach Typ)
        for (const entry of entriesToImport) {
            if (!entry.title) {
                return res.status(400).json({ 
                    error: 'Invalid entry: title is required' 
                });
            }
            
            const type = entry.type || 'password'; // Standard für Rückwärtskompatibilität
            
            // Validiere typ-spezifische Felder
            if (type === 'password' && (!entry.username || !entry.password)) {
                return res.status(400).json({ 
                    error: 'Invalid password entry: username and password are required' 
                });
            }
        }

        // Import folders if they exist
        if (folders && Array.isArray(folders)) {
            const existingFolders = await FileManager.readFolders();
            const existingFolderNames = new Set(existingFolders.map(f => f.name.toLowerCase().trim()));
            
            // Filter out duplicate folders by name
            const newFolders = folders.filter(f => !existingFolderNames.has(f.name.toLowerCase().trim()));
            
            if (newFolders.length > 0) {
                const processedFolders = newFolders.map((folder, index) => ({
                    ...folder,
                    id: folder.id || uuidv4(),
                    order: typeof folder.order === 'number' ? folder.order : (existingFolders.length + index),
                    createdAt: folder.createdAt || new Date().toISOString(),
                    updatedAt: new Date().toISOString()
                }));
                
                const allFolders = [...existingFolders, ...processedFolders];
                
                // Sort all folders by order index
                allFolders.sort((a, b) => {
                    const orderA = typeof a.order === 'number' ? a.order : Number.MAX_SAFE_INTEGER;
                    const orderB = typeof b.order === 'number' ? b.order : Number.MAX_SAFE_INTEGER;
                    return orderA - orderB;
                });
                
                // Update order indices to ensure consistency
                allFolders.forEach((folder, index) => {
                    folder.order = index;
                });
                
                await FileManager.writeFolders(allFolders);
            }
        }

        // Build a folderId remap so passwords keep correct folder assignment
        // even if imported folders were de-duplicated by name and got new IDs.
        const folderIdRemap = new Map();
        try {
            const finalFolders = await FileManager.readFolders();
            const nameToFinalId = new Map(finalFolders.map(f => [String(f.name || '').toLowerCase().trim(), f.id]));

            if (folders && Array.isArray(folders)) {
                for (const f of folders) {
                    const nameKey = String(f?.name || '').toLowerCase().trim();
                    if (!nameKey) continue;
                    const finalId = nameToFinalId.get(nameKey);
                    if (finalId && f.id && f.id !== finalId) {
                        folderIdRemap.set(f.id, finalId);
                    }
                }
            }
        } catch (_) {
            // Non-fatal: if anything goes wrong, we just skip remapping
        }

        // Add IDs to imported entries if missing und normalisiere Typ
        const processedEntries = entriesToImport.map(entry => {
            const mappedFolderId = (entry.folderId && folderIdRemap.has(entry.folderId))
                ? folderIdRemap.get(entry.folderId)
                : entry.folderId;

            return {
                ...entry,
                id: entry.id || uuidv4(),
                type: entry.type || 'password', // Standard-Typ für Rückwärtskompatibilität
                folderId: typeof mappedFolderId === 'string' ? mappedFolderId : (mappedFolderId ?? null),
                createdAt: entry.createdAt || new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };
        });

        const dataKey = getMasterPassword(req);
        await FileManager.addMultiplePasswords(processedEntries, dataKey);
        
        // Zähle verschiedene Eintragstypen für bessere Antwort
        const typeCounts = processedEntries.reduce((acc, entry) => {
            acc[entry.type] = (acc[entry.type] || 0) + 1;
            return acc;
        }, {});
        
        const typeNames = {
            'password': 'passwords',
            'website': 'websites',
            'link': 'links',
            'note': 'notes'
        };
        
        const countMessages = Object.entries(typeCounts).map(([type, count]) => 
            `${count} ${typeNames[type] || type}`
        ).join(', ');
        
        const importResult = { 
            message: `Data imported successfully: ${countMessages}`, 
            entriesCount: processedEntries.length,
            typeCounts,
            foldersCount: folders && Array.isArray(folders) ? folders.length : 0
        };
        
        // Fix for ERR_CONTENT_LENGTH_MISMATCH with large JSON responses
        const jsonString = JSON.stringify(importResult);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', Buffer.byteLength(jsonString, 'utf8'));
        res.end(jsonString);
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
        let isAuthenticated = false;
        let sessionValid = false;
        let sessionRecoverable = false;
        let sessionInfo = {};
        
        try {
            sessionValid = Boolean(req.session && req.session.authenticated);
            isAuthenticated = Boolean(sessionValid && getMasterPassword(req));
            
            // Add detailed session info for debugging
            sessionInfo = {
                hasSession: Boolean(req.session),
                sessionId: req.session?.id || null,
                authenticated: req.session?.authenticated || false,
                hasMasterPassword: Boolean(getMasterPassword(req)),
                lastActivity: req.session?.lastActivity || null,
                cookie: req.session?.cookie || null
            };
            
            // Log session details for distributed app debugging
            if (process.env.ELECTRON === 'true') {
                console.log('Session status check - Session info:', sessionInfo);
            }
        } catch (sessionError) {
            console.error('Session validation error:', sessionError);
            sessionValid = false;
            isAuthenticated = false;
        }

        if (isAuthenticated) {
            // Extra validation: ensure a master password still exists and the session password is valid
            try {
                const anySet = await FileManager.isMasterPasswordSet();
                // We now store the DataKey in session, so just ensure that master passwords still exist
                if (!anySet) {
                    clearSession(req);
                    isAuthenticated = false;
                }
            } catch (validationError) {
                console.error('Master password validation error:', validationError);
                // On any error, consider session invalid
                clearSession(req);
                isAuthenticated = false;
            }
        } else {
            // Check if session can be recovered (user has data but no active session)
            try {
                const recoveryStatus = await tryRecoverSession(req);
                sessionRecoverable = recoveryStatus === 'RECOVERABLE';
            } catch (recoveryError) {
                console.error('Session recovery check error:', recoveryError);
                sessionRecoverable = false;
            }
        }

        res.json({ 
            authenticated: isAuthenticated,
            sessionValid: sessionValid,
            sessionRecoverable: sessionRecoverable,
            lastActivity: req.session?.lastActivity || null,
            timestamp: new Date().toISOString(),
            sessionInfo: sessionInfo,
            // Add environment info for debugging
            environment: {
                electron: process.env.ELECTRON === 'true',
                nodeEnv: process.env.NODE_ENV,
                dataDir: process.env.DATA_DIR || 'default'
            }
        });
    } catch (error) {
        console.error('Session status check error:', error);
        res.status(500).json({ 
            error: 'Failed to check session status',
            authenticated: false,
            sessionValid: false,
            sessionRecoverable: false
        });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    try {
        const sessionInfo = {
            hasSession: Boolean(req.session),
            authenticated: Boolean(req.session?.authenticated),
            hasMasterPassword: Boolean(getMasterPassword(req)),
            sessionId: req.session?.id || null
        };
        
        // Check file system permissions for distributed app
        let fileSystemStatus = 'unknown';
        if (process.env.ELECTRON === 'true') {
            try {
                const fs = require('fs');
                const sessionsDir = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'sessions');
                
                if (fs.existsSync(sessionsDir)) {
                    // Test write permissions
                    const testFile = path.join(sessionsDir, '.health-check-' + Date.now());
                    fs.writeFileSync(testFile, 'health-check');
                    fs.unlinkSync(testFile);
                    fileSystemStatus = 'writable';
                } else {
                    fileSystemStatus = 'directory-missing';
                }
            } catch (fsError) {
                fileSystemStatus = 'permission-error: ' + fsError.message;
            }
        }
        
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            sessionActive: req.session?.authenticated || false,
            sessionInfo: sessionInfo,
            dataDir: DATA_DIR,
            electron: process.env.ELECTRON === 'true',
            nodeEnv: process.env.NODE_ENV,
            fileSystemStatus: fileSystemStatus,
            sessionSecret: process.env.SESSION_SECRET ? 'set' : 'not-set'
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({ 
            status: 'ERROR',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Folder management endpoints
// Get all folders
app.get('/api/folders', largeDataLimiter, requireMasterPassword, async (req, res) => {
    try {
        const folders = await FileManager.readFolders();
        
        // Fix for ERR_CONTENT_LENGTH_MISMATCH with large JSON responses
        const jsonString = JSON.stringify(folders);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', Buffer.byteLength(jsonString, 'utf8'));
        
        // Handle client disconnect gracefully
        req.on('close', () => {
            console.log('Client disconnected from /api/folders');
        });
        
        res.end(jsonString);
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
        
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
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
            order: folders.length, // Set order to end of list
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        folders.push(newFolder);
        await FileManager.writeFolders(folders);
        res.status(201).json(newFolder);
    } catch (error) {
        console.error('Error creating folder:', error);
        res.status(500).json({ error: error.message });
    }
});

// Reorder folders (placed before param routes to avoid :id catching 'reorder')
app.put('/api/folders/reorder', requireMasterPassword, async (req, res) => {
    try {
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
        }
        
        // Be lenient with payload shape: accept array body, {order}, {ids}, or comma-separated string
        let incoming = req.body;
        let order = Array.isArray(incoming)
            ? incoming
            : (incoming && (incoming.order ?? incoming.ids ?? incoming.folderIds));

        if (typeof order === 'string') {
            try {
                // Try JSON first, fallback to comma-separated list
                const parsed = JSON.parse(order);
                order = Array.isArray(parsed) ? parsed : String(order).split(',');
            } catch (_) {
                order = String(order).split(',');
            }
        }

        if (!Array.isArray(order)) {
            return res.status(400).json({ error: 'Invalid order payload' });
        }

        // Normalize to strings and unique while preserving first occurrence
        const normalized = [];
        const seen = new Set();
        for (const id of order) {
            const sid = String(id || '').trim();
            if (!sid || seen.has(sid)) continue;
            seen.add(sid);
            normalized.push(sid);
        }

        const folders = await FileManager.readFolders();
        const byId = new Map(folders.map(f => [f.id, f]));
        const ordered = normalized.map(id => byId.get(id)).filter(Boolean);
        const rest = folders.filter(f => !normalized.includes(f.id));
        const finalList = [...ordered, ...rest];
        
        // Update order indices for all folders
        finalList.forEach((folder, index) => {
            folder.order = index;
            folder.updatedAt = new Date().toISOString();
        });
        
        await FileManager.writeFolders(finalList);
        res.json(finalList);
    } catch (error) {
        console.error('Error reordering folders:', error);
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
        
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
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
        console.error('Error updating folder:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete folder (optionally migrate passwords to another folder or null)
app.delete('/api/folders/:id', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { migrateTo } = req.query; // optional destination folder id or 'null'
        
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
        }
        
        // Validate folder ID
        if (!id || typeof id !== 'string' || id.trim().length === 0) {
            return res.status(400).json({ error: 'Invalid folder ID' });
        }
        
        let folders = await FileManager.readFolders();
        const folderExists = folders.some(f => f.id === id);
        if (!folderExists) {
            return res.status(404).json({ error: 'Folder not found' });
        }
        
        // Remove folder
        folders = folders.filter(f => f.id !== id);
        await FileManager.writeFolders(folders);

        // Reassign passwords to the target folder (or null for "no folder")
        try {
            const dataKey = getMasterPassword(req);
            
            // Use the new method to update passwords directly without decryption
            const movedCount = await FileManager.updatePasswordFolderIds(id, null);
            
            if (movedCount > 0) {
                console.log(`Moved ${movedCount} passwords to "no folder"`);
            }
            
            // ADDITIONAL CLEANUP: Ensure no passwords reference deleted folders
            try {
                await FileManager.cleanupOrphanedPasswordFolders();
            } catch (cleanupError) {
                console.warn('Error during orphaned folder cleanup:', cleanupError);
            }
            
            // Return information about moved passwords
            res.json({ 
                message: 'Folder deleted', 
                migratedTo: migrateTo === 'null' || !migrateTo ? null : String(migrateTo),
                movedPasswords: movedCount,
                movedToFolderId: null
            });
        } catch (passwordError) {
            console.error('Error reassigning passwords during folder deletion:', passwordError);
            // Continue with folder deletion even if password reassignment fails
            res.json({ 
                message: 'Folder deleted', 
                migratedTo: migrateTo === 'null' || !migrateTo ? null : String(migrateTo),
                movedPasswords: 0,
                movedToFolderId: null,
                warning: 'Passwords could not be reassigned'
            });
        }
    } catch (error) {
        console.error('Error deleting folder:', error);
        res.status(500).json({ error: 'Internal server error during folder deletion' });
    }
});

// (duplicate reorder route removed; the canonical route is declared above before param routes)

// Move password to folder
app.put('/api/passwords/:id/move', requireMasterPassword, async (req, res) => {
    try {
        const { id } = req.params;
        const { folderId } = req.body; // can be null
        
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
        }
        
        const dataKey = getMasterPassword(req);
        
        // Lade alle Passwörter
        const passwords = await FileManager.readPasswords();
        const index = passwords.findIndex(p => p.id === id);
        if (index === -1) {
            return res.status(404).json({ error: 'Password not found' });
        }
        
        // Only update if folder actually changed
        if (passwords[index].folderId === folderId) {
            // Entschlüssele für die Antwort
            const decryptedPasswords = await FileManager.loadAndDecryptPasswords(dataKey);
            const password = decryptedPasswords.find(p => p.id === id);
            return res.json(password); // No change needed
        }
        
        // Aktualisiere nur das folderId Feld
        passwords[index] = { ...passwords[index], folderId: folderId || null, updatedAt: new Date().toISOString() };
        // WICHTIG: Cache invalidieren, damit /api/all sofort aktualisierte Daten liefert
        await FileManager.writePasswordsCached(passwords, dataKey);
        
        // Entschlüssele für die Antwort
        const decryptedPasswords = await FileManager.loadAndDecryptPasswords(dataKey);
        const updatedPassword = decryptedPasswords.find(p => p.id === id);
        
        res.json(updatedPassword);
    } catch (error) {
        console.error('Error moving password:', error);
        res.status(500).json({ error: error.message });
    }
});

// Batch move passwords to folder (optimized)
app.put('/api/passwords/batch-move', requireMasterPassword, async (req, res) => {
    try {
        const { passwordIds, folderId } = req.body;
        
        if (!Array.isArray(passwordIds) || passwordIds.length === 0) {
            return res.status(400).json({ error: 'Password IDs array is required' });
        }
        
        // Double-check authentication before proceeding
        const currentMasterPassword = getMasterPassword(req);
        if (!currentMasterPassword || !req.session?.authenticated) {
            return res.status(401).json({ 
                error: 'Session expired. Please login again.',
                code: 'SESSION_EXPIRED'
            });
        }
        
        const dataKey = getMasterPassword(req);
        
        // Verwende die optimierte Batch-Methode
        const updated = await FileManager.movePasswordsToFolder(passwordIds, folderId, dataKey);
        
        if (!updated) {
            return res.json({ message: 'No passwords were moved (already in target folder)' });
        }
        
        res.json({ 
            message: `Successfully moved ${passwordIds.length} password(s) to folder`,
            movedCount: passwordIds.length,
            targetFolderId: folderId
        });
    } catch (error) {
        console.error('Error batch moving passwords:', error);
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
                console.log(`HTTPS server running on port ${PORT}`);
            });
        } catch (error) {
            console.error('HTTPS setup failed, falling back to HTTP:', error);
            startHttpServer();
        }
    } else {
        startHttpServer();
    }
};

const startHttpServer = () => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`HTTP server running on port ${PORT}`);
        console.log(`Data directory: ${process.env.DATA_DIR || 'default'}`);
        console.log(`Session store: ${process.env.ELECTRON === 'true' ? 'file-store (Electron)' : 'memory-store (dev)'}`);
    });
};

// Start the server
const initializeServer = async () => {
    try {
        // Clean up folders on startup
        console.log('Initializing server and cleaning up folders...');
        const folders = await FileManager.readFolders();
        console.log(`Found ${folders.length} folders, cleaned up and normalized.`);
        
        // Start the server
        startServer();
    } catch (error) {
        console.error('Error during server initialization:', error);
        // Start server anyway
        startServer();
    }
};

initializeServer();

// Performance-Statistiken
app.get('/api/performance', requireMasterPassword, async (req, res) => {
    try {
        const stats = getPerformanceStats();
        res.json({
            ...stats,
            timestamp: new Date().toISOString(),
            cacheSize: {
                passwords: passwordCache.size,
                searchIndices: searchIndex.size
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cache zurücksetzen (nur für Entwickler)
app.post('/api/performance/reset-cache', requireMasterPassword, async (req, res) => {
    try {
        clearAllCaches();
        res.json({ 
            message: 'All caches cleared successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cleanup orphaned password folder references
app.post('/api/cleanup-orphaned-folders', requireMasterPassword, async (req, res) => {
    try {
        const cleanedCount = await FileManager.cleanupOrphanedPasswordFolders();
        res.json({ 
            message: `Cleaned up ${cleanedCount} orphaned password folder references`,
            cleanedCount,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error in cleanup-orphaned-folders:', error);
        res.status(500).json({ error: error.message });
    }
});