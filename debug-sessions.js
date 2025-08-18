#!/usr/bin/env node

/**
 * Session-Debugging-Skript für verteilte Passwortmanager-App
 * 
 * Verwendung:
 * node debug-sessions.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('🔍 Session-Debugging für Passwortmanager-App\n');

// 1. Überprüfe Umgebungsvariablen
console.log('📋 Umgebungsvariablen:');
console.log(`  ELECTRON: ${process.env.ELECTRON || 'nicht gesetzt'}`);
console.log(`  NODE_ENV: ${process.env.NODE_ENV || 'nicht gesetzt'}`);
console.log(`  DATA_DIR: ${process.env.DATA_DIR || 'nicht gesetzt'}`);
console.log(`  SESSION_SECRET: ${process.env.SESSION_SECRET ? 'gesetzt' : 'nicht gesetzt'}`);

// 2. Bestimme Datenverzeichnis
let dataDir = process.env.DATA_DIR;
if (!dataDir) {
    if (process.env.ELECTRON === 'true') {
        // Simuliere Electron-Pfad
        dataDir = path.join(os.homedir(), 'Library', 'Application Support', 'Passwortmanager', 'data');
    } else {
        dataDir = path.join(__dirname, 'data');
    }
}

console.log(`\n📁 Datenverzeichnis: ${dataDir}`);

// 3. Überprüfe Verzeichnisstruktur
console.log('\n📂 Verzeichnisstruktur:');
try {
    if (fs.existsSync(dataDir)) {
        console.log(`  ✓ Hauptverzeichnis existiert: ${dataDir}`);
        
        const sessionsDir = path.join(dataDir, 'sessions');
        if (fs.existsSync(sessionsDir)) {
            console.log(`  ✓ Sessions-Verzeichnis existiert: ${sessionsDir}`);
            
            // Überprüfe Berechtigungen
            try {
                fs.accessSync(sessionsDir, fs.constants.R_OK | fs.constants.W_OK);
                console.log('  ✓ Sessions-Verzeichnis ist lesbar und beschreibbar');
            } catch (permError) {
                console.log(`  ✗ Sessions-Verzeichnis-Berechtigungen: ${permError.message}`);
            }
            
            // Liste Session-Dateien
            try {
                const files = fs.readdirSync(sessionsDir);
                console.log(`  📄 Anzahl Session-Dateien: ${files.length}`);
                if (files.length > 0) {
                    console.log('  📄 Session-Dateien:');
                    files.forEach(file => {
                        if (file.endsWith('.json')) {
                            const filePath = path.join(sessionsDir, file);
                            try {
                                const stats = fs.statSync(filePath);
                                const content = fs.readFileSync(filePath, 'utf8');
                                const parsed = JSON.parse(content);
                                console.log(`    - ${file} (${stats.size} bytes, ${parsed.cookie?.expires ? 'expired' : 'active'})`);
                            } catch (fileError) {
                                console.log(`    - ${file} (Fehler beim Lesen: ${fileError.message})`);
                            }
                        }
                    });
                }
            } catch (readError) {
                console.log(`  ✗ Fehler beim Lesen des Sessions-Verzeichnisses: ${readError.message}`);
            }
        } else {
            console.log(`  ✗ Sessions-Verzeichnis existiert nicht: ${sessionsDir}`);
        }
        
        // Überprüfe andere wichtige Dateien
        const importantFiles = ['passwords.json', 'master_passwords.json', 'folders.json'];
        importantFiles.forEach(file => {
            const filePath = path.join(dataDir, file);
            if (fs.existsSync(filePath)) {
                try {
                    const stats = fs.statSync(filePath);
                    console.log(`  ✓ ${file} existiert (${stats.size} bytes)`);
                } catch (statError) {
                    console.log(`  ✗ ${file} existiert, aber kann nicht gelesen werden: ${statError.message}`);
                }
            } else {
                console.log(`  - ${file} existiert nicht`);
            }
        });
        
    } else {
        console.log(`  ✗ Hauptverzeichnis existiert nicht: ${dataDir}`);
    }
} catch (error) {
    console.log(`  ✗ Fehler beim Überprüfen des Datenverzeichnisses: ${error.message}`);
}

// 4. Teste Schreibberechtigungen
console.log('\n✏️  Schreibberechtigungen testen:');
try {
    const testFile = path.join(dataDir, '.debug-test-' + Date.now());
    fs.writeFileSync(testFile, 'Test-Datei für Debugging');
    console.log(`  ✓ Test-Datei erstellt: ${testFile}`);
    
    // Lösche Test-Datei
    fs.unlinkSync(testFile);
    console.log('  ✓ Test-Datei gelöscht');
    
    // Teste Sessions-Verzeichnis
    const sessionsDir = path.join(dataDir, 'sessions');
    if (fs.existsSync(sessionsDir)) {
        const testSessionFile = path.join(sessionsDir, '.debug-session-test-' + Date.now());
        fs.writeFileSync(testSessionFile, '{"test": "session"}');
        console.log(`  ✓ Test-Session-Datei erstellt: ${testSessionFile}`);
        fs.unlinkSync(testSessionFile);
        console.log('  ✓ Test-Session-Datei gelöscht');
    }
} catch (writeError) {
    console.log(`  ✗ Schreibtest fehlgeschlagen: ${writeError.message}`);
}

// 5. Überprüfe Port-Verfügbarkeit
console.log('\n🌐 Port-Verfügbarkeit testen:');
const net = require('net');
const PORT = 57321;

const testPort = () => {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.listen(PORT, () => {
            server.close();
            resolve(true);
        });
        server.on('error', () => {
            resolve(false);
        });
    });
};

testPort().then(available => {
    if (available) {
        console.log(`  ✓ Port ${PORT} ist verfügbar`);
    } else {
        console.log(`  ✗ Port ${PORT} ist bereits belegt`);
    }
});

// 6. Empfehlungen
console.log('\n💡 Empfehlungen:');
if (!process.env.ELECTRON) {
    console.log('  - Setze ELECTRON=true für verteilte App');
}
if (!process.env.SESSION_SECRET) {
    console.log('  - Setze SESSION_SECRET für bessere Sicherheit');
}

console.log('\n🔧 Nächste Schritte:');
console.log('  1. Starte die App neu');
console.log('  2. Überprüfe die Developer Tools Konsole');
console.log('  3. Rufe http://localhost:57321/api/health auf');
console.log('  4. Rufe http://localhost:57321/api/session-status auf');
console.log('  5. Versuche dich mit dem Master-Passwort anzumelden');

console.log('\n📚 Weitere Hilfe:');
console.log('  - Siehe debug-sessions.md für detaillierte Anleitung');
console.log('  - Überprüfe die App-Logs in der Konsole');
console.log('  - Teste die Berechtigungen manuell mit den angezeigten Befehlen');
