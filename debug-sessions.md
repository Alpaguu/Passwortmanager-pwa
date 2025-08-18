# Session-Debugging für verteilte Passwortmanager-App

## Problem
In der verteilten Electron-App (DMG) werden keine Sessions erstellt, obwohl der Login erfolgreich ist.

## Mögliche Ursachen

### 1. Dateiberechtigungen
- Die App kann keine Dateien im `~/Library/Application Support/Passwortmanager/data/sessions/` Verzeichnis erstellen
- Fehlende Schreibberechtigungen für den Benutzer

### 2. Session-Store-Konfiguration
- `session-file-store` kann nicht auf das Dateisystem zugreifen
- Falsche Pfade oder Umgebungsvariablen

### 3. Cookie-Einstellungen
- Cookies werden nicht korrekt gesetzt oder gelesen
- Domain-Probleme mit `localhost`

## Debugging-Schritte

### 1. Überprüfe die Konsole
Öffne die Developer Tools (Cmd+Option+I) und schaue nach Fehlermeldungen:
- Session-Speicherfehler
- Dateiberechtigungsfehler
- Cookie-Fehler

### 2. Überprüfe die Health-API
Rufe `http://localhost:57321/api/health` auf und prüfe:
- `fileSystemStatus`: Sollte "writable" sein
- `sessionSecret`: Sollte "set" sein
- `dataDir`: Sollte den korrekten Pfad zeigen

### 3. Überprüfe den Session-Status
Rufe `http://localhost:57321/api/session-status` auf und prüfe:
- `sessionInfo`: Detaillierte Session-Informationen
- `environment`: Electron-Status und Datenverzeichnis

### 4. Überprüfe das Dateisystem
```bash
# Überprüfe das Datenverzeichnis
ls -la ~/Library/Application\ Support/Passwortmanager/data/

# Überprüfe das Sessions-Verzeichnis
ls -la ~/Library/Application\ Support/Passwortmanager/data/sessions/

# Teste Schreibberechtigungen
touch ~/Library/Application\ Support/Passwortmanager/data/sessions/test.txt
rm ~/Library/Application\ Support/Passwortmanager/data/sessions/test.txt
```

## Lösungen

### 1. Berechtigungen reparieren
```bash
# Setze korrekte Berechtigungen
chmod -R 755 ~/Library/Application\ Support/Passwortmanager/data/
chmod -R 755 ~/Library/Application\ Support/Passwortmanager/data/sessions/
```

### 2. App neu starten
- Schließe die App vollständig
- Lösche eventuell vorhandene Session-Dateien
- Starte die App neu

### 3. Datenverzeichnis zurücksetzen
```bash
# Sichere wichtige Daten
cp -r ~/Library/Application\ Support/Passwortmanager/data/passwords.json ~/Desktop/
cp -r ~/Library/Application\ Support/Passwortmanager/data/master_passwords.json ~/Desktop/

# Lösche das Datenverzeichnis
rm -rf ~/Library/Application\ Support/Passwortmanager/data/

# Starte die App neu (erstellt das Verzeichnis automatisch)
```

## Prävention

### 1. Regelmäßige Berechtigungsprüfung
Die App prüft jetzt automatisch die Schreibberechtigungen beim Start.

### 2. Besseres Logging
Alle Session-Operationen werden jetzt detailliert geloggt.

### 3. Fallback-Mechanismen
Die App versucht, auch bei Session-Fehlern weiterzuarbeiten.

## Support
Bei anhaltenden Problemen:
1. Sammle alle Konsolen-Ausgaben
2. Überprüfe die Berechtigungen
3. Teste die Health-API
4. Erstelle einen Bug-Report mit allen Informationen
