# 📦 Version Update Anleitung

## So aktualisierst du die App-Version:

### 1. Version in package.json ändern
Ändere die Version in der `package.json` Datei:
```json
{
  "version": "1.9.1"  // ← Hier die neue Version eintragen
}
```

### 2. Version synchronisieren
Führe das Sync-Script aus, um die Version automatisch in der App zu aktualisieren:
```bash
npm run sync-version
```

### 3. Fertig! 🎉
Die Version wird jetzt automatisch oben links in der App angezeigt.

## Was passiert beim Sync?
- Das Script liest die Version aus der `package.json`
- Es aktualisiert die `APP_VERSION` Konstante in der `index.html`
- Die App zeigt automatisch die neue Version an

## Automatische Anzeige
Die Version wird in folgenden Modi angezeigt:
- **Lokaler Modus**: Verwendet die `APP_VERSION` Konstante
- **Server-Modus**: Lädt Version über API-Endpoint `/api/version`
- **Fallback**: Verwendet die Konstante als Backup

## Beispiel
```bash
# Version von 1.9.0 auf 1.9.1 aktualisieren
# 1. In package.json: "version": "1.9.1"
# 2. Script ausführen:
npm run sync-version
# ✅ Version v1.9.1 wird oben links angezeigt
```

---
*Diese Datei wurde automatisch generiert. Bei Fragen schau in die `sync-version.js` Datei.*
