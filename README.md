# 🔐 Sicherer Passwort-Manager

Eine vollständig offlinefähige, sichere Passwort-Manager-Web-App, die lokal im Browser läuft.

## ✨ Features

- **🔒 AES256-Verschlüsselung** - Alle Daten werden mit militärischer Verschlüsselung geschützt
- **🌐 Offline-fähig** - Funktioniert ohne Internetverbindung
- **📱 Responsive Design** - Optimiert für Desktop und mobile Geräte
- **🔑 Master-Passwort-Schutz** - Ein sicheres Master-Passwort schützt alle Daten
- **🔍 Suchfunktion** - Schnelle Suche in allen Passwörtern
- **📤 Export/Import** - Sichern und Wiederherstellen Ihrer Daten
- **🔧 Passwort-Generator** - Erstellt sichere Passwörter automatisch
- **👁️ Passwort-Sichtbarkeit** - Ein-/Ausblenden von Passwörtern
- **📋 Kopieren-Funktion** - Ein-Klick-Kopieren von Benutzernamen und Passwörtern

## 🚀 Installation & Verwendung

### Einfache Installation
1. Laden Sie die `index.html` Datei herunter
2. Öffnen Sie die Datei in Ihrem Browser (Chrome, Firefox, Safari, Edge)
3. Das war's! Die App läuft sofort

### Erste Einrichtung
1. **Master-Passwort erstellen**: Geben Sie ein sicheres Master-Passwort ein (mindestens 8 Zeichen)
2. **Passwort bestätigen**: Wiederholen Sie das Master-Passwort
3. **Anmelden**: Klicken Sie auf "Anmelden / Registrieren"

### Passwörter verwalten
- **Hinzufügen**: Klicken Sie auf "+ Neues Passwort"
- **Bearbeiten**: Klicken Sie auf "Bearbeiten" bei einem Passwort
- **Löschen**: Klicken Sie auf "Löschen" bei einem Passwort
- **Suchen**: Nutzen Sie die Suchleiste oben
- **Kopieren**: Klicken Sie auf "Kopieren" bei Benutzername oder Passwort

## 🔧 Technische Details

### Sicherheit
- **AES256-Verschlüsselung** mit PBKDF2-Schlüsselableitung
- **Salting** für zusätzliche Sicherheit
- **Lokale Speicherung** - Daten verlassen nie Ihr Gerät
- **Master-Passwort-Schutz** - Ohne Master-Passwort keine Entschlüsselung

### Datenspeicherung
- **LocalStorage** - Daten werden im Browser gespeichert
- **Verschlüsselt** - Alle Daten sind AES256-verschlüsselt
- **Offline** - Keine Server-Kommunikation erforderlich

### Browser-Kompatibilität
- ✅ Chrome 60+
- ✅ Firefox 55+
- ✅ Safari 11+
- ✅ Edge 79+

## 📤 Export & Import

### Daten exportieren
1. Klicken Sie auf "📤 Alle Daten exportieren"
2. Eine verschlüsselte JSON-Datei wird heruntergeladen
3. Bewahren Sie diese Datei sicher auf

### Daten importieren
1. Klicken Sie auf "📥 Daten importieren"
2. Wählen Sie eine zuvor exportierte JSON-Datei aus
3. Die Daten werden automatisch entschlüsselt und importiert

## 🔑 Passwort-Generator

Der integrierte Passwort-Generator erstellt sichere Passwörter mit:
- Mindestens 16 Zeichen
- Groß- und Kleinbuchstaben
- Zahlen
- Sonderzeichen
- Zufällige Verteilung

## 📱 Mobile Nutzung

Die App ist vollständig für mobile Geräte optimiert:
- Responsive Design
- Touch-freundliche Buttons
- Optimierte Darstellung auf kleinen Bildschirmen
- Einfache Bedienung mit Fingern

## 🛡️ Sicherheitshinweise

### Master-Passwort
- **Merken Sie sich Ihr Master-Passwort!** Es kann nicht wiederhergestellt werden
- Verwenden Sie ein sicheres, einzigartiges Master-Passwort
- Mindestens 8 Zeichen mit Groß-/Kleinbuchstaben, Zahlen und Sonderzeichen

### Datensicherung
- Exportieren Sie regelmäßig Ihre Daten
- Bewahren Sie Backups an einem sicheren Ort auf
- Verwenden Sie verschiedene Geräte für Backup und Hauptnutzung

### Browser-Daten
- Die App speichert Daten im Browser-LocalStorage
- Löschen Sie Browser-Daten nur, wenn Sie ein Backup haben
- Nutzen Sie den privaten/inkognito Modus für zusätzliche Sicherheit

## 🔧 Fehlerbehebung

### "Entschlüsselung fehlgeschlagen"
- Überprüfen Sie Ihr Master-Passwort
- Stellen Sie sicher, dass Sie das richtige Master-Passwort verwenden
- Bei der ersten Nutzung: Das Master-Passwort wird beim ersten Login erstellt

### Daten gehen verloren
- Überprüfen Sie, ob Browser-Daten gelöscht wurden
- Stellen Sie sicher, dass Sie ein Backup haben
- Importieren Sie Ihre exportierten Daten

### App funktioniert nicht
- Aktualisieren Sie Ihren Browser
- Überprüfen Sie, ob JavaScript aktiviert ist
- Versuchen Sie einen anderen Browser

## 📄 Lizenz

Diese App ist Open Source und steht unter der MIT-Lizenz zur freien Verfügung.

## 🤝 Beitragen

Verbesserungsvorschläge und Bug-Reports sind willkommen!

## ⚠️ Haftungsausschluss

Diese App wird "wie besehen" bereitgestellt. Der Entwickler übernimmt keine Haftung für Datenverluste oder Sicherheitsprobleme. Verwenden Sie die App auf eigene Verantwortung.

---

**🔐 Ihre Passwörter sind sicher - lokal, verschlüsselt und unter Ihrer Kontrolle!** # Passwortmanager-pwa
