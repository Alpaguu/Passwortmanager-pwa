# 🔐 Passwort-Manager Backend

Ein sicheres, lokales Node.js Backend für den Passwort-Manager mit AES-256-Verschlüsselung.

## 🚀 Installation

### Voraussetzungen
- Node.js (Version 14 oder höher)
- npm oder yarn

### Installation der Abhängigkeiten
```bash
npm install
```

### Umgebungsvariablen (optional)
Erstellen Sie eine `.env` Datei im Hauptverzeichnis:
```env
PORT=3000
```

## 🏃‍♂️ Starten des Servers

### Entwicklung (mit Auto-Reload)
```bash
npm run dev
```

### Produktion
```bash
npm start
```

Der Server läuft dann auf `http://localhost:3000`

## 📁 Projektstruktur

```
Passwortmanager/
├── server.js              # Hauptserver-Datei
├── package.json           # Abhängigkeiten und Scripts
├── public/
│   └── index.html         # Frontend (wird vom Server bereitgestellt)
├── data/                  # Automatisch erstellt
│   └── passwords.json     # Verschlüsselte Passwort-Daten
├── README_BACKEND.md      # Diese Datei
└── .env                   # Umgebungsvariablen (optional)
```

## 🔧 API-Endpunkte

### Authentifizierung

#### `POST /api/set-master-password`
Setzt das Master-Passwort für die Verschlüsselung.

**Request Body:**
```json
{
  "password": "IhrSicheresMasterPasswort123!"
}
```

**Response:**
```json
{
  "message": "Master password set successfully"
}
```

### Passwort-Verwaltung

#### `GET /api/all`
Gibt alle entschlüsselten Passwörter zurück.

**Response:**
```json
[
  {
    "id": "uuid-string",
    "title": "Amazon",
    "username": "user@example.com",
    "password": "entschlüsseltes-passwort",
    "url": "https://amazon.com",
    "notes": "Optional notes",
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
]
```

#### `POST /api/add`
Fügt ein neues Passwort hinzu.

**Request Body:**
```json
{
  "title": "Amazon",
  "username": "user@example.com",
  "password": "sicheres-passwort",
  "url": "https://amazon.com",
  "notes": "Optional notes"
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "title": "Amazon",
  "username": "user@example.com",
  "password": "sicheres-passwort",
  "url": "https://amazon.com",
  "notes": "Optional notes",
  "createdAt": "2024-01-01T00:00:00.000Z",
  "updatedAt": "2024-01-01T00:00:00.000Z"
}
```

#### `PUT /api/update/:id`
Aktualisiert ein bestehendes Passwort.

**Request Body:**
```json
{
  "title": "Amazon (Updated)",
  "username": "newuser@example.com",
  "password": "neues-passwort",
  "url": "https://amazon.com",
  "notes": "Updated notes"
}
```

#### `DELETE /api/delete/:id`
Löscht ein Passwort.

**Response:**
```json
{
  "message": "Password deleted successfully"
}
```

### Import/Export

#### `GET /api/export`
Exportiert alle Passwörter als JSON-Datei.

**Response:** Download einer JSON-Datei mit allen Passwörtern.

#### `POST /api/import`
Importiert Passwörter aus einer JSON-Datei.

**Request Body:**
```json
{
  "passwords": [
    {
      "title": "Amazon",
      "username": "user@example.com",
      "password": "password123",
      "url": "https://amazon.com",
      "notes": "Optional notes"
    }
  ]
}
```

### System

#### `GET /api/health`
Health-Check für den Server.

**Response:**
```json
{
  "status": "OK",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "masterPasswordSet": true
}
```

## 🔒 Sicherheit

### Verschlüsselung
- **AES-256-CBC** Verschlüsselung für alle sensiblen Daten
- **PBKDF2** Schlüsselableitung mit 100.000 Iterationen
- **Salting** für zusätzliche Sicherheit
- **IV (Initialization Vector)** für jede Verschlüsselung

### Datenspeicherung
- Alle Daten werden in `./data/passwords.json` gespeichert
- Benutzername und Passwort werden verschlüsselt gespeichert
- Das Master-Passwort wird nur im Arbeitsspeicher gehalten
- Keine Daten werden unverschlüsselt gespeichert

### Authentifizierung
- Master-Passwort muss beim Start gesetzt werden
- Alle API-Endpunkte (außer `/set-master-password`) erfordern ein gesetztes Master-Passwort
- Session-basierte Authentifizierung (Master-Passwort bleibt bis zum Neustart aktiv)

## 🛠️ Entwicklung

### Debugging
Der Server gibt detaillierte Logs aus:
- Server-Start und Konfiguration
- API-Anfragen und Antworten
- Fehler und Exceptions

### Fehlerbehebung

#### "Master password not set"
- Setzen Sie zuerst das Master-Passwort über `/api/set-master-password`
- Das Master-Passwort muss mindestens 8 Zeichen lang sein

#### "Decryption failed"
- Überprüfen Sie, ob Sie das richtige Master-Passwort verwenden
- Bei falschem Master-Passwort können die Daten nicht entschlüsselt werden

#### "File not found"
- Das `data/` Verzeichnis wird automatisch erstellt
- Bei der ersten Nutzung existiert noch keine `passwords.json` Datei

## 📱 Frontend-Integration

Das Backend stellt automatisch das Frontend unter `http://localhost:3000` bereit. Das Frontend kommuniziert über die API-Endpunkte mit dem Backend.

### CORS
Das Backend ist für lokale Entwicklung konfiguriert und erlaubt CORS-Anfragen von `localhost`.

## 🔄 Migration von localStorage

Falls Sie von der localStorage-Version migrieren möchten:

1. **Exportieren Sie Ihre Daten** aus der localStorage-Version
2. **Starten Sie das Backend**
3. **Setzen Sie das Master-Passwort** über die API
4. **Importieren Sie die Daten** über die API

## 🚀 Deployment

### Lokale Nutzung
```bash
npm start
```

### Als Service (Linux)
```bash
# Mit PM2
npm install -g pm2
pm2 start server.js --name "password-manager"

# Mit systemd
sudo systemctl enable password-manager
sudo systemctl start password-manager
```

### Docker (optional)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:3000/api/health
```

### Logs
```bash
# Mit PM2
pm2 logs password-manager

# Mit systemd
journalctl -u password-manager -f
```

## 🔧 Konfiguration

### Port ändern
```env
PORT=8080
```

### Datenverzeichnis ändern
Ändern Sie in `server.js`:
```javascript
const DATA_FILE = './custom/path/passwords.json';
const DATA_DIR = './custom/path';
```

## 🛡️ Sicherheitshinweise

1. **Master-Passwort**: Merken Sie sich Ihr Master-Passwort gut - es kann nicht wiederhergestellt werden
2. **Backup**: Exportieren Sie regelmäßig Ihre Daten
3. **Lokale Nutzung**: Das Backend ist für lokale Nutzung konzipiert
4. **Firewall**: Stellen Sie sicher, dass Port 3000 nicht öffentlich zugänglich ist
5. **Updates**: Halten Sie Node.js und die Abhängigkeiten aktuell

## 📄 Lizenz

MIT License - siehe LICENSE Datei.

---

**🔐 Ihre Passwörter sind sicher - lokal, verschlüsselt und unter Ihrer Kontrolle!** 