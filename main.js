const { app, BrowserWindow } = require('electron');
const path = require('path');

// ⚡ Performance-Optimierungen
app.commandLine.appendSwitch('--disable-background-timer-throttling');
app.commandLine.appendSwitch('--disable-renderer-backgrounding');
app.commandLine.appendSwitch('--disable-backgrounding-occluded-windows');
app.commandLine.appendSwitch('--disable-features', 'TranslateUI');

process.env.ELECTRON = 'true';
process.env.NODE_ENV = app.isPackaged ? 'production' : 'development';

const setDataDirectoryEnv = () => {
  try {
    // For distributed app, use userData directory
    const userDataDir = path.join(app.getPath('userData'), 'data');
    process.env.DATA_DIR = userDataDir;
    
    // Ensure the data directory exists with proper permissions
    const fs = require('fs');
    if (!fs.existsSync(userDataDir)) {
      fs.mkdirSync(userDataDir, { recursive: true, mode: 0o755 });
    }
    
    // Ensure sessions subdirectory exists with proper permissions
    const sessionsDir = path.join(userDataDir, 'sessions');
    if (!fs.existsSync(sessionsDir)) {
      fs.mkdirSync(sessionsDir, { recursive: true, mode: 0o755 });
    }
    
    // Set proper permissions for existing directories
    try {
      fs.chmodSync(userDataDir, 0o755);
      fs.chmodSync(sessionsDir, 0o755);
    } catch (permError) {
      console.warn('Could not set permissions on data directories:', permError.message);
    }
    
    // Also set SESSION_SECRET for distributed app
    if (!process.env.SESSION_SECRET) {
      process.env.SESSION_SECRET = 'distributed-app-secret-key-' + Date.now();
    }
    
    // Set additional environment variables for better session handling
    process.env.ELECTRON = 'true';
    process.env.NODE_ENV = 'production';
    
    console.log('Data directory set to:', userDataDir);
    console.log('Sessions directory:', sessionsDir);
    console.log('Session secret set:', process.env.SESSION_SECRET ? 'Yes' : 'No');
    
    // Test write permissions
    try {
      const testFile = path.join(sessionsDir, '.test-write');
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      console.log('✓ Write permissions OK for sessions directory');
    } catch (writeError) {
      console.error('✗ Write permission test failed for sessions directory:', writeError.message);
      console.error('This may cause session creation issues!');
    }
  } catch (error) {
    console.error('Error setting up data directory:', error);
    // Fallback to server default
    process.env.DATA_DIR = path.join(__dirname, 'data');
  }
};

const PORT = Number(process.env.PORT) || 57321;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForServer = async (url, timeoutMs = 10000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${url}/api/health`, { signal: controller.signal });
      clearTimeout(id);
      if (res && res.ok) return true;
    } catch (_) {}
    await wait(300);
  }
  return false;
};

const startBackendServer = () => {
  try {
    // Requiring starts the HTTP(S) server immediately
    console.log('Starting backend server from:', path.join(__dirname, 'server.js'));
    require(path.join(__dirname, 'server.js'));
    console.log('Backend server started successfully');
  } catch (error) {
    console.error('Failed to start backend server:', error);
    // Fallback: try to start with explicit path
    try {
      require('./server.js');
      console.log('Backend server started with fallback path');
    } catch (fallbackError) {
      console.error('Fallback also failed:', fallbackError);
    }
  }
};

const createMainWindow = async () => {
  const window = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: false, // ⚡ Für lokale Dateien
    },
    show: true, // ⚡ Sofort anzeigen!
    backgroundColor: '#ffffff',
    // 🖱️ MODERNE macOS Titelleiste (bewegbar + schön)
    titleBarStyle: 'hiddenInset', 
    frame: true,
    transparent: false,
    minimizable: true,
    maximizable: true,
    closable: true,
    // 🎯 Zusätzliche Drag-Optionen
    movable: true,
    resizable: true,
  });

  // ⚡ SOFORT Splash Screen laden!
  console.log('Loading splash screen immediately...');
  await window.loadFile('splash.html');
  console.log('Splash screen displayed instantly');
  
  // Nach 2 Sekunden zur Hauptapp wechseln
  setTimeout(async () => {
    await window.loadFile('index.html');
    console.log('Main app loaded');
  }, 2000);

  // ⚡ Server im Hintergrund prüfen (non-blocking)
  checkServerInBackground(window);
  
  return window;
};

const checkServerInBackground = async (window) => {
  const baseUrl = `http://localhost:${PORT}`;
  console.log('Checking server in background:', baseUrl);
  
  // Nicht blockierend - prüfe ob Server verfügbar wird
  const ready = await waitForServer(baseUrl, 5000);
  
  if (ready) {
    console.log('Server ready - reloading with server URL');
    window.loadURL(baseUrl);
  } else {
    console.log('Server not available - staying with local file');
  }
};

const init = async () => {
  setDataDirectoryEnv();
  
  // ⚡ FENSTER SOFORT starten (nicht warten!)
  const window = await createMainWindow();
  
  // ⚡ Server parallel im Hintergrund starten
  startBackendServer();
  
  console.log('App initialized - window shown immediately');
  return window;
};

const singleInstanceLock = app.requestSingleInstanceLock();
if (!singleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const [win] = BrowserWindow.getAllWindows();
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });

  app.whenReady().then(init);

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
}


