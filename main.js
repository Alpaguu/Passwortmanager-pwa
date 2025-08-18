const { app, BrowserWindow } = require('electron');
const path = require('path');

process.env.ELECTRON = 'true';
process.env.NODE_ENV = app.isPackaged ? 'production' : 'development';

const setDataDirectoryEnv = () => {
  try {
    // For distributed app, use userData directory
    const userDataDir = path.join(app.getPath('userData'), 'data');
    process.env.DATA_DIR = userDataDir;
    
    // Ensure the data directory exists
    const fs = require('fs');
    if (!fs.existsSync(userDataDir)) {
      fs.mkdirSync(userDataDir, { recursive: true });
    }
    
    // Ensure sessions subdirectory exists with proper permissions
    const sessionsDir = path.join(userDataDir, 'sessions');
    if (!fs.existsSync(sessionsDir)) {
      fs.mkdirSync(sessionsDir, { recursive: true, mode: 0o755 });
    }
    
    // Also set SESSION_SECRET for distributed app
    if (!process.env.SESSION_SECRET) {
      process.env.SESSION_SECRET = 'distributed-app-secret-key-' + Date.now();
    }
    
    console.log('Data directory set to:', userDataDir);
    console.log('Sessions directory:', sessionsDir);
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
  // Requiring starts the HTTP(S) server immediately
  require(path.join(__dirname, 'server.js'));
};

const createMainWindow = async () => {
  const window = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
    show: false,
  });

  const baseUrl = `http://localhost:${PORT}`;
  const ready = await waitForServer(baseUrl, 15000);
  await window.loadURL(ready ? baseUrl : `file://${path.join(__dirname, 'index.html')}`);
  window.show();
};

const init = async () => {
  setDataDirectoryEnv();
  startBackendServer();
  await createMainWindow();
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


