// Enclave desktop — Electron shell.
// Starts the local Enclave server (in Electron's own Node, so no external `node`
// is required) and opens the console in a native window. The server attaches to
// the user's `claude` CLI exactly as `node server.mjs` does; the window is just a
// nicer front door than a browser tab.

const { app, BrowserWindow, shell, dialog } = require('electron');
const path = require('path');
const http = require('http');
const { pathToFileURL } = require('url');

const PORT = 8977;
const HEALTH = `http://localhost:${PORT}/api/health`;
const CONSOLE = `http://localhost:${PORT}/app.html`;

// where the server + its assets live: bundled resources when packaged, repo root in dev
const ENCLAVE_ROOT = app.isPackaged ? path.join(process.resourcesPath, 'enclave') : path.join(__dirname, '..');
process.env.ENCLAVE_ROOT = ENCLAVE_ROOT;

let win;

function ping() {
  return new Promise(resolve => {
    const req = http.get(HEALTH, res => { res.resume(); resolve(true); });
    req.on('error', () => resolve(false));
    req.setTimeout(600, () => { req.destroy(); resolve(false); });
  });
}
async function waitReady() {
  for (let i = 0; i < 80; i++) { if (await ping()) return true; await new Promise(r => setTimeout(r, 250)); }
  return false;
}

function createWindow(loadingHtml) {
  win = new BrowserWindow({
    width: 1380, height: 900, minWidth: 980, minHeight: 640,
    backgroundColor: '#0a0d13', title: 'Enclave',
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  win.setMenuBarVisibility(false);
  // open external links (if any) in the real browser, never inside the shell
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
  win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(loadingHtml));
}

const LOADING = `<body style="margin:0;height:100vh;display:grid;place-items:center;background:#0a0d13;color:#c9d4e3;font:15px system-ui">
  <div style="text-align:center">
    <div style="font-size:26px;letter-spacing:.02em">◈ Enclave</div>
    <div style="margin-top:10px;color:#6b7688">starting the sealed console · attaching to your Claude CLI…</div>
  </div></body>`;

async function boot() {
  createWindow(LOADING);
  try {
    await import(pathToFileURL(path.join(ENCLAVE_ROOT, 'server.mjs')).href); // starts listening
  } catch (e) {
    dialog.showErrorBox('Enclave — server failed to start', String(e && e.stack || e));
  }
  const ok = await waitReady();
  if (ok && win && !win.isDestroyed()) win.loadURL(CONSOLE);
  else if (win && !win.isDestroyed())
    win.loadURL('data:text/html,' + encodeURIComponent('<body style="background:#0a0d13;color:#f16d6d;font:15px system-ui;padding:40px">Server did not come up on port ' + PORT + '. Is it already running, or is the port in use?</body>'));
}

app.whenReady().then(boot);
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) boot(); });
app.on('window-all-closed', () => app.quit());
