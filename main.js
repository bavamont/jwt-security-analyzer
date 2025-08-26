const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const url = require('url');
const httpProxy = require('http-proxy');
const { Readable } = require('stream');
const forge = require('node-forge');
const ValidationUtils = require('./validation');

let mainWindow;
let updateDownloaded = false;
let proxyServer = null;
let caKey = null;
let caCert = null;
const certCache = new Map();
const CERT_CACHE_MAX_SIZE = 100;
const CERT_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Creates the main application window with security configurations
 * @function
 */
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            enableRemoteModule: false
        },
        icon: getIconPath(),
        show: false,
        frame: false,
        titleBarStyle: 'hidden',
        backgroundColor: '#0a0e1a',
        title: 'JWT Security Analyzer'
    });

    mainWindow.setMenu(null);
    mainWindow.loadFile('index.html');

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        if (process.argv.includes('--dev') || process.env.NODE_ENV === 'development') {
            mainWindow.webContents.openDevTools();
        }

        if (!process.argv.includes('--dev')) {
            checkForUpdates();
        }
    });

    mainWindow.on('closed', () => {
        if (proxyServer) {
            proxyServer.close();
            proxyServer = null;
        }
        certCache.clear();
        mainWindow = null;
    });

    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });
}

function getIconPath() {
    const iconPaths = {
        win32: 'assets/icon.ico',
        darwin: 'assets/icon.icns',
        linux: 'assets/icon.png'
    };

    const iconPath = iconPaths[process.platform] || iconPaths.linux;
    return path.join(__dirname, iconPath);
}

function setupAutoUpdater() {
    autoUpdater.checkForUpdatesAndNotify();

    autoUpdater.on('checking-for-update', () => {
        if (mainWindow) {
            mainWindow.webContents.send('update-checking');
        }
    });

    autoUpdater.on('update-available', (info) => {
        if (mainWindow) {
            mainWindow.webContents.send('update-available', info);
        }
    });

    autoUpdater.on('update-not-available', (info) => {
        if (mainWindow) {
            mainWindow.webContents.send('update-not-available', info);
        }
    });

    autoUpdater.on('error', (err) => {
        if (mainWindow) {
            mainWindow.webContents.send('update-error', err);
        }
    });

    autoUpdater.on('download-progress', (progressObj) => {
        if (mainWindow) {
            mainWindow.webContents.send('update-download-progress', progressObj);
        }
    });

    autoUpdater.on('update-downloaded', (info) => {
        updateDownloaded = true;
        if (mainWindow) {
            mainWindow.webContents.send('update-downloaded', info);
        }
    });
}

function checkForUpdates() {
    if (process.platform === 'linux') {
        return;
    }

    try {
        autoUpdater.checkForUpdatesAndNotify();
    } catch (error) {
    }
}

ipcMain.handle('check-for-updates', async () => {
    try {
        const result = await autoUpdater.checkForUpdates();
        return { success: true, updateInfo: result };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('download-update', async () => {
    try {
        await autoUpdater.downloadUpdate();
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('install-update', async () => {
    try {
        if (updateDownloaded) {
            autoUpdater.quitAndInstall();
            return { success: true };
        } else {
            return { success: false, error: 'No update downloaded' };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-update-info', async () => {
    try {
        return {
            success: true,
            version: app.getVersion(),
            updateDownloaded: updateDownloaded,
            platform: process.platform
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('window-minimize', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.minimize();
    }
    return { success: true };
});

ipcMain.handle('window-maximize', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        if (mainWindow.isMaximized()) {
            mainWindow.unmaximize();
        } else {
            mainWindow.maximize();
        }
    }
    return { success: true };
});

ipcMain.handle('window-close', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.close();
    }
    return { success: true };
});

ipcMain.handle('window-is-maximized', () => {
    return mainWindow && !mainWindow.isDestroyed() ? mainWindow.isMaximized() : false;
});

ipcMain.handle('load-file', async (event, filters) => {
    try {
        const { filePaths, canceled } = await dialog.showOpenDialog(mainWindow, {
            properties: ['openFile'],
            filters: filters || [
                { name: 'All Files', extensions: ['*'] },
                { name: 'JSON Files', extensions: ['json'] },
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'Dictionary Files', extensions: ['dic'] },
                { name: 'Wordlist Files', extensions: ['lst'] }
            ]
        });

        if (canceled) {
            return { success: false, cancelled: true };
        }

        if (filePaths.length > 0) {
            const content = await fs.readFile(filePaths[0], 'utf-8');
            return { success: true, content, path: filePaths[0] };
        }
        return { success: false, cancelled: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-file', async (event, content, defaultPath = null, filters = null) => {
    try {
        const dialogOptions = {
            title: 'Save File',
            filters: filters || [
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'JSON Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        };

        if (defaultPath) {
            dialogOptions.defaultPath = defaultPath;
        }

        const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, dialogOptions);

        if (canceled) {
            return { success: false, canceled: true };
        }

        await fs.writeFile(filePath, content, 'utf8');
        return { success: true, path: filePath };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('load-wordlist', async (event) => {
    try {
        const { filePaths, canceled } = await dialog.showOpenDialog(mainWindow, {
            title: 'Load Wordlist',
            properties: ['openFile'],
            filters: [
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'Dictionary Files', extensions: ['dic'] },
                { name: 'Wordlist Files', extensions: ['lst'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        });

        if (canceled) {
            return { success: false, canceled: true };
        }

        const content = await fs.readFile(filePaths[0], 'utf-8');
        const words = content.split('\n').filter(line => line.trim());

        return {
            success: true,
            content: content,
            words: words,
            path: filePaths[0],
            count: words.length
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-wordlist', async (event, wordlist, filename = null) => {
    try {
        const defaultFileName = filename || `custom-wordlist-${Date.now()}.txt`;

        const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
            title: 'Save Wordlist',
            defaultPath: defaultFileName,
            filters: [
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'Dictionary Files', extensions: ['dic'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        });

        if (canceled) {
            return { success: false, canceled: true };
        }

        const content = Array.isArray(wordlist) ? wordlist.join('\n') : wordlist;
        await fs.writeFile(filePath, content, 'utf8');

        return { success: true, path: filePath };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-system-language', async () => {
    try {
        const locale = app.getLocale();
        const language = locale.substring(0, 2);

        const supportedLanguages = ['en', 'de'];
        const detectedLanguage = supportedLanguages.includes(language) ? language : 'en';

        return {
            success: true,
            language: detectedLanguage,
            locale: locale,
            systemLanguages: app.getPreferredSystemLanguages()
        };
    } catch (error) {
        return { success: false, error: error.message, language: 'en' };
    }
});

ipcMain.handle('get-system-info', async () => {
    try {
        return {
            success: true,
            platform: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            electronVersion: process.versions.electron,
            chromeVersion: process.versions.chrome,
            totalMemory: os.totalmem(),
            freeMemory: os.freemem(),
            cpus: os.cpus().length,
            cpuModel: os.cpus()[0]?.model || 'Unknown',
            homeDir: os.homedir(),
            tempDir: os.tmpdir(),
            username: os.userInfo().username,
            hostname: os.hostname(),
            appVersion: app.getVersion(),
            appName: app.getName()
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('save-settings', async (event, settings, filePath = null) => {
    try {
        let savePath = filePath;

        if (!savePath) {
            const { filePath: selectedPath, canceled } = await dialog.showSaveDialog(mainWindow, {
                title: 'Save Settings',
                defaultPath: 'jwt-analyzer-settings.json',
                filters: [
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (canceled) {
                return { success: false, canceled: true };
            }

            savePath = selectedPath;
        }

        const settingsData = {
            version: '1.2.0',
            timestamp: new Date().toISOString(),
            application: 'jwt-security-analyzer',
            settings: settings
        };

        await fs.writeFile(savePath, JSON.stringify(settingsData, null, 2), 'utf8');
        return { success: true, path: savePath };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('load-settings', async (event, filePath = null) => {
    try {
        let loadPath = filePath;

        if (!loadPath) {
            const { filePaths, canceled } = await dialog.showOpenDialog(mainWindow, {
                title: 'Load Settings',
                filters: [
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'All Files', extensions: ['*'] }
                ],
                properties: ['openFile']
            });

            if (canceled) {
                return { success: false, canceled: true };
            }

            loadPath = filePaths[0];
        }

        const data = await fs.readFile(loadPath, 'utf8');
        const settingsData = JSON.parse(data);

        const settings = settingsData.settings || settingsData;

        return {
            success: true,
            settings,
            path: loadPath,
            version: settingsData.version,
            timestamp: settingsData.timestamp
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('check-path-exists', async (event, filePath) => {
    try {
        const stats = await fs.stat(filePath);
        return {
            exists: true,
            isDirectory: stats.isDirectory(),
            isFile: stats.isFile(),
            size: stats.size,
            modified: stats.mtime
        };
    } catch (error) {
        return { exists: false };
    }
});

ipcMain.handle('open-external', async (event, url) => {
    try {
        if (!ValidationUtils.isValidURL(url)) {
            return { success: false, error: 'Invalid URL' };
        }
        await shell.openExternal(url);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('generate-secure-token', async (event, length = 32) => {
    try {
        const token = crypto.randomBytes(length).toString('hex');
        return { success: true, token };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('hash-string', async (event, input, algorithm = 'sha256') => {
    try {
        const hash = crypto.createHash(algorithm).update(input).digest('hex');
        return { success: true, hash };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('show-error-dialog', async (event, title, message, detail = null) => {
    try {
        const options = {
            type: 'error',
            title: title || 'Error',
            message: message || 'An unknown error occurred',
            buttons: ['OK']
        };

        if (detail) {
            options.detail = detail;
        }

        await dialog.showMessageBox(mainWindow, options);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('show-info-dialog', async (event, title, message, detail = null) => {
    try {
        const options = {
            type: 'info',
            title: title || 'Information',
            message: message || '',
            buttons: ['OK']
        };

        if (detail) {
            options.detail = detail;
        }

        await dialog.showMessageBox(mainWindow, options);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('show-warning-dialog', async (event, title, message, buttons = ['Continue', 'Cancel']) => {
    try {
        const result = await dialog.showMessageBox(mainWindow, {
            type: 'warning',
            title: title || 'Warning',
            message: message || '',
            buttons: buttons,
            defaultId: 0,
            cancelId: buttons.length - 1
        });

        return {
            success: true,
            response: result.response,
            canceled: result.response === buttons.length - 1,
            buttonClicked: buttons[result.response]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('show-question-dialog', async (event, title, message, buttons = ['Yes', 'No']) => {
    try {
        const result = await dialog.showMessageBox(mainWindow, {
            type: 'question',
            title: title || 'Question',
            message: message || '',
            buttons: buttons,
            defaultId: 0,
            cancelId: buttons.length - 1
        });

        return {
            success: true,
            response: result.response,
            buttonIndex: result.response,
            buttonClicked: buttons[result.response],
            canceled: result.response === buttons.length - 1
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-app-version', async () => {
    return {
        success: true,
        version: app.getVersion(),
        name: app.getName()
    };
});

ipcMain.handle('show-error', async (event, title, message) => {
    dialog.showErrorBox(title, message);
    return { success: true };
});

ipcMain.handle('show-info', async (event, title, message) => {
    await dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: title,
        message: message,
        buttons: ['OK']
    });
    return { success: true };
});

/**
 * Generates a root Certificate Authority (CA) for HTTPS proxy
 * @function
 * @returns {Object} Object containing CA key and certificate
 */
function generateRootCA() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date('2099-12-31T23:59:59Z');
    
    const attrs = [{
        name: 'commonName',
        value: `JWT-Test-CA-${crypto.randomBytes(4).toString('hex')}`
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'CA'
    }, {
        name: 'localityName',
        value: 'San Francisco'
    }, {
        name: 'organizationName',
        value: 'JWT Security Analyzer'
    }, {
        shortName: 'OU',
        value: 'Certificate Authority'
    }];
    
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }]);
    
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    return {
        key: keys.privateKey,
        cert: cert
    };
}

/**
 * Generates a server certificate for the specified hostname
 * @function
 * @param {string} hostname - The hostname to generate certificate for
 * @returns {Object} Object containing certificate and private key
 */
function generateServerCertificate(hostname) {
    if (certCache.has(hostname)) {
        const cached = certCache.get(hostname);
        if (Date.now() - cached.timestamp < CERT_CACHE_TTL) {
            return { cert: cached.cert, key: cached.key };
        } else {
            certCache.delete(hostname);
        }
    }
    
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Date.now().toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date('2099-12-31T23:59:59Z');
    
    const attrs = [{
        name: 'commonName',
        value: hostname
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'CA'
    }, {
        name: 'localityName',
        value: 'San Francisco'
    }, {
        name: 'organizationName',
        value: 'JWT Security Analyzer Proxy'
    }];
    
    cert.setSubject(attrs);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions([{
        name: 'basicConstraints',
        cA: false
    }, {
        name: 'keyUsage',
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 2,
            value: hostname
        }]
    }]);
    
    cert.sign(caKey, forge.md.sha256.create());
    
    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    
    const result = {
        cert: certPem,
        key: keyPem
    };
    
    const cacheEntry = {
        cert: result.cert,
        key: result.key,
        timestamp: Date.now()
    };

    if (certCache.size >= CERT_CACHE_MAX_SIZE) {
        const oldestKey = certCache.keys().next().value;
        certCache.delete(oldestKey);
    }

    certCache.set(hostname, cacheEntry);
    return result;
}

ipcMain.handle('start-proxy', async (event, { port, httpsEnabled }) => {
    if (proxyServer) {
        return { success: false, error: 'Proxy is already running' };
    }

    if (!ValidationUtils.isValidPort(port)) {
        return { success: false, error: 'Invalid port number' };
    }

    try {
        if (httpsEnabled && !caKey) {
            const ca = generateRootCA();
            caKey = ca.key;
            caCert = ca.cert;
        }
        const proxy = httpProxy.createProxyServer({
            target: 'http://localhost',
            changeOrigin: true,
            ws: true,
            secure: false,
            xfwd: true,
            preserveHeaderKeyCase: true,
            autoRewrite: true,
            followRedirects: true
        });
        
        proxy.on('error', (err, req, res) => {
            if (res && res.writeHead && !res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'text/plain' });
                res.end('Proxy Error: ' + err.message);
            }
        });

        proxy.on('proxyReq', (proxyReq, req, res) => {
            const requestBody = req.body || '';
            
            const requestTokens = extractJWTTokens(req, requestBody);
            if (requestTokens.length > 0) {
                requestTokens.forEach(tokenData => {
                    if (mainWindow && !mainWindow.isDestroyed()) {
                        mainWindow.webContents.send('jwt-token-captured', tokenData);
                    }
                });
            }

            if (requestBody) {
                proxyReq.setHeader('Content-Length', Buffer.byteLength(requestBody));
                proxyReq.write(requestBody);
            }
        });

        proxy.on('proxyRes', (proxyRes, req, res) => {
            let responseBody = '';
            
            const _writeHead = res.writeHead;
            const _write = res.write;
            const _end = res.end;
            
            res.writeHead = function() {
                if (proxyRes.headers['content-encoding']) {
                    delete proxyRes.headers['content-encoding'];
                }
                _writeHead.apply(res, arguments);
            };
            
            res.write = function(chunk) {
                if (chunk) {
                    responseBody += chunk.toString();
                }
                return _write.apply(res, arguments);
            };
            
            res.end = function(chunk) {
                if (chunk) {
                    responseBody += chunk.toString();
                }
                
                const responseTokens = extractJWTTokensFromResponse(proxyRes, responseBody);
                if (responseTokens.length > 0) {
                    responseTokens.forEach(tokenData => {
                        if (mainWindow && !mainWindow.isDestroyed()) {
                            mainWindow.webContents.send('jwt-token-captured', tokenData);
                        }
                    });
                }
                
                return _end.apply(res, arguments);
            };
        });
        
        proxyServer = http.createServer((req, res) => {
            let body = '';
            
            req.on('data', chunk => {
                body += chunk.toString();
            });
            
            req.on('end', () => {
                req.body = body;
                
                let targetUrl;
                if (req.url.startsWith('http://') || req.url.startsWith('https://')) {
                    targetUrl = req.url;
                } else {
                    const host = req.headers.host || 'localhost';
                    const protocol = 'http';
                    targetUrl = `${protocol}://${host}${req.url}`;
                }
                
                const parsedUrl = new URL(targetUrl);
                const targetBase = `${parsedUrl.protocol}//${parsedUrl.host}`;
                
                proxy.web(req, res, {
                    target: targetBase,
                    changeOrigin: true,
                    selfHandleResponse: false
                });
            });
            
            req.on('error', (err) => {
                if (!res.headersSent) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end('Bad Request');
                }
            });
        });

        if (httpsEnabled) {
            proxyServer.on('connect', (req, clientSocket, head) => {
                const [hostname, port] = req.url.split(':');
                const targetPort = parseInt(port) || 443;
                
                clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
                                 'Proxy-agent: JWT-Security-Analyzer\r\n' +
                                 '\r\n');
                
                const serverCert = generateServerCertificate(hostname);
                
                const tlsOptions = {
                    key: serverCert.key,
                    cert: serverCert.cert,
                    isServer: true
                };
                
                const tlsSocket = new tls.TLSSocket(clientSocket, tlsOptions);
                
                tlsSocket.on('secure', () => {
                    const targetOptions = {
                        host: hostname,
                        port: targetPort,
                        rejectUnauthorized: false
                    };
                    
                    const targetSocket = tls.connect(targetOptions, () => {
                        let requestData = '';
                        let responseData = '';
                        
                        tlsSocket.on('data', (data) => {
                            const dataStr = data.toString();
                            
                            if (dataStr.includes('HTTP/')) {
                                const lines = dataStr.split('\r\n');
                                const method = lines[0].split(' ')[0];
                                const path = lines[0].split(' ')[1];
                                
                                const headers = {};
                                let headerEnd = false;
                                let body = '';
                                
                                for (let i = 1; i < lines.length; i++) {
                                    if (lines[i] === '') {
                                        headerEnd = true;
                                        body = lines.slice(i + 1).join('\r\n');
                                        break;
                                    }
                                    const [key, value] = lines[i].split(': ');
                                    if (key && value) {
                                        headers[key.toLowerCase()] = value;
                                    }
                                }
                                
                                const mockReq = {
                                    headers: headers,
                                    method: method,
                                    url: `https://${hostname}${path}`,
                                    body: body
                                };
                                
                                const tokens = extractJWTTokens(mockReq, body);
                                if (tokens.length > 0) {
                                    tokens.forEach(tokenData => {
                                        if (mainWindow && !mainWindow.isDestroyed()) {
                                            mainWindow.webContents.send('jwt-token-captured', tokenData);
                                        }
                                    });
                                }
                            }
                            
                            targetSocket.write(data);
                        });
                        
                        targetSocket.on('data', (data) => {
                            const dataStr = data.toString();
                            
                            if (dataStr.includes('HTTP/')) {
                                const lines = dataStr.split('\r\n');
                                const headers = {};
                                let headerEnd = false;
                                let body = '';
                                
                                for (let i = 1; i < lines.length; i++) {
                                    if (lines[i] === '') {
                                        headerEnd = true;
                                        body = lines.slice(i + 1).join('\r\n');
                                        break;
                                    }
                                    const [key, value] = lines[i].split(': ');
                                    if (key && value) {
                                        headers[key.toLowerCase()] = value;
                                    }
                                }
                                
                                const mockRes = {
                                    headers: headers,
                                    req: {
                                        method: 'UNKNOWN',
                                        path: '/'
                                    }
                                };
                                
                                const tokens = extractJWTTokensFromResponse(mockRes, body);
                                if (tokens.length > 0) {
                                    tokens.forEach(tokenData => {
                                        if (mainWindow && !mainWindow.isDestroyed()) {
                                            mainWindow.webContents.send('jwt-token-captured', tokenData);
                                        }
                                    });
                                }
                            }
                            
                            tlsSocket.write(data);
                        });
                        
                        tlsSocket.on('end', () => targetSocket.end());
                        targetSocket.on('end', () => tlsSocket.end());
                        tlsSocket.on('error', () => targetSocket.destroy());
                        targetSocket.on('error', () => tlsSocket.destroy());
                    });
                });
                
                tlsSocket.on('error', (err) => {
                    clientSocket.destroy();
                });
            });
        }

        return new Promise((resolve, reject) => {
            proxyServer.listen(port, '127.0.0.1', () => {
                resolve({ success: true, port });
            });
            
            proxyServer.on('error', (err) => {
                proxyServer = null;
                if (err.code === 'EADDRINUSE') {
                    resolve({ success: false, error: `Port ${port} is already in use` });
                } else {
                    resolve({ success: false, error: err.message });
                }
            });
        });
        
    } catch (error) {
        proxyServer = null;
        return { success: false, error: error.message };
    }
});

ipcMain.handle('stop-proxy', async () => {
    if (!proxyServer) {
        return { success: false, error: 'No proxy server running' };
    }

    try {
        return new Promise((resolve) => {
            proxyServer.close(() => {
                proxyServer = null;
                resolve({ success: true });
            });
            
            setTimeout(() => {
                if (proxyServer) {
                    proxyServer = null;
                    resolve({ success: true });
                }
            }, 5000);
        });
    } catch (error) {
        proxyServer = null;
        return { success: false, error: error.message };
    }
});

function extractJWTTokens(req, body) {
    const tokens = [];
    const jwtRegex = /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g;
    
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const bearerMatch = authHeader.match(/Bearer\s+(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*)/);
        if (bearerMatch) {
            tokens.push({
                token: bearerMatch[1],
                source: 'Authorization Header',
                url: `${req.method} ${req.url}`,
                timestamp: Date.now()
            });
        }
    }
    
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        const cookieMatches = cookieHeader.match(jwtRegex);
        if (cookieMatches) {
            cookieMatches.forEach(token => {
                tokens.push({
                    token,
                    source: 'Cookie',
                    url: `${req.method} ${req.url}`,
                    timestamp: Date.now()
                });
            });
        }
    }
    
    if (body) {
        const bodyMatches = body.match(jwtRegex);
        if (bodyMatches) {
            bodyMatches.forEach(token => {
                tokens.push({
                    token,
                    source: 'Request Body',
                    url: `${req.method} ${req.url}`,
                    timestamp: Date.now()
                });
            });
        }
    }
    
    Object.keys(req.headers).forEach(headerName => {
        if (headerName.toLowerCase().includes('token') || headerName.toLowerCase().includes('jwt')) {
            const headerValue = req.headers[headerName];
            const headerMatches = headerValue.match(jwtRegex);
            if (headerMatches) {
                headerMatches.forEach(token => {
                    tokens.push({
                        token,
                        source: `Header: ${headerName}`,
                        url: `${req.method} ${req.url}`,
                        timestamp: Date.now()
                    });
                });
            }
        }
    });
    
    return tokens;
}

function extractJWTTokensFromResponse(res, body) {
    const tokens = [];
    const jwtRegex = /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g;
    
    Object.keys(res.headers).forEach(headerName => {
        const headerValue = res.headers[headerName];
        if (typeof headerValue === 'string') {
            const headerMatches = headerValue.match(jwtRegex);
            if (headerMatches) {
                headerMatches.forEach(token => {
                    tokens.push({
                        token,
                        source: `Response Header: ${headerName}`,
                        url: res.req ? `${res.req.method} ${res.req.path}` : 'Unknown',
                        timestamp: Date.now()
                    });
                });
            }
        }
    });
    
    if (res.headers['set-cookie']) {
        const cookies = Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [res.headers['set-cookie']];
        cookies.forEach(cookie => {
            const cookieMatches = cookie.match(jwtRegex);
            if (cookieMatches) {
                cookieMatches.forEach(token => {
                    tokens.push({
                        token,
                        source: 'Set-Cookie Header',
                        url: res.req ? `${res.req.method} ${res.req.path}` : 'Unknown',
                        timestamp: Date.now()
                    });
                });
            }
        });
    }
    
    if (body) {
        const bodyMatches = body.match(jwtRegex);
        if (bodyMatches) {
            bodyMatches.forEach(token => {
                tokens.push({
                    token,
                    source: 'Response Body',
                    url: res.req ? `${res.req.method} ${res.req.path}` : 'Unknown',
                    timestamp: Date.now()
                });
            });
        }
    }
    
    return tokens;
}

function streamify(text) {
    const stream = new Readable();
    stream.push(text);
    stream.push(null);
    return stream;
}

ipcMain.handle('get-proxy-status', async () => {
    return {
        success: true,
        running: proxyServer !== null,
        port: proxyServer ? proxyServer.address()?.port : null
    };
});

ipcMain.handle('export-ca-certificate', async () => {
    try {
        if (!caCert) {
            const ca = generateRootCA();
            caKey = ca.key;
            caCert = ca.cert;
        }
        
        const certPem = forge.pki.certificateToPem(caCert);
        
        const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
            title: 'Save CA Certificate',
            defaultPath: 'jwt-analyzer-ca.crt',
            filters: [
                { name: 'Certificate Files', extensions: ['crt', 'pem'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        });
        
        if (canceled) {
            return { success: false, canceled: true };
        }
        
        await fs.writeFile(filePath, certPem, 'utf8');
        return { success: true, path: filePath };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

process.on('uncaughtException', (error) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        dialog.showErrorBox('Unexpected Error',
            `An unexpected error occurred: ${error.message}\n\nThe application will continue running, but you may want to restart it.`
        );
    }
});

process.on('unhandledRejection', (reason, promise) => {
});


app.whenReady().then(() => {
    Menu.setApplicationMenu(null);
    createWindow();
    setupAutoUpdater();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', (event) => {
    if (updateDownloaded) {
        event.preventDefault();
        autoUpdater.quitAndInstall();
        return;
    }
    
    if (proxyServer) {
        proxyServer.close();
        proxyServer = null;
    }
    certCache.clear();

    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.removeAllListeners('closed');
    }
});

app.on('web-contents-created', (event, contents) => {
    contents.on('new-window', (event, url) => {
        event.preventDefault();
        shell.openExternal(url);
    });

    contents.on('will-navigate', (event, navigationUrl) => {
        const parsedUrl = new URL(navigationUrl);

        if (parsedUrl.origin !== 'file://') {
            event.preventDefault();
            shell.openExternal(navigationUrl);
        }
    });

    contents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });
});

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
    if (process.env.NODE_ENV === 'development' || process.argv.includes('--dev')) {
        event.preventDefault();
        callback(true);
    } else {
        callback(false);
    }
});

app.setAboutPanelOptions({
    applicationName: 'JWT Security Analyzer',
    applicationVersion: app.getVersion(),
    copyright: 'Copyright © 2025',
    credits: 'Built with Electron for JWT security testing',
    website: 'https://www.bavamont.com'
});

if (process.env.NODE_ENV === 'production') {
    const gotTheLock = app.requestSingleInstanceLock();

    if (!gotTheLock) {
        app.quit();
    } else {
        app.on('second-instance', () => {
            if (mainWindow) {
                if (mainWindow.isMinimized()) mainWindow.restore();
                mainWindow.focus();
            }
        });
    }
}