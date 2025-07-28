const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const crypto = require('crypto');

let mainWindow;
let updateDownloaded = false;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            enableRemoteModule: true
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
        console.log('Checking for update...');
        if (mainWindow) {
            mainWindow.webContents.send('update-checking');
        }
    });

    autoUpdater.on('update-available', (info) => {
        console.log('Update available:', info);
        if (mainWindow) {
            mainWindow.webContents.send('update-available', info);
        }
    });

    autoUpdater.on('update-not-available', (info) => {
        console.log('Update not available:', info);
        if (mainWindow) {
            mainWindow.webContents.send('update-not-available', info);
        }
    });

    autoUpdater.on('error', (err) => {
        console.error('Update error:', err);
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
        console.log('Update downloaded:', info);
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
        console.error('Error checking for updates:', error);
    }
}

// Auto-updater IPC handlers
ipcMain.handle('check-for-updates', async () => {
    try {
        const result = await autoUpdater.checkForUpdates();
        return { success: true, updateInfo: result };
    } catch (error) {
        console.error('Error checking for updates:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('download-update', async () => {
    try {
        await autoUpdater.downloadUpdate();
        return { success: true };
    } catch (error) {
        console.error('Error downloading update:', error);
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
        console.error('Error installing update:', error);
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

// Window control IPC handlers
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

// File system IPC handlers
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
        console.error('Error loading file:', error);
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
        console.error('Error saving file:', error);
        return { success: false, error: error.message };
    }
});

// Wordlist handling
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
        console.error('Error loading wordlist:', error);
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
        console.error('Error saving wordlist:', error);
        return { success: false, error: error.message };
    }
});

// System information
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
        console.error('Error getting system language:', error);
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
        console.error('Error getting system info:', error);
        return { success: false, error: error.message };
    }
});

// Settings management
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
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            application: 'jwt-security-analyzer',
            settings: settings
        };

        await fs.writeFile(savePath, JSON.stringify(settingsData, null, 2), 'utf8');
        return { success: true, path: savePath };
    } catch (error) {
        console.error('Error saving settings:', error);
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
        console.error('Error loading settings:', error);
        return { success: false, error: error.message };
    }
});

// Utility functions
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
        await shell.openExternal(url);
        return { success: true };
    } catch (error) {
        console.error('Error opening external URL:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('generate-secure-token', async (event, length = 32) => {
    try {
        const token = crypto.randomBytes(length).toString('hex');
        return { success: true, token };
    } catch (error) {
        console.error('Error generating secure token:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('hash-string', async (event, input, algorithm = 'sha256') => {
    try {
        const hash = crypto.createHash(algorithm).update(input).digest('hex');
        return { success: true, hash };
    } catch (error) {
        console.error('Error hashing string:', error);
        return { success: false, error: error.message };
    }
});

// Dialog helpers
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
        console.error('Error showing error dialog:', error);
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
        console.error('Error showing info dialog:', error);
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
        console.error('Error showing warning dialog:', error);
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
        console.error('Error showing question dialog:', error);
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

// Error handling
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);

    if (mainWindow && !mainWindow.isDestroyed()) {
        dialog.showErrorBox('Unexpected Error',
            `An unexpected error occurred: ${error.message}\n\nThe application will continue running, but you may want to restart it.`
        );
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// App lifecycle
app.enableSandbox = false;

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

app.on('before-quit', (event) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.removeAllListeners('closed');
    }
});

app.setAboutPanelOptions({
    applicationName: 'JWT Security Analyzer',
    applicationVersion: app.getVersion(),
    copyright: 'Copyright © 2025',
    credits: 'Built with Electron for JWT security testing',
    website: 'https://www.bavamont.com'
});

// Single instance lock
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