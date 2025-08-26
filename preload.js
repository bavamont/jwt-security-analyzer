const { contextBridge, ipcRenderer } = require('electron');

/**
 * Validation utilities embedded in preload script for security
 * @class
 */
class ValidationUtils {
    static isValidJWT(token) {
        if (!token || typeof token !== 'string') return false;
        
        const parts = token.split('.');
        if (parts.length !== 3) return false;
        
        try {
            parts.forEach(part => {
                if (!part) throw new Error('Empty JWT part');
                const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
                atob(base64);
            });
            return true;
        } catch (error) {
            return false;
        }
    }
    
    static sanitizeString(input, maxLength = 10000) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/[<>"'&]/g, '')
            .substring(0, maxLength)
            .trim();
    }
    
    static isValidURL(url) {
        if (!url || typeof url !== 'string') return false;
        
        try {
            const parsed = new URL(url);
            return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (error) {
            return false;
        }
    }
    
    static isValidPort(port) {
        const numPort = parseInt(port, 10);
        return !isNaN(numPort) && numPort >= 1024 && numPort <= 65535;
    }
    
    static isValidAlgorithm(algorithm) {
        const validAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'none'];
        return validAlgorithms.includes(algorithm);
    }
    
    static validateFilePath(filePath) {
        if (!filePath || typeof filePath !== 'string') return false;
        
        const dangerousPatterns = [
            /\.\./,
            /[<>:"|?*]/,
            /^\/dev\//,
            /^\/proc\//,
        ];
        
        return !dangerousPatterns.some(pattern => pattern.test(filePath));
    }
    
    static sanitizeHeaders(headers) {
        if (!headers || typeof headers !== 'object') return {};
        
        const sanitized = {};
        const maxHeaders = 50;
        const maxHeaderLength = 8192;
        
        let count = 0;
        for (const [key, value] of Object.entries(headers)) {
            if (count >= maxHeaders) break;
            
            const sanitizedKey = this.sanitizeString(key, 256);
            const sanitizedValue = this.sanitizeString(value, maxHeaderLength);
            
            if (sanitizedKey && sanitizedValue) {
                sanitized[sanitizedKey] = sanitizedValue;
                count++;
            }
        }
        
        return sanitized;
    }
}

/**
 * Expose secure Electron APIs to the renderer process
 * Provides sandboxed access to system functions through IPC
 */
contextBridge.exposeInMainWorld('electronAPI', {
    windowMinimize: () => ipcRenderer.invoke('window-minimize'),
    windowMaximize: () => ipcRenderer.invoke('window-maximize'),
    windowClose: () => ipcRenderer.invoke('window-close'),
    windowIsMaximized: () => ipcRenderer.invoke('window-is-maximized'),

    loadFile: (filters) => ipcRenderer.invoke('load-file', filters),
    saveFile: (content, defaultPath, filters) => ipcRenderer.invoke('save-file', content, defaultPath, filters),
    loadWordlist: () => ipcRenderer.invoke('load-wordlist'),
    saveWordlist: (wordlist, filename) => ipcRenderer.invoke('save-wordlist', wordlist, filename),

    saveSettings: (settings, filePath) => ipcRenderer.invoke('save-settings', settings, filePath),
    loadSettings: (filePath) => ipcRenderer.invoke('load-settings', filePath),

    getSystemLanguage: () => ipcRenderer.invoke('get-system-language'),
    getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
    getAppVersion: () => ipcRenderer.invoke('get-app-version'),

    showErrorDialog: (title, message, detail) => ipcRenderer.invoke('show-error-dialog', title, message, detail),
    showInfoDialog: (title, message, detail) => ipcRenderer.invoke('show-info-dialog', title, message, detail),
    showWarningDialog: (title, message, buttons) => ipcRenderer.invoke('show-warning-dialog', title, message, buttons),
    showQuestionDialog: (title, message, buttons) => ipcRenderer.invoke('show-question-dialog', title, message, buttons),

    checkPathExists: (filePath) => ipcRenderer.invoke('check-path-exists', filePath),
    openExternal: (url) => ipcRenderer.invoke('open-external', url),
    generateSecureToken: (length) => ipcRenderer.invoke('generate-secure-token', length),
    hashString: (input, algorithm) => ipcRenderer.invoke('hash-string', input, algorithm),

    checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
    downloadUpdate: () => ipcRenderer.invoke('download-update'),
    installUpdate: () => ipcRenderer.invoke('install-update'),
    getUpdateInfo: () => ipcRenderer.invoke('get-update-info'),

    startProxy: (config) => ipcRenderer.invoke('start-proxy', config),
    stopProxy: () => ipcRenderer.invoke('stop-proxy'),
    getProxyStatus: () => ipcRenderer.invoke('get-proxy-status'),
    exportCACertificate: () => ipcRenderer.invoke('export-ca-certificate'),

    onUpdateChecking: (callback) => ipcRenderer.on('update-checking', callback),
    onUpdateAvailable: (callback) => ipcRenderer.on('update-available', callback),
    onUpdateNotAvailable: (callback) => ipcRenderer.on('update-not-available', callback),
    onUpdateDownloadProgress: (callback) => ipcRenderer.on('update-download-progress', callback),
    onUpdateDownloaded: (callback) => ipcRenderer.on('update-downloaded', callback),
    onUpdateError: (callback) => ipcRenderer.on('update-error', callback),
    onJwtTokenCaptured: (callback) => ipcRenderer.on('jwt-token-captured', callback),

    removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});

/**
 * Expose validation utilities to the renderer process
 * Provides secure input validation functions
 */
contextBridge.exposeInMainWorld('validation', {
    isValidJWT: ValidationUtils.isValidJWT,
    sanitizeString: ValidationUtils.sanitizeString,
    isValidURL: ValidationUtils.isValidURL,
    isValidPort: ValidationUtils.isValidPort,
    isValidAlgorithm: ValidationUtils.isValidAlgorithm,
    validateFilePath: ValidationUtils.validateFilePath,
    sanitizeHeaders: ValidationUtils.sanitizeHeaders
});

