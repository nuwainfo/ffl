/*!
 * FastFileLink - Download Manager
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Common download functionality including progress tracking, retry logic, and Service Worker integration
 *
 * See LICENSE file in the project root for full license information.
 */

// Independent log function - works with or without global log (using unique name to avoid conflicts)
const dmLog = (typeof window !== 'undefined' && typeof window.log === 'function') ? window.log : function(category, message, ...args) {
    if (typeof console !== 'undefined' && console.log) {
        const timestamp = new Date().toISOString();
        const prefix = `[${timestamp}] [${category}]`;
        if (args.length > 0) {
            console.log(`${prefix} ${message}`, ...args);
        } else {
            console.log(`${prefix} ${message}`);
        }
    }
};

// Independent translation function - works with or without global t function
const dmT = (typeof window !== 'undefined' && typeof window.t === 'function') ? window.t : function(key, defaultValue, options = {}) {
    // Dummy function that supports basic interpolation
    if (typeof defaultValue === 'string') {
        return defaultValue.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            return options[key] || match;
        });
    }
    return defaultValue || key;
};

/**
 * AuthGateRegistry — collects auth gates (pickup code, pubkey, E2EE key, …) and runs them
 * in sequence before invoking onUnlockedCallback. Decoupled from DownloadManager so that
 * DownloadManager can be constructed at the right moment with correct, final values.
 *
 * Each gate: { validate() → null|string, apply() → void, focus?() → void }
 */
class AuthGateRegistry {
    constructor(options = {}) {
        this.gates = [];
        this.unlockBtnId = options.unlockBtnId || 'unlock-btn';
        this.onUnlockedCallback = options.onUnlockedCallback || null;
        this.authEndpoint = options.authEndpoint || null;
        this.authErrorMsgId = options.authErrorMsgId || null;
        this.gateContainerId = options.gateContainerId || 'authGateContainer';
        this.downloadBlockId = options.downloadBlockId || 'downloadBlock';

        const btn = document.getElementById(this.unlockBtnId);
        if (btn) {
            btn.addEventListener('click', () => this.unlock());
        }
        for (const inputId of (options.inputIds || [])) {
            const input = document.getElementById(inputId);
            if (input) {
                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        this.unlock();
                    }
                });
            }
        }
    }

    registerGate(gate) {
        if (this.gates.length === 0) {
            document.getElementById(this.gateContainerId)?.style.setProperty('display', 'block');
            document.getElementById(this.downloadBlockId)?.style.setProperty('display', 'none');
        }
        this.gates.push(gate);
        gate.show?.();
    }

    async unlock() {
        const btn = document.getElementById(this.unlockBtnId);
        let originalContent = null;
        if (btn) {
            btn.disabled = true;
            originalContent = btn.innerHTML;
            const spinnerHtml = '<span class="auth-gate-spinner"></span>';
            const label = dmT('Download:auth.verifying', 'Verifying…');
            btn.innerHTML = `${spinnerHtml}<span>${label}</span>`;
        }
        try {
            for (const gate of this.gates) {
                const error = await gate.validate();
                if (error !== null) {
                    gate.focus?.();
                    return;
                }
            }
            for (const gate of this.gates) {
                try {
                    await gate.apply();
                } catch {
                    return;
                }
            }
            if (this.authEndpoint) {
                const headers = {};
                for (const gate of this.gates) {
                    Object.assign(headers, gate.authHeaders ?? {});
                }
                const response = await fetch(this.authEndpoint, { method: 'POST', headers });
                if (!response.ok) {
                    const errorMsg = this.authErrorMsgId ? document.getElementById(this.authErrorMsgId) : null;
                    if (errorMsg) {
                        const msg = response.status === 429
                            ? dmT('Download:auth.rateLimited', 'Too many failed attempts. Please try again in 5 minutes.')
                            : dmT('Download:auth.failed', 'Authentication failed. Please try again.');
                        errorMsg.textContent = msg;
                        errorMsg.style.display = 'block';
                    }
                    return;
                }
            }
            if (this.gateContainerId) {
                document.getElementById(this.gateContainerId)?.style.setProperty('display', 'none');
            }
            if (this.downloadBlockId) {
                document.getElementById(this.downloadBlockId)?.style.setProperty('display', 'block');
            }
            await this.onUnlockedCallback?.();
        } finally {
            if (btn) {
                btn.disabled = false;
                if (originalContent !== null) {
                    btn.innerHTML = originalContent;
                }
            }
        }
    }
}

/**
 * PickupCodeGate — auth gate for 6-digit pickup code.
 * Implements the { validate(), apply(), focus() } interface for AuthGateRegistry.
 *
 * options:
 *   codeInputId    — id of the code <input>  (default: 'pickup-code-input')
 *   errorMsgId     — id of the error element (default: 'pickup-error-message')
 *   verifyEndpoint — string; when provided, verifies the code server-side before accepting it.
 *                    GET: appends ?verify=code to the URL (e.g. Caddy file_server).
 *                    POST: sends { verify: 'code' } in the JSON body (e.g. P2P Python server).
 *   verifyMethod   — 'GET' or 'POST' (default 'POST')
 *   onAccepted     — callback(code: string) invoked after the gate passes
 *   t              — translation function (key, defaultValue) → string
 */
class PickupCodeGate {
    constructor(options = {}) {
        this.codeInputId    = options.codeInputId    || 'pickup-code-input';
        this.errorMsgId     = options.errorMsgId     || 'pickup-error-message';
        this.containerId    = options.containerId    || null;
        this.verifyEndpoint = options.verifyEndpoint || null;
        this.verifyMethod   = options.verifyMethod   || 'POST';
        this.onAccepted     = options.onAccepted     || null;
        this.t              = options.t              || dmT;
        this._code          = null;
    }

    get authHeaders() {
        return this._code ? { [PickupCodeGate.HEADER]: this._code } : {};
    }

    show() {
        if (this.containerId) {
            document.getElementById(this.containerId)?.style.setProperty('display', 'block');
        }
    }

    validate() {
        const code     = document.getElementById(this.codeInputId).value.trim();
        const errorMsg = document.getElementById(this.errorMsgId);
        if (!/^\d{6}$/.test(code)) {
            errorMsg.textContent = this.t('Download:pickup.invalidCode', 'Please enter a valid 6-digit numeric code.');
            errorMsg.style.display = 'block';
            return 'invalid-code';
        }
        errorMsg.style.display = 'none';
        return null;
    }

    async apply() {
        const code     = document.getElementById(this.codeInputId).value.trim();
        const errorMsg = document.getElementById(this.errorMsgId);
        if (this.verifyEndpoint) {
            let url = this.verifyEndpoint;
            const fetchOptions = { method: this.verifyMethod, headers: { [PickupCodeGate.HEADER]: code } };
            if (this.verifyMethod === 'GET') {
                url += (url.includes('?') ? '&' : '?') + 'verify=code';
            } else {
                fetchOptions.headers['Content-Type'] = 'application/json';
                fetchOptions.body = JSON.stringify({ verify: 'code' });
            }
            const response = await fetch(url, fetchOptions);
            if (response.status === 429) {
                errorMsg.textContent = this.t('Download:auth.rateLimited', 'Too many failed attempts. Please try again in 5 minutes.');
                errorMsg.style.display = 'block';
                throw new Error('Rate limited');
            }
            if (!response.ok) {
                errorMsg.textContent = this.t('Download:pickup.wrongCode', 'Invalid pickup code. Please check and try again.');
                errorMsg.style.display = 'block';
                throw new Error('Invalid pickup code');
            }
            errorMsg.style.display = 'none';
        }
        this._code = code;
        this.onAccepted?.(code);
    }

    focus() {
        document.getElementById(this.codeInputId).focus();
    }
}
PickupCodeGate.HEADER = 'X-FFL-Pickup';

/**
 * PubkeyGate — RSA-OAEP challenge-response authentication gate.
 *
 * Options:
 *   fileInputId    — id of the <input type="file"> element (default 'pubkey-file-input')
 *   fileLabelId    — id of the label/span element showing file name (default 'pubkey-file-label')
 *   errorMsgId     — id of error <p> element (default 'pubkey-error-message')
 *   containerId    — id of gate wrapper div (shown by show())
 *   challenge      — base64-encoded RSA-OAEP ciphertext (server-generated)
 *   verifyEndpoint — URL to verify the proof (optional).
 *                    GET: appends ?verify=proof (e.g. Caddy file_server auth endpoint).
 *                    POST: sends { verify: 'proof' } in JSON body (e.g. P2P Python server).
 *   verifyMethod   — 'GET' or 'POST' (default 'POST')
 *   onAccepted     — callback(proof: string) invoked after the gate passes
 *   t              — translation function (key, defaultValue) → string
 */
class PubkeyGate {
    constructor(options = {}) {
        this.fileInputId    = options.fileInputId  || 'pubkey-file-input';
        this.fileLabelId    = options.fileLabelId  || 'pubkey-file-label';
        this.errorMsgId     = options.errorMsgId   || 'pubkey-error-message';
        this.containerId    = options.containerId  || null;
        this.challenge      = options.challenge;
        this.verifyEndpoint = options.verifyEndpoint || null;
        this.verifyMethod   = options.verifyMethod || 'POST';
        this.onAccepted     = options.onAccepted   || null;
        this.t              = options.t            || dmT;
        this._proof         = null;

        // Update label text when the user picks a file
        const fileInput = document.getElementById(this.fileInputId);
        const fileLabel = document.getElementById(this.fileLabelId);
        if (fileInput && fileLabel) {
            fileInput.addEventListener('change', () => {
                fileLabel.textContent = fileInput.files[0]
                    ? `✓ ${fileInput.files[0].name}`
                    : this.t('Download:pubkey.selectFile', '📁 Select .fflkey file');
            });
        }
    }

    get authHeaders() {
        return this._proof ? { [PubkeyGate.HEADER]: this._proof } : {};
    }

    show() {
        if (this.containerId) {
            document.getElementById(this.containerId)?.style.setProperty('display', 'block');
        }
    }

    validate() {
        const err = document.getElementById(this.errorMsgId);
        if (!document.getElementById(this.fileInputId).files[0]) {
            err.textContent = this.t('Download:pubkey.noFile', 'Please select your .fflkey private key file.');
            err.style.display = 'block';
            return 'no-file';
        }
        err.style.display = 'none';
        return null;
    }

    async apply() {
        const err  = document.getElementById(this.errorMsgId);
        const file = document.getElementById(this.fileInputId).files[0];
        let privKeyPem;
        try {
            privKeyPem = await file.text();
        } catch (e) {
            err.textContent = this.t('Download:pubkey.readError', 'Failed to read key file.');
            err.style.display = 'block';
            throw e;
        }
        if (!privKeyPem.includes('PRIVATE KEY')) {
            err.textContent = this.t('Download:pubkey.invalidPem', 'Invalid key file — expected a PKCS#8 private key (.fflkey).');
            err.style.display = 'block';
            throw new Error('invalid-pem');
        }
        const b64 = privKeyPem
            .replace(/-----BEGIN PRIVATE KEY-----/, '')
            .replace(/-----END PRIVATE KEY-----/, '')
            .replace(/\s+/g, '');
        let der;
        try {
            der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        } catch (e) {
            err.textContent = this.t('Download:pubkey.base64Error', 'Invalid key file (base64 decode failed).');
            err.style.display = 'block';
            throw e;
        }
        let privateKey;
        try {
            privateKey = await crypto.subtle.importKey(
                'pkcs8', der.buffer,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false, ['decrypt']
            );
        } catch (e) {
            err.textContent = this.t('Download:pubkey.invalidFormat', 'Invalid private key — wrong format or not an RSA-OAEP key.');
            err.style.display = 'block';
            throw e;
        }
        const ciphertextBytes = Uint8Array.from(atob(this.challenge), c => c.charCodeAt(0));
        let plaintext;
        try {
            plaintext = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' }, privateKey, ciphertextBytes.buffer
            );
        } catch (e) {
            err.textContent = this.t('Download:pubkey.decryptError', 'Decryption failed — wrong private key.');
            err.style.display = 'block';
            throw e;
        }
        const proof = btoa(String.fromCharCode(...new Uint8Array(plaintext)));
        if (this.verifyEndpoint) {
            let url = this.verifyEndpoint;
            const fetchOptions = { method: this.verifyMethod, headers: { [PubkeyGate.HEADER]: proof } };
            if (this.verifyMethod === 'GET') {
                url += (url.includes('?') ? '&' : '?') + 'verify=proof';
            } else {
                fetchOptions.headers['Content-Type'] = 'application/json';
                fetchOptions.body = JSON.stringify({ verify: 'proof' });
            }
            const authResp = await fetch(url, fetchOptions);
            if (authResp.status === 429) {
                err.textContent = this.t('Download:auth.rateLimited', 'Too many failed attempts. Please try again in 5 minutes.');
                err.style.display = 'block';
                throw new Error('Rate limited');
            }
            if (!authResp.ok) {
                err.textContent = this.t('Download:pubkey.authFailed', 'Authentication failed — check your key.');
                err.style.display = 'block';
                throw new Error('Auth failed');
            }
        }
        err.style.display = 'none';
        this._proof = proof;
        this.onAccepted?.(proof);
    }

    focus() {
        document.getElementById(this.fileInputId).click();
    }
}
PubkeyGate.HEADER = 'X-FFL-Proof';

/**
 * EmailGate — email OTP authentication gate.
 *
 * Flow:
 *   1. show() displays the gate and the recipient email address.
 *   2. User clicks "Send Code" → _sendCode() POSTs to otpRequestUrl with {email, link}.
 *   3. OTP input section appears after successful send.
 *   4. User enters 6-digit OTP and clicks the main unlock button.
 *   5. validate() checks the format; apply() stores the OTP.
 *   6. authHeaders carries X-FFL-EmailOTP / X-FFL-EmailAddress / X-FFL-EmailLink
 *      to the auth endpoint (P2P: POST /{uid}/auth → Python server calls FFL API).
 *
 * Options:
 *   containerId       — id of the gate wrapper div
 *   sendBtnId         — id of the "Send Code" button (default: 'email-send-btn')
 *   otpSectionId      — id of the OTP input section shown after send (default: 'email-otp-section')
 *   otpInputId        — id of the OTP <input> (default: 'email-otp-input')
 *   emailDisplayId    — id of the element showing the recipient email (default: 'email-address-display')
 *   statusMsgId       — id of the success/info message element (default: 'email-status-message')
 *   errorMsgId        — id of error <p> (default: 'email-error-message')
 *   recipientEmail    — pre-configured recipient email address
 *   otpRequestUrl     — full URL for POST {email, link} to trigger OTP send
 *   shareLink         — the share link used as the OTP binding key (window.location.href)
 *   onAccepted        — callback(otp: string) invoked after gate passes
 *   t                 — translation function
 */
class EmailGate {
    constructor(options = {}) {
        this.containerId    = options.containerId    || null;
        this.sendBtnId      = options.sendBtnId      || 'email-send-btn';
        this.otpSectionId   = options.otpSectionId   || 'email-otp-section';
        this.otpInputId     = options.otpInputId     || 'email-otp-input';
        this.emailDisplayId = options.emailDisplayId || 'email-address-display';
        this.statusMsgId    = options.statusMsgId    || 'email-status-message';
        this.errorMsgId     = options.errorMsgId     || 'email-error-message';
        this.recipientEmail = options.recipientEmail || '';
        this.otpRequestUrl  = options.otpRequestUrl  || null;
        this.verifyEndpoint = options.verifyEndpoint || null;
        this.shareLink      = options.shareLink      || window.location.href;
        this.onAccepted     = options.onAccepted     || null;
        this.t              = options.t              || dmT;
        this._otp           = null;
        this._codeSent      = false;

        const sendBtn = document.getElementById(this.sendBtnId);
        if (sendBtn) {
            sendBtn.addEventListener('click', () => this._sendCode());
        }
    }

    get authHeaders() {
        return this._otp ? {
            [EmailGate.HEADER_OTP]:     this._otp,
            [EmailGate.HEADER_ADDRESS]: this.recipientEmail,
            [EmailGate.HEADER_LINK]:    this.shareLink,
        } : {};
    }

    show() {
        if (this.containerId) {
            document.getElementById(this.containerId)?.style.setProperty('display', 'block');
        }
        const emailDisplay = document.getElementById(this.emailDisplayId);
        if (emailDisplay && this.recipientEmail) {
            emailDisplay.textContent = this.recipientEmail;
        }
    }

    validate() {
        const errorMsg = document.getElementById(this.errorMsgId);
        if (!this._codeSent) {
            errorMsg.textContent = this.t('Download:email.sendFirst', 'Please request a verification code first.');
            errorMsg.style.display = 'block';
            return 'no-code-sent';
        }
        const otp = document.getElementById(this.otpInputId)?.value.trim();
        if (!/^\d{6}$/.test(otp)) {
            errorMsg.textContent = this.t('Download:email.invalidCode', 'Please enter the 6-digit code from your email.');
            errorMsg.style.display = 'block';
            return 'invalid-code';
        }
        errorMsg.style.display = 'none';
        return null;
    }

    async apply() {
        this._otp = document.getElementById(this.otpInputId)?.value.trim();
        if (this.verifyEndpoint) {
            const response = await fetch(this.verifyEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: this.recipientEmail, link: this.shareLink, otp: this._otp }),
            });
            const errorMsg = document.getElementById(this.errorMsgId);
            if (response.status === 429) {
                if (errorMsg) {
                    errorMsg.textContent = this.t('Download:auth.rateLimited', 'Too many failed attempts. Please try again in 5 minutes.');
                    errorMsg.style.display = 'block';
                }
                throw new Error('Rate limited');
            }
            if (!response.ok) {
                if (errorMsg) {
                    errorMsg.textContent = this.t('Download:auth.failed', 'Authentication failed. Please try again.');
                    errorMsg.style.display = 'block';
                }
                throw new Error('OTP verification failed');
            }
        }
        this.onAccepted?.(this._otp);
    }

    focus() {
        document.getElementById(this.otpInputId)?.focus();
    }

    async _sendCode() {
        const errorMsg  = document.getElementById(this.errorMsgId);
        const statusMsg = document.getElementById(this.statusMsgId);
        const sendBtn   = document.getElementById(this.sendBtnId);
        const originalContent = sendBtn.innerHTML;
        sendBtn.disabled = true;
        sendBtn.innerHTML = `<span class="auth-gate-spinner" style="border-color:rgba(255,255,255,0.4);border-top-color:white;"></span><span>${this.t('Download:email.sending', 'Sending…')}</span>`;
        try {
            const resp = await fetch(this.otpRequestUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: this.recipientEmail, link: this.shareLink }),
            });
            if (resp.ok) {
                sendBtn.innerHTML = originalContent;
                document.getElementById(this.otpSectionId)?.style.setProperty('display', 'block');
                this._codeSent = true;
                if (statusMsg) {
                    statusMsg.textContent = this.t('Download:email.codeSent', 'Code sent! Please check your email.');
                    statusMsg.style.display = 'block';
                }
                if (errorMsg) errorMsg.style.display = 'none';
            } else {
                const data = await resp.json().catch(() => ({}));
                if (errorMsg) {
                    errorMsg.textContent = data.error || this.t('Download:email.sendFailed', 'Failed to send code. Please try again.');
                    errorMsg.style.display = 'block';
                }
                sendBtn.innerHTML = originalContent;
                sendBtn.disabled = false;
            }
        } catch (_e) {
            if (errorMsg) {
                errorMsg.textContent = this.t('Download:email.sendError', 'Network error. Please try again.');
                errorMsg.style.display = 'block';
            }
            sendBtn.innerHTML = originalContent;
            sendBtn.disabled = false;
        }
    }
}
EmailGate.HEADER_OTP     = 'X-FFL-EmailOTP';
EmailGate.HEADER_ADDRESS = 'X-FFL-EmailAddress';
EmailGate.HEADER_LINK    = 'X-FFL-EmailLink';

class DownloadManager {
    constructor(options = {}) {
        // Configuration
        this.DEBUG = options.debug !== undefined ? options.debug : true;
        this.uid = options.uid || this.extractUidFromPath();
        this.isFirefox = navigator.userAgent.includes('Firefox');
        
        // Firefox hybrid strategy configuration
        this.FF_SW_LIMIT = options.ffSwLimit || 512 * 1024 * 1024; // 512MB default threshold
        
        // Service Worker configuration
        this.serviceWorkerPath = options.serviceWorkerPath || '/static/js/ProgressServiceWorker.js';
        this.serviceWorkerScope = options.serviceWorkerScope || '/';
        
        // UI Elements (assigned once, used consistently)
        this.progressBar = options.progressBar || '#progress-bar';
        this.statusHeading = options.statusHeading || '#status-heading';
        this.statusDetails = options.statusDetails || '#status-details';
        this.progressInfo = options.progressInfo || '#progress-info';
        this.retryLink = options.retryLink || '#retry-link';
        this.completeStatusHeading = options.completeStatusHeading || null;
        this.downloadLink = options.downloadLink || '#download-link';
        this.filenameInput = options.filenameInput || '#filename';
        
        // Configurable timing options
        this.stallTimeoutMs = options.stallTimeoutMs || 60000; // 60 seconds for pass-through mode monitoring
        this.stallCheckInterval = options.stallCheckInterval || 5000; // 5 seconds 
        this.stallCheckIntervalBackground = options.stallCheckIntervalBackground || 30000; // 30 seconds when hidden
        this.stallThreshold = options.stallThreshold || 3; // n checks
        
        // ServiceWorker progress reporting configuration
        this.swReportEveryBytes = options.swReportEveryBytes || 5 * 1024 * 1024; // 5MB default
        this.swReportEveryMs = options.swReportEveryMs || 250; // 250ms default

        // E2E encryption configuration
        this.e2eeEnabled = options.e2eeEnabled || false;
        this.httpDecryptor = null;

        // Auth headers (e.g. X-FFL-Pickup for pickup code auth)
        this.authHeaders = options.authHeaders || null;

        // State tracking
        this.downloadStarted = false;
        this.adaptiveUnlockTimer = null;
        this.totalBytesHint = 0;
        this.startTime = null; // Will be set when download actually starts
        this.activeDlId = null;
        this.downloadTriggeredOnce = false;
        this.progressMonitorTimer = null;
        this.lastProgressValue = 0;
        this.lastProgressTime = 0;
        this.stallCheckCount = 0;
        this.skipDownloadDueToRestriction = false;
        this.newTabOpened = false; // Flag to prevent retry after new tab
        this.currentCheckInterval = this.stallCheckInterval; // Current active interval
        this.isTabHidden = document.hidden || false; // Track visibility state
        this.checksumVerified = false;
        this.pendingChecksumResult = null;

        // Server-assigned download ID for POST /complete ACK (relay truncation fix)
        this.serverDownloadId = null;

        // Resume support state
        this.resumeConfig = null;
        
        // Configurable adaptive unlock delay options
        this.ADAPTIVE_DELAY_CONFIG = options.adaptiveDelayConfig || {
            LARGE_FILE_THRESHOLD: 1024 * 1024 * 1024,   // 1GB
            MEDIUM_FILE_THRESHOLD: 100 * 1024 * 1024,   // 100MB
            LARGE_FILE_DELAY: 15000,   // 15 seconds for >=1GB files, not too long because retry style is subtle.
            MEDIUM_FILE_DELAY: 10000,  // 10 seconds for 100MB-1GB files
            DEFAULT_DELAY: 5000       // 5 seconds for smaller/unknown files
        };
        
        // Configurable delay calculation function
        this.calculateDelayMs = options.calculateDelayMs || this.defaultCalculateDelayMs.bind(this);

        // Callback functions for external integration
        this.onServiceWorkerReadyCallback = options.onServiceWorkerReadyCallback || null;
        this.onDownloadStartCallback = options.onDownloadStartCallback || null;
        this.onDownloadCompleteCallback = options.onDownloadCompleteCallback || null;
        this.onDownloadErrorCallback = options.onDownloadErrorCallback || null;

        // Custom log function (if provided, use it; otherwise use default dmLog)
        this.customLogFn = options.logFunction || null;

        // BroadcastChannel for SW progress updates
        this.dlChannel = ('BroadcastChannel' in window) ? new BroadcastChannel('dl-progress') : null;

        // Bind methods
        this.log = this.log.bind(this);
        this.t = this.t.bind(this);
        this.formatBytes = this.formatBytes.bind(this);
        this.calculateSpeed = this.calculateSpeed.bind(this);
        
        // Initialize
        this.setupBroadcastChannel();
        this.setupVisibilityChangeHandler();
    }
    
    extractUidFromPath() {
        const path = window.location.pathname;
        const match = path.match(/\/([^\/]+)\//);
        return match ? match[1] : 'unknown';
    }
    
    log(category, message, ...args) {
        if (this.DEBUG) {
            if (this.customLogFn) {
                this.customLogFn(category, message, ...args);
            } else {
                dmLog(category, message, ...args);
            }
        }
    }
    
    t(key, defaultValue, options = {}) {
        return dmT(key, defaultValue, options);
    }

    // ============ Size Utility Functions ============

    /**
     * Check if size represents unknown/indeterminate size
     * @param {number} size - File size to check
     * @returns {boolean} True if size is unknown (-1, null, undefined, or ≤0)
     */
    isUnknownSize(size) {
        return size == null || size <= 0;
    }

    /**
     * Check if size is valid and known
     * @param {number} size - File size to check
     * @returns {boolean} True if size is a positive number
     */
    isValidSize(size) {
        return typeof size === 'number' && size > 0;
    }

    /**
     * Check if we should show determinate (percentage-based) progress
     * @param {number} size - File size
     * @param {string} mode - Download mode ('sw' or 'pass')
     * @returns {boolean} True if we can show percentage progress
     */
    shouldShowDeterminateProgress(size, mode) {
        // Unknown size → always indeterminate
        if (this.isUnknownSize(size)) {
            return false;
        }

        // Pass-through mode → indeterminate (browser handles download)
        if (mode === 'pass') {
            return false;
        }

        // SW mode with known size → determinate
        return true;
    }

    /**
     * Get the planned download mode based on browser and file size
     * @param {Object} options - Options object with uid and filename
     * @returns {Object} Plan object with browser, size, and mode
     */
    getPlannedMode({ uid, filename } = {}) {
        // Get file size from hidden metadata elements
        let size = 0;
        const fileSizeElement = document.getElementById('fileSize');
        if (fileSizeElement) {
            const sizeText = fileSizeElement.textContent || fileSizeElement.innerText || '0';
            size = parseInt(sizeText.trim(), 10);
            if (isNaN(size)) {
                size = 0;
            }
        }

        const sizeDesc = this.isUnknownSize(size) ? 'unknown' : this.formatBytes(size);
        this.log('DownloadManager', `File size detected from metadata: ${size} bytes (${sizeDesc})`);

        // Decision logic (unified)
        if (!this.isFirefox) {
            // Chromium: Always use SW + Transform (handles unknown size via indeterminate progress)
            return { browser: 'chromium', size, mode: 'sw' };
        }

        // Firefox: Use SW for small files, pass-through for large/unknown
        if (this.isValidSize(size) && size <= this.FF_SW_LIMIT) {
            return { browser: 'firefox', size, mode: 'sw' };
        }

        // Firefox large/unknown: pass-through (browser handles download directly)
        return { browser: 'firefox', size, mode: 'pass' };
    }
    
    parsePositiveNumber(value) {
        const num = Number(value);
        return Number.isFinite(num) && num >= 0 ? num : null;
    }

    normalizeResumeOptions(resume) {
        if (!resume || typeof resume !== 'object') {
            return null;
        }

        const baseBytes = this.parsePositiveNumber(resume.baseBytes);
        if (baseBytes === null || baseBytes <= 0) {
            return null;
        }

        const expectedSize = this.parsePositiveNumber(resume.expectedSize);
        const rangeStartRaw = this.parsePositiveNumber(resume.rangeStart);
        const chunkSize = this.parsePositiveNumber(resume.chunkSize);
        const skipBytesRaw = this.parsePositiveNumber(resume.skipBytes);

        const rangeStart = rangeStartRaw !== null ? Math.min(rangeStartRaw, baseBytes) : baseBytes;
        const normalizedSkip = skipBytesRaw !== null ? Math.min(skipBytesRaw, baseBytes - rangeStart) : Math.max(0, baseBytes - rangeStart);
        const normalizedExpected = expectedSize !== null ? expectedSize : 0;

        if (normalizedExpected && rangeStart >= normalizedExpected) {
            return null;
        }

        return {
            baseBytes,
            rangeStart,
            skipBytes: normalizedSkip,
            expectedSize: normalizedExpected,
            chunkSize: (chunkSize !== null && chunkSize > 0) ? chunkSize : null
        };
    }

    setResumeConfig(resumeOptions) {
        const normalized = this.normalizeResumeOptions(resumeOptions);
        this.resumeConfig = normalized;
        return normalized;
    }

    resolveTotalBytes(primaryTotal) {
        const candidates = [
            primaryTotal,
            this.resumeConfig && this.resumeConfig.expectedSize,
            this.totalBytesHint
        ].filter(value => typeof value === 'number' && value > 0);

        return candidates.length ? Math.max(...candidates) : 0;
    }
    
    handleDownloadStarted(id, total, sent = 0) {
        const initialSent = typeof sent === 'number' ? sent : 0;
        this.log('DownloadManager', `Download started: id=${id}, total=${total}, initialSent=${initialSent}`);
        this.onDownloadStart(total, initialSent);

        // Call external callback if provided
        if (this.onDownloadStartCallback) {
            try {
                this.onDownloadStartCallback(id, total);
            } catch (e) {
                this.log('DownloadManager', 'Error in onDownloadStartCallback:', e);
            }
        }
    }

    handleDownloadProgress(sent, total) {
        // Early return: Skip progress updates for pass-through mode
        if (this.currentPlan && this.currentPlan.mode === 'pass') {
            this.log('DownloadManager', 'Skipping progress update for pass-through mode');
            return;
        }

        const resolvedTotal = this.resolveTotalBytes(total);
        const safeSent = typeof sent === 'number' ? sent : 0;
        const baseBytes = this.resumeConfig ? (this.resumeConfig.baseBytes || 0) : 0;
        const httpSent = Math.max(0, safeSent - baseBytes);
        const speed = this.calculateSpeed(httpSent, this.startTime);

        // Unified progress display based on whether we know the total size
        if (this.isValidSize(resolvedTotal)) {
            // Determinate progress (known size)
            const clampedSent = Math.min(safeSent, resolvedTotal);
            const percent = (clampedSent / resolvedTotal) * 100;
            this.updateProgressBar(percent);

            const transferredStr = this.formatBytes(clampedSent);
            const totalStr = this.formatBytes(resolvedTotal);
            this.updateProgressInfo(`${transferredStr} / ${totalStr}${speed ? ' (' + speed + ')' : ''}`);
        } else {
            // Indeterminate progress (unknown size)
            this.showIndeterminateProgress();

            const transferredStr = this.formatBytes(safeSent);
            this.updateProgressInfo(`${transferredStr}${speed ? ' (' + speed + ')' : ''}`);
        }
    }

    handleDownloadComplete(total) {
        this.log('DownloadManager', 'Download complete');
        this.stopProgressMonitoring();
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        this.updateProgressBar(100);

        // Update progress info to show completion with full file size
        const resolvedTotal = this.resolveTotalBytes(total);
        if (resolvedTotal && resolvedTotal > 0) {
            const totalStr = this.formatBytes(resolvedTotal);
            this.updateProgressInfo(`${totalStr} / ${totalStr}`);
        }

        this.updateStatus(this.t('Download:complete.title', 'Download completed!'), '');
        if (this.checksumVerified) {
            this.showChecksumVerifiedMessage();
        }

        // Notify server that client has received all bytes.
        // Mirrors WebRTC.js _downloadComplete() POST to /complete.
        // Unblocks _waitForHTTPDownloadComplete() on the server so shutdown/doAfterDownload
        // is only triggered after the relay has fully drained to the client.
        if (this.serverDownloadId && this.uid) {
            this.log('DownloadManager', `Notifying server of HTTP download completion, downloadId: ${this.serverDownloadId}`);
            fetch(`/${this.uid}/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ downloadId: this.serverDownloadId, receivedBytes: resolvedTotal || 0 }),
            }).catch(err => {
                this.log('DownloadManager', `Failed to notify server of HTTP completion: ${err}`);
            });
            this.serverDownloadId = null; // Prevent duplicate ACK on re-entry
        }

        // Call external callback if provided
        if (this.onDownloadCompleteCallback) {
            try {
                this.onDownloadCompleteCallback(total);
            } catch (e) {
                this.log('DownloadManager', 'Error in onDownloadCompleteCallback:', e);
            }
        }
    }

    handleDownloadError(message) {
        this.log('DownloadManager', 'Download error:', message);
        this.stopProgressMonitoring();
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        if (!this.downloadStarted && !this.newTabOpened) {
            this.showRetryLink();
        }

        // Call external callback if provided
        if (this.onDownloadErrorCallback) {
            try {
                this.onDownloadErrorCallback(message);
            } catch (e) {
                this.log('DownloadManager', 'Error in onDownloadErrorCallback:', e);
            }
        }
    }

    handleChecksumVerificationResult(result, transport = 'http') {
        if (!result) {
            return;
        }

        if (result.verified) {
            this.checksumVerified = true;
            this.showChecksumVerifiedMessage();
            this.log('Checksum', `${transport} checksum verified`, {
                algorithm: result.algorithm || 'blake2b',
                checksum: result.localChecksum
            });
            return;
        }

        if (result.pending || result.transportMismatch) {
            this.log('Checksum', `${transport} checksum verification skipped`, result);
            return;
        }

        this.checksumVerified = false;
        this.clearChecksumVerifiedMessage();
        this.log('Checksum', `${transport} checksum verification failed`, result);
        this.updateStatus(
            this.t('Download:complete.title', 'Download completed!'),
            this.t(
                'Download:complete.checksumFailed',
                'Checksum verification failed. Please re-download the file if integrity is required.'
            )
        );
    }

    _checksumBadgeTargets() {
        const targets = [this.statusHeading];
        if (this.completeStatusHeading) {
            targets.push(this.completeStatusHeading);
        }
        return targets;
    }

    _resolveTarget(target) {
        return (typeof target === 'string') ? document.querySelector(target) : target;
    }

    showChecksumVerifiedMessage() {
        const verifiedText = this.t('Download:checksum.verified', 'verified');
        const className = 'ffl-checksum-verified';

        for (const target of this._checksumBadgeTargets()) {
            const targetSelector = (typeof target === 'string') ? target : null;
            const targetElement = targetSelector ? null : target;

            if (typeof FFLChecksum !== 'undefined' && typeof FFLChecksum.showVerifiedBadge === 'function') {
                FFLChecksum.showVerifiedBadge({ targetSelector, targetElement, text: verifiedText, className });
                continue;
            }

            const el = this._resolveTarget(target);
            if (!el || el.querySelector('.' + className)) {
                continue;
            }

            const span = document.createElement('span');
            span.className = className;
            span.textContent = ` (${verifiedText})`;
            span.style.opacity = '0';
            span.style.transition = 'opacity 250ms';
            el.appendChild(span);
            requestAnimationFrame(() => { span.style.opacity = '1'; });
        }
    }

    clearChecksumVerifiedMessage() {
        const className = 'ffl-checksum-verified';
        for (const target of this._checksumBadgeTargets()) {
            this._resolveTarget(target)?.querySelector('.' + className)?.remove();
        }
    }

    createChecksumVerifierForHTTP(resumeConfig = null) {
        const hasResume = !!resumeConfig && (
            (resumeConfig.rangeStart || 0) > 0 ||
            (resumeConfig.baseBytes || 0) > 0 ||
            (resumeConfig.skipBytes || 0) > 0
        );
        if (hasResume) {
            this.log('Checksum', 'Skip checksum verifier for resumed HTTP transfer');
            return null;
        }

        if (typeof FFLChecksum === 'undefined' || typeof FFLChecksum.createVerifier !== 'function') {
            this.log('Checksum', 'Checksum module unavailable, skip verifier');
            return null;
        }

        return FFLChecksum.createVerifier({
            uid: this.uid,
            transport: 'http',
            log: (category, message, payload) => this.log(category, message, payload)
        });
    }

    setupBroadcastChannel() {
        if (this.dlChannel) {
            this.dlChannel.onmessage = (evt) => {
                const { type, sent, total, id } = evt.data;
                this.log('DownloadManager', 'Broadcast event received:', evt.data);

                // Filter events by download ID to prevent cross-tab interference
                if (id && this.activeDlId && id !== this.activeDlId) {
                    return;
                }

                if (type === 'download-started') {
                    this.handleDownloadStarted(id, total, sent);
                } else if (type === 'download-progress') {
                    this.handleDownloadProgress(sent, total);
                } else if (type === 'download-complete') {
                    if (evt.data.serverId) {
                        this.serverDownloadId = evt.data.serverId;
                    }
                    this.handleDownloadComplete(total);
                } else if (type === 'download-error') {
                    this.handleDownloadError(evt.data.message);
                } else if (type === 'download-checksum') {
                    this.handleChecksumVerificationResult(evt.data, evt.data.transport || 'http');
                } else if (type === 'debug' && evt.data.message) {
                    this.log('ProgressSW', evt.data.message);
                }
            };
        }
    }
    
    setupVisibilityChangeHandler() {
        // Handle tab visibility changes to optimize CPU usage
        document.addEventListener('visibilitychange', () => {
            const wasHidden = this.isTabHidden;
            this.isTabHidden = document.hidden;
            
            if (wasHidden !== this.isTabHidden) {
                this.log('DownloadManager', `Tab visibility changed: ${this.isTabHidden ? 'hidden' : 'visible'}`);
                
                // Restart progress monitoring with new interval if it's currently running
                // Only for browsers/modes that use real progress monitoring (not pass-through mode)
                const isPassMode = this.currentPlan && this.currentPlan.mode === 'pass';
                if (this.progressMonitorTimer && !isPassMode) {
                    this.restartProgressMonitoring();
                }
            }
        });
    }
    
    // Default delay calculation function (can be overridden)
    defaultCalculateDelayMs(totalBytes) {
        if (totalBytes >= this.ADAPTIVE_DELAY_CONFIG.LARGE_FILE_THRESHOLD) {
            return this.ADAPTIVE_DELAY_CONFIG.LARGE_FILE_DELAY;
        } else if (totalBytes >= this.ADAPTIVE_DELAY_CONFIG.MEDIUM_FILE_THRESHOLD) {
            return this.ADAPTIVE_DELAY_CONFIG.MEDIUM_FILE_DELAY;
        }
        return this.ADAPTIVE_DELAY_CONFIG.DEFAULT_DELAY;
    }
    
    // Adaptive unlock timing based on file size
    scheduleAdaptiveUnlock() {
        // Clear any existing timer first
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        
        const delayMs = this.calculateDelayMs(this.totalBytesHint);
        
        this.log('DownloadManager', 'Scheduling retry unlock in', delayMs/1000, 'seconds for', this.formatBytes(this.totalBytesHint));
        
        this.adaptiveUnlockTimer = setTimeout(() => {
            this.showRetryLink();
        }, delayMs);
    }
    
    showRetryLink() {
        // Don't show retry if new tab was already opened
        if (this.newTabOpened) {
            this.log('DownloadManager', 'Skipping retry - new tab already opened');
            return;
        }
        
        this.log('DownloadManager', 'Showing retry link');
        
        // Use configurable progress bar for progress checking
        const progressBar = $(this.progressBar);
        const progressValue = progressBar[0] && progressBar[0].tagName === 'PROGRESS' ? 
            parseFloat(progressBar[0].value || '0') : 
            parseInt(progressBar.attr('aria-valuenow') || '0');
        
        // Check if we should use subtle style
        // Firefox pass-through mode: always use subtle style (direct download likely works)
        // Firefox SW mode or Chromium: use subtle style if progress detected, prominent if no progress
        const isFirefoxPassMode = this.currentPlan && this.currentPlan.mode === 'pass';
        const shouldUseSubtleStyle = isFirefoxPassMode || 
                                   (!isFirefoxPassMode && this.downloadStarted && progressValue > 0);
        
        $('.delayed-show').fadeIn();
        
        if (this.currentPlan && this.currentPlan.mode === 'pass') {
            this.updateStatus(
                this.t('Download:progress.backgroundHeading', 'Download is processing in background'),
                this.t('Download:progress.backgroundDetailsByPass', 
                  'Check your browser download bar (usually at bottom/top) for progress — or confirmation that the download has already finished.')
            );
            this.updateProgressInfo(this.t('Download:progress.downloadingMightDone', 'Downloading file...It may already be done.'));            
        } else {
            this.updateStatus(
                this.t('Download:progress.backgroundHeading', 'Download is processing in background'),
                this.t('Download:progress.backgroundDetails', 'Check your browser download bar (usually at bottom/top) for progress')
            );
        }
        
        // Style retry button based on browser and progress status
        this.styleRetryButton(shouldUseSubtleStyle);
        
        // Start progress monitoring
        if (shouldUseSubtleStyle) {
            if (isFirefoxPassMode) {
                // Firefox pass-through mode: Use time-based monitoring since no real progress is available
                this.startFirefoxStallMonitoring();
            } else {
                // Firefox SW mode or Chromium: Monitor actual progress
                this.lastProgressValue = progressValue;
                this.lastProgressTime = Date.now();
                this.stallCheckCount = 0;
                this.startProgressMonitoring();
            }
        }
    }
    
    styleRetryButton(useSubtleStyle) {
        const retryButton = $(this.retryLink);
        
        if (useSubtleStyle) {
            // Firefox pass-through mode or browsers with progress: subtle blue text link style
            retryButton.removeClass('btn retry-link-prominent').addClass('retry-link-subtle');
            retryButton.html(this.t('Download:progress.troubleSubtle', 'Having trouble? Try again in new tab'));
            this.log('DownloadManager', 'Using subtle retry link (Firefox pass-through or progress detected)');
        } else {
            // Browsers with no progress: prominent amber button
            retryButton.removeClass('retry-link-subtle').addClass('retry-link-prominent');
            retryButton.html(this.t('Download:progress.troubleProminent', '🔄 Having trouble? Try again in new tab'));
            this.log('DownloadManager', 'Using prominent retry button (no progress detected)');
        }
    }
    
    startFirefoxStallMonitoring() {
        this.log('DownloadManager', 'Starting Firefox stall monitoring');
        
        this.progressMonitorTimer = setTimeout(() => {
            this.log('DownloadManager', 'Firefox timeout reached, switching to highlighted retry button');
            // Switch to highlighted style if retry link is still visible
            if ($(this.retryLink).is(':visible')) {
                this.styleRetryButton(false);
            }
            this.progressMonitorTimer = null;
        }, this.stallTimeoutMs);
    }
    
    restartProgressMonitoring() {
        // Stop current monitoring
        if (this.progressMonitorTimer) {
            clearInterval(this.progressMonitorTimer);
            this.progressMonitorTimer = null;
        }
        
        // Restart with appropriate interval based on visibility
        this.startProgressMonitoring();
        this.log('DownloadManager', `Progress monitoring restarted with ${this.getCurrentInterval()}ms interval`);
    }
    
    getCurrentInterval() {
        return this.isTabHidden ? this.stallCheckIntervalBackground : this.stallCheckInterval;
    }
    
    startProgressMonitoring() {
        // Only monitor progress for SW modes (Chromium or Firefox small files)
        // Skip for Firefox pass-through mode
        const isPassMode = this.currentPlan && this.currentPlan.mode === 'pass';
        if (isPassMode) {
            return;
        }
        
        const currentInterval = this.getCurrentInterval();
        this.log('DownloadManager', `Starting progress monitoring with ${currentInterval}ms interval (tab ${this.isTabHidden ? 'hidden' : 'visible'})`);
        
        this.progressMonitorTimer = setInterval(() => {
            let currentProgress = 0;
            const progressBar = $(this.progressBar);
            if (progressBar[0] && progressBar[0].tagName === 'PROGRESS') {
                currentProgress = parseFloat(progressBar[0].value || '0');
            } else {
                currentProgress = parseInt(progressBar.attr('aria-valuenow') || '0');
            }
            const currentTime = Date.now();
            
            if (currentProgress > this.lastProgressValue) {
                // Progress detected, reset stall counter
                this.lastProgressValue = currentProgress;
                this.lastProgressTime = currentTime;
                this.stallCheckCount = 0;
                this.log('DownloadManager', `Progress detected: ${currentProgress}%`);
            } else {
                // No progress since last check
                this.stallCheckCount++;
                this.log('DownloadManager', `No progress detected (${this.stallCheckCount}/${this.stallThreshold})`);
                
                if (this.stallCheckCount >= this.stallThreshold) {
                    this.log('DownloadManager', 'Download appears stalled, switching to highlighted retry button');
                    // Switch to highlighted style if retry link is visible
                    if ($(this.retryLink).is(':visible')) {
                        this.styleRetryButton(false);
                    }
                    // Stop monitoring once we've switched to highlighted
                    clearInterval(this.progressMonitorTimer);
                    this.progressMonitorTimer = null;
                }
            }
        }, currentInterval);
    }
    
    stopProgressMonitoring() {
        if (this.progressMonitorTimer) {
            const isPassMode = this.currentPlan && this.currentPlan.mode === 'pass';
            if (isPassMode) {
                clearTimeout(this.progressMonitorTimer);  // Pass-through mode uses setTimeout
            } else {
                clearInterval(this.progressMonitorTimer); // SW mode uses setInterval
            }
            this.progressMonitorTimer = null;
            this.log('DownloadManager', 'Progress monitoring stopped');
        }
    }
    
    stopCurrentTabProcessing() {
        // Stop all processing in current tab when retry opens new tab
        this.log('DownloadManager', 'Stopping current tab processing for retry');
        
        // Stop progress monitoring
        this.stopProgressMonitoring();
        
        // Stop adaptive unlock timer
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        
        // Close broadcast channel to avoid cross-tab interference
        if (this.dlChannel) {
            this.dlChannel.close();
            this.dlChannel = null;
            this.log('DownloadManager', 'Closed broadcast channel to prevent cross-tab interference');
        }
        
        // Mark download as stopped
        this.downloadStarted = false;
        this.downloadTriggeredOnce = true; // Prevent restart
    }
    
    updateStatus(heading, details) {
        // Update status heading and details
        const statusHeading = $(this.statusHeading);
        const statusDetails = $(this.statusDetails);
        
        if (statusHeading.length) {
            statusHeading.text(heading);
        }
        if (statusDetails.length && details) {
            statusDetails.text(details);
        }
    }
    
    onDownloadStart(total, initialSent = 0) {
        this.downloadStarted = true;
        this.checksumVerified = false;
        this.pendingChecksumResult = null;
        this.clearChecksumVerifiedMessage();
        this.startTime = Date.now(); // Reset timer when download actually starts
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        
        const resolvedTotal = this.resolveTotalBytes(total);
        if (resolvedTotal && resolvedTotal > 0) {
            this.totalBytesHint = Math.max(this.totalBytesHint || 0, resolvedTotal);
        }
        
        this.updateStatus(
            this.t('Download:progress.inProgressHeading', 'Download in progress...'), 
            this.t('Download:progress.inProgressDetails', 'Please wait while your file downloads')
        );
        
        // Check if we should use Firefox pass-through UI or normal progress UI
        const firefoxTotal = resolvedTotal || total;
        if (this.currentPlan && this.currentPlan.mode === 'pass') {
            this.log('DownloadManager', 'Firefox pass-through mode - showing full animated progress');
            this.showFirefoxDownloadProgress(firefoxTotal);
        } else {
            this.log('DownloadManager', 'Normal progress mode (Chromium or Firefox small file)');
            const safeInitialSent = typeof initialSent === 'number' && initialSent > 0 ? initialSent : 0;
            if (resolvedTotal && safeInitialSent > 0) {
                const clampedSent = Math.min(safeInitialSent, resolvedTotal);
                const percent = (clampedSent / resolvedTotal) * 100;
                this.updateProgressBar(percent);
                const transferredStr = this.formatBytes(clampedSent);
                const totalStr = this.formatBytes(resolvedTotal);
                this.updateProgressInfo(`${transferredStr} / ${totalStr}`);
            } else {
                this.updateProgressInfo(this.t('Download:progress.starting', 'Starting download...')); // Clear the "Connecting..." message
            }
        }
        
        this.log('DownloadManager', 'Download started, scheduling adaptive unlock');
        this.scheduleAdaptiveUnlock();
    }
    
    /**
     * Show indeterminate progress (striped animated bar, no percentage)
     */
    showIndeterminateProgress() {
        const progressBar = $(this.progressBar);

        // Only add animation classes if not already present (avoid redundant DOM updates)
        if (!progressBar.hasClass('progress-bar-animated')) {
            progressBar.addClass('progress-bar-striped progress-bar-animated');
        }

        // Set full width with no text
        progressBar.css({
            'width': '100%',
            'text-align': '',  // Clear any text alignment
            'line-height': '',  // Clear any line height overrides
            'position': ''      // Clear any position overrides
        }).attr('aria-valuenow', 100);

        progressBar.text(''); // No percentage text for indeterminate progress
    }

    showFirefoxDownloadProgress(total) {
        // Set progress bar to animated indeterminate mode
        this.showIndeterminateProgress();

        // Show file size info in progress-info area
        if (this.isValidSize(total)) {
            const totalStr = this.formatBytes(total);
            this.updateProgressInfo(this.t('Download:progress.downloadingWithSize', 'Downloading {{size}} file...', { size: totalStr }));
        } else {
            this.updateProgressInfo(this.t('Download:progress.downloading', 'Downloading file...'));
        }

        this.log('DownloadManager', 'Firefox progress bar set to animated indeterminate mode');
    }
    
    updateProgressBar(percent) {
        // Update progress bar with percentage
        const progressBar = $(this.progressBar);
        const p = Math.max(0, Math.min(100, percent));
        
        // Handle HTML5 progress element vs Bootstrap progress bar
        if (progressBar[0] && progressBar[0].tagName === 'PROGRESS') {
            // Handle HTML5 progress element
            progressBar[0].value = p;
        } else {
            // Handle Bootstrap progress bar
            progressBar.css('width', p + '%').attr('aria-valuenow', p);
            
            // Skip text updates only for Firefox pass-through mode (uses empty progress bar with animation)
            const shouldShowPercentText = !this.currentPlan || this.currentPlan.mode !== 'pass';
            if (shouldShowPercentText) {
                const displayPercent = Math.round(p * 10) / 10;
                progressBar.text(displayPercent + '%');
                
                progressBar.css({
                    'text-align': 'center',
                    'line-height': '20px',
                    'position': 'relative'
                });
            }
        }
    }
    
    updateProgressInfo(text) {
        const progressInfo = $(this.progressInfo);
        if (progressInfo.length) {
            progressInfo.text(text);
        }
    }
    
    /**
     * Show starting UI based on download plan
     * @param {Object} options - Options with filename, size, and indeterminate flag
     */
    showStartingUI({ filename, size, indeterminate }) {
        // Determine if progress is indeterminate (unified logic)
        const isIndeterminate = indeterminate || this.isUnknownSize(size);
        const sizeStr = this.isValidSize(size) ? this.formatBytes(size) : 'unknown size';

        if (isIndeterminate) {
            // Indeterminate progress (unknown size or pass-through mode)
            this.updateStatus(
                this.t('Download:progress.starting', 'Starting download...'),
                this.t('Download:progress.checkDownloads', 'You can check progress in the Downloads panel (Ctrl+J)')
            );

            this.showIndeterminateProgress();

            const messageKey = this.isUnknownSize(size)
                ? 'Download:progress.preparingUnknownSize'
                : 'Download:progress.preparingLarge';
            const messageDefault = this.isUnknownSize(size)
                ? 'Preparing download (size unknown)...'
                : 'Preparing {{size}} file for direct download...';

            this.updateProgressInfo(this.t(messageKey, messageDefault, { size: sizeStr }));
        } else {
            // Determinate progress (known size)
            this.updateStatus(
                this.t('Download:progress.starting', 'Starting download...'),
                this.t('Download:progress.pleaseWait', 'Please wait while your file downloads')
            );
            this.updateProgressInfo(this.t('Download:progress.preparing', 'Preparing download...'));
        }

        this.log('DownloadManager', `Starting UI shown for ${filename} (${sizeStr}), indeterminate: ${isIndeterminate}`);
    }
    
    /**
     * Show indeterminate "started" UI for Firefox large files
     */
    showIndeterminateStartedUI() {
        this.updateStatus(
            this.t('Download:progress.started', '✓ Download started in your browser (Firefox)'),
            this.t('Download:progress.checkDownloads', 'You can check progress in the Downloads panel (Ctrl+J)')
        );

        // Add backup retry option after a delay
        setTimeout(() => {
            if (!this.downloadStarted) { // Only show if no progress detected
                this.updateStatus(
                    this.t('Download:progress.started', '✓ Download started in your browser (Firefox)'),
                    this.t('Download:progress.havingTrouble', 'Having trouble? Try again or check your Downloads folder')
                );
            }
        }, 4000);

        this.log('DownloadManager', 'Firefox indeterminate started UI shown');
    }

    /**
     * Show error UI when E2EE is blocked in Firefox passthrough mode
     * @param {number} size - File size in bytes
     */
    showE2EEFirefoxBlockedUI(size) {
        const sizeStr = size ? this.formatBytes(size) : 'large';
        const limitStr = this.formatBytes(this.FF_SW_LIMIT);

        this.updateStatus(
            this.t('Download:e2ee.firefoxBlocked.title', '🔒 Encrypted Download Not Available'),
            this.t('Download:e2ee.firefoxBlocked.details',
                'Encrypted downloads larger than {{limit}} require a Chromium-based browser for streaming decryption.',
                { limit: limitStr })
        );

        // Set progress bar to error state (red, no animation)
        const progressBar = $(this.progressBar);
        if (progressBar.length) {
            progressBar.removeClass('progress-bar-striped progress-bar-animated')
                      .addClass('bg-danger')
                      .css('width', '100%')
                      .attr('aria-valuenow', 100)
                      .text('');
        }

        this.updateProgressInfo(
            this.t('Download:e2ee.firefoxBlocked.fileSize', 'File size: {{size}}', { size: sizeStr })
        );

        // Show error message with browser recommendations
        const $statusDetails = $(this.statusDetails);
        if ($statusDetails.length) {
            const recommendedBrowsers = this.t('Download:e2ee.firefoxBlocked.browsers',
                'Chrome, Edge, or Brave');

            $statusDetails.html(
                `<strong>${this.t('Download:e2ee.firefoxBlocked.why', 'Why?')}</strong> ` +
                this.t('Download:e2ee.firefoxBlocked.explanation',
                    'Large encrypted files cannot be streaming decrypted reliably in Firefox.') +
                `<br><br><strong>${this.t('Download:e2ee.firefoxBlocked.solution', 'Solution:')}</strong><br>` +
                `• ${this.t('Download:e2ee.firefoxBlocked.useBrowser', 'Use {{browsers}}', { browsers: recommendedBrowsers })}<br>` +
                `• ${this.t('Download:e2ee.firefoxBlocked.useCLI', 'Or use the <a href="https://github.com/nuwainfo/ffl" target="_blank" style="display: inline !important; padding: 0 !important; margin: 0 !important; border: none !important; background: none !important; color: #007bff !important; text-decoration: underline !important; font-size: inherit !important;">FastFileLink CLI</a>')}<br>` +
                `• ${this.t('Download:e2ee.firefoxBlocked.smallFiles', 'Small encrypted files (<{{limit}}) work on Firefox', { limit: limitStr })}`
            );
        }

        this.log('DownloadManager', `E2EE Firefox blocked UI shown for ${sizeStr} file (limit: ${limitStr})`);
    }
    
    formatBytes(bytes) {
        if (bytes === 0) {
            return '0 Bytes';
        }
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
    
    calculateSpeed(transferred, startTime) {
        const elapsed = (Date.now() - startTime) / 1000;
        if (elapsed < 1) {
            return '';
        }
        
        const speed = transferred / elapsed;
        return this.formatBytes(speed) + '/s';
    }
    
    async ensureProgressSWControlled() {
        if (!('serviceWorker' in navigator)) {
            this.log('DownloadManager', 'Service Worker not supported');
            return false;
        }

        try {
            this.log('DownloadManager', `Registering Service Worker: ${this.serviceWorkerPath} with scope: ${this.serviceWorkerScope}`);
            const reg = await navigator.serviceWorker.register(this.serviceWorkerPath, { scope: this.serviceWorkerScope });

            await navigator.serviceWorker.ready;

            if (!navigator.serviceWorker.controller) {
                this.log('DownloadManager', 'Waiting for SW to take control...');

                await new Promise((resolve) => {
                    const onCtl = () => {
                        navigator.serviceWorker.removeEventListener('controllerchange', onCtl);
                        this.log('DownloadManager', 'SW now controlling');
                        resolve();
                    };
                    navigator.serviceWorker.addEventListener('controllerchange', onCtl, { once: true });
                });
            }

            this.log('DownloadManager', 'Progress SW is ready and controlling');

            // Invoke callback when Service Worker is ready and WAIT for it to complete
            if (this.onServiceWorkerReadyCallback) {
                try {
                    await this.onServiceWorkerReadyCallback(navigator.serviceWorker.controller);
                } catch (e) {
                    this.log('DownloadManager', 'Error in onServiceWorkerReadyCallback:', e);
                }
            }

            return true;
        } catch (err) {
            this.log('[SW ERROR]', 'SW registration failed');
            this.log('[SW ERROR]', `Error name: ${err.name}`);
            this.log('[SW ERROR]', `Error message: ${err.message}`);
            this.log('[SW ERROR]', `Error stack: ${err.stack}`);
            this.log('[SW ERROR]', `SW path: ${this.serviceWorkerPath}`);
            this.log('[SW ERROR]', `SW scope: ${this.serviceWorkerScope}`);
            this.log('[SW ERROR]', `Origin: ${location.origin}`);
            this.log('[SW ERROR]', `Full URL: ${location.href}`);
            return false;
        }
    }
    
    ensureDownloadId(downloadUrl) {
        // Use existing dl parameter from URL, or generate if missing
        const existingDl = downloadUrl.searchParams.get('dl');
        if (existingDl) {
            this.activeDlId = existingDl;
        } else {
            // Generate download token only if not already present
            this.activeDlId = (crypto?.randomUUID && crypto.randomUUID()) || String(Date.now() + Math.random());
            downloadUrl.searchParams.set('dl', this.activeDlId);
        }

        this.log('DownloadManager', 'Download ID:', this.activeDlId);
        return this.activeDlId;
    }

    async fetchToWriter(urlPath, writer, needsDecryption, resume = null, progressCallback = null, checksumVerifier = null) {
        if (needsDecryption) {
            this.log('DownloadManager', 'E2EE decryption will be applied during resume (bypassing Service Worker)');

            if (!this.httpDecryptor) {
                const error = 'E2EE resume requires httpDecryptor (should have been created upfront)';
                this.log('DownloadManager', 'ERROR:', error);
                throw new Error(error);
            }

            this.log('DownloadManager', 'Using existing HTTPDecryptor instance from constructor');

            // Set resume position if needed
            if (resume && typeof resume.rangeStart === 'number') {
                this.httpDecryptor.setResumeState(resume.rangeStart);
                this.log('DownloadManager', `HTTPDecryptor resume position set to: ${resume.rangeStart}`);
            }
        }

        // Prepare Range header if resuming
        const headers = new Headers();
        let wantRange = false;
        if (resume && Number.isFinite(resume.rangeStart) && resume.rangeStart > 0) {
            headers.set('Range', `bytes=${resume.rangeStart}-`);
            wantRange = true;
            this.log('DownloadManager', `Resume request: Range bytes=${resume.rangeStart}-, skipBytes=${resume.skipBytes || 0}`);
        }
        if (this.authHeaders) {
            for (const [key, value] of Object.entries(this.authHeaders)) {
                headers.set(key, value);
            }
        }

        // This fetch will trigger ProgressServiceWorker if SW is available.
        const response = await fetch(urlPath, { headers, cache: 'no-cache' });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Capture server-assigned download ID for POST /complete ACK (relay truncation fix).
        // Only reachable when SW is NOT active (SW path gets serverId via broadcast instead).
        const serverDlId = response.headers.get('FFL-DownloadId');
        if (serverDlId) {
            this.serverDownloadId = serverDlId;
        }

        // Validate 206 / Content-Range for resume and get total size
        let totalSizeFromServer = 0;
        let contentRange = response.headers.get('Content-Range');
        if (wantRange) {
            if (response.status === 206 && contentRange) {
                // e.g. Content-Range: bytes 20709376-104857599/104857600
                const m = contentRange.match(/^bytes\s+(\d+)-(\d+)\/(\d+)$/i);
                if (m) {
                    const start = parseInt(m[1], 10);
                    const end = parseInt(m[2], 10);
                    const full = parseInt(m[3], 10);
                    if (start !== resume.rangeStart) {
                        throw new Error(`Server returned mismatched range start: ${start} != ${resume.rangeStart}`);
                    }
                    totalSizeFromServer = full;
                    this.totalBytesHint = Math.max(this.totalBytesHint || 0, full);
                    this.log('DownloadManager', `206 Partial Content: ${contentRange}, total=${full}`);
                }
            } else if (response.status === 200) {
                // Server doesn't support Range; fallback to client-side discard
                this.log('DownloadManager', 'WARNING: Server ignored Range header (200), using client-side discard');
                const len = response.headers.get('Content-Length');
                if (len) {
                    totalSizeFromServer = parseInt(len, 10);
                }
            } else {
                throw new Error(`Unexpected response status for ranged request: ${response.status}`);
            }
        } else {
            // No range request, get Content-Length for progress
            const len = response.headers.get('Content-Length');
            if (len) {
                totalSizeFromServer = parseInt(len, 10);
            }
        }

        this.log('DownloadManager', 'Fetch response received, reading stream');

        // Calculate initial sent bytes (for resume scenarios)
        const baseBytes = resume?.baseBytes || 0;

        // Read the stream and write to the writer
        const reader = response.body.getReader();
        let totalWritten = 0;                 // Bytes written in this HTTP session
        let firstChunk = true;
        let bytesToDiscard = resume?.skipBytes ? Math.max(0, resume.skipBytes) : 0;

        while (true) {
            const { done, value } = await reader.read();

            if (done) {
                this.log('DownloadManager', 'Stream read complete, total written:', totalWritten);
                break;
            }

            let chunk = value;

            if (checksumVerifier) {
                checksumVerifier.update(chunk);
            }

            // Apply E2EE decryption only when resuming (bypassing Service Worker)
            // Normal path: Service Worker already decrypts chunks
            if (needsDecryption) {
                try {
                    const encryptedSize = chunk.byteLength;
                    chunk = await this.httpDecryptor.decryptChunk(chunk);
                    this.log('DownloadManager', `E2EE resume: Chunk decrypted, encrypted size: ${encryptedSize}, decrypted size: ${chunk.byteLength}`);
                } catch (e) {
                    this.log('DownloadManager', 'ERROR: E2EE decryption failed during resume:', e);
                    throw new Error('E2EE decryption failed: ' + e.message);
                }
            }

            // Only discard bytes in first chunk(s) for client-side resume fallback
            if (firstChunk && bytesToDiscard > 0) {
                if (chunk.byteLength <= bytesToDiscard) {
                    // Discard entire chunk
                    this.log('DownloadManager', `Discarding entire chunk (${chunk.byteLength} bytes), remaining=${bytesToDiscard - chunk.byteLength}`);
                    bytesToDiscard -= chunk.byteLength;
                    continue; // Don't set firstChunk=false yet, may need more discarding
                } else {
                    // Discard first part, keep rest
                    this.log('DownloadManager', `Discarding ${bytesToDiscard} bytes from first chunk, keeping ${chunk.byteLength - bytesToDiscard}`);
                    chunk = chunk.subarray(bytesToDiscard);
                    bytesToDiscard = 0;
                }
            }
            firstChunk = false;

            // Write chunk to the existing StreamSaver writer
            await writer.write(chunk);
            totalWritten += chunk.byteLength;

            // Report progress if callback provided (no-SW case)
            if (progressCallback) {
                const currentSent = baseBytes + totalWritten;
                progressCallback(currentSent, totalSizeFromServer);
            }
        }

        // Close the writer (completes the file)
        await writer.close();
        this.log('DownloadManager', 'Writer closed successfully, HTTP bytes written:', totalWritten);

        if (checksumVerifier) {
            try {
                const checksumResult = await checksumVerifier.finalizeAndVerify();
                this.pendingChecksumResult = checksumResult;
            } catch (verifyError) {
                this.log('Checksum', 'Failed to verify HTTP checksum:', verifyError);
            }
        }

        // Return total size for caller to handle completion
        return totalSizeFromServer;
    }

    triggerNativeDownloadLink(url) {
        // Helper method to trigger native browser download via <a> tag
        // Used when Service Worker handles everything or as final fallback
        const a = document.createElement('a');
        a.href = url;
        //a.download = ''; // Don't set - it disables TransformStream in Service Worker
        a.style.display = 'none';
        document.body.appendChild(a);

        this.log('DownloadManager', 'Triggering native download link');
        a.click();

        document.body.removeChild(a);
    }

    async startNativeDownload(url, filename, {
        writer = null,
        progressSwSupported = false,
        resumeConfig = null,
        forceWriter = false,
        forceNativeLink = false
    } = {}) {
        if (this.downloadTriggeredOnce) {
            this.log('DownloadManager', 'Download already triggered, ignoring duplicate request');
            return;
        }
        this.downloadTriggeredOnce = true;

        this.log('DownloadManager', 'Starting native download', {
            hasWriter: !!writer,
            progressSwSupported,
            hasResumeConfig: !!resumeConfig,
            forceWriter,
            forceNativeLink
        });

        const downloadUrl = new URL(url, location.origin);
        this.ensureDownloadId(downloadUrl);
        this.log('DownloadManager', 'Download URL with token:', downloadUrl.href);

        if (forceNativeLink) {
            this.log('DownloadManager', 'BRANCH: forceNativeLink → native <a> download (cookie auth only, no SW header injection)');
            this.handleDownloadStarted(this.activeDlId, this.totalBytesHint || 0, 0);
            this.triggerNativeDownloadLink(downloadUrl.pathname + downloadUrl.search);
            return;
        }

        if (this.authHeaders && navigator.serviceWorker && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'auth-headers',
                downloadId: this.activeDlId,
                headers: this.authHeaders
            });
        }

        if (progressSwSupported) {
            // Case A: Service Worker is available
            if (writer && (resumeConfig || forceWriter)) {
                // Has SW + (has resumeConfig OR forceWriter) + has writer
                // SW handles resume + decryption, we just write plaintext to writer
                // No progressCallback needed (SW broadcasts events)
                // forceWriter=true ensures ZIP preview can feed chunks even without resume
                this.log('DownloadManager', 'BRANCH: SW + writer + (resumeConfig OR forceWriter) -> fetchToWriter (SW handles resume/decrypt)');
                const needsDecryption = false;
                const progressCallback = null;  // SW broadcasts events
                return this.fetchToWriter(
                    downloadUrl.pathname + downloadUrl.search,
                    writer,
                    needsDecryption,
                    null,  // Resume handled by SW
                    progressCallback,
                    null
                ).catch(err => {
                    this.log('DownloadManager', 'Writer-based download failed:', err);
                    this.onDownloadErrorCallback && this.onDownloadErrorCallback(String(err));
                });
            } else {
                // Has SW + no resumeConfig (or no writer)
                // Use <a> tag, let SW handle everything (including all events)
                this.log('DownloadManager', 'BRANCH: SW without resumeConfig → <a> tag (SW handles download)');
                this.triggerNativeDownloadLink(downloadUrl.pathname + downloadUrl.search);
                return;
            }
        }

        // Case B: No Service Worker controller
        if (writer) {
            // No SW + has writer
            // Direct fetch with manual resume + decryption
            // Simulate broadcast events manually
            this.log('DownloadManager', 'BRANCH: No SW + writer -> direct fetchToWriter (manual resume/decrypt + event simulation)');

            // Prepare callbacks and parameters
            const needsDecryption = this.e2eeEnabled;
            const progressCallback = this.handleDownloadProgress.bind(this);
            const checksumVerifier = this.createChecksumVerifierForHTTP(resumeConfig);
            const baseBytes = resumeConfig?.baseBytes || 0;

            // Get expected total size for download-started event
            const expectedSize = resumeConfig?.expectedSize || this.totalBytesHint || 0;

            try {
                // Simulate download-started event (before fetching)
                this.log('DownloadManager', 'Simulating download-started event (no SW)');
                this.handleDownloadStarted(this.activeDlId, expectedSize, baseBytes);

                // Perform the actual download
                const totalSize = await this.fetchToWriter(
                    downloadUrl.pathname + downloadUrl.search,
                    writer,
                    needsDecryption,
                    resumeConfig,
                    progressCallback,
                    checksumVerifier
                );

                // Simulate download-complete event (after success)
                this.log('DownloadManager', 'Simulating download-complete event (no SW)');
                this.handleDownloadComplete(totalSize || expectedSize);
                if (this.pendingChecksumResult) {
                    this.handleChecksumVerificationResult(this.pendingChecksumResult, 'http');
                    this.pendingChecksumResult = null;
                }

            } catch (err) {
                this.log('DownloadManager', 'Direct fetch -> writer failed:', err);

                // Simulate download-error event
                this.handleDownloadError(String(err));
            }

            return;
        }

        // No SW + no writer
        // Final fallback: native <a> download (may download encrypted file)
        // Can only simulate start event (no way to track progress/completion)
        this.log('DownloadManager', 'BRANCH: No SW + no writer -> fallback <a> download (no progress tracking)');

        // Get expected size for UI (if available)
        const expectedSize = resumeConfig?.expectedSize || this.totalBytesHint || 0;

        // Simulate download-started event to show initial UI
        this.log('DownloadManager', 'Simulating download-started event (no SW, no tracking)');
        this.handleDownloadStarted(this.activeDlId, expectedSize, 0);

        // Trigger native download (browser handles everything, no progress tracking)
        this.triggerNativeDownloadLink(downloadUrl.pathname + downloadUrl.search);

        // Note: No download-complete event - we have no way to know when it finishes
        // User will see "check your downloads" UI via adaptive unlock
    }

    // InApp Guard integration methods
    isRestrictedEnvironment() {
        // Check if InAppGuard is available and if download is restricted
        return typeof InAppGuard !== 'undefined' && InAppGuard.isDownloadRestricted();
    }
    
    handleRestrictedDownload() {
        // Match the original HTML behavior for restricted environments
        if (typeof InAppGuard !== 'undefined') {
            // Always prevent download in restricted environments
            const message = InAppGuard.getRestrictedMessage();
            alert(message + '\n\nClick OK to open in browser.');

            // Try to open in external browser
            InAppGuard.openExternally();

            this.log('DownloadManager', 'Manual download link blocked and redirected to external browser');
        } else {
            // Fallback if InAppGuard is not available
            alert('Downloads are not supported in this environment. Please open this link in your default browser.');
            this.log('DownloadManager', 'Download blocked - InAppGuard not available');
        }
    }

    /**
     * Show warning when retry is blocked due to E2EE
     * Direct HTTP downloads cannot perform client-side decryption
     */
    showE2EERetryBlockedWarning() {
        this.log('DownloadManager', 'Retry blocked - E2EE requires JavaScript context for decryption');

        // Hide retry link to prevent confusion
        $(this.retryLink).hide();

        // Show E2EE-specific retry blocked warning
        $('#e2ee-retry-blocked').show();
    }

    setupRetryHandlers() {
        // Event handlers for retry functionality
        $(document).on('click', this.retryLink, (e) => {
            e.preventDefault();
            this.stopProgressMonitoring();

            // Check for restricted environment before showing retry
            if (this.isRestrictedEnvironment()) {
                this.handleRestrictedDownload();
                return;
            }

            // Check for E2EE - direct HTTP download cannot decrypt
            if (this.e2eeEnabled) {
                this.showE2EERetryBlockedWarning();
                return;
            }

            $('#retry-confirmation').show();
            $(e.target).hide();
        });
        
        $(document).on('click', '#confirm-retry', (e) => {
            // Generate direct download URL for new tab - no tokens needed for direct downloads
            // Direct download links don't need SW tokens since there's no HTML/JS in new tab
            const currentPath = location.pathname;
            const baseUrl = currentPath.endsWith('/') ? currentPath + 'download' : currentPath + '/download';
            const url = new URL(baseUrl, location.origin);
            
            // NO parameters needed for direct downloads - browser handles it natively
            // Direct download = no HTML page = no JS = no SW = no tokens needed
            
            // Set the clean download URL
            $(e.target).attr('href', url.href);
            
            // Stop current tab's ServiceWorker monitoring and broadcast channel
            this.stopCurrentTabProcessing();
            
            // Update UI after short delay
            setTimeout(() => {
                this.newTabOpened = true; // Prevent retry from showing again
                $('#close-tab-wrap').show();
                $('#retry-confirmation').hide();
                $('.delayed-show').hide();
                
                // Clear progress bar and show stopped state
                const progressBar = $(this.progressBar);
                if (progressBar.length) {
                    progressBar.removeClass('progress-bar-striped progress-bar-animated')
                              .css('width', '0%')
                              .attr('aria-valuenow', 0)
                              .text('');
                }
                
                this.updateStatus(
                    this.t('Download:progress.newTabOpened', 'Download opened in new tab'), 
                    this.t('Download:progress.canCloseTab', 'You can close this tab if desired')
                );
                
                this.updateProgressInfo(this.t('Download:progress.stoppedForNewTab', 'Download stopped in this tab - continuing in new tab'));
            }, 100);
        });
        
        $(document).on('click', '#cancel-retry', (e) => {
            e.preventDefault();
            $('#retry-confirmation').hide();
            $(this.retryLink).show();
        });
        
        $(document).on('click', '#close-this-tab', (e) => {
            e.preventDefault();
            window.close();
            
            // Most browsers won't allow closing, so provide fallback message
            setTimeout(() => {
                if (!document.hidden) {
                    $('#close-this-tab').text(this.t('Download:progress.unableToClose', 'Unable to auto-close, you can manually close this tab'));
                }
            }, 300);
        });
    }
    
    addSwConfigToUrl(url, plan, resumeConfig = null) {
        // Add ServiceWorker configuration parameters to download URL
        try {
            const urlObj = new URL(url, window.location.origin);

            // Add download ID for progress tracking
            const dlId = (crypto.randomUUID && crypto.randomUUID()) || String(Date.now());
            urlObj.searchParams.set('dl', dlId);
            this.activeDlId = dlId;

            // Add file size if known (fallback for missing Content-Length header)
            if (plan.size && plan.size > 0) {
                urlObj.searchParams.set('size', plan.size.toString());
                this.log('DownloadManager', `Added file size to URL: ${plan.size} bytes`);
            }

            // Add ServiceWorker progress reporting config
            urlObj.searchParams.set('reportBytes', this.swReportEveryBytes.toString());
            urlObj.searchParams.set('reportMs', this.swReportEveryMs.toString());

            // Add debug flag if debugging is enabled
            if (this.DEBUG) {
                urlObj.searchParams.set('debug', '1');
                this.log('DownloadManager', 'Debug mode enabled - ServiceWorker will use verbose logging');
            }

            // Add Firefox routing flag for large files (pass-through mode)
            if (plan.browser === 'firefox' && plan.mode === 'pass') {
                urlObj.searchParams.set('ff_pass', '1');
                this.log('DownloadManager', `Firefox large/unknown file mode: pass-through (${this.formatBytes(plan.size) || 'unknown size'})`);
            }

            // Add E2EE flag if decryption is enabled
            if (this.e2eeEnabled) {
                urlObj.searchParams.set('e2ee', '1');
                this.log('DownloadManager', 'E2EE decryption enabled for HTTP download');
            }

            // Add resume parameters if provided - SW will detect and apply Range header
            if (resumeConfig) {
                const rangeStart = resumeConfig.rangeStart ?? 0;
                const baseBytes = resumeConfig.baseBytes ?? 0;
                const skipBytes = resumeConfig.skipBytes ?? 0;
                const expectedSize = resumeConfig.expectedSize ?? 0;

                if (rangeStart > 0) {
                    urlObj.searchParams.set('resume_start', String(rangeStart));
                    this.log('DownloadManager', `Added resume_start to URL: ${rangeStart}`);
                }
                if (baseBytes > 0) {
                    urlObj.searchParams.set('resume_base', String(baseBytes));
                    this.log('DownloadManager', `Added resume_base to URL: ${baseBytes}`);
                }
                if (skipBytes > 0) {
                    urlObj.searchParams.set('resume_skip', String(skipBytes));
                    this.log('DownloadManager', `Added resume_skip to URL: ${skipBytes}`);
                }
                if (expectedSize > 0) {
                    urlObj.searchParams.set('resume_expected', String(expectedSize));
                    this.log('DownloadManager', `Added resume_expected to URL: ${expectedSize}`);
                }
            }

            this.log('DownloadManager', `Added SW config to URL: reportBytes=${this.swReportEveryBytes}, reportMs=${this.swReportEveryMs}, dlId=${dlId}, size=${plan.size || 'unknown'}, debug=${this.DEBUG}, e2ee=${this.e2eeEnabled}, resume=${!!resumeConfig}`);
            return urlObj.toString();
        } catch (e) {
            this.log('DownloadManager', 'Failed to add SW config to URL:', e);
            return url; // Return original URL if parsing fails
        }
    }
    
    async startDownload(options = {}) {
        // Extract writer as first-class parameter
        const writer = options.writer || null;
        const forceWriter = options.forceWriter || false;
        const forceNativeLink = options.forceNativeLink || false;

        const resumeConfig = this.setResumeConfig(options.resume);
        if (resumeConfig) {
            this.log(
                'DownloadManager',
                `Resume requested: base=${resumeConfig.baseBytes}, rangeStart=${resumeConfig.rangeStart}, skip=${resumeConfig.skipBytes}`
            );
            if (resumeConfig.expectedSize) {
                this.totalBytesHint = Math.max(this.totalBytesHint || 0, resumeConfig.expectedSize);
            }
        } else {
            this.log('DownloadManager', 'No resume information provided - starting from beginning');
        }

        // Ensure progress bar has max=100 for percentage-based updates
        const progressBar = $(this.progressBar);
        if (progressBar[0] && progressBar[0].tagName === 'PROGRESS') {
            progressBar[0].max = 100;
            progressBar[0].value = 0;
            this.log('DownloadManager', 'Set progress bar max=100 for percentage updates');
        }

        let url = $(this.downloadLink).attr('href') || `/${this.uid}/download`;
        const filename = $(this.filenameInput).val() || 'download';

        // Get the planned download mode based on browser and file size
        const plan = this.getPlannedMode({ uid: this.uid, filename });
        if (resumeConfig && resumeConfig.expectedSize && (!plan.size || plan.size < resumeConfig.expectedSize)) {
            plan.size = resumeConfig.expectedSize;
        }
        this.log('DownloadManager', `Download plan:`, plan);

        // Store plan for UI updates
        this.currentPlan = plan;

        // Block E2EE downloads in Firefox passthrough mode BEFORE scheduling anything
        if (this.e2eeEnabled && plan.browser === 'firefox' && plan.mode === 'pass') {
            this.log('DownloadManager', 'BLOCKING: E2EE not supported in Firefox passthrough mode');
            this.showE2EEFirefoxBlockedUI(plan.size);
            return; // Stop download from starting
        }

        // Schedule initial unlock (will be updated when file size is known)
        this.scheduleAdaptiveUnlock();

        // Add ServiceWorker configuration parameters and routing flags to URL
        url = this.addSwConfigToUrl(url, plan, resumeConfig);

        // UI: Show starting message based on plan
        this.showStartingUI({ filename, size: plan.size, indeterminate: plan.mode !== 'sw' });

        // Firefox large file watchdog: show "started" UI after delay
        if (plan.browser === 'firefox' && plan.mode === 'pass') {
            setTimeout(() => {
                this.showIndeterminateStartedUI();
            }, 4000);
        }

        const progressSwSupported = await this.ensureProgressSWControlled();

        // if ff_pass=1, we still use ProgressServiceWorker.js to handle fetch request, but pass-through browser directly.

        // Unified download entry point - all branches handled in startNativeDownload
        return this.startNativeDownload(url, filename, {
            writer,
            progressSwSupported,
            resumeConfig,
            forceWriter,
            forceNativeLink
        });
    }
}

/**
 * BlobWriter: Writer implementation that accumulates chunks in memory
 * Mimics WritableStream writer interface for compatibility with fetchToWriter
 * Automatically triggers download when closed
 */
class BlobWriter {
    constructor(fileName, expectedSize = null) {
        this.fileName = fileName;
        this.chunks = [];
        this.bytesWritten = 0;
        this.expectedSize = expectedSize;
        this.closed = false;
    }

    async write(chunk) {
        if (this.closed) {
            throw new Error('Writer is closed');
        }

        // Store a copy to prevent external modifications
        const chunkView = chunk instanceof ArrayBuffer
            ? new Uint8Array(chunk.slice(0))
            : new Uint8Array(chunk);

        this.chunks.push(chunkView);
        this.bytesWritten += chunkView.byteLength;
    }

    async close() {
        if (this.closed) {
            return;
        }
        this.closed = true;

        // Size verification (skip if size is unknown)
        const hasKnownSize = this.expectedSize !== null && this.expectedSize > 0;
        if (hasKnownSize && this.bytesWritten !== this.expectedSize) {
            throw new Error(`Size mismatch: written=${this.bytesWritten}, expected=${this.expectedSize}`);
        }

        // Automatically trigger blob download on close
        this.triggerDownload();
    }

    triggerDownload() {
        if (!this.closed) {
            throw new Error('Writer must be closed before triggering download');
        }

        dmLog("BlobWriter", `Creating blob download for ${this.fileName} (${this.bytesWritten} bytes)`);

        const blob = new Blob(this.chunks, { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = this.fileName;
        a.style.display = 'none';
        document.body.appendChild(a);

        dmLog("BlobWriter", `Triggering download for ${this.fileName}`);
        a.click();

        setTimeout(() => {
            dmLog("BlobWriter", "Cleaning up object URL");
            URL.revokeObjectURL(url);
            a.remove();
        }, 60000);
    }
}

/**
 * WriterFactory: Creates appropriate writer based on file size and browser capabilities
 */
class WriterFactory {

    static create(fileName, fileSize) {
        const USE_BLOB_THRESHOLD = 10 * 1024 * 1024; // 10MB

        // Check if size is unknown
        const isUnknownSize = fileSize == null || fileSize <= 0;
        const sizeDesc = isUnknownSize ? 'unknown' : `${fileSize} bytes`;

        // Check if StreamSaver is available
        const canUseSW = location.protocol === 'https:' ||
                        location.hostname === 'localhost' ||
                        location.hostname === '127.0.0.1';

        const streamSaverReady = canUseSW &&
                                'serviceWorker' in navigator &&
                                typeof streamSaver !== 'undefined';

        // Use StreamSaver for:
        // 1. Large files (> threshold)
        // 2. Unknown size files (to avoid memory issues)
        const needsStreamSaver = isUnknownSize || fileSize > USE_BLOB_THRESHOLD;

        if (streamSaverReady && needsStreamSaver) {
            try {
                dmLog("WriterFactory", `Creating StreamSaver writer for ${fileName} (${sizeDesc})`);

                // Configure StreamSaver mitm path
                if (!streamSaver.mitm) {
                    streamSaver.mitm = '/static/assets/mitm.html';
                }

                // For unknown size, don't specify size option (let browser handle it)
                const streamOptions = isUnknownSize ? {} : { size: fileSize };
                const fileStream = streamSaver.createWriteStream(fileName, streamOptions);
                const writer = fileStream.getWriter();

                return {
                    type: 'streamsaver',
                    writer: writer,
                    fileName: fileName,
                    fileSize: fileSize
                };
            } catch (e) {
                dmLog('WriterFactory', 'StreamSaver initialization failed, falling back to Blob', e);
                // Fall through to blob creation
            }
        }

        // Use Blob for small files with known size
        dmLog("WriterFactory", `Creating Blob writer for ${fileName} (${sizeDesc})`);
        const blobWriter = new BlobWriter(fileName, fileSize);

        return {
            type: 'blob',
            writer: blobWriter,
            fileName: fileName,
            fileSize: fileSize
        };
    }

    static getUnsupportedReason(fileSize) {
        const USE_BLOB_THRESHOLD = 10 * 1024 * 1024;

        // Unknown size - need StreamSaver to avoid memory issues
        // Treat as large file (requires ServiceWorker)
        const isUnknownSize = fileSize == null || fileSize <= 0;
        const isSmallFile = !isUnknownSize && fileSize <= USE_BLOB_THRESHOLD;

        if (isSmallFile) {
            return null; // Small files always supported (BlobWriter)
        }

        // Large or unknown size files require ServiceWorker + StreamSaver
        const canUseSW = location.protocol === 'https:' ||
                        location.hostname === 'localhost' ||
                        location.hostname === '127.0.0.1';

        if (!canUseSW) {
            return 'ServiceWorker not available (requires HTTPS or localhost)';
        }

        if (!('serviceWorker' in navigator)) {
            return 'ServiceWorker not supported by browser';
        }

        if (typeof streamSaver === 'undefined') {
            return 'StreamSaver library not loaded';
        }

        return null;
    }

    static isSupported(fileSize) {
        return this.getUnsupportedReason(fileSize) === null;
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DownloadManager, BlobWriter, WriterFactory };
} else {
    window.DownloadManager = DownloadManager;
    window.BlobWriter = BlobWriter;
    window.WriterFactory = WriterFactory;
}
