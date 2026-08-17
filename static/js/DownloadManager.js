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

class DownloadIssueReporter {
    static FORM_ID = 'downloadIssueForm';
    static STORAGE_KEY = 'ffl_download_issue_report_v2';
    static FEEDBACK_TONE_COLORS = {
        info: '#0c5460',
        success: '#155724',
        error: '#721c24',
    };

    constructor(config = {}) {
        if (typeof config.log !== 'function' || !config.log.logger || typeof config.log.logger.addReporter !== 'function') {
            throw new Error('DownloadIssueReporter requires log.logger');
        }

        this.senderEndpoint = config.senderEndpoint || '';
        this.developerEndpoint = config.developerEndpoint || '';
        this.reportModeParam = config.reportModeParam || 'report_error';
        this.reportModeValue = config.reportModeValue || 'true';
        this.reportIdParam = config.reportIdParam || 'report_id';
        this.batchSize = Number.isFinite(config.batchSize) ? Math.max(1, config.batchSize) : 20;
        this.flushDelayMs = Number.isFinite(config.flushDelayMs) ? Math.max(250, config.flushDelayMs) : 2500;
        this.source = config.source || 'download-page';
        this.logFunction = config.log;

        this.buffer = [];
        this.flushTimer = null;
        this.activeDraft = null;
        this.isDiagnosticActive = false;
        this.listenersInstalled = false;
        this.diagnosticFinalized = false;
        this.boundDownloadManager = null;
        this.downloadManagerUnsubscribers = [];
        this.logFunction.logger.addReporter(this);
        this._initialize();
    }

    static safeStringify(value) {
        if (value instanceof Error) {
            return `${value.name}: ${value.message}${value.stack ? `\n${value.stack}` : ''}`;
        }

        if (typeof value === 'string') {
            return value;
        }

        try {
            return JSON.stringify(value);
        } catch (jsonErr) {
            try {
                return String(value);
            } catch (stringErr) {
                return '[unserializable value]';
            }
        }
    }

    static createId() {
        if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
            return crypto.randomUUID();
        }

        return `report-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    }

    _initialize() {
        this.bindModalActions();

        if (this.isDiagnosticMode()) {
            this.startDiagnosticMode();
        }
    }

    attachToDownloadManager(downloadManager) {
        if (
            !downloadManager
            || typeof downloadManager.registerOnDownloadComplete !== 'function'
            || typeof downloadManager.registerOnDownloadError !== 'function'
        ) {
            throw new Error('DownloadIssueReporter requires a DownloadManager instance');
        }

        if (this.boundDownloadManager === downloadManager) {
            return;
        }

        this.detachFromDownloadManager();
        this.boundDownloadManager = downloadManager;
        this.downloadManagerUnsubscribers = [
            downloadManager.registerOnDownloadComplete(() => {
                this.markDownloadComplete();
            }),
            downloadManager.registerOnDownloadError((message) => {
                this.markDownloadError(message);
            }),
        ].filter((unsubscribe) => typeof unsubscribe === 'function');
    }

    detachFromDownloadManager() {
        this.downloadManagerUnsubscribers.forEach((unsubscribe) => {
            unsubscribe();
        });
        this.downloadManagerUnsubscribers = [];
        this.boundDownloadManager = null;
    }

    log(logObj) {
        const normalizedLogObj = (
            typeof window !== 'undefined'
            && window.FFLLogging
            && typeof window.FFLLogging.normalizeLogObject === 'function'
        )
            ? window.FFLLogging.normalizeLogObject(logObj)
            : {
                category: logObj.category || logObj.tag || 'log',
                message: typeof logObj.args?.[0] === 'undefined' ? '' : DownloadIssueReporter.safeStringify(logObj.args[0]),
                args: Array.isArray(logObj.args)
                    ? logObj.args.slice(1).map((arg) => DownloadIssueReporter.safeStringify(arg))
                    : [],
                timestamp: logObj.date instanceof Date ? logObj.date.toISOString() : new Date(logObj.date).toISOString(),
            };

        this.captureLog({
            category: normalizedLogObj.category,
            message: normalizedLogObj.message,
            args: normalizedLogObj.args,
            timestamp: normalizedLogObj.timestamp,
        });
    }

    isDiagnosticMode() {
        const params = new URLSearchParams(window.location.search || '');
        return params.get(this.reportModeParam) === this.reportModeValue;
    }

    currentReportIdFromUrl() {
        const params = new URLSearchParams(window.location.search || '');
        return params.get(this.reportIdParam) || '';
    }

    extractUid() {
        const parts = (window.location.pathname || '').split('/').filter(Boolean);
        return parts.length > 0 ? parts[0] : '';
    }

    bindModalActions() {
        const form = document.getElementById(DownloadIssueReporter.FORM_ID);
        if (!form) {
            return;
        }

        const submitButton = document.getElementById('downloadIssueSubmitBtn');
        const diagnoseButton = document.getElementById('downloadIssueDiagnoseBtn');

        if (submitButton) {
            submitButton.addEventListener('click', () => {
                this.submitIssue({ requestDiagnostics: false });
            });
        }

        if (diagnoseButton) {
            diagnoseButton.addEventListener('click', () => {
                this.submitIssue({ requestDiagnostics: true });
            });
        }
    }

    showFeedback(message, tone = 'info') {
        const feedback = document.getElementById('downloadIssueFeedback');
        if (!feedback) {
            return;
        }

        feedback.textContent = message;
        feedback.style.display = 'block';
        feedback.style.color = DownloadIssueReporter.FEEDBACK_TONE_COLORS[tone]
            || DownloadIssueReporter.FEEDBACK_TONE_COLORS.info;
    }

    setButtonsDisabled(disabled) {
        ['downloadIssueSubmitBtn', 'downloadIssueDiagnoseBtn'].forEach((id) => {
            const button = document.getElementById(id);
            if (button) {
                button.disabled = disabled;
            }
        });
    }

    collectFormPayload() {
        const form = document.getElementById(DownloadIssueReporter.FORM_ID);
        if (!form) {
            return null;
        }

        const selectedReason = form.querySelector('input[name="downloadIssueReason"]:checked');
        if (!selectedReason) {
            if (typeof form.reportValidity === 'function') {
                form.reportValidity();
            }

            return null;
        }

        const detailsElement = document.getElementById('downloadIssueDetails');
        return {
            reportId: DownloadIssueReporter.createId(),
            uid: this.extractUid(),
            reason: selectedReason.value,
            details: detailsElement ? detailsElement.value.trim() : '',
            path: window.location.pathname,
            url: window.location.href,
            referrer: document.referrer || '',
            userAgent: navigator.userAgent,
            source: this.source,
            submittedAt: new Date().toISOString(),
        };
    }

    collectDeliveryOptions() {
        const notifySenderElement = document.getElementById('downloadIssueNotifySender');
        const sendDeveloperElement = document.getElementById('downloadIssueSendDeveloper');

        return {
            notifySender: !!(notifySenderElement && notifySenderElement.checked),
            sendDeveloper: !!(sendDeveloperElement && sendDeveloperElement.checked),
        };
    }

    buildSubmissionState({ requestDiagnostics }) {
        const basePayload = this.collectFormPayload();
        if (!basePayload) {
            return null;
        }

        const deliveryOptions = this.collectDeliveryOptions();
        if (requestDiagnostics) {
            deliveryOptions.sendDeveloper = true;
        }

        if (!deliveryOptions.notifySender && !deliveryOptions.sendDeveloper) {
            this.showFeedback('Please choose at least one report option.', 'error');
            return null;
        }

        if (deliveryOptions.notifySender && !this.resolveSenderEndpoint(basePayload.uid)) {
            this.showFeedback('Unable to notify the sender for this download.', 'error');
            return null;
        }

        if (deliveryOptions.sendDeveloper && !this.developerEndpoint) {
            this.showFeedback('FastFileLink diagnostics are unavailable for this download.', 'error');
            return null;
        }

        return { basePayload, deliveryOptions };
    }

    resolveSenderEndpoint(uid) {
        if (this.senderEndpoint) {
            return this.senderEndpoint;
        }

        if (!uid) {
            return '';
        }

        return `/${uid}/download/issue`;
    }

    buildDiagnosticUrl(reportId) {
        const nextUrl = new URL(window.location.href);
        nextUrl.searchParams.set('debug', 'true');
        nextUrl.searchParams.set(this.reportModeParam, this.reportModeValue);
        nextUrl.searchParams.set(this.reportIdParam, reportId);
        return nextUrl.toString();
    }

    async submitIssue({ requestDiagnostics }) {
        const submissionState = this.buildSubmissionState({ requestDiagnostics });
        if (!submissionState) {
            return;
        }

        const { basePayload, deliveryOptions } = submissionState;
        this.setButtonsDisabled(true);

        try {
            if (deliveryOptions.notifySender) {
                await this.sendSenderPayload({
                    ...basePayload,
                    action: requestDiagnostics ? 'diagnostic_requested' : 'submit',
                    diagnosticRequested: !!requestDiagnostics,
                });
            }

            if (requestDiagnostics) {
                const draft = {
                    ...basePayload,
                    action: 'diagnostic_requested',
                    diagnosticRequested: true,
                    debugUrl: this.buildDiagnosticUrl(basePayload.reportId),
                };

                this.saveDraft(draft);
                await this.sendDeveloperPayload(draft);
                this.showFeedback(
                    'Diagnostic mode will reload the page once. Please retry the download, then you can close this page after the problem happens again or the download finishes.',
                    'info'
                );

                setTimeout(() => {
                    window.location.href = draft.debugUrl;
                }, 250);
                return;
            }

            if (deliveryOptions.sendDeveloper) {
                await this.sendDeveloperPayload({
                    ...basePayload,
                    action: 'submit',
                    diagnosticRequested: false,
                });
            }

            this.showFeedback('Your report has been sent. Thank you.', 'success');
            this.hideModalSoon();
        } catch (sendErr) {
            this.showFeedback('Unable to send the report right now. Please try again.', 'error');
        } finally {
            this.setButtonsDisabled(false);
        }
    }

    hideModalSoon() {
        const modalElement = document.getElementById('downloadIssueModal');
        if (!modalElement || !window.bootstrap || !window.bootstrap.Modal) {
            return;
        }

        const modal = window.bootstrap.Modal.getInstance(modalElement);
        if (!modal) {
            return;
        }

        setTimeout(() => {
            modal.hide();
        }, 900);
    }

    saveDraft(draft) {
        try {
            sessionStorage.setItem(DownloadIssueReporter.STORAGE_KEY, JSON.stringify(draft));
        } catch (storageErr) {
        }
    }

    loadDraft() {
        try {
            const raw = sessionStorage.getItem(DownloadIssueReporter.STORAGE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (storageErr) {
            return null;
        }
    }

    clearDraft() {
        try {
            sessionStorage.removeItem(DownloadIssueReporter.STORAGE_KEY);
        } catch (storageErr) {
        }
    }

    startDiagnosticMode() {
        const draft = this.loadDraft();
        const reportId = this.currentReportIdFromUrl() || (draft && draft.reportId) || DownloadIssueReporter.createId();

        this.activeDraft = {
            reportId,
            uid: (draft && draft.uid) || this.extractUid(),
            reason: (draft && draft.reason) || '',
            details: (draft && draft.details) || '',
            submittedAt: (draft && draft.submittedAt) || new Date().toISOString(),
            source: (draft && draft.source) || this.source,
        };
        this.isDiagnosticActive = true;
        this.diagnosticFinalized = false;
        this.clearDraft();
        this.showDiagnosticBanner();
        this.installWindowListeners();

        this.sendDeveloperPayload({
            ...this.activeDraft,
            action: 'diagnostic_started',
            path: window.location.pathname,
            url: window.location.href,
            referrer: document.referrer || '',
            userAgent: navigator.userAgent,
        }).catch(() => {
        });
    }

    showDiagnosticBanner() {
        const downloadBlock = document.getElementById('downloadBlock');
        if (!downloadBlock || document.getElementById('download-report-error-status')) {
            return;
        }

        const banner = document.createElement('div');
        banner.id = 'download-report-error-status';
        banner.className = 'alert alert-info';
        banner.style.marginTop = '15px';
        banner.style.textAlign = 'left';
        banner.textContent = 'Diagnostic mode is active for this retry. Please retry the download once, then you can close this page after the same problem happens again or after the download finishes.';
        downloadBlock.insertBefore(banner, downloadBlock.firstChild);
    }

    installWindowListeners() {
        if (this.listenersInstalled) {
            return;
        }

        this.listenersInstalled = true;

        window.addEventListener('error', (event) => {
            this.captureLog({
                category: 'window.error',
                message: event.error
                    ? DownloadIssueReporter.safeStringify(event.error)
                    : `${event.message} @ ${event.filename}:${event.lineno}:${event.colno}`,
                args: [],
                timestamp: new Date().toISOString(),
            });
        });

        window.addEventListener('unhandledrejection', (event) => {
            this.captureLog({
                category: 'window.unhandledrejection',
                message: DownloadIssueReporter.safeStringify(event.reason),
                args: [],
                timestamp: new Date().toISOString(),
            });
        });

        const flushOnExit = () => {
            this.flush({ final: true, state: 'page_exit', useBeacon: true });
        };

        window.addEventListener('pagehide', flushOnExit);
        window.addEventListener('beforeunload', flushOnExit);
    }

    shouldIgnoreLog(entry) {
        if (!entry) {
            return true;
        }

        if (entry.category === 'Status') {
            return true;
        }

        const renderedArgs = Array.isArray(entry.args)
            ? entry.args.map((arg) => DownloadIssueReporter.safeStringify(arg)).join(' ')
            : '';
        const fullText = `${entry.message || ''} ${renderedArgs}`;
        return fullText.includes('/status');
    }

    captureLog(entry) {
        if (!this.isDiagnosticActive || this.shouldIgnoreLog(entry)) {
            return;
        }

        const normalizedEntry = {
            timestamp: entry.timestamp || new Date().toISOString(),
            category: entry.category || 'log',
            message: entry.message || '',
            args: Array.isArray(entry.args)
                ? entry.args.map((arg) => DownloadIssueReporter.safeStringify(arg))
                : [],
        };

        this.buffer.push(normalizedEntry);
        this.scheduleFlush();
    }

    scheduleFlush() {
        if (this.diagnosticFinalized) {
            return;
        }

        if (this.buffer.length >= this.batchSize) {
            this.flush({ final: false }).catch(() => {
            });
            return;
        }

        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
        }

        this.flushTimer = setTimeout(() => {
            this.flush({ final: false }).catch(() => {
            });
        }, this.flushDelayMs);
    }

    async flush({ final, state = '', useBeacon = false }) {
        if (!this.isDiagnosticActive || !this.activeDraft) {
            return;
        }

        if (final && this.diagnosticFinalized) {
            return;
        }

        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }

        const entries = this.buffer.splice(0, this.buffer.length);
        if (!entries.length && !final) {
            return;
        }

        const payload = {
            ...this.activeDraft,
            action: 'diagnostic_logs',
            path: window.location.pathname,
            url: window.location.href,
            referrer: document.referrer || '',
            userAgent: navigator.userAgent,
            state,
            final: !!final,
            entries,
            sentAt: new Date().toISOString(),
        };

        await this.sendDeveloperPayload(payload, { useBeacon });

        if (final) {
            this.diagnosticFinalized = true;
        }
    }

    markDownloadComplete() {
        if (!this.isDiagnosticActive) {
            return;
        }

        this.flush({ final: true, state: 'download_complete' }).catch(() => {
        });
    }

    markDownloadError(message) {
        if (!this.isDiagnosticActive) {
            return;
        }

        this.captureLog({
            category: 'download.error',
            message: String(message || 'download_error'),
            args: [],
            timestamp: new Date().toISOString(),
        });
        this.flush({ final: true, state: 'download_error' }).catch(() => {
        });
    }

    async sendSenderPayload(payload) {
        const endpoint = this.resolveSenderEndpoint(payload.uid);
        if (!endpoint) {
            return;
        }

        await this.sendJSON(endpoint, payload, {
            mode: 'same-origin',
            credentials: 'same-origin',
        });
    }

    async sendDeveloperPayload(payload, { useBeacon = false } = {}) {
        if (!this.developerEndpoint) {
            return;
        }

        await this.sendJSON(this.developerEndpoint, payload, {
            mode: 'cors',
            credentials: 'omit',
            useBeacon,
        });
    }

    async sendJSON(endpoint, payload, { mode, credentials, useBeacon = false }) {
        const body = JSON.stringify(payload);
        if (useBeacon && navigator.sendBeacon) {
            const blob = new Blob([body], { type: 'application/json' });
            navigator.sendBeacon(endpoint, blob);
            return;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            mode,
            credentials,
            keepalive: useBeacon,
            headers: {
                'Content-Type': 'application/json',
            },
            body,
        });

        if (!response.ok) {
            throw new Error(`Download issue report failed: ${response.status}`);
        }
    }
}

const DEFAULT_MAX_AUTOMATIC_WRITER_RESUME_ATTEMPTS = 8;
const WRITER_RESUME_ATTEMPT_SIZE_STEP = 512 * 1024 * 1024;
const DEFAULT_READER_CANCEL_TIMEOUT_MS = 1500;
const DEFAULT_WRITER_READ_STALL_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_FETCH_RESPONSE_RESUME_BASE_DELAY_MS = 5000;
const DEFAULT_FETCH_RESPONSE_RESUME_MAX_DELAY_MS = 60000;
const DEFAULT_MAX_FETCH_RESPONSE_RETRY_ATTEMPTS = 8;

class WriterResumeDiagnostics {
    constructor(options = {}) {
        this.enabled = !!options.enabled;
        this.latestState = null;

        if (this.enabled && typeof window !== 'undefined') {
            window.__FFL_GET_WRITER_RESCUE_STATE__ = () => this.snapshot();
        }
    }

    record({ transferState = null, pendingResumeRequest = null, readStallTimeoutMs = 0, patch = {} } = {}) {
        if (!this.enabled || typeof window === 'undefined') {
            return;
        }

        const currentBytes = transferState && typeof transferState.getReceivedBytes === 'function'
            ? transferState.getReceivedBytes()
            : 0;

        this.latestState = {
            readStallTimeoutMs,
            pendingResumeRequest: !!pendingResumeRequest,
            hasCurrentTransfer: !!transferState,
            downloadPath: transferState ? (transferState.downloadPath || '') : '',
            currentBytes,
            expectedSize: transferState ? (transferState.expectedSize || 0) : 0,
            externalResumeRequested: !!(transferState && transferState.externalResumeRequested),
            lastEventAt: Date.now(),
            ...patch,
        };

        // Keep a single snapshot object for backward-compatible test introspection.
        window.__FFL_WRITER_RESCUE_STATE__ = this.snapshot();
    }

    snapshot() {
        return this.latestState ? { ...this.latestState } : null;
    }
}

class WriterResumeRetryPolicy {
    constructor(options = {}) {
        this.fetchResponseBaseDelayMs = Number.isFinite(options.fetchResponseBaseDelayMs)
            ? Math.max(0, options.fetchResponseBaseDelayMs)
            : DEFAULT_FETCH_RESPONSE_RESUME_BASE_DELAY_MS;
        this.fetchResponseMaxDelayMs = Number.isFinite(options.fetchResponseMaxDelayMs)
            ? Math.max(this.fetchResponseBaseDelayMs, options.fetchResponseMaxDelayMs)
            : DEFAULT_FETCH_RESPONSE_RESUME_MAX_DELAY_MS;
        this.maxFetchResponseRetryAttempts = Number.isFinite(options.maxFetchResponseRetryAttempts)
            ? Math.max(1, options.maxFetchResponseRetryAttempts)
            : DEFAULT_MAX_FETCH_RESPONSE_RETRY_ATTEMPTS;
    }

    getRetryDelayMs(error, attemptIndex) {
        if (!error || error.code !== 'FFL_FETCH_RESPONSE_STALL') {
            return 0;
        }

        const normalizedAttempt = Math.max(1, attemptIndex);
        const delayMs = this.fetchResponseBaseDelayMs * Math.pow(2, normalizedAttempt - 1);
        return Math.min(delayMs, this.fetchResponseMaxDelayMs);
    }

    async waitBeforeRetry(error, attemptIndex, logger) {
        const delayMs = this.getRetryDelayMs(error, attemptIndex);
        if (!delayMs) {
            return;
        }

        if (typeof logger === 'function') {
            logger(
                'DownloadManager',
                `Waiting ${delayMs}ms before automatic writer resume retry (${attemptIndex}) due to ${error.code || 'unknown'}`
            );
        }

        await new Promise((resolve) => setTimeout(resolve, delayMs));
    }

    resolveRetryDecision(error, context = {}) {
        const {
            mainAttemptIndex = 0,
            mainAttemptLimit = 0,
            fetchResponseRetryIndex = 0,
        } = context;

        if (error && error.code === 'FFL_FETCH_RESPONSE_STALL') {
            const nextFetchResponseRetryIndex = fetchResponseRetryIndex + 1;
            return {
                allowed: nextFetchResponseRetryIndex <= this.maxFetchResponseRetryAttempts,
                countAgainstMainAttempts: false,
                mainAttemptIndex,
                mainAttemptLimit,
                fetchResponseRetryIndex: nextFetchResponseRetryIndex,
                fetchResponseRetryLimit: this.maxFetchResponseRetryAttempts,
            };
        }

        const nextMainAttemptIndex = mainAttemptIndex + 1;
        return {
            allowed: nextMainAttemptIndex <= mainAttemptLimit,
            countAgainstMainAttempts: true,
            mainAttemptIndex: nextMainAttemptIndex,
            mainAttemptLimit,
            fetchResponseRetryIndex: 0,
            fetchResponseRetryLimit: this.maxFetchResponseRetryAttempts,
        };
    }
}

class WriterResumeController {
    constructor(manager, options = {}) {
        this.manager = manager;
        const pageParams = new URLSearchParams(window.location.search || '');
        const stallMsFromUrl = pageParams.has('writer-stall-ms')
            ? WriterResumeController.parseNonNegativeNumber(pageParams.get('writer-stall-ms'))
            : null;
        const rescueDebugFromUrl = pageParams.has('writer-rescue-debug')
            ? !/^(0|false|no|off)$/i.test(String(pageParams.get('writer-rescue-debug') || '').trim())
            : false;
        this.readStallTimeoutMs = Number.isFinite(options.readStallTimeoutMs)
            ? Math.max(0, options.readStallTimeoutMs)
            : (stallMsFromUrl !== null ? stallMsFromUrl : DEFAULT_WRITER_READ_STALL_TIMEOUT_MS);
        this.diagnostics = new WriterResumeDiagnostics({
            enabled: !!(
                options.debugStateEnabled ||
                rescueDebugFromUrl ||
                (typeof window !== 'undefined' && window.__FFL_DEBUG_WRITER_RESCUE__)
            )
        });
        this.currentTransfer = null;
        this.pendingResumeRequest = null;
    }

    updateState(transferState, patch = {}) {
        this.diagnostics.record({
            transferState: transferState || this.currentTransfer || null,
            pendingResumeRequest: this.pendingResumeRequest,
            readStallTimeoutMs: this.readStallTimeoutMs,
            patch,
        });
    }

    getDebugSnapshot() {
        return this.diagnostics.snapshot();
    }

    static parseNonNegativeNumber(value) {
        const num = Number(value);
        return Number.isFinite(num) && num >= 0 ? num : null;
    }

    getUrlSizeHint(urlPath) {
        try {
            const urlObj = new URL(urlPath, window.location.origin);
            return WriterResumeController.parseNonNegativeNumber(urlObj.searchParams.get('size')) || 0;
        } catch (error) {
            return 0;
        }
    }

    resolveTransferTotal(primaryTotal, resumeConfig = null, urlPath = null, totalBytesHint = 0) {
        const candidates = [
            primaryTotal,
            resumeConfig && resumeConfig.expectedSize,
            totalBytesHint,
            urlPath ? this.getUrlSizeHint(urlPath) : 0
        ].filter(value => typeof value === 'number' && value > 0);

        return candidates.length ? Math.max(...candidates) : 0;
    }

    resolveAttemptLimit(configuredLimit, expectedSize) {
        const baseLimit = Number.isFinite(configuredLimit) ? Math.max(0, configuredLimit) : 0;
        if (!expectedSize || expectedSize <= 0) {
            return baseLimit;
        }

        const sizeBasedLimit = Math.ceil(expectedSize / WRITER_RESUME_ATTEMPT_SIZE_STEP) + 8;
        return Math.max(baseLimit, sizeBasedLimit);
    }

    async cancelReaderAfterTransferError(reader, transferError, timeoutMs = DEFAULT_READER_CANCEL_TIMEOUT_MS) {
        if (!reader || typeof reader.cancel !== 'function') {
            return 'missing-reader';
        }

        const cancelTask = reader.cancel(transferError)
            .then(() => 'cancelled')
            .catch(() => 'cancel-error');

        const timeoutTask = new Promise((resolve) => {
            setTimeout(() => resolve('timeout'), timeoutMs);
        });

        return Promise.race([cancelTask, timeoutTask]);
    }

    shouldEnableRescue() {
        return this.readStallTimeoutMs > 0;
    }

    beginTransfer(transferState) {
        this.endTransfer();
        this.currentTransfer = {
            ...transferState,
            externalResumeRequested: false,
            stallTimer: null,
            guardSequence: 0
        };
        this.updateState(this.currentTransfer, {
            event: 'begin-transfer',
            phase: 'idle',
        });
        return this.currentTransfer;
    }

    clearStallTimer(transferState) {
        if (!transferState || transferState.stallTimer === null) {
            return;
        }

        clearTimeout(transferState.stallTimer);
        transferState.stallTimer = null;
    }

    endTransfer(transferState = null) {
        const activeTransfer = transferState || this.currentTransfer;
        this.clearStallTimer(activeTransfer);
        this.updateState(activeTransfer, {
            event: 'end-transfer',
            phase: 'idle',
        });
        if (!transferState || transferState === this.currentTransfer) {
            this.currentTransfer = null;
        }
    }

    createReaderStallError(transferState) {
        const receivedBytes = transferState.getReceivedBytes();
        const error = new Error(
            `Reader stalled at ${receivedBytes}/${transferState.expectedSize || '?'} bytes for ${this.readStallTimeoutMs}ms`
        );
        error.code = 'FFL_READER_STALL';
        error.phase = 'reader.read';
        error.receivedBytes = receivedBytes;
        error.expectedSize = transferState.expectedSize || 0;
        error.stallDurationMs = this.readStallTimeoutMs;
        return error;
    }

    createWriterStallError(transferState, chunkBytes = 0) {
        const receivedBytes = transferState.getReceivedBytes();
        const error = new Error(
            `Writer stalled at ${receivedBytes}/${transferState.expectedSize || '?'} bytes for ${this.readStallTimeoutMs}ms`
        );
        error.code = 'FFL_WRITER_STALL';
        error.phase = 'writer.write';
        error.receivedBytes = receivedBytes;
        error.expectedSize = transferState.expectedSize || 0;
        error.stallDurationMs = this.readStallTimeoutMs;
        error.chunkBytes = chunkBytes;
        return error;
    }

    createSwStallError(stallEvent = {}) {
        const receivedBytes = WriterResumeController.parseNonNegativeNumber(stallEvent.delivered) || 0;
        const expectedSize = WriterResumeController.parseNonNegativeNumber(stallEvent.total) || 0;
        const stallDurationMs = WriterResumeController.parseNonNegativeNumber(stallEvent.stallDurationMs) || 0;
        const error = new Error(
            `SW stall at ${receivedBytes}/${expectedSize || '?'} bytes after ${stallDurationMs}ms`
        );
        error.code = 'FFL_SW_STALL';
        error.phase = 'reader.read';
        error.receivedBytes = receivedBytes;
        error.expectedSize = expectedSize;
        error.stallDurationMs = stallDurationMs;
        error.probeStatus = stallEvent.probeStatus || '';
        error.rangeOk = !!stallEvent.rangeOk;
        return error;
    }

    createSwPrematureEOFError(eofEvent = {}) {
        const receivedBytes = WriterResumeController.parseNonNegativeNumber(eofEvent.sent) || 0;
        const expectedSize = WriterResumeController.parseNonNegativeNumber(eofEvent.total) || 0;
        const missingBytes = WriterResumeController.parseNonNegativeNumber(eofEvent.missingBytes) || 0;
        const error = new Error(
            `SW premature EOF at ${receivedBytes}/${expectedSize || '?'} bytes, missing=${missingBytes}`
        );
        error.code = 'FFL_SW_PREMATURE_EOF';
        error.phase = 'reader.read';
        error.receivedBytes = receivedBytes;
        error.expectedSize = expectedSize;
        error.missingBytes = missingBytes;
        error.serverId = eofEvent.serverId || '';
        return error;
    }

    createFetchResponseStallError(transferState) {
        const receivedBytes = transferState.getReceivedBytes();
        const error = new Error(
            `Fetch response stalled at ${receivedBytes}/${transferState.expectedSize || '?'} bytes for ${this.readStallTimeoutMs}ms`
        );
        error.code = 'FFL_FETCH_RESPONSE_STALL';
        error.phase = 'fetch.response';
        error.receivedBytes = receivedBytes;
        error.expectedSize = transferState.expectedSize || 0;
        error.stallDurationMs = this.readStallTimeoutMs;
        return error;
    }

    async fetchResponseWithGuard(fetchPromise, transferState) {
        if (!this.shouldEnableRescue()) {
            return fetchPromise;
        }

        const responsePromise = Promise.resolve(fetchPromise);
        const stallPromise = new Promise((_, reject) => {
            this.updateState(transferState, {
                event: 'fetch-response-guard-armed',
                phase: 'fetch.response'
            });
            transferState.stallTimer = setTimeout(() => {
                const error = this.createFetchResponseStallError(transferState);
                this.updateState(transferState, {
                    event: 'fetch-response-timeout',
                    phase: 'fetch.response',
                    code: error.code,
                    stallDurationMs: error.stallDurationMs || 0,
                });
                try {
                    transferState.abortController.abort(error);
                } catch (_) {}
                reject(error);
            }, this.readStallTimeoutMs);
        });

        try {
            const response = await Promise.race([responsePromise, stallPromise]);
            this.updateState(transferState, {
                event: 'fetch-response-received',
                phase: 'fetch.response'
            });
            return response;
        } finally {
            this.clearStallTimer(transferState);
        }
    }

    requestResume(transferState, error) {
        if (!transferState || transferState.externalResumeRequested) {
            return false;
        }

        transferState.externalResumeRequested = true;
        this.pendingResumeRequest = error;
        this.clearStallTimer(transferState);

        this.manager.log(
            'DownloadManager',
            `Requesting same-writer resume at ${error.receivedBytes}/${error.expectedSize || '?'} bytes via ${error.code}`
        );
        this.updateState(transferState, {
            event: 'request-resume',
            phase: error.phase || 'reader.read',
            code: error.code || '',
            stallDurationMs: error.stallDurationMs || 0,
        });
        try {
            transferState.abortController.abort(error);
        } catch (_) {}

        try {
            if (transferState.reader && typeof transferState.reader.cancel === 'function') {
                transferState.reader.cancel(error).catch(() => {});
            }
        } catch (_) {}

        return true;
    }

    async readWithGuard(reader, transferState) {
        if (!this.shouldEnableRescue()) {
            return reader.read();
        }

        transferState.guardSequence += 1;
        const guardSequence = transferState.guardSequence;
        this.updateState(transferState, {
            event: 'reader-guard-armed',
            phase: 'reader.read',
            guardSequence,
        });
        const readPromise = reader.read();
        const stallPromise = new Promise((_, reject) => {
            transferState.stallTimer = setTimeout(() => {
                const error = this.createReaderStallError(transferState);
                this.updateState(transferState, {
                    event: 'reader-stall-timeout',
                    phase: 'reader.read',
                    guardSequence,
                    code: error.code,
                    stallDurationMs: error.stallDurationMs || 0,
                });
                this.requestResume(transferState, error);
                reject(error);
            }, this.readStallTimeoutMs);
        });

        try {
            const result = await Promise.race([readPromise, stallPromise]);
            this.updateState(transferState, {
                event: result && result.done ? 'reader-read-done' : 'reader-read-value',
                phase: 'reader.read',
                guardSequence,
            });
            return result;
        } finally {
            this.clearStallTimer(transferState);
        }
    }

    async writeWithGuard(writer, chunk, transferState) {
        if (!this.shouldEnableRescue()) {
            return writer.write(chunk);
        }

        const chunkBytes = chunk?.byteLength || 0;
        let timer = null;
        const writePromise = Promise.resolve().then(() => writer.write(chunk));
        const stallPromise = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const error = this.createWriterStallError(transferState, chunkBytes);
                this.updateState(transferState, {
                    event: 'writer-stall-timeout',
                    phase: 'writer.write',
                    code: error.code,
                    stallDurationMs: error.stallDurationMs || 0,
                    chunkBytes,
                });
                this.requestResume(transferState, error);
                reject(error);
            }, this.readStallTimeoutMs);
        });

        try {
            return await Promise.race([writePromise, stallPromise]);
        } finally {
            if (timer !== null) {
                clearTimeout(timer);
            }
        }
    }

    handleDownloadStall(stallEvent = {}) {
        const transferState = this.currentTransfer;
        if (!transferState || transferState.externalResumeRequested) {
            return false;
        }

        if (!String(transferState.downloadPath || '').startsWith('sw_writer')) {
            return false;
        }

        if (!this.shouldEnableRescue()) {
            return false;
        }

        const canResume = !!stallEvent.rangeOk || stallEvent.probeStatus === '206';
        if (!canResume) {
            this.updateState(transferState, {
                event: 'sw-stall-ignored',
                phase: 'reader.read',
                code: 'SW_STALL_NOT_RESUMABLE',
                probeStatus: stallEvent.probeStatus || '',
                rangeOk: !!stallEvent.rangeOk,
                stallDurationMs: stallEvent.stallDurationMs || 0,
            });
            return false;
        }

        this.updateState(transferState, {
            event: 'sw-stall-resume',
            phase: 'reader.read',
            code: 'FFL_SW_STALL',
            probeStatus: stallEvent.probeStatus || '',
            rangeOk: !!stallEvent.rangeOk,
            stallDurationMs: stallEvent.stallDurationMs || 0,
        });
        return this.requestResume(transferState, this.createSwStallError(stallEvent));
    }

    handlePrematureEOF(eofEvent = {}) {
        const transferState = this.currentTransfer;
        if (!transferState || transferState.externalResumeRequested) {
            return false;
        }

        if (!String(transferState.downloadPath || '').startsWith('sw_writer')) {
            return false;
        }

        if (!this.shouldEnableRescue()) {
            return false;
        }

        const receivedBytes = WriterResumeController.parseNonNegativeNumber(eofEvent.sent) || 0;
        const expectedSize = WriterResumeController.parseNonNegativeNumber(eofEvent.total) || 0;
        if (receivedBytes <= 0 || expectedSize <= 0 || receivedBytes >= expectedSize) {
            return false;
        }

        this.updateState(transferState, {
            event: 'sw-premature-eof-resume',
            phase: 'reader.read',
            code: 'FFL_SW_PREMATURE_EOF',
            receivedBytes,
            expectedSize,
            missingBytes: WriterResumeController.parseNonNegativeNumber(eofEvent.missingBytes) || 0,
        });
        return this.requestResume(transferState, this.createSwPrematureEOFError(eofEvent));
    }

    consumePendingResumeRequest(fallbackReceivedBytes, fallbackExpectedSize, originalError) {
        if (!this.pendingResumeRequest) {
            return null;
        }

        const resumeError = this.pendingResumeRequest;
        this.pendingResumeRequest = null;

        const mergedError = new Error(resumeError.message || (originalError && originalError.message) || 'resume requested');
        mergedError.code = resumeError.code;
        mergedError.phase = resumeError.phase || 'reader.read';
        mergedError.receivedBytes = Math.max(fallbackReceivedBytes || 0, resumeError.receivedBytes || 0);
        mergedError.expectedSize = Math.max(fallbackExpectedSize || 0, resumeError.expectedSize || 0);
        mergedError.stallDurationMs = resumeError.stallDurationMs;
        mergedError.probeStatus = resumeError.probeStatus;
        mergedError.rangeOk = resumeError.rangeOk;
        mergedError.missingBytes = resumeError.missingBytes;
        mergedError.cause = originalError || null;
        this.updateState(this.currentTransfer, {
            event: 'consume-pending-resume',
            phase: mergedError.phase || 'reader.read',
            code: mergedError.code || '',
            receivedBytes: mergedError.receivedBytes || 0,
            expectedSize: mergedError.expectedSize || 0,
        });
        return mergedError;
    }
}

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
            const label = dmT('Download:auth.verifying', 'Verifying...');
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
 */
class PubkeyGate {
    constructor(options = {}) {
        this.fileInputId    = options.fileInputId  || 'pubkey-file-input';
        this.fileLabelId    = options.fileLabelId  || 'pubkey-file-label';
        this.errorMsgId     = options.errorMsgId   || 'pubkey-error-message';
        this.containerId    = options.containerId  || null;
        this.challenges     = Array.isArray(options.challenges) ? options.challenges : [];
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

        let proof = null;
        for (const challenge of this.challenges) {
            const ciphertextBytes = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));
            try {
                const plaintext = await crypto.subtle.decrypt(
                    { name: 'RSA-OAEP' }, privateKey, ciphertextBytes.buffer
                );
                proof = btoa(String.fromCharCode(...new Uint8Array(plaintext)));
                break;
            } catch (_e) {
            }
        }

        if (!proof) {
            err.textContent = this.t('Download:pubkey.decryptError', 'Decryption failed — wrong private key.');
            err.style.display = 'block';
            throw new Error('decrypt-failed');
        }

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
 */
class EmailGate {
    constructor(options = {}) {
        this.containerId    = options.containerId    || null;
        this.sendBtnId      = options.sendBtnId      || 'email-send-btn';
        this.emailInputSectionId = options.emailInputSectionId || 'email-address-input-section';
        this.emailInputId   = options.emailInputId   || 'email-address-input';
        this.otpSectionId   = options.otpSectionId   || 'email-otp-section';
        this.otpInputId     = options.otpInputId     || 'email-otp-input';
        this.emailDisplayId = options.emailDisplayId || 'email-address-display';
        this.statusMsgId    = options.statusMsgId    || 'email-status-message';
        this.errorMsgId     = options.errorMsgId     || 'email-error-message';
        this.recipientEmails = Array.isArray(options.recipientEmails) ? options.recipientEmails : [];
        this.otpRequestUrl  = options.otpRequestUrl  || null;
        this.allowlistVerifyEndpoint = options.allowlistVerifyEndpoint || null;
        this.verifyEndpoint = options.verifyEndpoint || null;
        this.shareLink      = options.shareLink      || window.location.href;
        this.onAccepted     = options.onAccepted     || null;
        this.t              = options.t              || dmT;
        this._otp           = null;
        this._codeSent      = false;
        this._verificationToken = null;

        const sendBtn = document.getElementById(this.sendBtnId);
        if (sendBtn) {
            sendBtn.addEventListener('click', () => this._sendCode());
        }
    }

    get authHeaders() {
        const email = this._resolveRecipientEmail();
        return this._otp ? {
            [EmailGate.HEADER_OTP]:     this._otp,
            [EmailGate.HEADER_ADDRESS]: email,
            [EmailGate.HEADER_LINK]:    this.shareLink,
        } : {};
    }

    show() {
        if (this.containerId) {
            document.getElementById(this.containerId)?.style.setProperty('display', 'block');
        }
        const emailDisplay = document.getElementById(this.emailDisplayId);
        const emailInputSection = document.getElementById(this.emailInputSectionId);
        if (emailDisplay) {
            if (this.recipientEmails.length === 1) {
                emailDisplay.textContent = this.recipientEmails[0];
                emailDisplay.style.display = 'block';
            } else {
                emailDisplay.textContent = '';
                emailDisplay.style.display = 'none';
            }
        }
        if (emailInputSection) {
            emailInputSection.style.display = this.recipientEmails.length > 1 ? 'block' : 'none';
        }
    }

    validate() {
        const errorMsg = document.getElementById(this.errorMsgId);
        const email = this._resolveRecipientEmail();
        if (!email) {
            errorMsg.textContent = this.t('Download:email.enterAddress', 'Please enter your email address first.');
            errorMsg.style.display = 'block';
            return 'missing-email';
        }
        if (!this._isAllowedEmail(email)) {
            errorMsg.textContent = this.t('Download:email.notAllowed', 'This email address is not allowed to download this file.');
            errorMsg.style.display = 'block';
            return 'email-not-allowed';
        }
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
        const recipientEmail = this._resolveRecipientEmail();
        this._otp = document.getElementById(this.otpInputId)?.value.trim();
        this._verificationToken = null;
        if (this.verifyEndpoint) {
            const response = await fetch(this.verifyEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: recipientEmail, link: this.shareLink, otp: this._otp }),
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
            const responseData = await response.json().catch(() => ({}));
            this._verificationToken = responseData.verificationToken || null;
        }
        this.onAccepted?.(this._otp, recipientEmail, this.shareLink, this._verificationToken);
    }

    focus() {
        const focusTargetId = this.recipientEmails.length > 1 ? this.emailInputId : this.otpInputId;
        document.getElementById(focusTargetId)?.focus();
    }

    async _sendCode() {
        const errorMsg  = document.getElementById(this.errorMsgId);
        const statusMsg = document.getElementById(this.statusMsgId);
        const sendBtn   = document.getElementById(this.sendBtnId);
        const email = this._resolveRecipientEmail();
        if (!email) {
            if (errorMsg) {
                errorMsg.textContent = this.t('Download:email.enterAddress', 'Please enter your email address first.');
                errorMsg.style.display = 'block';
            }
            return;
        }
        if (!this._isAllowedEmail(email)) {
            if (errorMsg) {
                errorMsg.textContent = this.t('Download:email.notAllowed', 'This email address is not allowed to download this file.');
                errorMsg.style.display = 'block';
            }
            return;
        }

        const originalContent = sendBtn.innerHTML;
        sendBtn.disabled = true;
        sendBtn.innerHTML = `<span class="auth-gate-spinner" style="border-color:rgba(255,255,255,0.4);border-top-color:white;"></span><span>${this.t('Download:email.sending', 'Sending...')}</span>`;
        try {
            if (this.allowlistVerifyEndpoint) {
                const allowlistResponse = await fetch(this.allowlistVerifyEndpoint, {
                    method: 'GET',
                    headers: { [EmailGate.HEADER_ADDRESS]: email },
                });
                if (!allowlistResponse.ok) {
                    if (errorMsg) {
                        errorMsg.textContent = this.t('Download:email.notAllowed', 'This email address is not allowed to download this file.');
                        errorMsg.style.display = 'block';
                    }
                    sendBtn.innerHTML = originalContent;
                    sendBtn.disabled = false;
                    return;
                }
            }

            const resp = await fetch(this.otpRequestUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    link: this.shareLink,
                    language: this._resolveLanguage(),
                }),
            });
            if (resp.ok) {
                sendBtn.innerHTML = originalContent;
                document.getElementById(this.otpSectionId)?.style.setProperty('display', 'block');
                this._codeSent = true;
                if (statusMsg) {
                    statusMsg.textContent = this.t('Download:email.codeSent', 'Code sent! Please check your email.');
                    statusMsg.style.display = 'block';
                }
                if (errorMsg) {
                    errorMsg.style.display = 'none';
                }
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

    _resolveRecipientEmail() {
        if (this.recipientEmails.length === 1) {
            return this.recipientEmails[0];
        }

        const emailInput = document.getElementById(this.emailInputId);
        return emailInput ? emailInput.value.trim().toLowerCase() : '';
    }

    _resolveLanguage() {
        const resolvedLanguage = window.i18next?.resolvedLanguage || window.i18next?.language;
        if (resolvedLanguage) {
            return resolvedLanguage;
        }

        if (typeof navigator !== 'undefined' && navigator.language) {
            return navigator.language;
        }

        return 'en';
    }

    _isAllowedEmail(email) {
        const normalizedEmail = (email || '').trim().toLowerCase();
        if (!normalizedEmail) {
            return false;
        }
        return this.recipientEmails.map(candidate => candidate.toLowerCase()).includes(normalizedEmail);
    }
}
EmailGate.HEADER_OTP     = 'X-FFL-EmailOTP';
EmailGate.HEADER_ADDRESS = 'X-FFL-EmailAddress';
EmailGate.HEADER_LINK    = 'X-FFL-EmailLink';

/**
 * ReceiptConfirmationUI — post-download dialog that asks the receiver to send a receipt.
 *
 * Usage:
 *   const rc = new ReceiptConfirmationUI({
 *       endpoint: '/uid=xxxx/receipt/confirm',
 *       message:  'Please confirm you received the file.',   // optional override
 *       dialogId: 'receipt-confirm-dialog',                  // optional
 *   });
 *   rc.show(serverMessage);   // called from /complete response handler
 */
class ReceiptConfirmationUI {
    constructor(options = {}) {
        this.endpoint  = options.endpoint  || null;
        this.message   = options.message   || null;
        this.dialogId  = options.dialogId  || 'receipt-confirm-dialog';
        this._log      = options.logFunction || dmLog;
        this._t        = options.tFunction   || dmT;
        this._bound    = false;
    }

    show(message) {
        const dialog = document.getElementById(this.dialogId);
        if (!dialog) return;

        const msgEl = document.getElementById('receipt-confirm-sender-msg');
        if (msgEl) msgEl.textContent = message || this.message || '';

        dialog.style.display = 'block';

        if (!this._bound) {
            this._bound = true;
            this._bindButtons();
        }
    }

    async sendNotification(message) {
        if (!this.endpoint) {
            return;
        }

        try {
            await fetch(this.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message }),
            });
        } catch (e) {
            this._log('ReceiptConfirm', 'Failed to send notification: ' + e);
            throw e;
        }
    }

    _bindButtons() {
        const sendBtn  = document.getElementById('receipt-confirm-send-btn');
        const skipBtn  = document.getElementById('receipt-confirm-skip-btn');

        const hideDialog = () => {
            const dialog = document.getElementById(this.dialogId);
            if (dialog) dialog.style.display = 'none';
        };

        const showThanks = () => {
            const thanks = document.getElementById('receipt-confirm-thanks');
            if (thanks) thanks.style.display = 'block';
        };

        if (sendBtn) {
            sendBtn.addEventListener('click', async () => {
                const reply   = (document.getElementById('receipt-confirm-reply')?.value || '').trim();
                const spinner = document.getElementById('receipt-confirm-spinner');

                sendBtn.disabled = true;
                if (skipBtn) skipBtn.disabled = true;
                if (spinner) {
                    spinner.textContent = this._t('Download:receiptConfirm.sending', 'Sending…');
                    spinner.style.display = 'inline';
                }

                if (this.endpoint) {
                    try {
                        await this.sendNotification(reply);
                    } catch (e) {
                        this._log('ReceiptConfirm', 'Failed to send confirmation: ' + e);
                    }
                }

                if (spinner) spinner.style.display = 'none';
                hideDialog();
                showThanks();
            });
        }

        if (skipBtn) {
            skipBtn.addEventListener('click', () => hideDialog());
        }
    }
}

class DownloadManager {
    constructor(options = {}) {
        // Configuration
        this.DEBUG = options.debug !== undefined ? options.debug : true;
        this.uid = options.uid || this.extractUidFromPath();
        this.isFirefox = navigator.userAgent.includes('Firefox');
        
        // Firefox hybrid strategy configuration
        this.FF_SW_LIMIT = options.ffSwLimit || 512 * 1024 * 1024; // 512MB default threshold
        
        // Debug-friendly route profiles. Keep route selection centralized so we can
        // test different download paths without scattering ad-hoc query handling.
        this.DOWNLOAD_ROUTE_PROFILES = Object.freeze({
            auto: Object.freeze({
                name: 'auto',
                mode: null,
                description: 'Browser-default route selection'
            }),
            sw: Object.freeze({
                name: 'sw',
                mode: 'sw',
                description: 'Force Service Worker TransformStream route'
            }),
            pass: Object.freeze({
                name: 'pass',
                mode: 'pass',
                description: 'Force browser passthrough route'
            })
        });
        this.routeOverride = this.getRequestedRouteProfile();
        
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
        this.fileNameElement = options.fileNameElement || '#fileName';
        
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
        this.writerAutoResumeUsed = false;
        this.completionHandled = false;
        this.completionReplayTimer = null;
        this.completionReplayAttempts = 0;
        this.completionReplayIntervalMs = options.completionReplayIntervalMs || 30000;
        this.maxCompletionReplayAttempts = Number.isFinite(options.maxCompletionReplayAttempts)
            ? Math.max(0, options.maxCompletionReplayAttempts)
            : 960; // 8 hours at the default 30s interval.

        // Server-assigned download ID for POST /complete ACK (relay truncation fix)
        this.serverDownloadId = null;
        this.serverAckSent = false;
        this.activeDownloadPath = null;

        // Resume support state
        this.resumeConfig = null;
        this.maxAutomaticWriterResumeAttempts = Number.isFinite(options.maxAutomaticWriterResumeAttempts)
            ? Math.max(0, options.maxAutomaticWriterResumeAttempts)
            : DEFAULT_MAX_AUTOMATIC_WRITER_RESUME_ATTEMPTS;
        this.writerResumeRetryPolicy = new WriterResumeRetryPolicy(options.writerResumeRetryPolicy || {});
        this.writerResumeController = new WriterResumeController(this, options.writerResumeController || {});
        
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

        // Receipt confirmation dialog (optional — set to a ReceiptConfirmationUI instance)
        this.receiptConfirmationUI = options.receiptConfirmationUI || null;

        // Callback functions for external integration
        this._lifecycleCallbacks = {
            serviceWorkerReady: new Set(),
            downloadStart: new Set(),
            downloadComplete: new Set(),
            downloadError: new Set(),
        };
        this._registerLifecycleCallback('serviceWorkerReady', options.onServiceWorkerReadyCallback, { allowMissing: true });
        this._registerLifecycleCallback('downloadStart', options.onDownloadStartCallback, { allowMissing: true });
        this._registerLifecycleCallback('downloadComplete', options.onDownloadCompleteCallback, { allowMissing: true });
        this._registerLifecycleCallback('downloadError', options.onDownloadErrorCallback, { allowMissing: true });

        // Custom log function (if provided, use it; otherwise use default dmLog)
        this.customLogFn = options.logFunction || null;

        // BroadcastChannel for SW progress updates
        this.dlChannel = ('BroadcastChannel' in window) ? new BroadcastChannel('dl-progress') : null;
        this.serviceWorkerMessageHandler = null;

        // Bind methods
        this.log = this.log.bind(this);
        this.t = this.t.bind(this);
        this.formatBytes = this.formatBytes.bind(this);
        this.calculateSpeed = this.calculateSpeed.bind(this);
        
        // Initialize
        this.setupBroadcastChannel();
        this.setupServiceWorkerMessageHandler();
        this.setupVisibilityChangeHandler();
    }

    _registerLifecycleCallback(eventName, callback, { allowMissing = false } = {}) {
        if (typeof callback !== 'function') {
            if (allowMissing) {
                return null;
            }
            throw new Error(`${eventName} callback must be a function`);
        }

        this._lifecycleCallbacks[eventName].add(callback);
        return () => {
            this._lifecycleCallbacks[eventName].delete(callback);
        };
    }

    registerOnServiceWorkerReady(callback) {
        return this._registerLifecycleCallback('serviceWorkerReady', callback);
    }

    registerOnDownloadStart(callback) {
        return this._registerLifecycleCallback('downloadStart', callback);
    }

    registerOnDownloadComplete(callback) {
        return this._registerLifecycleCallback('downloadComplete', callback);
    }

    registerOnDownloadError(callback) {
        return this._registerLifecycleCallback('downloadError', callback);
    }

    async _notifyLifecycleCallbacks(eventName, args = [], { awaitCallbacks = false } = {}) {
        const callbacks = Array.from(this._lifecycleCallbacks[eventName] || []);
        for (const callback of callbacks) {
            try {
                const result = callback(...args);
                if (awaitCallbacks) {
                    await result;
                }
            } catch (e) {
                this.log('DownloadManager', `Error in ${eventName} callback:`, e);
            }
        }
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

    getFileSizeFromMetadata() {
        const fileSizeElement = document.getElementById('fileSize');
        if (!fileSizeElement) {
            return 0;
        }

        const sizeText = fileSizeElement.textContent || fileSizeElement.innerText || '0';
        const size = parseInt(sizeText.trim(), 10);
        return isNaN(size) ? 0 : size;
    }

    buildAutoDownloadPlan(size) {
        if (!this.isFirefox) {
            return { browser: 'chromium', size, mode: 'sw' };
        }

        // Firefox's Service Worker TransformStream download route can
        // prematurely appear as completed while the payload is still incomplete.
        // Track upstream at:
        // https://bugzilla.mozilla.org/show_bug.cgi?id=2033956
        if (this.isValidSize(size) && size <= this.FF_SW_LIMIT) {
            return { browser: 'firefox', size, mode: 'sw' };
        }

        return { browser: 'firefox', size, mode: 'pass' };
    }

    normalizeRouteProfileValue(value) {
        if (!value) {
            return null;
        }

        const normalized = String(value).trim().toLowerCase();
        const aliases = {
            auto: 'auto',
            default: 'auto',
            sw: 'sw',
            transform: 'sw',
            transformstream: 'sw',
            firefox_sw: 'sw',
            'firefox-sw': 'sw',
            pass: 'pass',
            passthrough: 'pass',
            ff_pass: 'pass',
            'ff-pass': 'pass',
            firefox_pass: 'pass',
            'firefox-pass': 'pass'
        };

        return aliases[normalized] || null;
    }

    getRequestedRouteProfile() {
        const searchParams = new URLSearchParams(window.location.search || '');
        const rawValue = searchParams.get('route');
        if (rawValue) {
            const profileName = this.normalizeRouteProfileValue(rawValue);
            if (!profileName) {
                this.log('DownloadManager', `Ignoring unknown route profile override from route: ${rawValue}`);
                return null;
            }

            return {
                key: 'route',
                rawValue,
                profile: this.DOWNLOAD_ROUTE_PROFILES[profileName]
            };
        }

        return null;
    }

    propagatePageDownloadDebugParams(downloadUrl) {
        const searchParams = new URLSearchParams(window.location.search || '');
        const paramMappings = [
            ['inject-premature-eof-after', 'inject-premature-eof-after'],
            ['writer-stall-ms', 'stallMs']
        ];

        for (const [sourceParam, targetParam] of paramMappings) {
            if (!searchParams.has(sourceParam) || downloadUrl.searchParams.has(targetParam)) {
                continue;
            }
            downloadUrl.searchParams.set(targetParam, searchParams.get(sourceParam));
        }
    }

    applyRouteProfile(plan, routeOverride) {
        const resolvedPlan = {
            ...plan,
            routeProfile: 'auto',
            routeProfileSource: 'planner'
        };

        if (!routeOverride || !routeOverride.profile || !routeOverride.profile.mode) {
            return resolvedPlan;
        }

        const overriddenPlan = {
            ...resolvedPlan,
            mode: routeOverride.profile.mode,
            routeProfile: routeOverride.profile.name,
            routeProfileSource: routeOverride.key
        };

        this.log(
            'DownloadManager',
            `Applying route profile override: ${routeOverride.profile.name} (from ${routeOverride.key}=${routeOverride.rawValue})`
        );
        return overriddenPlan;
    }

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
     * @param {Object} options - Options object with uid and fileName
     * @returns {Object} Plan object with browser, size, and mode
     */
    getPlannedMode({ uid, fileName } = {}) {
        const size = this.getFileSizeFromMetadata();

        const sizeDesc = this.isUnknownSize(size) ? 'unknown' : this.formatBytes(size);
        this.log('DownloadManager', `File size detected from metadata: ${size} bytes (${sizeDesc})`);

        const autoPlan = this.buildAutoDownloadPlan(size);
        return this.applyRouteProfile(autoPlan, this.routeOverride);
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

    // Whether the server serves E2EE Range/resume reads chunk-aligned
    // (protocol v2+, from the "version" field of /e2ee/manifest, stamped into
    // the decryptor context by E2EEManager.setupHTTPDecryptor). Legacy servers
    // (no version) encrypted Range reads from the raw requested offset -- the
    // old nonce-reuse hazard -- so against them E2EE must only ever be a full
    // download from byte 0.
    e2eeAlignedRangeSupported() {
        const context = this.httpDecryptor ? this.httpDecryptor.e2eeContext : null;
        return !!(context && Number.isInteger(context.version) && context.version >= 2);
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
        this._notifyLifecycleCallbacks('downloadStart', [id, total]).catch(() => {});
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
        if (this.completionHandled) {
            this.log('DownloadManager', 'Download completion already handled, ignoring duplicate event');
            return;
        }

        this.completionHandled = true;
        this.log('DownloadManager', 'Download complete');
        this.stopProgressMonitoring();
        this.stopCompletionReplayChecks();
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
        if (this.serverDownloadId && this.uid && !this.serverAckSent) {
            this.sendServerCompleteAck(resolvedTotal || 0);
        }

        // Call external callback if provided
        this._notifyLifecycleCallbacks('downloadComplete', [total]).catch(() => {});
    }

    handleDownloadCompleteEvent(data = {}, source = 'event') {
        if (data.serverId) {
            this.serverDownloadId = data.serverId;
        }
        if (data.downloadPath) {
            this.activeDownloadPath = data.downloadPath;
        }
        this.serverAckSent = this.serverAckSent || !!data.serverAckSent;

        // When the SW drives the download (native <a> tag path), it POSTs the
        // completion ACK itself instead of the page -- see sendServerCompleteAck,
        // which is skipped above via serverAckSent. So the SW's own ACK is the
        // only place that ever saw /complete's response body, and it must relay
        // confirmRequired/message here or the receipt-confirm dialog never shows.
        if (this.receiptConfirmationUI && data.confirmRequired) {
            this.receiptConfirmationUI.show(data.confirmMessage);
        }

        this.log('DownloadManager', `Handling download-complete from ${source}`, data);
        this.handleDownloadComplete(data.total || data.sent || this.totalBytesHint || 0);
    }

    handleDownloadError(message) {
        this.log('DownloadManager', 'Download error:', message);
        this.stopProgressMonitoring();
        this.stopCompletionReplayChecks();
        if (this.adaptiveUnlockTimer) {
            clearTimeout(this.adaptiveUnlockTimer);
            this.adaptiveUnlockTimer = null;
        }
        if (!this.downloadStarted && !this.newTabOpened) {
            this.showRetryLink();
        }

        // Call external callback if provided
        this._notifyLifecycleCallbacks('downloadError', [message]).catch(() => {});
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

    handleDownloadSignal(eventData, source = 'broadcast') {
        if (!eventData || typeof eventData !== 'object') {
            return;
        }

        const { type, sent, total, id } = eventData;
        if (!type) {
            return;
        }

        this.log('DownloadManager', `${source} event received:`, eventData);

        // Filter events by download ID to prevent cross-tab interference
        if (id && this.activeDlId && id !== this.activeDlId) {
            return;
        }

        if (type === 'download-started') {
            this.handleDownloadStarted(id, total, sent);
        } else if (type === 'download-progress') {
            this.handleDownloadProgress(sent, total);
        } else if (type === 'download-complete') {
            this.handleDownloadCompleteEvent(eventData, eventData.replayed ? 'sw-replay' : source);
        } else if (type === 'download-premature-eof') {
            const handled = this.writerResumeController.handlePrematureEOF(eventData);
            this.log(
                'DownloadManager',
                `SW premature EOF detected: sent=${eventData.sent}/${eventData.total}, missing=${eventData.missingBytes}, handled=${handled}`
            );
        } else if (type === 'download-stall') {
            this.log('DownloadManager', `SW stall [${eventData.phase}]: delivered=${eventData.delivered}/${eventData.total} (${eventData.percent}%), probe=${eventData.probeStatus}, rangeOk=${eventData.rangeOk}, stallMs=${eventData.stallDurationMs}`);
            this.writerResumeController.handleDownloadStall(eventData);
        } else if (type === 'download-error') {
            this.handleDownloadError(eventData.message);
        } else if (type === 'download-checksum') {
            this.handleChecksumVerificationResult(eventData, eventData.transport || 'http');
        } else if (type === 'debug' && eventData.message) {
            this.log('ProgressSW', eventData.message);
        }
    }

    setupBroadcastChannel() {
        if (this.dlChannel) {
            this.dlChannel.onmessage = (evt) => {
                this.handleDownloadSignal(evt.data, 'broadcast');
            };
        }
    }

    setupServiceWorkerMessageHandler() {
        if (!('serviceWorker' in navigator) || !navigator.serviceWorker) {
            return;
        }

        this.serviceWorkerMessageHandler = (event) => {
            this.handleDownloadSignal(event.data, 'sw-message');
        };
        navigator.serviceWorker.addEventListener('message', this.serviceWorkerMessageHandler);
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

                if (!this.isTabHidden) {
                    this.queryServiceWorkerCompletion('visibilitychange');
                }
            }
        });

        window.addEventListener('focus', () => {
            this.queryServiceWorkerCompletion('focus');
        });
    }

    canQueryServiceWorkerCompletion() {
        return !!(
            this.activeDlId &&
            !this.completionHandled &&
            typeof MessageChannel !== 'undefined' &&
            navigator.serviceWorker &&
            navigator.serviceWorker.controller
        );
    }

    queryServiceWorkerCompletion(reason = 'manual') {
        if (!this.canQueryServiceWorkerCompletion()) {
            return Promise.resolve(false);
        }

        const controller = navigator.serviceWorker.controller;
        const requestId = (crypto?.randomUUID && crypto.randomUUID()) || String(Date.now() + Math.random());

        this.log('DownloadManager', `Querying SW completion state (${reason}) for ${this.activeDlId}`);

        return new Promise((resolve) => {
            const channel = new MessageChannel();
            const timeout = setTimeout(() => {
                channel.port1.onmessage = null;
                this.log('DownloadManager', `SW completion query timed out (${reason})`);
                resolve(false);
            }, 2000);

            channel.port1.onmessage = (event) => {
                clearTimeout(timeout);
                const data = event.data || {};

                if (data.type !== 'download-completion-state' || data.requestId !== requestId) {
                    resolve(false);
                    return;
                }

                if (!data.found || !data.completion) {
                    resolve(false);
                    return;
                }

                const completion = data.completion;
                if (completion.id && completion.id !== this.activeDlId) {
                    resolve(false);
                    return;
                }

                this.handleDownloadCompleteEvent(completion, `sw-query:${reason}`);
                resolve(true);
            };

            try {
                controller.postMessage({
                    type: 'query-download-completion',
                    requestId,
                    downloadId: this.activeDlId
                }, [channel.port2]);
            } catch (e) {
                clearTimeout(timeout);
                this.log('DownloadManager', `Failed to query SW completion state (${reason}):`, e);
                resolve(false);
            }
        });
    }

    scheduleCompletionReplayChecks() {
        this.stopCompletionReplayChecks();

        if (!this.canQueryServiceWorkerCompletion()) {
            return;
        }

        this.completionReplayAttempts = 0;
        this.completionReplayTimer = setInterval(() => {
            if (!this.canQueryServiceWorkerCompletion()) {
                this.stopCompletionReplayChecks();
                return;
            }

            this.completionReplayAttempts += 1;
            if (this.completionReplayAttempts > this.maxCompletionReplayAttempts) {
                this.log('DownloadManager', 'Stopping SW completion replay checks after max attempts');
                this.stopCompletionReplayChecks();
                return;
            }

            this.queryServiceWorkerCompletion('timer');
        }, this.completionReplayIntervalMs);

        setTimeout(() => {
            this.queryServiceWorkerCompletion('initial');
        }, 3000);
    }

    stopCompletionReplayChecks() {
        if (this.completionReplayTimer) {
            clearInterval(this.completionReplayTimer);
            this.completionReplayTimer = null;
        }
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
        this.stopCompletionReplayChecks();
        
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
        if (this.serviceWorkerMessageHandler && 'serviceWorker' in navigator && navigator.serviceWorker) {
            navigator.serviceWorker.removeEventListener('message', this.serviceWorkerMessageHandler);
            this.serviceWorkerMessageHandler = null;
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
     * @param {Object} options - Options with fileName, size, and indeterminate flag
     */
    showStartingUI({ fileName, size, indeterminate }) {
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

        this.log('DownloadManager', `Starting UI shown for ${fileName} (${sizeStr}), indeterminate: ${isIndeterminate}`);
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

            const reg = await navigator.serviceWorker.register(this.serviceWorkerPath, {
                scope: this.serviceWorkerScope
            });

            // Skip navigator.serviceWorker.ready — in Firefox it blocks 1-2s waiting for SW
            // activation even when clients.claim() has already fired. Instead use controller
            // directly: already set means the page is controlled (may be an older SW version,
            // but that is acceptable since ProgressServiceWorker.js rarely changes); not set
            // means we wait for controllerchange which fires right after clients.claim().
            if (!navigator.serviceWorker.controller) {
                this.log('DownloadManager', 'Waiting for SW to take control...');

                await new Promise((resolve, reject) => {
                    if (navigator.serviceWorker.controller) { resolve(); return; }

                    const timeout = setTimeout(() => {
                        navigator.serviceWorker.removeEventListener('controllerchange', onCtl);
                        reject(new Error('Timed out waiting for Service Worker controllerchange'));
                    }, 5000);

                    const onCtl = () => {
                        clearTimeout(timeout);
                        this.log('DownloadManager', 'SW now controlling');
                        resolve();
                    };

                    navigator.serviceWorker.addEventListener('controllerchange', onCtl, { once: true });
                });
            }

            const controller = navigator.serviceWorker.controller;

            if (!controller) {
                this.log('DownloadManager', 'SW registered but page is still uncontrolled');
                return false;
            }

            this.log('DownloadManager', 'Progress SW is ready and controlling');

            // Invoke callback when Service Worker is ready and WAIT for it to complete
            await this._notifyLifecycleCallbacks('serviceWorkerReady', [controller], { awaitCallbacks: true });

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

    setDownloadPathParam(downloadUrl, downloadPath) {
        if (!downloadPath) {
            downloadUrl.searchParams.delete('dl_path');
            return;
        }

        downloadUrl.searchParams.set('dl_path', downloadPath);
        this.log('DownloadManager', `Download path recorded as ${downloadPath}`);
    }

    buildServerCompleteAckUrl() {
        const completeUrl = new URL(`/${this.uid}/complete`, window.location.origin);
        if (this.activeDownloadPath) {
            completeUrl.searchParams.set('dl_path', this.activeDownloadPath);
        }
        return completeUrl.pathname + completeUrl.search;
    }

    async sendServerCompleteAck(receivedBytes) {
        if (!this.serverDownloadId || !this.uid) {
            return null;
        }

        if (this.serverAckSent) {
            this.log('DownloadManager', 'Server completion ACK already sent, skipping duplicate page ACK');
            return null;
        }

        const downloadId = this.serverDownloadId;
        const completeUrl = this.buildServerCompleteAckUrl();
        this.serverAckSent = true;

        this.log(
            'DownloadManager',
            `Notifying server of HTTP download completion, downloadId: ${downloadId}, path: ${this.activeDownloadPath || 'unknown'}`
        );

        try {
            const response = await fetch(completeUrl, {
                method: 'POST',
                keepalive: true,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ downloadId, receivedBytes: receivedBytes || 0 }),
            });

            const data = await response.json().catch(() => null);
            if (this.receiptConfirmationUI && data && data.confirmRequired) {
                this.receiptConfirmationUI.show(data.message);
            }
            return data;
        } catch (err) {
            this.log('DownloadManager', `Failed to notify server of HTTP completion: ${err}`);
            return null;
        } finally {
            this.serverDownloadId = null;
        }
    }

    resolveDownloadPath({
        useServiceWorker = false,
        hasWriter = false,
        hasResumeConfig = false,
        forceWriter = false,
        forceNativeLink = false
    } = {}) {
        if (forceNativeLink) {
            return 'direct_native_link';
        }

        if (useServiceWorker) {
            if (hasWriter && hasResumeConfig) {
                return 'sw_writer_resume';
            }

            if (hasWriter && forceWriter) {
                return 'sw_writer';
            }

            return 'sw_native_link';
        }

        if (hasWriter && hasResumeConfig) {
            return 'direct_writer_resume';
        }

        if (hasWriter) {
            return 'direct_writer';
        }

        return 'direct_native_link';
    }

    buildAutomaticWriterResumeUrl(urlPath, resumeConfig = null) {
        const urlObj = new URL(urlPath, window.location.origin);

        // Writer resume still needs the Service Worker for auth headers and Range
        // construction, but the page is now consuming the response stream directly
        // and appending it to the existing writer. Keep the SW in passthrough mode
        // so Firefox does not wrap the resumed long-lived body in TransformStream
        // again, which can report a premature EOF as a completed native download.
        urlObj.searchParams.set('ff_pass', '1');

        if (resumeConfig && resumeConfig.rangeStart > 0) {
            urlObj.searchParams.set('resume_start', String(resumeConfig.rangeStart));
        } else {
            urlObj.searchParams.delete('resume_start');
        }

        if (resumeConfig && resumeConfig.baseBytes > 0) {
            urlObj.searchParams.set('resume_base', String(resumeConfig.baseBytes));
        } else {
            urlObj.searchParams.delete('resume_base');
        }

        if (resumeConfig && resumeConfig.skipBytes > 0) {
            urlObj.searchParams.set('resume_skip', String(resumeConfig.skipBytes));
        } else {
            urlObj.searchParams.delete('resume_skip');
        }

        if (resumeConfig && resumeConfig.expectedSize > 0) {
            urlObj.searchParams.set('resume_expected', String(resumeConfig.expectedSize));
        } else {
            urlObj.searchParams.delete('resume_expected');
        }

        urlObj.searchParams.set('ff_auto_resume', '1');
        this.setDownloadPathParam(urlObj, 'sw_writer_resume');
        this.activeDownloadPath = 'sw_writer_resume';
        return urlObj.pathname + urlObj.search;
    }

    buildAutomaticWriterResumeConfig(baseBytes, expectedSize) {
        if (!Number.isFinite(baseBytes) || baseBytes <= 0) {
            return null;
        }

        return this.normalizeResumeOptions({
            baseBytes,
            rangeStart: baseBytes,
            skipBytes: 0,
            expectedSize: expectedSize || 0
        });
    }

    getUrlSizeHint(urlPath) {
        return this.writerResumeController.getUrlSizeHint(urlPath);
    }

    resolveWriterTransferTotal(primaryTotal, resumeConfig = null, urlPath = null) {
        return this.writerResumeController.resolveTransferTotal(
            primaryTotal,
            resumeConfig,
            urlPath,
            this.totalBytesHint
        );
    }

    resolveWriterResumeAttemptLimit(expectedSize) {
        return this.writerResumeController.resolveAttemptLimit(
            this.maxAutomaticWriterResumeAttempts,
            expectedSize
        );
    }

    async cancelReaderAfterTransferError(reader, transferError, timeoutMs = DEFAULT_READER_CANCEL_TIMEOUT_MS) {
        return this.writerResumeController.cancelReaderAfterTransferError(
            reader,
            transferError,
            timeoutMs
        );
    }

    getWriterRescueDebugSnapshot() {
        return this.writerResumeController.getDebugSnapshot();
    }

    createPrematureEOFError(receivedBytes, expectedSize) {
        const error = new Error(
            `Premature EOF while reading download stream: received ${receivedBytes} of ${expectedSize} bytes`
        );
        error.code = 'FFL_PREMATURE_EOF';
        error.phase = 'reader.read';
        error.receivedBytes = receivedBytes;
        error.expectedSize = expectedSize;
        return error;
    }

    parseResumedResponseMetadata(response, activeResume, e2eeAlignmentDiscard = 0) {
        const contentRange = response.headers.get('Content-Range');
        const resumeMode = response.headers.get('FFL-Resume-Mode');
        const resumeStartHeader = this.parsePositiveNumber(response.headers.get('FFL-Resume-Start'));

        if (response.status === 206 && contentRange) {
            const match = contentRange.match(/^bytes\s+(\d+)-(\d+)\/(\d+)$/i);
            if (match) {
                const start = parseInt(match[1], 10);
                const full = parseInt(match[3], 10);
                
                // With E2EE, the server aligns the actual read down to the encryption
                // chunk boundary (a partial GCM block can't be tag-verified), so it
                // legitimately starts earlier than requested by up to one chunk --
                // e2eeAlignmentDiscard is that exact, independently-computed amount.
                const expectedStart = activeResume.rangeStart - e2eeAlignmentDiscard;
                if (start !== expectedStart) {
                    throw new Error(`Server returned mismatched range start: ${start} != ${expectedStart}`);
                }

                this.log('DownloadManager', `206 Partial Content: ${contentRange}, total=${full}`);
                return full;
            }
        }

        if (
            response.status === 206 &&
            resumeMode === 'handoff' &&
            resumeStartHeader === activeResume.rangeStart
        ) {
            this.log(
                'DownloadManager',
                `206 handoff resume accepted without Content-Range, start=${resumeStartHeader}`
            );
            return activeResume.expectedSize || 0;
        }

        if (response.status === 200) {
            this.log('DownloadManager', 'WARNING: Server ignored Range header (200), using client-side discard');
            const len = response.headers.get('Content-Length');
            return len ? parseInt(len, 10) : 0;
        }

        throw new Error(`Unexpected response status for ranged request: ${response.status}`);
    }

    async fetchToWriter(urlPath, writer, needsDecryption, resume = null, progressCallback = null, checksumVerifier = null) {
        this.writerAutoResumeUsed = false;

        // Against a legacy (pre-v2) E2EE server, a Range read is encrypted from
        // the raw requested offset, so resuming mid-writer can't decrypt
        // correctly -- and a partially-written writer can't be rewound to
        // restart from zero. Fail closed here; startDownload() already falls
        // back to a full download before a resume ever reaches this point.
        const e2eeRangeSupported = !needsDecryption || this.e2eeAlignedRangeSupported();
        if (!e2eeRangeSupported && resume && resume.rangeStart > 0) {
            throw new Error('E2EE resume is not supported by this server (protocol < 2)');
        }

        let activeUrlPath = urlPath;
        let activeResume = resume;
        let activeProgressCallback = progressCallback;
        let finalTotalSize = 0;
        let attemptIndex = 0;
        let fetchResponseRetryIndex = 0;

        while (true) {
            
            // AES-GCM nonces are derived from a chunk index, so the server always
            // aligns the actual read down to the encryption chunk boundary when
            // E2EE is enabled (a partial GCM block can't be tag-verified) -- see
            // CryptoHelper.alignChunkStart in bases/E2EE.py. That means an
            // unaligned resume gets a few extra plaintext bytes at the front of
            // the first decrypted chunk that must be discarded, same as the
            // existing client-side discard used for the stdin-handoff/200-fallback
            // paths below.
            let e2eeAlignmentDiscard = 0;

            if (needsDecryption) {
                this.log('DownloadManager', 'E2EE decryption will be applied during resume (bypassing Service Worker)');

                if (!this.httpDecryptor) {
                    const error = 'E2EE resume requires httpDecryptor (should have been created upfront)';
                    this.log('DownloadManager', 'ERROR:', error);
                    throw new Error(error);
                }

                this.log('DownloadManager', 'Using existing HTTPDecryptor instance from constructor');
                if (activeResume && typeof activeResume.rangeStart === 'number') {
                    this.httpDecryptor.setResumeState(activeResume.rangeStart);
                    e2eeAlignmentDiscard = activeResume.rangeStart % this.httpDecryptor.chunkSize;
                    this.log(
                        'DownloadManager',
                        `HTTPDecryptor resume position set to: ${activeResume.rangeStart}` +
                            (e2eeAlignmentDiscard > 0 ? `, alignment discard: ${e2eeAlignmentDiscard}` : '')
                    );
                }
            }

            const headers = new Headers();
            let wantRange = false;
            if (activeResume && Number.isFinite(activeResume.rangeStart) && activeResume.rangeStart > 0) {
                headers.set('Range', `bytes=${activeResume.rangeStart}-`);
                wantRange = true;
                this.log(
                    'DownloadManager',
                    `Resume request: Range bytes=${activeResume.rangeStart}-, skipBytes=${activeResume.skipBytes || 0}`
                );
            }
            if (this.authHeaders) {
                for (const [key, value] of Object.entries(this.authHeaders)) {
                    headers.set(key, value);
                }
            }

            const baseBytes = activeResume?.baseBytes || 0;
            
            let totalSizeFromServer = 0;
            let expectedTotal = this.resolveWriterTransferTotal(0, activeResume, activeUrlPath);
            let reader = null;
            let totalWritten = 0;
            let firstChunk = true;
            let bytesToDiscard = (activeResume?.skipBytes ? Math.max(0, activeResume.skipBytes) : 0) + e2eeAlignmentDiscard;
            
            const abortController = new AbortController();
            
            const transferState = this.writerResumeController.beginTransfer({
                urlPath: activeUrlPath,
                downloadPath: this.activeDownloadPath,
                abortController,
                reader: null,
                expectedSize: expectedTotal,
                getReceivedBytes: () => baseBytes + totalWritten
            });
            
            const discardInitialChunk = (chunk, label) => {
                if (!firstChunk || bytesToDiscard <= 0) {
                    return chunk;
                }
                if (chunk.byteLength <= bytesToDiscard) {
                    this.log(
                        'DownloadManager',
                        `Discarding ${label} (${chunk.byteLength} bytes), remaining=${bytesToDiscard - chunk.byteLength}`
                    );
                    bytesToDiscard -= chunk.byteLength;
                    return null;
                }

                this.log(
                    'DownloadManager',
                    `Discarding ${bytesToDiscard} bytes from ${label}, keeping ${chunk.byteLength - bytesToDiscard}`
                );
                chunk = chunk.subarray(bytesToDiscard);
                bytesToDiscard = 0;
                return chunk;
            };
            
            const writeChunk = async (chunk, label) => {
                try {
                    await this.writerResumeController.writeWithGuard(writer, chunk, transferState);
                } catch (writeError) {
                    const error = new Error(`Writer failed while writing ${label}: ${writeError.message || writeError}`);
                    error.code = 'FFL_WRITER_WRITE_ERROR';
                    error.phase = 'writer.write';
                    error.cause = writeError;
                    error.receivedBytes = baseBytes + totalWritten;
                    error.expectedSize = expectedTotal;
                    throw error;
                }
                totalWritten += chunk.byteLength;
                fetchResponseRetryIndex = 0;

                if (activeProgressCallback) {
                    activeProgressCallback(baseBytes + totalWritten, expectedTotal || totalSizeFromServer);
                }
            };

            try {
                const response = await this.writerResumeController.fetchResponseWithGuard(
                    fetch(activeUrlPath, {
                        headers,
                        cache: 'no-cache',
                        signal: abortController.signal
                    }),
                    transferState
                );
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const serverDlId = response.headers.get('FFL-DownloadId');
                if (serverDlId) {
                    this.serverDownloadId = serverDlId;
                }

                if (wantRange) {
                    totalSizeFromServer = this.parseResumedResponseMetadata(response, activeResume, e2eeAlignmentDiscard);
                    if (totalSizeFromServer > 0) {
                        this.totalBytesHint = Math.max(this.totalBytesHint || 0, totalSizeFromServer);
                    }
                } else {
                    const len = response.headers.get('Content-Length');
                    if (len) {
                        totalSizeFromServer = parseInt(len, 10);
                    }
                }

                expectedTotal = this.resolveWriterTransferTotal(totalSizeFromServer, activeResume, activeUrlPath);
                transferState.expectedSize = expectedTotal;
                reader = response.body.getReader();
                transferState.reader = reader;
                this.log('DownloadManager', 'Fetch response received, reading stream');

                while (true) {
                    let readResult;
                    try {
                        readResult = await this.writerResumeController.readWithGuard(reader, transferState);
                    } catch (readError) {
                        const error = new Error(`Reader failed while streaming download: ${readError.message || readError}`);
                        error.code = 'FFL_STREAM_READ_ERROR';
                        error.phase = 'reader.read';
                        error.cause = readError;
                        error.receivedBytes = baseBytes + totalWritten;
                        error.expectedSize = expectedTotal;
                        throw error;
                    }

                    const { done, value } = readResult;
                    if (done) {
                        // HTTPDecryptor buffers a final encrypted fragment smaller than its
                        // normal chunk size.  Flush it before checking the plaintext byte
                        // count; otherwise a valid final partial chunk looks like a premature
                        // EOF and the writer-resume loop retries the same tail indefinitely.
                        if (needsDecryption) {
                            let finalChunk;
                            try {
                                finalChunk = await this.httpDecryptor.flush();
                                this.log(
                                    'DownloadManager',
                                    `E2EE resume: Flushed final buffered chunk, decrypted size: ${finalChunk.byteLength}`
                                );
                            } catch (decryptError) {
                                this.log('DownloadManager', 'ERROR: E2EE final-chunk decryption failed during resume:', decryptError);
                                
                                const error = new Error('E2EE final-chunk decryption failed: ' + decryptError.message);
                                error.code = 'FFL_E2EE_DECRYPT_ERROR';
                                error.phase = 'decrypt.flush';
                                error.cause = decryptError;
                                error.receivedBytes = baseBytes + totalWritten;
                                error.expectedSize = expectedTotal;
                                throw error;
                            }

                            finalChunk = discardInitialChunk(finalChunk, 'final chunk');
                            firstChunk = false;

                            if (finalChunk && finalChunk.byteLength > 0) {
                                await writeChunk(finalChunk, 'final download chunk');
                            }
                        }

                        const receivedBytes = baseBytes + totalWritten;
                        if (expectedTotal > 0 && receivedBytes < expectedTotal) {
                            throw this.createPrematureEOFError(receivedBytes, expectedTotal);
                        }
                        this.log('DownloadManager', 'Stream read complete, total written:', totalWritten);
                        finalTotalSize = Math.max(finalTotalSize, totalSizeFromServer, expectedTotal);
                        break;
                    }

                    let chunk = value;
                    if (checksumVerifier) {
                        checksumVerifier.update(chunk);
                    }

                    if (needsDecryption) {
                        try {
                            const encryptedSize = chunk.byteLength;
                            chunk = await this.httpDecryptor.decryptChunk(chunk);
                            this.log(
                                'DownloadManager',
                                `E2EE resume: Chunk decrypted, encrypted size: ${encryptedSize}, decrypted size: ${chunk.byteLength}`
                            );
                        } catch (decryptError) {
                            this.log('DownloadManager', 'ERROR: E2EE decryption failed during resume:', decryptError);
                            const error = new Error('E2EE decryption failed: ' + decryptError.message);
                            error.code = 'FFL_E2EE_DECRYPT_ERROR';
                            error.phase = 'decrypt';
                            error.cause = decryptError;
                            error.receivedBytes = baseBytes + totalWritten;
                            error.expectedSize = expectedTotal;
                            throw error;
                        }
                    }

                    chunk = discardInitialChunk(chunk, 'chunk');
                    if (!chunk) {
                        continue;
                    }
                    firstChunk = false;
                    await writeChunk(chunk, 'download chunk');
                }
            } catch (transferError) {
                const pendingResumeError = this.writerResumeController.consumePendingResumeRequest(
                    baseBytes + totalWritten,
                    expectedTotal || this.resolveWriterTransferTotal(totalSizeFromServer, activeResume, activeUrlPath),
                    transferError
                );
                if (pendingResumeError) {
                    transferError = pendingResumeError;
                }

                const cancelResult = await this.cancelReaderAfterTransferError(reader, transferError);
                if (cancelResult === 'cancel-error') {
                    this.log('DownloadManager', 'Reader cancel after failure did not complete cleanly');
                } else if (cancelResult === 'timeout') {
                    this.log('DownloadManager', 'Reader cancel after failure timed out, continuing with resume');
                }

                const writtenBytes = baseBytes + totalWritten;
                const retryExpectedSize = expectedTotal || this.resolveWriterTransferTotal(totalSizeFromServer, activeResume, activeUrlPath);
                const attemptLimit = this.resolveWriterResumeAttemptLimit(retryExpectedSize);
                const retryDecision = this.writerResumeRetryPolicy.resolveRetryDecision(transferError, {
                    mainAttemptIndex: attemptIndex,
                    mainAttemptLimit: attemptLimit,
                    fetchResponseRetryIndex,
                });
                const canRetry = retryDecision.allowed;

                if (!canRetry || (!writtenBytes && !retryExpectedSize)) {
                    throw transferError;
                }

                // Same legacy-server constraint as the entry guard above: an
                // automatic Range retry after partial delivery would decrypt
                // misaligned ciphertext, so fail closed instead of resuming.
                if (!e2eeRangeSupported && writtenBytes > 0) {
                    this.log('DownloadManager', 'E2EE writer auto-resume blocked: server protocol < 2');
                    throw transferError;
                }

                attemptIndex = retryDecision.mainAttemptIndex;
                fetchResponseRetryIndex = retryDecision.fetchResponseRetryIndex;
                this.writerAutoResumeUsed = true;
                activeResume = this.buildAutomaticWriterResumeConfig(writtenBytes, retryExpectedSize);
                this.resumeConfig = activeResume;
                activeUrlPath = this.buildAutomaticWriterResumeUrl(urlPath, activeResume);
                if (!activeProgressCallback) {
                    activeProgressCallback = this.handleDownloadProgress.bind(this);
                }

                this.log(
                    'DownloadManager',
                    retryDecision.countAgainstMainAttempts
                        ? `Automatic writer resume triggered (${attemptIndex}/${attemptLimit}) after ${writtenBytes} bytes:`
                        : `Automatic writer resume triggered (fetch-response ${fetchResponseRetryIndex}/${retryDecision.fetchResponseRetryLimit}, main ${attemptIndex}/${attemptLimit}) after ${writtenBytes} bytes:`,
                    transferError
                );
                this.log('DownloadManager', 'Automatic writer resume URL:', activeUrlPath);
                await this.writerResumeRetryPolicy.waitBeforeRetry(
                    transferError,
                    retryDecision.countAgainstMainAttempts ? attemptIndex : fetchResponseRetryIndex,
                    this.log.bind(this)
                );
                continue;
            } finally {
                this.writerResumeController.endTransfer(transferState);
            }

            break;
        }

        await writer.close();
        this.log('DownloadManager', 'Writer closed successfully after writer download/resume flow');

        if (checksumVerifier) {
            try {
                const checksumResult = await checksumVerifier.finalizeAndVerify();
                this.pendingChecksumResult = checksumResult;
            } catch (verifyError) {
                this.log('Checksum', 'Failed to verify HTTP checksum:', verifyError);
            }
        }

        return finalTotalSize;
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

    async startNativeDownload(url, fileName, {
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
        this.completionHandled = false;
        this.stopCompletionReplayChecks();
        this.serverAckSent = false;
        this.activeDownloadPath = null;

        this.log('DownloadManager', 'Starting native download', {
            hasWriter: !!writer,
            progressSwSupported,
            hasResumeConfig: !!resumeConfig,
            forceWriter,
            forceNativeLink
        });

        const downloadUrl = new URL(url, location.origin);
        this.ensureDownloadId(downloadUrl);
        this.propagatePageDownloadDebugParams(downloadUrl);
        const useServiceWorker = progressSwSupported;
        const downloadPath = this.resolveDownloadPath({
            useServiceWorker,
            hasWriter: !!writer,
            hasResumeConfig: !!resumeConfig,
            forceWriter,
            forceNativeLink
        });
        this.setDownloadPathParam(downloadUrl, downloadPath);
        this.activeDownloadPath = downloadPath;
        this.log('DownloadManager', 'Download URL with token:', downloadUrl.href);

        if (forceNativeLink) {
            this.log('DownloadManager', 'BRANCH: forceNativeLink → native <a> download (cookie auth only, no SW header injection)');
            this.handleDownloadStarted(this.activeDlId, this.totalBytesHint || 0, 0);
            this.triggerNativeDownloadLink(downloadUrl.pathname + downloadUrl.search);
            return;
        }

        if (this.authHeaders && useServiceWorker && navigator.serviceWorker && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'auth-headers',
                downloadId: this.activeDlId,
                headers: this.authHeaders
            });
        }

        if (useServiceWorker) {
            // Case A: Service Worker is available
            if (writer && resumeConfig) {
                // Keep ProgressServiceWorker in the path for auth/range handling, but avoid
                // wrapping the resumed long-lived body in TransformStream when the page itself
                // will consume the response stream and forward it into an existing writer.
                downloadUrl.searchParams.set('ff_pass', '1');
                this.log('DownloadManager', 'BRANCH: SW + writer + resumeConfig -> fetchToWriter via SW passthrough resume');

                const needsDecryption = this.e2eeEnabled;
                const progressCallback = this.handleDownloadProgress.bind(this);
                const checksumVerifier = this.createChecksumVerifierForHTTP(resumeConfig);
                const expectedSize = resumeConfig.expectedSize || this.totalBytesHint || 0;

                try {
                    const totalSize = await this.fetchToWriter(
                        downloadUrl.pathname + downloadUrl.search,
                        writer,
                        needsDecryption,
                        resumeConfig,
                        progressCallback,
                        checksumVerifier
                    );

                    this.handleDownloadComplete(totalSize || expectedSize);
                    if (this.pendingChecksumResult) {
                        this.handleChecksumVerificationResult(this.pendingChecksumResult, 'http');
                        this.pendingChecksumResult = null;
                    }
                } catch (err) {
                    this.log('DownloadManager', 'SW passthrough resume -> writer failed:', err);
                    this.handleDownloadError(String(err));
                }
                return;
            }

            if (writer && forceWriter) {
                // Has SW + writer, but no resume. Keep TransformStream path for ZIP preview and
                // other writer-first flows that depend on SW-driven progress events.
                this.log('DownloadManager', 'BRANCH: SW + writer + forceWriter -> fetchToWriter (SW handles download)');
                const needsDecryption = false;
                const progressCallback = null;  // SW broadcasts events
                return this.fetchToWriter(
                    downloadUrl.pathname + downloadUrl.search,
                    writer,
                    needsDecryption,
                    null,  // Resume handled by SW
                    progressCallback,
                    null
                ).then(totalSize => {
                    if (!this.writerAutoResumeUsed) {
                        return totalSize;
                    }

                    this.handleDownloadComplete(totalSize || this.totalBytesHint || 0);
                    if (this.pendingChecksumResult) {
                        this.handleChecksumVerificationResult(this.pendingChecksumResult, 'http');
                        this.pendingChecksumResult = null;
                    }
                    return totalSize;
                }).catch(err => {
                    this.log('DownloadManager', 'Writer-based download failed:', err);
                    this._notifyLifecycleCallbacks('downloadError', [String(err)]).catch(() => {});
                });
            } else {
                // Has SW + no resumeConfig (or no writer)
                // Use <a> tag, let SW handle everything (including all events)
                this.log('DownloadManager', 'BRANCH: SW without resumeConfig → <a> tag (SW handles download)');
                this.scheduleCompletionReplayChecks();
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

            // Add passthrough routing flag when the selected route profile bypasses
            // the TransformStream path and lets the browser consume the download directly.
            if (plan.mode === 'pass') {
                urlObj.searchParams.set('ff_pass', '1');
                this.log(
                    'DownloadManager',
                    `Added ff_pass=1 for pass-through route (${plan.routeProfile || 'auto'}, ${this.formatBytes(plan.size) || 'unknown size'})`
                );
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
        let writer = options.writer || null;
        const forceWriter = options.forceWriter || false;
        const forceNativeLink = options.forceNativeLink || false;

        let resumeConfig = this.setResumeConfig(options.resume);

        if (resumeConfig && this.e2eeEnabled && !this.e2eeAlignedRangeSupported()) {
            // Legacy (pre-v2) E2EE server: Range reads are encrypted from the
            // raw requested offset, so resume decryption can't line up chunk
            // indexes/nonces. Abandon the resume (and any partially-written
            // file -- it can't be safely appended to) and restart as a clean
            // full download from byte 0. Loses resume, not correctness.
            this.log('DownloadManager', 'E2EE resume not supported by this server (protocol < 2) - restarting as full download');
            resumeConfig = this.setResumeConfig(null);
            if (writer) {
                try {
                    writer.abort();
                } catch (abortError) {
                    this.log('DownloadManager', 'Writer abort during E2EE legacy-server fallback failed:', abortError);
                }
                writer = null;
            }
        }

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
        const $fileNameEl = $(this.fileNameElement);
        const fileName = ($fileNameEl.val() || $fileNameEl.text()).trim() || 'download';

        // Get the planned download mode based on browser and file size
        const plan = this.getPlannedMode({ uid: this.uid, fileName });
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
        this.showStartingUI({ fileName, size: plan.size, indeterminate: plan.mode !== 'sw' });

        // Firefox large file watchdog: show "started" UI after delay
        if (plan.browser === 'firefox' && plan.mode === 'pass') {
            setTimeout(() => {
                this.showIndeterminateStartedUI();
            }, 4000);
        }

        const progressSwSupported = await this.ensureProgressSWControlled();

        // if ff_pass=1, we still use ProgressServiceWorker.js to handle fetch request, but pass-through browser directly.

        // Unified download entry point - all branches handled in startNativeDownload
        return this.startNativeDownload(url, fileName, {
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
    module.exports = { DownloadManager, BlobWriter, WriterFactory, DownloadIssueReporter };
} else {
    window.DownloadManager = DownloadManager;
    window.BlobWriter = BlobWriter;
    window.WriterFactory = WriterFactory;
    window.DownloadIssueReporter = DownloadIssueReporter;
}
