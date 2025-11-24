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
        this.completeBlock = options.completeBlock || '#completeBlock';
        this.downloadBlock = options.downloadBlock || '#downloadBlock';
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
            if (isNaN(size))
                size = 0;
        }
        
        this.log('DownloadManager', `File size detected from metadata: ${size} bytes (${this.formatBytes(size)})`);
        
        // Decision logic
        if (!this.isFirefox) {
            return { browser: 'chromium', size, mode: 'sw' }; // Chromium: SW + Transform
        }
        
        if (size && size <= this.FF_SW_LIMIT) {
            return { browser: 'firefox', size, mode: 'sw' }; // FF small file: SW
        }
        
        return { browser: 'firefox', size, mode: 'pass' }; // FF large/unknown: pass-through
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
            chunkSize: (chunkSize !== null && chunkSize > 0) ? chunkSize : null,
            writer: resume.writer || null  // Preserve writer reference for continuation
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
                    const initialSent = typeof sent === 'number' ? sent : 0;
                    this.log('DownloadManager', `Download started broadcast received, id=${id}, total=${total}, initialSent=${initialSent}`);
                    this.onDownloadStart(total, initialSent);

                    // Call external callback if provided
                    if (this.onDownloadStartCallback) {
                        try {
                            this.onDownloadStartCallback(id, total);
                        } catch (e) {
                            this.log('DownloadManager', 'Error in onDownloadStartCallback:', e);
                        }
                    }
                } else if (type === 'download-progress') {
                    // Skip progress updates only for Firefox pass-through mode (large files)
                    // Firefox small files using SW should show normal progress like Chromium
                    const shouldShowProgress = !this.currentPlan || this.currentPlan.mode !== 'pass';
                    
                    if (shouldShowProgress) {
                        const resolvedTotal = this.resolveTotalBytes(total);
                        const safeSent = typeof sent === 'number' ? sent : 0;
                        const clampedSent = resolvedTotal ? Math.min(safeSent, resolvedTotal) : safeSent;
                        const percent = resolvedTotal ? (clampedSent / resolvedTotal) * 100 : 0;
                        this.updateProgressBar(percent);
                        
                        const baseBytes = this.resumeConfig ? (this.resumeConfig.baseBytes || 0) : 0;
                        const httpSent = Math.max(0, safeSent - baseBytes);
                        const speed = this.calculateSpeed(httpSent, this.startTime);
                        const transferredStr = this.formatBytes(clampedSent);
                        const totalStr = resolvedTotal ? this.formatBytes(resolvedTotal) : '?';
                        
                        this.updateProgressInfo(`${transferredStr} / ${totalStr}${speed ? ' (' + speed + ')' : ''}`);
                    } else {
                        this.log('DownloadManager', 'Skipping progress update for Firefox pass-through mode');
                    }
                } else if (type === 'download-complete') {
                    this.log('DownloadManager', 'Download complete via broadcast');
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

                    this.updateStatus(this.t('download.complete.title', 'Download completed!'), '');
                    this.showCompleteBlock();

                    // Call external callback if provided
                    if (this.onDownloadCompleteCallback) {
                        try {
                            this.onDownloadCompleteCallback(total);
                        } catch (e) {
                            this.log('DownloadManager', 'Error in onDownloadCompleteCallback:', e);
                        }
                    }
                } else if (type === 'download-error') {
                    console.error('[DownloadManager] Download error via broadcast:', evt.data.message);
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
                            this.onDownloadErrorCallback(evt.data.message);
                        } catch (e) {
                            this.log('DownloadManager', 'Error in onDownloadErrorCallback:', e);
                        }
                    }
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
                this.t('download.progress.backgroundHeading', 'Download is processing in background'),
                this.t('download.progress.backgroundDetailsByPass', 
                  'Check your browser download bar (usually at bottom/top) for progress — or confirmation that the download has already finished.')
            );
            this.updateProgressInfo(this.t('download.progress.downloadingMightDone', 'Downloading file...It may already be done.'));            
        } else {
            this.updateStatus(
                this.t('download.progress.backgroundHeading', 'Download is processing in background'),
                this.t('download.progress.backgroundDetails', 'Check your browser download bar (usually at bottom/top) for progress')
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
            retryButton.html(this.t('download.progress.troubleSubtle', 'Having trouble? Try again in new tab'));
            this.log('DownloadManager', 'Using subtle retry link (Firefox pass-through or progress detected)');
        } else {
            // Browsers with no progress: prominent amber button
            retryButton.removeClass('retry-link-subtle').addClass('retry-link-prominent');
            retryButton.html(this.t('download.progress.troubleProminent', '🔄 Having trouble? Try again in new tab'));
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
            this.t('download.progress.inProgressHeading', 'Download in progress...'), 
            this.t('download.progress.inProgressDetails', 'Please wait while your file downloads')
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
                this.updateProgressInfo(this.t('download.progress.starting', 'Starting download...')); // Clear the "Connecting..." message
            }
        }
        
        this.log('DownloadManager', 'Download started, scheduling adaptive unlock');
        this.scheduleAdaptiveUnlock();
    }
    
    showFirefoxDownloadProgress(total) {
        // Set progress bar to 100% with animation for Firefox
        const progressBar = $(this.progressBar);
        
        // Ensure we have the animation classes first
        progressBar.addClass('progress-bar-striped progress-bar-animated');
        
        // Set full width and no text
        progressBar.css({
            'width': '100%',
            'text-align': '',  // Clear any text alignment
            'line-height': '',  // Clear any line height overrides
            'position': ''      // Clear any position overrides
        }).attr('aria-valuenow', '100');
        
        progressBar.text(''); // No text in progress bar for Firefox
        
        // Show file size info only in progress-info area
        if (total) {
            const totalStr = this.formatBytes(total);
            this.updateProgressInfo(this.t('download.progress.downloadingWithSize', 'Downloading {{size}} file...', { size: totalStr }));
        } else {
            this.updateProgressInfo(this.t('download.progress.downloading', 'Downloading file...'));
        }
        
        this.log('DownloadManager', 'Firefox progress bar set to animated 100% (no text)');
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
        const sizeStr = size ? this.formatBytes(size) : 'unknown size';
        
        if (indeterminate) {
            // Firefox large file: indeterminate progress
            this.updateStatus(
                this.t('download.progress.starting', 'Starting download...'),
                this.t('download.progress.checkDownloads', 'You can check progress in the Downloads panel (Ctrl+J)')
            );
            
            // Set progress bar to indeterminate (striped animation)
            const progressBar = $(this.progressBar);
            if (progressBar.length) {
                progressBar.addClass('progress-bar-striped progress-bar-animated')
                          .css('width', '100%')
                          .attr('aria-valuenow', 100);
            }
            
            this.updateProgressInfo(this.t('download.progress.preparingLarge', 'Preparing {{size}} file for direct download...', { size: sizeStr }));
        } else {
            // Normal progress tracking
            this.updateStatus(
                this.t('download.progress.starting', 'Starting download...'),
                this.t('download.progress.pleaseWait', 'Please wait while your file downloads')
            );
            this.updateProgressInfo(this.t('download.progress.preparing', 'Preparing download...'));
        }
        
        this.log('DownloadManager', `Starting UI shown for ${filename} (${sizeStr}), indeterminate: ${indeterminate}`);
    }
    
    /**
     * Show indeterminate "started" UI for Firefox large files
     */
    showIndeterminateStartedUI() {
        this.updateStatus(
            this.t('download.progress.started', '✓ Download started in your browser (Firefox)'),
            this.t('download.progress.checkDownloads', 'You can check progress in the Downloads panel (Ctrl+J)')
        );

        // Add backup retry option after a delay
        setTimeout(() => {
            if (!this.downloadStarted) { // Only show if no progress detected
                this.updateStatus(
                    this.t('download.progress.started', '✓ Download started in your browser (Firefox)'),
                    this.t('download.progress.havingTrouble', 'Having trouble? Try again or check your Downloads folder')
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
            this.t('download.e2ee.firefoxBlocked.title', '🔒 Encrypted Download Not Available'),
            this.t('download.e2ee.firefoxBlocked.details',
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
            this.t('download.e2ee.firefoxBlocked.fileSize', 'File size: {{size}}', { size: sizeStr })
        );

        // Show error message with browser recommendations
        const $statusDetails = $(this.statusDetails);
        if ($statusDetails.length) {
            const recommendedBrowsers = this.t('download.e2ee.firefoxBlocked.browsers',
                'Chrome, Edge, or Brave');

            $statusDetails.html(
                `<strong>${this.t('download.e2ee.firefoxBlocked.why', 'Why?')}</strong> ` +
                this.t('download.e2ee.firefoxBlocked.explanation',
                    'Large encrypted files cannot be streaming decrypted reliably in Firefox.') +
                `<br><br><strong>${this.t('download.e2ee.firefoxBlocked.solution', 'Solution:')}</strong><br>` +
                `• ${this.t('download.e2ee.firefoxBlocked.useBrowser', 'Use {{browsers}}', { browsers: recommendedBrowsers })}<br>` +
                `• ${this.t('download.e2ee.firefoxBlocked.useCLI', 'Or use the <a href="https://github.com/nuwainfo/ffl" target="_blank" style="display: inline !important; padding: 0 !important; margin: 0 !important; border: none !important; background: none !important; color: #007bff !important; text-decoration: underline !important; font-size: inherit !important;">FastFileLink CLI</a>')}<br>` +
                `• ${this.t('download.e2ee.firefoxBlocked.smallFiles', 'Small encrypted files (<{{limit}}) work on Firefox', { limit: limitStr })}`
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

    async fetchToWriter(urlPath, writer, needsDecryption, resume = null) {
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
        
        // This fetch will trigger ProgressServiceWorker.
        const response = await fetch(urlPath, { headers, cache: 'no-cache' });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Validate 206 / Content-Range for resume
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
        } 

        this.log('DownloadManager', 'Fetch response received, reading stream');

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
        }

        // Close the writer (completes the file)
        await writer.close();
        this.log('DownloadManager', 'Writer closed successfully, HTTP bytes written:', totalWritten);
    }

    startNativeDownloadWithBroadcast(url, filename, resumeConfig = null) {
        if (this.downloadTriggeredOnce) {
            this.log('DownloadManager', 'Download already triggered, ignoring duplicate request');
            return;
        }
        this.downloadTriggeredOnce = true;

        this.log('DownloadManager', 'Starting native download with broadcast progress');

        const downloadUrl = new URL(url, location.origin);
        this.ensureDownloadId(downloadUrl);
        this.log('DownloadManager', 'Download URL with token:', downloadUrl.href);

        // If writer is provided in resumeConfig, read the stream and write to the writer in page context
        const writer = resumeConfig?.writer;
        if (writer) {
            this.log('DownloadManager', 'Writer provided - reading stream and writing to existing writer');

            // E2EE decryption only needed when resuming (bypassing Service Worker)
            // Normal path: Service Worker already decrypts chunks before they reach writer
            const needsDecryption = false;

            // Resume will be handled by ProgressServiceWorker, so we don't need to pass it.
            this.fetchToWriter(downloadUrl.pathname + downloadUrl.search, writer, needsDecryption)
                .catch(err => {
                    this.log('DownloadManager', 'Writer-based download failed:', err);
                    this.onDownloadErrorCallback && this.onDownloadErrorCallback(String(err));
                });
            return;
        }

        // Trigger native download (no resume writer - standard path, this will be handled by ProgressServiceWorker)
        const a = document.createElement('a');
        a.href = downloadUrl.pathname + downloadUrl.search;
        //a.download = filename || ''; // Don't uncomment it, it disables TransformStream.
        a.style.display = 'none';
        document.body.appendChild(a);

        this.log('DownloadManager', 'About to click download link');
        a.click();
        this.log('DownloadManager', 'Download link clicked');

        document.body.removeChild(a);
    }

    showCompleteBlock() {
        const completeBlock = $(this.completeBlock);
        const downloadBlock = $(this.downloadBlock);
        if (completeBlock.length) {
            completeBlock.show();
        }
        if (downloadBlock.length) {
            downloadBlock.hide();
        }
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
                    this.t('download.progress.newTabOpened', 'Download opened in new tab'), 
                    this.t('download.progress.canCloseTab', 'You can close this tab if desired')
                );
                
                this.updateProgressInfo(this.t('download.progress.stoppedForNewTab', 'Download stopped in this tab - continuing in new tab'));
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
                    $('#close-this-tab').text(this.t('download.progress.unableToClose', 'Unable to auto-close, you can manually close this tab'));
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

        // Only use broadcast/native when actually have controller; otherwise use direct fetch→writer
        if (progressSwSupported) {
            this.log('DownloadManager', 'BRANCH: Using Progress SW with broadcast (has controller)');
            this.startNativeDownloadWithBroadcast(url, filename, resumeConfig);
        } else if (writer) {
            this.log('DownloadManager', 'BRANCH: No controller; using direct fetch→writer');
            try {
                // Prepare URL with download token for direct fetch
                const downloadUrl = new URL(url, location.origin);
                this.ensureDownloadId(downloadUrl);

                await this.fetchToWriter(downloadUrl.pathname + downloadUrl.search, writer, this.e2eeEnabled, resumeConfig);
            } catch (err) {
                this.log('DownloadManager', 'Direct fetch→writer failed:', err);
                this.onDownloadErrorCallback && this.onDownloadErrorCallback(String(err));
            }
        } else {
            // No writer and no Service Worker - fallback to native download
            this.log('DownloadManager', 'BRANCH: No controller and no writer; falling back to native <a> download');
            // This wouldn't work if e2ee enabled. (download encrypted data)
            // Maybe we should also show showE2EEFirefoxBlockedUI (not just for Firefox)
            this.startNativeDownloadWithBroadcast(url, filename, resumeConfig);
        }
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DownloadManager;
} else {
    window.DownloadManager = DownloadManager;
}
