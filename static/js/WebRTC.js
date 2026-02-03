/*!
 * FastFileLink - WebRTC and download utilities for file transfers
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 
 * See LICENSE file in the project root for full license information.
 */

// ============================================================
// Utility Functions
// ============================================================

/**
 * Helper function to parse boolean-like parameters (matches server-side parseURLBooleanParam)
 */
const parseBooleanParam = (value, defaultValue = false) => {
    if (!value)
        return defaultValue;

    const lowerValue = value.toLowerCase();

    // True values: true, 1, on, yes (case-insensitive)
    if (['true', '1', 'on', 'yes'].includes(lowerValue)) {
        return true;
    }

    // False values: false, 0, off, no (case-insensitive)
    if (['false', '0', 'off', 'no'].includes(lowerValue)) {
        return false;
    }

    // Unrecognized value - return default
    return defaultValue;
};

/**
 * Helper function to check if an IP is a local/private IP
 */
const isLocalIp = (ip) => {
    if (typeof ip !== 'string')
        return false;

    const s = ip.toLowerCase().trim();
    return (
        // IPv6 loopback
        s === '::1' ||
        // mDNS / hostname
        s.endsWith('.local') ||
        // IPv4 loopback
        s.startsWith('127.') ||
        // Private IPv4
        s.startsWith('10.') ||
        s.startsWith('192.168.') ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s) || // 172.16.0.0 ~ 172.31.255.255
        // IPv4 link-local
        s.startsWith('169.254.') ||
        // IPv6 link-local / ULA
        s.startsWith('fe80:') || // link-local
        s.startsWith('fc')   ||  // fc00::/7
        s.startsWith('fd')       // fd00::/8
    );
};

/**
 * Browser detection utility
 */
const getBrowserInfo = () => {
    const ua = navigator.userAgent;
    const vendor = navigator.vendor || '';

    // Check Edge first (before Chrome, since Edge contains "Chrome" in UA)
    if (ua.includes('Edg/') || ua.includes('Edge/')) {
        return 'edge';
    } else if (ua.includes('Chrome') && vendor.includes('Google')) {
        return 'chrome';
    } else if (ua.includes('Firefox')) {
        return 'firefox';
    } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
        return 'safari';
    }
    return 'unknown';
};

/**
 * Detect RTC connection type (local vs remote)
 */
const detectRTCConnectionType = async () => {
    // Check if RTCPeerConnection is supported
    if (typeof RTCPeerConnection === 'undefined') {
        log("Connection", "RTCPeerConnection not supported, skipping connection type detection");
        return { isLocalConnection: false, detectedIp: null };
    }

    return new Promise((resolve, reject) => {
        const tempPc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        const timeout = setTimeout(() => {
            tempPc.close();
            resolve({ isLocalConnection: false, detectedIp: null });
        }, 5000);

        let hostIps = new Set();
        let srflxIps = new Set();
        let hasLocalCandidate = false;
        let candidateCount = 0;

        tempPc.onicecandidate = (event) => {
            if (event.candidate) {
                const candidate = event.candidate.candidate;
                candidateCount++;
                log("ICE-Detect", `Candidate ${candidateCount}: ${candidate.substring(0, 80)}...`);

                // Parse candidate string
                const parts = candidate.split(' ');
                let ip = null;
                let candidateType = null;

                // Find type first
                for (let i = 0; i < parts.length; i++) {
                    if (parts[i] === 'typ' && i + 1 < parts.length) {
                        candidateType = parts[i + 1];
                        break;
                    }
                }

                // Find IP based on candidate type and format
                if (candidateType === 'host') {
                    // For host candidates, IP could be at index 4 or could be .local format
                    for (let i = 0; i < parts.length; i++) {
                        const part = parts[i];
                        // Check for IPv4 address
                        if (/^\d+\.\d+\.\d+\.\d+$/.test(part)) {
                            ip = part;
                            break;
                        }
                        // Check for .local mDNS format (indicates local network)
                        else if (part.endsWith('.local')) {
                            ip = part;
                            hasLocalCandidate = true;
                            break;
                        }
                        // Check for IPv6 link-local or ULA
                        else if (part.startsWith('fe80:') || part.startsWith('fc') || part.startsWith('fd')) {
                            ip = part;
                            hasLocalCandidate = true;
                            break;
                        }
                    }
                } else if (candidateType === 'srflx') {
                    // For srflx candidates, IP is usually at index 4
                    if (parts[4] && /^\d+\.\d+\.\d+\.\d+$/.test(parts[4])) {
                        ip = parts[4];
                    }
                }

                if (ip && candidateType) {
                    log("ICE-Detect", `Parsed - IP: ${ip}, Type: ${candidateType}`);

                    if (candidateType === 'host') {
                        hostIps.add(ip);

                        // Check if this is a local IP
                        if (isLocalIp(ip)) {
                            hasLocalCandidate = true;
                        }
                    } else if (candidateType === 'srflx') {
                        srflxIps.add(ip);
                    }

                    // Check if we have enough information
                    if (candidateCount >= 2) {
                        clearTimeout(timeout);
                        tempPc.close();

                        const hostIpArray = Array.from(hostIps);
                        const srflxIpArray = Array.from(srflxIps);

                        // Determine if this is a local connection
                        // If we have .local candidates or private IPs, it's local
                        const isLocalConnection = hasLocalCandidate || hostIpArray.some(isLocalIp);

                        const result = {
                            isLocalConnection: isLocalConnection,
                            detectedIp: `host:[${hostIpArray.join(',')}] srflx:[${srflxIpArray.join(',')}]`
                        };

                        log("Connection", `Detection result - Local: ${result.isLocalConnection}, IPs: ${result.detectedIp}`);
                        resolve(result);
                        return;
                    }
                }
            } else {
                // End of candidates
                clearTimeout(timeout);
                tempPc.close();

                const hostIpArray = Array.from(hostIps);
                const srflxIpArray = Array.from(srflxIps);

                const isLocalConnection = hasLocalCandidate || hostIpArray.some(isLocalIp);

                const result = {
                    isLocalConnection: isLocalConnection,
                    detectedIp: `host:[${hostIpArray.join(',')}] srflx:[${srflxIpArray.join(',')}]`
                };

                log("Connection", `Final detection - Local: ${result.isLocalConnection}, IPs: ${result.detectedIp}`);
                resolve(result);
            }
        };

        tempPc.onicegatheringstatechange = () => {
            log("ICE-Detect", `ICE gathering state: ${tempPc.iceGatheringState}`);
        };

        // Create data channel to trigger ICE gathering
        tempPc.createDataChannel('detect');

        tempPc.createOffer()
            .then(offer => tempPc.setLocalDescription(offer))
            .catch(reject);
    });
};

/**
 * Get comprehensive connection information
 */
const getConnectionInfo = async () => {
    const baseInfo = {
        browser: getBrowserInfo(),
        domain: window.location.hostname,
        protocol: window.location.protocol,
        userAgent: navigator.userAgent.substring(0, 100),
        inAppBrowser: InAppGuard.isInAppBrowser(),
        downloadRestricted: InAppGuard.isDownloadRestricted()
    };

    // Try to detect if this is actually a local connection via WebRTC
    try {
        const rtcInfo = await detectRTCConnectionType();
        return { ...baseInfo, ...rtcInfo };
    } catch (e) {
        log("Connection", "Failed to detect RTC connection type:", e);
        return baseInfo;
    }
};

// ============================================================
// Writer Classes
// ============================================================

/**
 * WritePump: Write queue manager with single state machine
 * Manages writer (StreamSaver or BlobWriter) with guaranteed write ordering and proper completion.
 */
class WritePump {

    constructor(writer, expectedSize = null, callbacks = {}) {
        // Support lazy writer initialization - accept function or actual writer
        if (typeof writer === 'function') {
            this.writerFactory = writer;
            this.writer = null; // Will be initialized on first write
        } else {
            this.writer = writer;
            this.writerFactory = null;
        }

        this.expected = Number.isFinite(expectedSize) ? expectedSize : null;
        this.bytesWritten = 0;

        this.onComplete = callbacks.onComplete || (() => {});
        this.onFallback = callbacks.onFallback || ((reason) => this.log('WritePump', `Fallback: ${reason}`));
        this.log = callbacks.log || ((tag, msg) => console.log(`[${tag}] ${msg}`));

        // Single-threaded queue - no concurrent writes
        this.queue = [];
        this.intakeOpen = true;     // Accept new chunks?
        this.draining = false;      // Drain loop running?
        this.inFlight = 0;          // Number of writes in progress (should always be 0 or 1)
        this.drainLoopPromise = null;
        this.idleResolver = null;   // Resolves when queue empty and inFlight=0
        this.writeError = null;     // First error encountered
    }

    /**
     * Lazy-initialize writer from factory on first use
     * This allows blocking operations to happen
     * only when first chunk arrives, not during WritePump construction
     */
    async _ensureWriter() {
        if (this.writer) {
            return this.writer;
        }

        if (this.writerFactory) {
            this.log('WritePump', 'Lazy-initializing writer from factory...');
            this.writer = await this.writerFactory();
            this.writerFactory = null; // Clear factory after use
            this.log('WritePump', 'Writer initialized');
        }

        return this.writer;
    }

    isAccepting() {
        return this.intakeOpen && !this.writeError;
    }

    enqueue(chunk) {
        if (!this.intakeOpen) {
            // After EOF, ignore new chunks (prevents race condition)
            return false;
        }

        if (this.writeError) {
            this.log('WritePump', `Skipping write due to previous error: ${this.writeError}`);
            return false;
        }

        this.queue.push(chunk);

        // Start drain loop if not already running
        if (!this.drainLoopPromise) {
            this.drainLoopPromise = this._drainLoop();
        }

        return true;
    }

    async eof() {
        if (!this.intakeOpen) {
            this.log('WritePump', 'EOF called but intake already closed, ignoring');
            return;
        }

        // Close intake immediately - no more chunks accepted
        this.intakeOpen = false;
        this.log('WritePump', `EOF received, queue=${this.queue.length}, inFlight=${this.inFlight}, bytesWritten=${this.bytesWritten}`);

        try {
            // Wait for queue to drain completely (no timeout, no race)
            await this._waitIdle();
            this.log('WritePump', `Queue drained, bytesWritten=${this.bytesWritten}`);

            // Ensure writer is initialized (even if no chunks were written)
            const writer = await this._ensureWriter();

            // Close writer only after all writes complete
            await writer.close();
            this.log('WritePump', 'Writer closed successfully');

            // Verify size matches expectation (skip if size is unknown)
            // Unknown size: expected === null or expected <= 0
            const hasKnownSize = this.expected !== null && this.expected > 0;
            if (hasKnownSize && this.bytesWritten !== this.expected) {
                const reason = `Size mismatch: written=${this.bytesWritten}, expected=${this.expected}`;
                this.log('WritePump', reason);
                this.onFallback(reason);
                return;
            }

            // Success! Pass writer reference for blob downloads
            this.onComplete({
                bytesWritten: this.bytesWritten,
                writer: this.writer
            });

        } catch (err) {
            this.log('WritePump', `EOF error: ${err?.message || err}`);
            this.onFallback(`Writer error: ${err?.message || err}`);
        }
    }

    async prepareForFallback(timeoutMs, reason = 'fallback') {
        if (!this.intakeOpen) {
            this.log('WritePump', 'Prepare for fallback called but intake already closed');
            return;
        }

        // Stop accepting new writes immediately
        this.intakeOpen = false;
        this.log('WritePump', `Preparing for fallback with ${timeoutMs}ms deadline: ${reason}`);
        this.log('WritePump', `Current state: queue=${this.queue.length}, inFlight=${this.inFlight}, bytesWritten=${this.bytesWritten}`);

        const deadline = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('deadline')), timeoutMs)
        );

        try {
            // Try to wait for queue to drain within timeout
            await Promise.race([this._waitIdle(), deadline]);
            this.log('WritePump', `All writes flushed within deadline, bytesWritten=${this.bytesWritten}`);
        } catch (err) {
            this.log('WritePump', `Deadline exceeded, some writes may be lost: ${err?.message || err}`);
            this.log('WritePump', `Final state: queue=${this.queue.length}, inFlight=${this.inFlight}, bytesWritten=${this.bytesWritten}`);
        }

        // DO NOT close writer - let DownloadManager reuse it for HTTP resume
        this.log('WritePump', `Ready for fallback, writer still open for DownloadManager`);
        this.onFallback(reason);
    }

    async _drainLoop() {
        if (this.draining) {
            this.log('WritePump', 'Drain loop already running');
            return;
        }

        this.draining = true;

        try {
            // Ensure writer is initialized before first write
            const writer = await this._ensureWriter();

            while (this.queue.length > 0) {
                const chunk = this.queue.shift();
                this.inFlight++;

                try {
                    // Write one chunk at a time - fully await before next
                    await writer.write(chunk);
                    this.bytesWritten += chunk.byteLength || chunk.size || chunk.length || 0;
                } catch (err) {
                    // Store first error and stop processing
                    if (!this.writeError) {
                        this.writeError = err.message || String(err);
                        this.log('WritePump', `Write error: ${this.writeError}`);
                    }
                    throw err;
                } finally {
                    this.inFlight--;
                }
            }
        } finally {
            this.draining = false;
            this.drainLoopPromise = null;

            // If idle and someone is waiting, resolve them
            if (this.queue.length === 0 && this.inFlight === 0 && this.idleResolver) {
                const resolve = this.idleResolver;
                this.idleResolver = null;
                resolve();
            }
        }
    }

    async _waitIdle() {
        // Already idle?
        if (this.queue.length === 0 && this.inFlight === 0) {
            return;
        }

        // Wait for drain loop to finish
        return new Promise((resolve) => {
            this.idleResolver = resolve;
        });
    }
}

/**
 * BlobWriter: Writer implementation that accumulates chunks in memory
 * Mimics WritableStream writer interface for compatibility with WritePump
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

        log("BlobWriter", `Creating blob download for ${this.fileName} (${this.bytesWritten} bytes)`);

        const blob = new Blob(this.chunks, { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = this.fileName;
        a.style.display = 'none';
        document.body.appendChild(a);

        log("BlobWriter", `Triggering download for ${this.fileName}`);
        a.click();

        setTimeout(() => {
            log("BlobWriter", "Cleaning up object URL");
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
                log("WriterFactory", `Creating StreamSaver writer for ${fileName} (${sizeDesc})`);

                // Configure StreamSaver (encapsulated here)
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
                log('WriterFactory', 'StreamSaver initialization failed, falling back to Blob', e);
                // Fall through to blob creation
            }
        }

        // Use Blob for small files with known size
        log("WriterFactory", `Creating Blob writer for ${fileName} (${sizeDesc})`);
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

// ============================================================
// Debug Configuration Manager
// ============================================================

/**
 * Manages debug configuration from URL parameters.
 * Handles test/debug flags for fallback simulation, stall testing, etc.
 */
class DebugConfigManager {
    constructor(log) {
        // Store log function for use in methods
        this.log = log;

        // Parse all debug parameters from URL
        const urlParams = new URLSearchParams(window.location.search);

        // Fallback timeout override
        const fallbackMsParam = parseInt(urlParams.get('fallback-ms'), 10);
        this.fallbackTimeoutMs = !isNaN(fallbackMsParam) && fallbackMsParam > 0
            ? fallbackMsParam
            : null;

        // Force fallback parameters
        this.forceFallback = parseBooleanParam(urlParams.get('force-fallback'));

        const forceFallbackAfterParam = parseInt(urlParams.get('force-fallback-after'), 10);
        this.forceFallbackThreshold = !isNaN(forceFallbackAfterParam) && forceFallbackAfterParam >= 0
            ? forceFallbackAfterParam
            : 0;

        // Stall simulation parameters
        this.simulateStall = parseBooleanParam(urlParams.get('simulate-stall'));
        const stallAfterValue = parseInt(urlParams.get('stall-after'));
        this.stallAfterBytes = !isNaN(stallAfterValue) ? stallAfterValue : 50000; // Default 50KB

        // ICE failure simulation
        this.simulateICEFailure = parseBooleanParam(urlParams.get('simulate-ice-failure'));

        // HTTP fallback toggle
        this.httpFallbackEnabled = parseBooleanParam(urlParams.get('fallback'), true); // Default: true

        // Runtime state
        this.forceFallbackIssued = false;
        this.stallSimulated = false;

        // Log configuration if any debug mode is active
        if (this.simulateStall || this.simulateICEFailure) {
            this.log("Debug", `Testing mode enabled: stall=${this.simulateStall} (after ${this.stallAfterBytes} bytes), ice-failure=${this.simulateICEFailure}`);
        }
    }

    getFallbackTimeout(defaultTimeout) {
        return this.fallbackTimeoutMs || defaultTimeout;
    }

    isHTTPFallbackEnabled() {
        return this.httpFallbackEnabled;
    }

    shouldForceFallback(bytesReceived) {
        if (!this.forceFallback || this.forceFallbackIssued) {
            return false;
        }

        if (bytesReceived > 0 && bytesReceived >= this.forceFallbackThreshold) {
            this.forceFallbackIssued = true;
            return true;
        }

        return false;
    }

    shouldLogForceFallbackCandidate() {
        return this.forceFallback && !this.forceFallbackIssued;
    }

    simulateStallIfNeeded(bytesReceived, dataChannel) {
        if (this.stallSimulated) {
            return true;
        }

        if (!this.simulateStall || bytesReceived < this.stallAfterBytes) {
            return false;
        }

        this.stallSimulated = true;
        this.log("Debug", `Simulating network stall - closing data channel after ${bytesReceived} bytes`);

        // Simulate real network failure by closing the data channel
        setTimeout(() => {
            try {
                dataChannel.close();
                this.log("Debug", "Data channel closed to simulate network failure");
            } catch (e) {
                this.log("Debug", "Error closing data channel:", e);
            }
        }, 100); // Small delay to complete current processing

        return true; // Indicates stall was simulated
    }

    // Build debug parameters for server offer URL
    buildOfferDebugParams() {
        const debugParams = new URLSearchParams();

        if (this.simulateICEFailure) {
            debugParams.set('simulate-ice-failure', 'true');
        }
        if (this.simulateStall) {
            debugParams.set('simulate-stall', 'true');
            debugParams.set('stall-after', this.stallAfterBytes.toString());
        }

        return debugParams.toString();
    }
}

// ============================================================
// Download UI Manager
// ============================================================

/**
 * Manages all UI updates for the download process.
 * Encapsulates DOM manipulation, progress tracking, and status display.
 */
class DownloadUIManager {
    constructor(elements, t, options = {}) {
        // DOM elements
        this.progressBar = elements.progressBar;
        this.statusText = elements.statusText;
        this.connectionType = elements.connectionType;
        this.downloadMessage = elements.downloadMessage;
        this.downloadButton = elements.downloadButton || null;

        // Translation function
        this.t = t;

        // Countdown state
        this.countdownInterval = null;
        this.countdownSeconds = 0;
    }

    // ============ Download Button Management ============

    /**
     * Show download button
     */
    showDownloadButton() {
        if (this.downloadButton) {
            this.downloadButton.style.display = 'inline-flex';
        }
    }

    /**
     * Hide download button
     */
    hideDownloadButton() {
        if (this.downloadButton) {
            this.downloadButton.style.display = 'none';
        }
    }

    setStatus(text, showLoading = false) {
        if (!this.statusText) return;

        this.statusText.innerHTML = '';

        if (showLoading) {
            const loadingIcon = document.createElement('span');
            loadingIcon.className = 'loading-icon';
            loadingIcon.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> ';
            this.statusText.appendChild(loadingIcon);
        }

        this.statusText.appendChild(document.createTextNode(text));
        document.title = `FastFileLink - ${text}`;
    }

    setConnectionType(text) {
        if (this.connectionType) {
            this.connectionType.textContent = text;
        }
    }

    setDownloadMessage(text) {
        if (this.downloadMessage) {
            this.downloadMessage.textContent = text;
        }
    }

    updateProgress(current, total = null) {
        if (!this.progressBar) {
            return;
        }

        // Unified logic: determinate vs indeterminate progress
        const hasKnownTotal = total !== null && total > 0;

        if (hasKnownTotal) {
            // Determinate progress (known size)
            this.progressBar.value = current;
            const percent = Math.round(current * 100 / total);
            this.setStatus(
                this.t('Download:client.status.downloadingPercent', 'Downloading via P2P: {{percent}}%', { percent })
            );
        } else {
            // Indeterminate progress (unknown size) - remove value attribute
            // Native <progress> elements show animated indeterminate state when value is absent
            this.progressBar.removeAttribute('value');
            this.setStatus(
                this.t('Download:client.status.downloading', 'Downloading via P2P...')
            );
        }
    }

    setProgressMax(max) {
        if (this.progressBar && max > 0) {
            this.progressBar.max = max;
        }
    }

    removeProgressBar() {
        const progressElements = document.getElementsByClassName('progress');
        Array.from(progressElements).forEach(el => el.remove());
    }

    // ============ Countdown Management ============
    startCountdown(seconds, shouldStopCallback) {
        this.stopCountdown(); // Clear any existing countdown

        this.countdownSeconds = seconds;
        this.setConnectionType(
            this.t('Download:client.connection.waitingPeer', 'Waiting for peer ({{seconds}}s)', {
                seconds: this.countdownSeconds
            })
        );

        this.countdownInterval = setInterval(() => {
            if (shouldStopCallback && shouldStopCallback()) {
                this.stopCountdown();
                return;
            }

            this.countdownSeconds--;

            if (this.countdownSeconds >= 0) {
                this.setConnectionType(
                    this.t('Download:client.connection.waitingPeer', 'Waiting for peer ({{seconds}}s)', {
                        seconds: this.countdownSeconds
                    })
                );
            } else {
                this.stopCountdown();
            }
        }, 1000);
    }

    stopCountdown() {
        if (this.countdownInterval) {
            clearInterval(this.countdownInterval);
            this.countdownInterval = null;
        }
    }

    // ============ Connection States ============
    showEstablishingP2P(timeoutSeconds, shouldStopCallback) {
        this.setStatus(
            this.t('Download:client.status.establishingP2p', 'Establishing P2P connection...'),
            true
        );
        this.startCountdown(timeoutSeconds, shouldStopCallback);
    }

    showP2PChecking() {
        this.setStatus(
            this.t('Download:client.status.p2pChecking', 'P2P connection...[Checking]'),
            true
        );
    }

    showP2PConnecting() {
        this.setStatus(
            this.t('Download:client.status.p2pConnecting', 'P2P connection...[Connecting]'),
            true
        );
    }

    showP2PSuccess() {
        this.setStatus(
            this.t('Download:client.status.p2pSuccess', 'P2P connection successful! Downloading...')
        );
        this.setConnectionType(
            this.t('Download:client.connection.directP2p', 'Direct P2P transfer')
        );
        this.setDownloadMessage(
            this.t('Download:client.download.deviceStarted', 'Device-to-Device download started.')
        );
        this.stopCountdown();
    }

    showReconnecting() {
        this.setStatus(
            this.t('Download:client.status.reconnecting', 'Connection lost, attempting to reconnect...'),
            true
        );
    }

    showNetworkFluctuation() {
        this.setStatus(
            this.t('Download:client.status.networkFluctuation', 'Network fluctuation detected, continuing transfer...'),
            true
        );
    }

    showRetryingP2P() {
        this.setStatus(
            this.t('Download:client.status.retryingP2p', 'Retrying P2P connection…'),
            true
        );
        this.setConnectionType(
            this.t('Download:client.connection.retrying', 'Retrying P2P connection')
        );
    }

    showSavingFile() {
        this.setStatus(
            this.t('Download:client.status.savingFile', 'Saving file...')
        );
    }

    showSwitchingToRelay(reason) {
        this.setStatus(
            this.t('Download:client.status.switchingRelay', `Switching to relay mode: ${reason}`, { reason })
        );
        this.setConnectionType(
            this.t('Download:client.connection.serverRelay', 'Using Server Relay Download')
        );
        this.stopCountdown();
    }

    showRelayStarted() {
        this.setStatus(
            this.t('Download:client.status.relayStarted', 'Relayed P2P Download Started.')
        );
    }

    showBrowserNotSupported() {
        this.setStatus(
            this.t('Download:client.fallback.browserNotSupported', 'Downloads not supported in this browser')
        );
    }

    showComplete(fileSize) {
        this.setStatus(
            this.t('Download:complete.title', '✅ Download complete!')
        );

        if (this.progressBar) {
            this.progressBar.value = fileSize || 100;
        }

        this.setDownloadMessage(
            this.t('Download:client.download.fileSaved', 'File saved. Please check your download folder.')
        );

        // Hide progress bar after 1 second
        setTimeout(() => {
            this.removeProgressBar();
        }, 1000);
    }

    updateFallbackMessage() {
        this.setDownloadMessage(
            this.t('Download:client.download.startShortly', 'Your download will start shortly.')
        );
    }

    // ============ Cleanup ============
    cleanup() {
        this.stopCountdown();
    }
}

// ============================================================
// Fallback Manager
// ============================================================

/**
 * FallbackManager - Handles HTTP fallback logic
 */
class FallbackManager {
    constructor({
        debugConfig,
        e2eeManager,
        uiManager,
        fileSize,
        uid,
        downloadUrl,
        log,
        t,
        // Callbacks for external state
        getWritePump,
        getBytesReceived,
        getDownloadCompleted,
        hasTransferStarted,
        isStalled,
        onConnectionFailureHandled
    }) {
        // Configuration dependencies
        this.debugConfig = debugConfig;
        this.e2eeManager = e2eeManager;
        this.uiManager = uiManager;
        this.fileSize = fileSize;
        this.uid = uid;
        this.downloadUrl = downloadUrl;
        this.log = log;
        this.t = t;

        // Callbacks
        this.getWritePump = getWritePump;
        this.getBytesReceived = getBytesReceived;
        this.getDownloadCompleted = getDownloadCompleted;
        this.hasTransferStarted = hasTransferStarted;
        this.isStalled = isStalled;
        this.onConnectionFailureHandled = onConnectionFailureHandled;

        this.fallbackTriggered = false;

        // References
        this.downloadManager = null;
        this.fallbackTimer = null;
    }

    // Create fallback timer with timeout
    createFallbackTimer(timeoutMs) {
        this.log("Fallback", `Setting up timeout for ${timeoutMs}ms`);
        this.fallbackTimer = setTimeout(() => {
            this.log("Fallback", `Timeout reached after ${timeoutMs}ms`);
            this.triggerFallback("Connection timeout");
        }, timeoutMs);
        return this.fallbackTimer;
    }

    clearFallbackTimer() {
        if (this.fallbackTimer) {
            clearTimeout(this.fallbackTimer);
            this.fallbackTimer = null;
        }
    }

    // Main fallback trigger method
    async triggerFallback(reason, force = false) {
        if (!this.debugConfig.isHTTPFallbackEnabled()) {
            this.log("Fallback", `Skip fallback (${reason}): fallback disabled`);
            return;
        }

        if (this.fallbackTriggered || this.getDownloadCompleted()) {
            this.log("Fallback", `Skip fallback (${reason}): already handled`);
            return;
        }

        // Use callbacks to check external state
        if (!force && this.hasTransferStarted() && !this.isStalled()) {
            this.log("Fallback", `Skip fallback (${reason}): transfer active / not stalled`);
            return;
        }

        const writePump = this.getWritePump();
        const bytesReceived = this.getBytesReceived();

        this.log("Fallback", `Switching to HTTP download: ${reason}`);
        this.log("Fallback", `Current state: bytesReceived=${bytesReceived}, pump.bytesWritten=${writePump ? writePump.bytesWritten : 0}`);

        // Prepare WritePump for fallback
        const flushPromise = writePump
            ? writePump.prepareForFallback(5000, `Fallback: ${reason}`)
            : Promise.resolve();

        // Notify external state manager that connection failure has been handled
        this.onConnectionFailureHandled();

        // Show UI updates
        this.uiManager.showSwitchingToRelay(reason);
        this.uiManager.updateFallbackMessage();

        try {
            await this._startDownloadManager(flushPromise, writePump);
        } catch (error) {
            this.log("Fallback", "DownloadManager failed, redirecting to download URL:", error);
            window.location.href = this.downloadUrl;
        }

        this.uiManager.showRelayStarted();
    }

    async _startDownloadManager(flushPromise, writePump) {
        const e2eeEnabledValue = (this.e2eeManager && this.e2eeManager.e2eeEnabled);

        // Create DownloadManager instance
        this.downloadManager = new DownloadManager({
            debug: DEBUG,
            logFunction: this.log,
            uid: this.uid,
            e2eeEnabled: e2eeEnabledValue,
            progressBar: document.getElementById('downloadProgress'),
            statusHeading: '#download-message',
            statusDetails: '#status-details',
            progressInfo: '#connectionType',
            retryLink: '#retry-link',
            onServiceWorkerReadyCallback: async (controller) => {
                if (this.downloadManager.httpDecryptor && controller) {
                    this.log("E2EE", "Sending E2EE context to Service Worker...");
                    this.downloadManager.httpDecryptor.sendContextToServiceWorker('__pre_registered__', controller);
                    this.log("E2EE", "✓ E2EE context pre-registered with Service Worker");
                }
            },
            onDownloadStartCallback: (downloadId, total) => {
                this.log("Fallback", `DownloadManager started, download ID: ${downloadId}, total: ${total}`);

                if (this.downloadManager.httpDecryptor && navigator.serviceWorker && navigator.serviceWorker.controller) {
                    this.downloadManager.httpDecryptor.sendContextToServiceWorker(downloadId, navigator.serviceWorker.controller);
                    this.log("E2EE", `✓ E2EE context sent for specific download ID: ${downloadId}`);
                }

                // Notify external state that connection failure is handled
                this.onConnectionFailureHandled();

                // Clear P2P timers
                this.uiManager.stopCountdown();
                if (this.fallbackTimer) {
                    clearTimeout(this.fallbackTimer);
                }

                this.uiManager.setConnectionType(this.t('Download:client.connection.serverRelay', 'Using Server Relay Download'));
                this.log("Fallback", "Successfully transitioned from P2P to HTTP download");
            }
        });

        // Setup retry handlers
        this.downloadManager.setupRetryHandlers();

        // Start download
        await flushPromise;
        this.fallbackTriggered = true;

        const actualBytesWritten = writePump ? writePump.bytesWritten : 0;
        const bytesReceived = this.getBytesReceived();
        this.log("Fallback", "Queue flushed, starting DownloadManager download");
        this.log("Fallback", `Current state (after flush): bytesReceived=${bytesReceived}, bytesWritten=${actualBytesWritten}`);

        if (e2eeEnabledValue) {
            this.downloadManager.httpDecryptor = await this.e2eeManager.setupHTTPDecryptor();
            this.log("E2EE", "✓ HTTP decryptor ready");
        }

        // Calculate resume options
        const resumeOptions = this._calculateResumeOptions(actualBytesWritten);

        this.log("Fallback", `Starting DownloadManager with writer: ${writePump ? 'YES' : 'NO'}, resume: ${resumeOptions ? 'YES' : 'NO'}`);
        this.downloadManager.startDownload({
            writer: writePump ? writePump.writer : null,
            resume: resumeOptions
        });
    }

    _calculateResumeOptions(actualBytesWritten) {
        const hasBytes = actualBytesWritten > 0;
        const hasSize = typeof this.fileSize === 'number' && this.fileSize > 0;

        if (!hasBytes || !hasSize) {
            this.log("Fallback", `Resume not applicable: bytesWritten=${actualBytesWritten}, fileSize=${this.fileSize}`);
            return null;
        }

        if (actualBytesWritten >= this.fileSize) {
            this.log("Fallback", `Resume skipped: bytesWritten (${actualBytesWritten}) >= fileSize (${this.fileSize})`);
            return null;
        }

        const ALIGN = 256 * 1024;
        const alignedStart = Math.floor(actualBytesWritten / ALIGN) * ALIGN;
        const skipBytes = actualBytesWritten - alignedStart;

        const resumePayload = {
            baseBytes: actualBytesWritten,
            rangeStart: alignedStart,
            skipBytes: skipBytes,
            expectedSize: this.fileSize,
            chunkSize: ALIGN
        };

        this.log("Fallback", `Resume calculation: baseBytes=${actualBytesWritten}, rangeStart=${alignedStart}, skipBytes=${skipBytes}, expectedSize=${this.fileSize}`);

        if (resumePayload.rangeStart >= 0 && resumePayload.rangeStart < this.fileSize) {
            this.log("Fallback", `Resume options prepared`);
            return resumePayload;
        } else {
            this.log("Fallback", `Resume range invalid: start=${resumePayload.rangeStart}, fileSize=${this.fileSize}`);
            return null;
        }
    }
}

// ============================================================
// Pause Gate
// ============================================================

/**
 * PauseGate - Manages pause/resume before download starts
 *
 * States:
 * - CONNECTING: ICE/candidate polling in progress
 * - READY_TO_START_P2P: DataChannel ready, waiting for START signal
 * - READY_TO_START_HTTP: HTTP fallback ready, waiting to start
 * - TRANSFERRING: Actually downloading
 * - PAUSED_BEFORE_START: User paused before transfer started
 */
class PauseGate {
    constructor({ uiManager, log, t, onNeedReconnect }) {
        this.uiManager = uiManager;
        this.log = log;
        this.t = t;
        this.onNeedReconnect = onNeedReconnect;

        this.pauseRequested = false;
        this.paused = false;
        this.pauseSince = null;

        this.pendingStart = null;   // function to call when resume
        this.pendingKind = null;    // 'webrtc' | 'http'
        this.getWebRTCHealth = null; // () => { pcState, dcState }
        this.maxPauseMs = 2 * 60 * 1000; // 2 minutes max pause time

        // Heartbeat mechanism for WebRTC
        this.dataChannel = null;
        this.heartbeatTimer = null;

        // Attach event listener to download button
        this._initDownloadButton();
    }

    /**
     * Initialize download button event listener
     * @private
     */
    _initDownloadButton() {
        // Attach click handler
        this.uiManager.downloadButton.addEventListener('click', () => {
            this.log("PauseGate", "User clicked download button");
            this.resume();
        });

        // Initial state: hidden
        this.uiManager.hideDownloadButton();

        this.log("PauseGate", "Download button initialized");
    }

    /**
     * Start heartbeat mechanism for WebRTC (sends PING every 15s)
     * @private
     */
    _startHeartbeat() {
        if (!this.dataChannel || this.heartbeatTimer) return;

        this.log("PauseGate", "Starting heartbeat mechanism");
        this.heartbeatTimer = setInterval(() => {
            if (this.dataChannel && this.dataChannel.readyState === 'open') {
                try {
                    this.dataChannel.send('PING');
                    this.log("PauseGate", "Sent PING heartbeat");
                } catch (err) {
                    this.log("PauseGate", `Heartbeat send failed: ${err.message}`);
                }
            }
        }, 15000);
    }

    /**
     * Stop heartbeat mechanism
     * @private
     */
    _stopHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
            this.log("PauseGate", "Stopped heartbeat mechanism");
        }
    }

    /**
     * User requested pause (can be called anytime before transfer starts)
     */
    requestPause() {
        this.log("PauseGate", "User requested pause");
        this.pauseRequested = true;

        // If not already paused and not transferring, pause now
        if (!this.paused) {
            this.paused = true;
            this.pauseSince = Date.now();
            this.uiManager.stopCountdown();
            this.log("PauseGate", "Paused - stopping countdown and events");
        }
    }

    /**
     * Set pending start function (called when connection is ready)
     * Returns true if should start immediately, false if delayed due to pause
     */
    setPendingStart({ kind, startFn, getHealth, dataChannel }) {
        this.pendingKind = kind;
        this.pendingStart = startFn;
        this.getWebRTCHealth = getHealth || null;
        this.dataChannel = dataChannel || null;

        this.log("PauseGate", `Connection ready (${kind}), pauseRequested=${this.pauseRequested}`);

        if (this.pauseRequested) {
            this.paused = true;
            this.pauseSince = this.pauseSince || Date.now();

            // Show paused UI with download button
            this.uiManager.setStatus(
                this.t('Download:client.status.readyToDownload', 'Ready to download')
            );
            this.uiManager.setConnectionType(
                kind === 'webrtc'
                    ? this.t('Download:client.connection.p2pReady', 'P2P Connection Ready')
                    : this.t('Download:client.connection.relayReady', 'Server Relay Ready')
            );

            // Show download button (managed by DownloadUIManager)
            this.uiManager.showDownloadButton();

            // Start heartbeat for WebRTC to keep connection alive
            if (kind === 'webrtc' && this.dataChannel) {
                this._startHeartbeat();
            }

            this.log("PauseGate", `Paused in READY_TO_START_${kind.toUpperCase()} state`);
            return false; // delayed
        } else {
            // Not paused - update status to show connection is ready
            this.uiManager.setStatus('Starting download...');
            this.uiManager.setConnectionType(
                kind === 'webrtc' ? 'P2P Connection Established' : 'Server Relay Connected'
            );
            this.log("PauseGate", `Connection ready, starting immediately (${kind})`);
        }

        return true; // can start now
    }

    /**
     * Resume download (user clicked download button)
     */
    async resume() {
        if (!this.paused) {
            this.log("PauseGate", "Resume called but not paused");
            return;
        }

        this.log("PauseGate", "User requested resume");
        this.paused = false;
        this.pauseRequested = false;

        // Stop heartbeat mechanism
        this._stopHeartbeat();

        // Hide download button (managed by DownloadUIManager)
        this.uiManager.hideDownloadButton();

        // Check pause duration
        const pausedMs = Date.now() - (this.pauseSince || Date.now());
        this.log("PauseGate", `Paused for ${Math.round(pausedMs/1000)}s`);

        if (pausedMs > this.maxPauseMs) {
            this.log("PauseGate", `Paused too long (${Math.round(pausedMs/1000)}s > ${this.maxPauseMs/1000}s)`);
            this.onNeedReconnect(`Paused too long (${Math.round(pausedMs/1000)}s)`);
            return;
        }

        // WebRTC health check for P2P
        if (this.pendingKind === 'webrtc' && this.getWebRTCHealth) {
            const { pcState, dcState } = this.getWebRTCHealth();
            this.log("PauseGate", `WebRTC health: pc=${pcState}, dc=${dcState}`);

            if (dcState !== 'open' || ['failed', 'closed', 'disconnected'].includes(pcState)) {
                this.log("PauseGate", `WebRTC connection stale: pc=${pcState}, dc=${dcState}`);
                this.onNeedReconnect(`WebRTC stale: pc=${pcState}, dc=${dcState}`);
                return;
            }
        }

        // Start the download
        const fn = this.pendingStart;
        this.pendingStart = null;
        this.pendingKind = null;
        this.getWebRTCHealth = null;
        this.dataChannel = null;
        this.pauseSince = null;

        this.log("PauseGate", "Calling pending start function...");
        await fn?.();
    }

    /**
     * Check if currently paused
     */
    isPaused() {
        return this.paused;
    }
}

// ============================================================
// WebRTC Manager
// ============================================================

/**
 * WebRTCManager - Main WebRTC download manager
 * Encapsulates the entire WebRTC download flow including P2P connection,
 * data transfer, E2EE support, and HTTP fallback.
 */
class WebRTCManager {
    constructor(config) {
        // Required configuration
        this.uid = config.uid;                     // Actual UID (not template)
        this.disableWebRTC = config.disableWebRTC || false;
        this.debug = config.debug || false;

        // File metadata
        this.fileName = config.fileName;
        this.fileSize = config.fileSize;

        // Functions
        this.log = config.log;
        this.t = config.t;

        // DOM Elements
        this.elements = {
            progressBar: config.progressBar,
            statusText: config.statusText,
            connectionType: config.connectionType,
            downloadMessage: config.downloadMessage,
            downloadButton: config.downloadButton
        };

        // Configuration
        this.defaultFallbackMs = config.defaultFallbackMs || 30000;
        this.stallDetectionMs = config.stallDetectionMs || 12000;
        this.chunkSize = config.chunkSize || 256 * 1024; // 256 KB

        // Build endpoints from UID
        this.endpoints = {
            offer: `/${this.uid}/offer`,
            candidate: `/${this.uid}/candidate`,
            answer: `/${this.uid}/answer`,
            complete: `/${this.uid}/complete`,
            download: `/${this.uid}/download`,
            manifest: `/${this.uid}/manifest`,
            thumbnailTemplate: `/${this.uid}/thumb?path={path}&w=420&h=320&fmt=jpeg`,
            fileTemplate: `/${this.uid}/file?path={path}`
        };

        // State tracking
        this.downloadInitialized = false;
        this.dataChannelEstablished = false;
        this.bytesReceived = 0;
        this.connectionFailureHandled = false;
        this.downloadCompleted = false;
        this.lastProgressTs = 0;
        this.restartAttempted = false;
        this.stopCandidatePolling = false;

        // Timers
        this.disconnectedTime = null;
        this.disconnectDuringTransferTimer = null;
        this.stallFallbackTimer = null;

        // References
        this.writePump = null;
        this.debugConfig = null;
        this.uiManager = null;
        this.pauseGate = null;
        this.previewUI = null;
        this.fallbackManager = null;
        this.e2eeManager = null;
        this.webrtcDecryptor = null;
        this.pc = null;
        this.dc = null;
        this.peerId = null;
        this.cleanupConnectionsCallback = null;
    }

    /**
     * Check if WebRTC is supported in the browser
     */
    isWebRTCSupported() {
        return typeof RTCPeerConnection !== 'undefined' &&
               typeof RTCDataChannel !== 'undefined';
    }

    /**
     * Helper functions for state checking
     */
    hasTransferStarted() {
        return this.dataChannelEstablished && this.bytesReceived > 0;
    }

    isStalled() {
        if (!this.hasTransferStarted()) {
            return false;
        }
        if (this.lastProgressTs === 0) {
            return false;
        }
        const timeSinceLastProgress = Date.now() - this.lastProgressTs;
        return timeSinceLastProgress >= this.stallDetectionMs;
    }

    shouldStopPeerOperations() {
        return (this.fallbackManager && this.fallbackManager.fallbackTriggered) ||
               this.connectionFailureHandled ||
               this.downloadCompleted;
    }

    shouldHandlePreTransferFailure() {
        return !this.shouldStopPeerOperations() && !this.hasTransferStarted();
    }

    /**
     * Main entry point - start the WebRTC download process
     */
    async start() {
        // Prevent duplicate execution
        if (this.downloadInitialized) {
            return;
        }
        this.downloadInitialized = true;

        try {
            await this._initialize();
        } catch (error) {
            this.log("WebRTCManager", `Fatal error: ${error.message}`);
            this.log("WebRTCManager", `Stack: ${error.stack}`);
            // Fallback to HTTP download
            window.location.href = this.endpoints.download;
        }
    }

    /**
     * Initialize all managers and start the download process
     * @private
     */
    async _initialize() {
        // Initialize Debug Configuration Manager
        this.debugConfig = new DebugConfigManager(this.log);

        const fallbackMs = this.debugConfig.getFallbackTimeout(this.defaultFallbackMs);
        const countdownSeconds = Math.floor(fallbackMs / 1000);

        this.log("Init", "Starting WebRTC download process");
        this.log("Config", `Fallback timeout: ${fallbackMs}ms, Chunk size: ${this.chunkSize} bytes`);

        // E2EE Setup
        try {
            this.e2eeManager = new E2EEManager(this.log);
            const e2eeEnabled = await this.e2eeManager.checkE2EEStatus();
            if (e2eeEnabled) {
                this.log("E2EE", "🔒 End-to-End encryption enabled");
                this.webrtcDecryptor = await this.e2eeManager.setupWebRTCDecryptor();
                this.log("E2EE", "✓ Decryptor ready");
            }
        } catch (error) {
            this.log("E2EE", `Setup failed: ${error.message} - continuing without E2EE`);
            this.e2eeManager = null;
            this.webrtcDecryptor = null;
        }

        // Get connection info
        const connectionInfo = await getConnectionInfo();
        this.log("Client", `Browser: ${connectionInfo.browser}, Domain: ${connectionInfo.domain}`);
        this.log("Client", `Local: ${connectionInfo.isLocalConnection}, InApp: ${connectionInfo.inAppBrowser}, DownloadRestricted: ${connectionInfo.downloadRestricted}`);

        // Get file metadata
        this.log("File", `Name: ${this.fileName}, Size: ${this.fileSize} bytes`);

        // Preview mode check
        const urlParams = new URLSearchParams(window.location.search);
        const isPreviewMode = parseBooleanParam(urlParams.get('preview'));
        this.log("PreviewMode", `Mode: ${isPreviewMode ? 'preview-first' : 'download-first'}`);

        // Initialize UI Manager
        this.uiManager = new DownloadUIManager(this.elements, this.t);

        // Initialize PauseGate
        this.pauseGate = new PauseGate({
            uiManager: this.uiManager,
            log: this.log,
            t: this.t,
            onNeedReconnect: (reason) => {
                this.log("PauseGate", `Need reconnect: ${reason} - reloading page`);
                location.reload();
            }
        });

        // Initialize PreviewUI
        this.previewUI = new PreviewUI({
            log: this.log,
            debug: this.debug || false,
            metadataURL: this.endpoints.manifest,
            thumbnailURLTemplate: this.endpoints.thumbnailTemplate,
            fileURLTemplate: this.endpoints.fileTemplate,
            e2eeManager: this.e2eeManager,  // Share E2EE manager to avoid duplicate checks
            getDownloadState: () => ({
                started: this.hasTransferStarted(),
                completed: this.downloadCompleted,
                pauseFn: () => this.pauseGate.requestPause()
            })
        });

        // Expose PreviewUI globally for debugging
        window.previewUI = this.previewUI;

        // Auto-open preview in preview mode
        if (isPreviewMode) {
            this.previewUI.openPreview().then(() => {
                this.log("PreviewMode", "Auto-opened preview overlay");
            }).catch(err => {
                this.log("PreviewMode", `Failed to auto-open preview: ${err}`);
            });
        }

        // Initialize FallbackManager
        this.fallbackManager = new FallbackManager({
            debugConfig: this.debugConfig,
            e2eeManager: this.e2eeManager,
            uiManager: this.uiManager,
            fileSize: this.fileSize,
            uid: this.uid,
            downloadUrl: this.endpoints.download,
            log: this.log,
            t: this.t,
            getWritePump: () => this.writePump,
            getBytesReceived: () => this.bytesReceived,
            getDownloadCompleted: () => this.downloadCompleted,
            hasTransferStarted: () => this.hasTransferStarted(),
            isStalled: () => this.isStalled(),
            onConnectionFailureHandled: () => { this.connectionFailureHandled = true; }
        });

        // Fallback to HTTP helper
        const fallbackToHTTP = (reason, force = false) => {
            const startFn = () => this.fallbackManager.triggerFallback(reason, force);
            const shouldStartNow = this.pauseGate.setPendingStart({
                kind: 'http',
                startFn: startFn,
                getHealth: null
            });
            if (shouldStartNow) {
                startFn();
            } else {
                this.log("Fallback", "HTTP download paused - waiting for user to click download");
            }
        };

        // Set progress bar max
        this.uiManager.setProgressMax(this.fileSize);

        // Check for download restrictions
        if (typeof SKIP_WEBRTC_DUE_TO_RESTRICTION !== 'undefined' && SKIP_WEBRTC_DUE_TO_RESTRICTION) {
            this.log("InAppGuard", "Download blocked due to in-app browser restrictions");
            this.uiManager.showBrowserNotSupported();
            return;
        }

        // Check if file download is supported
        if (!WriterFactory.isSupported(this.fileSize)) {
            const reason = WriterFactory.getUnsupportedReason(this.fileSize);
            this.log("WriterFactory", `File download not supported: ${reason}`);
            fallbackToHTTP(this.t('Download:client.fallback.fileTooBig', 'File too large for direct download - using server relay'));
            return;
        }

        // Initialize WritePump with lazy writer factory
        // Writer creation (and PreviewUI.wrapWriter) only happens when first chunk arrives
        // This allows WebRTC connection to start immediately without blocking on metadata fetch
        this.writePump = new WritePump(async () => {
            // Create writer (deferred until first chunk)
            const writerContext = WriterFactory.create(this.fileName, this.fileSize);
            this.log("WriterFactory", `Created ${writerContext.type} writer`);

            // Wrap writer with TeeWriter if file is previewable
            // This is where metadata fetch happens (if not already loaded)
            const finalWriter = await this.previewUI.wrapWriter(writerContext.writer);

            return finalWriter;
        }, this.fileSize, {
            onComplete: ({ bytesWritten, writer }) => {
                this.log("Download", `✅ Complete! ${bytesWritten} bytes written`);
                this._downloadComplete();
            },
            onFallback: (reason) => {
                this.log("Download", `WritePump fallback: ${reason}`);
                if (!this.shouldStopPeerOperations()) {
                    fallbackToHTTP(reason, true);
                }
            },
            log: this.log
        });

        this.log("WritePump", `Initialized with lazy writer factory (writer created on first chunk)`);

        // Check WebRTC support
        const webrtcSupported = this.isWebRTCSupported();

        if (!webrtcSupported || this.disableWebRTC) {
            if (!webrtcSupported) {
                this.log("WebRTC", "WebRTC not supported in this browser");
                fallbackToHTTP(this.t('Download:client.fallback.webrtcNotSupported', 'WebRTC not supported - using server relay'));
            } else {
                fallbackToHTTP(this.t('Download:client.fallback.p2pDisabled', 'Device-to-Device P2P disabled. Use Relayed P2P.'));
            }
            return;
        }

        // Start WebRTC connection
        await this._startWebRTCConnection(fallbackMs, countdownSeconds, fallbackToHTTP);
    }

    /**
     * Start WebRTC P2P connection
     * @private
     */
    async _startWebRTCConnection(fallbackMs, countdownSeconds, fallbackToHTTP) {
        // Show establishing P2P status
        this.uiManager.showEstablishingP2P(countdownSeconds, () => this.shouldStopPeerOperations());

        // Request offer from server
        this.log("WebRTC", "Requesting offer from server");
        let offerResponse;

        try {
            let offerURL = this.endpoints.offer;
            const debugParams = this.debugConfig.buildOfferDebugParams();

            if (debugParams) {
                offerURL += '?' + debugParams;
                this.log("WebRTC", `Using debug offer URL: ${offerURL}`);
            }

            offerResponse = await fetch(offerURL);
            this.log("WebRTC", `Got response: ${offerResponse.status} ${offerResponse.statusText}`);
        } catch (err) {
            this.log("WebRTC", "Failed to fetch offer:", err);
            fallbackToHTTP("Failed to get offer from server");
            return;
        }

        if (!offerResponse.ok) {
            this.log("WebRTC", `Server returned ${offerResponse.status}: ${offerResponse.statusText}`);
            fallbackToHTTP(`Server returned ${offerResponse.status}`);
            return;
        }

        // Parse offer data
        let offerData;
        try {
            offerData = await offerResponse.json();
            this.log("WebRTC", `Parsed offer data: type=${offerData.type}, sdp length=${offerData.sdp.length}`);
            this.log("WebRTC", `SDP excerpt: ${offerData.sdp.substring(0, 50)}...`);

            this.peerId = offerData.peerId;
            this.log("WebRTC", `Got peerId: ${this.peerId}`);
        } catch (err) {
            this.log("WebRTC", "Failed to parse offer data:", err);
            fallbackToHTTP("Invalid offer data from server");
            return;
        }

        // Setup peer connection
        await this._setupPeerConnection(offerData, fallbackMs, fallbackToHTTP);
    }

    /**
     * Setup RTCPeerConnection and data channel
     * @private
     */
    async _setupPeerConnection(offerData, fallbackMs, fallbackToHTTP) {
        this.log("WebRTC", "Setting up peer connection...");

        try {
            // Create RTCPeerConnection with STUN servers
            this.log("WebRTC", "Creating peer connection");
            this.pc = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun.cloudflare.com:3478' },
                    { urls: 'stun:stun.nextcloud.com:443' },
                    { urls: 'stun:openrelayproject.org:80' },
                    { urls: 'stun:openrelayproject.org:443' }
                ],
            });
            this.log("WebRTC", "Peer connection created:", this.pc);

            // Create fallback timer
            this.fallbackManager.createFallbackTimer(fallbackMs);

            // Setup ICE connection state handler
            this.pc.oniceconnectionstatechange = () => this._handleICEConnectionStateChange(fallbackToHTTP);

            // Simplified connection state monitoring
            this.pc.onconnectionstatechange = () => {
                if (this.shouldStopPeerOperations()) {
                    return;
                }

                // Only handle clear failures before transfer starts
                if (this.pc.connectionState === 'failed' &&
                    this.shouldHandlePreTransferFailure()) {
                    fallbackToHTTP("WebRTC connection failed");
                }
            };

            // ICE candidate handler
            this.pc.onicecandidate = (event) => this._handleICECandidate(event);

            // Data channel handler
            this.log("WebRTC", "Setting up data channel handler");
            this.pc.ondatachannel = ({ channel }) => {
                this._handleDataChannelReceived(channel, fallbackToHTTP);
            };

            // SDP Exchange
            await this._setRemoteOffer(offerData, fallbackToHTTP);
            await this._createAndSetAnswer(fallbackToHTTP);
            await this._sendAnswerToServer(fallbackToHTTP);

            // Start polling remote candidates
            this._startPollingRemoteCandidates(this.pc);

            this.log("WebRTC", "Waiting for data channel...");

        } catch (error) {
            this.log("WebRTC", `Setup failed: ${error.message}`);
            fallbackToHTTP("WebRTC setup failed");
        }
    }

    /**
     * Handle ICE connection state changes
     * @private
     */
    _handleICEConnectionStateChange(fallbackToHTTP) {
        this.log("ICE", `Connection state changed to: ${this.pc.iceConnectionState}`);

        // If P2P operations should stop, ignore
        if (this.shouldStopPeerOperations()) {
            return;
        }

        switch (this.pc.iceConnectionState) {
            case 'checking':
                this.uiManager.showP2PChecking();
                break;

            case 'connected':
                // Clear countdown and disconnect timers when connection established
                this.uiManager.stopCountdown();
                this.log("UI", "Countdown cleared on connection established");
                this.disconnectedTime = null;

                if (this.disconnectDuringTransferTimer) {
                    clearTimeout(this.disconnectDuringTransferTimer);
                    this.disconnectDuringTransferTimer = null;
                }

                this.stopCandidatePolling = true;
                this.log("ICE", "Connection established successfully");
                break;

            case 'completed':
                this.disconnectedTime = null;

                if (this.disconnectDuringTransferTimer) {
                    clearTimeout(this.disconnectDuringTransferTimer);
                    this.disconnectDuringTransferTimer = null;
                }

                this.log("ICE", "All ICE candidates have been found");
                break;

            case 'disconnected':
                this.log("ICE", "Connection lost temporarily");

                if (!this.hasTransferStarted()) {
                    this.disconnectedTime = Date.now();
                    this.uiManager.showReconnecting();

                    // Increased timeout for pre-transfer disconnections
                    setTimeout(() => {
                        if (this.pc.iceConnectionState === 'disconnected' &&
                            this.disconnectedTime &&
                            Date.now() - this.disconnectedTime > 15000 &&
                            this.shouldHandlePreTransferFailure()) {

                            fallbackToHTTP("Connection lost before transfer started");
                        }
                    }, 16000);

                // During transfer: show network fluctuation and set fallback timer
                } else {
                    this.log("ICE", "Network fluctuation during transfer - continuing");
                    this.uiManager.showNetworkFluctuation();

                    // Don't create duplicate timers
                    if (!this.disconnectDuringTransferTimer) {
                        const delay = this.stallDetectionMs + 3000; // Buffer beyond stall detection

                        this.disconnectDuringTransferTimer = setTimeout(() => {
                            this.disconnectDuringTransferTimer = null;

                            // Exit if download already completed or fallback triggered
                            if (this.shouldStopPeerOperations()) {
                                return;
                            }

                            // Exit if ICE recovered to connected/completed
                            if (this.pc.iceConnectionState !== 'disconnected') {
                                return;
                            }

                            // Conservative: only fallback if transfer started AND actually stalled
                            if (!this.hasTransferStarted() || !this.isStalled()) {
                                return;
                            }

                            this.log("ICE", "Still disconnected and stalled - switching to HTTP fallback");
                            // Use force = true to bypass "transfer in progress" protection
                            fallbackToHTTP("ICE disconnected during active transfer (stalled)", true);
                        }, delay);
                    }
                }
                break;

            case 'failed':
                // Only handle failure if transfer hasn't started
                if (!this.hasTransferStarted()) {
                    if (!this.restartAttempted) {
                        this.restartAttempted = true;
                        this.log("ICE", "ICE failed – trying restartIce() once");
                        this.pc.restartIce();
                        this.uiManager.showRetryingP2P();

                        setTimeout(() => {
                            if ((this.pc.iceConnectionState === 'failed' || this.pc.iceConnectionState === 'disconnected') &&
                                this.shouldHandlePreTransferFailure()) {

                                fallbackToHTTP("Connection restart failed");
                            }
                        }, 20000);
                    } else {
                        fallbackToHTTP("Connection failed after restart");
                    }
                } else {
                    this.log("ICE", "ICE failed during transfer - but data channel still active");
                }
                break;

            case 'closed':
                this.log("ICE", "Connection closed");
                break;
        }
    }

    /**
     * Send local ICE candidate to server
     * @private
     */
    _sendLocalCandidate(candidate) {
        const candidateData = {
            peerId: this.peerId,
            candidate: candidate.candidate,
            sdpMid: candidate.sdpMid,
            sdpMLineIndex: candidate.sdpMLineIndex
        };

        const candidateJson = JSON.stringify(candidateData);
        this.log("ICE", `New candidate: ${candidate.candidate?.substring(0, 50)}...`);

        this.log("ICE", `Sending candidate to server: ${candidateJson.substring(0, 50)}...`);
        fetch(this.endpoints.candidate, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: candidateJson,
        }).then(() => {
            this.log("ICE", `Successfully sent candidate to server`);
            // Don't update status if we're past connecting phase (paused or downloading)
            if (!this.shouldStopPeerOperations() && !this.hasTransferStarted() && !this.pauseGate.isPaused()) {
                this.uiManager.showP2PConnecting();
            }
        }).catch(err => {
            this.log("ICE", `Failed to send candidate:`, err);
            // Continue despite error - this might not be fatal
        });
    }

    /**
     * Send end-of-candidates marker to server
     * @private
     */
    _sendEndOfCandidates() {
        const endCandidatesData = {
            peerId: this.peerId,
            candidate: 'end-of-candidates'
        };

        fetch(this.endpoints.candidate, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(endCandidatesData),
        }).catch(err => {
            this.log("ICE", `Failed to send end-of-candidates:`, err);
        });

        this.log("ICE", "All candidates gathered");
    }

    /**
     * Handle ICE candidate events
     * @private
     */
    _handleICECandidate(event) {
        if (event.candidate) {
            this._sendLocalCandidate(event.candidate);
        } else {
            this._sendEndOfCandidates();
        }
    }

    /**
     * Setup data channel event handlers
     * @private
     */
    _setupDataChannelHandlers(dc) {
        // Configure data channel
        dc.binaryType = 'arraybuffer';
        this.log("DataChannel", `Binary type set to: ${dc.binaryType}`);

        // Register cleanup callback for downloadComplete function
        this.cleanupConnectionsCallback = () => {
            setTimeout(() => {
                this.log("WebRTC", "Closing peer connection");

                try {
                    dc.close();
                    this.log("DataChannel", "Closed");
                } catch (e) {
                    this.log("DataChannel", "Error closing:", e);
                }

                try {
                    this.pc.close();
                    this.log("WebRTC", "Peer connection closed");
                } catch (e) {
                    this.log("WebRTC", "Error closing peer connection:", e);
                }
            }, 500);
        };

        // Enhanced data channel state monitoring
        dc.onopen = () => {
            this.log("DataChannel", "Channel opened");
            this.dataChannelEstablished = true;
            this.lastProgressTs = Date.now();
        };

        dc.onclose = () => {
            this.log("DataChannel", "Channel closed");
            if (this.stallFallbackTimer) {
                clearTimeout(this.stallFallbackTimer);
                this.stallFallbackTimer = null;
            }
            const bytesWrittenSoFar = this.writePump.bytesWritten;
            if (!this.shouldStopPeerOperations() && bytesWrittenSoFar < this.fileSize) {
                this.log("DataChannel", `Channel closed before completion (written: ${bytesWrittenSoFar}/${this.fileSize})`);
                const fallbackToHTTP = (reason, force = false) => {
                    const startFn = () => this.fallbackManager.triggerFallback(reason, force);
                    const shouldStartNow = this.pauseGate.setPendingStart({
                        kind: 'http',
                        startFn: startFn,
                        getHealth: null
                    });
                    if (shouldStartNow) {
                        startFn();
                    }
                };
                fallbackToHTTP("Data channel closed unexpectedly", true);
            }
        };

        dc.onerror = (err) => {
            this.log("DataChannel", "Error:", err);
            if (!this.shouldStopPeerOperations()) {
                const fallbackToHTTP = (reason, force = false) => {
                    const startFn = () => this.fallbackManager.triggerFallback(reason, force);
                    const shouldStartNow = this.pauseGate.setPendingStart({
                        kind: 'http',
                        startFn: startFn,
                        getHealth: null
                    });
                    if (shouldStartNow) {
                        startFn();
                    }
                };
                fallbackToHTTP("Data channel error", true);
            }
        };
    }

    /**
     * Handle control messages (EOF, ERROR, PONG)
     * @private
     */
    async _handleControlMessage(message, fallbackToHTTP) {
        this.log("DataChannel", `Received string message: ${message}`);

        if (message === 'PONG') {
            // Heartbeat response from server (no action needed, just keepalive)
            return;
        } else if (message === 'EOF') {
            this.log("DataChannel", `End of file received after ${this._chunks} chunks, ${this._received} bytes`);
            this.uiManager.showSavingFile();

            // EOF with deadline - if writer stuck, fallback to HTTP resume
            const FINISH_DEADLINE_MS = 10000; // 10 seconds for writer to finish
            try {
                await Promise.race([
                    this.writePump.eof(),
                    new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('writer-finish-timeout')), FINISH_DEADLINE_MS)
                    )
                ]);
                // Success - EOF completed within deadline
            } catch (err) {
                // Writer stuck (SW/mitm not accepting writes fast enough)
                this.log("DataChannel", `Writer finish timeout after ${FINISH_DEADLINE_MS}ms: ${err.message}`);
                this.log("DataChannel", `Preparing for HTTP fallback with resume from ${this.writePump.bytesWritten} bytes`);

                // Prepare for fallback - flush pending writes but keep writer open
                await this.writePump.prepareForFallback(5000, 'Writer stuck finishing after EOF');

                // Trigger HTTP fallback with resume support
                fallbackToHTTP('Writer stuck finishing after EOF', true);
            }
        } else if (message === 'ERROR') {
            this.log("DataChannel", "Server reported error");
            if (!this.shouldStopPeerOperations()) {
                fallbackToHTTP("Server reported error", true);
            }
        } else {
            this.log("DataChannel", `Unknown string message: ${message}`);
        }
    }

    /**
     * Update progress UI (throttled)
     * @private
     */
    _updateProgressUI(received, chunks) {
        const now = Date.now();
        if (now - this._lastProgressUpdate >= this._PROGRESS_THROTTLE_MS || received === this.fileSize) {
            this._lastProgressUpdate = now;

            // Log progress periodically
            if (chunks % 50 === 0 || received === this.fileSize) {
                this.log("Progress", `Received ${chunks} chunks, ${received} bytes (written: ${this.writePump.bytesWritten})`);
            }

            // Update UI progress
            this.uiManager.updateProgress(received, this.fileSize);
        }
    }

    /**
     * Handle binary data chunk
     * @private
     */
    async _handleBinaryData(data, dc, fallbackToHTTP) {
        if (this._chunks === 0) {
            this.log("DataChannel", `>>> First binary chunk received! <<<`);
            // NOW show P2P success - we confirmed data is flowing
            this.uiManager.showP2PSuccess();
            this.log("DataChannel", "✓ P2P transfer confirmed - data flowing");
        }

        // Binary data - decrypt if E2EE enabled
        let plainData = data;
        if (this.webrtcDecryptor) {
            const encryptedChunk = new Uint8Array(data);
            plainData = (await this.webrtcDecryptor.decryptChunk(encryptedChunk)).buffer;
        }

        // Update progress immediately (not tied to writing)
        this._chunks++;
        this._received += plainData.byteLength;
        this.bytesReceived = this._received; // Update global tracker for UI/progress

        if (this.debugConfig.shouldLogForceFallbackCandidate()) {
            this.log(
                "Fallback",
                `Force fallback candidate: chunk=${plainData.byteLength}, received=${this.bytesReceived}, threshold=${this.debugConfig.forceFallbackThreshold}`
            );
        }

        if (this.debugConfig.shouldForceFallback(this.bytesReceived)) {
            this.log("Fallback", "Force fallback parameter detected - switching to HTTP");
            fallbackToHTTP("Forced fallback via URL parameter", true);
            return;
        }

        // Debug: Simulate stall after specified bytes
        if (this.debugConfig.simulateStallIfNeeded(this._received, dc)) {
            if (!this.stallFallbackTimer) {
                this.stallFallbackTimer = setTimeout(() => {
                    this.stallFallbackTimer = null;
                    if (!this.shouldStopPeerOperations()) {
                        this.log("Fallback", "Simulated stall did not close channel - forcing HTTP fallback");
                        fallbackToHTTP("Simulated stall did not close channel", true);
                    }
                }, 2000);
            }
            return;
        }

        this.lastProgressTs = Date.now(); // Update progress timestamp

        // Queue data for writing - WritePump handles all write ordering
        this.writePump.enqueue(new Uint8Array(plainData));

        // Immediate progress updates (not tied to write completion)
        this._updateProgressUI(this._received, this._chunks);
    }

    /**
     * Handle data channel message (control or binary)
     * @private
     */
    async _handleDataChannelMessage(data, dc, fallbackToHTTP) {
        // Check message type (control or data)
        if (typeof data === 'string') {
            await this._handleControlMessage(data, fallbackToHTTP);
        } else {
            await this._handleBinaryData(data, dc, fallbackToHTTP);
        }
    }

    /**
     * Start P2P transfer (send START signal)
     * @private
     */
    async _startP2PTransfer(dc) {
        // Wait for dc to be open (if not already)
        if (dc.readyState !== 'open') {
            this.log("DataChannel", `Waiting for channel to open (current: ${dc.readyState})...`);
            await new Promise((resolve, reject) => {
                const onOpen = () => { cleanup(); resolve(); };
                const onFail = () => { cleanup(); reject(new Error(`dc not open: ${dc.readyState}`)); };
                const cleanup = () => {
                    dc.removeEventListener('open', onOpen);
                    dc.removeEventListener('close', onFail);
                    dc.removeEventListener('error', onFail);
                };
                dc.addEventListener('open', onOpen, { once: true });
                dc.addEventListener('close', onFail, { once: true });
                dc.addEventListener('error', onFail, { once: true });
            });
        }

        // Send START signal to server (requires server-side support)
        // NOTE: Server must wait for START before sending file data
        try {
            dc.send('START');
            this.log("DataChannel", "✓ START signal sent");
        } catch (e) {
            this.log("DataChannel", `✗ Failed to send START: ${e}`);
            throw e; // Re-throw to trigger fallback
        }

        // Don't show "P2P success" yet - wait for first binary chunk
        this.uiManager.setStatus('Starting download...');
        this.uiManager.setConnectionType(
            this.t('Download:client.connection.p2pReady', 'P2P Connection Ready')
        );
    }

    /**
     * Handle data channel received from peer
     * @private
     */
    _handleDataChannelReceived(dc, fallbackToHTTP) {
        this.log("DataChannel", `Received data channel: ${dc.label}, ID: ${dc.id}`);
        this.log("DataChannel", `ordered=${dc.ordered}, maxRetransmits=${dc.maxRetransmits ?? 'null'}, maxPacketLifeTime=${dc.maxPacketLifeTime ?? 'null'}`);

        this.dataChannelEstablished = true;
        this.lastProgressTs = Date.now(); // Initialize progress timestamp when channel is established
        this.fallbackManager.clearFallbackTimer();
        this.log("Fallback", "Cleared timeout - connection successful");

        // Setup all data channel handlers (onopen, onclose, onerror)
        this._setupDataChannelHandlers(dc);

        // Message processing state
        this._received = 0;
        this._chunks = 0;
        this._lastProgressUpdate = 0;
        this._PROGRESS_THROTTLE_MS = 50; // Faster progress updates (50ms)

        // Sequential processing to prevent race conditions (especially for small files)
        let messageProcessingChain = Promise.resolve();

        // Set up message handler NOW before sending START
        dc.onmessage = ({ data }) => {
            // Chain message processing to ensure sequential execution
            messageProcessingChain = messageProcessingChain
                .then(() => this._handleDataChannelMessage(data, dc, fallbackToHTTP))
                .catch(err => {
                    this.log("DataChannel", `Message processing error: ${err}`);
                    if (!this.shouldStopPeerOperations()) {
                        fallbackToHTTP("Message processing error", true);
                    }
                });
        };

        // Store dc reference for pause gate and cleanup
        this.dc = dc;

        // Check preview mode
        const urlParams = new URLSearchParams(window.location.search);
        const isPreviewMode = parseBooleanParam(urlParams.get('preview'));

        // Use PauseGate to control when transfer starts
        // If in preview mode, request pause before registering pending start
        if (isPreviewMode) {
            this.pauseGate.requestPause();
        }

        // Always register the pending start (returns true if should start now, false if paused)
        const shouldStartNow = this.pauseGate.setPendingStart({
            kind: 'webrtc',
            startFn: () => this._startP2PTransfer(dc),
            getHealth: () => ({
                pcState: this.pc.connectionState,
                dcState: dc.readyState
            }),
            dataChannel: dc
        });

        // Determine behavior based on mode and pause state
        if (shouldStartNow) {
            // Download-first mode: START sent immediately
            this.log("DataChannel", "Auto-starting download");
            this._startP2PTransfer(dc).catch(err => {
                this.log("DataChannel", `✗ Failed to start P2P transfer: ${err}`);
                fallbackToHTTP("Failed to start P2P transfer", true);
            });
        } else {
            // Paused or preview-first mode: wait for user action (PauseGate handles heartbeat)
            this.log("DataChannel", `⏸ Transfer paused - ${isPreviewMode ? 'preview mode' : 'user pause'}`);
        }
    }

    /**
     * Set remote SDP offer
     * @private
     */
    async _setRemoteOffer(offerData, fallbackToHTTP) {
        this.log("WebRTC", "Setting remote description");
        try {
            await this.pc.setRemoteDescription({ type: offerData.type, sdp: offerData.sdp });
            this.log("WebRTC", "Remote description set successfully");
        } catch (err) {
            this.log("WebRTC", "Failed to set remote description:", err);
            fallbackToHTTP("Failed to set remote description");
            throw err; // Re-throw to stop execution
        }
    }

    /**
     * Create and set SDP answer
     * @private
     */
    async _createAndSetAnswer(fallbackToHTTP) {
        this.log("WebRTC", "Creating answer");
        try {
            const answer = await this.pc.createAnswer();
            this.log("WebRTC", `Answer created: type=${answer.type}, sdp length=${answer.sdp.length}`);
            this.log("WebRTC", `Answer SDP excerpt: ${answer.sdp.substring(0, 50)}...`);

            this.log("WebRTC", "Setting local description");
            await this.pc.setLocalDescription(answer);
            this.log("WebRTC", "Local description set successfully");

            return answer;
        } catch (err) {
            this.log("WebRTC", "Failed to create/set answer:", err);
            fallbackToHTTP("Failed to create answer");
            throw err; // Re-throw to stop execution
        }
    }

    /**
     * Send SDP answer to server
     * @private
     */
    async _sendAnswerToServer(fallbackToHTTP) {
        this.log("WebRTC", "Sending answer to server");
        try {
            const connectionInfo = await getConnectionInfo();
            const answerResponse = await fetch(this.endpoints.answer, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    peerId: this.peerId,
                    sdp: this.pc.localDescription.sdp,
                    type: this.pc.localDescription.type,
                    clientInfo: connectionInfo
                }),
            });
            this.log("WebRTC", `Answer sent, response: ${answerResponse.status} ${answerResponse.statusText}`);
        } catch (err) {
            this.log("WebRTC", "Failed to send answer:", err);
            fallbackToHTTP("Failed to send answer to server");
            throw err; // Re-throw to stop execution
        }
    }

    /**
     * Start polling remote ICE candidates
     * @private
     */
    async _startPollingRemoteCandidates(pcRef) {
        while (!this.stopCandidatePolling) {
            try {
                // GET candidate endpoint (204 = Temporarily unavailable)
                const resp = await fetch(`${this.endpoints.candidate}?peer=${this.peerId}`);
                if (resp.status === 204) {
                    await new Promise(r => setTimeout(r, 200)); // Ask again in 200 ms
                    continue;
                }
                if (resp.status === 404) {
                    this.log("ICE", "Server reports peer closed, stop polling");
                    break;
                }
                if (!resp.ok) {                               // Exit on other errors
                    this.log("ICE", `Fetch remote cand failed: ${resp.status}`);
                    break;
                }

                const cand = await resp.json();
                if (cand.candidate === "end-of-candidates") { // All candidates received
                    this.log("ICE", "End-of-candidates from server");
                    break;
                }

                this.log("ICE", `Remote candidate: ${cand.candidate?.substring(0,50)}...`);
                await pcRef.addIceCandidate(cand);            // Add to ICE agent
            } catch (err) {
                this.log("ICE", `Polling error: ${err}`);
                break;
            }
        }
    }

    /**
     * Handle download completion
     * @private
     */
    _downloadComplete() {
        if (this.downloadCompleted) {
            return;
        }

        if (this.fileSize && this.bytesReceived < this.fileSize) {
            this.log("Download", `Incomplete P2P transfer detected: expected ${this.fileSize}, got ${this.bytesReceived}`);
            if (!this.shouldStopPeerOperations()) {
                const fallbackToHTTP = (reason, force = false) => {
                    const startFn = () => this.fallbackManager.triggerFallback(reason, force);
                    const shouldStartNow = this.pauseGate.setPendingStart({
                        kind: 'http',
                        startFn: startFn,
                        getHealth: null
                    });
                    if (shouldStartNow) {
                        startFn();
                    }
                };
                fallbackToHTTP("Incomplete P2P transfer detected", true);
            }
            return;
        }

        this.log("Download", "Complete!");
        this.downloadCompleted = true;

        // Show completion UI
        this.uiManager.showComplete(this.fileSize);

        // Notify server
        if (this.peerId) {
            this.log("Signal", `Notifying server of download completion for peer ${this.peerId}`);
            fetch(this.endpoints.complete, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ peerId: this.peerId, receivedBytes: this.bytesReceived }),
            }).then(() => {
                this.log("Signal", "Successfully notified server of completion");
            }).catch(err => {
                this.log("Signal", `Failed to notify server of completion: ${err}`);
            });
        }

        // Stop polling and timers
        this.stopCandidatePolling = true;
        this.connectionFailureHandled = true;
        this.fallbackManager.clearFallbackTimer();
        this.uiManager.stopCountdown();

        // Cleanup connections
        if (this.cleanupConnectionsCallback) {
            this.cleanupConnectionsCallback();
        }
    }
}
