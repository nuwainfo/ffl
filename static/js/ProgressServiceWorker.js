/*!
 * FastFileLink - Progress Service Worker
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 * See LICENSE file in the project root for full license information.
 */

// Import E2EE decryption functions (DRY - don't duplicate code)
// These functions are defined in E2EE.js and should be available in Service Worker scope
// Note: importScripts requires same-origin, so E2EE.js must be served from the same domain as this SW
try {
    importScripts('/static/js/E2EE.js');
} catch (e) {
    console.error('[ProgressSW] Failed to import E2EE.js:', e);
    console.error('[ProgressSW] E2EE.js must be served from the same origin as the Service Worker');
}

// Verbose log function for debug mode
const verboseLog = function(...args) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}]`, ...args);
    try {
        const formatted = args.map(arg => {
            if (typeof arg === 'string') return arg;
            try {
                return JSON.stringify(arg);
            } catch (e) {
                return String(arg);
            }
        }).join(' ');
        broadcast({ type: 'debug', message: `[${timestamp}] ${formatted}` });
    } catch (e) {
        // Ignore broadcast errors in logging helper
    }
};

// Silent log function for normal mode
const silentLog = function() {};

// Initialize with silent log (will be updated per-request based on debug parameter)
let log = (typeof self.log === 'function') ? self.log : silentLog;

log('[ProgressSW] Service Worker script loaded');

self.addEventListener('install', (e) => {
    log('[ProgressSW] Install event');
    self.skipWaiting();
});

self.addEventListener('activate', (e) => {
    log('[ProgressSW] Activate event');
    e.waitUntil(self.clients.claim());
});

// BroadcastChannel for progress updates
let dlChannel = null;
function broadcast(msg) {
    if (!dlChannel && 'BroadcastChannel' in self) {
        dlChannel = new BroadcastChannel('dl-progress');
    }
    dlChannel && dlChannel.postMessage(msg);
}

function isDownloadRequest(url) {
    return url.origin === self.location.origin && url.pathname.endsWith('/download');
}

// Helper function to get configuration from URL parameters
function getConfigFromUrl(url, paramName, defaultValue) {
    try {
        const paramValue = url.searchParams.get(paramName);
        if (paramValue !== null) {
            const parsed = parseInt(paramValue, 10);
            if (!isNaN(parsed) && parsed > 0) {
                return parsed;
            }
        }
    } catch (e) {
        log('[ProgressSW] Error parsing config parameter:', paramName, e);
    }
    return defaultValue;
}

// Helper function to get file size from Content-Length header or URL parameter
function getFileSize(upstream, url) {
    const contentRange = parseContentRange(upstream.headers.get('Content-Range'));
    if (contentRange && contentRange.total) {
        return contentRange.total;
    }

    let total = parseInt(upstream.headers.get('Content-Length') || '0', 10);

    // Fallback to URL parameter if header is missing or 0
    if (!total || total === 0) {
        const sizeParam = url.searchParams.get('size');
        if (sizeParam) {
            total = parseInt(sizeParam, 10);
            log('[ProgressSW] Using file size from URL parameter:', total, 'bytes');
        }
    }

    return total;
}

// Firefox detection - use user agent from service worker context
const isFirefox = (typeof navigator !== 'undefined' && navigator.userAgent.includes('Firefox')) ||
                  (typeof self !== 'undefined' && self.navigator?.userAgent?.includes('Firefox'));

// E2EE decryption context storage (download ID -> context)
const e2eeContexts = new Map();
// Resume configuration storage (download ID -> resume settings)
const resumeConfigs = new Map();

function parseContentRange(header) {
    if (!header) {
        return null;
    }

    const match = header.match(/bytes\s+(\d+)-(\d+)\/(\d+|\*)/i);
    if (!match) {
        return null;
    }

    const start = parseInt(match[1], 10);
    const end = parseInt(match[2], 10);
    const total = match[3] === '*' ? null : parseInt(match[3], 10);

    return {
        start: Number.isFinite(start) ? start : null,
        end: Number.isFinite(end) ? end : null,
        total: total !== null && Number.isFinite(total) ? total : null
    };
}

function buildResumeAwareRequest(request, resumeConfig) {
    if (
        !resumeConfig ||
        typeof resumeConfig.rangeStart !== 'number' ||
        resumeConfig.rangeStart <= 0
    ) {
        return request;
    }

    const headers = new Headers(request.headers);
    headers.set('Range', `bytes=${resumeConfig.rangeStart}-`);
    headers.set('Cache-Control', 'no-cache');

    return new Request(request, { headers });
}

// Message handler for E2EE context registration and resume configuration
self.addEventListener('message', (event) => {
    log('[ProgressSW] Message received:', event.data?.type);

    if (event.data && event.data.type === 'e2ee-context') {
        const { downloadId, context } = event.data;
        log('[ProgressSW] E2EE context message - downloadId:', downloadId, 'hasContext:', !!context);
        log('[ProgressSW] Current e2eeContexts size:', e2eeContexts.size, 'keys:', Array.from(e2eeContexts.keys()));
        if (downloadId && context) {
            e2eeContexts.set(downloadId, context);
        } else {
            log('[ProgressSW] Invalid E2EE context message - missing downloadId or context');
        }
    } else if (event.data && event.data.type === 'download-resume') {
        const { downloadId, resume } = event.data;
        if (downloadId && resume && typeof resume.rangeStart === 'number') {
            resumeConfigs.set(downloadId, {
                rangeStart: Math.max(0, Number(resume.rangeStart) || 0),
                baseBytes: Math.max(0, Number(resume.baseBytes) || 0),
                skipBytes: Math.max(0, Number(resume.skipBytes) || 0),
                expectedSize: Math.max(0, Number(resume.expectedSize) || 0),
                chunkSize: Math.max(0, Number(resume.chunkSize) || 0)
            });
            log('[ProgressSW] Resume config stored - downloadId:', downloadId, 'config:', resumeConfigs.get(downloadId));
        } else {
            log('[ProgressSW] Invalid resume message:', event.data);
        }
    }
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    if (event.request.method === 'GET' && isDownloadRequest(url)) {
        // Check for debug parameter and switch log function accordingly
        const debugEnabled = url.searchParams.get('debug') === '1';
        if (debugEnabled) {
            log = verboseLog;
            log('[ProgressSW] Debug mode ENABLED for this request');
        } else {
            log = silentLog;
        }

        const downloadId = url.searchParams.get('dl') || url.pathname;
        const resumeConfig = resumeConfigs.get(downloadId);
        const hasRangeHeader = !!event.request.headers.get('Range');

        if (hasRangeHeader && !resumeConfig) {
            log('[ProgressSW] Range request detected without SW resume config, passing through');
            event.respondWith(fetch(event.request));
            return;
        }

        log('[ProgressSW] ✅ INTERCEPTING download request:', url.pathname);

        // Check for Firefox routing flags
        const ffPass = url.searchParams.get('ff_pass') === '1'; // Large file/unknown → pass-through
        const ffSW = url.searchParams.get('ff_sw') === '1';     // Small file → SW with transform

        if (resumeConfig) {
            log('[ProgressSW] Resume configuration detected - forcing TransformStream handling');
            event.respondWith(handleDownloadWithTransform(event, url, downloadId, resumeConfig));
        } else if (ffPass) {
            // Firefox large file: pass-through mode
            log('[ProgressSW] Firefox large file - using pass-through mode');
            event.respondWith(handleFirefoxPassthrough(event, url, downloadId));
        } else if (ffSW || !isFirefox) {
            // Firefox small file OR Chromium: use TransformStream
            log('[ProgressSW] Firefox small file or Chromium - using TransformStream mode');
            event.respondWith(handleDownloadWithTransform(event, url, downloadId, null));
        } else {
            // Fallback: use TransformStream for unknown cases
            log('[ProgressSW] Unknown routing case - defaulting to TransformStream mode');
            event.respondWith(handleDownloadWithTransform(event, url, downloadId, null));
        }
    }
});

async function handleFirefoxPassthrough(event, url, downloadId) {
    log('[ProgressSW] Firefox pass-through mode (large file/unknown size), ID:', downloadId);

    try {
        const upstream = await fetch(event.request);

        if (upstream.ok) {
            const total = getFileSize(upstream, url);
            log('[ProgressSW] Firefox passthrough - broadcasting started, size:', total, 'bytes');

            // Broadcast started event for Firefox
            broadcast({ type: 'download-started', id: downloadId, total });
        }

        return upstream;
    } catch (err) {
        console.error('[ProgressSW] Firefox passthrough failed:', err);
        broadcast({ type: 'download-error', id: downloadId, message: String(err) });
        return fetch(event.request);
    }
}

async function handleDownloadWithTransform(event, url, downloadId, resumeConfig) {
    const e2eeEnabled = url.searchParams.get('e2ee') === '1';

    log('[ProgressSW] Handling download with TransformStream, ID:', downloadId, 'E2EE:', e2eeEnabled, 'resume:', !!resumeConfig);
    if (resumeConfig) {
        log('[ProgressSW] Resume config details:', {
            rangeStart: resumeConfig.rangeStart,
            baseBytes: resumeConfig.baseBytes,
            skipBytes: resumeConfig.skipBytes,
            expectedSize: resumeConfig.expectedSize
        });
    }

    const request = buildResumeAwareRequest(event.request, resumeConfig);

    // Log the actual request being made
    log('[ProgressSW] Fetching URL:', request.url);
    log('[ProgressSW] Request has Range header:', request.headers.has('Range'));
    if (request.headers.has('Range')) {
        log('[ProgressSW] Range header value:', request.headers.get('Range'));
    }

    let upstream;
    try {
        upstream = await fetch(request);
        log('[ProgressSW] Fetch completed, status:', upstream.status, 'statusText:', upstream.statusText);
        // FIXED: Serialize headers to plain object to avoid DataCloneError
        const headersObj = {};
        upstream.headers.forEach((value, key) => { headersObj[key] = value; });
        log('[ProgressSW] Response headers count:', upstream.headers.size || Object.keys(headersObj).length);
        log('[ProgressSW] Content-Range:', upstream.headers.get('Content-Range'));
        log('[ProgressSW] Content-Length:', upstream.headers.get('Content-Length'));
        log('[ProgressSW] Step 1: After headers log');

        log('[ProgressSW] Step 2: Checking 416 status, status is:', upstream.status);
        if (resumeConfig && upstream.status === 416) {
            log('[ProgressSW] Resume request returned 416 - clearing resume config and retrying without Range');
            resumeConfigs.delete(downloadId);
            return fetch(event.request);
        }

        log('[ProgressSW] Step 3: Checking upstream.ok:', upstream.ok);
        if (!upstream.ok) {
            console.error('[ProgressSW] Upstream response not OK:', upstream.status);
            return upstream;
        }

        log('[ProgressSW] Step 4: Checking upstream.body:', !!upstream.body);
        if (!upstream.body) {
            log('[ProgressSW] No body stream, passing through');
            return upstream;
        }

        log('[ProgressSW] Step 5: About to parse Content-Range');
        const rangeFromServer = parseContentRange(upstream.headers.get('Content-Range'));
        log('[ProgressSW] Step 6: Parsed Content-Range:', rangeFromServer);

        const reportedSize = getFileSize(upstream, url);
        log('[ProgressSW] Reported size from headers:', reportedSize);

        const expectedSize = resumeConfig && resumeConfig.expectedSize ? resumeConfig.expectedSize : 0;
        const total = Math.max(reportedSize || 0, expectedSize || 0);

        const baseBytes = resumeConfig ? resumeConfig.baseBytes : 0;
        let skipRemaining = resumeConfig ? resumeConfig.skipBytes || 0 : 0;
        let delivered = baseBytes;
        let lastReport = baseBytes;
        let lastReportTime = 0;

        log('[ProgressSW] Download size (resolved):', total, 'bytes. BaseBytes:', baseBytes, 'Skip:', skipRemaining);
        log('[ProgressSW] About to broadcast download-started with delivered:', delivered);

        // CRITICAL FIX: Only send serializable data in broadcast
        try {
            broadcast({
                type: 'download-started',
                id: downloadId,
                total: total,
                sent: delivered
            });
            log('[ProgressSW] Broadcast sent successfully');
        } catch (broadcastError) {
            console.error('[ProgressSW] Broadcast failed:', broadcastError);
            log('[ProgressSW] Broadcast error:', String(broadcastError));
        }

        log('[ProgressSW] Checking if upstream.body exists:', !!upstream.body);
        log('[ProgressSW] upstream.body type:', typeof upstream.body);

        // Check if E2EE decryption is needed and context is available
        log('[ProgressSW] Looking for E2EE context - size:', e2eeContexts.size, 'keys:', Array.from(e2eeContexts.keys()));
        const specificContext = e2eeContexts.get(downloadId);
        const preRegisteredContext = e2eeContexts.get('__pre_registered__');
        const e2eeContext = e2eeEnabled ? (specificContext || preRegisteredContext) : null;
        if (e2eeEnabled && !e2eeContext) {
            log('[ProgressSW] WARNING: E2EE enabled but no context found for download:', downloadId);
        } else if (e2eeContext) {
            const contextSource = e2eeContexts.has(downloadId) ? 'specific ID' : 'pre-registered';
            log('[ProgressSW] ✓ E2EE decryption will be applied using', contextSource, 'context');
        }

        // Configurable progress reporting thresholds
        const REPORT_EVERY_BYTES = getConfigFromUrl(url, 'reportBytes', 5 * 1024 * 1024); // Default 5MB
        const REPORT_EVERY_MS = getConfigFromUrl(url, 'reportMs', 250); // Default 250ms

        log('[ProgressSW] Progress reporting config:', {
            reportEveryBytes: REPORT_EVERY_BYTES,
            reportEveryMs: REPORT_EVERY_MS
        });

        let resolveDone;
        const progressComplete = new Promise((resolve) => {
            resolveDone = resolve;
        });

        // E2EE decryptor (if enabled)
        let httpDecryptor = null;
        if (e2eeContext) {
            // Check if HTTPDecryptor is available from imported E2EE.js
            if (typeof HTTPDecryptor === 'undefined') {
                console.error('[ProgressSW] HTTPDecryptor not available - E2EE.js not loaded properly');
                broadcast({ type: 'download-error', id: downloadId, message: 'HTTPDecryptor not available' });
                return fetch(event.request);
            }

            // Use factory method to create HTTPDecryptor from context
            httpDecryptor = HTTPDecryptor.fromContext(e2eeContext, log);

            // Set resume position if needed
            if (resumeConfig && typeof resumeConfig.rangeStart === 'number') {
                httpDecryptor.setResumeState(resumeConfig.rangeStart);
                log('[ProgressSW] HTTPDecryptor resume position set to:', resumeConfig.rangeStart);
            }

            log('[ProgressSW] ✓ HTTPDecryptor created for download:', downloadId);
        } else {
            log('[ProgressSW] No E2EE decryption - context not available');
        }

        let chunkCount = 0;
        const progressTransform = new TransformStream({
            async transform(chunk, controller) {
                chunkCount++;
                const chunkSize = chunk.byteLength || chunk.length || 0;
                log('[ProgressSW] Transform chunk #' + chunkCount + ' received, size:', chunkSize, 'skipRemaining:', skipRemaining, 'delivered:', delivered);
                
                // This chunk is the actual data going to the browser
                let processedChunk = chunk;

                // Apply E2EE decryption if enabled
                if (httpDecryptor) {
                    try {
                        processedChunk = await httpDecryptor.decryptChunk(chunk);
                        log('[ProgressSW] Chunk decrypted, new size:', processedChunk.byteLength || processedChunk.length);
                    } catch (e) {
                        console.error('[ProgressSW] E2EE decryption failed:', e);
                        broadcast({ type: 'download-error', id: downloadId, message: 'E2EE decryption failed: ' + e.message });
                        controller.error(e);
                        return;
                    }
                }

                let chunkView;
                if (processedChunk instanceof Uint8Array) {
                    chunkView = processedChunk;
                } else if (processedChunk instanceof ArrayBuffer) {
                    chunkView = new Uint8Array(processedChunk);
                } else if (processedChunk?.buffer instanceof ArrayBuffer) {
                    chunkView = new Uint8Array(processedChunk.buffer);
                } else {
                    chunkView = new Uint8Array(processedChunk);
                }

                if (skipRemaining > 0) {
                    log('[ProgressSW] Skipping bytes:', skipRemaining, 'chunkView.length:', chunkView.length);
                    if (skipRemaining >= chunkView.length) {
                        skipRemaining -= chunkView.length;
                        log('[ProgressSW] Skipped entire chunk, skipRemaining now:', skipRemaining);
                        return;
                    }
                    chunkView = chunkView.slice(skipRemaining);
                    log('[ProgressSW] Skipped partial chunk, new chunkView.length:', chunkView.length);
                    skipRemaining = 0;
                }

                if (chunkView.length === 0) {
                    log('[ProgressSW] Chunk length is 0, skipping enqueue');
                    return;
                }
                
                // Pass the processed chunk through to the browser
                controller.enqueue(chunkView);
                log('[ProgressSW] Enqueued chunk, size:', chunkView.length);

                delivered += chunkView.length;

                const now = Date.now();
                const shouldReport = (
                    delivered - lastReport >= REPORT_EVERY_BYTES ||
                    now - lastReportTime >= REPORT_EVERY_MS
                );

                if (shouldReport) {
                    lastReport = delivered;
                    lastReportTime = now;
                    log('[ProgressSW] Progress report:', delivered, '/', total || '(unknown)', '(' + Math.round(delivered/total*100) + '%)');
                    try {
                        broadcast({ type: 'download-progress', id: downloadId, sent: delivered, total });
                    } catch (broadcastError) {
                        console.error('[ProgressSW] Progress broadcast failed:', broadcastError);
                    }
                }
            },

            async flush(controller) {
                // Flush any remaining decrypted data
                if (httpDecryptor) {
                    try {
                        const finalChunk = await httpDecryptor.flush();
                        if (finalChunk && finalChunk.byteLength > 0) {
                            let finalView = finalChunk instanceof Uint8Array ? finalChunk : new Uint8Array(finalChunk);

                            if (skipRemaining > 0) {
                                if (skipRemaining >= finalView.length) {
                                    skipRemaining = 0;
                                    finalView = new Uint8Array(0);
                                } else {
                                    finalView = finalView.slice(skipRemaining);
                                    skipRemaining = 0;
                                }
                            }

                            if (finalView.length > 0) {
                                controller.enqueue(finalView);
                                delivered += finalView.length;
                            }
                        }
                    } catch (e) {
                        console.error('[ProgressSW] E2EE flush failed:', e);
                    }
                }

                const resolvedTotal = total || expectedSize || delivered;
                log('[ProgressSW] Transform stream completed, total delivered:', delivered, 'expected:', resolvedTotal);
                try {
                    broadcast({ type: 'download-complete', id: downloadId, sent: delivered, total: resolvedTotal });
                } catch (broadcastError) {
                    console.error('[ProgressSW] Complete broadcast failed:', broadcastError);
                }
                resolveDone();

                // Clean up E2EE context
                if (e2eeEnabled) {
                    e2eeContexts.delete(downloadId);
                }
            }
        });

        // 🔑 Keep SW alive until the entire stream is processed
        event.waitUntil(progressComplete);

        // Prepare headers - try keeping Content-Length first
        const headers = new Headers(upstream.headers);
        if (!headers.has('Content-Disposition')) {
            headers.set('Content-Disposition', 'attachment');
        }
        
        // Only delete Content-Length for Firefox to prevent early cutoff
        if (isFirefox) {
            headers.delete('Content-Length');
        }
        
        if (resumeConfig) {
            headers.delete('Content-Length'); // Also Chromium
            headers.set('Accept-Ranges', 'bytes');        
        }

        log('[ProgressSW] About to pipe through transform stream');
        log('[ProgressSW] Returning transformed response for native download');

        const transformedBody = upstream.body.pipeThrough(progressTransform);
        log('[ProgressSW] Transform stream created, creating Response');

        const response = new Response(transformedBody, {
            status: upstream.status,
            statusText: upstream.statusText,
            headers,
        });

        log('[ProgressSW] Response created, returning to browser');
        return response;

    } catch (err) {
        console.error('[ProgressSW] Download handling failed:', err);
        broadcast({ type: 'download-error', id: downloadId, message: String(err) });
        return fetch(event.request);
    } finally {
        if (resumeConfig) {
            resumeConfigs.delete(downloadId);
        }
    }
}
