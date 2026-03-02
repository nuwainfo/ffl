/*!
 * FastFileLink - Checksum Utility
 * https://github.com/nuwainfo/ffl
 *
 * Uses third-party BLAKE2b implementation from hash-wasm:
 * https://www.npmjs.com/package/hash-wasm
 */

(function initializeChecksumModule(globalScope) {
    'use strict';

    if (globalScope.FFLChecksum) {
        return;
    }

    function noop() {}

    function normalizeInput(input) {
        if (input instanceof Uint8Array) {
            return input;
        }

        if (input instanceof ArrayBuffer) {
            return new Uint8Array(input);
        }

        if (ArrayBuffer.isView(input)) {
            return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        }

        if (typeof input === 'string') {
            return new TextEncoder().encode(input);
        }

        throw new Error('Input must be a string, ArrayBuffer, or Uint8Array');
    }

    function buildChecksumUrl(uid) {
        return '/' + uid + '/checksum';
    }

    function getBlake2bProvider() {
        if (!globalScope.hashwasm || typeof globalScope.hashwasm.createBLAKE2b !== 'function') {
            return null;
        }
        return globalScope.hashwasm;
    }

    async function createBlake2bHasher() {
        var provider = getBlake2bProvider();
        if (!provider) {
            throw new Error('hash-wasm BLAKE2b provider is unavailable');
        }
        return provider.createBLAKE2b(512);
    }

    async function verifyDigest(options) {
        var uid = options.uid;
        var localChecksum = (options.localChecksum || '').toLowerCase();
        var transport = options.transport || '';
        var logger = options.log || noop;

        if (!uid) {
            return {
                verified: false,
                reason: 'missing-uid',
                localChecksum: localChecksum
            };
        }

        var response = await fetch(buildChecksumUrl(uid), { cache: 'no-cache' });
        if (!response.ok) {
            return {
                verified: false,
                reason: 'endpoint-error',
                status: response.status,
                localChecksum: localChecksum
            };
        }

        var remoteData = await response.json();
        if (!remoteData || remoteData.ready !== true) {
            return {
                verified: false,
                pending: true,
                reason: 'not-ready',
                localChecksum: localChecksum,
                remote: remoteData || null
            };
        }

        var remoteTransport = remoteData.transport || '';
        if (transport && remoteTransport && transport !== remoteTransport) {
            logger('Checksum', 'Transport mismatch, skip strict verify', {
                expectedTransport: transport,
                remoteTransport: remoteTransport
            });
            return {
                verified: false,
                transportMismatch: true,
                reason: 'transport-mismatch',
                localChecksum: localChecksum,
                remoteChecksum: (remoteData.checksum || '').toLowerCase(),
                remote: remoteData
            };
        }

        var remoteChecksum = (remoteData.checksum || remoteData.digest || '').toLowerCase();
        var isMatch = !!remoteChecksum && remoteChecksum === localChecksum;

        return {
            verified: isMatch,
            reason: isMatch ? 'ok' : 'mismatch',
            algorithm: remoteData.algorithm || 'blake2b',
            localChecksum: localChecksum,
            remoteChecksum: remoteChecksum,
            remote: remoteData
        };
    }

    function showVerifiedBadge(options) {
        var opts = options || {};
        var text = opts.text || 'verified';
        var className = opts.className || 'ffl-checksum-verified';
        var targetElement = opts.targetElement || null;
        var targetSelector = opts.targetSelector || null;
        var badgeText = ' (' + text + ')';

        var jq = globalScope.jQuery || globalScope.$ || null;
        if (jq) {
            var $target = targetElement ? jq(targetElement) : jq(targetSelector);
            if (!$target.length) {
                return false;
            }

            var $existing = $target.find('.' + className);
            if ($existing.length) {
                $existing.stop(true, true).show();
                return true;
            }

            var $badge = jq('<span></span>')
                .addClass(className)
                .text(badgeText)
                .hide();
            $target.append($badge);
            $badge.fadeIn(250);
            return true;
        }

        var target = targetElement || (targetSelector ? globalScope.document.querySelector(targetSelector) : null);
        if (!target) {
            return false;
        }

        if (target.querySelector('.' + className)) {
            return true;
        }

        var span = globalScope.document.createElement('span');
        span.className = className;
        span.textContent = badgeText;
        target.appendChild(span);
        return true;
    }

    class TransferChecksumVerifier {
        constructor(options) {
            var opts = options || {};
            this.uid = opts.uid || '';
            this.transport = opts.transport || '';
            this.log = opts.log || noop;

            this.hasData = false;
            this.finalized = false;
            this.cachedHex = '';
            this.lastResult = null;
            this.hasher = null;
            this.pendingChunks = [];
            this.initError = null;

            this.hasherReadyPromise = createBlake2bHasher()
                .then((hasher) => {
                    this.hasher = hasher;
                    this._flushPendingChunks();
                    return hasher;
                })
                .catch((error) => {
                    this.initError = error;
                    this.log('Checksum', 'Failed to initialize BLAKE2b hasher', {
                        error: String(error)
                    });
                    return null;
                });
        }

        _flushPendingChunks() {
            if (!this.hasher || !this.pendingChunks.length) {
                return;
            }

            for (var chunkIndex = 0; chunkIndex < this.pendingChunks.length; chunkIndex++) {
                this.hasher.update(this.pendingChunks[chunkIndex]);
            }
            this.pendingChunks = [];
        }

        update(chunk) {
            if (this.finalized) {
                return;
            }

            var normalizedChunk = normalizeInput(chunk);
            if (normalizedChunk.length === 0) {
                return;
            }

            this.hasData = true;

            if (this.hasher) {
                this.hasher.update(normalizedChunk);
                return;
            }

            var chunkCopy = new Uint8Array(normalizedChunk.length);
            chunkCopy.set(normalizedChunk);
            this.pendingChunks.push(chunkCopy);
        }

        async finalHex() {
            if (this.finalized) {
                return this.cachedHex || '';
            }

            this.finalized = true;
            if (!this.hasData) {
                this.cachedHex = '';
                return this.cachedHex;
            }

            await this.hasherReadyPromise;
            if (!this.hasher) {
                this.cachedHex = '';
                return this.cachedHex;
            }

            this._flushPendingChunks();
            this.cachedHex = (this.hasher.digest('hex') || '').toLowerCase();
            return this.cachedHex;
        }

        async finalizeAndVerify() {
            if (this.lastResult) {
                return this.lastResult;
            }

            var localChecksum = await this.finalHex();
            if (!localChecksum) {
                this.lastResult = {
                    verified: false,
                    pending: true,
                    reason: this.initError ? 'verifier-unavailable' : 'no-data',
                    localChecksum: '',
                    error: this.initError ? String(this.initError) : null
                };
                return this.lastResult;
            }

            this.lastResult = await verifyDigest({
                uid: this.uid,
                transport: this.transport,
                localChecksum: localChecksum,
                log: this.log
            });
            return this.lastResult;
        }
    }

    globalScope.FFLChecksum = {
        algorithm: 'blake2b',
        createVerifier: function createVerifier(options) {
            return new TransferChecksumVerifier(options);
        },
        verifyDigest: verifyDigest,
        showVerifiedBadge: showVerifiedBadge
    };
})((typeof globalThis !== 'undefined') ? globalThis : ((typeof self !== 'undefined') ? self : window));
