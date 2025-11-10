/*!
 * FastFileLink - End-to-End Encryption Support
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Client-side E2E encryption/decryption for WebRTC and HTTP downloads.
 * Works non-intrusively by wrapping WebRTC data channel message handlers.
 *
 * Architecture:
 * - E2EManager: Handles /e2ee/manifest detection and RSA key exchange via /e2ee/init
 * - WebRTCDecryptor: Unframes and decrypts WebRTC chunks transparently
 * - HTTPDecryptor: Decrypts HTTP chunks with Range resume support
 *
 * See LICENSE file in the project root for full license information.
 */

// ========== Utility Functions ==========

function base64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes));
}

function toBigEndian64(num) {
    return new Uint8Array(new BigUint64Array([BigInt(num)]).buffer).reverse();
}

function toBigEndian32(num) {
    return new Uint8Array(new Uint32Array([num]).buffer).reverse();
}

const textEncoder = new TextEncoder();
function encodeText(str) {
    return textEncoder.encode(str);
}

// ========== Crypto Helper Functions (Shared) ==========

/**
 * Build 12-byte nonce for AES-GCM
 * Format: nonce_base(8 bytes) || chunk_index(4 bytes BE)
 */
function buildNonce(nonceBase, chunkIndex) {
    const nonce = new Uint8Array(12);
    nonce.set(nonceBase.slice(0, 8), 0);
    const chunkIndexBytes = new Uint8Array(4);
    new DataView(chunkIndexBytes.buffer).setUint32(0, chunkIndex, false); // Big-endian
    nonce.set(chunkIndexBytes, 8);
    return nonce;
}

/**
 * Build AAD for AES-GCM - WebRTC format (string-based)
 * Format: filename(utf-8) | filesize(ascii) | chunkIndex(ascii)
 */
function buildAADStringFormat(filename, filesize, chunkIndex) {
    const filenamePart = encodeText(filename);
    const filesizePart = encodeText(String(filesize));
    const chunkIndexPart = encodeText(String(chunkIndex));

    const aad = new Uint8Array(filenamePart.length + 1 + filesizePart.length + 1 + chunkIndexPart.length);
    let offset = 0;
    aad.set(filenamePart, offset);
    offset += filenamePart.length;
    aad[offset++] = 0x7C; // '|' character
    aad.set(filesizePart, offset);
    offset += filesizePart.length;
    aad[offset++] = 0x7C; // '|' character
    aad.set(chunkIndexPart, offset);

    return aad;
}

/**
 * Build AAD for AES-GCM - HTTP struct format
 * Format: filename(utf-8) || filesize(8 bytes BE) || chunkIndex(4 bytes BE)
 */
function buildAADStructFormat(filename, filesize, chunkIndex) {
    const filenameBytes = encodeText(filename);
    const filesizeBytes = new Uint8Array(8);
    new DataView(filesizeBytes.buffer).setBigUint64(0, BigInt(filesize), false); // Big-endian
    const chunkIndexBytes = new Uint8Array(4);
    new DataView(chunkIndexBytes.buffer).setUint32(0, chunkIndex, false); // Big-endian

    const aad = new Uint8Array(filenameBytes.length + 8 + 4);
    aad.set(filenameBytes, 0);
    aad.set(filesizeBytes, filenameBytes.length);
    aad.set(chunkIndexBytes, filenameBytes.length + 8);

    return aad;
}

/**
 * Decrypt data using AES-GCM
 * @param {Uint8Array} contentKey - AES key bytes
 * @param {Uint8Array} nonce - 12-byte nonce
 * @param {Uint8Array} aad - Additional authenticated data
 * @param {Uint8Array} ciphertext - Ciphertext bytes
 * @param {Uint8Array} tag - 16-byte authentication tag
 * @returns {Promise<Uint8Array>} - Decrypted plaintext
 */
async function decryptAESGCM(contentKey, nonce, aad, ciphertext, tag) {
    // Concatenate ciphertext + tag for AES-GCM
    const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
    ciphertextWithTag.set(ciphertext, 0);
    ciphertextWithTag.set(tag, ciphertext.length);

    // Import content key
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        contentKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // Decrypt using AES-GCM
    const plaintext = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            tagLength: 128,
            additionalData: aad
        },
        cryptoKey,
        ciphertextWithTag
    );

    return new Uint8Array(plaintext);
}

// ========== Crypto Helper Functions ==========

async function deriveHKDF(keyMaterial, salt, info, length) {
    const ikm = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveBits"]);

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: typeof salt === 'string' ? encodeText(salt) : salt,
            info: typeof info === 'string' ? encodeText(info) : info
        },
        ikm,
        length * 8
    );

    return new Uint8Array(derivedBits);
}

/**
 * Verify key commitment to prevent key substitution attacks
 * @param {Uint8Array} contentKey - AES-256 content key
 * @param {string} commitmentB64 - Base64-encoded commitment from server
 * @param {number} chunkSize - Chunk size
 * @param {number} filesize - File size
 * @param {string} filename - Filename
 * @param {boolean} debug - Enable debug logging
 * @returns {Promise<boolean>} - True if commitment is valid
 */
async function verifyKeyCommitment(contentKey, commitmentB64, chunkSize, filesize, filename, debug = false) {
    if (!commitmentB64) {
        if (debug) console.log('[E2EE] No commitment to verify');
        return true;
    }

    try {
        // Build commitment message: "commit" + "AES-256-GCM" + chunkSize + filesize + filename
        const commitPrefix = encodeText('commit');
        const algoPrefix = encodeText('AES-256-GCM');
        const chunkSizeBytes = new Uint8Array(8);
        new DataView(chunkSizeBytes.buffer).setBigUint64(0, BigInt(chunkSize), false);
        const filesizeBytes = new Uint8Array(8);
        new DataView(filesizeBytes.buffer).setBigUint64(0, BigInt(filesize), false);
        const filenameBytes = encodeText(filename);

        const totalLength = commitPrefix.length + algoPrefix.length + 8 + 8 + filenameBytes.length;
        const message = new Uint8Array(totalLength);
        let offset = 0;
        message.set(commitPrefix, offset); offset += commitPrefix.length;
        message.set(algoPrefix, offset); offset += algoPrefix.length;
        message.set(chunkSizeBytes, offset); offset += 8;
        message.set(filesizeBytes, offset); offset += 8;
        message.set(filenameBytes, offset);

        // Derive commitment key using HKDF
        const commitKey = await deriveHKDF(contentKey, 'commit-hmac', 'key-commitment-v1', 32);

        // Compute HMAC-SHA256
        const hmacKey = await crypto.subtle.importKey('raw', commitKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const computedCommitment = await crypto.subtle.sign('HMAC', hmacKey, message);
        const computedB64 = bytesToBase64(new Uint8Array(computedCommitment));

        // Compare
        const match = computedB64 === commitmentB64;
        if (debug) {
            console.log('[E2EE] Commitment verification:', match ? 'PASS' : 'FAIL');
            if (!match) {
                console.log('[E2EE] Expected:', commitmentB64);
                console.log('[E2EE] Computed:', computedB64);
            }
        }
        return match;

    } catch (err) {
        console.error('[E2EE] Commitment verification error:', err);
        return false;
    }
}

async function generateRSAKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportPublicKeyPEM(publicKey) {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    const exportedAsBase64 = bytesToBase64(new Uint8Array(exported));
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
}

async function decryptRSA(privateKey, ciphertext) {
    return await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        ciphertext
    );
}

// ========== WebRTCDecryptor Class ==========

class WebRTCDecryptor {
    constructor(contentKey, nonceBase, filename, filesize, log) {
        this.contentKey = contentKey;
        this.nonceBase = nonceBase;
        this.filename = filename;
        this.filesize = filesize;
        this.log = log || console.log;

        // TLV frame constants (match E2EE.py E2EEFramerBase)
        this.MAGIC = new Uint8Array([0xFF, 0x4C]);
        this.VERSION = 1;
        this.TAG_LENGTH = 16;
        this.HEADER_SIZE = 2 + 1 + 8 + 4 + 16; // Magic(2) + Ver(1) + ChunkIdx(8) + CipherLen(4) + Tag(16) = 31
    }

    /**
     * Build 12-byte nonce for AES-GCM (matches CryptoHelper.buildNonce in E2EE.py)
     * Format: nonce_base(8 bytes) || chunk_index(4 bytes BE)
     */
    buildNonce(chunkIndex) {
        return buildNonce(this.nonceBase, chunkIndex);
    }

    /**
     * Build AAD for AES-GCM (matches CryptoHelper.buildAAD with useStructFormat=False)
     * Format: filename(utf-8) | filesize(ascii) | chunkIndex(ascii)
     */
    buildAAD(chunkIndex) {
        return buildAADStringFormat(this.filename, this.filesize, chunkIndex);
    }

    /**
     * Decrypt a single encrypted TLV frame
     * Frame format (matches E2EEFramer.packFrame in E2EE.py):
     * | Magic(2) | Ver(1) | ChunkIndex(8, uint64 BE) | CipherLen(4, uint32 BE) | Tag(16 bytes) | Ciphertext |
     */
    async decryptChunk(encryptedFrame) {
        try {
            if (encryptedFrame.length < this.HEADER_SIZE) {
                throw new Error(`Frame too short: ${encryptedFrame.length} < ${this.HEADER_SIZE}`);
            }

            // Parse TLV header
            const magic = encryptedFrame.slice(0, 2);
            const version = encryptedFrame[2];
            const chunkIndexBytes = encryptedFrame.slice(3, 11); // 8 bytes
            const cipherLenBytes = encryptedFrame.slice(11, 15); // 4 bytes
            const tag = encryptedFrame.slice(15, 31); // 16 bytes

            // Verify magic bytes
            if (magic[0] !== this.MAGIC[0] || magic[1] !== this.MAGIC[1]) {
                throw new Error(`Invalid magic bytes: [${magic[0]}, ${magic[1]}]`);
            }

            // Verify version
            if (version !== this.VERSION) {
                throw new Error(`Invalid version: ${version}`);
            }

            // Read chunk index (8 bytes, big-endian uint64)
            const chunkIndexView = new DataView(chunkIndexBytes.buffer, chunkIndexBytes.byteOffset, 8);
            const chunkIndex = Number(chunkIndexView.getBigUint64(0, false)); // Big-endian

            // Read cipher length (4 bytes, big-endian uint32)
            const cipherLenView = new DataView(cipherLenBytes.buffer, cipherLenBytes.byteOffset, 4);
            const cipherLen = cipherLenView.getUint32(0, false); // Big-endian

            // Verify frame is complete
            if (encryptedFrame.length < this.HEADER_SIZE + cipherLen) {
                throw new Error(`Frame incomplete: expected ${this.HEADER_SIZE + cipherLen}, got ${encryptedFrame.length}`);
            }

            // Extract ciphertext
            const ciphertext = encryptedFrame.slice(this.HEADER_SIZE, this.HEADER_SIZE + cipherLen);

            // Build nonce and AAD
            const nonce = this.buildNonce(chunkIndex);
            const aad = this.buildAAD(chunkIndex);

            // Decrypt using shared AES-GCM function
            return await decryptAESGCM(this.contentKey, nonce, aad, ciphertext, tag);

        } catch (e) {
            throw new Error(`Decryption failed: ${e.message}`);
        }
    }
}

// ========== E2EEManager Class ==========

class E2EEManager {
    constructor(log) {
        this.log = log || console.log;
        this.e2eeEnabled = false;
        this.manifest = null;
    }

    /**
     * Check if E2EE is enabled - first check for embedded data, then fall back to /e2ee/manifest
     */
    async checkE2EEStatus() {
        try {
            // First check for embedded E2EE data (avoids network request)
            if (typeof EMBEDDED_E2EE_DATA !== 'undefined' && EMBEDDED_E2EE_DATA) {
                this.log("E2EE", "Found embedded E2EE data - using local metadata");

                // Decompress embedded data using pako
                const compressedData = Uint8Array.from(atob(EMBEDDED_E2EE_DATA), c => c.charCodeAt(0));
                const decompressed = pako.inflate(compressedData, { to: 'string' });
                const e2eeData = JSON.parse(decompressed);

                this.manifest = e2eeData.manifest;
                this.e2eeEnabled = true;

                // Store tags data for later use (no need to fetch from server)
                this.embeddedTagsData = {
                    tags: e2eeData.tags,
                    nonceBase: e2eeData.nonceBase,
                    commitment: e2eeData.commitment
                };

                this.log("E2EE", `✓ E2EE enabled (embedded) - chunk size: ${this.manifest.chunkSize}`);
                return true;
            }

            // Fall back to fetching /e2ee/manifest if no embedded data
            this.log("E2EE", "No embedded data found - trying /e2ee/manifest endpoint");

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch('/e2ee/manifest', { signal: controller.signal });
            clearTimeout(timeoutId);

            if (response.status === 404) {
                this.log("E2EE", "E2E encryption not enabled (404)");
                this.e2eeEnabled = false;
                return false;
            }

            if (!response.ok) {
                this.log("E2EE", `E2EE manifest fetch failed: ${response.status}`);
                this.e2eeEnabled = false;
                return false;
            }

            this.manifest = await response.json();
            this.e2eeEnabled = this.manifest.e2eeEnabled === true;

            if (this.e2eeEnabled) {
                this.log("E2EE", `✓ E2EE enabled - chunk size: ${this.manifest.chunkSize}`);
            }

            return this.e2eeEnabled;

        } catch (error) {
            if (error.name === 'AbortError') {
                this.log("E2EE", "E2EE manifest timeout - continuing without E2EE");
            } else {
                this.log("E2EE", `E2EE check error: ${error.message}`);
            }
            this.e2eeEnabled = false;
            return false;
        }
    }

    /**
     * Perform RSA key exchange to get content key (Kc) and nonce base
     * This exchanges RSA public key (Ki) for wrapped content key
     * @returns {Promise<{contentKey: Uint8Array, nonceBase: Uint8Array, filename: string, filesize: number}>}
     */
    async performKeyExchange() {
        try {
            // Generate RSA key pair (Ki)
            const keyPair = await generateRSAKeyPair();
            const publicKeyPEM = await exportPublicKeyPEM(keyPair.publicKey);
            this.log('E2EE', '✓ RSA key pair (Ki) generated');

            // POST /e2e/init with public key to get wrapped content key
            const initResp = await fetch('/e2ee/init', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ publicKey: publicKeyPEM })
            });

            if (!initResp.ok) {
                throw new Error(`Key exchange failed: ${initResp.status}`);
            }

            const initData = await initResp.json();
            this.log('E2EE', '✓ Received wrapped content key (Kc wrapped with Ki)');

            // Unwrap content key (Kc) and nonce base using RSA private key (Ki)
            const wrappedKeyBytes = base64ToBytes(initData.wrappedContentKey);
            const wrappedNonceBytes = base64ToBytes(initData.nonceBase);

            const contentKeyBytes = await decryptRSA(keyPair.privateKey, wrappedKeyBytes);
            const nonceBaseBytes = await decryptRSA(keyPair.privateKey, wrappedNonceBytes);

            this.log('E2EE', '✓ Content key (Kc) unwrapped successfully');

            return {
                contentKey: new Uint8Array(contentKeyBytes),
                nonceBase: new Uint8Array(nonceBaseBytes),
                filename: initData.filename,
                filesize: initData.filesize
            };

        } catch (error) {
            this.log('E2EE', `Key exchange failed: ${error.message}`);
            throw error;
        }
    }

    /**
     * Setup WebRTC decryptor with TLV frame unwrapping
     * @returns {Promise<WebRTCDecryptor>} - WebRTC decryptor instance
     */
    async setupWebRTCDecryptor() {
        const keyData = await this.performKeyExchange();
        const decryptor = new WebRTCDecryptor(
            keyData.contentKey,
            keyData.nonceBase,
            keyData.filename,
            keyData.filesize,
            this.log
        );
        this.log('E2EE', '✓ WebRTC decryptor ready');
        return decryptor;
    }

    /**
     * Setup HTTP decryptor for Service Worker usage
     * @param {string|null} userKeyB64 - Optional base64-encoded AES-256 content key for embedded mode.
     *                                   If null, performs RSA key exchange with server.
     * @returns {Promise<HTTPDecryptor>} - HTTP decryptor instance
     */
    async setupHTTPDecryptor(userKeyB64 = null) {
        let contentKey, nonceBase, filename, filesize, embeddedTags = null;

        if (userKeyB64) {
            // Embedded mode: Use user-provided key with embedded tags
            if (!this.embeddedTagsData) {
                throw new Error('No embedded E2EE data available');
            }

            // Decode and validate content key
            contentKey = base64ToBytes(userKeyB64);
            if (contentKey.length !== 32) {
                throw new Error('Invalid key length (expected 32 bytes for AES-256)');
            }

            // Verify key commitment
            const isValid = await verifyKeyCommitment(
                contentKey,
                this.embeddedTagsData.commitment,
                this.manifest.chunkSize,
                this.manifest.filesize,
                this.manifest.filename
            );

            if (!isValid) {
                throw new Error('Encryption key verification failed - wrong key or tampered file');
            }

            this.log('E2EE', '✓ Key commitment verified');

            // Use embedded data
            nonceBase = base64ToBytes(this.embeddedTagsData.nonceBase);
            filename = this.manifest.filename;
            filesize = this.manifest.filesize;
            embeddedTags = this.embeddedTagsData.tags;

        } else {
            // Server mode: Perform RSA key exchange
            const keyData = await this.performKeyExchange();
            contentKey = keyData.contentKey;
            nonceBase = keyData.nonceBase;
            filename = keyData.filename;
            filesize = keyData.filesize;
        }

        // Create HTTPDecryptor
        const httpDecryptor = new HTTPDecryptor(
            contentKey,
            nonceBase,
            filename,
            filesize,
            this.manifest.chunkSize,
            embeddedTags,
            this.log
        );

        this.log('E2EE', embeddedTags ? '✓ HTTP decryptor ready with embedded tags' : '✓ HTTP decryptor ready');
        return httpDecryptor;
    }

    /**
     * Wrap WebRTC data channel to decrypt chunks transparently
     * @param {DataChannel} dataChannel - WebRTC data channel to wrap
     * @param {WebRTCDecryptor} decryptor - WebRTC decryptor instance
     * @param {Function} onDecryptedMessage - Callback for decrypted messages
     */
    wrapDataChannel(dataChannel, decryptor, onDecryptedMessage) {
        if (!this.e2eeEnabled || !decryptor) {
            // Pass through without modification
            return dataChannel;
        }

        const originalOnMessage = dataChannel.onmessage;

        dataChannel.onmessage = async (event) => {
            const data = event.data;

            // Pass through string messages (EOF, ERROR)
            if (typeof data === 'string') {
                if (originalOnMessage) {
                    originalOnMessage.call(dataChannel, event);
                }
                if (onDecryptedMessage) {
                    onDecryptedMessage(data);
                }
                return;
            }

            // Decrypt binary chunk
            try {
                const encryptedChunk = new Uint8Array(data);
                const decryptedChunk = await decryptor.decryptChunk(encryptedChunk);

                // Call handler with decrypted data
                if (onDecryptedMessage) {
                    onDecryptedMessage(decryptedChunk.buffer);
                }

            } catch (error) {
                this.log("E2EE", `Decryption error: ${error.message}`);
                throw error;
            }
        };

        return dataChannel;
    }
}

// ========== HTTP Decryption Integration ==========

/**
 * HTTPDecryptor - HTTP E2E decryption for Service Worker
 *
 * Similar to WebRTCDecryptor but for HTTP downloads via Service Worker.
 * Handles chunk buffering, tag fetching, and AES-GCM decryption.
 */
class HTTPDecryptor {
    constructor(contentKey, nonceBase, filename, filesize, chunkSize, embeddedTags = null, log = null) {
        this.contentKey = contentKey;
        this.nonceBase = nonceBase;
        this.filename = filename;
        this.filesize = filesize;
        this.chunkSize = chunkSize;
        this.log = log || console.log;

        // Service Worker decryption state
        this.chunkBuffer = new Uint8Array(0);
        this.currentChunkIndex = 0;
        this.tagMap = new Map();
        this.tagBatchSize = 100;
        this.embedded = false;

        // Build E2EE context for Service Worker (base64-encoded for serialization)
        this.e2eeContext = {
            contentKey: bytesToBase64(this.contentKey),
            nonceBase: bytesToBase64(this.nonceBase),
            filename: this.filename,
            filesize: this.filesize,
            chunkSize: this.chunkSize,
            tags: [] // Will be populated if using embedded mode
        };

        // Pre-load embedded tags if provided (avoids fetching from server)
        if (embeddedTags && Array.isArray(embeddedTags) && embeddedTags.length > 0) {
            this.log('E2EE', `Pre-loading ${embeddedTags.length} embedded tags`);

            // Populate tagMap for main thread decryption
            for (const tagEntry of embeddedTags) {
                this.tagMap.set(tagEntry.chunkIndex, base64ToBytes(tagEntry.tag));
            }

            // Populate e2eeContext.tags for Service Worker
            this.e2eeContext.tags = embeddedTags.map(entry => ({
                chunkIndex: entry.chunkIndex,
                tag: entry.tag // Already base64-encoded
            }));
            
            this.embedded = true;

            this.log('E2EE', `✓ HTTPDecryptor initialized with ${embeddedTags.length} embedded tags`);
        }
    }

    /**
     * Factory method to create HTTPDecryptor from E2EE context/manifest
     *
     * This method encapsulates the common logic for creating HTTPDecryptor instances
     * from base64-encoded E2EE context, used in both ProgressServiceWorker and DownloadManager.
     *
     * @param {Object} e2eeContext - E2EE context/manifest with base64-encoded keys
     * @param {string} e2eeContext.contentKey - Base64-encoded AES-256-GCM content key
     * @param {string} e2eeContext.nonceBase - Base64-encoded nonce base
     * @param {string} e2eeContext.filename - Original filename
     * @param {number} e2eeContext.filesize - Original file size
     * @param {number} e2eeContext.chunkSize - Encryption chunk size (e.g., 262144)
     * @param {Array} [e2eeContext.tags] - Optional array of embedded tags [{chunkIndex, tag}]
     * @param {Function} [log] - Optional logging function
     * @returns {HTTPDecryptor} - Configured HTTPDecryptor instance
     */
    static fromContext(e2eeContext, log = null) {
        // Helper to decode base64 to Uint8Array
        const base64ToBytes = (base64) => {
            const binString = atob(base64);
            return Uint8Array.from(binString, (m) => m.codePointAt(0));
        };

        // Decode base64 keys
        const contentKey = base64ToBytes(e2eeContext.contentKey);
        const nonceBase = base64ToBytes(e2eeContext.nonceBase);

        // Extract embedded tags if available
        const embeddedTags = (e2eeContext.tags && Array.isArray(e2eeContext.tags) && e2eeContext.tags.length > 0)
            ? e2eeContext.tags
            : null;

        if (log) {
            log('HTTPDecryptor', 'Creating from context:', {
                filename: e2eeContext.filename,
                filesize: e2eeContext.filesize,
                chunkSize: e2eeContext.chunkSize,
                hasTags: !!embeddedTags,
                tagCount: embeddedTags ? embeddedTags.length : 0
            });
        }

        // Create and return HTTPDecryptor instance
        return new HTTPDecryptor(
            contentKey,
            nonceBase,
            e2eeContext.filename,
            e2eeContext.filesize,
            e2eeContext.chunkSize,
            embeddedTags,
            log
        );
    }

    /**
     * Concatenate multiple Uint8Array chunks into single array
     * @param {Array<Uint8Array>} chunks - Array of chunks to concatenate
     * @returns {Uint8Array} - Concatenated result
     */
    _concatenateChunks(chunks) {
        if (chunks.length === 0) return new Uint8Array(0);
        const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return result;
    }

    setResumeState(rangeStart) {
        if (typeof rangeStart !== 'number' || rangeStart < 0 || !this.chunkSize) {
            return;
        }

        const newChunkIndex = Math.floor(rangeStart / this.chunkSize);
        if (Number.isFinite(newChunkIndex) && newChunkIndex >= 0) {
            this.currentChunkIndex = newChunkIndex;
            this.chunkBuffer = new Uint8Array(0);
        }
    }

    /**
     * Decrypt chunk - processes incoming encrypted data
     * Buffers partial chunks and decrypts complete chunks
     * @param {ArrayBuffer|Uint8Array} chunk - Encrypted chunk data
     * @returns {Promise<Uint8Array>} - Decrypted plaintext (may be empty if buffering)
     */
    async decryptChunk(chunk) {
        // Append chunk to buffer
        const newBuffer = new Uint8Array(this.chunkBuffer.length + chunk.byteLength);
        newBuffer.set(this.chunkBuffer, 0);
        newBuffer.set(new Uint8Array(chunk), this.chunkBuffer.length);
        this.chunkBuffer = newBuffer;

        const plaintextChunks = [];

        // Process complete encrypted chunks
        while (this.chunkBuffer.length >= this.chunkSize) {
            const encryptedChunk = this.chunkBuffer.slice(0, this.chunkSize);
            this.chunkBuffer = this.chunkBuffer.slice(this.chunkSize);
            
            if (!this.embedded)
                await this.fetchTagIfNeeded(this.currentChunkIndex);
            
            const tag = this.tagMap.get(this.currentChunkIndex);
            if (!tag) {
                throw new Error(`Missing tag for chunk ${this.currentChunkIndex}`);
            }

            const plaintext = await this.decryptSingleChunk(this.currentChunkIndex, encryptedChunk, tag);
            plaintextChunks.push(plaintext);
            this.currentChunkIndex++;
        }

        return this._concatenateChunks(plaintextChunks);
    }

    /**
     * Flush remaining buffered data (call at end of stream)
     * @returns {Promise<Uint8Array>} - Decrypted final chunk
     */
    async flush() {
        if (this.chunkBuffer.length > 0) {
            // Process final partial chunk
            await this.fetchTagIfNeeded(this.currentChunkIndex);

            const tag = this.tagMap.get(this.currentChunkIndex);
            if (!tag) {
                throw new Error(`Missing tag for final chunk ${this.currentChunkIndex}`);
            }

            const plaintext = await this.decryptSingleChunk(
                this.currentChunkIndex,
                this.chunkBuffer,
                tag
            );

            this.chunkBuffer = new Uint8Array(0);
            return plaintext;
        }

        return new Uint8Array(0);
    }

    /**
     * Fetch authentication tags from server if not cached
     * @param {number} chunkIndex - Chunk index to fetch tag for
     */
    async fetchTagIfNeeded(chunkIndex) {
        if (!this.tagMap.has(chunkIndex)) {
            // Fetch batch of tags directly from server
            const tagsURL = `/e2ee/tags?start=${chunkIndex}&count=${this.tagBatchSize}`;

            try {
                this.log('E2EE', `Fetching tags from ${tagsURL}`);
                const response = await fetch(tagsURL);

                if (!response.ok) {
                    throw new Error(`Failed to fetch tags: HTTP ${response.status}`);
                }

                const data = await response.json();
                const tags = data.tags || [];
                this.log('E2EE', `Fetched ${tags.length} tags starting at chunk ${chunkIndex}`);

                // Cache all fetched tags
                for (const tagEntry of tags) {
                    this.tagMap.set(tagEntry.chunkIndex, base64ToBytes(tagEntry.tag));
                }
            } catch (error) {
                this.log('E2EE', `Failed to fetch tags: ${error.message}`);
                throw error;
            }
        }
    }

    /**
     * Decrypt single chunk with AES-GCM
     * Uses HTTP struct format for AAD
     * @param {number} chunkIndex - Chunk index
     * @param {Uint8Array} ciphertext - Encrypted data
     * @param {Uint8Array} tag - Authentication tag
     * @returns {Promise<Uint8Array>} - Decrypted plaintext
     */
    async decryptSingleChunk(chunkIndex, ciphertext, tag) {
        const nonce = buildNonce(this.nonceBase, chunkIndex);
        const aad = buildAADStructFormat(this.filename, this.filesize, chunkIndex);
        return await decryptAESGCM(this.contentKey, nonce, aad, ciphertext, tag);
    }

    /**
     * Send E2E context to Service Worker before download starts
     * @param {string} downloadId - Download ID from DownloadManager
     * @param {ServiceWorker} serviceWorker - Active service worker
     */
    sendContextToServiceWorker(downloadId, serviceWorker) {
        if (!serviceWorker) {
            this.log('E2EE', 'No active Service Worker found');
            return;
        }

        try {
            // Send E2E context to Service Worker
            serviceWorker.postMessage({
                type: 'e2ee-context',
                downloadId: downloadId,
                context: this.e2eeContext
            });

            this.log('E2EE', `✓ E2EE context sent to Service Worker for download: ${downloadId}`);
        } catch (error) {
            this.log('E2EE', `Failed to send E2EE context to Service Worker: ${error.message}`);
            throw error;
        }
    }
}

// Export to global scope (works in both window and Service Worker contexts)
const globalScope = typeof window !== 'undefined' ? window : self;
globalScope.E2EEManager = E2EEManager;
globalScope.WebRTCDecryptor = WebRTCDecryptor;
globalScope.HTTPDecryptor = HTTPDecryptor;
