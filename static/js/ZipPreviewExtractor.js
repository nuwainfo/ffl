/*!
 * FastFileLink - ZipPreviewExtractor
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * - Feed raw ZIP bytes (Uint8Array chunks) from the download stream
 * - Uses /[uid]/manifest for metadata (sizes by filename)
 * - Fetches individual files via /[uid]/file endpoint when user clicks thumbnails
 * - Stores extracted/fetched files into IndexedDB for instant access
 * - Files marked as READY when fetched via /[uid]/file OR extracted from download stream
 *
 * See LICENSE file in the project root for full license information.
 */

class ZipPreviewExtractor {
    constructor(opts = {}) {
        this.dbName = opts.dbName || 'zip_gallery';
        this.storeName = opts.storeName || 'files';
        this.onFileReady = opts.onFileReady || null; // ({name, index, blob}) => void
        this.onStatus = opts.onStatus || null; // (msg) => void
        this.downloadId = opts.downloadId || null;
        // Control whether to fetch individual files via /[uid]/file when requested
        this.enableFileFetch = (opts.enableFileFetch ?? true) ? true : false;
        // URL template for fetching individual files (e.g., '/uid=****/file?path={path}')
        this.fileURLTemplate = opts.fileURLTemplate || '/uid=****/file?path={path}';
        this._fetchInflight = new Map();

        // Log function from PreviewUI (already handles debug flag)
        this.log = opts.log || ((tag, msg) => console.log(`[${tag}] ${msg}`));
        this.verifyAfterPut = opts.verifyAfterPut ?? false;

        // E2EE support - reuse existing manager if provided to avoid duplicate checks
        this.e2eeManager = opts.e2eeManager || null;
        this.e2eeContext = null;

        // Only initialize E2EE if manager is provided
        // If no manager provided, it means WebRTCManager already checked and E2EE is disabled
        if (this.e2eeManager) {
            this.log('ZipPreviewExtractor', 'Reusing existing E2EE manager (skip duplicate check)');
            this._e2eeInitPromise = this._reuseE2EEManager(); // Reuse existing manager
        } else {
            this.log('ZipPreviewExtractor', 'No E2EE manager provided - E2EE already checked and disabled');
            this._e2eeInitPromise = Promise.resolve(); // No-op, E2EE disabled
        }

        // If raw metadata provided, parse it (with E2EE decryption if needed)
        if (opts.rawMetadata) {
            this._metadataInitPromise = this._initMetadata(opts.rawMetadata, opts.rawMetadataOriginalSize || null);
        }

        this._stats = {
            fedChunks: 0,
            fedBytes: 0,
            parsedHeaders: 0,
            extractedFiles: 0,
            skippedUnknown: 0,
            resyncSkips: 0,
            dbOpen: 0,
            dbPut: 0,
            dbGet: 0,
            lastSig: null,
            lastEntry: null,
        };

        // filename -> { index, size, mime }
        this.metaByName = new Map();
        this._metaLoaded = false;

        this.q = new ByteQueue();
        this._parsing = false;
        this._stopped = false;
        this._current = null; // {name, size, index, mime}

        this._db = null;

        this.log('ZipPreviewExtractor', `Initialized (db: ${this.dbName}/${this.storeName})`);
    }

    // --- E2EE Support --------------------------------------------------------

    /**
     * Reuse existing E2EE manager (skip duplicate status check)
     */
    async _reuseE2EEManager() {
        this.log('ZipPreviewExtractor', 'Reusing existing E2EE manager...');

        try {
            // Check if manager is enabled (already checked by WebRTCManager - no network request!)
            // If first check was 404, e2eeEnabled will be false and we skip immediately
            if (!this.e2eeManager.e2eeEnabled || !this.e2eeManager.manifest) {
                this.log('ZipPreviewExtractor', 'E2EE not enabled on existing manager (skip duplicate check)');
                this.e2eeManager = null;
                return;
            }

            this.log('ZipPreviewExtractor', 'E2EE enabled on existing manager, performing key exchange...');

            // Perform key exchange to get content key
            const keyData = await this.e2eeManager.performKeyExchange();
            this.e2eeContext = {
                contentKey: keyData.contentKey,
                nonceBase: keyData.nonceBase,
                chunkSize: this.e2eeManager.manifest.chunkSize
            };

            this.log('ZipPreviewExtractor', '✓ E2EE initialized from existing manager - files will be decrypted');

        } catch (error) {
            this.log('ZipPreviewExtractor', `E2EE reuse failed: ${error.message}`);
            this.log('ZipPreviewExtractor', `Error stack: ${error.stack}`);
            this.e2eeManager = null;
        }
    }


    /**
     * Wait for E2EE initialization to complete (DRY helper)
     */
    async _waitForE2EEInit() {
        if (this._e2eeInitPromise) {
            await this._e2eeInitPromise;
        }
    }

    /**
     * Fetch and decrypt data from server (DRY helper for manifest/thumbnails/files)
     * @param {string|null} url - URL to fetch (null if rawData provided)
     * @param {string} streamId - Stream ID for tag fetching (e.g., "manifest", "thumb/image.png", "folder/file.txt")
     * @param {number|null} originalSize - Original data size (optional - will read from X-Original-Size header if not provided)
     * @param {ArrayBuffer|null} rawData - Raw data (if already fetched, null to fetch from URL)
     * @returns {Promise<ArrayBuffer>} - Decrypted data (or plaintext if E2EE not enabled)
     */
    async _fetchAndDecrypt(url, streamId, originalSize = null, rawData = null) {
        let data;
        let response = null;

        // Fetch data from server if not provided
        if (rawData === null) {
            response = await fetch(url, { cache: 'no-cache' });
            if (!response.ok) {
                throw new Error(`Fetch failed: ${response.status}`);
            }
            data = await response.arrayBuffer();
        } else {
            // Use provided raw data
            data = rawData;
        }

        // Decrypt if E2EE is enabled
        if (this.e2eeContext) {
            // Get original size from header if not provided
            if (originalSize === null && response) {
                const sizeHeader = response.headers.get('X-Original-Size');
                if (sizeHeader) {
                    originalSize = parseInt(sizeHeader, 10);
                } else {
                    throw new Error(`Missing X-Original-Size header for encrypted resource: ${streamId}`);
                }
            }

            this.log('ZipPreviewExtractor', `Decrypting ${streamId} (${data.byteLength} bytes encrypted -> ${originalSize || 'unknown'} bytes expected)`);

            // Create HTTPDecryptor for this resource
            const decryptor = new HTTPDecryptor(
                this.e2eeContext.contentKey,
                this.e2eeContext.nonceBase,
                streamId,                    // filename (for AAD) = streamId
                originalSize,                // original size (for AAD)
                this.e2eeContext.chunkSize,
                null,                        // no embedded tags
                this.log,
                streamId                     // streamId for per-resource tag storage
            );

            // Decrypt chunks
            const decryptedChunk = await decryptor.decryptChunk(data);
            const finalChunk = await decryptor.flush();

            // Concatenate decrypted chunks
            const totalLength = decryptedChunk.byteLength + finalChunk.byteLength;
            const plaintext = new Uint8Array(totalLength);
            plaintext.set(decryptedChunk, 0);
            plaintext.set(finalChunk, decryptedChunk.byteLength);

            this.log('ZipPreviewExtractor', `✓ Decrypted ${streamId} (${plaintext.byteLength} bytes plaintext)`);
            data = plaintext.buffer;
        }

        return data;
    }

    /**
     * Initialize metadata from raw data (decrypt if E2EE enabled)
     * @param {ArrayBuffer} rawData - Raw metadata from server
     * @param {number|null} originalSize - Original size before encryption (from X-Original-Size header)
     */
    async _initMetadata(rawData, originalSize = null) {
        try {
            // Wait for E2EE initialization
            await this._waitForE2EEInit();

            let data = rawData;

            // Decrypt if E2EE is enabled
            if (this.e2eeContext) {
                this.log('ZipPreviewExtractor', 'Decrypting metadata...');
                data = await this._fetchAndDecrypt(null, 'manifest', originalSize, data);
            }

            // Parse JSON
            const decoder = new TextDecoder('utf-8');
            const jsonText = decoder.decode(data);
            const metaJson = JSON.parse(jsonText);

            // Set metadata
            this.setMetadata(metaJson);

            this.log('ZipPreviewExtractor', `Metadata initialized: ${(metaJson.entries || []).length} entries`);

        } catch (error) {
            this.log('ZipPreviewExtractor', `Metadata initialization failed: ${error.message}`);
            throw error;
        }
    }

    // --- Public API ----------------------------------------------------------

    setMetadata(metaJson) {
        // metaJson: { zipName, entries: [{index,name,size,mime}, ...] }
        this.meta = metaJson || {
            entries: []
        };
        this.metaByName.clear();

        const entries = (this.meta.entries || []);
        let missingSize = 0;
        const dup = new Map();

        for (const e of entries) {
            if (!e || !e.name)
                continue;

            const sizeOk = Number.isFinite(e.size);

            if (!sizeOk)
                missingSize += 1;

            if (this.metaByName.has(e.name))
                dup.set(e.name, (dup.get(e.name) || 1) + 1);

            this.metaByName.set(e.name, {
                index: e.index,
                size: e.size,
                mime: e.mime || '',
                dataOffset: e.dataOffset
            });
        }

        this._metaLoaded = true;
        this.log('ZipPreviewExtractor',
            `Metadata loaded: ${entries.length} entries, ${this.metaByName.size} mapped`);

        // If chunks were already fed before metadata, kick the drain loop.
        if (this.q && this.q.available > 0 && !this._parsing) {
            this._parsing = true;
            queueMicrotask(() => this._drain().finally(() => {
                this._parsing = false;
            }));
        }
    }

    async _fetchFileViaZipEndpoint(entry) {
        // Fetch individual file from ZIP via /[uid]/file endpoint
        if (!this.enableFileFetch)
            return null;

        if (!entry || !entry.name)
            return null;

        const size = Number(entry.size);
        if (!Number.isFinite(size) || size <= 0) {
            this.log('ZipPreviewExtractor', `File fetch skipped (missing size): ${entry.name}`);
            return null;
        }

        // Wait for E2EE initialization to complete (if ongoing)
        await this._waitForE2EEInit();

        // Use fileURLTemplate to construct URL (replaces {path} placeholder)
        const url = this.fileURLTemplate.replace('{path}', encodeURIComponent(entry.name));
        this.log('ZipPreviewExtractor', `Fetching file: ${entry.name} (${size} bytes)`);

        // Fetch and decrypt using DRY helper (streamId = arcname)
        const buf = await this._fetchAndDecrypt(url, entry.name, size);

        if (!buf || buf.byteLength <= 0)
            return null;

        const mime = entry.mime || (this.metaByName.get(entry.name)?.mime) || 'application/octet-stream';
        return new Blob([buf], {
            type: mime
        });
    }

    /**
     * Fetch and decrypt thumbnail for a file
     * @param {string} arcname - File path in ZIP
     * @param {string} thumbnailURL - Thumbnail URL (e.g., '/uid/thumb?path=...&w=420&h=320')
     * @returns {Promise<string>} - Blob URL for decrypted thumbnail
     */
    async getThumbnailBlob(arcname, thumbnailURL) {
        try {
            // Wait for E2EE initialization to complete (if ongoing)
            await this._waitForE2EEInit();

            // Fetch and decrypt thumbnail using DRY helper
            // StreamId = "thumb/{arcname}" for per-thumbnail tag storage
            const streamId = `thumb/${arcname}`;
            const data = await this._fetchAndDecrypt(thumbnailURL, streamId);

            // Create blob from decrypted data
            // Content type is image/jpeg or image/png (depends on server, default to jpeg)
            const blob = new Blob([data], { type: 'image/jpeg' });

            // Create blob URL
            const blobURL = URL.createObjectURL(blob);
            this.log('ZipPreviewExtractor', `✓ Thumbnail ready: ${arcname} (${blobURL})`);

            return blobURL;

        } catch (error) {
            this.log('ZipPreviewExtractor', `Thumbnail fetch error for ${arcname}: ${error.message}`);
            throw error;
        }
    }

    async getFileBlob(index, shouldFetch = false) {
        // Lookup name by index from metadata, then load blob from IndexedDB.
        // Only fetches via /[uid]/file if shouldFetch=true (explicit user action, like clicking thumbnail)
        if (!this.meta || !Array.isArray(this.meta.entries)) {
            return null;
        }
        const e = this.meta.entries.find(x => x && x.index === index);
        if (!e || !e.name) {
            return null;
        }

        // 1) Check IndexedDB first (files from download stream or previous fetches)
        const rec = await this.getFile(e.name);
        const blob = (rec && rec.blob) ? rec.blob : null;
        if (blob && blob.size > 0)
            return blob;

        // 2) Only fetch if explicitly requested (shouldFetch=true)
        if (!shouldFetch) {
            return null;
        }

        // 3) Fetch via /[uid]/file endpoint (only when user clicks thumbnail)
        if (!this.enableFileFetch)
            return null;

        const inflightKey = e.name;
        if (this._fetchInflight.has(inflightKey)) {
            return await this._fetchInflight.get(inflightKey);
        }

        const p = (async () => {
            const b = await this._fetchFileViaZipEndpoint(e);
            if (!b || b.size <= 0)
                return null;

            // Persist to IndexedDB so subsequent access is instant
            await this.putFile(e.name, b, e.index, e.mime || '');
            this.log('ZipPreviewExtractor', `File stored to DB: ${e.name}`);

            // Notify UI to mark file as READY (same callback as stream-extracted files)
            try {
                if (typeof this.onFileReady === 'function')
                    this.onFileReady({
                        name: e.name,
                        index: e.index,
                        blob: b
                    });
            } catch (err) {
                this.log('ZipPreviewExtractor', `onFileReady error: ${err}`);
            }
            return b;
        })().finally(() => {
            this._fetchInflight.delete(inflightKey);
        });

        this._fetchInflight.set(inflightKey, p);
        return await p;
    }

    async clear() {
        await this._transaction('readwrite', (store) => {
            store.clear();
        });
        this.log('ZipPreviewExtractor', 'DB cleared');
    }

    stop() {
        this._stopped = true;
    }

    // --- IndexedDB -----------------------------------------------------------

    /**
     * Helper to run IndexedDB transaction with consistent error handling
     * @param {string} mode - 'readonly' or 'readwrite'
     * @param {Function} callback - (store) => void, performs operations on the store
     * @returns {Promise<any>} Resolves with callback result or rejects on error
     */
    async _transaction(mode, callback) {
        const db = await this.openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(this.storeName, mode);
            const store = tx.objectStore(this.storeName);

            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error || new Error('tx abort'));

            try {
                const result = callback(store, resolve, reject);
                if (result !== undefined)
                    resolve(result);
            } catch (e) {
                reject(e);
            }
        });
    }

    async openDb() {
        if (this._db)
            return this._db;

        this._stats.dbOpen += 1;
        this._db = await new Promise((resolve, reject) => {
            const req = indexedDB.open(this.dbName, 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName, {
                        keyPath: 'name'
                    });
                    this.log('ZipPreviewExtractor', `DB created object store: ${this.storeName}`);
                }
            };
            req.onsuccess = () => {
                const db = req.result;
                db.onversionchange = () => {
                    try {
                        db.close();
                    } catch {}
                    this._db = null;
                };
                this.log('ZipPreviewExtractor', `DB opened: ${db.name}`);
                resolve(db);
            };
            req.onerror = () => {
                this.log('ZipPreviewExtractor', `DB open error: ${req.error}`);
                reject(req.error);
            };
            req.onblocked = () => this.log('ZipPreviewExtractor', 'DB open blocked');
        });

        return this._db;
    }

    async putFile(name, blob, index = -1, mime = '') {
        this._stats.dbPut += 1;

        await this._transaction('readwrite', (store, resolve, reject) => {
            try {
                const req = store.put({
                    name,
                    blob,
                    index,
                    mime,
                    ts: Date.now()
                });
                req.onsuccess = () => {
                    this.log('ZipPreviewExtractor', `DB put: ${name} (${blob?.size || 0} bytes)`);
                };
                req.onerror = () => {
                    this.log('ZipPreviewExtractor', `DB put error: ${name} - ${req.error}`);
                    reject(req.error);
                };
            } catch (e) {
                this.log('ZipPreviewExtractor', `DB put failed: ${name} - ${e.message || e}`);
                reject(e);
            }
        });

        if (this.verifyAfterPut) {
            try {
                const rec = await this.getFile(name);
                const ok = !!(rec && rec.blob && typeof rec.blob.size === 'number' && rec.blob.size > 0);
                if (!ok) {
                    this.log('ZipPreviewExtractor', `DB verify failed: ${name}`);
                }
            } catch (e) {
                this.log('ZipPreviewExtractor', `DB verify error: ${name} - ${e.message || e}`);
            }
        }
    }

    async getFile(name) {
        this._stats.dbGet += 1;

        return await this._transaction('readonly', (store, resolve, reject) => {
            const req = store.get(name);

            req.onsuccess = () => {
                const rec = req.result || null;
                resolve(rec);
            };
            req.onerror = () => {
                this.log('ZipPreviewExtractor', `DB get error: ${name} - ${req.error}`);
                reject(req.error);
            };
        });
    }

    async hasFile(name) {
        const r = await this.getFile(name);
        return !!r;
    }

    // --- ZIP stream parsing --------------------------------------------------

    // Feed one chunk of ZIP bytes (Uint8Array)
    feed(chunk) {
        if (this._stopped)
            return;

        if (!(chunk instanceof Uint8Array))
            chunk = new Uint8Array(chunk);

        if (chunk.byteLength === 0)
            return;

        this._stats.fedChunks += 1;
        this._stats.fedBytes += chunk.byteLength;

        this.q.push(chunk);

        // Parse asynchronously; do not block caller
        if (!this._parsing) {
            this._parsing = true;
            queueMicrotask(() => this._drain().finally(() => {
                this._parsing = false;
            }));
        }
    }

    async _drain() {
        if (!this._metaLoaded) {
            // allow feeding before metadata; we'll just buffer and wait
            return;
        }

        try {
            while (!this._stopped) {
                // Need at least 4 bytes to detect signature
                if (this.q.available < 4)
                    return;

                // If we don't have a current entry, parse a new local file header
                if (!this._current) {
                    const sig = this.q.peekU32LE();
                    this._stats.lastSig = sig;

                    // Local file header: 0x04034b50
                    if (sig === 0x04034b50) {
                        if (this.q.available < 30)
                            return; // wait

                        const hdr = this.q.peekBytes(30);
                        const dv = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);

                        // local header fields
                        const version = dv.getUint16(4, true);
                        const flags = dv.getUint16(6, true);
                        const method = dv.getUint16(8, true);
                        const crc32 = dv.getUint32(14, true);
                        const compSize = dv.getUint32(18, true);
                        const uncompSize = dv.getUint32(22, true);
                        const nameLen = dv.getUint16(26, true);
                        const extraLen = dv.getUint16(28, true);

                        const need = 30 + nameLen + extraLen;
                        if (this.q.available < need)
                            return;

                        this._stats.parsedHeaders += 1;

                        // consume fixed header
                        this.q.skip(30);

                        // filename
                        const nameBytes = this.q.readBytes(nameLen);
                        const name = new TextDecoder('utf-8').decode(nameBytes);

                        // extra
                        if (extraLen)
                            this.q.skip(extraLen);

                        // Central dir or weird entries won't have metadata; handle gracefully
                        if (name.endsWith('/')) {
                            // directory entry
                            this._current = null;
                            continue;
                        }

                        const meta = this.metaByName.get(name);
                        if (!meta || !Number.isFinite(meta.size)) {
                            // Unknown entry: best-effort skip by scanning to next local header signature.
                            this._stats.skippedUnknown += 1;
                            this.log('ZipPreviewExtractor', `Skip unknown entry: ${name}`);
                            this._current = {
                                name,
                                size: -1,
                                index: -1,
                                mime: ''
                            };
                        } else {
                            this._current = {
                                name,
                                size: meta.size,
                                index: meta.index,
                                mime: meta.mime || ''
                            };
                            this._stats.lastEntry = {
                                name,
                                size: meta.size,
                                index: meta.index
                            };
                        }
                    } else if (sig === 0x02014b50 || sig === 0x06054b50) {
                        // central directory / EOCD reached
                        this.log('ZipPreviewExtractor', 'Reached central directory');
                        this.stop();
                        return;
                    } else {
                        // Not aligned; skip one byte and retry (resync)
                        this._stats.resyncSkips += 1;
                        this.q.skip(1);
                        continue;
                    }
                }

                // We have current entry: read its data
                if (this._current) {
                    const cur = this._current;

                    if (cur.size < 0) {
                        // Unknown-size entry: attempt resync by scanning for next local header signature.
                        const advanced = this.q.scanToSignature(0x04034b50);
                        if (!advanced)
                            return;

                        this._current = null;
                        continue;
                    }

                    if (this.q.available < cur.size) {
                        // wait for full file bytes
                        return;
                    }

                    const fileBytes = this.q.readBytes(cur.size);

                    // Optional data descriptor (Reader.py style): signature + 3x u32 => 16 bytes
                    if (this.q.available >= 4) {
                        const nextSig = this.q.peekU32LE();
                        if (nextSig === 0x08074b50) {
                            if (this.q.available < 16)
                                return; // wait (rare)

                            this.q.skip(16);
                        }
                    }

                    const mime = cur.mime || 'application/octet-stream';
                    const blob = new Blob([fileBytes], {
                        type: mime
                    });

                    this.log('ZipPreviewExtractor', `Extracted file: ${cur.name} (${blob.size} bytes)`);

                    await this.putFile(cur.name, blob, cur.index, mime);
                    this._stats.extractedFiles += 1;

                    try {
                        this.onFileReady && this.onFileReady({
                            name: cur.name,
                            index: cur.index,
                            blob
                        });
                    } catch (e) {
                        this.log('ZipPreviewExtractor', `onFileReady error: ${cur.name} - ${e.message || e}`);
                    }

                    this._current = null;
                }
            }
        } catch (e) {
            this.log('ZipPreviewExtractor', `Drain error: ${e.stack || e}`);
            // If parsing crashes repeatedly, stop to avoid infinite loop
            this.stop();
        }
    }

}

class ByteQueue {
    constructor() {
        this.chunks = [];
        this.headIndex = 0;
        this.headOffset = 0;
        this.available = 0;
    }

    push(u8) {
        if (!u8 || u8.byteLength === 0)
            return;

        this.chunks.push(u8);
        this.available += u8.byteLength;
    }

    peekU32LE() {
        const b = this.peekBytes(4);
        const dv = new DataView(b.buffer, b.byteOffset, 4);
        return dv.getUint32(0, true);
    }

    peekBytes(n) {
        if (n <= 0)
            return new Uint8Array(0);

        if (this.available < n)
            throw new Error('peekBytes: insufficient data');

        // fast path: in one chunk
        const head = this.chunks[this.headIndex];
        const remainingInHead = head.byteLength - this.headOffset;
        if (remainingInHead >= n) {
            return head.subarray(this.headOffset, this.headOffset + n);
        }

        // slow path: copy
        const out = new Uint8Array(n);
        let outOff = 0;
        let idx = this.headIndex;
        let off = this.headOffset;
        while (outOff < n) {
            const c = this.chunks[idx];
            const take = Math.min(n - outOff, c.byteLength - off);
            out.set(c.subarray(off, off + take), outOff);
            outOff += take;
            idx += 1;
            off = 0;
        }
        return out;
    }

    readBytes(n) {
        // NOTE: caller must ensure enough `available`.
        const out = new Uint8Array(n);
        let outOff = 0;
        while (outOff < n) {
            const head = this.chunks[this.headIndex];
            if (!head)
                throw new Error(
                `readBytes: out of data (need=${n}, outOff=${outOff}, available=${this.available})`);

            const remainingInHead = head.byteLength - this.headOffset;
            const take = Math.min(n - outOff, remainingInHead);
            out.set(head.subarray(this.headOffset, this.headOffset + take), outOff);
            outOff += take;
            this.headOffset += take;
            this.available -= take;
            if (this.headOffset >= head.byteLength) {
                this.headIndex += 1;
                this.headOffset = 0;
                // compact occasionally
                if (this.headIndex > 64) {
                    this.chunks = this.chunks.slice(this.headIndex);
                    this.headIndex = 0;
                }
            }
        }
        return out;
    }

    skip(n) {
        this.readBytes(n); // discard
    }

    // Best-effort resync: scan bytes until signature found (returns true if advanced)
    scanToSignature(sigU32LE) {
        // We need at least 4 bytes to match
        while (this.available >= 4) {
            const s = this.peekU32LE();
            if (s === sigU32LE)
                return true;

            this.skip(1);
        }
        return false;
    }
}

// Expose globally for <script> and importScripts() usage
(function() {
    const g = (typeof self !== 'undefined') ? self : (typeof window !== 'undefined' ? window : this);
    g.ZipPreviewExtractor = ZipPreviewExtractor;
})();