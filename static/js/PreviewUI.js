/*!
 * FastFileLink - File Preview User Interface
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * File info hint and ZIP preview gallery with glassmorphism design
 * Integrates with existing FastFileLink download page
 *
 * See LICENSE file in the project root for full license information.
 */

(function() {
    'use strict';


    // Utility functions for file size formatting
    const FormatUtils = {
        /**
         * Format bytes to human-readable size with decimal precision
         * @param {number} bytes - Size in bytes
         * @returns {string} Formatted size (e.g., "22.1 KB", "1.5 MB")
         */
        formatBytes(bytes) {
            if (bytes === 0)
                return '0 Bytes';
                
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        /**
         * Format bytes to simple human-readable size (rounded, no decimals)
         * @param {number|string} sizeStr - Size in bytes (number or string)
         * @returns {string} Simplified size (e.g., "22 KB", "2 MB")
         */
        formatBytesSimple(sizeStr) {
            const bytes = typeof sizeStr === 'string' ? parseInt(sizeStr) : sizeStr;
            if (isNaN(bytes))
                return String(sizeStr);

            if (bytes === 0)
                return '0 bytes';
                
            if (bytes >= 1024 * 1024 * 1024) {
                return Math.round(bytes / (1024 * 1024 * 1024)) + ' GB';
            } else if (bytes >= 1024 * 1024) {
                return Math.round(bytes / (1024 * 1024)) + ' MB';
            } else if (bytes >= 1024) {
                return Math.round(bytes / 1024) + ' KB';
            } else {
                return bytes + ' bytes';
            }
        }
    };

    // ========================================================================
    // File Preview & Initialization
    // ========================================================================

    class PreviewUI {
        constructor(options = {}) {
            this.options = {
                log: options.log || ((tag, msg) => console.log(`[${tag}] ${msg}`)),
                metadataURL: options.metadataURL || '/uid=****/manifest',
                thumbnailURLTemplate: options.thumbnailURLTemplate ||
                    '/uid=****/thumb?path={path}&w=420&h=320&fmt=jpeg',
                fileURLTemplate: options.fileURLTemplate || '/uid=****/file?path={path}',
                ...options
            };

            this.isPreviewableZip = false;
            this.overlay = null;
            this.viewer = null;
            this.extractor = null;

            // Store getDownloadState function
            this.getDownloadState = options.getDownloadState || null;

            // Thumbnail loading queue (prevents tunnel/relay 502 from too many simultaneous requests)
            this._thumbnailQueue = [];
            this._activeThumbnailLoads = 0;
            this._maxConcurrentThumbnails = 5; // Limit concurrent thumbnail requests
            this._thumbnailLoadToken = 0;

            // Translation helper (uses window.t if available)
            this.t = (typeof window !== 'undefined' && typeof window.t === 'function')
                ? window.t
                : (key, defaultValue) => defaultValue || key;

            this.log('PreviewUI', 'Constructed');

            // Initialize immediately in constructor
            this._initPromise = this._initialize();
        }

        async _initialize() {
            this.log('ZipPreview', 'Initializing...');

            // Try to fetch metadata to determine if this is a previewable ZIP
            try {
                this.log('ZipPreview', 'Checking for preview support (fetching metadata)...');
                const response = await fetch(this.options.metadataURL, {
                    cache: 'no-cache'
                });

                if (response.ok) {
                    // Fetch raw data (don't parse - let extractor handle decryption)
                    const rawData = await response.arrayBuffer();
                    this.log('ZipPreview', `Metadata fetched: ${rawData.byteLength} bytes`);

                    // Extract X-Original-Size header (needed for E2EE decryption)
                    const originalSize = response.headers.get('X-Original-Size');
                    const originalSizeNum = originalSize ? parseInt(originalSize, 10) : null;

                    if (originalSizeNum !== null) {
                        this.log('ZipPreview', `Original size: ${originalSizeNum} bytes`);
                    }

                    // Metadata fetch succeeded - create extractor with raw data
                    this.isPreviewableZip = true;
                    this.createExtractor(rawData, originalSizeNum);
                    this.log('ZipPreview', 'Extractor created with metadata');
                } else {
                    this.log('ZipPreview', `No preview support (metadata fetch failed: ${response.status})`);
                    this.isPreviewableZip = false;
                }
            } catch (e) {
                this.log('ZipPreview', `No preview support (metadata error: ${e})`);
                this.isPreviewableZip = false;
            }

            // Enhance info icon for hover behavior (for all files)
            this.enhanceInfoIcon();

            // Enhance preview button (only for previewable ZIPs)
            if (this.isPreviewableZip) {
                this.enhancePreviewButton();
            }

            // Auto-show inline hint on page load
            this.showInlineHint();

            // Auto-hide after 5 seconds
            setTimeout(() => {
                this.hideInlineHint();
            }, 5000);

            this.log('ZipPreview', 'Initialization complete - inline hint shown, will auto-hide after 5s');
        }

        log(tag, message) {
            if (this.options.log) {
                this.options.log(tag, message);
            }
        }

        // ====================================================================
        // UI Initialization
        // ====================================================================

        enhanceInfoIcon() {
            const infoIcon = document.getElementById('file-info-icon');
            if (!infoIcon) {
                this.log('ZipPreview', 'Info icon element not found');
                return;
            }

            this.log('ZipPreview', `Info icon element found, isPreviewableZip: ${this.isPreviewableZip}`);

            // Set up hover behavior to show file hint
            let showTimer = null;
            let hideTimer = null;
            let isHintVisible = false;

            const cancelHideTimer = () => {
                if (hideTimer) {
                    clearTimeout(hideTimer);
                    hideTimer = null;
                }
            };

            const scheduleHide = () => {
                cancelHideTimer();
                hideTimer = setTimeout(() => {
                    this.hideFileInfoHint();
                    isHintVisible = false;
                }, 300);
            };

            infoIcon.addEventListener('mouseenter', () => {
                // Cancel any pending hide
                cancelHideTimer();

                // Show hint after short delay (prevent flicker)
                if (!isHintVisible) {
                    showTimer = setTimeout(() => {
                        this.showFileInfoHint();
                        isHintVisible = true;
                    }, 200);
                }
            });

            infoIcon.addEventListener('mouseleave', () => {
                // Cancel show if mouse leaves quickly
                if (showTimer) {
                    clearTimeout(showTimer);
                    showTimer = null;
                }

                // Schedule hide
                if (isHintVisible) {
                    scheduleHide();
                }
            });

            // Keep hint visible when hovering over it
            const hintEl = document.getElementById('file-intro-hint');
            if (hintEl) {
                hintEl.addEventListener('mouseenter', () => {
                    // Cancel any pending hide when mouse enters hint
                    cancelHideTimer();
                    isHintVisible = true;
                });

                hintEl.addEventListener('mouseleave', () => {
                    // Schedule hide when mouse leaves hint
                    scheduleHide();
                });
            }

            // Add click handler to show detail overlay (same as hover)
            infoIcon.style.cursor = 'pointer';
            infoIcon.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                // Toggle hint visibility on click
                if (!isHintVisible) {
                    this.showFileInfoHint();
                    isHintVisible = true;
                    cancelHideTimer(); // Don't auto-hide after clicking
                    this.log('ZipPreview', 'Info icon clicked, showing detail overlay');
                } else {
                    this.hideFileInfoHint();
                    isHintVisible = false;
                    this.log('ZipPreview', 'Info icon clicked, hiding detail overlay');
                }
            });

            // For ZIP files, add visual indicator
            if (this.isPreviewableZip) {
                infoIcon.classList.add('has-zip-preview', 'pulse');
                this.log('ZipPreview', 'Added classes: has-zip-preview, pulse');

                // Remove pulse after 5 seconds
                setTimeout(() => {
                    infoIcon.classList.remove('pulse');
                    this.log('ZipPreview', 'Pulse animation removed');
                }, 5000);

                this.log('ZipPreview', 'Info icon enhanced for ZIP preview - click or hover for info!');
            } else {
                this.log('ZipPreview', 'Info icon enhanced - click or hover for file info');
            }
        }

        enhancePreviewButton() {
            const previewBtn = document.getElementById('file-preview-btn');
            if (!previewBtn) {
                this.log('ZipPreview', 'Preview button element not found');
                return;
            }

            // Show preview button for ZIP files
            previewBtn.style.display = 'inline';
            this.log('ZipPreview', 'Preview button shown (ZIP file detected)');

            // Wire up click handler - uses same logic as preview button in hint
            previewBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                this.log('PreviewButton', 'Status preview button clicked');
                this.openPreviewWithStateCheck();
            });

            this.log('ZipPreview', 'Preview button click handler wired up');
        }

        createOverlay() {
            if (this.overlay)
                return; // Already created

            // Create overlay HTML
            const overlayHtml = `
                <div class="zip-preview-overlay" id="zip-preview-overlay">
                    <div class="zip-preview-container">
                        <!-- Header -->
                        <div class="zip-preview-header">
                            <!-- Header Top Row -->
                            <div class="zip-preview-header-top">
                                <div class="zip-preview-title">
                                    <i class="fas fa-file-archive zip-preview-title-icon"></i>
                                    <div class="zip-preview-title-text">
                                        <div class="zip-preview-title-main" id="zip-preview-filename">${this.t('Download:zipPreview.archiveContents', 'Archive Contents')}</div>
                                        <div class="zip-preview-title-sub" id="zip-preview-subtitle">${this.t('Download:zipPreview.loading', 'Loading...')}</div>
                                    </div>
                                </div>
                                <button class="zip-preview-play-btn" id="zip-preview-play-btn" title="${this.t('Download:zipPreview.startDownload', 'Start download')}">
                                    <i class="fas fa-download"></i>
                                </button>
                                <button class="zip-preview-close-btn" id="zip-preview-close" title="${this.t('Download:zipPreview.closePreview', 'Close preview')}">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>

                            <!-- Download Progress (synced with main page) -->
                            <div class="zip-preview-download-progress" id="zip-preview-download-progress" style="display: none;">
                                <div class="zip-preview-download-status">
                                    <div class="zip-preview-download-status-text" id="zip-preview-status-text">${this.t('Download:client.status.establishing', 'Establishing connection...')}</div>
                                    <div class="zip-preview-download-connection" id="zip-preview-connection-type"></div>
                                </div>
                                <div class="zip-preview-download-progress-bar">
                                    <div class="zip-preview-download-progress-bar-fill" id="zip-preview-progress-bar-fill"></div>
                                    <progress id="zip-preview-progress-bar" value="0" max="100"></progress>
                                </div>
                                <div class="zip-preview-download-message" id="zip-preview-download-message"></div>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="zip-preview-content" id="zip-preview-content">
                            <div class="zip-preview-loading" id="zip-preview-loading">
                                <div class="zip-preview-spinner"></div>
                                <div class="zip-preview-loading-text">${this.t('Download:zipPreview.loadingContents', 'Loading archive contents...')}</div>
                            </div>

                            <div class="zip-preview-grid" id="zip-preview-grid" style="display: none;">
                                <!-- Gallery cards will be inserted here -->
                            </div>

                            <div class="zip-preview-empty" id="zip-preview-empty" style="display: none;">
                                <i class="fas fa-folder-open zip-preview-empty-icon"></i>
                                <div class="zip-preview-empty-text">${this.t('Download:zipPreview.noFiles', 'No previewable files found')}</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- File Viewer Modal -->
                <div class="zip-file-viewer" id="zip-file-viewer">
                    <div class="zip-file-viewer-content">
                        <div class="zip-file-viewer-header">
                            <div class="zip-file-viewer-name" id="zip-viewer-name">${this.t('Download:zipPreview.file', 'File')}</div>
                            <button class="zip-file-viewer-close" id="zip-viewer-close">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        <div class="zip-file-viewer-body" id="zip-viewer-body">
                            <div class="zip-file-viewer-loading" id="zip-viewer-loading" style="display: none;">
                                <div class="zip-file-viewer-spinner"></div>
                                <div class="zip-file-viewer-loading-text">${this.t('Download:zipPreview.loading', 'Loading...')}</div>
                            </div>
                            <img id="zip-viewer-img" src="" alt="" style="display: none;" />
                            <video id="zip-viewer-video" controls style="display: none; max-width: 100%; max-height: 100%;"></video>
                        </div>
                    </div>
                </div>
            `;

            // Insert into DOM
            document.body.insertAdjacentHTML('beforeend', overlayHtml);

            // Get references
            this.overlay = document.getElementById('zip-preview-overlay');
            this.viewer = document.getElementById('zip-file-viewer');

            // Attach event listeners
            this.attachEventListeners();

            this.log('ZipPreview', 'Overlay created');
        }

        attachEventListeners() {
            // Close button
            const closeBtn = document.getElementById('zip-preview-close');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => this.closePreview());
            }

            // Play button - sync with main play button
            const overlayPlayBtn = document.getElementById('zip-preview-play-btn');
            if (overlayPlayBtn) {
                overlayPlayBtn.addEventListener('click', () => {
                    // Trigger the main play button click
                    const mainPlayBtn = document.getElementById('play-download-btn');
                    if (mainPlayBtn) {
                        mainPlayBtn.click();
                    }
                });

                // Sync visibility with main play button
                const mainPlayBtn = document.getElementById('play-download-btn');
                if (mainPlayBtn) {
                    // Check initial state FIRST (in case button is already visible)
                    const updateVisibility = () => {
                        if (mainPlayBtn.style.display === 'inline-flex') {
                            overlayPlayBtn.classList.add('visible');
                        } else {
                            overlayPlayBtn.classList.remove('visible');
                        }
                    };

                    // Set initial state
                    updateVisibility();

                    // Then observe future changes
                    const observer = new MutationObserver(updateVisibility);
                    observer.observe(mainPlayBtn, {
                        attributes: true,
                        attributeFilter: ['style']
                    });
                }
            }

            // Click outside to close
            this.overlay.addEventListener('click', (e) => {
                if (e.target === this.overlay) {
                    this.closePreview();
                }
            });

            // Viewer close button
            const viewerCloseBtn = document.getElementById('zip-viewer-close');
            if (viewerCloseBtn) {
                viewerCloseBtn.addEventListener('click', () => this.closeViewer());
            }

            // Click outside viewer to close
            this.viewer.addEventListener('click', (e) => {
                if (e.target === this.viewer) {
                    this.closeViewer();
                }
            });

            // ESC key to close
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    if (this.viewer.classList.contains('active')) {
                        this.closeViewer();
                    } else if (this.overlay.classList.contains('active')) {
                        this.closePreview();
                    }
                }
            });
        }

        // ====================================================================
        // Progress Syncing
        // ====================================================================

        startProgressSync() {
            // Show progress section
            const progressSection = document.getElementById('zip-preview-download-progress');
            if (progressSection) {
                progressSection.style.display = 'flex';
            }

            // Sync progress immediately
            this.syncProgress();

            // Set up periodic sync (every 100ms for smooth updates)
            if (this.progressSyncInterval) {
                clearInterval(this.progressSyncInterval);
            }

            this.progressSyncInterval = setInterval(() => {
                this.syncProgress();
            }, 100);
        }

        stopProgressSync() {
            if (this.progressSyncInterval) {
                clearInterval(this.progressSyncInterval);
                this.progressSyncInterval = null;
            }
        }

        syncProgress() {
            // Get elements from main page
            const mainStatusText = document.getElementById('statusText');
            const mainProgressBar = document.getElementById('downloadProgress');
            const mainConnectionType = document.getElementById('connectionType');
            const mainDownloadMessage = document.getElementById('download-message');

            // Get elements from overlay
            const overlayStatusText = document.getElementById('zip-preview-status-text');
            const overlayProgressBar = document.getElementById('zip-preview-progress-bar');
            const overlayProgressBarFill = document.getElementById('zip-preview-progress-bar-fill');
            const overlayConnectionType = document.getElementById('zip-preview-connection-type');
            const overlayDownloadMessage = document.getElementById('zip-preview-download-message');

            // Sync status text
            if (mainStatusText && overlayStatusText) {
                overlayStatusText.textContent = mainStatusText.textContent || this.t('Download:client.status.establishing', 'Establishing connection...');
            }

            // Sync progress bar - use BOTH progress element AND div fallback
            if (mainProgressBar) {
                const progressValue = mainProgressBar.value || 0;
                const progressMax = mainProgressBar.max || 100;
                const progressPercent = (progressValue / progressMax) * 100;

                // Update progress element
                if (overlayProgressBar) {
                    overlayProgressBar.value = progressValue;
                    overlayProgressBar.max = progressMax;
                    overlayProgressBar.setAttribute('value', progressValue);
                    overlayProgressBar.setAttribute('max', progressMax);
                }

                // Update div-based progress bar (FALLBACK - this will definitely work!)
                if (overlayProgressBarFill) {
                    overlayProgressBarFill.style.width = progressPercent + '%';
                }

                // Progress logging removed - too verbose
            }

            // Sync connection type
            if (mainConnectionType && overlayConnectionType) {
                overlayConnectionType.textContent = mainConnectionType.textContent || '';
            }

            // Sync download message
            if (mainDownloadMessage && overlayDownloadMessage) {
                overlayDownloadMessage.textContent = mainDownloadMessage.textContent || '';
            }
        }

        // ====================================================================
        // Preview Operations
        // ====================================================================

        /**
         * Open preview with download state check (DRY helper)
         * Handles preview opening with proper state detection
         */
        openPreviewWithStateCheck() {
            if (this.getDownloadState) {
                const state = this.getDownloadState();
                this.handlePreviewButtonClick(state);
            } else {
                // Fallback if state not available (shouldn't happen in normal flow)
                this.openPreview();
            }
        }

        handlePreviewButtonClick(downloadState) {
            // Three scenarios based on download state
            const {
                started,
                completed
            } = downloadState;

            this.log('ZipPreview',
                `handlePreviewButtonClick called: started=${started}, completed=${completed}`);

            if (completed) {
                // Scenario C: Download complete - directly open preview
                this.log('ZipPreview', 'Scenario C: Download complete, opening preview');
                this.openPreview();
            } else if (!started) {
                // Scenario A: Not started - pause and open preview
                this.log('ZipPreview', 'Scenario A: Not started, pausing and opening preview');
                if (downloadState.pauseFn) {
                    downloadState.pauseFn(); // Pause download (prevent START)
                }
                this.openPreview();
            } else {
                // Scenario B: Downloading - show options modal
                this.log('ZipPreview', 'Scenario B: Download in progress, showing options modal');
                this.showPreviewOptionsModal(downloadState);
            }
        }

        showPreviewOptionsModal(downloadState) {
            this.log('ZipPreview', 'showPreviewOptionsModal called, creating modal...');

            // Remove existing modal if any
            const existingModal = document.getElementById('preview-options-modal');
            if (existingModal) {
                this.log('ZipPreview', 'Removing existing modal before creating new one');
                existingModal.remove();
            }

            // Create modal HTML
            const modalHtml = `
                <div class="preview-options-modal" id="preview-options-modal">
                    <div class="preview-options-content">
                        <h3>${this.t('Download:zipPreview.optionsTitle', 'Preview Options')}</h3>
                        <p>${this.t('Download:zipPreview.optionsMessage', 'Your download is in progress. How would you like to preview?')}</p>
                        <div class="preview-options-buttons">
                            <button class="preview-option-btn primary" id="preview-continue-download">
                                <i class="fas fa-download"></i>
                                <span>${this.t('Download:zipPreview.continueDownloading', 'Continue downloading while previewing (Recommended)')}</span>
                            </button>
                            <button class="preview-option-btn secondary" id="preview-only">
                                <i class="fas fa-eye"></i>
                                <span>${this.t('Download:zipPreview.previewOnly', 'Preview only (Cancel current download)')}</span>
                            </button>
                        </div>
                        <p class="preview-options-hint">${this.t('Download:zipPreview.optionsHint', 'Note: "Preview only" will discard downloaded progress and reload the page.')}</p>
                    </div>
                </div>
            `;

            // Insert modal
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            const modal = document.getElementById('preview-options-modal');
            this.log('ZipPreview', `Modal inserted into DOM: ${!!modal}`);

            if (!modal) {
                this.log('ZipPreview', 'ERROR: Modal element not found after insertion!');
                return;
            }

            // Debug: Check computed styles
            const computedStyle = window.getComputedStyle(modal);
            this.log('ZipPreview',
                `Modal computed styles: display=${computedStyle.display}, zIndex=${computedStyle.zIndex}, opacity=${computedStyle.opacity}`
                );
            this.log('ZipPreview',
                `Modal position in DOM: ${modal.parentElement?.tagName}, children=${modal.children.length}`);

            // Option 1: Continue downloading + preview
            const continueBtn = document.getElementById('preview-continue-download');
            const previewOnlyBtn = document.getElementById('preview-only');

            this.log('ZipPreview',
                `Modal buttons found: continue=${!!continueBtn}, previewOnly=${!!previewOnlyBtn}`);

            if (continueBtn) {
                continueBtn.addEventListener('click', () => {
                    this.log('ZipPreview', 'User chose: continue downloading');
                    modal.remove();
                    this.openPreview(); // Open preview without stopping download
                });
            }

            // Option 2: Preview only (reload page with ?preview=true)
            if (previewOnlyBtn) {
                previewOnlyBtn.addEventListener('click', () => {
                    this.log('ZipPreview', 'User chose: preview only (reload)');
                    const newURL = window.location.pathname + '?preview=true' + window.location.hash;
                    window.location.href = newURL; // Reload with preview mode
                });
            }

            // Close on outside click
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.log('ZipPreview', 'User clicked outside modal, closing');
                    modal.remove();
                }
            });

            this.log('ZipPreview', 'Modal setup complete and should be visible');
        }

        async openPreview() {
            this.log('ZipPreview', 'Opening preview...');

            // Wait for initialization to complete before opening
            await this._initPromise;

            // Create overlay if not exists (show loading state)
            this.createOverlay();

            // Show overlay with loading state
            this.overlay.classList.add('active');
            document.body.style.overflow = 'hidden';

            // Show loading indicator while waiting for metadata
            const loadingEl = document.getElementById('zip-preview-loading');
            const gridEl = document.getElementById('zip-preview-grid');
            if (loadingEl) {
                loadingEl.style.display = 'flex';
            }
            if (gridEl) {
                gridEl.style.display = 'none';
            }

            // Wait for metadata to be decrypted and loaded (E2EE takes time)
            if (this.extractor && this.extractor._metadataInitPromise) {
                this.log('ZipPreview', 'Waiting for metadata initialization...');
                await this.extractor._metadataInitPromise;
                this.log('ZipPreview', 'Metadata initialization complete');
            }

            // Start syncing download progress from main page
            this.startProgressSync();

            // Update UI with metadata (now guaranteed to be loaded)
            this.updateMetadataUI();

            // Render gallery (this will hide loading and show grid)
            this.renderGallery();

            // Update badges for files already in IndexedDB (if download started before preview opened)
            await this.updateExistingFileBadges();
        }

        closePreview() {
            this.log('ZipPreview', 'Closing preview');

            // Stop syncing progress
            this.stopProgressSync();

            // Disconnect thumbnail lazy loading observer
            if (this._thumbnailObserver) {
                this._thumbnailObserver.disconnect();
                this._thumbnailObserver = null;
            }
            this._thumbnailQueue = [];
            this._thumbnailLoadToken += 1;

            if (this.overlay) {
                this.overlay.classList.remove('active');
            }

            document.body.style.overflow = '';
        }

        updateMetadataUI() {
            // Get metadata from extractor (already loaded in _initialize)
            const metadata = this.extractor?.meta;
            if (!metadata) {
                this.log('ZipPreview', 'Cannot update UI - metadata not loaded');
                return;
            }

            this.log('ZipPreview', 'Updating UI with metadata from extractor');

            // Update header UI
            const fileNameEl = document.getElementById('zip-preview-filename');
            const subtitleEl = document.getElementById('zip-preview-subtitle');

            if (fileNameEl && metadata.zipName) {
                fileNameEl.textContent = metadata.zipName;
            }

            if (subtitleEl) {
                const count = (metadata.entries || []).length;
                const sizeStr = this.formatFileSize(metadata.zipSize || 0);
                subtitleEl.textContent = this.t('Download:zipPreview.filesSizeCount', '{{count}} files • {{size}}', { count, size: sizeStr });
            }

            this.log('ZipPreview', `Metadata UI updated: ${(metadata.entries || []).length} entries`);
        }

        renderGallery() {
            const loadingEl = document.getElementById('zip-preview-loading');
            const gridEl = document.getElementById('zip-preview-grid');
            const emptyEl = document.getElementById('zip-preview-empty');

            if (!this.extractor?.meta || !this.extractor?.meta.entries || this.extractor?.meta.entries.length === 0) {
                if (loadingEl)
                    loadingEl.style.display = 'none';

                if (emptyEl)
                    emptyEl.style.display = 'flex';

                return;
            }

            // Hide loading, show grid
            if (loadingEl)
                loadingEl.style.display = 'none';

            if (gridEl)
                gridEl.style.display = 'grid';

            // Clear existing cards
            gridEl.innerHTML = '';

            // Render cards
            this.extractor?.meta.entries.forEach((entry) => {
                const card = this.createCard(entry);
                gridEl.appendChild(card);
            });

            this.log('ZipPreview', `Rendered ${this.extractor?.meta.entries.length} cards`);

            // Set up lazy loading for thumbnails using IntersectionObserver
            this._thumbnailQueue = [];
            this._thumbnailLoadToken += 1;
            this._setupThumbnailLazyLoading();
        }

        createCard(entry) {
            const card = document.createElement('div');
            card.className = 'zip-preview-card';
            card.dataset.index = entry.index;

            const thumbnailURL = this.options.thumbnailURLTemplate.replace('{path}', encodeURIComponent(entry
                .name));
            const fileName = entry.name || `#${entry.index + 1}`; // User-friendly index (1-based)
            const fileSize = this.formatFileSize(entry.size || 0);

            // Check debug mode (URL parameter or localStorage)
            const debugMode = new URLSearchParams(window.location.search).has('debug') ||
                            localStorage.getItem('zip_preview_debug') === 'true';

            card.innerHTML = `
                <div class="zip-preview-thumb-wrap">
                    <img class="zip-preview-thumb"
                         data-thumbnail-url="${thumbnailURL}"
                         data-arcname="${entry.name}"
                         alt="${fileName}"
                         loading="lazy" />
                    ${debugMode ? `<div class="zip-preview-badge wait">${this.t('Download:zipPreview.badge.waiting', 'Waiting')}</div>` : ''}
                    <div class="zip-preview-actions">
                        <button class="zip-preview-action" data-action="view" title="${this.t('Download:zipPreview.actions.viewFullSize', 'View full size')}">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="zip-preview-action" data-action="download" title="${this.t('Download:zipPreview.actions.downloadFile', 'Download file')}">
                            <i class="fas fa-download"></i>
                        </button>
                    </div>
                </div>
                <div class="zip-preview-meta">
                    <div class="zip-preview-name" title="${fileName}">${this.truncateFileName(fileName)}</div>
                    <div class="zip-preview-details">
                        <span class="zip-preview-size">${fileSize}</span>
                        <span class="zip-preview-index">#${entry.index + 1}</span>
                    </div>
                </div>
            `;

            // Thumbnail loading strategy:
            // - Always lazy load via IntersectionObserver + queue to avoid burst requests
            const imgEl = card.querySelector('.zip-preview-thumb');
            imgEl.dataset.pendingLoad = 'true';

            // Click handler for card and actions
            card.addEventListener('click', (e) => {
                // Check if clicked on action button
                const actionBtn = e.target.closest('.zip-preview-action');
                if (actionBtn) {
                    e.stopPropagation(); // Prevent card click
                    const action = actionBtn.dataset.action;
                    if (action === 'view') {
                        this.openFileViewer(entry);
                    } else if (action === 'download') {
                        this.downloadFile(entry);
                    }
                } else {
                    // Clicked on card - open viewer
                    this.openFileViewer(entry);
                }
            });

            return card;
        }

        async updateExistingFileBadges() {
            // Check which files are already in IndexedDB and update their badges
            // This is needed when preview is opened after download has already started
            if (!this.extractor || !this.extractor?.meta || !this.extractor?.meta.entries) {
                return;
            }

            this.log('ZipPreview', 'Checking for existing files in IndexedDB...');
            let readyCount = 0;

            // Check each entry to see if it exists in IndexedDB (don't fetch)
            for (const entry of this.extractor?.meta.entries) {
                try {
                    // shouldFetch=false (default): only check IndexedDB, don't fetch via /zip/file
                    const blob = await this.extractor.getFileBlob(entry.index);
                    if (blob && blob.size > 0) {
                        // File exists in IndexedDB, update its badge
                        await this.updateCardBadge(entry.index, 'ready', blob);
                        readyCount++;
                    }
                } catch (e) {
                    // File doesn't exist yet, ignore
                }
            }

            if (readyCount > 0) {
                this.log('ZipPreview', `Updated ${readyCount} existing file badges to 'ready'`);
            }
        }

        /**
         * Add thumbnail to loading queue (LIFO - current viewport loads first)
         * @private
         */
        _queueThumbnail(imgEl, arcname, thumbnailURL) {
            // Add to queue (LIFO - push to end, pop from end)
            this._thumbnailQueue.push({ imgEl, arcname, thumbnailURL, token: this._thumbnailLoadToken });
            this.log('ZipPreview', `Queued thumbnail: ${arcname} (queue size: ${this._thumbnailQueue.length})`);

            // Try to process queue
            this._processThumbnailQueue();
        }

        /**
         * Process thumbnail loading queue with concurrency limit
         * LIFO (Last In, First Out) - loads current viewport thumbnails first
         * @private
         */
        async _processThumbnailQueue() {
            // Check if we can process more
            while (this._activeThumbnailLoads < this._maxConcurrentThumbnails && this._thumbnailQueue.length > 0) {
                // LIFO: Pop from end (most recent = current viewport)
                const task = this._thumbnailQueue.pop();
                if (!task) {
                    break;
                }

                if (!task.imgEl || !task.imgEl.isConnected || task.token !== this._thumbnailLoadToken) {
                    continue;
                }

                this._activeThumbnailLoads++;
                this.log('ZipPreview', `Processing thumbnail: ${task.arcname} (active: ${this._activeThumbnailLoads}/${this._maxConcurrentThumbnails})`);

                // Load thumbnail asynchronously
                this._loadThumbnail(task.imgEl, task.arcname, task.thumbnailURL)
                    .finally(() => {
                        this._activeThumbnailLoads--;
                        this.log('ZipPreview', `Completed thumbnail: ${task.arcname} (active: ${this._activeThumbnailLoads})`);
                        // Process next in queue
                        this._processThumbnailQueue();
                    });
            }
        }

        /**
         * Set up lazy loading for E2EE thumbnails using IntersectionObserver
         * Only loads thumbnails when they're about to enter the viewport
         */
        _setupThumbnailLazyLoading() {
            // Disconnect previous observer if exists
            if (this._thumbnailObserver) {
                this._thumbnailObserver.disconnect();
            }

            // Create IntersectionObserver with rootMargin to preload slightly before visible
            this._thumbnailObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const imgEl = entry.target;
                        const arcname = imgEl.dataset.arcname;
                        const thumbnailURL = imgEl.dataset.thumbnailUrl;

                        // Add to queue if not already loaded (LIFO - current viewport first)
                        if (imgEl.dataset.pendingLoad === 'true') {
                            imgEl.dataset.pendingLoad = 'false';
                            this._queueThumbnail(imgEl, arcname, thumbnailURL);
                        }

                        // Stop observing this image after queuing
                        this._thumbnailObserver.unobserve(imgEl);
                    }
                });
            }, {
                root: document.getElementById('zip-preview-content'),
                rootMargin: '100px', // Preload 100px before entering viewport
                threshold: 0.01
            });

            // Observe all pending thumbnail images
            const pendingImages = document.querySelectorAll('.zip-preview-thumb[data-pending-load="true"]');
            pendingImages.forEach(img => {
                this._thumbnailObserver.observe(img);
            });

            this.log('ZipPreview', `Lazy loading observer set up for ${pendingImages.length} E2EE thumbnails`);
        }

        /**
         * Load thumbnail with E2EE decryption support
         * @param {HTMLImageElement} imgEl - Image element to load thumbnail into
         * @param {string} arcname - File path in ZIP
         * @param {string} thumbnailURL - Thumbnail URL
         */
        async _loadThumbnail(imgEl, arcname, thumbnailURL) {
            const existingSrc = imgEl.getAttribute('src');
            if (imgEl.dataset.thumbnailLoaded === 'true' || (existingSrc && existingSrc.trim() !== '')) {
                return;
            }

            // Find the card element and add loading class
            const card = imgEl.closest('.zip-preview-card');
            if (card) {
                card.classList.add('loading');
            }

            try {
                // Check if E2EE is enabled and extractor supports decryption
                if (this.extractor.e2eeContext && typeof this.extractor.getThumbnailBlob === 'function') {
                    // E2EE enabled - fetch and decrypt thumbnail
                    this.log('ZipPreview', `Fetching encrypted thumbnail: ${arcname}`);
                    const blobURL = await this.extractor.getThumbnailBlob(arcname, thumbnailURL);
                    imgEl.src = blobURL;
                } else {
                    // E2EE not enabled - load thumbnail directly
                    imgEl.src = thumbnailURL;
                }

                // Wait for image to actually load
                await new Promise((resolve, reject) => {
                    imgEl.onload = resolve;
                    imgEl.onerror = reject;
                });

                imgEl.dataset.thumbnailLoaded = 'true';
                imgEl.dataset.pendingLoad = 'false';

                // Remove loading class after image loads
                if (card) {
                    card.classList.remove('loading');
                }
            } catch (error) {
                this.log('ZipPreview', `Thumbnail load error for ${arcname}: ${error.message}`);
                // Remove loading class on error
                if (card) {
                    card.classList.remove('loading');
                }
                // On error, try direct load as fallback
                imgEl.src = thumbnailURL;
            }
        }

        // ====================================================================
        // Loading State Helpers (DRY)
        // ====================================================================

        _showFileViewerLoading() {
            const loadingEl = document.getElementById('zip-viewer-loading');
            if (loadingEl) {
                loadingEl.style.display = 'flex';
            }
        }

        _hideFileViewerLoading() {
            const loadingEl = document.getElementById('zip-viewer-loading');
            if (loadingEl) {
                loadingEl.style.display = 'none';
            }
        }

        // ====================================================================
        // File Viewer
        // ====================================================================

        /**
         * Get file extension in lowercase
         * @private
         */
        _getFileExtension(filename) {
            if (!filename) {
                return '';
            }
            return filename.toLowerCase().substring(filename.lastIndexOf('.'));
        }

        /**
         * Get preview strategy based on file type
         * @private
         * @returns {'image'|'video'|'default'}
         */
        _getPreviewStrategy(filename) {
            const ext = this._getFileExtension(filename);

            // Image files - show in modal viewer
            const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico'];
            if (imageExtensions.includes(ext)) {
                return 'image';
            }

            // Video files - show in modal video player
            const videoExtensions = ['.mp4', '.webm', '.ogg', '.mov', '.avi', '.mkv', '.m4v'];
            if (videoExtensions.includes(ext)) {
                return 'video';
            }

            // All others (PDF, TXT, ZIP, etc.) - open in new tab
            return 'default';
        }

        /**
         * Open non-image file in new tab (PDF, TXT, ZIP, etc.)
         * Browser will use native viewer for the file type
         * @private
         */
        async openFileViewer(entry) {
            this.log('ZipPreview', `Opening file viewer for: ${entry.name}`);

            // Determine preview strategy
            const strategy = this._getPreviewStrategy(entry.name);

            // Route to appropriate preview method
            switch (strategy) {
                case 'image':
                    await this._previewImage(entry);
                    break;
                case 'video':
                    await this._previewVideo(entry);
                    break;
                default:
                    await this._previewInNewTab(entry);
                    break;
            }
        }

        /**
         * Show file viewer modal with loading state
         * @private
         */
        _showViewerModal(entry) {
            const viewer = document.getElementById('zip-file-viewer');
            const nameEl = document.getElementById('zip-viewer-name');

            if (viewer) {
                viewer.classList.add('active');
            }

            if (nameEl) {
                nameEl.textContent = entry.name || this.t('Download:zipPreview.fileNumber', 'File #{{index}}', { index: entry.index + 1 });
            }

            this._showFileViewerLoading();
        }

        // ====================================================================
        // Preview Handlers (Display Logic)
        // ====================================================================

        /**
         * Image Preview Handler - Displays image blob in modal
         * @private
         */
        async _handleImagePreview(blob, entry, imgEl) {
            if (blob && blob.size > 0) {
                // Display full image
                const url = URL.createObjectURL(blob);
                imgEl.src = url;
                imgEl.style.display = 'block';
                imgEl.style.maxWidth = '100%';
                imgEl.style.maxHeight = '100%';
                imgEl.style.objectFit = 'contain';
                imgEl.alt = entry.name || 'Preview';
                imgEl.onload = () => {
                    URL.revokeObjectURL(url);
                    this._hideFileViewerLoading();
                };
                imgEl.onerror = () => {
                    this._hideFileViewerLoading();
                };
            } else {
                // Fallback to thumbnail
                await this._handleImageFallback(entry, imgEl);
            }
        }

        /**
         * Image Fallback Handler - Shows thumbnail when full image unavailable
         * @private
         */
        async _handleImageFallback(entry, imgEl) {
            const thumbnailURL = this.options.thumbnailURLTemplate.replace('{path}', encodeURIComponent(entry.name));
            await this._loadThumbnail(imgEl, entry.name, thumbnailURL);
            imgEl.style.display = 'block';
            imgEl.alt = entry.name || 'Preview';
            this._hideFileViewerLoading();
        }

        /**
         * Video Preview Handler - Displays video blob in modal player
         * @private
         */
        _handleVideoPreview(blob, videoEl) {
            if (blob && blob.size > 0) {
                const url = URL.createObjectURL(blob);
                videoEl.src = url;
                videoEl.style.display = 'block';
                videoEl.onloadeddata = () => {
                    URL.revokeObjectURL(url);
                    this._hideFileViewerLoading();
                };
                videoEl.onerror = () => {
                    this._hideFileViewerLoading();
                };
            } else {
                this._hideFileViewerLoading();
            }
        }

        /**
         * Fallback Preview Handler - Opens file in new tab (PDF, TXT, etc.)
         * @private
         */
        _handleFallbackPreview(blob) {
            if (!blob || blob.size === 0) {
                return;
            }

            const url = URL.createObjectURL(blob);
            const newWindow = window.open(url, '_blank');

            if (newWindow) {
                newWindow.addEventListener('load', () => {
                    setTimeout(() => URL.revokeObjectURL(url), 100);
                });
            } else {
                URL.revokeObjectURL(url);
            }
        }

        /**
         * Preview image in modal viewer
         * @private
         */
        async _previewImage(entry) {
            const imgEl = document.getElementById('zip-viewer-img');
            const videoEl = document.getElementById('zip-viewer-video');

            if (!imgEl || !this.extractor) {
                return;
            }

            // Show modal and hide video element
            this._showViewerModal(entry);
            if (videoEl) {
                videoEl.style.display = 'none';
            }

            // Fetch blob and handle display
            try {
                const blob = await this.extractor.getFileBlob(entry.index, true);
                await this._handleImagePreview(blob, entry, imgEl);
            } catch (e) {
                await this._handleImageFallback(entry, imgEl);
            }
        }

        /**
         * Preview video in modal player
         * @private
         */
        async _previewVideo(entry) {
            const imgEl = document.getElementById('zip-viewer-img');
            const videoEl = document.getElementById('zip-viewer-video');

            if (!videoEl) {
                return;
            }

            // Show viewer modal
            this._showViewerModal(entry);

            // Hide image element
            if (imgEl) {
                imgEl.style.display = 'none';
            }

            // Fetch and display video
            if (!this.extractor) {
                this._hideFileViewerLoading();
                return;
            }

            try {
                const blob = await this.extractor.getFileBlob(entry.index, true);

                if (blob && blob.size > 0) {
                    const url = URL.createObjectURL(blob);
                    videoEl.src = url;
                    videoEl.style.display = 'block';
                    videoEl.onloadeddata = () => {
                        URL.revokeObjectURL(url);
                        this._hideFileViewerLoading();
                    };
                    videoEl.onerror = () => {
                        this._hideFileViewerLoading();
                    };
                } else {
                    this._hideFileViewerLoading();
                }
            } catch (e) {
                this._hideFileViewerLoading();
            }
        }

        /**
         * Preview non-media file in new tab (PDF, TXT, ZIP, etc.)
         * @private
         */
        async _previewInNewTab(entry) {
            if (!this.extractor) {
                return;
            }

            this._setActionLoading(entry, 'view', true);

            try {
                const blob = await this.extractor.getFileBlob(entry.index, true);
                if (!blob || blob.size === 0) {
                    return;
                }

                // Open in new tab
                const url = URL.createObjectURL(blob);
                const newWindow = window.open(url, '_blank');

                if (newWindow) {
                    newWindow.addEventListener('load', () => {
                        setTimeout(() => URL.revokeObjectURL(url), 100);
                    });
                } else {
                    URL.revokeObjectURL(url);
                }
            } catch (e) {
                this.log('ZipPreview', `Failed to open file: ${e}`);
            } finally {
                this._setActionLoading(entry, 'view', false);
            }
        }

        _setActionLoading(entry, action, isLoading) {
            const card = document.querySelector(`.zip-preview-card[data-index="${entry.index}"]`);
            const actionBtn = card?.querySelector(`.zip-preview-action[data-action="${action}"]`);
            const icon = actionBtn?.querySelector('i');
            if (!actionBtn || !icon) {
                return;
            }

            const defaultIconClass = action === 'download' ? 'fas fa-download' : 'fas fa-eye';

            if (isLoading) {
                actionBtn.classList.add('loading');
                icon.className = 'fas fa-spinner fa-spin';
            } else {
                actionBtn.classList.remove('loading');
                icon.className = defaultIconClass;
            }
        }

        async downloadFile(entry) {
            this.log('ZipPreview', `Downloading individual file: ${entry.name}`);

            if (!this.extractor) {
                this.log('ZipPreview', 'No extractor available');
                return;
            }

            try {
                // Show loading state
                this._setActionLoading(entry, 'download', true);

                // Get file blob from IndexedDB or fetch (may take time)
                const blob = await this.extractor.getFileBlob(entry.index, true);

                if (!blob || blob.size === 0) {
                    this.log('ZipPreview', 'Failed to get file blob');
                    return;
                }

                // Trigger download
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = entry.name || `file_${entry.index + 1}`; // User-friendly filename (1-based)
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                this.log('ZipPreview', `Download triggered for: ${entry.name}`);
            } catch (e) {
                this.log('ZipPreview', `Failed to download file: ${e}`);
            } finally {
                // Restore download icon
                this._setActionLoading(entry, 'download', false);
            }
        }

        closeViewer() {
            const viewer = document.getElementById('zip-file-viewer');
            if (viewer) {
                viewer.classList.remove('active');
            }
        }

        // ====================================================================
        // Utilities
        // ====================================================================

        formatFileSize(bytes) {
            // Use common utility
            return (typeof FormatUtils !== 'undefined') ?
                FormatUtils.formatBytes(bytes) :
                `${bytes} bytes`;
        }

        truncateFileName(fileName, maxLength = 30) {
            if (!fileName || fileName.length <= maxLength)
                return fileName;

            const ext = fileName.lastIndexOf('.');
            if (ext > 0 && ext > maxLength - 10) {
                const name = fileName.substring(0, maxLength - 10);
                const extension = fileName.substring(ext);
                return name + '...' + extension;
            }

            return fileName.substring(0, maxLength) + '...';
        }

        // ====================================================================
        // File Info Hint (small card near info icon - works for any file)
        // ====================================================================

        showFileInfoHint() {
            const introHint = document.getElementById('file-intro-hint');
            const infoIcon = document.getElementById('file-info-icon');

            if (!introHint) {
                this.log('FileInfo', 'Hint element not found');
                return;
            }

            if (!infoIcon) {
                this.log('FileInfo', 'Info icon element not found');
                return;
            }

            // Get file info from page
            const fileNameEl = document.getElementById('fileName');
            const fileName = fileNameEl ? fileNameEl.textContent.trim() : 'File';

            // Populate hint with file info
            const filenameEl = document.getElementById('file-intro-filename');
            const filesizeEl = document.getElementById('file-intro-filesize');
            const fileCountEl = document.getElementById('file-intro-filecount');
            const statImagesEl = document.getElementById('file-intro-stat-images');
            const statOthersEl = document.getElementById('file-intro-stat-others');
            const hintIconEl = document.getElementById('file-intro-icon');
            const statsContainer = document.querySelector('.file-intro-hint-stats');

            // Set filename
            if (filenameEl) {
                filenameEl.textContent = fileName;
                this.log('FileInfo', `Set filename: ${fileName}`);
            }

            // Set icon based on file type
            if (hintIconEl) {
                if (this.isPreviewableZip) {
                    hintIconEl.className = 'fas fa-file-archive file-intro-hint-icon';
                } else {
                    hintIconEl.className = 'fas fa-file file-intro-hint-icon';
                }
            }

            // For ZIP files with metadata, show detailed stats
            if (this.isPreviewableZip && this.extractor?.meta) {
                // Set filesize
                if (filesizeEl) {
                    const sizeStr = this.formatFileSize(this.extractor?.meta.zipSize || 0);
                    filesizeEl.textContent = sizeStr;
                    this.log('FileInfo', `Set filesize: ${sizeStr}`);
                }

                // Set file count
                const entries = this.extractor?.meta.entries || [];
                const totalCount = entries.length;
                if (fileCountEl) {
                    fileCountEl.textContent = this.t('Download:zipPreview.filesCount', '{{count}} files', { count: totalCount });
                    this.log('FileInfo', `Set file count: ${totalCount}`);
                }

                // Calculate image count and other files
                let imageCount = 0;
                let otherCount = 0;

                entries.forEach(entry => {
                    const mime = entry.mime || '';
                    if (mime.startsWith('image/')) {
                        imageCount++;
                    } else {
                        otherCount++;
                    }
                });

                // Set statistics
                if (statImagesEl) {
                    statImagesEl.textContent = imageCount.toLocaleString();
                    this.log('FileInfo', `Set image count: ${imageCount}`);
                }

                if (statOthersEl) {
                    statOthersEl.textContent = otherCount.toLocaleString();
                    this.log('FileInfo', `Set other files count: ${otherCount}`);
                }

                // Show stats section
                if (statsContainer) {
                    statsContainer.style.display = 'grid';
                }
            } else {
                // For non-ZIP files, hide stats section and show basic info
                if (statsContainer) {
                    statsContainer.style.display = 'none';
                }

                // Just show file size from page (no file count) - use simple format
                if (filesizeEl) {
                    const fileSizeDisplay = document.getElementById('fileSize');
                    const sizeBytes = fileSizeDisplay ? fileSizeDisplay.textContent.trim() : '';
                    const sizeText = (typeof FormatUtils !== 'undefined' && sizeBytes) ?
                        FormatUtils.formatBytesSimple(sizeBytes) :
                        (sizeBytes || 'Unknown size');
                        
                    filesizeEl.textContent = sizeText;
                }

                if (fileCountEl) {
                    fileCountEl.textContent = this.t('Download:zipPreview.filesCount', '{{count}} files', { count: 1 });
                }
            }

            // Wire up preview button (only for ZIP files)
            const previewBtn = document.getElementById('file-intro-preview-btn');
            if (previewBtn) {
                if (this.isPreviewableZip) {
                    previewBtn.style.display = 'flex';
                    if (!previewBtn.dataset.initialized) {
                        previewBtn.addEventListener('click', () => {
                            this.log('PreviewButton', 'Preview button clicked');
                            this.hideFileInfoHint();
                            this.openPreviewWithStateCheck();
                        });
                        previewBtn.dataset.initialized = 'true';
                        this.log('PreviewButton', 'Preview button initialized');
                    }
                } else {
                    // Hide preview button for non-ZIP files
                    previewBtn.style.display = 'none';
                }
            }

            // Position hint near info icon
            this.positionHintNearIcon(introHint, infoIcon);

            // Show hint with fade-in animation
            introHint.classList.add('active');
            this.log('FileInfo', 'File info hint shown (hover mode)');
        }

        positionHintNearIcon(hint, icon) {
            // Get icon position
            const iconRect = icon.getBoundingClientRect();

            // Position hint below and aligned to left of icon
            hint.style.position = 'fixed';
            hint.style.top = `${iconRect.bottom + 12}px`;
            hint.style.left = `${iconRect.left}px`;
        }

        hideFileInfoHint() {
            const introHint = document.getElementById('file-intro-hint');
            if (introHint && introHint.classList.contains('active')) {
                // Add fade-out animation
                introHint.classList.add('fade-out');

                // Remove hint after animation completes (300ms)
                setTimeout(() => {
                    introHint.classList.remove('active', 'fade-out');
                    this.log('FileInfo', 'File info hint hidden');
                }, 300);
            }
        }

        showInlineHint() {
            const inlineHint = document.getElementById('file-intro-inline-hint');
            const inlineText = document.getElementById('file-intro-inline-text');

            if (!inlineHint || !inlineText) {
                this.log('FileInfo', 'Inline hint elements not found');
                return;
            }

            // Get file info from page
            const fileNameEl = document.getElementById('fileName');
            const fileSizeEl = document.getElementById('fileSize');
            const fileName = fileNameEl ? fileNameEl.textContent.trim() : 'File';
            const fileSizeBytes = fileSizeEl ? fileSizeEl.textContent.trim() : '';

            // Use common utility for simple size formatting
            const simpleSize = (typeof FormatUtils !== 'undefined') ?
                FormatUtils.formatBytesSimple(fileSizeBytes) :
                fileSizeBytes;

            // Different hint text for ZIP folders vs regular files
            const folderIcon = this.isPreviewableZip ?
                ' <i class="fas fa-folder" style="color: #ffc107;"></i>' : '';
            const detailsText = this.t('Download:zipPreview.hint.inlineDetails', 'for details');
            const previewText = this.t('Download:zipPreview.hint.inlinePreview', 'to preview');
            const hintText = this.isPreviewableZip ?
                `<i class="fas fa-info-circle" style="color: #007bff; font-size: 16px;"></i> ${detailsText}, <i class="fas fa-eye" style="color: #28a745; font-size: 16px;"></i> ${previewText}` :
                `<i class="fas fa-info-circle" style="color: #007bff; font-size: 16px;"></i> ${detailsText}`;

            let hintHTML = `
                <strong>${fileName}</strong>${folderIcon} (${simpleSize}) • ${hintText}
            `;

            inlineText.innerHTML = hintHTML;

            // Make inline hint clickable for ZIP files (only initialize once)
            if (this.isPreviewableZip && !inlineHint.dataset.clickInitialized) {
                inlineHint.style.cursor = 'pointer';
                inlineHint.addEventListener('click', () => {
                    this.log('InlineHint', 'Inline hint clicked, opening preview');
                    this.hideInlineHint(); // Hide the hint first
                    this.openPreviewWithStateCheck();
                });
                inlineHint.dataset.clickInitialized = 'true';
                this.log('InlineHint', 'Click handler initialized for inline hint');
            }

            // Show hint with fade-in animation
            inlineHint.classList.remove('fade-out');
            inlineHint.classList.add('fade-in');

            this.log('FileInfo', 'Inline hint shown (fade-in)');
        }

        hideInlineHint() {
            const inlineHint = document.getElementById('file-intro-inline-hint');
            if (inlineHint && inlineHint.classList.contains('fade-in')) {
                // Add fade-out animation
                inlineHint.classList.remove('fade-in');
                inlineHint.classList.add('fade-out');

                this.log('FileInfo', 'Inline hint hidden (fade-out)');
            }
        }


        createExtractor(rawMetadata, originalSize = null) {
            if (typeof ZipPreviewExtractor === 'undefined') {
                this.log('ZipPreview', 'ZipPreviewExtractor not loaded');
                return;
            }

            // Create extractor instance with raw metadata (will be decrypted internally)
            this.extractor = new ZipPreviewExtractor({
                dbName: 'zip_gallery',
                storeName: 'files',
                fileURLTemplate: this.options.fileURLTemplate,
                rawMetadata: rawMetadata,  // Pass raw data to extractor
                rawMetadataOriginalSize: originalSize,  // Pass original size for E2EE decryption
                e2eeManager: this.options.e2eeManager,  // Reuse existing E2EE manager to avoid duplicate checks
                onFileReady: ({
                    name,
                    index,
                    blob
                }) => {
                    this.log('ZipPreview',
                        `File ready: ${name} (index ${index}, ${blob.size} bytes)`);
                    this.updateCardBadge(index, 'ready', blob);
                },
                onStatus: (msg) => {
                    this.log('ZipPreview', `Extractor status: ${msg}`);
                },
                log: this.log.bind(this)
            });

            // Expose globally for DownloadManager to feed chunks
            if (typeof window !== 'undefined') {
                window.zipPreviewExtractor = this.extractor;
                this.log('ZipPreview', 'Extractor exposed as window.zipPreviewExtractor');
            }
        }

        async updateCardBadge(index, status, blob = null) {
            // Check debug mode
            const debugMode = new URLSearchParams(window.location.search).has('debug') ||
                            localStorage.getItem('zip_preview_debug') === 'true';

            // Find card by index
            const card = document.querySelector(`.zip-preview-card[data-index="${index}"]`);
            if (!card) {
                return;
            }

            // Only update badges in debug mode
            if (debugMode) {
                const badge = card.querySelector('.zip-preview-badge');
                if (!badge) {
                    return;
                }

                badge.classList.remove('wait', 'ready', 'error');
                badge.classList.add(status);

                if (status === 'ready') {
                    badge.textContent = this.t('Download:zipPreview.badge.ready', 'Ready');
                } else if (status === 'error') {
                    badge.textContent = this.t('Download:zipPreview.badge.error', 'Error');
                } else {
                    badge.textContent = this.t('Download:zipPreview.badge.waiting', 'Waiting');
                }
            }

            // Update thumbnail regardless of debug mode
            if (status === 'ready' && blob && blob.type.startsWith('image/')) {
                const img = card.querySelector('.zip-preview-thumb');
                if (img) {
                    try {
                        // Generate client-side thumbnail from extracted blob
                        const thumbnailURL = await this.createThumbnail(blob, 420, 320);
                        img.src = thumbnailURL;
                        img.dataset.thumbnailLoaded = 'true';
                        img.dataset.pendingLoad = 'false';
                        this.log('ZipPreview', `Thumbnail updated from IndexedDB for index ${index}`);
                    } catch (e) {
                        this.log('ZipPreview', `Failed to create thumbnail for index ${index}: ${e}`);
                    }
                }
            }
        }

        async createThumbnail(blob, maxWidth, maxHeight) {
            return new Promise((resolve, reject) => {
                const img = new Image();
                const url = URL.createObjectURL(blob);

                img.onload = () => {
                    // Create canvas for thumbnail
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');

                    // Calculate thumbnail size (maintain aspect ratio)
                    let width = img.width;
                    let height = img.height;

                    if (width > height) {
                        if (width > maxWidth) {
                            height = (height * maxWidth) / width;
                            width = maxWidth;
                        }
                    } else {
                        if (height > maxHeight) {
                            width = (width * maxHeight) / height;
                            height = maxHeight;
                        }
                    }

                    canvas.width = width;
                    canvas.height = height;

                    // Draw image
                    ctx.drawImage(img, 0, 0, width, height);

                    // Revoke original blob URL
                    URL.revokeObjectURL(url);

                    // Convert canvas to blob URL
                    canvas.toBlob((thumbBlob) => {
                        if (thumbBlob) {
                            const thumbURL = URL.createObjectURL(thumbBlob);
                            resolve(thumbURL);
                        } else {
                            reject(new Error('Failed to create thumbnail blob'));
                        }
                    }, 'image/jpeg', 0.85);
                };

                img.onerror = () => {
                    URL.revokeObjectURL(url);
                    reject(new Error('Failed to load image'));
                };

                img.src = url;
            });
        }

        /**
         * Wrap writer with TeeWriter to feed chunks to extractor if file is previewable
         * @param {Object} writer - The original writer (from WriterFactory)
         * @returns {Promise<Object>} Wrapped writer or original writer
         */
        async wrapWriter(writer) {
            // Wait for initialization to complete (metadata fetch)
            await this._initPromise;

            this.log('ZipPreview',
                `wrapWriter - isPreviewableZip: ${this.isPreviewableZip}, hasExtractor: ${!!this.extractor}`
                );

            if (!this.isPreviewableZip || !this.extractor) {
                this.log('ZipPreview', `Not wrapping writer (not a previewable ZIP)`);
                return writer;
            }

            this.log('ZipPreview', '✓ Wrapping writer with TeeWriter to feed extractor');
            const realWriter = writer;
            const logFn = this.log.bind(this);
            const extractor = this.extractor; // Capture extractor reference
            let chunkCount = 0;

            return {
                async write(chunk) {
                    // Convert to Uint8Array if needed
                    const u8 = (chunk instanceof Uint8Array) ? chunk : new Uint8Array(chunk);

                    // Feed to ZIP extractor (for real-time extraction)
                    if (extractor) {
                        try {
                            extractor.feed(u8);
                            chunkCount++;
                            // Log every 100th chunk
                            if (chunkCount % 100 === 0) {
                                logFn('TeeWriter',
                                    `Fed chunk #${chunkCount} to extractor (${u8.byteLength} bytes)`);
                            }
                        } catch (e) {
                            logFn('TeeWriter', `Extractor feed error: ${e.message || e}`);
                            console.error('[TeeWriter] Extractor feed error:', e);
                        }
                    } else {
                        if (chunkCount === 0) {
                            logFn('TeeWriter', 'WARNING: No extractor available to feed chunks');
                        }
                    }

                    // Write to actual destination (file or blob)
                    return realWriter.write(chunk);
                },
                close() {
                    logFn('TeeWriter', `Closing writer, total chunks fed: ${chunkCount}`);
                    return realWriter.close ? realWriter.close() : Promise.resolve();
                },
                abort(e) {
                    return realWriter.abort ? realWriter.abort(e) : Promise.resolve();
                }
            };
        }
    }

    // ========================================================================
    // Export PreviewUI class
    // ========================================================================

    // Expose PreviewUI class globally
    if (typeof window !== 'undefined') {
        window.PreviewUI = PreviewUI;
    }

})();
