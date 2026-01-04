/*!
 * FastFileLink - InApp Guard v1.1.0
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Universal In-App Browser Detection
 *
 * See LICENSE file in the project root for full license information.
 */
(function(global) {
    'use strict';

    // Check if log function is available, otherwise use empty function
    const log = (typeof global.log === 'function') ? global.log : function() {};

    // Independent translation function - works with or without global t function
    const iagT = (typeof global.t === 'function') ? global.t : function(key, defaultValue, options = {}) {
        // Dummy function that supports basic interpolation
        if (typeof defaultValue === 'string') {
            return defaultValue.replace(/\{\{(\w+)\}\}/g, (match, key) => {
                return options[key] || match;
            });
        }
        return defaultValue || key;
    };

    const InAppGuard = (function () {
        // Zero-latency environment detection
        const nav = typeof navigator !== 'undefined' ? navigator : {};
        const ua = (nav.userAgent || '');
        const uad = nav.userAgentData || null;
        const doc = typeof document !== 'undefined' ? document : { referrer: '' };
        const win = typeof window !== 'undefined' ? window : {};

        log("InAppGuard", `Initializing with UA: ${ua}`);

        const isAndroid = ua.indexOf('Android') !== -1;
        const isIOS = (ua.indexOf('iPhone') !== -1 || ua.indexOf('iPad') !== -1 || ua.indexOf('iPod') !== -1);

        // Android WebView detection
        let hasAndroidWebViewBrand = false;
        try {
            if (uad && uad.brands) {
                for (let i = 0; i < uad.brands.length; i++) {
                    if (uad.brands[i] && uad.brands[i].brand === 'Android WebView') {
                        hasAndroidWebViewBrand = true;
                        break;
                    }
                }
            }
        } catch (e) {}

        const hasAndroidWVToken = (ua.indexOf('; wv)') !== -1) ||
                                  (ua.indexOf('Android') !== -1 && ua.indexOf('Version/') !== -1 && ua.indexOf('Chrome/') === -1);

        // iOS browser detection
        const iosKnownBrowsers = ['Safari/', 'CriOS', 'FxiOS', 'EdgiOS', 'OPiOS', 'DuckDuckGo'];
        const hasIOSKnownBrowserToken = iosKnownBrowsers.some(token => ua.indexOf(token) !== -1);

        const isLikelyIOSWebView = isIOS && !hasIOSKnownBrowserToken;

        // Taiwan-focused in-app browser signatures
        const INAPP_SIGS = [
            'FBAN', 'FBAV', 'FB_IAB', 'Instagram', 'WhatsApp',
            'Line/', 'LINE/', 'MicroMessenger', 'KAKAOTALK', 'KakaoTalk',
            'Twitter', 'TikTok', 'Snapchat', 'Pinterest', 'LinkedInApp',
            'Telegram', 'Viber', 'SkypeUriPreview', 'GSA/', 'GoogleApp',
            'Outlook-iOS', 'Gmail', 'YahooMobile', 'UCBrowser',
            'SamsungBrowser', 'MiuiBrowser'
        ];

        const hasInAppToken = (function () {
            for (let i = 0; i < INAPP_SIGS.length; i++) {
                if (ua.indexOf(INAPP_SIGS[i]) !== -1) {
                    log("InAppGuard", `Found in-app signature: ${INAPP_SIGS[i]}`);
                    return true;
                }
            }
            return false;
        })();

        const isFromAndroidAppReferrer = !!(doc.referrer && doc.referrer.indexOf('android-app://') === 0);
        const isFromIOSAppReferrer = !!(doc.referrer && doc.referrer.indexOf('ios-app://') === 0);

        const isStandaloneMode = (nav.standalone === true) || 
                                 (win.matchMedia && win.matchMedia('(display-mode: standalone)').matches);

        // Download capability detection
        const hasFileSystemAccessAPI = typeof win.showSaveFilePicker === 'function';
        const hasAnchorDownload = typeof HTMLAnchorElement !== 'undefined' && 'download' in HTMLAnchorElement.prototype;
        const canCreateBlobUrl = !!(win.URL && win.URL.createObjectURL);

        function detectIOSWebViewByAPI() {
            if (!isIOS) 
                return false;
            
            const hasSafariWebkitAPIs = !!(win.webkit && win.webkit.messageHandlers);
            const hasDeviceAPIs = typeof win.DeviceMotionEvent !== 'undefined' && 
                                  typeof win.DeviceOrientationEvent !== 'undefined';
            return !hasSafariWebkitAPIs && !hasDeviceAPIs;
        }

        function isNotStandaloneBrowser() {
            if (isStandaloneMode) 
                return false;
            
            if (hasAndroidWebViewBrand) 
                return true;
            if (hasAndroidWVToken) 
                return true;
            if (isLikelyIOSWebView) 
                return true;
            if (detectIOSWebViewByAPI()) 
                return true;
            if (hasInAppToken) 
                return true;
            if (isFromAndroidAppReferrer || isFromIOSAppReferrer) 
                return true;
            
            return false;
        }

        function isDownloadLikelyBlocked() {
            const notStandalone = isNotStandaloneBrowser();
            
            log("InAppGuard", `Download detection - notStandalone: ${notStandalone}, hasFileSystemAccessAPI: ${hasFileSystemAccessAPI}, hasInAppToken: ${hasInAppToken}`);
            
            // If we're in a known problematic WebView/in-app environment, block regardless of API support
            if (notStandalone) {
                // iOS WebViews are notoriously restrictive
                if (isIOS) {
                    log("InAppGuard", "Download blocked: iOS WebView");
                    return true;
                }
                
                // Known problematic in-app browsers (like LINE, Facebook, etc.)
                if (hasInAppToken) {
                    log("InAppGuard", "Download blocked: Known in-app browser detected");
                    return true;
                }
                
                // Android WebViews (if not caught by hasInAppToken)
                if (hasAndroidWebViewBrand || hasAndroidWVToken) {
                    log("InAppGuard", "Download blocked: Android WebView detected");
                    return true;
                }
            }
            
            // Modern browsers with File System Access API can download (only if not in problematic WebView)
            if (hasFileSystemAccessAPI) {
                log("InAppGuard", "Download allowed: has File System Access API in standalone browser");
                return false;
            }
            
            // Standalone browsers with basic download capabilities should work
            if (!notStandalone && hasAnchorDownload && canCreateBlobUrl) {
                log("InAppGuard", "Download allowed: standalone browser with basic capabilities");
                return false;
            }
            
            log("InAppGuard", "Download blocked: no reliable download method detected");
            return true;
        }

        const ENV = (function () {
            const notStandalone = isNotStandaloneBrowser();
            const downloadBlocked = isDownloadLikelyBlocked();
            
            const env = {
                userAgent: ua,
                isAndroid: isAndroid,
                isIOS: isIOS,
                hasAndroidWebViewBrand: hasAndroidWebViewBrand,
                hasAndroidWVToken: hasAndroidWVToken,
                isLikelyIOSWebView: isLikelyIOSWebView,
                hasInAppToken: hasInAppToken,
                isFromAndroidAppReferrer: isFromAndroidAppReferrer,
                isFromIOSAppReferrer: isFromIOSAppReferrer,
                isStandaloneMode: isStandaloneMode,
                hasFileSystemAccessAPI: hasFileSystemAccessAPI,
                hasAnchorDownload: hasAnchorDownload,
                canCreateBlobUrl: canCreateBlobUrl,
                isNotStandaloneBrowser: notStandalone,
                isDownloadRestricted: downloadBlocked
            };
            
            log("InAppGuard", "Environment detected", env);
            return Object.freeze(env);
        })();

        function getEnv() {
            return ENV;
        }

        function isDownloadRestricted() {
            return ENV.isDownloadRestricted;
        }

        function isRestricted() {
            return ENV.isNotStandaloneBrowser;
        }

        function isInAppBrowser() {
            return ENV.isNotStandaloneBrowser;
        }

        async function openExternally(targetUrl, options) {
            const url = targetUrl || (win.location ? String(win.location.href) : '');
            const opts = options || {};
            const fallbackUrl = opts.fallbackUrl || url;

            log("InAppGuard", `Attempting to open externally: ${url}`);

            // Helper function to handle fallback window.open
            const fallbackOpen = () => {
                if (win.open) {
                    win.open(url, '_blank', 'noopener,noreferrer');
                    return true;
                }
                return false;
            };

            // iOS: Use Web Share API (highest success rate in in-app browsers)
            if (ENV.isIOS) {
                // Try Web Share first (many in-app browsers allow this)
                /* // Actually, this confusing user because Safari is not in share list.
                if (nav.share) {
                    try {
                        log("InAppGuard", "Attempting iOS Web Share");
                        await nav.share({ url: url });
                        return true;
                    } catch (e) {
                        // User cancelled or share failed
                        log("InAppGuard", "Web Share cancelled or failed", e);
                    }
                }

                // Fallback: Try clipboard copy
                if (nav.clipboard && nav.clipboard.writeText) {
                    try {
                        await nav.clipboard.writeText(url);
                        log("InAppGuard", "URL copied to clipboard");
                        if (win.alert) {
                            win.alert(iagT('Download:inappguard.clipboard.copied', 'Link copied! Please paste it in Safari to download.'));
                        }
                        return true;
                    } catch (e) {
                        log("InAppGuard", "Clipboard copy failed", e);
                    }
                }
                */

                // Last resort: Try Safari URL scheme (may not work in many apps)
                try {
                    const isHttps = url.indexOf('https://') === 0;
                    const isHttp = url.indexOf('http://') === 0;

                    if (isHttps || isHttp) {
                        // Try x-safari-https (more reliable than Chrome on iOS)
                        const safariUrl = isHttps
                            ? 'x-safari-https://' + url.slice(8)
                            : 'x-safari-http://' + url.slice(7);

                        log("InAppGuard", `Attempting Safari URL scheme: ${safariUrl}`);
                        win.location.href = safariUrl;

                        // Fallback to window.open after delay if scheme fails
                        setTimeout(fallbackOpen, 500);
                        return true;
                    }
                } catch (e) {
                    log("InAppGuard", "Safari URL scheme failed", e);
                    return fallbackOpen();
                }

                // Final fallback
                return fallbackOpen();
            }

            // Android: Use intent URLs (usually more reliable)
            if (ENV.isAndroid) {
                try {
                    const urlObj = new URL(url, win.location ? win.location.href : undefined);
                    const scheme = urlObj.protocol.replace(':', '');

                    const intentUrl = 'intent://' + urlObj.host + urlObj.pathname + urlObj.search + urlObj.hash +
                      '#Intent;scheme=' + scheme +
                      ';package=' + (opts.androidPackage || 'com.android.chrome') +
                      ';S.browser_fallback_url=' + encodeURIComponent(fallbackUrl) +
                      ';end';

                    log("InAppGuard", `Using Android intent: ${intentUrl}`);
                    win.location.href = intentUrl;
                    return true;
                } catch (e) {
                    log("InAppGuard", "Android intent failed, using window.open", e);
                    return fallbackOpen();
                }
            }

            return fallbackOpen();
        }

        function getRecommendedBrowser() {
            if (ENV.isIOS) 
                return iagT('Download:inappguard.browsers.safari', 'Safari');
            if (ENV.isAndroid) 
                return iagT('Download:inappguard.browsers.chrome', 'Chrome');
            return iagT('Download:inappguard.browsers.yourBrowser', 'your browser');
        }

        function getRestrictedMessage(action) {
            const actionText = action || iagT('Download:inappguard.actions.download', 'download');
            const browser = getRecommendedBrowser();

            if (ENV.isIOS) {
                // iOS: Guide users with specific steps since automatic opening often fails
                return iagT('Download:inappguard.messages.iosRestricted',
                    'Downloads are restricted in this app. Please: (1) Tap the button below to share or copy the link, (2) Open {{browser}}, (3) Paste and open the link to {{action}}.',
                    { action: actionText, browser: browser });
            }
            if (ENV.isAndroid) {
                // Android: Intent URLs usually work better than iOS
                return iagT('Download:inappguard.messages.androidRestricted',
                    'To {{action}} this file, tap the button below to open in {{browser}}. If that doesn\'t work, try the menu (⋮) and select "Open in browser".',
                    { action: actionText, browser: browser });
            }
            return iagT('Download:inappguard.messages.generalRestricted',
                'To {{action}} this file, please open this link in {{browser}}.',
                { action: actionText, browser: browser });
        }

        // Copy link to clipboard with user feedback
        async function copyLinkToClipboard(url) {
            const targetUrl = url || (win.location ? String(win.location.href) : '');

            if (nav.clipboard && nav.clipboard.writeText) {
                try {
                    await nav.clipboard.writeText(targetUrl);
                    log("InAppGuard", "Link copied to clipboard");
                    return true;
                } catch (e) {
                    log("InAppGuard", "Clipboard copy failed", e);
                    return false;
                }
            }

            // Fallback for older browsers
            try {
                const textarea = doc.createElement('textarea');
                textarea.value = targetUrl;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                doc.body.appendChild(textarea);
                textarea.select();
                const success = doc.execCommand('copy');
                doc.body.removeChild(textarea);
                return success;
            } catch (e) {
                log("InAppGuard", "Fallback clipboard copy failed", e);
                return false;
            }
        }

        // Initialize InApp Guard and handle UI warnings
        function initInAppGuardUI(options = {}) {
            const logger = options.log || log; // Use existing log or provided log
            const skipVariableName = options.skipVariableName || 'skipDownloadDueToRestriction';

            logger('[FastFileLink]', 'InApp Guard initialized');
            logger('[FastFileLink]', 'Environment:', {
                isDownloadRestricted: isDownloadRestricted(),
                isInAppBrowser: isInAppBrowser(),
                recommendedBrowser: getRecommendedBrowser()
            });

            let shouldSkipDownload = false;

            // Show warning if download is likely to be restricted
            if (isDownloadRestricted()) {
                const warningElement = document.getElementById('inapp-warning');
                const warningText = document.getElementById('warning-text');
                const openBrowserBtn = document.getElementById('open-browser-btn');
                const copyLinkBtn = document.getElementById('copy-link-btn');

                if (warningElement && warningText && openBrowserBtn) {
                    // Update warning text with specific message
                    warningText.textContent = getRestrictedMessage();

                    // Set up "Open in Browser" button - uses Web Share on iOS, intent on Android
                    openBrowserBtn.addEventListener('click', function(e) {
                        e.preventDefault();
                        logger('[FastFileLink]', 'User clicked "Open in Browser"');
                        openExternally();
                    });

                    // Set up "Copy Link" button if it exists (recommended for iOS)
                    if (copyLinkBtn) {
                        copyLinkBtn.addEventListener('click', async function(e) {
                            e.preventDefault();
                            logger('[FastFileLink]', 'User clicked "Copy Link"');
                            const success = await copyLinkToClipboard();
                            if (success && win.alert) {
                                win.alert(iagT('Download:inappguard.clipboard.copied',
                                    'Link copied! Please paste it in Safari to download.'));
                            } else if (!success && win.alert) {
                                win.alert(iagT('Download:inappguard.clipboard.failed',
                                    'Could not copy link. Please manually copy the URL from your address bar.'));
                            }
                        });
                    }

                    // Show the warning
                    warningElement.style.display = 'block';

                    // Re-localize the warning elements to ensure proper translation
                    if (typeof $ !== 'undefined' && $.fn.localize) {
                        $(warningElement).localize();
                    }

                    logger('[FastFileLink]', 'Download restriction warning displayed and localized');
                }

                // Set flag to skip download
                shouldSkipDownload = true;
                logger('[FastFileLink]', 'Will skip download due to restrictions');

                // Set global variable if requested
                if (skipVariableName && typeof window !== 'undefined') {
                    window[skipVariableName] = true;
                }
            }

            return shouldSkipDownload;
        }

        return {
            getEnv: getEnv,
            isDownloadRestricted: isDownloadRestricted,
            isRestricted: isRestricted,
            isInAppBrowser: isInAppBrowser,
            openExternally: openExternally,
            copyLinkToClipboard: copyLinkToClipboard,
            getRecommendedBrowser: getRecommendedBrowser,
            getRestrictedMessage: getRestrictedMessage,
            initInAppGuardUI: initInAppGuardUI
        };
    })();

    // Export to global scope
    global.InAppGuard = InAppGuard;

})(typeof window !== 'undefined' ? window : this);