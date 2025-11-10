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

        function openExternally(targetUrl, options) {
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

            if (ENV.isIOS) {
                try {
                    const isHttps = url.indexOf('https://') === 0;
                    const isHttp = url.indexOf('http://') === 0;
                    
                    if (isHttps) {
                        win.location.href = 'googlechromes://' + url.slice(8);
                    } else if (isHttp) {
                        win.location.href = 'googlechrome://' + url.slice(7);
                    }
                    
                    setTimeout(fallbackOpen, 500);
                    return true;
                } catch (e) {
                    return fallbackOpen();
                }
            }

            return fallbackOpen();
        }

        function getRecommendedBrowser() {
            if (ENV.isIOS) 
                return iagT('inappguard.browsers.safari', 'Safari');
            if (ENV.isAndroid) 
                return iagT('inappguard.browsers.chrome', 'Chrome');
            return iagT('inappguard.browsers.yourBrowser', 'your browser');
        }

        function getRestrictedMessage(action) {
            const actionText = action || iagT('inappguard.actions.download', 'download');
            const browser = getRecommendedBrowser();
            
            if (ENV.isIOS) {
                return iagT('inappguard.messages.iosRestricted', 'To {{action}} this file, please open this link in {{browser}}. Tap the share button and select "Open in {{browser}}".', { action: actionText, browser: browser });
            }
            if (ENV.isAndroid) {
                return iagT('inappguard.messages.androidRestricted', 'To {{action}} this file, please open this link in {{browser}}. Tap the menu button and select "Open in browser".', { action: actionText, browser: browser });
            }
            return iagT('inappguard.messages.generalRestricted', 'To {{action}} this file, please open this link in {{browser}}.', { action: actionText, browser: browser });
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
                
                if (warningElement && warningText && openBrowserBtn) {
                    // Update warning text with specific message
                    warningText.textContent = getRestrictedMessage();
                    
                    // Set up "Open in Browser" button
                    openBrowserBtn.addEventListener('click', function(e) {
                        e.preventDefault();
                        logger('[FastFileLink]', 'User clicked "Open in Browser"');
                        openExternally();
                    });
                    
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
            getRecommendedBrowser: getRecommendedBrowser,
            getRestrictedMessage: getRestrictedMessage,
            initInAppGuardUI: initInAppGuardUI
        };
    })();

    // Export to global scope
    global.InAppGuard = InAppGuard;

})(typeof window !== 'undefined' ? window : this);