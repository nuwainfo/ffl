/*!
 * FastFileLink - Common i18n Initialization
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Shared i18next setup providing internationalization functionality
 *
 * See LICENSE file in the project root for full license information.
 */

/**
 * Initialize i18n system with configurable options
 * @param {Object} config - Configuration object
 * @param {string} config.localesPath - Path to locales directory (default: '/locales')
 * @param {string[]} config.supportedLanguages - Array of supported language codes (default: ['en', 'zh-hant'])
 * @param {boolean} config.debug - Enable debug mode (default: true)
 * @param {Function} config.log - Logging function (default: global log or no-op)
 * 
 * @example
 * // Default configuration
 * initializeI18n();
 * 
 * // Custom locales path
 * initializeI18n({ localesPath: '/static/locales' });
 * 
 * // Custom languages and path
 * initializeI18n({ 
 *   localesPath: '/translations',
 *   supportedLanguages: ['en', 'es', 'fr'],
 *   debug: false,
 *   log: console.log
 * });
 */
function initializeI18n(config = {}) {
    // Configuration with defaults
    const localesPath = config.localesPath || '/locales';
    const supportedLanguages = config.supportedLanguages || ['en', 'zh-hant'];
    const debug = config.debug !== undefined ? config.debug : true;
    const version = config.version || '1.0.0';
    const log = config.log || (typeof window !== 'undefined' && typeof window.log === 'function' ? window.log : function() {});
    
    // Initialize i18next with http-backend and language detection
    i18next
        .use(i18nextHttpBackend)
        .use(i18nextBrowserLanguageDetector)
        .init({
            fallbackLng: 'en',
            supportedLngs: [...supportedLanguages, 'zh-TW', 'zh-tw', 'zh-Hant', 'zh'],
            debug: debug,
            load: 'languageOnly',
            checkForDefaultNamespace: false,
            
            // Backend configuration
            backend: {
                loadPath: function(languages, namespaces) {
                    const [language] = languages;
                    const [namespace] = namespaces;
                    
                    // Map Chinese language variants to zh-hant file
                    if (language === 'zh-TW' || language === 'zh-tw' || 
                        language === 'zh-Hant' || language === 'zh-hant' || 
                        language === 'zh') {
                        return `${localesPath}/zh-hant/${namespace}.json?v=${version}`;
                    }
                    
                    return `${localesPath}/${language}/${namespace}.json?v=${version}`;
                }
            },
            
            // Language detection configuration
            detection: {
                order: ['querystring', 'localStorage', 'navigator'],
                caches: ['localStorage'],
                lookupQuerystring: 'language',
                convertDetectedLanguage: function(lng) {
                    log('FFLI18n', 'Detected language:', lng);
                    // Map various Chinese language codes to zh-hant
                    if (lng === 'zh-TW' || lng === 'zh-tw' || lng === 'zh-Hant' || lng === 'zh-hant' || lng === 'zh') {
                        log('FFLI18n', 'Using Chinese variant, returning zh-hant');
                        return 'zh-hant';
                    }
                    return lng;
                },
                checkWhitelist: false
            }
        }, function(err, t) {
            if (err) {
                log('FFLI18n', 'i18next initialization failed:', err);
                window.dispatchEvent(new CustomEvent('i18nReady'));
                return;
            }
            
            log('FFLI18n', 'i18next initialized with http-backend');
            log('FFLI18n', 'Final language:', i18next.language);
            log('FFLI18n', 'Resolved language:', i18next.resolvedLanguage);
            log('FFLI18n', 'Detected language from detector:', i18next.services?.languageDetector?.detectedLanguage);
            log('FFLI18n', 'Browser language:', navigator.language);
            log('FFLI18n', 'LocalStorage language:', localStorage.getItem('i18nextLng'));
            
            // Check if we should switch to Chinese based on browser preference
            const browserLang = navigator.language || navigator.languages?.[0] || 'en';
            const currentLang = i18next.language;
            
            // Initialize jquery-i18next first
            jqueryI18next.init(i18next, $);
            
            if ((browserLang.includes('zh') || browserLang.includes('TW') || browserLang.includes('Hant')) && 
                currentLang.startsWith('en')) {
                log('FFLI18n', 'Browser prefers Chinese but got English, switching to zh-hant...');
                i18next.changeLanguage('zh-hant', function(switchErr) {
                    if (!switchErr) {
                        log('FFLI18n', 'Successfully switched to Chinese:', i18next.language);
                        updatePageTranslations(log);
                    } else {
                        log('FFLI18n', 'Failed to switch to Chinese:', switchErr);
                    }
                });
            } else {
                log('FFLI18n', 'Test translation:', i18next.t('nav.home', 'Home'));
                // Update page content with translations
                updatePageTranslations(log);
            }
            
            // Trigger custom event for application-specific initialization
            window.dispatchEvent(new CustomEvent('i18nReady'));
        });
}

// Safe t function - handles case when i18next is not ready yet
function t(key, defaultValue, options = {}) {
    // Check if i18next is initialized and ready
    if (typeof i18next === 'undefined' || !i18next.isInitialized || !i18next.hasLoadedNamespace('translation')) {
        return defaultValue || key;
    }
    return i18next.t(key, { ...options, defaultValue });
}

// Function to update all page translations using jquery-i18next only
function updatePageTranslations(log) {
    // Use global log or fallback to no-op
    const logger = log || (typeof window !== 'undefined' && typeof window.log === 'function' ? window.log : function() {});
    logger('FFLI18n', 'Updating page translations for language:', i18next.language);
    
    // Use jquery-i18next to automatically translate all elements with data-i18n
    $('body').localize();
}

// Function to change language
function changeLanguage(lang, log) {
    // Use global log or fallback to no-op
    const logger = log || (typeof window !== 'undefined' && typeof window.log === 'function' ? window.log : function() {});
    
    i18next.changeLanguage(lang, function(err, t) {
        if (err) {
            logger('FFLI18n', 'Language change failed:', err);
            return;
        }
        updatePageTranslations(logger);
        logger('FFLI18n', 'Language changed to:', lang);
    });
}

// Make functions globally available
window.t = t;
window.updatePageTranslations = updatePageTranslations;
window.changeLanguage = changeLanguage;
window.initializeI18n = initializeI18n;