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

window.currentLanguage = null;
function applyFontByLanguage(lng) {
  var $html = $("html");

  $html.removeClass("lang-zh-hans lang-zh-hant lang-en");

  if (lng === "zh-hans" || lng === "zh-Hans") {
    $html.addClass("lang-zh-hans");
  } else if (lng === "zh-hant") {
    $html.addClass("lang-zh-hant");
  } else {
    $html.addClass("lang-en");
  }
}

async function fetchSettingLanguage() {
  try {
    const res = await fetch("/language/");
    if (res.status === 404) {
      return null;
    }
    const data = await res.json();
    return data.language;
  } catch (err) {
    return null;
  }
}

async function initializeI18n(config = {}) {
  // Configuration with defaults
  let _fetchSettingLanguage =
    config.getCurrentLanguageFunc || fetchSettingLanguage;
  let currentLanguage = null;
  if (_fetchSettingLanguage) {
    currentLanguage = await _fetchSettingLanguage();
  }

  const localesPath = config.localesPath || "/locales";
  const supportedLanguages = config.supportedLanguages || [
    "en",
    "zh-hant",
    "zh-hans",
  ];
  const chineseMap = {
    // 繁體
    "zh-TW": "zh-hant",
    "zh-tw": "zh-hant",
    "zh-Hant": "zh-hant",
    "zh-hant": "zh-hant",
    zh: "zh-hant",
    "zh-HK": "zh-hant",
    "zh-hk": "zh-hant",

    // 簡體
    "zh-CN": "zh-hans",
    "zh-cn": "zh-hans",
    "zh-Hans": "zh-hans",
    "zh-hans": "zh-hans",
    "zh-SG": "zh-hans",
    "zh-sg": "zh-hans",
  };
  const debug = config.debug !== undefined ? config.debug : true;
  const version = config.version || "1.0.0";
  const log =
    config.log ||
    (typeof window !== "undefined" && typeof window.log === "function"
      ? window.log
      : function () {});

  // Common and user-defined namespaces
  const commonNamespaces = ["Nav", "Footer", "Modal", "Common"];
  const userNamespaces = Array.isArray(config.ns)
    ? config.ns
    : config.ns
    ? [config.ns]
    : [];
  const namespaces = [...new Set([...commonNamespaces, ...userNamespaces])];

  // Initialize i18next with http-backend and language detection
  i18next
    .use(i18nextHttpBackend)
    .use(i18nextBrowserLanguageDetector)
    .init(
      {
        fallbackLng: "en",
        supportedLngs: [
          "en",
          "zh-hant",
          "zh-hans",
          "zh",
          "zh-TW",
          "zh-HK",
          "zh-CN",
          "zh-SG",
          "zh-Hant",
          "zh-Hans",
        ],
        debug: debug,
        load: "currentOnly",
        checkForDefaultNamespace: false,
        ns: namespaces,

        // Backend configuration
        backend: {
          loadPath: function (languages, namespaces) {
            const [language] = languages;
            const [namespace] = namespaces;

            const mappedLang = chineseMap[language];

            if (mappedLang) {
              return `${localesPath}/${mappedLang}/${namespace}.json?v=${version}`;
            }

            return `${localesPath}/${language}/${namespace}.json?v=${version}`;
          },
        },

        // Language detection configuration
        detection: {
          order: ["querystring", "localStorage", "navigator"],
          caches: ["localStorage"],
          lookupQuerystring: "language",
          convertDetectedLanguage: function (lng) {
            if (
              currentLanguage &&
              currentLanguage !== lng &&
              currentLanguage !== null
            ) {
              return currentLanguage;
            }

            if (lng === "zh") {
              return "zh-hant";
            }

            if (chineseMap[lng]) {
              return chineseMap[lng];
            }

            log("FFLI18n", "Detected language:", lng);
            return lng;
          },
          checkWhitelist: false,
        },
      },
      function (err, t) {
        if (err) {
          log("FFLI18n", "i18next initialization failed:", err);
          window.dispatchEvent(new CustomEvent("i18nReady"));
          return;
        }

        log("FFLI18n", "i18next initialized with http-backend");
        log("FFLI18n", "Final language:", i18next.language);
        log("FFLI18n", "Resolved language:", i18next.resolvedLanguage);
        log(
          "FFLI18n",
          "Detected language from detector:",
          i18next.services?.languageDetector?.detectedLanguage
        );
        log("FFLI18n", "Browser language:", navigator.language);
        log(
          "FFLI18n",
          "LocalStorage language:",
          localStorage.getItem("i18nextLng")
        );

        // Check if we should switch to Chinese based on browser preference
        const browserLang =
          navigator.language || navigator.languages?.[0] || "en";
        const currentLang = i18next.language;

        let preferredChinese = null;

        if (chineseMap[browserLang]) {
          preferredChinese = chineseMap[browserLang];
        }

        // Initialize jquery-i18next first
        jqueryI18next.init(i18next, $);
        if (currentLang) {
          window.currentLanguage = currentLang;
          applyFontByLanguage(currentLang);
          i18next.changeLanguage(currentLang, function (switchErr) {
            if (!switchErr) {
              updatePageTranslations(log);
            }
          });
        }

        // Trigger custom event for application-specific initialization
        window.dispatchEvent(new CustomEvent("i18nReady"));
      }
    );
}

// Safe t function - handles case when i18next is not ready yet
function t(key, defaultValue, options = {}) {
  // Check if i18next is initialized and ready
  if (typeof i18next === "undefined" || !i18next.isInitialized) {
    return defaultValue || key;
  }
  return i18next.t(key, { ...options, defaultValue });
}

// Function to update all page translations using jquery-i18next only
function updatePageTranslations(log) {
  // Use global log or fallback to no-op
  const logger =
    log ||
    (typeof window !== "undefined" && typeof window.log === "function"
      ? window.log
      : function () {});
  logger(
    "FFLI18n",
    "Updating page translations for language:",
    i18next.language
  );

  // Use jquery-i18next to automatically translate all elements with data-i18n
  $("body").localize();
}

// Function to change language
function changeLanguage(lang, log) {
  // Use global log or fallback to no-op
  const logger =
    log ||
    (typeof window !== "undefined" && typeof window.log === "function"
      ? window.log
      : function () {});

  i18next.changeLanguage(lang, function (err, t) {
    window.currentLanguage = lang;
    applyFontByLanguage(lang);
    if (err) {
      logger("FFLI18n", "Language change failed:", err);
      return;
    }
    updatePageTranslations(logger);
    logger("FFLI18n", "Language changed to:", lang);
  });

  $.post("/i18n/setlang", {
    language: lang,
    next: window.location.href,
  })
    .done(function () {
      logger("FFLI18n", "Django session language updated to: " + lang);
    })
    .fail(function (err) {
      logger("FFLI18n", "Failed to update Django session language:", err);
    });
}

// Make functions globally available
window.t = t;
window.updatePageTranslations = updatePageTranslations;
window.changeLanguage = changeLanguage;
window.initializeI18n = initializeI18n;
