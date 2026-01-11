#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gettext
import json
import locale
import os

from bases.Kernel import PUBLIC_VERSION, Singleton, StorageLocator, getLogger

try:
    from babel import Locale, UnknownLocaleError
    BABEL_AVAILABLE = True
except ImportError:
    BABEL_AVAILABLE = False

logger = getLogger(__name__, version=PUBLIC_VERSION)


class BabelI18nManager(Singleton):
    """
    Internationalization manager using gettext for Python backend translations.
    Manages language preferences, translation loading, and provides translation functions.

    Configuration:
        - Config file: ~/.fastfilelink/i18n.json
        - Auto-detects OS language if no preference saved
        - Falls back to English for missing translations
    """

    CONFIG_FILENAME = 'i18n.json'

    DOMAIN_CORE = 'messages'

    DEFAULT_LANGUAGE = 'en'

    SUPPORTED_LANGUAGES = ['en', 'zh_Hant', 'zh_Hans']

    def initialize(self):
        """Initialize I18nManager singleton"""
        self.storageLocator = StorageLocator.getInstance()
        self.configPath = self.storageLocator.findConfig(self.CONFIG_FILENAME)

        # Find locales directory using StorageLocator with SOURCE_BASE preference
        self.localeDir = self.storageLocator.findStorage('locales', StorageLocator.Location.SOURCE_BASE)

        self.currentLanguage = None
        self.translationCache = {} # Cache compiled translation objects per domain: {domain: {language: translation}}

        # Debug output
        logger.debug(f"Config path: {self.configPath}")
        logger.debug(f"Locale dir: {self.localeDir}")
        logger.debug(f"Config exists: {os.path.exists(self.configPath)}")

        # Load or detect language
        self._loadOrDetectLanguage()

        logger.debug(f"Final language: {self.currentLanguage}")
        logger.info(f"I18n initialized with language: {self.currentLanguage}, locale dir: {self.localeDir}")

    def _loadOrDetectLanguage(self):
        """Load saved language preference or detect from OS"""
        config = self._loadConfig(useDefault=False)

        if config and 'language' in config:
            # Use saved preference
            self.currentLanguage = config['language']
            logger.debug(f"Loaded language preference from config: {self.currentLanguage}")
        elif not config or (config and config.get('auto_detect', True)): # not config means no config file.
            # Auto-detect from OS
            self.currentLanguage = self._detectOSLanguage()
            logger.debug(f"Auto-detected OS language: {self.currentLanguage}")
        else:
            # Default to English
            self.currentLanguage = self.DEFAULT_LANGUAGE
            logger.debug(f"Using default language: {self.currentLanguage}")

        # Ensure language is supported
        if self.currentLanguage not in self.SUPPORTED_LANGUAGES:
            logger.warning(f"Unsupported language '{self.currentLanguage}', falling back to {self.DEFAULT_LANGUAGE}")
            self.currentLanguage = self.DEFAULT_LANGUAGE

    def _mapBabelLocaleToLanguageCode(self, babelLocale):
        """
        Map babel Locale object to our language code format.

        Args:
            babelLocale: babel.Locale object

        Returns:
            Language code string (e.g., 'en', 'zh_Hant', 'zh_Hans')
        """
        # Handle Chinese variants based on script or territory
        if babelLocale.language == 'zh':
            # Traditional Chinese: script=Hant or territories TW, HK, MO
            if babelLocale.script == 'Hant' or babelLocale.territory in ('TW', 'HK', 'MO'):
                return 'zh_Hant'
            # Simplified Chinese: script=Hans or territories CN, SG
            elif babelLocale.script == 'Hans' or babelLocale.territory in ('CN', 'SG'):
                return 'zh_Hans'
            # Default to Simplified if no script/territory info
            return 'zh_Hans'

        # For other languages, return the language code
        return babelLocale.language

    def _detectOSLanguage(self):
        """Detect OS default language using locale and babel normalization"""
        try:
            osLocale = locale.getdefaultlocale()[0]
            if osLocale:
                # Use babel to parse and normalize locale
                babelLocale = Locale.parse(osLocale, sep='_')

                # Map to our language code format
                langCode = self._mapBabelLocaleToLanguageCode(babelLocale)

                # Return if supported, otherwise default
                if langCode in self.SUPPORTED_LANGUAGES:
                    return langCode

        except (UnknownLocaleError, ValueError) as e:
            logger.debug(f"Could not parse locale {osLocale}: {e}")
        except Exception as e:
            logger.warning(f"Failed to detect OS language: {e}")

        return self.DEFAULT_LANGUAGE

    def _loadConfig(self, useDefault=True):
        """Load i18n configuration from JSON file"""
        if not os.path.exists(self.configPath):
            if useDefault:
                logger.debug(f"Config file not found, using defaults")
                return self._getDefaultConfig()
            else:
                return None

        try:
            with open(self.configPath, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.debug(f"Loaded config: {config}")
                return config
        except Exception as e:
            if useDefault:
                logger.warning(f"Failed to load i18n config: {e}, using defaults")
                return self._getDefaultConfig()
            else:
                return None

    def _saveConfig(self, config):
        """Save i18n configuration to JSON file"""
        try:
            # Ensure storage directory exists
            self.storageLocator.ensureStorageDir()

            with open(self.configPath, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved i18n config to {self.configPath}")
        except Exception as e:
            logger.error(f"Failed to save i18n config: {e}")

    def _getDefaultConfig(self):
        """Get default configuration"""
        return {'language': self.DEFAULT_LANGUAGE, 'auto_detect': True, 'supported_languages': self.SUPPORTED_LANGUAGES}

    def _getTranslation(self, language, domain=None):
        """Get gettext translation object for a language and domain (with caching)

        Args:
            language: Language code
            domain: Translation domain ('messages' for core, 'addons' for addons)

        Returns:
            Translation object
        """
        if domain is None:
            domain = self.DOMAIN_CORE

        # Nested cache: domain -> language -> translation
        if domain not in self.translationCache:
            self.translationCache[domain] = {}

        if language in self.translationCache[domain]:
            return self.translationCache[domain][language]

        try:
            # Check if locale directory and language files exist
            langDir = os.path.join(self.localeDir, language, 'LC_MESSAGES')
            moFile = os.path.join(langDir, f'{domain}.mo')

            if not os.path.exists(moFile):
                logger.debug(f"Translation file not found: {moFile}, using fallback")
                # Return NullTranslations for graceful fallback
                translation = gettext.NullTranslations()
            else:
                translation = gettext.translation(domain, localedir=self.localeDir, languages=[language], fallback=True)
                logger.debug(f"Loaded translation for domain '{domain}', language: {language}")

            self.translationCache[domain][language] = translation
            return translation

        except Exception as e:
            logger.warning(f"Failed to load translation for {language} (domain: {domain}): {e}")
            # Return NullTranslations as fallback
            translation = gettext.NullTranslations()
            self.translationCache[domain][language] = translation
            return translation

    def _(self, message, domain=None):
        """
        Translate message to current language (gettext-style function).

        Args:
            message: String to translate
            domain: Translation domain ('addons' for addon translations, 'messages' or None for core)

        Returns:
            Translated string, or original message if translation not found
        """
        if domain is None:
            domain = self.DOMAIN_CORE

        translation = self._getTranslation(self.currentLanguage, domain)
        return translation.gettext(message)

    def ngettext(self, singular, plural, n, domain=None):
        """
        Plural-aware translation.

        Args:
            singular: Singular form message
            plural: Plural form message
            n: Count for determining singular vs plural
            domain: Translation domain ('addons' for addon translations, 'messages' or None for core)

        Returns:
            Translated string in correct plural form
        """
        if domain is None:
            domain = self.DOMAIN_CORE

        translation = self._getTranslation(self.currentLanguage, domain)
        return translation.ngettext(singular, plural, n)

    def setLanguage(self, langCode):
        """
        Change current language and persist preference.

        Args:
            langCode: Language code ('en', 'zh_Hant', etc.)
        """
        # Normalize language code
        normalizedLang = self._normalizeLanguageCode(langCode)

        if normalizedLang not in self.SUPPORTED_LANGUAGES:
            logger.warning(f"Unsupported language: {langCode}, ignoring")
            return

        self.currentLanguage = normalizedLang

        # Save preference
        config = self._loadConfig()
        config['language'] = normalizedLang
        self._saveConfig(config)

        logger.info(f"Language changed to: {normalizedLang}")

    def _normalizeLanguageCode(self, code):
        """
        Normalize language code to standard format using babel.

        Examples:
            'zh-hant' -> 'zh_Hant'
            'zh-tw' -> 'zh_Hant'
            'en' -> 'en'
        """
        if not code:
            return self.DEFAULT_LANGUAGE

        try:
            # Try parsing with babel (handles both '-' and '_' separators)
            babelLocale = Locale.parse(code, sep='_')

            # Use the shared mapping logic
            return self._mapBabelLocaleToLanguageCode(babelLocale)

        except (UnknownLocaleError, ValueError):
            # If babel can't parse it, try simple normalization
            normalized = code.lower().replace('-', '_')

            # Direct match for common patterns
            if normalized in ('zh_hant', 'zh_tw', 'zh_hk', 'zh_mo'):
                return 'zh_Hant'
            elif normalized in ('zh_hans', 'zh_cn', 'zh_sg'):
                return 'zh_Hans'
            elif normalized.startswith('en'):
                return 'en'
            else:
                return code

    def getLanguage(self):
        """Get current language code"""
        return self.currentLanguage

    def getSupportedLanguages(self):
        """Get list of supported language codes"""
        return self.SUPPORTED_LANGUAGES.copy()


class DummyI18nManager(Singleton):
    """
    Dummy I18nManager for when babel is not available.
    Always uses English language and returns messages unchanged.
    """

    DEFAULT_LANGUAGE = 'en'
    SUPPORTED_LANGUAGES = ['en']

    def initialize(self):
        """Initialize dummy manager with English only"""
        self.currentLanguage = self.DEFAULT_LANGUAGE
        logger.debug("DummyI18nManager initialized (babel not available, using English only)")

    def _(self, message, domain=None):
        """Return message unchanged (no translation)"""
        return message

    def ngettext(self, singular, plural, n, domain=None):
        """Simple plural handling without translation"""
        return singular if n == 1 else plural

    def setLanguage(self, langCode):
        """No effect - always uses English"""
        if langCode != self.DEFAULT_LANGUAGE:
            logger.warning(f"Cannot set language to '{langCode}' - babel not available, using English only")

    def getLanguage(self):
        """Always returns 'en'"""
        return self.currentLanguage

    def getSupportedLanguages(self):
        """Returns only English"""
        return self.SUPPORTED_LANGUAGES.copy()


# Select I18nManager based on babel availability
if BABEL_AVAILABLE:
    I18nManager = BabelI18nManager
else:
    I18nManager = DummyI18nManager


# Module-level translation functions (automatically use the singleton)
def _(message, domain=None):
    """
    Translate message to current language.

    This is a module-level convenience function that automatically
    uses the I18nManager singleton.

    Args:
        message: String to translate
        domain: Translation domain ('addons' for addon translations, 'messages' or None for core)

    Returns:
        Translated string
    """
    return I18nManager.getInstance()._(message, domain)


def ngettext(singular, plural, n, domain=None):
    """
    Plural-aware translation.

    This is a module-level convenience function that automatically
    uses the I18nManager singleton.

    Args:
        singular: Singular form message
        plural: Plural form message
        n: Count for determining singular vs plural
        domain: Translation domain ('addons' for addon translations, 'messages' or None for core)

    Returns:
        Translated string in correct plural form
    """
    return I18nManager.getInstance().ngettext(singular, plural, n, domain)
