/*!
 * FastFileLink - Logging
 * https://github.com/nuwainfo/ffl
 *
 * Licensed under the Apache-2.0 license
 *
 * Category-aware logging facade built on top of browser loglevel with shared
 * log normalization and reporter fan-out for the download page.
 *
 * See LICENSE file in the project root for full license information.
 */

(function(global) {
    const loglevelLib = (() => {
        if (!global.log || typeof global.log.getLogger !== 'function' || typeof global.log.noConflict !== 'function') {
            throw new Error('FFLLogging requires browser loglevel to be loaded first');
        }

        return global.log.noConflict();
    })();

    const LEVEL_NAMES = ['trace', 'debug', 'info', 'warn', 'error', 'silent'];
    const LEVEL_VALUES = {
        trace: loglevelLib.levels.TRACE,
        debug: loglevelLib.levels.DEBUG,
        info: loglevelLib.levels.INFO,
        warn: loglevelLib.levels.WARN,
        error: loglevelLib.levels.ERROR,
        silent: loglevelLib.levels.SILENT,
    };
    const ACTIVE_LEVEL_NAMES = LEVEL_NAMES.filter((levelName) => levelName !== 'silent');

    const DEFAULT_CATEGORY_LEVELS = {
        '*': 'info',
    };

    function toISOString(dateValue) {
        if (dateValue instanceof Date) {
            return dateValue.toISOString();
        }

        return new Date(dateValue).toISOString();
    }

    function safeStringify(value) {
        if (value instanceof Error) {
            return `${value.name}: ${value.message}${value.stack ? `\n${value.stack}` : ''}`;
        }

        if (typeof value === 'string') {
            return value;
        }

        try {
            return JSON.stringify(value);
        } catch (jsonErr) {
            try {
                return String(value);
            } catch (stringErr) {
                return '[unserializable value]';
            }
        }
    }

    function normalizeLevelName(levelName, fallbackLevelName = 'info') {
        if (typeof levelName !== 'string') {
            return fallbackLevelName;
        }

        const normalizedLevelName = levelName.toLowerCase();
        return Object.prototype.hasOwnProperty.call(LEVEL_VALUES, normalizedLevelName)
            ? normalizedLevelName
            : fallbackLevelName;
    }

    function cloneCategoryLevels(categoryLevels = {}) {
        return {
            ...DEFAULT_CATEGORY_LEVELS,
            ...categoryLevels,
        };
    }

    function resolveConfiguredLevelName(category, categoryLevels, fallbackLevelName) {
        if (category && Object.prototype.hasOwnProperty.call(categoryLevels, category)) {
            return normalizeLevelName(categoryLevels[category], fallbackLevelName);
        }

        if (category) {
            const categoryParts = category.split('.');
            while (categoryParts.length > 1) {
                categoryParts.pop();
                const prefixCategory = `${categoryParts.join('.')}.*`;
                if (Object.prototype.hasOwnProperty.call(categoryLevels, prefixCategory)) {
                    return normalizeLevelName(categoryLevels[prefixCategory], fallbackLevelName);
                }
            }
        }

        if (Object.prototype.hasOwnProperty.call(categoryLevels, '*')) {
            return normalizeLevelName(categoryLevels['*'], fallbackLevelName);
        }

        return fallbackLevelName;
    }

    function normalizeLogObject(logObj) {
        const args = Array.isArray(logObj && logObj.args) ? logObj.args : [];
        const [message, ...messageArgs] = args;
        const timestamp = toISOString(logObj && logObj.date ? logObj.date : new Date());
        const category = (logObj && (logObj.category || logObj.tag)) || 'log';
        const levelName = normalizeLevelName(logObj && logObj.levelName ? logObj.levelName : 'info', 'info');
        const normalizedMessage = typeof message === 'undefined' ? '' : safeStringify(message);
        const normalizedArgs = messageArgs.map((arg) => safeStringify(arg));

        return {
            ...logObj,
            timestamp,
            category,
            levelName,
            message: normalizedMessage,
            rawArgs: messageArgs,
            args: normalizedArgs,
            fullMessage: normalizedArgs.length > 0
                ? `${normalizedMessage} ${normalizedArgs.join(' ')}`
                : normalizedMessage,
        };
    }

    function reportReporterFailure(reporterErr) {
        if (typeof console !== 'undefined' && typeof console.warn === 'function') {
            console.warn('Logger reporter failed:', reporterErr);
        }
    }

    class CategoryLogger {
        constructor(logger, category) {
            this._logger = logger;
            this._category = category || 'log';
        }

        log(message, ...args) {
            this.info(message, ...args);
        }

        setLevel(levelName) {
            this._logger.setCategoryLevel(this._category, levelName);
        }

        getLevel() {
            return this._logger.getCategoryLevel(this._category);
        }
    }

    ACTIVE_LEVEL_NAMES.forEach((levelName) => {
        CategoryLogger.prototype[levelName] = function(message, ...args) {
            this._logger.log(this._category, levelName, message, ...args);
        };
    });

    class FFLLogger {
        constructor(options = {}) {
            this._baseLogger = loglevelLib.getLogger('__ffl_root__');
            this._baseLogger.setLevel(loglevelLib.levels.SILENT, false);

            this._reporters = [];
            this._categoryLoggers = new Map();
            this._defaultLevelName = normalizeLevelName(options.defaultLevel || DEFAULT_CATEGORY_LEVELS['*'], 'info');
            this._categoryLevels = cloneCategoryLevels(options.categoryLevels || {});
        }

        addReporter(reporter) {
            if (!reporter || typeof reporter.log !== 'function') {
                throw new Error('Reporter must implement log(logObj)');
            }

            this._reporters.push(reporter);
            return reporter;
        }

        removeReporter(reporter) {
            this._reporters = this._reporters.filter((currentReporter) => currentReporter !== reporter);
        }

        withTag(category) {
            const normalizedCategory = category || 'log';
            if (!this._categoryLoggers.has(normalizedCategory)) {
                this._categoryLoggers.set(normalizedCategory, new CategoryLogger(this, normalizedCategory));
            }
            return this._categoryLoggers.get(normalizedCategory);
        }

        log(category, levelName, message, ...args) {
            const normalizedCategory = category || 'log';
            const normalizedLevelName = normalizeLevelName(levelName, 'info');
            const categoryLogger = this._getLevelLogger(normalizedCategory);

            if (categoryLogger.getLevel() > LEVEL_VALUES[normalizedLevelName]) {
                return;
            }

            this._emitLogObject(this._buildLogObject(normalizedCategory, normalizedLevelName, message, args));
        }

        setDefaultLevel(levelName) {
            this._defaultLevelName = normalizeLevelName(levelName, this._defaultLevelName);
            this._reapplyLevels();
        }

        setCategoryLevel(category, levelName) {
            this._categoryLevels[category] = normalizeLevelName(levelName, this._defaultLevelName);
            this._applyCategoryLevel(category);
        }

        getCategoryLevel(category) {
            return resolveConfiguredLevelName(category, this._categoryLevels, this._defaultLevelName);
        }

        getCategoryLevels() {
            return { ...this._categoryLevels };
        }

        _getLevelLogger(category) {
            const levelLogger = loglevelLib.getLogger(category);
            this._applyCategoryLevel(category);
            return levelLogger;
        }

        _applyCategoryLevel(category) {
            const levelLogger = loglevelLib.getLogger(category);
            const resolvedLevelName = this.getCategoryLevel(category);
            levelLogger.setLevel(LEVEL_VALUES[resolvedLevelName], false);
        }

        _reapplyLevels() {
            Object.keys(loglevelLib.getLoggers()).forEach((category) => {
                this._applyCategoryLevel(category);
            });
        }

        _buildLogObject(category, levelName, message, args) {
            return {
                category,
                tag: category,
                level: LEVEL_VALUES[levelName],
                levelName,
                args: [message, ...args],
                date: new Date(),
            };
        }

        _emitLogObject(logObj) {
            this._reporters.forEach((reporter) => {
                try {
                    reporter.log(logObj);
                } catch (reporterErr) {
                    reportReporterFailure(reporterErr);
                }
            });
        }
    }

    function createLogger(options = {}) {
        return new FFLLogger(options);
    }

    function createLogFunction(logger, defaultLevelName = 'info') {
        const normalizedDefaultLevelName = normalizeLevelName(defaultLevelName, 'info');

        function log(category, message, ...args) {
            logger.log(category, normalizedDefaultLevelName, message, ...args);
        }

        ACTIVE_LEVEL_NAMES.forEach((levelName) => {
            log[levelName] = function(category, message, ...args) {
                logger.log(category, levelName, message, ...args);
            };
        });

        return log;
    }

    function createConsoleReporter({ enabled }) {
        return {
            log(logObj) {
                if (!enabled()) {
                    return;
                }

                if (typeof console === 'undefined') {
                    return;
                }

                const normalizedLogObj = normalizeLogObject(logObj);
                const prefix = `[${normalizedLogObj.timestamp}] [${normalizedLogObj.category}] [${normalizedLogObj.levelName}]`;
                const consoleMethodName = typeof console[normalizedLogObj.levelName] === 'function'
                    ? normalizedLogObj.levelName
                    : 'log';

                if (normalizedLogObj.rawArgs.length > 0) {
                    console[consoleMethodName](`${prefix} ${normalizedLogObj.message}`, ...normalizedLogObj.rawArgs);
                    return;
                }

                console[consoleMethodName](`${prefix} ${normalizedLogObj.message}`);
            }
        };
    }

    function createServerReporter({ enabled, endpoint, sessionId = null, onError = null }) {
        return {
            log(logObj) {
                if (!enabled()) {
                    return;
                }

                const normalizedLogObj = normalizeLogObject(logObj);

                try {
                    fetch(endpoint, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            category: normalizedLogObj.category,
                            message: normalizedLogObj.fullMessage,
                            timestamp: normalizedLogObj.timestamp,
                            sessionId,
                        })
                    }).catch((err) => {
                        if (typeof onError === 'function') {
                            onError(err, normalizedLogObj);
                        }
                    });
                } catch (err) {
                    if (typeof onError === 'function') {
                        onError(err, normalizedLogObj);
                    }
                }
            }
        };
    }

    function installGlobalErrorLogging(log, { enabled }) {
        if (typeof global === 'undefined' || typeof global.addEventListener !== 'function') {
            return;
        }

        if (global.__FFL_GLOBAL_ERROR_LOGGING_INSTALLED__) {
            return;
        }

        let isHandlingGlobalError = false;

        global.addEventListener('error', (event) => {
            if (!enabled() || isHandlingGlobalError) {
                return;
            }

            isHandlingGlobalError = true;

            try {
                const errorDetails = event.error || `${event.message} @ ${event.filename}:${event.lineno}:${event.colno}`;
                log.error('Window', 'Unhandled window error', errorDetails);
            } finally {
                isHandlingGlobalError = false;
            }
        });

        global.__FFL_GLOBAL_ERROR_LOGGING_INSTALLED__ = true;
    }

    function getLogFunction(debugEnabled, reporters = [], options = {}) {
        const logger = createLogger({
            defaultLevel: options.defaultLevel || (debugEnabled ? 'debug' : 'info'),
            categoryLevels: {
                '*': debugEnabled ? 'debug' : 'info',
                ...(options.categoryLevels || {}),
            },
        });

        logger.addReporter(createConsoleReporter({
            enabled: () => !!debugEnabled,
        }));

        reporters.forEach((reporter) => {
            logger.addReporter(reporter);
        });

        const log = createLogFunction(logger, options.defaultMethodLevel || 'info');
        log.logger = logger;

        installGlobalErrorLogging(log, {
            enabled: () => options.captureWindowErrors !== false && !!debugEnabled,
        });

        return log;
    }

    global.FFLLogging = {
        LEVEL_NAMES,
        LEVEL_VALUES,
        DEFAULT_CATEGORY_LEVELS,
        createLogger,
        createLogFunction,
        createConsoleReporter,
        createServerReporter,
        getLogFunction,
        installGlobalErrorLogging,
        normalizeLogObject,
        safeStringify,
        toISOString,
    };
})(typeof window !== 'undefined' ? window : globalThis);
