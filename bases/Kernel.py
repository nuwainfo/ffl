#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os
import importlib
import logging
import platform
import sys
import threading
import json
import inspect
import functools
import secrets
import string

import sentry_sdk

from pathlib import Path
from enum import Enum

from signalslot import Signal

from sentry_sdk.integrations.logging import SentryHandler, LoggingIntegration
from sentry_sdk.integrations import atexit as sentryAtexit


def getSecret(key: str, jsonFile: str = '.secret'):
    value = os.getenv(key)
    if value:
        return value

    secretPath = Path(jsonFile)
    if not secretPath.exists():
        try:
            callerPath = Path(__file__).resolve().parent.parent / jsonFile
            if not callerPath.exists():
                return None
            secretPath = callerPath
        except NameError as e: # without __file__ ?
            logger = logging.getLogger(__name__)
            logger.debug(f"Unable to determine caller path for secret: {e}")
            return None

    data = json.loads(secretPath.read_text())
    return data.get(key)


# TODO: Best to control by GrowthBook
PUBLIC_VERSION = '3.6.1'

SENTRY_DSN = getSecret('SENTRY_DSN')


def configureGlobalLogLevel(logLevel):
    """
    Configure the global logging level for the application.
    This affects all loggers created via getLogger().
    
    Args:
        logLevel: Logging level (logging.DEBUG, logging.INFO, etc.)
    """
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logLevel)

    # Add console handler if none exists
    if not rootLogger.handlers:
        consoleHandler = logging.StreamHandler()
        consoleHandler.setLevel(logLevel)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        consoleHandler.setFormatter(formatter)
        rootLogger.addHandler(consoleHandler)
    else:
        # Update existing handlers
        for handler in rootLogger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, SentryHandler):
                handler.setLevel(logLevel)


def getLogger(name, version=PUBLIC_VERSION):
    """
    Get a logger with Sentry integration. Uses Sentry's own initialization state to avoid duplicate setup.
    """
    try:
        # Import Sentry components locally to avoid circular imports

        # Check if Sentry is already initialized using Sentry's own state
        notInit = not sentry_sdk.Hub.current or not sentry_sdk.Hub.current.client
        sentryInitialized = False

        if notInit and SENTRY_DSN:
            # Override default_callback to suppress "sentry is attempting to send pending events..." message
            sentryAtexit.default_callback = lambda pending, timeout: None

            # Initialize Sentry once
            sentry_sdk.init(
                dsn=SENTRY_DSN,
                default_integrations=False,
                integrations=[
                    LoggingIntegration(),
                    sentryAtexit.AtexitIntegration(),
                ],
            )
            sentryInitialized = True

        # Create logger
        logger = logging.getLogger(name)

        # Add Sentry handler if not already present
        if not any(isinstance(h, SentryHandler) for h in logger.handlers):
            extra = {'version': version or 'unknown'}
            formatter = logging.Formatter('%(asctime)s version[%(version)s] : %(message)s')

            syslog = SentryHandler()
            syslog.setFormatter(formatter)
            logger.addHandler(syslog)
            logger = logging.LoggerAdapter(logger, extra)

        if sentryInitialized:
            logger.debug(f'Sentry initialized with DSN: {SENTRY_DSN}')

        return logger

    except Exception as e:
        logger = logging.getLogger(name)

        # If Sentry setup fails, log the error and continue with standard logging
        logger.warning(f"Failed to initialize Sentry: {e}")

        return logger


def classForName(qualifiedName):
    """
    Get a class or module by its fully qualified name.
    """
    if not isinstance(qualifiedName, str):
        qualifiedName = str(qualifiedName)

    if '.' not in qualifiedName:
        return __import__(qualifiedName)

    parts = qualifiedName.split('.')
    moduleName = ".".join(parts[:-1])
    module = __import__(moduleName, fromlist=[parts[-1]])

    try:
        return getattr(module, parts[-1])
    except AttributeError:
        raise ImportError(f"Unable to import '{qualifiedName}'.")


class Singleton:
    """
    Thread-safe singleton base class that can be inherited by other classes.
    Provides the standard singleton pattern with thread safety and getInstance() method.
    Uses template method pattern where subclasses override initialize() for custom initialization.
    """

    _instances = {}
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls not in cls._instances:
            with cls._lock:
                if cls not in cls._instances:
                    cls._instances[cls] = super().__new__(cls)
        return cls._instances[cls]

    def __init__(self, *args, **kwargs):
        """
        Constructor that handles the _initialized pattern common to singletons.
        Only calls initialize() once for the lifetime of the singleton.
        Passes all arguments to the initialize method.
        """
        if not hasattr(self, '_initialized'):
            self.initialize(*args, **kwargs)
            self._initialized = True

    def initialize(self, *args, **kwargs):
        """
        Template method for subclasses to override for custom initialization.
        This method is called only once when the singleton instance is first created.
        Receives all arguments passed to __init__.
        """
        pass

    @classmethod
    def getInstance(cls):
        """
        Static access method for the singleton instance.
        """
        if cls not in cls._instances:
            cls()
        return cls._instances[cls]


class EventTiming(Enum):
    """Constants for event timing phases"""
    BEFORE = "BEFORE"
    AFTER = "AFTER"


class EventService(Singleton):
    """
    This service provides a mechanism to dispatch events to all components.
    It is implemented as a thread-safe singleton and uses the 'signalslot'
    library to manage signal dispatching.
    """

    def initialize(self):
        """
        Initialize the EventService with signal storage.
        """
        self.signals = {}

    def reset(self):
        """
        Clears all registered signals. Should only be used in test suites
        to ensure test isolation.
        """
        self.signals.clear()

    def _getSignalObjects(self, event):
        """
        Get the internal Signal objects for an event.
        """
        return self.signals.get(event)

    def _normalizeTiming(self, timing):
        """
        Normalize timing parameter to EventTiming enum value.
        """
        if timing is None:
            return None

        if isinstance(timing, EventTiming):
            return timing

        if isinstance(timing, str):
            try:
                return EventTiming(timing.upper())
            except ValueError:
                raise ValueError(f"Invalid timing value: '{timing}'. Must be 'BEFORE' or 'AFTER'.")

        raise ValueError(f"Timing must be EventTiming enum, string, or None. Got: {type(timing)}")

    def trigger(self, event, *args, **kwargs):
        """
        Trigger an event, calling all connected observers (slots).
        """
        timing = kwargs.pop('timing', None)
        normalizedTiming = self._normalizeTiming(timing)

        signalObjects = self._getSignalObjects(event)
        if not signalObjects:
            return

        beforeSignal, afterSignal = signalObjects

        if normalizedTiming in (EventTiming.BEFORE, None):
            beforeSignal.emit(*args, **kwargs)

        if normalizedTiming in (EventTiming.AFTER, None):
            afterSignal.emit(*args, **kwargs)

    def isRegistered(self, event):
        """
        Check if an event is registered.
        """
        return event in self.signals

    def register(self, event):
        """
        Register a new event by creating Signal objects for it.
        """
        if self.isRegistered(event):
            return False
        self.signals[event] = (Signal(), Signal())
        return True

    def unregister(self, event):
        """
        Unregister an event and disconnect all its observers.
        """
        if not self.isRegistered(event):
            return False

        beforeSignal, afterSignal = self.signals[event]
        beforeSignal.disconnect_all()
        afterSignal.disconnect_all()
        del self.signals[event]
        return True

    def attach(self, event, trigger):
        """
        Attach an event to a function or method.
        """
        if not self.isRegistered(event):
            raise KeyError(f"Event '{event}' is not registered yet!")

        qualifiedName = getattr(trigger, '__qualname__', '')
        isPotentialMethod = inspect.isfunction(trigger) and '.' in qualifiedName

        @functools.wraps(trigger)
        def wrapper(*args, **kwargs):
            context = {'args': args, 'kwargs': kwargs, 'event': wrapper.event}

            argSpec = inspect.getfullargspec(trigger)
            for i, argName in enumerate(argSpec.args):
                if i < len(args):
                    context[argName] = args[i]
            context.update(kwargs)

            sender = args[0] if isPotentialMethod and args else None

            self.trigger(event, sender=sender, context=context, timing=EventTiming.BEFORE)

            if 'return' not in context:
                context['return'] = trigger(*args, **kwargs)

            self.trigger(event, sender=sender, context=context, timing=EventTiming.AFTER)

            return context['return']

        wrapper.event = event
        wrapper.bak = trigger
        wrapper.events = getattr(trigger, 'events', ()) + (event,)

        if inspect.ismethod(trigger) and getattr(trigger, '__self__', None) is not None:
            setattr(trigger.__self__, trigger.__name__, wrapper)
        elif isPotentialMethod:
            module = classForName(trigger.__module__)
            className = qualifiedName.split('.')[0]
            cls = getattr(module, className)
            setattr(cls, trigger.__name__, wrapper)
        else:
            module = classForName(trigger.__module__)
            setattr(module, trigger.__name__, wrapper)

        return wrapper

    def detach(self, event, trigger):
        """
        Detach an event from a wrapped function.
        """
        if not hasattr(trigger, 'bak'):
            raise TypeError(f"'{trigger.__name__}' is not an attached function.")

        if event not in getattr(trigger, 'events', ()):
            raise RuntimeError(f"Event '{event}' is not attached to '{trigger.__name__}'.")

        chain = []
        curr = trigger
        while hasattr(curr, 'bak'):
            chain.append(curr)
            curr = curr.bak
        originalFunction = curr
        chain.reverse()

        newTrigger = originalFunction
        for wrapper in chain:
            if wrapper.event != event:
                newTrigger = self.attach(wrapper.event, newTrigger)

        return newTrigger

    def original(self, attached):
        """
        Get the original callable from a wrapped one.
        """
        f = attached
        while hasattr(f, 'bak'):
            f = f.bak
        return f

    def subscribe(self, event, observer, timing=EventTiming.AFTER, index=-1):
        """
        Subscribe an observer to an event, with full control over execution order.
        """
        if not self.isRegistered(event):
            raise KeyError(f"You must register event '{event}' first.")

        normalizedTiming = self._normalizeTiming(timing)
        if normalizedTiming not in (EventTiming.BEFORE, EventTiming.AFTER):
            raise ValueError("Timing must be EventTiming.BEFORE or EventTiming.AFTER.")

        signalObject = self.signals[event][0 if normalizedTiming == EventTiming.BEFORE else 1]

        if observer in signalObject._slots:
            return

        if index == -1:
            signalObject.connect(observer)
        else:
            signalObject._slots.insert(index, observer)

    def unsubscribe(self, event, observer, timing=None):
        """
        Unsubscribe an observer from an event.
        """
        if not self.isRegistered(event):
            return

        timingsToCheck = [self._normalizeTiming(timing)] if timing else [EventTiming.BEFORE, EventTiming.AFTER]

        for t in timingsToCheck:
            if t in (EventTiming.BEFORE, EventTiming.AFTER):
                signalObject = self.signals[event][0 if t == EventTiming.BEFORE else 1]
                if observer in signalObject._slots:
                    signalObject.disconnect(observer)

    def find(self, event, observer, timing=EventTiming.AFTER):
        """
        Find the index of an observer for an event.
        """
        if not self.isRegistered(event):
            return -1

        normalizedTiming = self._normalizeTiming(timing)
        signalObject = self.signals[event][0 if normalizedTiming == EventTiming.BEFORE else 1]

        try:
            return signalObject._slots.index(observer)
        except ValueError:
            return -1


class Event:
    """ Simple Event wrapper"""

    def __init__(self, key):
        self.key = key

        self.eventService = EventService.getInstance()

    def subscribe(self, observer, timing=EventTiming.AFTER, index=-1):
        return self.eventService.subscribe(self.key, observer, timing=timing, index=index)

    def unsubscribe(self, observer, timing=None):
        return self.eventService.unsubscribe(self.key, observer, timing=timing)

    def trigger(self, *args, **kwargs):
        return self.eventService.trigger(self.key, *args, **kwargs)


class AddonsManager(Singleton):
    """
    Manages loading and initialization of addons in an ordered, unintrusive way.
    This allows addons to extend Core functionality through the Event system.
    """

    def initialize(self):
        """
        Initialize the AddonsManager with logger and addon tracking lists.
        """
        self.logger = getLogger(__name__)
        self.loadedAddons = []
        self.failedAddons = []
        self.storageLocator = StorageLocator.getInstance()

    def getEnabledAddons(self):
        """
        Get the list of enabled addons from addons.__init__, filtered by disabled addons.
        Returns empty list if addons list doesn't exist or can't be imported.

        Disabling Priority (highest to lowest):
        1. addons.json config file: JSON object with "disabled" array containing addon names to disable
        2. DISABLE_ADDONS environment variable: Comma-separated list of addon names to disable (fallback when no config file)

        Note: If addons.json exists and has a valid "disabled" field, the environment variable is ignored.
        This ensures user config files are authoritative and predictable.

        Example addons.json:
        {
            "disabled": ["GUI", "Tunnels"]
        }
        """
        try:
            addonsModule = importlib.import_module('addons')
            addonsList = getattr(addonsModule, 'addons', [])

            if not isinstance(addonsList, (list, tuple)):
                raise RuntimeError("addons.addons is not a list")

            # Filter out disabled addons
            disabledAddons = self._getDisabledAddons()
            addonsList = [addon for addon in addonsList if addon not in disabledAddons]

            return addonsList

        except ImportError as e:
            self.logger.debug(f"Could not import addons module: {e}")
            return []

    def _getDisabledAddons(self):
        """
        Get disabled addons from multiple sources with priority:
        1. addons.json config file (highest priority)
        2. DISABLE_ADDONS environment variable (fallback when no config file)

        Returns:
            set: Set of disabled addon names
        """
        disabledAddons = set()
        configFileFound = False

        # 1. Read from addons.json config file first (highest priority)
        try:
            addonsConfigPath = self.storageLocator.findConfig('addons.json')
            if os.path.exists(addonsConfigPath):
                with open(addonsConfigPath, 'r', encoding='utf-8') as f:
                    addonsConfig = json.load(f)

                # If we have a valid JSON file, mark config as found (even if no 'disabled' field)
                if isinstance(addonsConfig, dict):
                    configFileFound = True

                    if 'disabled' in addonsConfig:
                        configDisabled = addonsConfig['disabled']
                        if isinstance(configDisabled, (list, tuple)):
                            validDisabled = [addon.strip() for addon in configDisabled if isinstance(addon, str) and addon.strip()]
                            disabledAddons.update(validDisabled)
                            if validDisabled:
                                self.logger.debug(f"Disabled addons from addons.json: {', '.join(validDisabled)}")
                        else:
                            self.logger.warning(f"addons.json 'disabled' field should be an array, got: {type(configDisabled)}")

        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            self.logger.debug(f"Could not read addons.json config: {e}")
        except Exception as e:
            self.logger.warning(f"Unexpected error reading addons.json config: {e}")

        # 2. Read from DISABLE_ADDONS environment variable (fallback when no valid config file)
        if not configFileFound:
            envDisabled = os.getenv('DISABLE_ADDONS', '')
            if envDisabled:
                envDisabledList = [addon.strip() for addon in envDisabled.split(',') if addon.strip()]
                if envDisabledList:
                    disabledAddons.update(envDisabledList)
                    self.logger.debug(f"Disabled addons from DISABLE_ADDONS: {', '.join(envDisabledList)}")

        # Log final disabled addons list if any
        if disabledAddons:
            self.logger.info(f"Disabled addons: {', '.join(sorted(disabledAddons))}")

        return disabledAddons

    def loadAddon(self, addonName):
        """
        Load a single addon by name.

        Before loading, checks if the addon declares __ADDONS_REQUIRED__ and verifies
        all required dependencies are enabled. If any dependency is missing, the addon
        is not loaded and an error is logged.

        If the addon has a load() function, it will be called after dependency validation.
        Returns True if successfully loaded, False otherwise.
        """
        # Check if addon is already loaded
        if addonName in self.loadedAddons:
            self.logger.debug(f"Addon {addonName} is already loaded, skipping")
            return True

        # Check if addon already failed to load
        failedAddonNames = [name for name, _ in self.failedAddons]
        if addonName in failedAddonNames:
            self.logger.debug(f"Addon {addonName} previously failed to load, skipping")
            return False

        try:
            self.logger.debug(f"Loading addon: {addonName}")

            # Import the addon module
            addonModule = importlib.import_module(f'addons.{addonName}')

            # Check for __ADDONS_REQUIRED__ attribute
            requiredAddons = getattr(addonModule, '__ADDONS_REQUIRED__', None)
            if requiredAddons:
                if not isinstance(requiredAddons, (tuple, list)):
                    self.logger.warning(f"Addon {addonName} has invalid __ADDONS_REQUIRED__ format (should be tuple/list): {type(requiredAddons)}")
                else:
                    # Check if all required addons are enabled and can be loaded
                    enabledAddons = self.getEnabledAddons()
                    missingDependencies = []

                    for dep in requiredAddons:
                        if dep not in enabledAddons:
                            missingDependencies.append(dep)
                        elif dep not in self.loadedAddons:
                            # Try to load the dependency first
                            self.logger.debug(f"Loading dependency {dep} for {addonName}")
                            depSuccess = self.loadAddon(dep)
                            if not depSuccess:
                                missingDependencies.append(dep)

                    if missingDependencies:
                        errorMsg = f"Addon {addonName} requires unavailable addons: {', '.join(missingDependencies)}. Required: {', '.join(requiredAddons)}"
                        self.logger.warning(errorMsg)
                        self.failedAddons.append((addonName, errorMsg))
                        return False

                    self.logger.debug(f"Addon {addonName} dependency check passed: {', '.join(requiredAddons)}")

            # Check if the addon has a load function
            loadFunction = getattr(addonModule, 'load', None)
            if loadFunction and callable(loadFunction):
                self.logger.debug(f"Calling load() function for addon: {addonName}")
                loadFunction()
            else:
                self.logger.debug(f"Addon {addonName} has no load() function, skipping initialization")

            self.loadedAddons.append(addonName)
            self.logger.info(f"Successfully loaded addon: {addonName}")
            return True

        except ImportError as e:
            self.logger.warning(f"Could not import addon {addonName}: {e}")
            self.failedAddons.append((addonName, str(e)))
            return False
        except Exception as e:
            self.logger.error(f"Error loading addon {addonName}: {e}", exc_info=True)
            self.failedAddons.append((addonName, str(e)))
            if os.getenv('RAISE_EXCEPTION') == "True":
                raise

            return False

    def loadAllAddons(self):
        """
        Load all enabled addons in the order specified in addons.__init__.addons list.
        """
        enabledAddons = self.getEnabledAddons()

        if not enabledAddons:
            return

        for addonName in enabledAddons:
            self.loadAddon(addonName)

        if self.failedAddons:
            failedNames = [name for name, _ in self.failedAddons]
            self.logger.warning(f"Failed to load addons: {failedNames}")

    def getLoadedAddons(self):
        """
        Get list of successfully loaded addon names.
        """
        return self.loadedAddons[:]

    def getFailedAddons(self):
        """
        Get list of tuples (addon_name, error_message) for failed addons.
        """
        return self.failedAddons[:]

    def isAddonLoaded(self, addonName):
        """
        Check if a specific addon is loaded.
        """
        return addonName in self.loadedAddons

    def getAddonObject(self, addonName, objectName):
        """
        Get a specific object (class, function, constant, etc.) from a loaded addon using classForName.
        Returns None if addon is not loaded or object doesn't exist.
        """
        if not self.isAddonLoaded(addonName):
            self.logger.warning(f"Addon {addonName} is not loaded")
            return None

        try:
            qualifiedName = f'addons.{addonName}.{objectName}'
            return classForName(qualifiedName)
        except ImportError as e:
            self.logger.debug(f"Could not import {qualifiedName}: {e}")
            return None

    def getAddonClass(self, addonName, className):
        """
        Get a specific class from a loaded addon. Convenience method that calls getAddonObject.
        Returns None if addon is not loaded or class doesn't exist.
        """
        return self.getAddonObject(addonName, className)

    def reloadAddon(self, addonName):
        """
        Reload a specific addon. Useful for development/testing.
        """
        try:
            # Remove from loaded list if present
            if addonName in self.loadedAddons:
                self.loadedAddons.remove(addonName)

            # Remove from failed list if present
            self.failedAddons = [(name, error) for name, error in self.failedAddons if name != addonName]

            # Reload the module
            moduleName = f'addons.{addonName}'
            if moduleName in sys.modules:
                importlib.reload(sys.modules[moduleName])

            # Load the addon again
            return self.loadAddon(addonName)

        except Exception as e:
            self.logger.error(f"Error reloading addon {addonName}: {e}", exc_info=True)
            return False

    def reset(self):
        """
        Reset the manager state. Useful for testing.
        """
        self.loadedAddons.clear()
        self.failedAddons.clear()


class StorageLocator(Singleton):
    """
    Simple storage location resolution for configuration and data files
    
    Environment Variables:
        FFL_STORAGE_LOCATION: Override storage location for testing and advanced users.
                             If set to an existing directory path, it will be used
                             with highest priority for both reading and writing operations.
    """

    class Location:
        CURRENT = 'current'
        HOME = 'home'
        PLATFORM = 'platform'

    def initialize(self, appName='fastfilelink'):
        """Initialize with application name"""
        self.appName = appName
        self._homeDir = os.path.expanduser(f'~/.{appName}')
        self._platformDir = self._getPlatformDir()

        self.logger = getLogger(__name__)

    def _getPlatformDir(self):
        """Get platform-specific directory"""
        system = platform.system()

        if system == 'Windows':
            appdata = os.getenv('APPDATA', os.path.expanduser('~'))
            return os.path.join(appdata, self.appName)
        elif system == 'Darwin': # macOS
            return os.path.expanduser(f'~/Library/Application Support/{self.appName}')
        else: # Linux and others
            return os.path.expanduser(f'~/.config/{self.appName}')

    def _getEnvStorageLocation(self):
        """
        Get storage location from FFL_STORAGE_LOCATION environment variable
        
        Returns:
            str or None: Valid storage location path if environment variable is set 
                        and points to an existing directory, None otherwise
        """
        envStorageLocation = os.getenv('FFL_STORAGE_LOCATION')
        if envStorageLocation and os.path.exists(envStorageLocation) and os.path.isdir(envStorageLocation):
            return envStorageLocation
        return None

    def ensureStorageDir(self, prefer=None):
        """
        Ensure storage directory exists for saving config/data files
        
        Args:
            prefer: Preferred location (Location.HOME, Location.PLATFORM, Location.CURRENT)
                   If None: home -> platform -> current
                   
        Returns:
            Path to created storage directory
        """
        # Check for FFL_STORAGE_LOCATION environment variable first
        envStorageLocation = self._getEnvStorageLocation()
        if envStorageLocation:
            # Environment variable overrides all preferences
            storageDirs = [envStorageLocation]
            self.logger.info(f'Using FFL_STORAGE_LOCATION environment override: {envStorageLocation}')
        elif prefer == self.Location.HOME:
            storageDirs = [self._homeDir, self._platformDir, os.path.abspath('.')]
        elif prefer == self.Location.PLATFORM:
            storageDirs = [self._platformDir, self._homeDir, os.path.abspath('.')]
        elif prefer == self.Location.CURRENT:
            storageDirs = [os.path.abspath('.'), self._homeDir, self._platformDir]
        else:
            # Default: home -> platform -> current
            storageDirs = [self._homeDir, self._platformDir, os.path.abspath('.')]

        for storageDir in storageDirs:
            testFile = os.path.join(storageDir, '.write_test')
            try:
                os.makedirs(storageDir, exist_ok=True)
                # Test write permission
                with open(testFile, 'w') as f:
                    f.write('test')

                return storageDir
            except (OSError, PermissionError) as e:
                self.logger.warning(f'Unable to use {storageDir} as storage directory => {e}.')
                continue
            finally:
                if os.path.exists(testFile):
                    os.remove(testFile)

        # Fallback to current directory if all fail
        return os.path.abspath('.')

    def findStorage(self, filename, prefer=None):
        """
        Find storage location for reading config/data files
        Default priority: current -> home -> platform
        If prefer specified: prefer location first, then original sequence
        
        Args:
            filename: Name of the file to find
            prefer: Preferred location (Location.CURRENT, Location.HOME, Location.PLATFORM)
            
        Returns:
            Path to the file (may not exist)
        """
        # Check for FFL_STORAGE_LOCATION environment variable first
        envStorageLocation = self._getEnvStorageLocation()
        if envStorageLocation:
            envPath = os.path.join(envStorageLocation, filename)
            if os.path.exists(envPath):
                return envPath

        # Original search sequence: current -> home -> platform
        originalPaths = [
            os.path.abspath(filename), # Current directory
            os.path.join(self._homeDir, filename), # Home directory  
            os.path.join(self._platformDir, filename) # Platform specific
        ]

        # If prefer is specified, try that location first
        if prefer:
            if prefer == self.Location.CURRENT:
                preferPath = originalPaths[0]
            elif prefer == self.Location.HOME:
                preferPath = originalPaths[1]
            elif prefer == self.Location.PLATFORM:
                preferPath = originalPaths[2]
            else:
                preferPath = None

            if preferPath and os.path.exists(preferPath):
                return preferPath

        # Search with original sequence
        for path in originalPaths:
            if os.path.exists(path):
                return path

        # If no file found, return the environment path if available, otherwise home directory path
        envStorageLocation = self._getEnvStorageLocation()
        if envStorageLocation:
            return os.path.join(envStorageLocation, filename)

        return os.path.join(self._homeDir, filename)

    def findConfig(self, filename, prefer=None):
        """
        Find configuration file
        Alias for findStorage with better naming for config files
        
        Args:
            filename: Name of the config file to find
            prefer: Preferred location (Location.CURRENT, Location.HOME, Location.PLATFORM)
            
        Returns:
            Path to the config file (may not exist)
        """
        return self.findStorage(filename, prefer=prefer)


class UIDGenerator:
    """Generate UIDs for file sharing links, with support for custom aliases"""

    UID_LEN = 8

    def generate(self):
        """
        Generate a UID for sharing link
                    
        Returns:
            str: Generated UID or the alias if provided
        """
        # Generate 8-character random string using letters and numbers
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(self.UID_LEN))


# Event pattern: RESTful + /[action] (create, update, get, delete, others...)
class FFLEvent:
    cliArgumentsCommandsRegister = Event('/cli/arguments/commands/create')
    cliArgumentsShareOptionsRegister = Event('/cli/arguments/share/options/create')
    cliArgumentsStore = Event('/cli/arguments/get')


eventService = EventService.getInstance()

eventService.register(FFLEvent.cliArgumentsCommandsRegister.key)
eventService.register(FFLEvent.cliArgumentsShareOptionsRegister.key)
eventService.register(FFLEvent.cliArgumentsStore.key)
