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

import shutil
import sys
import os

from datetime import timedelta
from enum import Enum

from bases.Kernel import PUBLIC_VERSION, Singleton, AddonsManager, getLogger

DEFAULT_STATIC_ROOT = 'static'
STATIC_SERVER = os.getenv('STATIC_SERVER', 'https://fastfilelink.com')
DEFAULT_SERVER = STATIC_SERVER

EMAIL = 'support@fastfilelink.com'
SUPPORT_URL = 'https://fastfilelink.com/support/'

LANGUAGES = []
# LANGUAGES = ['zh_TW', 'zh_CN']

RETENTION_TIMES = {
    '3 hours': timedelta(hours=3),
    '6 hours': timedelta(hours=6),
    '12 hours': timedelta(hours=12),
    '24 hours': timedelta(days=1),
    '72 hours': timedelta(days=3),
    '1 week': timedelta(days=7),
    '2 weeks': timedelta(days=14),
}

DEFAULT_AUTH_USER_NAME = 'ffl'

logger = getLogger(__name__)


class ExecutionMode(Enum):
    PURE_PYTHON = 1
    COSMOPOLITAN_LIBC = 2
    EXECUTABLE = 3


# Dummy objects for consistent interface when Features addon is not available
class DummyUser:
    """Dummy User implementation for consistent interface"""

    def __init__(self):
        self.serialNumber = '0123456789'
        self.name = None
        self.email = None
        self.points = 0
        self.level = 0 # FREE level

    def isRegistered(self):
        return True # Without FeatureManager, user should be considered as registered.

    def isFreeUser(self):
        return True

    @property
    def updateURL(self):
        return f'{DEFAULT_SERVER}/free'


class DummyFeatureManager(Singleton):
    """Dummy FeatureManager implementation for consistent interface"""

    def initialize(self):
        """Initialize the DummyFeatureManager with dummy user and flags."""
        self._user = DummyUser()
        self._userDataLoaded = True # Dummy is always "loaded"
        self._serialNumberResolved = True # Dummy doesn't need serial resolution

    def checkCompatibility(self):
        return True, PUBLIC_VERSION, PUBLIC_VERSION

    @property
    def user(self):
        return self._user

    def allowUpload(self):
        return False

    def allowFileSize(self, fileSize, domain=None):
        return True

    def getUploadUnavailableMessage(self):
        return "Features not available"

    def getFileSizeWarningMessage(self):
        return ""

    def getNotAllowFileSizeMessage(self):
        return ""

    def getUploadRetentionTimes(self):
        return RETENTION_TIMES

    def shouldShowBonusOffer(self):
        return False

    def isRegisteredUser(self):
        return self._user.isRegistered()

    def getDownloadHandler(self, handlerClass):
        """Dummy implementation - returns original handler class"""
        return handlerClass

    def getWebRTCManager(self, managerClass):
        """Dummy implementation - returns original manager class"""
        return managerClass


# =============================================================================
# API Exception Classes
# =============================================================================


class APIError(Exception):
    """Base exception for API-related errors"""

    def __init__(self, message, statusCode=None, response=None):
        super().__init__(message)
        self.statusCode = statusCode
        self.response = response


class UnauthenticatedError(APIError):
    """Raised when authentication credentials are missing or invalid (401)"""
    pass


class UnauthorizedError(APIError):
    """Raised when authenticated user lacks permission for the requested resource (403)"""
    pass


class DummyAPIHandler:
    """Dummy implementation of APIHandler for testing/fallback"""

    def getServerURL(self):
        return "http://127.0.0.1"

    def get(self, endpoint, params=None, **kwargs):
        """Dummy GET implementation"""
        return {'success': False, 'message': 'Dummy API handler - no real requests made'}

    def post(self, endpoint, data=None, json=None, **kwargs):
        """Dummy POST implementation"""
        return {'success': False, 'message': 'Dummy API handler - no real requests made'}

    def put(self, endpoint, data=None, **kwargs):
        """Dummy PUT implementation"""
        return {'success': False, 'message': 'Dummy API handler - no real requests made'}


# Singleton
class SettingsGetter(Singleton):

    @classmethod
    def getInstance(cls):
        if cls not in cls._instances:
            raise RuntimeError('Get SettingsGetter before initialized it.')
        return cls._instances[cls]

    def initialize(
        self,
        exeMode: ExecutionMode = ExecutionMode.PURE_PYTHON,
        baseDir=None,
        staticRoot=DEFAULT_STATIC_ROOT,
        platform=None,
    ):
        """Initialize the SettingsGetter with execution mode and static root."""
        self._exeMode = exeMode
        self._baseDir = baseDir
        self._staticRoot = staticRoot
        self._platform = platform
        self._featureManager = None # Cache for singleton FeatureManager

        self._addonsManager = AddonsManager.getInstance()
        self._addonsManager.loadAllAddons()

    @property
    def exeMode(self) -> ExecutionMode:
        return self._exeMode

    @property
    def baseDir(self):
        return self._baseDir

    @property
    def staticRoot(self):
        return self._staticRoot

    def isRunOnExecutable(self) -> bool:
        return self._exeMode == ExecutionMode.EXECUTABLE

    def isRunOnCosmopolitanLibc(self) -> bool:
        return self._exeMode == ExecutionMode.COSMOPOLITAN_LIBC

    def isRunOnDevelopment(self) -> bool:
        return self._exeMode == ExecutionMode.PURE_PYTHON

    def isWindows(self):
        return self._platform == "Windows"

    def isLinux(self):
        return self._platform == "Linux"

    def isDarwin(self):
        return self._platform == "Darwin"

    def which(self, binary):
        if not binary:
            return None

        if self.isRunOnCosmopolitanLibc():
            if self.isWindows():
                return shutil.which(f'{binary}.exe' if not binary.endswith('.exe') else binary)

        return shutil.which(binary)

    def hasGUISupport(self):
        """Check if GUI addon is available"""
        return self._checkAddonSupport('GUI')

    def hasUploadSupport(self):
        """Check if Upload addon is available"""
        return self._checkAddonSupport('Upload')

    def hasSupport(self, addonName):
        """Generic function to check if any addon is available"""
        return self._checkAddonSupport(addonName)

    def hasFeaturesSupport(self):
        """Check if Features addon is available"""
        return self._checkAddonSupport('Features')

    def hasTunnelsSupport(self):
        """Check if Tunnels addon is available"""
        return self._checkAddonSupport('Tunnels')

    def isCLIMode(self):
        """Check if application should run in CLI mode"""
        # If --cli is explicitly specified, use CLI mode
        if '--cli' in sys.argv:
            return True

        # If GUI is not available, use CLI mode
        return not self.hasGUISupport()

    def getFeatureManager(self):
        """Get feature manager instance - always returns a result (real or dummy)"""
        # Return cached instance if already created
        if self._featureManager is not None:
            return self._featureManager

        if self.hasFeaturesSupport():
            # Use AddonsManager to get the createFeatureManager function
            createFeatureManager = self._addonsManager.getAddonObject('Features', 'createFeatureManager')
            if createFeatureManager and callable(createFeatureManager):
                featureManager = createFeatureManager(self)
                if featureManager:
                    self._featureManager = featureManager
                    return self._featureManager
                else:
                    # Log but continue to fallback
                    logger.warning(f"Error creating FeatureManager")

        # Always fallback to dummy - ensures consistent interface
        self._featureManager = DummyFeatureManager()
        return self._featureManager

    def getAPIHandler(self, apiType=None, **kwargs):
        """Get API handler instance - always returns a result (real or dummy)"""
        if self.hasSupport('API'):
            # Use AddonsManager to get the createAPIHandler function
            createAPIHandler = self._addonsManager.getAddonObject('API', 'createAPIHandler')
            if createAPIHandler and callable(createAPIHandler):
                return createAPIHandler(apiType, **kwargs)

        # Always fallback to dummy - ensures consistent interface
        return DummyAPIHandler()

    def _checkAddonSupport(self, addonName):
        """
        Check if an addon is available using the AddonsManager.
        This integrates with the centralized addon management system.
        """
        return self._addonsManager.isAddonLoaded(addonName)
