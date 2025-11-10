#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
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

import shutil
import sys
import os

from datetime import timedelta
from enum import Enum

from bases.Kernel import PUBLIC_VERSION, Singleton, AddonsManager, getLogger

DEFAULT_STATIC_ROOT = 'static'
# Default static server for open source users - serves from local directory
STATIC_SERVER = os.getenv('STATIC_SERVER', '.')
DEFAULT_SERVER = STATIC_SERVER

# Transfer chunk size (256 KiB) - used for both WebRTC and HTTP downloads
TRANSFER_CHUNK_SIZE = int(os.getenv('TRANSFER_CHUNK_SIZE', 256 * 1024))

EMAIL = 'support@fastfilelink.com'

# Default support URL for open source users
SUPPORT_URL = 'https://github.com/nuwainfo/ffl/discussions'

# Default copyright for open source users
COPYRIGHT = 'Copyright (c) 2025 FastFileLink Contributors. Licensed under Apache-2.0.'

# Default footer message HTML for open source users (entire HTML block)
FOOTER_MESSAGE_HTML = """<span data-i18n="footer.message">
PS: Wishing you a great day! Download your free file sharing app at</span> 
<a href="https://github.com/nuwainfo/ffl" target="_blank">GitHub</a>
<span data-i18n="footer.period">.</span>
"""

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

    def getSupportURL(self):
        """
        Get support URL. Returns the current SUPPORT_URL value.
        Features addon may overwrite SUPPORT_URL based on user level or GUI support.
        """
        return SUPPORT_URL

    def getCopyright(self):
        """
        Get copyright text. Returns the current COPYRIGHT value.
        Features addon may overwrite COPYRIGHT based on user level or GUI support.
        """
        return COPYRIGHT

    def getFooterMessageHTML(self):
        """
        Get footer message HTML. Returns the current FOOTER_MESSAGE_HTML value.
        Features addon may overwrite FOOTER_MESSAGE_HTML based on user level or GUI support.
        """
        return FOOTER_MESSAGE_HTML

    def getStaticServer(self):
        """
        Get static server URL. Returns the current STATIC_SERVER value.
        Features addon may overwrite STATIC_SERVER based on user level or GUI support.
        """
        return STATIC_SERVER
