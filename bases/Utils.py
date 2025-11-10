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

import json
import locale
import os
import socket
import sys
import webbrowser

import bitmath
import chardet

from itertools import zip_longest

from bases.Kernel import getLogger, PUBLIC_VERSION
from bases.Settings import LANGUAGES, SettingsGetter

ONE_KB = bitmath.KiB(1).bytes
ONE_MB = bitmath.MiB(1).bytes
ONE_GB = bitmath.GiB(1).bytes
ONE_TB = bitmath.TiB(1).bytes

logger = getLogger(__name__)


def utf8(s, encodings=None, throw=True):
    """
    Convert a string (UNICODE or ANSI) to a utf8 string.

    @param s String.
    @param encodings Native encodings for decode. It will be tried to decode
                     string, try and error.
    @param throw Raise exception if it fails to convert string.
    @return UTF8 string.
    """
    if isinstance(s, str):
        return s.encode('utf-8')
    else:
        return _unicode(s, encodings=encodings, throw=throw).encode('utf-8')


_UNICODE_TRY_ENCODINGS = (locale.getlocale()[1],)
# See #2758. for details.
if 'cp950' not in _UNICODE_TRY_ENCODINGS:
    _UNICODE_TRY_ENCODINGS = _UNICODE_TRY_ENCODINGS + ('cp950',)


def _unicode(s, strict=False, encodings=None, throw=True, confidence=0.8):
    """
    Force to UNICODE string (str type in Python 3).

    @param s String.
    @param strict Useless, just for backward compatible.
    @param encodings Native encodings for decode. It will be tried to decode
                     string, try and error.
    @param throw Raise exception if it fails to convert string.
    @param confidence
    @return UNICODE type string.
    """
    # This is unicode() in Python 2 and str in Python 3
    if isinstance(s, str):
        return s
    else:
        if not encodings:
            encodings = []

        if not isinstance(s, bytes):
            return str(s)

        try:
            result = chardet.detect(s)

            if result['confidence'] > confidence:
                if result['encoding']:
                    encodings.append(result['encoding'])
                encodings.extend(_UNICODE_TRY_ENCODINGS)
            else:
                encodings.extend(_UNICODE_TRY_ENCODINGS)
                if result['encoding']:
                    encodings.append(result['encoding'])

        except Exception as e:
            encodings.extend(_UNICODE_TRY_ENCODINGS)

        error = None
        for e in encodings:
            try:
                return s.decode(e)
            except Exception as e:
                error = e

        if throw and error:
            raise error

    return None

def copy2Clipboard(text):
    if not text:
        return

    if sys.platform.startswith('linux'):
        isLinux = True
    else:
        isLinux = False

    if sys.platform.startswith('darwin'):
        os.environ['PATH'] = '/usr/bin:' + os.environ.get('PATH', '')

    try:
        import psutil
        import pyperclip

        if isLinux:
            xclipBefore = list(filter(lambda p: p.name() == "xclip", psutil.process_iter(['pid'])))

        pyperclip.copy(text)
        flushPrint('The link has been copied to the clipboard.')

        if isLinux:
            xclipAfter = list(filter(lambda p: p.name() == "xclip", psutil.process_iter(['pid'])))
            kill = list(set(xclipAfter) - set(xclipBefore))

            for process in kill:
                os.system(f"kill {process.pid}")
    except Exception as e:
        logger.error(f"Clipboard error: {e}")
        logger.exception(e)


# https://github.com/chriskiehl/Gooey/issues/701
# flush is required if this is in .exe file.
def flushPrint(text):
    try:
        print(text, flush=True)
    except UnicodeEncodeError as e:
        # Fallback for terminals that don't support certain characters (e.g., emojis on Windows cp950)
        # Replace unsupported characters with '?' instead of crashing
        logger.debug(f"UnicodeEncodeError during print, using fallback encoding: {e}")
        print(text.encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding), flush=True)


def formatSize(size, decimal=None, plural=None):
    if decimal is None:
        if size < ONE_GB: # Less than 1GB
            decimal = 0
        elif size < ONE_TB: # Between 1GB and 1TB
            decimal = 1
        else: # Greater than 1TB
            decimal = 2

    if plural is None:
        plural = False if size > ONE_KB else True

    sizeStr = bitmath.Byte(size).best_prefix(system=bitmath.SI).format(
        "{value:.%df}{%s}" % (decimal, 'unit_plural' if plural else 'unit')
    )

    if not sizeStr.endswith('Byte') and not sizeStr.endswith('Bytes') and not sizeStr.endswith('Bits'):
        return sizeStr.replace('B', '').upper()
    else:
        return sizeStr.replace('Byte', ' Byte').replace('Bit', ' Byte')


def detectOSLanguage():
    language = locale.getdefaultlocale()[0]

    if language in LANGUAGES:
        return language
    else:
        return 'english'


def getApplicationPath():
    return os.path.dirname(__file__)


def getAvailablePort(port=None):
    """
    Get an available port for the local server.
    
    Args:
        port: Specific port to check (None for auto-detect)
        
    Returns:
        int: Available port number
        
    Raises:
        OSError: If specified port is not available
    """
    if port is not None:
        # Check if specific port is available
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', port))
            sock.close()
            return port
        except OSError:
            sock.close()
            raise OSError(f"Port {port} is already in use or not available")
    else:
        # Auto-detect available port
        sock = socket.socket()
        sock.bind(('', 0))
        ip, port = sock.getsockname()
        sock.close()
        return port


def sendException(logger, e, action=None, errorPrefix="Oops, something went wrong"):
    if e and errorPrefix:
        flushPrint(f'{errorPrefix}: {e}')
    elif e:
        flushPrint(f'{e}')
    else: # only errorPrefix without e?
        logger.error(f'Incorrect argument: {errorPrefix=} {e=}')

    if action:
        flushPrint(action)
    else:
        flushPrint('Please try again or try later.')

    # Get dynamic support URL based on GUI support and user level
    settingsGetter = SettingsGetter.getInstance()
    supportURL = settingsGetter.getSupportURL()
    flushPrint(f'\nIf you still get the same problem, please contact us at {supportURL}.')
    flushPrint('We will fix the problem as soon as possible.\n')

    logger.exception(e)

    if os.getenv('RAISE_EXCEPTION', 'False') == 'True' and isinstance(e, BaseException):
        raise e


def getJSONWriter(args, fileSize, link, tunnelType=None, e2ee=False):
    settingsGetter = SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()
    user = featureManager.user

    if hasattr(args, 'json') and args.json:
        outputData = {
            "file": args.file,
            "file_size": fileSize,
            "upload_mode": "server" if args.upload else "p2p",
            "tunnel_type": tunnelType or "default",
            "link": link,
            "e2ee": e2ee,
            "user": {
                "user": user.name,
                "email": user.email,
                "level": user.level,
                "points": user.points,
                "serial_number": user.serialNumber
            }
        }

        def writeJSON():
            try:
                with open(args.json, 'w', encoding='utf-8') as f:
                    json.dump(outputData, f, indent=2)
                flushPrint(f"Sharing information saved to {args.json}")
            except Exception as e:
                flushPrint(f"Failed to write JSON file: {e}")
                sendException(logger, e)

        return writeJSON
    else:
        return None


# Helper functions for environment variable configuration
def getEnv(envVar, default):
    """Safely get value from environment variable with automatic type detection based on default"""
    try:
        value = os.getenv(envVar)
        if value is not None:
            # Automatically detect type based on default value
            if isinstance(default, int):
                return int(value)
            elif isinstance(default, float):
                return float(value)
            elif isinstance(default, str):
                return str(value)
            else:
                # For other types, try to convert to same type as default
                return type(default)(value)
        return default
    except (ValueError, TypeError):
        return default


def compareVersions(version1, version2):
    """
    Compare two version strings (e.g., "3.6.0" vs "10.10")
    
    Returns:
        int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
    """

    def parseVersionNumbers(versionStr):
        """Parse version string to list of integers"""
        try:
            return [int(x) for x in str(versionStr).split('.')]
        except (ValueError, AttributeError):
            logger.warning(f"Invalid version format: {versionStr}")
            return [0] # Default to 0 for invalid versions

    v1Numbers = parseVersionNumbers(version1)
    v2Numbers = parseVersionNumbers(version2)

    # Compare each component, filling missing parts with 0
    for x, y in zip_longest(v1Numbers, v2Numbers, fillvalue=0):
        if x != y:
            return -1 if x < y else 1

    return 0 # Versions are equal


def checkVersionCompatibility():
    """
    Check version compatibility with server and return version information
    
    Returns:
        tuple: (serverIsNewer, isCompatible, serverVersion, minimumVersion)
    """
    settingsGetter = SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()
    isCompatible, serverVersion, minimumVersion = featureManager.checkCompatibility()

    serverIsNewer = compareVersions(serverVersion, PUBLIC_VERSION) > 0

    return serverIsNewer, isCompatible, serverVersion, minimumVersion


def validateCompatibleWithServer(action=flushPrint):
    serverIsNewer, isCompatible, serverVersion, minimumVersion = checkVersionCompatibility()
    if not isCompatible:
        action("⚠️ VERSION INCOMPATIBLE: Please update to continue using the service.")
        settingsGetter = SettingsGetter.getInstance()
        featureManager = settingsGetter.getFeatureManager()
        user = featureManager.user
        webbrowser.open(user.updateURL)
        return False
    return True
