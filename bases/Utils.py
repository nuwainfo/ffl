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
        logger.debug(f"UnicodeEncodeError during print, using fallback encoding: {e}, {sys.stdout.encoding=}")

        # Prefer writing to the buffer in UTF-8 (preserve emoji)
        buf = getattr(sys.stdout, "buffer", None)
        if buf is not None:
            try:
                buf.write(text.encode("utf-8", errors="replace"))
                buf.write(b"\n")
                buf.flush()
                return
            except Exception as e2:
                logger.debug(f"fallback buffer write failed: {e2}")

        # Still not working...:(
        try:
            # Last resort: only use simple substitution when there’s truly no other way.
            safeText = ''.join(ch if ch.isprintable() else '?' for ch in text)
            print(safeText, flush=True)
        except Exception as e3:
            logger.debug(f"fallback character replace write failed: {e3}")
            # Replace unsupported characters with '?' instead of crashing
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
            if default is None:
                return value

            # Automatically detect type based on default value
            if isinstance(default, bool):
                return value == "True"
            elif isinstance(default, int):
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


def parseProxyString(proxyString):
    """
    Parse proxy string and return normalized proxy configuration.

    Accepts formats:
      - host:port (defaults to socks5h://)
      - socks5://host:port
      - socks5h://host:port
      - socks5://user:pass@host:port
      - socks5h://user:pass@host:port
      - http://host:port
      - https://host:port
      - http://user:pass@host:port
      - https://user:pass@host:port

    Returns:
        dict: {
            'type': 'socks5' | 'http',
            'url': 'protocol://[user:pass@]host:port',
            'host': 'host',
            'port': port (int),
            'protocol': 'socks5' | 'socks5h' | 'http' | 'https',
            'username': 'user' or None,
            'password': 'pass' or None
        }
        or None if invalid
    """
    if not proxyString:
        return None

    proxyString = proxyString.strip()
    if not proxyString:
        return None

    # Parse protocol and address
    if "://" in proxyString:
        protocol, _, address = proxyString.partition("://")
        protocol = protocol.lower()
    else:
        # No protocol specified - default to socks5h
        protocol = "socks5h"
        address = proxyString

    # Validate protocol
    if protocol not in ["socks5", "socks5h", "http", "https"]:
        logger.error(f"Invalid proxy protocol: {protocol}. Supported: socks5, socks5h, http, https")
        return None

    # Parse username:password@host:port or host:port
    username = None
    password = None

    if "@" in address:
        # Has credentials
        credentials, _, hostPort = address.rpartition("@")
        if ":" in credentials:
            username, _, password = credentials.partition(":")
        else:
            logger.error(f"Invalid credentials format (expected user:pass@host:port): {proxyString}")
            return None
    else:
        # No credentials
        hostPort = address

    # Parse host:port
    host, sep, portStr = hostPort.rpartition(":")
    if not sep:
        logger.error(f"Invalid proxy format (expected host:port): {proxyString}")
        return None

    try:
        port = int(portStr)
    except ValueError:
        logger.error(f"Invalid proxy port: {portStr}")
        return None

    # Determine proxy type and build normalized URL
    if protocol in ["socks5", "socks5h"]:
        proxyType = "socks5"
        if username and password:
            normalizedUrl = f"socks5h://{username}:{password}@{host}:{port}"
        else:
            normalizedUrl = f"socks5h://{host}:{port}"
    else:  # http or https
        proxyType = "http"
        if username and password:
            normalizedUrl = f"{protocol}://{username}:{password}@{host}:{port}"
        else:
            normalizedUrl = f"{protocol}://{host}:{port}"

    return {
        'type': proxyType,
        'url': normalizedUrl,
        'host': host,
        'port': port,
        'protocol': protocol,
        'username': username,
        'password': password
    }


def setupProxyEnvironment(proxyConfig):
    """
    Setup HTTP_PROXY and HTTPS_PROXY environment variables for requests library.

    Args:
        proxyConfig: dict returned from parseProxyString()
    """
    if not proxyConfig:
        return

    proxyUrl = proxyConfig['url']

    # Set HTTP/HTTPS proxy for requests library (works for both SOCKS5 and HTTP proxies)
    os.environ['HTTP_PROXY'] = proxyUrl
    os.environ['HTTPS_PROXY'] = proxyUrl
    logger.info(f"Proxy configured for HTTP requests: {proxyUrl}")


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


class ObjectProxy:

    def __init__(self, proxied=None):
        # Use super().__setattr__ to avoid going through our own __setattr__
        super().__setattr__("_proxied", proxied)

    @property
    def proxied(self):
        # just return the internal attribute
        return self._proxied

    @proxied.setter
    def proxied(self, obj):
        # set the internal attribute directly
        super().__setattr__("_proxied", obj)

    def __getattr__(self, name):
        if self._proxied is None:
            raise AttributeError("Proxy has no proxied object yet")
        return getattr(self._proxied, name)

    def __setattr__(self, name, value):
        # treat internal/proxy-control attributes specially
        if name in ("_proxied", "proxied"):
            super().__setattr__(name, value)
        else:
            if self._proxied is None:
                raise AttributeError("Proxy has no proxied object yet")
            setattr(self._proxied, name, value)

    def __delattr__(self, name):
        if name == "_proxied":
            super().__delattr__(name)
        else:
            if self._proxied is None:
                raise AttributeError("Proxy has no proxied object yet")
            delattr(self._proxied, name)

    def __call__(self, *args, **kwargs):
        if self._proxied is None:
            raise TypeError("Proxy has no proxied object yet")
        return self._proxied(*args, **kwargs)

    def __len__(self):
        return len(self._proxied)

    def __iter__(self):
        return iter(self._proxied)

    def __getitem__(self, key):
        return self._proxied[key]

    def __setitem__(self, key, value):
        self._proxied[key] = value

    def __delitem__(self, key):
        del self._proxied[key]

    def __str__(self):
        return str(self._proxied)

    def __repr__(self):
        return f"<Proxy for {repr(self._proxied)}>"

    def __eq__(self, other):
        return self._proxied == other

    def __ne__(self, other):
        return self._proxied != other

    def __bool__(self):
        return bool(self._proxied)
