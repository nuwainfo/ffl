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

import base64
import contextlib
import hashlib
import os
import re
import sys
import threading
import time
import urllib.parse

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple, Callable
from urllib.parse import urlparse, unquote

import requests

from bases.Checksum import DEFAULT_CHECKSUM_ALGORITHM
from bases.Kernel import getLogger
from bases.Utils import formatSize, getEnv, StallResilientAdapter
from bases.Progress import Progress
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.E2EE import E2EEClient
from bases.Readers import FolderChangedException
from bases.crypto import CryptoInterface
from bases.I18n import _

logger = getLogger(__name__)


@dataclass
class URLInfo:
    """Information extracted from a download URL"""
    baseURL: str # Base URL with trailing slash
    uid: str # UID (empty for custom tunnels or generic URLs)
    supportsWebRTC: bool # Whether WebRTC is supported
    isGenericURL: bool # Whether this is a generic HTTP URL (not FastFileLink)
    e2eeEnabled: bool = False # Whether E2EE encryption is enabled
    isUploadMode: bool = False # Whether this is an uploaded file (not P2P)
    urlFragment: str = "" # URL fragment (e.g., #key for E2EE upload mode)


class Downloader(ABC):
    """
    Generic base class for downloading a FastFileLink (or generic HTTP) URL.

    Holds all transport-agnostic state and helpers: URL parsing, HTTP
    metadata/HEAD requests, resume logic, checksum verification, E2EE
    context construction, and progress-bar management. Concrete transports
    are added via subclassing/mixins — see HTTPDownloader below and
    WebRTCDownloadMixin in bases/WebRTC.py.
    """

    _PROGRESS_BAR_FORMAT = '{desc} {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]{postfix}'

    _STATUS_CONNECTING = _("Connecting to server")
    _STATUS_REQUESTING = _("Requesting connection")
    _STATUS_DOWNLOADING = _("Downloading")
    _STATUS_HTTP_DOWNLOAD = _("HTTP download")
    _STATUS_HTTP_FALLBACK = _("HTTP fallback")
    _STATUS_FILE_COMPLETE = _("File already downloaded")
    _STATUS_METADATA = _("Getting file metadata")

    CHECKSUM_READY_POLL_RETRIES = 10
    CHECKSUM_READY_POLL_INTERVAL = 0.2

    @staticmethod
    def _isKnownSize(fileSize: int) -> bool:
        """Check if file size is known (not None or negative)"""
        return fileSize is not None and fileSize >= 0

    @staticmethod
    def _isPositiveSize(fileSize: int) -> bool:
        """Check if file size is known and positive (> 0)"""
        return fileSize is not None and fileSize > 0

    def __init__(self, loggerCallback: Callable = print, progressCallback: Optional[Callable] = None):
        self.loggerCallback = loggerCallback
        self.progressCallback = progressCallback
        self._currentProgress = None
        self._e2eeClient = None

    def _updateProgressStatus(self, progress, description):
        """Update progress bar description and refresh display"""
        progress.setDescription(description)
        if progress.useBar and progress.pbar:
            progress.pbar.refresh()

    def _ensureProgress(self, fileSize: int, desc: str, resumePosition: int = 0) -> Progress:
        """Ensure progress bar exists and is configured correctly - reuse if exists, create if needed"""
        if self._currentProgress:
            self._updateProgressStatus(self._currentProgress, desc)
            # Update to resume position if provided and greater than current
            if resumePosition > self._currentProgress.transferred:
                self._currentProgress.update(resumePosition)
            return self._currentProgress

        # Create new progress bar
        # For unknown sizes, use None to let Progress class choose appropriate format
        settingsGetter = SettingsGetter.getInstance()
        barFormat = None if not self._isKnownSize(fileSize) else self._PROGRESS_BAR_FORMAT

        self._currentProgress = Progress(
            fileSize,
            sizeFormatter=formatSize,
            loggerCallback=self.loggerCallback,
            useBar=settingsGetter.isCLIMode(),
            barFormat=barFormat
        )
        self._currentProgress.setDescription(desc)
        if resumePosition > 0:
            self._currentProgress.update(resumePosition)
        return self._currentProgress

    def _finishProgress(self, complete: bool = True):
        """Finish and clean up progress bar"""
        if self._currentProgress:
            self._currentProgress.finishBar(complete=complete)
            self._currentProgress = None

    def _finishAlreadyComplete(self, fileSize: int, resumePosition: int, finalOutputPath: str, sharedProgress=None):
        """Unified helper for file already complete scenario

        Args:
            fileSize: Total file size
            resumePosition: Current file position (should equal fileSize)
            finalOutputPath: Path to the complete file
            sharedProgress: Optional shared progress bar from WebRTC download
        """
        if sharedProgress:
            self._updateProgressStatus(sharedProgress, self._STATUS_FILE_COMPLETE)
            sharedProgress.update(fileSize, forceLog=True, extraText="HTTP fallback")
        else:
            progress = self._ensureProgress(fileSize, self._STATUS_FILE_COMPLETE, resumePosition)
            progress.update(fileSize, forceLog=True, extraText="HTTP fallback")
        self._finishProgress()
        logger.debug(f"File already downloaded: {finalOutputPath}")
        return finalOutputPath

    def _createAuthHeaders(self, credentials: Optional[Tuple[str, str]]) -> dict:
        """Create HTTP Basic Auth headers if credentials provided"""
        if not credentials:
            return {}

        username, password = credentials
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _makeHeaders(
        self, credentials: Optional[Tuple[str, str]], extra: Optional[dict] = None, userAgent: bool = True
    ) -> dict:
        """Create headers with auth and optional extra headers

        Args:
            credentials: Optional (username, password) tuple for Basic Auth
            extra: Optional additional headers
            userAgent: If True, add User-Agent header (default: True for better compatibility)
        """
        headers = self._createAuthHeaders(credentials)

        # Add User-Agent to mimic browser for better website compatibility
        if userAgent:
            headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )

        if extra:
            headers.update(extra)
            
        return headers

    def _buildURL(self, base: str, path: str, excludeUID: bool = False, **params) -> str:
        """Build URL with optional query parameters

        Args:
            base: Base URL (may include UID like https://domain.com/uid/)
            path: Path to append (e.g., "/download", "/e2ee/manifest")
            excludeUID: If True, strip UID from base before appending path
            **params: Query parameters

        Returns:
            Complete URL
        """
        # Filter out None values
        queryParams = {k: str(v) for k, v in params.items() if v is not None}

        # Strip UID from base if requested (for E2EE endpoints)
        if excludeUID:
            # Extract domain without UID: https://domain.com/uid/ -> https://domain.com
            match = re.match(r'(https://[^/]+)/[^/]+/?$', base)
            if match:
                base = match.group(1)

        # Ensure we don't create double slashes
        base = base.rstrip('/')
        path = '/' + path.lstrip('/')

        url = base + path
        if queryParams:
            url += "?" + urllib.parse.urlencode(queryParams)
            
        return url

    def _shouldVerifyChecksum(self, urlInfo: URLInfo, resumePosition: int) -> bool:
        """Checksum verification is only meaningful for full FastFileLink transfers."""
        return (not urlInfo.isGenericURL) and resumePosition == 0

    def _createTransferChecksumState(self, enabled: bool, algorithm: str = DEFAULT_CHECKSUM_ALGORITHM) -> Optional[dict]:
        if not enabled:
            return None

        return {'hasher': hashlib.new(algorithm), 'size': 0, 'checksum': None}

    def _updateTransferChecksumState(self, checksumState: Optional[dict], data: bytes):
        if not checksumState or not data:
            return

        checksumState['hasher'].update(data)
        checksumState['size'] += len(data)

    def _finalizeTransferChecksumState(self, checksumState: Optional[dict]) -> Optional[str]:
        if not checksumState:
            return None

        checksum = checksumState.get('checksum')
        if checksum:
            return checksum

        checksum = checksumState['hasher'].hexdigest()
        checksumState['checksum'] = checksum
        return checksum

    def _fetchReadyRemoteChecksum(self, baseURL: str, headers: dict) -> Optional[dict]:
        checksumURL = self._buildURL(baseURL, "checksum")

        for attemptIndex in range(self.CHECKSUM_READY_POLL_RETRIES):
            responseData, statusCode = self._sendHTTPRequest(checksumURL, "GET", None, headers, 10)

            if statusCode == 200 and isinstance(responseData, dict) and responseData.get('ready'):
                return responseData

            if attemptIndex + 1 < self.CHECKSUM_READY_POLL_RETRIES:
                time.sleep(self.CHECKSUM_READY_POLL_INTERVAL)

        return None

    def _verifyTransferChecksum(
        self, baseURL: str, headers: dict, checksumState: Optional[dict], expectedTransport: str
    ):
        localChecksum = self._finalizeTransferChecksumState(checksumState)
        if not localChecksum:
            return

        remoteData = self._fetchReadyRemoteChecksum(baseURL, headers)
        if not remoteData:
            logger.debug("Checksum endpoint not ready after transfer, skip strict checksum verification")
            return

        remoteTransport = remoteData.get('transport')
        if remoteTransport and remoteTransport != expectedTransport:
            logger.debug(
                f"Checksum transport mismatch (remote={remoteTransport}, local={expectedTransport}), skip verify"
            )
            return

        remoteChecksum = str(remoteData.get('checksum', '')).lower()
        if not remoteChecksum:
            raise RuntimeError("Checksum verification failed: remote checksum is empty")

        localChecksum = localChecksum.lower()
        if remoteChecksum != localChecksum:
            raise RuntimeError(f"Checksum verification failed: local={localChecksum}, remote={remoteChecksum}")

        remoteSize = remoteData.get('size')
        localSize = checksumState.get('size', 0)
        if isinstance(remoteSize, int) and remoteSize >= 0 and remoteSize != localSize:
            raise RuntimeError(f"Checksum size mismatch: local={localSize}, remote={remoteSize}")

        self.loggerCallback(_("Checksum verified"))

    @property
    def e2eeClient(self):
        """Lazy initialization of E2EEClient to ensure methods are available"""
        if self._e2eeClient is None:
            self._e2eeClient = E2EEClient(self._buildURL, self._makeHeaders)
            
        return self._e2eeClient

    def _getUploadModeEncryptionKey(self, urlFragment: str) -> bytes:
        """Get encryption key for upload mode - from URL fragment or user prompt

        Args:
            urlFragment: URL fragment that may contain the encryption key

        Returns:
            Raw encryption key bytes (32 bytes for AES-256)

        Raises:
            ValueError: If key is invalid or user doesn't provide one
        """
        # First check URL fragment for key
        if urlFragment:
            keyBase64 = urlFragment.strip()
            try:
                key = base64.b64decode(keyBase64)
                if len(key) == 32: # AES-256 requires 32 bytes
                    logger.debug("Using encryption key from URL fragment")
                    return key
                else:
                    logger.warning(f"Key from URL fragment has invalid length: {len(key)} bytes (expected 32)")
            except Exception as e:
                logger.warning(f"Failed to decode key from URL fragment: {e}")

        # Prompt user for key
        self.loggerCallback(_("\n⚠️  This file is encrypted. Please enter the encryption key:"))
        self.loggerCallback(_("(The key should be provided by the person who shared this file)\n"))

        try:
            keyInput = input(_("Encryption key: ")).strip()
            if not keyInput:
                raise ValueError(_("Encryption key is required to download this file"))

            # Decode base64 key
            key = base64.b64decode(keyInput)
            if len(key) != 32:
                raise ValueError(_("Invalid key length: {keyLength} bytes (expected 32 bytes for AES-256)").format(
                    keyLength=len(key)))

            return key
        except KeyboardInterrupt:
            raise RuntimeError(_("Download cancelled by user"))
        except Exception as e:
            raise ValueError(_("Invalid encryption key: {error}").format(error=e))

    def _getRemoteMetadata(self, url: str, headers: dict, isGenericURL: bool = False) -> Tuple[int, str, dict]:
        """Get file size and name from remote server using HEAD request

        Args:
            url: For generic URLs, this is the full URL; for FastFileLink URLs, this is the base URL
            headers: HTTP headers to include
            isGenericURL: If True, use URL directly; if False, append /download endpoint
        """
        # For generic URLs, use URL directly; for FastFileLink, append /download
        headURL = url if isGenericURL else self._buildURL(url, "download")
        head = self._sendHTTPHead(headURL, headers)
        fileSize = int(head.get("Content-Length", "0") or 0)
        if fileSize == 0: # Well, in Caddy case, it always return 0.
            fileSize = int(head.get("FFL-FileSize", "0") or 0)

        # For generic URLs, extract filename from URL if no Content-Disposition header
        if isGenericURL and "Content-Disposition" not in head:
            # Extract filename from URL path
            parsedURL = urlparse(url)
            fileName = unquote(parsedURL.path.split('/')[-1]) or 'index.html'
        else:
            fileName = self._parseFileInfo(head.get("Content-Disposition", 'attachment; filename=download.bin'))

        return fileSize, fileName, head

    def _resolveOutputPath(self, outputPath: Optional[str], fileName: str) -> str:
        """Resolve output path handling directory vs file path cases"""
        if outputPath == "-":
            return "-"

        if outputPath:
            return os.path.join(outputPath, fileName) if os.path.isdir(outputPath) else outputPath

        return fileName

    def _sendHTTPRequest(
        self,
        url: str,
        method: str = "GET",
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: int = 30
    ) -> Tuple[any, int]:
        """Make HTTP request using requests library"""
        requestHeaders = headers or {}

        try:
            if method == "GET":
                response = requests.get(url, headers=requestHeaders, timeout=timeout)
            elif method == "POST":
                requestHeaders["Content-Type"] = "application/json"
                response = requests.post(url, json=data, headers=requestHeaders, timeout=timeout)
            else:
                # Generic method support
                response = requests.request(
                    method, url, json=data if data else None, headers=requestHeaders, timeout=timeout
                )

            # Handle expected status codes for candidate polling
            if response.status_code in (204, 404):
                return None, response.status_code

            # Raise for other error status codes
            response.raise_for_status()

            # Try to parse JSON response
            if requestHeaders.get("Content-Type") == "application/json" or method == "GET":
                try:
                    return response.json(), response.status_code
                except ValueError:
                    return response.text, response.status_code
            else:
                return response.text, response.status_code

        except requests.exceptions.HTTPError as e:
            # Re-raise with status code if needed
            if e.response and e.response.status_code in (204, 404):
                return None, e.response.status_code
            raise

    def _sendHTTPHead(self, url: str, headers: Optional[dict] = None) -> dict:
        """Make HTTP HEAD request to get headers using requests library

        Automatically handles Caddy quirk where HEAD returns Content-Length: 0
        by retrying with GET when detected.
        """
        response = requests.head(url, headers=headers or {}, timeout=10)
        response.raise_for_status()
        head = response.headers

        # Check if Caddy returns Content-Length: 0 (Caddy quirk with HEAD requests)
        serverHeader = head.get('Server', '')
        contentLength = head.get('Content-Length', '')
        isCaddyWithZeroLength = ('Caddy' in serverHeader and contentLength == '0')

        # If Caddy returns Content-Length: 0, retry with GET to get proper headers
        if isCaddyWithZeroLength:
            logger.debug("Caddy returned Content-Length: 0 for HEAD, retrying with GET")
            response = requests.get(url, headers=headers or {}, timeout=10, stream=True)
            head = response.headers
            response.close() # Close immediately after getting headers

        return head # Return CaseInsensitiveDict for case-insensitive header access

    def _parseFileInfo(self, contentDisposition: str) -> str:
        """Parse filename from Content-Disposition header"""
        # Try RFC 5987 encoded filename first (handles UTF-8 properly)
        match = re.search(r"filename\*=UTF-8''([^;]+)", contentDisposition)
        if match:
            return urllib.parse.unquote(match.group(1))

        # Try standard filename parameter
        match = re.search(r'filename="?([^";]+)"?', contentDisposition)
        if match:
            # URL decode in case it's percent-encoded
            return urllib.parse.unquote(match.group(1))

        return "download.bin"

    def _handleResumeLogic(self, filePath: str, fileSize: int, allowResume: bool) -> int:
        """
        Handle resume logic for downloads

        Args:
            filePath: Path to output file
            fileSize: Total size of file to download (None or -1 for unknown)
            allowResume: Whether to resume (True) or overwrite (False)

        Returns:
            Resume position in bytes (0 for new download)
        """
        if filePath == "-":
            return 0

        if not os.path.exists(filePath):
            return 0

        currentSize = os.path.getsize(filePath)

        # Handle unknown file size (None or -1)
        if not self._isKnownSize(fileSize):
            if allowResume and currentSize > 0:
                # forceResume=True (WebRTC→HTTP fallback): partial file has valid data, resume from it
                logger.debug(f"Unknown size file with forceResume - resuming from {formatSize(currentSize)}: {filePath}")
                return currentSize
            if currentSize > 0:
                logger.info(f"Unknown size file - overwriting existing {formatSize(currentSize)} file: {filePath}")
            os.remove(filePath)
            return 0

        # Known file size - handle resume or overwrite
        if not allowResume:
            # Overwrite existing file
            logger.debug(f"Overwriting existing file: {filePath}")
            os.remove(filePath)
            return 0

        # Resume mode - check if already complete
        if currentSize >= fileSize:
            return currentSize

        # Resume from current position
        if currentSize > 0:
            logger.debug(f"Resuming from {formatSize(currentSize)} / {formatSize(fileSize)}")
            
        return currentSize

    def _extractURLInfo(self, url: str) -> URLInfo:
        """Extract base URL and UID from FastFileLink URL, validate it's downloadable

        This method handles three scenarios:
        1. fastfilelink.com domain - format: https://domain.fastfilelink.com/UID
        2. Custom tunnel domains - validate by checking Server header
        3. Generic HTTP URLs - treat as direct download URLs (like wget)

        Special case: Local test server uses format http://127.0.0.1:5000/port/UID
        where 'port' is a numeric port identifier and 'UID' is the actual share ID.

        Returns:
            URLInfo: Object containing URL information and validation results

        Raises:
            ValueError: If URL is not accessible or invalid
        """
        # Extract domain and URL fragment from URL
        parsedURL = urllib.parse.urlparse(url)
        domain = parsedURL.netloc
        urlFragment = parsedURL.fragment # Extract #key for E2EE upload mode

        # Try to extract UID from URL
        uid = ""
        baseURL = ""
        supportsWebRTC = True # Assume WebRTC is supported by default

        # Strip query and fragment for pattern matching
        urlForMatching = url.split('?')[0].split('#')[0]

        # Check if original URL ended with / (before query/fragment)
        endsWithSlash = urlForMatching.endswith('/')

        # Match the entire path and extract UID
        match = re.search(r'(https?://[^/]+)(/.+?)/?$', urlForMatching)
        if match:
            domainPart = match.group(1)
            pathPart = match.group(2)
            # Extract path segments
            pathSegments = [seg for seg in pathPart.split('/') if seg]

            if pathSegments:
                # Special case: Local test server (127.0.0.1) with /port/UID format
                # Pattern: http://127.0.0.1:5000/4444/DPnpNKWs
                # Here '4444' is a port identifier (numeric) and 'DPnpNKWs' is the UID
                isLocalTestServer = '127.0.0.1' in domain or 'localhost' in domain

                if isLocalTestServer and len(pathSegments) >= 2 and pathSegments[0].isdigit():
                    # Test server format: /port/UID
                    # Use last segment as UID, keep full path in baseURL
                    uid = pathSegments[-1]
                    baseURL = domainPart + pathPart.rstrip('/')
                else:
                    # Standard format: /UID or custom tunnel
                    # Last segment is the UID
                    uid = pathSegments[-1]
                    baseURL = domainPart + pathPart.rstrip('/')
            else:
                # No path segments
                baseURL = urlForMatching.rstrip('/')
                uid = ""
        else:
            # Custom tunnel without UID (e.g., https://custom.domain.com/)
            # Use the URL without query/fragment as base, will validate via HEAD request
            baseURL = urlForMatching.rstrip('/')

        # Only append / if original URL ended with /
        if endsWithSlash and not baseURL.endswith('/'):
            baseURL += '/'

        try:
            # Try HEAD request to base URL first (Caddy quirk handled automatically)
            head = self._sendHTTPHead(baseURL.rstrip('/'), self._makeHeaders(None))

            # Check if this is a FastFileLink server
            isFastFileLinkDomain = 'fastfilelink.com' in domain
            serverHeader = head.get('Server', '')
            fflServerHeader = head.get('FFL-Server', '')
            fflMode = head.get('FFL-Mode', '')
            isFastFileLinkServer = serverHeader.startswith('FFL Server/') or bool(fflServerHeader)

            if not isFastFileLinkDomain and not isFastFileLinkServer and not fflMode:
                # Not a FastFileLink server? TRY /download:
                head = self._sendHTTPHead(f"{baseURL.rstrip('/')}/download", self._makeHeaders(None))
                fflMode = head.get('FFL-Mode', '')
                if not fflMode:
                    #  fall through to generic URL handling
                    raise requests.exceptions.RequestException("Not a FastFileLink server")

            # For fastfilelink.com, check if UID starts with "0." (upload mode, WebRTC not supported)
            if isFastFileLinkDomain and uid.startswith("0."):
                logger.info(f"UID {uid} is upload mode (starts with '0.'), WebRTC not supported")
                supportsWebRTC = False

            # Check FFL-Mode header for E2EE, WebRTC support, and upload mode
            e2eeEnabled = '+E2EE' in fflMode
            isUploadMode = '+Upload' in fflMode
            if 'HTTP' in fflMode and 'P2P' not in fflMode:
                supportsWebRTC = False

            return URLInfo(
                baseURL,
                uid,
                supportsWebRTC,
                isGenericURL=False,
                e2eeEnabled=e2eeEnabled,
                isUploadMode=isUploadMode,
                urlFragment=urlFragment
            )

        except requests.exceptions.RequestException as e:
            logger.debug(
                f"No /download endpoint found (network error or endpoint doesn't exist), "
                f"treating as generic HTTP URL: {e}"
            )

            # Verify the URL itself is accessible (use consistent headers for better compatibility)
            head = self._sendHTTPHead(url, self._makeHeaders(None))
            # This is a valid generic HTTP URL
            return URLInfo(
                baseURL=url, # Use original URL as-is
                uid="",
                supportsWebRTC=False,
                isGenericURL=True
            )

    def _startStatusPollingThread(
        self,
        baseURL: str,
        authHeaders: dict,
        stopEvent: threading.Event,
        errorQueue: deque,
        onError: Optional[Callable[[Exception], None]] = None
    ):
        """
        Start background thread to poll server status for errors (unified for WebRTC and HTTP)

        Args:
            baseURL: Base URL for the download
            authHeaders: Authentication headers
            stopEvent: Threading event to signal when to stop polling
            errorQueue: Deque to store detected errors (thread-safe, lock-free reads)
        """

        def pollingWorker():
            statusURL = self._buildURL(baseURL, "status", excludeUID=False)
            pollInterval = 0.5 # Poll every 0.5 seconds for faster error detection

            logger.debug(f"[STATUS_POLL] Background thread started, URL: {statusURL}")

            while not stopEvent.is_set():
                try:
                    # Poll status endpoint
                    logger.debug(f"[STATUS_POLL] Polling status endpoint...")
                    statusData, status = self._sendHTTPRequest(statusURL, "GET", None, authHeaders, 5)

                    hasError = statusData.get('error') if statusData else None
                    logger.debug(f"[STATUS_POLL] Status response: {status}, has error: {hasError}")

                    if status == 200 and statusData:
                        error = statusData.get('error')
                        if error:
                            errorType = error.get('type', 'unknown')
                            errorDetail = error.get('detail', 'Server reported an error')
                            exceptionClass = error.get('exceptionClass', '')

                            logger.debug(f"[STATUS_POLL] Server error detected: {errorType}")

                            # Create appropriate exception based on server error class
                            if exceptionClass == FolderChangedException.__name__:
                                exception = FolderChangedException(errorDetail)
                            else:
                                exception = RuntimeError(errorDetail)

                            # Add to error queue (thread-safe append, no lock needed)
                            errorQueue.append(exception)

                            if onError:
                                try:
                                    onError(exception)
                                except Exception as callbackError:
                                    logger.debug(f"[STATUS_POLL] onError callback failed: {callbackError}")

                            logger.debug("[STATUS_POLL] Error added to queue, stopping polling")
                            return

                    # Wait before next poll (check stopEvent periodically)
                    stopEvent.wait(pollInterval)

                except Exception as e:
                    # Log but don't fail - status polling is best-effort
                    logger.debug(f"[STATUS_POLL] Polling error (non-fatal): {e}")
                    if not stopEvent.is_set():
                        stopEvent.wait(pollInterval)

            logger.debug("[STATUS_POLL] Background thread stopped")

        # Start background daemon thread
        thread = threading.Thread(target=pollingWorker, daemon=True, name="StatusPolling")
        thread.start()
        return thread

    def _fetchChecksumData(self, urlInfo) -> dict:
        """Fetch /checksum once. Always returns a dict with at least 'algorithm'.
        Also contains 'encryptedChallenges' when pubkey auth is enabled on the server."""
        checksumURL = self._buildURL(urlInfo.baseURL, "checksum")
        response = requests.get(checksumURL, timeout=15)
        response.raise_for_status()
        return response.json()

    def _resolveProof(self, checksumData: dict, recipientPrivateKeySpec: Optional[str]) -> Optional[str]:
        """Decrypt an RSA-OAEP challenge from checksumData['encryptedChallenges'], return base64 proof."""
        if not recipientPrivateKeySpec:
            return None

        encryptedChallenges = checksumData.get('encryptedChallenges') or []

        if not encryptedChallenges:
            return None

        with open(recipientPrivateKeySpec, 'r', encoding='utf-8') as f:
            privKeyPem = f.read()

        crypto = CryptoInterface()
        for encryptedChallenge in encryptedChallenges:
            try:
                challengeCiphertext = base64.b64decode(encryptedChallenge)
                challenge = crypto.decryptRSAOAEP(privKeyPem, challengeCiphertext)
                return base64.b64encode(challenge).decode()
            except Exception:
                logger.debug('Recipient private key did not match one pubkey challenge')

        return None

    def _resolveDownloadContext(self, url: str, credentials: Optional[Tuple[str, str]],
                                 recipientPrivateKey: Optional[str] = None) -> dict:
        """
        Perform the one-time, transport-agnostic setup shared by every concrete
        downloadFile() implementation: resolve URLInfo, fetch checksum metadata,
        resolve pubkey proof, and build E2EE context (including any user prompt).

        Must be called exactly ONCE per downloadFile() invocation, by whichever
        concrete downloadFile() is entered first — never via super().downloadFile()
        chaining, to avoid duplicate HEAD/checksum requests and duplicate
        input()-prompting for E2EE keys.
        """
        try:
            urlInfo = self._extractURLInfo(url)
        except (ValueError, requests.exceptions.RequestException) as e:
            raise RuntimeError(f"Invalid download URL: {e}")

        checksumData = {} if urlInfo.isGenericURL else self._fetchChecksumData(urlInfo)
        proof = self._resolveProof(checksumData, recipientPrivateKey)
        checksumAlgorithm = checksumData.get('algorithm', DEFAULT_CHECKSUM_ALGORITHM)

        e2eeContext = None
        if not urlInfo.isGenericURL and urlInfo.e2eeEnabled:
            self.loggerCallback(_("🔒 End-to-end encryption detected"))

            # Get encryption key for upload mode (from URL fragment or user input)
            contentKey = self._getUploadModeEncryptionKey(urlInfo.urlFragment) if urlInfo.isUploadMode else None

            # Build E2EE context (handles both upload and P2P modes)
            # Returns None if E2EE is not actually enabled (e.g., manifest endpoint returns 404)
            e2eeContext = self.e2eeClient.buildE2EEContext(urlInfo.baseURL, urlInfo.isUploadMode, contentKey)

            if e2eeContext and urlInfo.isUploadMode:
                self.loggerCallback(_("✓ Encryption key verified successfully"))

        return {
            'urlInfo': urlInfo,
            'checksumData': checksumData,
            'checksumAlgorithm': checksumAlgorithm,
            'proof': proof,
            'e2eeContext': e2eeContext,
        }

    @abstractmethod
    def downloadFile(self, url: str, outputPath: Optional[str] = None, credentials: Optional[Tuple[str, str]] = None,
                      resume: bool = False, pickupCode: Optional[str] = None,
                      recipientPrivateKey: Optional[str] = None) -> str:
        """Download url and return the local output path. Concrete transports must implement this."""

    def close(self):
        """No-op by default; overridden by transports holding resources (e.g. an event loop thread)."""
        pass


class HTTPDownloader(Downloader):
    """Downloader that only ever uses plain HTTP(S) — no P2P transport."""

    HTTP_CONNECT_TIMEOUT = getEnv('HTTP_CONNECT_TIMEOUT', 10)
    # Read timeout: 10 minutes to handle large file stalls
    HTTP_READ_TIMEOUT = getEnv('HTTP_READ_TIMEOUT', 600)

    def _downloadViaHTTP(
        self,
        url: str,
        outputPath: Optional[str] = None,
        credentials: Optional[Tuple[str, str]] = None,
        sharedProgress=None,
        resume: bool = False,
        forceResume: bool = False,
        e2eeContext: Optional[dict] = None,
        urlInfo=None,
        checksumAlgorithm: str = DEFAULT_CHECKSUM_ALGORITHM,
        pickupCode: Optional[str] = None,
        proof: Optional[str] = None
    ) -> str:
        """
        Download file via HTTP with resume capability as fallback

        Args:
            resume: If True, resume incomplete download; if False, overwrite existing file
            forceResume: If True, always resume from existing file (used for WebRTC fallback)
            urlInfo: Optional pre-parsed URL info to avoid redundant parsing
        """

        # Parse the original URL to get base URL and construct download endpoint
        # Follow same pattern as DownloadManager.js: /{uid}/download
        if urlInfo is None:
            urlInfo = self._extractURLInfo(url)

        # For generic URLs, use the URL directly; otherwise construct /download endpoint
        if urlInfo.isGenericURL:
            downloadURL = urlInfo.baseURL # Use original URL as-is for generic downloads
        else:
            # Construct the download URL (same as web interface)
            downloadURL = self._buildURL(urlInfo.baseURL, "download")

        # Build auth headers for pickup code and pubkey proof
        authExtra = {}
        if pickupCode:
            authExtra['X-FFL-Pickup'] = pickupCode
        if proof:
            authExtra['X-FFL-Proof'] = proof

        # Get file metadata using HEAD request - always respect Content-Disposition from server
        if sharedProgress:
            self._updateProgressStatus(sharedProgress, self._STATUS_METADATA)
        try:
            headers = self._makeHeaders(credentials, authExtra if authExtra else None)
            # For generic URLs, use the actual URL directly; for FastFileLink URLs, use baseURL
            metadataURL = url if urlInfo.isGenericURL else urlInfo.baseURL
            fileSize, fileName, metadataHeaders = self._getRemoteMetadata(
                metadataURL, headers, isGenericURL=urlInfo.isGenericURL
            )
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                raise RuntimeError("File not found or expired")
            raise RuntimeError(f"Failed to get file metadata: HTTP {e.response.status_code if e.response else 'error'}")
        except Exception as e:
            raise RuntimeError(f"Failed to get file metadata: {e}")

        # Resolve output path using helper
        finalOutputPath = self._resolveOutputPath(outputPath, fileName)

        # Handle resume logic (forceResume takes precedence for WebRTC fallback)
        resumePosition = self._handleResumeLogic(finalOutputPath, fileSize, forceResume or resume)
        verifyChecksum = self._shouldVerifyChecksum(urlInfo, resumePosition)

        # File already complete - early return (skip check for unknown/unreliable sizes)
        if (
            self._isPositiveSize(fileSize) and resumePosition >= fileSize and
            not (urlInfo.isGenericURL and fileSize == 0)
        ):
            return self._finishAlreadyComplete(fileSize, resumePosition, finalOutputPath, sharedProgress)

        # Show resume message if resuming (only when not using shared progress and size is known)
        if resumePosition > 0 and not sharedProgress and self._isPositiveSize(fileSize):
            self.loggerCallback(_("Resuming download from {resumePos} / {totalSize}").format(
                resumePos=formatSize(resumePosition), totalSize=formatSize(fileSize)
            ))

        # Use shared progress or create new one
        if sharedProgress:
            progress = sharedProgress
            self._updateProgressStatus(progress, self._STATUS_HTTP_DOWNLOAD)
            # Update progress to current resume position if needed
            if resumePosition > 0 and resumePosition > progress.transferred:
                progress.update(resumePosition)
        else:
            progress = self._ensureProgress(fileSize, self._STATUS_HTTP_DOWNLOAD, resumePosition)

        # Set range header for resume using helper
        rangeHeader = {'Range': f'bytes={resumePosition}-'} if resumePosition > 0 else None
        downloadHeaders = self._makeHeaders(credentials, {**(rangeHeader or {}), **authExtra})

        # Initialize E2EE stream decryptor if enabled (tags fetched on-demand)
        streamDecryptor = None
        if e2eeContext:
            streamDecryptor = self.e2eeClient.createHTTPDecryptor(e2eeContext, resumePosition)

        # Start download without extra logging if using shared progress

        # Create session with StallResilientAdapter for Python 3.12 workarounds and better stall handling
        session = requests.Session()
        adapter = StallResilientAdapter(
            chunkSize=TRANSFER_CHUNK_SIZE,
            allowedMethods={'GET'} # Download method only
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        activeResponse = {'response': None}

        def closeActiveResponseOnServerError(serverError):
            response = activeResponse.get('response')
            if response is None:
                return

            logger.debug(f"[HTTP] Closing active response after server error: {serverError}")
            response.close()

        def raiseQueuedServerErrorIfAny():
            if statusErrorQueue:
                serverError = statusErrorQueue[0]
                logger.debug(f"[HTTP] Error found in queue: {serverError}")
                statusStopEvent.set()
                raise serverError

        # Start background thread for status polling
        statusStopEvent = threading.Event()
        statusErrorQueue = deque()
        self._startStatusPollingThread(
            urlInfo.baseURL,
            downloadHeaders,
            statusStopEvent,
            statusErrorQueue,
            onError=closeActiveResponseOnServerError
        )

        serverDownloadId = None
        try:
            # Use tuple timeout: (connect_timeout, read_timeout) with increased read timeout
            # to handle large file stalls (especially on Python 3.12 + TLS 1.3)
            with session.get(
                downloadURL, headers=downloadHeaders, stream=True,
                timeout=(self.HTTP_CONNECT_TIMEOUT, self.HTTP_READ_TIMEOUT)
            ) as response:
                activeResponse['response'] = response
                raiseQueuedServerErrorIfAny()

                # Check status codes
                if response.status_code not in (200, 206): # 206 is partial content for resume
                    raise RuntimeError(f"HTTP download failed: {response.status_code}")

                # Verify content range for resume
                if resumePosition > 0 and response.status_code != 206:
                    raise RuntimeError("Server does not support resume")

                # Extract server-assigned download ID for completion ACK (relay drain coordination)
                serverDownloadId = response.headers.get('FFL-DownloadId')

                # For unknown size (generic URLs or stdin), try to get actual Content-Length from GET response
                if not self._isKnownSize(fileSize):
                    actualContentLength = response.headers.get('Content-Length')
                    if actualContentLength:
                        actualSize = int(actualContentLength)
                        if actualSize > 0:
                            fileSize = actualSize
                            # Recreate progress bar with actual size
                            if not sharedProgress:
                                self._finishProgress(complete=False)
                                progress = self._ensureProgress(fileSize, self._STATUS_HTTP_DOWNLOAD, resumePosition)

                # Open file for writing (append mode if resuming), or stream to stdout
                mode = 'ab' if resumePosition > 0 else 'wb'
                totalDownloaded = resumePosition # Start from resume position

                ctx = contextlib.nullcontext(sys.stdout.buffer) if finalOutputPath == "-" else open(finalOutputPath, mode)
                with ctx as f:
                    checksumState = self._createTransferChecksumState(verifyChecksum, checksumAlgorithm)
                    for chunk in response.iter_content(chunk_size=TRANSFER_CHUNK_SIZE):
                        # Check status error queue (lock-free, very fast - no performance impact)
                        raiseQueuedServerErrorIfAny()

                        if chunk: # Filter out keep-alive chunks
                            self._updateTransferChecksumState(checksumState, chunk)

                            # Process chunk (decrypt if E2EE enabled, otherwise passthrough)
                            processedData = streamDecryptor.processChunk(chunk) if streamDecryptor else chunk

                            f.write(processedData)
                            totalDownloaded += len(processedData)
                            progress.update(totalDownloaded, extraText="HTTP fallback")

                    # Flush any remaining buffered data
                    if streamDecryptor:
                        finalData = streamDecryptor.flush()
                        if finalData:
                            f.write(finalData)
                            totalDownloaded += len(finalData)
                            progress.update(totalDownloaded, extraText="HTTP fallback")

        except requests.exceptions.RequestException as e:
            if statusErrorQueue:
                serverError = statusErrorQueue[0]
                logger.debug(f"[HTTP] Request failed after server error: {serverError}")
                statusStopEvent.set()

                if not sharedProgress:
                    self._finishProgress(complete=False)

                raise serverError

            # Don't update progress to 100% on failure
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise RuntimeError(f"Network error during HTTP download: {e}")
        except KeyboardInterrupt:
            # User cancelled - clean up progress bar
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise
        except FolderChangedException:
            # Re-raise folder change exceptions as-is (don't wrap in RuntimeError)
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise
        except Exception as e:
            # Don't update progress to 100% on any failure
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise RuntimeError(f"HTTP download failed: {e}")
        finally:
            activeResponse['response'] = None
            statusStopEvent.set()
            session.close() # Clean up session resources

        # Verify final file size (skip for stdout and generic URLs and unknown sizes)
        if finalOutputPath == "-":
            finalSize = totalDownloaded
        else:
            finalSize = os.path.getsize(finalOutputPath)
            if not urlInfo.isGenericURL and self._isPositiveSize(fileSize) and finalSize != fileSize:
                raise RuntimeError(f"Download incomplete: {finalSize} != {fileSize} bytes")

        # Final progress update on success
        progress.update(finalSize, forceLog=True, extraText="HTTP fallback")
        if not sharedProgress: # Only finish bar if we created it
            self._finishProgress()

        if verifyChecksum:
            self._verifyTransferChecksum(urlInfo.baseURL, self._createAuthHeaders(credentials), checksumState, 'http')

        # Notify server that client has received all bytes (unblocks relay drain wait)
        if serverDownloadId and not urlInfo.isGenericURL:
            self._notifyHTTPDownloadComplete(urlInfo.baseURL, serverDownloadId, credentials, finalSize)

        # Only log to logger, not loggerCallback to avoid extra line after progress bar
        logger.debug(f"HTTP download completed: {finalOutputPath}")
        return finalOutputPath

    def _notifyHTTPDownloadComplete(
        self, baseURL: str, downloadId: str, credentials: Optional[Tuple[str, str]], receivedBytes: int
    ):
        """Notify server that client has received all bytes via HTTP.

        Mirrors the WebRTC /complete ACK so the server can safely call
        _handlePostDownloadActions() after the relay has fully drained.
        Errors are suppressed — the server will timeout gracefully after 30s.
        """
        try:
            completeURL = self._buildURL(baseURL, "complete")
            authHeaders = self._createAuthHeaders(credentials)
            self._sendHTTPRequest(
                completeURL,
                "POST", {
                    "downloadId": downloadId,
                    "receivedBytes": receivedBytes
                },
                authHeaders,
                timeout=10
            )
            logger.debug(f"HTTP download complete ACK sent for {downloadId[:8]}")
        except Exception as e:
            logger.debug(f"Failed to send HTTP download complete ACK: {e}")

    def _dispatchHTTPDownload(self, url, outputPath, credentials, resume, ctx, pickupCode=None):
        """
        Send a resolved download context to the HTTP transport, honoring the
        FFL-vs-generic-URL distinction: generic/third-party URLs never receive
        E2EE context or the FFL-specific X-FFL-Pickup/X-FFL-Proof auth headers.
        """
        urlInfo = ctx['urlInfo']
        if urlInfo.isGenericURL:
            self.loggerCallback(_("⚠️  This is not a FastFileLink URL, downloading directly via HTTP (like wget)..."))
            return self._downloadViaHTTP(url, outputPath, credentials, None, resume, e2eeContext=None, urlInfo=urlInfo)

        return self._downloadViaHTTP(
            url, outputPath, credentials, None, resume,
            e2eeContext=ctx['e2eeContext'], urlInfo=urlInfo, pickupCode=pickupCode,
            proof=ctx['proof'], checksumAlgorithm=ctx['checksumAlgorithm']
        )

    def downloadFile(self, url, outputPath=None, credentials=None, resume=False,
                      pickupCode=None, recipientPrivateKey=None) -> str:
        """Download a file over plain HTTP only, no other transport attempted."""
        ctx = self._resolveDownloadContext(url, credentials, recipientPrivateKey)
        return self._dispatchHTTPDownload(url, outputPath, credentials, resume, ctx, pickupCode)


# Imported last, and only here: bases.WebRTC never imports from this module, so
# WebRTCDownloadMixin stays purely WebRTC-focused. This is the one place that
# composes the concrete, FastFileLink-specific downloader.
from bases.WebRTC import WebRTCDownloadMixin # noqa: E402


class FFLDownloader(WebRTCDownloadMixin, HTTPDownloader):
    """
    FastFileLink CLI/receiver-side downloader. Combines the WebRTC transport
    (tried first, via WebRTCDownloadMixin) with the HTTP base transport
    (HTTPDownloader).

    Extension pattern for future transports (e.g. IrohDownloadMixin):
      1. Define the mixin in its own module (e.g. bases/Iroh.py), following
         WebRTCDownloadMixin's shape: __init__ cooperatively calls
         super().__init__(*args, **kwargs) first, then sets its own state;
         downloadFile() calls self._resolveDownloadContext(...) once,
         attempts its transport, and falls back to
         self._dispatchHTTPDownload(...) (or chains via
         super().downloadFile(...)) on failure. It must not import from
         bases.Download, matching WebRTCDownloadMixin's contract.
      2. Import it here and list it before HTTPDownloader in the bases tuple:
         class FFLDownloader(WebRTCDownloadMixin, IrohDownloadMixin, HTTPDownloader):
    """
    pass
