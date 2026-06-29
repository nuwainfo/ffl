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

import hashlib
import json
import os
import re
import secrets
import socket
import sys
import uuid
import datetime
import base64
import threading
import time

import requests

from dataclasses import dataclass
from typing import Optional
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from jinja2 import Environment, FileSystemLoader

from bases.Kernel import getLogger, PUBLIC_VERSION, FFLEvent, Throttler
from bases.Utils import flushPrint, utf8, formatSize
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.WebRTC import WebRTCManager, WebRTCDisabledError
from bases.Progress import Progress
from bases.Auth import RecipientAuth
from bases.E2EE import E2EEManager, CryptoHelper
from bases.Checksum import DEFAULT_CHECKSUM_ALGORITHM, TransferChecksumStore
from bases.Readers import FolderChangedException
from bases.I18n import _
from bases.Session import ShareStatus, ShareSession

LOG_OUTPUT_DURATION = 1 # Seconds

logger = getLogger(__name__)

try:
    if sys.platform == "win32":
        import winloop
        # https://github.com/Vizonex/Winloop/issues/9
        import winloop._noop
        winloop.install()
    else:
        import asyncio
        import uvloop
        import platform

        # Check if running in WSL (Windows Subsystem for Linux)
        # uvloop has known issues with WSL2's epoll implementation
        isWSL = 'microsoft' in platform.uname().release.lower() or 'wsl' in platform.uname().release.lower()

        if not isWSL:
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        else:
            logger.info("WSL detected - using default asyncio event loop instead of uvloop for compatibility")
except ImportError:
    logger.debug("Unable to optimize event loop in platform")


@dataclass
class HTTPAuth:
    """HTTP Basic Authentication credentials."""
    user: Optional[str] = None
    password: Optional[str] = None

    def isEnabled(self) -> bool:
        """Check if authentication is enabled (password is required)."""
        return bool(self.password)


class AuthMixin:
    """
    A mixin to handle Basic Authentication for BaseHTTPRequestHandler.
    Provides authentication functionality for protecting HTTP resources.

    Child classes must implement:
        @property
        def auth(self) -> HTTPAuth:
            return HTTPAuth(user=..., password=...)
    """
    REALM = 'FastFileLink Protected Resource'

    def handleAuthentication(self):
        """
        Checks the 'Authorization' header and validates user credentials.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        # Skip auth if not configured (password is required to enable auth)
        if not self.auth.isEnabled():
            return True

        authHeader = self.headers.get('Authorization')

        if not authHeader or not authHeader.startswith('Basic '):
            logger.warning("Authentication challenge sent: No or invalid auth header")
            self.sendAuthChallenge()
            return False

        try:
            # Decode credentials from Base64
            encodedCredentials = authHeader.split(' ')[1]
            decodedBytes = base64.b64decode(encodedCredentials)
            credentials = decodedBytes.decode('utf-8')
            username, password = credentials.split(':', 1)

            # Verify credentials against auth property
            if username == self.auth.user and password == self.auth.password:
                logger.info(f"Authentication successful for user: '{username}'")

                # Trigger authSuccess event
                FFLEvent.authSuccess.trigger(
                    username=username,
                    timestamp=datetime.datetime.now().isoformat(),
                    clientIp=self.client_address[0] if self.client_address else None
                )

                return True
            else:
                logger.warning(f"Authentication failed: Invalid credentials for user '{username}'")

                # Trigger authFailed event
                FFLEvent.authFailed.trigger(
                    username=username,
                    clientIp=self.client_address[0] if self.client_address else None,
                    timestamp=datetime.datetime.now().isoformat()
                )

                self.sendAuthChallenge()
                return False
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            logger.error(f"Error decoding credentials: {e}")
            self.sendAuthChallenge()
            return False

    def sendAuthChallenge(self):
        """
        Sends a 401 Unauthorized response to the client, prompting for credentials.
        """
        # Trigger authRequired event
        FFLEvent.authRequired.trigger(realm=self.REALM, timestamp=datetime.datetime.now().isoformat())

        html = b'<h1>401 Unauthorized</h1><p>Authentication required to access this resource.</p>'

        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', f'Basic realm="{self.REALM}"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()

        self.wfile.write(html)


class AuthRateLimiter:
    """Brute-force protection for all credential verification (pickup code, pubkey, email OTP).

    Tracks failure counts per credential type independently so that failures in one
    type do not consume the budget of another (e.g. 2 pickup failures + 3 OTP failures
    locks neither). Each type gets its own MAX_FAILURES budget and lockout timer.

    Locks for LOCKOUT_DURATION seconds after MAX_FAILURES consecutive failures of the same type.
    Resets on a successful verification of that type. Tracks globally per server instance.
    """

    MAX_FAILURES = 5
    LOCKOUT_DURATION = 300 # 5 minutes

    def __init__(self):
        self._state = {} # authType -> {'failures': int, 'lockedUntil': float}
        self._lock = threading.Lock()

    def _stateFor(self, authType: str) -> dict:
        """Return (creating if needed) the state dict for authType. Must be called under lock."""
        if authType not in self._state:
            self._state[authType] = {'failures': 0, 'lockedUntil': 0.0}
        return self._state[authType]

    def isLocked(self, authType: str) -> bool:
        with self._lock:
            return time.time() < self._stateFor(authType)['lockedUntil']

    def recordFailure(self, authType: str):
        with self._lock:
            state = self._stateFor(authType)
            state['failures'] += 1
            if state['failures'] >= self.MAX_FAILURES:
                state['lockedUntil'] = time.time() + self.LOCKOUT_DURATION
                state['failures'] = 0

    def recordSuccess(self, authType: str):
        with self._lock:
            self._state[authType] = {'failures': 0, 'lockedUntil': 0.0}


class DownloadSessionStore:
    """Thread-safe in-memory store for download session cookies.

    Lifecycle:
    - POST /auth exchanges X-FFL-* credentials for a session cookie (dlk).
    - Once claimed, the credentials cannot be used again to create a new session.
    - The existing session cookie (dlk) remains valid until expiry and supports Range requests.
    """

    SESSION_TTL = 600 # seconds

    def __init__(self):
        self._sessions = {} # dlk_hash -> expires_at
        self._claimed = False
        self._lock = threading.Lock()

    def create(self) -> str:
        """Generate and store a new session token. Raises RuntimeError if already claimed."""
        with self._lock:
            if self._claimed:
                raise RuntimeError("Download session already claimed")

            dlk = secrets.token_urlsafe(32)
            dlkHash = hashlib.sha256(dlk.encode()).hexdigest()
            self._sessions[dlkHash] = time.time() + self.SESSION_TTL
            self._claimed = True
            return dlk

    def validate(self, dlk: str) -> bool:
        """Return True if dlk is a valid, unexpired session token."""
        dlkHash = hashlib.sha256(dlk.encode()).hexdigest()
        with self._lock:
            expiresAt = self._sessions.get(dlkHash)
            if expiresAt is None:
                return False

            if time.time() > expiresAt:
                del self._sessions[dlkHash]
                return False

            return True


class DownloadRecordStore:
    """Thread-safe downloadId keyed record store.

    Subclasses own the record schema and behavior; this base only centralizes
    the shared lock/map lifecycle.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._downloads = {}

    def _putRecord(self, downloadId, record):
        with self._lock:
            self._downloads[downloadId] = record

    def unregister(self, downloadId):
        with self._lock:
            self._downloads.pop(downloadId, None)


class DownloadProgressStore(DownloadRecordStore):
    """Thread-safe per-download progress tracker for server-side stall detection.

    Each active HTTP download registers here.  The /status poll checks for
    downloads that have stopped making progress and reports them to /diagnosis
    via the public tunnel URL so the relay can also log the event.
    """

    STALL_THRESHOLD_SECONDS = int(os.getenv('STALL_DETECTION_SECONDS', '60'))

    def register(self, downloadId, total):
        now = time.time()
        self._putRecord(
            downloadId, {
                'downloadId': downloadId,
                'written': 0,
                'total': total,
                'lastUpdateTime': now,
                'startTime': now,
                'stallReported': False,
            }
        )

    def update(self, downloadId, written):
        with self._lock:
            entry = self._downloads.get(downloadId)
            if entry:
                entry['written'] = written
                entry['lastUpdateTime'] = time.time()
                entry['stallReported'] = False # reset on any progress

    def getStalledDownloads(self):
        """Return snapshots of downloads with no progress for STALL_THRESHOLD_SECONDS."""
        now = time.time()
        stalled = []
        with self._lock:
            for entry in self._downloads.values():
                if not entry['stallReported']:
                    if now - entry['lastUpdateTime'] >= self.STALL_THRESHOLD_SECONDS:
                        stalled.append(dict(entry))

        return stalled

    def markStallReported(self, downloadId):
        with self._lock:
            entry = self._downloads.get(downloadId)
            if entry:
                entry['stallReported'] = True


class HTTPDownloadCompletionStore(DownloadRecordStore):
    """Thread-safe ACK tracker for HTTP relay download completion.

    The browser may legitimately send duplicate POST /complete requests when we
    add a Service Worker-side ACK as a reliability backstop while keeping the
    existing page-side ACK path. The server should treat the first ACK as the
    authoritative completion signal and quietly ignore duplicates.
    """

    def register(self, downloadId):
        self._putRecord(downloadId, {
            'event': threading.Event(),
            'acknowledged': False,
        })

    def wait(self, downloadId, timeout):
        with self._lock:
            entry = self._downloads.get(downloadId)
            event = entry['event'] if entry else None

        if not event:
            return False

        return event.wait(timeout=timeout)

    def acknowledge(self, downloadId):
        """Mark downloadId as acknowledged.

        Returns:
            str: One of:
                - 'accepted': first valid ACK for this downloadId
                - 'duplicate': ACK already processed earlier
                - 'unknown': downloadId is not being tracked
        """
        with self._lock:
            entry = self._downloads.get(downloadId)
            if not entry:
                return 'unknown'

            if entry['acknowledged']:
                return 'duplicate'

            entry['acknowledged'] = True
            entry['event'].set()
            return 'accepted'


@dataclass
class LogicalDownloadRequest:
    logicalDl: str
    requestId: str
    rangeStart: int
    rangeEnd: Optional[int]
    startedAt: float
    superseded: bool = False


class LogicalDownloadRequestStore:
    """Track active logical download requests and supersede overlapping older ones.

    Browser/native retry behaviour may open a new /download request using the same
    logical dl identifier before the earlier request has fully drained. We keep
    the newer request and mark overlapping older ones as superseded so they can
    stop sending duplicate data at the next safe checkpoint.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._requests = {} # logicalDl -> requestId -> LogicalDownloadRequest

    def _getRequestsFor(self, logicalDl):
        if logicalDl not in self._requests:
            self._requests[logicalDl] = {}

        return self._requests[logicalDl]

    @staticmethod
    def _rangesOverlap(start1, end1, start2, end2):
        normalizedEnd1 = float('inf') if end1 is None else end1
        normalizedEnd2 = float('inf') if end2 is None else end2
        return start1 <= normalizedEnd2 and start2 <= normalizedEnd1

    def register(self, logicalDl, requestId, rangeStart, rangeEnd):
        supersededRequestIds = []

        with self._lock:
            requestsForDl = self._getRequestsFor(logicalDl)
            for entry in requestsForDl.values():
                if self._rangesOverlap(rangeStart, rangeEnd, entry.rangeStart, entry.rangeEnd):
                    entry.superseded = True
                    supersededRequestIds.append(entry.requestId)

            requestsForDl[requestId] = LogicalDownloadRequest(
                logicalDl=logicalDl,
                requestId=requestId,
                rangeStart=rangeStart,
                rangeEnd=rangeEnd,
                startedAt=time.time(),
            )

        return supersededRequestIds

    def isSuperseded(self, logicalDl, requestId):
        with self._lock:
            entry = self._requests.get(logicalDl, {}).get(requestId)
            return bool(entry and entry.superseded)

    def unregister(self, logicalDl, requestId):
        with self._lock:
            requestsForDl = self._requests.get(logicalDl)
            if not requestsForDl:
                return

            requestsForDl.pop(requestId, None)
            if not requestsForDl:
                self._requests.pop(logicalDl, None)


class SupersededDownloadError(ConnectionAbortedError):
    """Raised when a newer overlapping logical download request replaces this one."""


class DownloadHandler(AuthMixin, SimpleHTTPRequestHandler):
    # Transfer chunk size - shared across WebRTC and HTTP downloads
    CHUNK_SIZE = TRANSFER_CHUNK_SIZE

    range = None

    # To let browser can resume downloads
    protocol_version = 'HTTP/1.1'
    etag = uuid.uuid4()

    _jinja2EnvCache = None

    UA_RULES = {
        # Direct download (non-browsers or explicitly excluded from index)
        "DIRECT_DOWNLOAD": [["windowspowershell"],],

        # In-app browser whitelist (only explicitly listed are considered)
        # Each item requires all tokens to match (AND)
        "IN_APP": [
            ["micromessenger"], # WeChat
            ["line/", "iab"], # LINE (conservative)
            ["telegram-android/"], # Telegram Android
            ["mqqbrowser", " qq"], # QQ (common pattern)
            ["qqtheme"], # QQ (alternative signal)
            ["whatsapp"], # WhatsApp (may include bots)
        ],

        # General browser whitelist (avoid treating unknown clients as browsers)
        "BROWSER": [
            ["chrome/"],
            ["crios/"],
            ["safari/"],
            ["firefox/"],
            ["fxios"],
            ["edg/"],
            ["mozilla"],
        ],

        # Preview/crawlers (currently also redirected to index)
        "PREVIEW_BOTS": [
            ["facebookexternalhit"],
            ["line-"],
        ],
    }

    def __init__(self, request, client_address, server):
        # Define path handlers for HEAD, GET, and POST methods
        # HEAD is using to let server side get file information like filename, file size, etc.
        self.headPathMap = {
            '/download': self._handleDownloadHead,
            '/static/index.html': self._handleDefaultHead,
            '/': self._handleHeadRedirect,
            '': self._handleHeadRedirect,

            # All paths require a /{uid}/... prefix in multi-session mode.
            # These WebRTC paths are additionally forbidden for HEAD — GET/POST only.
            '/offer': self._handleForbiddenHead,
            '/answer': self._handleForbiddenHead,
            '/candidate': self._handleForbiddenHead,
            '/complete': self._handleForbiddenHead
        }

        self.getPathMap = {
            '/download': self._handleDownload,
            '/checksum': self._handleChecksum,
            '/static/index.html': self._handleStaticIndex,
            '/static/js/ProgressServiceWorker.js': self._handleProgressServiceWorker,
            '/static/js/Checksum.js': self._handleChecksumScript,
            '/static/js/E2EE.js': self._handleE2EEScript,
            '/offer': self._handleWebRTCOffer,
            '/candidate': self._handleWebRTCCandidatePolling,
            '/e2ee/manifest': self._handleE2EEManifest,
            '/e2ee/tags': self._handleE2EETags,
            '/status': self._handleStatus,
            '/diagnosis': self._handleDiagnosis,
            '/': self._handleRedirect,
            '': self._handleRedirect
        }

        self.postPathMap = {
            '/answer': self._handleWebRTCAnswer,
            '/candidate': self._handleWebRTCCandidate,
            '/complete': self._handleDownloadComplete,
            '/e2ee/init': self._handleE2EEInit,
            '/auth': self._handleAuth,
            '/email/request': self._handleEmailOTPRequest,
        }

        if os.getenv('JS_LOG_TO_SERVER_DEBUG') == 'True':
            self.postPathMap.update({
                '/debug/log': self._handleDebugLog,
            })

        # One request one handler, so _extraHeaders can be safely used in self.end_headers.
        self._extraHeaders = {}
        self.session = None
        self._requestQuery = ''
        self._requestArgs = {}
        self._pathForbidden = False

        # Generate unique download ID for tracking
        self._downloadId = str(uuid.uuid4())
        self._downloadStartTime = None

        settingsGetter = SettingsGetter.getInstance()

        super().__init__(request, client_address, server, directory=settingsGetter.baseDir)

    @property
    def auth(self) -> HTTPAuth:
        if self.session is None:
            return HTTPAuth()
            
        return HTTPAuth(user=self.session.config.authUser, password=self.session.config.authPassword)

    def _appendDownloadRequestLog(self, args, name, size):
        """Append a lightweight JSON line for each /download request when enabled."""
        logPath = os.getenv('FFL_DOWNLOAD_REQUEST_LOG')
        if not logPath:
            return

        try:
            entry = {
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'method': self.command,
                'path': self.path,
                'downloadId': self._downloadId,
                'logicalDl': args.get('dl', [None])[0] if args else None,
                'range': self.headers.get('Range'),
                'host': self.headers.get('Host'),
                'userAgent': self.headers.get('User-Agent'),
                'fileName': name,
                'fileSize': size,
            }
            with open(logPath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception as exc:
            logger.warning(f"Failed to append FFL_DOWNLOAD_REQUEST_LOG entry: {exc}")

    def _registerAdditionalEndpoints(self, server, session=None):
        """
        Hook method for addons to register additional endpoints.
        Override this method in enhanced handler classes to add custom endpoints.
        """
        self._mergeAdditionalEndpointMaps(server=server, session=session)

    def _mergeAdditionalEndpointMaps(self, server, session=None):
        originalPathsByMap = {
            'getPathMap': set(self.getPathMap.keys()),
            'postPathMap': set(self.postPathMap.keys()),
            'headPathMap': set(self.headPathMap.keys()),
        }
        routeMaps = {
            'getPathMap': dict(self.getPathMap),
            'postPathMap': dict(self.postPathMap),
            'headPathMap': dict(self.headPathMap),
        }

        FFLEvent.serverEndpointsRegister.trigger(
            handler=self,
            server=server,
            session=session,
            getPathMap=routeMaps['getPathMap'],
            postPathMap=routeMaps['postPathMap'],
            headPathMap=routeMaps['headPathMap']
        )

        for mapName, routeMap in routeMaps.items():
            originalPaths = originalPathsByMap[mapName]
            targetMap = getattr(self, mapName)
            for path, endpointHandler in routeMap.items():
                if path not in originalPaths:
                    targetMap[path] = endpointHandler

    def _resolveRequestContext(self):
        parsedURL = urlparse(self.path)
        query = parsedURL.query
        path = parsedURL.path

        # Try to resolve session from the first path segment (the UID)
        parts = path.lstrip('/').split('/', 1)
        uid = parts[0] if parts else ''
        session = self.server.getSession(uid) if uid else None

        if session is not None:
            # UID prefix found — strip it so handlers see a clean path
            path = '/' + (parts[1] if len(parts) > 1 else '')
        else:
            # No valid UID prefix — fall back to the single active session (Core.py mode)
            # so that root-relative browser requests (e.g. /status, /static/...) still work
            session = self.server.getDefaultSession()
            # path stays as-is (no uid to strip)

        forbidden = self._checkPathForbidden(path, session)
        return session, path, query, forbidden

    def _prepareRequestContext(self):
        self.session, self.path, self._requestQuery, self._pathForbidden = self._resolveRequestContext()
        self._requestArgs = parse_qs(self._requestQuery)

        if self.session is not None:
            self._registerAdditionalEndpoints(server=self.server, session=self.session)

    def parse_request(self):
        if not super().parse_request():
            return False

        # BaseHTTPRequestHandler.__init__() drives the request lifecycle immediately:
        # __init__() -> handle_one_request() -> parse_request() -> do_GET/do_POST/do_HEAD().
        # We prepare session/path/query context here so endpoint registration can run
        # with a resolved session before the do_* handlers execute.
        try:
            self._prepareRequestContext()
        except Exception as e:
            logger.exception(f"Failed to prepare request context: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return False

        return True

    def _checkPathForbidden(self, path, session=None):
        # WebRTC paths are forbidden when WebRTC is disabled server-side (--force-relay for licensed users).
        # Derive the set from headPathMap to avoid a separate list to maintain.
        if self.headPathMap.get(path) == self._handleForbiddenHead:
            return session is not None and not session.config.defaultWebRTC
            
        return False

    def _parseByteRange(self, byteRange):
        try:
            if byteRange.strip() == '':
                return None

            reg = re.search(r'bytes=(\d+)-(\d+)?$', byteRange)
            if not reg:
                raise ValueError(f'Invalid byte range {byteRange}')

            # end might be None (protocol supported)
            start, end = [x and int(x) for x in reg.groups()]
            if end and start > end:
                raise ValueError(f'Invalid byte range {byteRange}')
            return start, end

        except Exception as e:
            logger.exception(e)
            return None

    def _parseRange(self):
        if 'Range' in self.headers:
            self.range = self._parseByteRange(self.headers['Range'])

    def parseURLBooleanParam(self, value):
        """
        Parse URL boolean parameters with support for multiple formats.

        True values: true, 1, on, yes (case-insensitive)
        False values: false, 0, off, no (case-insensitive)

        Args:
            value: String value from URL parameter

        Returns:
            bool: True/False, or None if value is not a recognized boolean
        """
        if not value:
            return False

        lowerValue = value.lower()

        # True values
        if lowerValue in ('true', '1', 'on', 'yes'):
            return True

        # False values
        if lowerValue in ('false', '0', 'off', 'no'):
            return False

        # Unrecognized value
        return None

    def _getFileInfo(self, quoteName=True):
        # Reader is always available and provides file/directory information        
        reader = self.session.reader
        path = os.path.join(reader.directory, reader.file) if reader.directory else reader.file

        if quoteName:
            name = quote(reader.contentName)
        else:
            name = reader.contentName

        size = reader.size # None means unknown length (e.g., stdin)
        ctype = reader.contentType

        return path, name, size, ctype, reader

    # HEAD handlers
    def _handleForbiddenHead(self, message='Disabled by server policy'):
        content = message.encode('utf-8')
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()

    def _handleDefaultHead(self):
        super().do_HEAD()

    def _determineRedirectPath(self):
        userAgent = self.headers.get("User-Agent", "")
        if not userAgent:
            return "/download"

        userAgentLower = userAgent.lower()

        def matchAll(tokens):
            # Convert tokens to lowercase as well, to avoid issues if rules contain uppercase
            return all(t.lower() in userAgentLower for t in tokens)

        def matchAny(listOfTokenGroups):
            return any(matchAll(group) for group in listOfTokenGroups)

        # 1) Direct download
        if matchAny(self.UA_RULES["DIRECT_DOWNLOAD"]):
            return "/download"

        # 2) In-app whitelist
        if matchAny(self.UA_RULES["IN_APP"]):
            return "/static/index.html"

        # 3) Preview bots (decide whether to treat as index; currently follows original behavior: go to index)
        if matchAny(self.UA_RULES["PREVIEW_BOTS"]):
            return "/static/index.html"

        # 4) General browsers
        isBrowser = matchAny(self.UA_RULES["BROWSER"])

        return "/static/index.html" if isBrowser else "/download"

    def _handleHeadRedirect(self):
        """Handle redirect by determining path and calling appropriate handler"""
        redirectPath = self._determineRedirectPath()
        self.path = redirectPath

        # Get handler from getPathMap
        handler = self.headPathMap.get(redirectPath)
        if handler:
            handler()
        else:
            logger.error(f"No handler found for redirect path: {redirectPath}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Redirect handler not found")

    def _handleDownloadHead(self):
        path, name, size, ctype, reader = self._getFileInfo()

        self.send_response(HTTPStatus.OK)

        if size is not None:
            self.send_header("Content-Length", str(size))
        else:
            # Unknown size - use chunked transfer encoding
            self.send_header("Transfer-Encoding", "chunked")

        args = parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
        viewMode = self.parseURLBooleanParam(args.get('view', [None])[0]) is True
        if viewMode:
            mediaType = self.guess_type(name)
            self.send_header("Content-type", mediaType)
            self.send_header("Content-Disposition", f"inline; filename={name}")
        else:
            self.send_header("Content-type", ctype)
            self.send_header("Content-Disposition", f"attachment; filename={name}")
        self.end_headers()

    # Add HTTP HEAD to let server can get Content-Disposition without triggered download
    def do_HEAD(self):
        if not self._guardRequest():
            return

        headHandler = self.headPathMap.get(self.path)
        if not headHandler:
            headHandler = self.getPathMap.get(self.path)

        logger.debug(f"[ROUTE] HEAD {self.path} -> handler={'found' if headHandler else 'NOT FOUND (using default)'}")

        if headHandler:
            headHandler()
        else:
            # Default handling for other paths
            super().do_HEAD()

    # GET handlers
    def _handleRedirect(self, args):
        """Handle redirect by determining path and calling appropriate handler"""
        redirectPath = self._determineRedirectPath()
        self.path = redirectPath

        # Get handler from getPathMap
        handler = self.getPathMap.get(redirectPath)
        if handler:
            handler(args)
        else:
            logger.error(f"No handler found for redirect path: {redirectPath}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Redirect handler not found")

    def _writeChunk(self, data: bytes):
        """
        Write a single chunk in HTTP/1.1 chunked transfer encoding format

        Args:
            data: Chunk data to write
        """
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    def _finishChunked(self):
        """Write the final chunk marker for HTTP/1.1 chunked transfer encoding"""
        self.wfile.write(b"0\r\n\r\n")

    def _handleStartDownloadActions(self, size):
        flushPrint(_('[{timestamp}] Downloading by user').format(timestamp=self.date_time_string()))

        # Track per-download progress for server-side stall detection
        self.session.downloadProgressStore.register(self._downloadId, size)

        # Register completion state so _waitForHTTPDownloadComplete can block until client ACKs
        self.session.httpDownloadCompletionStore.register(self._downloadId)

        # Get client information
        userAgent = self.headers.get('User-Agent', 'Unknown')
        host = self.headers.get('Host', 'Unknown')

        # Trigger downloadStarted event
        FFLEvent.downloadStarted.trigger(
            timestamp=self.date_time_string(),
            downloadId=self._downloadId,
            connectionType='http',
            clientInfo={
                'userAgent': userAgent,
                'domain': host
            },
            resumeOffset=self.range[0] if self.range else 0,
            fileSize=size,
            fileName=self.session.reader.contentName
        )

    def _handlePostDownloadActions(self, size):
        flushPrint(_(
            'File sending is complete. '
            'Please wait for the recipient to finish downloading before you close the application.\n'
        ))

        # Calculate download duration and average speed
        duration = time.time() - self._downloadStartTime
        averageSpeed = int(size / duration) if (size and duration > 0) else 0

        # Get client information
        userAgent = self.headers.get('User-Agent', 'Unknown')
        host = self.headers.get('Host', 'Unknown')

        # Trigger downloadCompleted event
        FFLEvent.downloadCompleted.trigger(
            downloadId=self._downloadId,
            bytesTransferred=size if size else 0,
            duration=duration,
            averageSpeed=averageSpeed,
            connectionType='http',
            clientInfo={
                'userAgent': userAgent,
                'domain': host
            }
        )

        self.server.doAfterDownload(self.session.uid)

    def _waitForHTTPDownloadComplete(self):
        """Block until the client ACKs receipt via POST /complete, or until timeout.

        Mirrors the WebRTC sendFile() completionEvent.wait() pattern.
        Prevents server.shutdown() (triggered by doAfterDownload) from racing
        the relay/tunnel that is still draining buffered bytes to the client.

        FFL clients (browser, CLI) send /complete immediately after receiving all
        bytes, so the wait resolves in milliseconds. Non-FFL clients (curl, wget)
        never send /complete — the short timeout lets the server proceed quickly
        without hanging.
        """
        completed = self.session.httpDownloadCompletionStore.wait(self._downloadId, timeout=5)
        if not completed:
            logger.debug(
                f"HTTP download complete ACK not received for {self._downloadId[:8]} "
                "(non-FFL client or slow relay), proceeding"
            )

    def _parsePositiveDebugIntArg(self, args, argName, default=None):
        """Parse a positive integer debug query parameter."""
        if not args or argName not in args:
            return default

        rawValue = args[argName][0]
        if rawValue.isdecimal():
            return int(rawValue)

        logger.warning(f"[Test] Invalid {argName} value: {rawValue!r}, must be a positive integer")
        return default

    def _parseIntArg(self, args, argName, default=0):
        """Parse an integer query parameter, falling back to default on invalid input."""
        if not args or argName not in args:
            return default

        try:
            return int(args[argName][0])
        except (ValueError, IndexError, TypeError):
            return default

    def _getDownloadDebugOptions(self, args):
        """Collect download-specific debug/test injection options."""
        return {
            'stallAfterBytes': self._parsePositiveDebugIntArg(args, 'stall-after'),
            'disconnectAfterBytes': self._parsePositiveDebugIntArg(args, 'disconnect-after'),
        }

    def _getClientDebugFlags(self, args):
        """Resolve page-level debug flags from environment, server defaults, and URL params."""
        flags = {
            'debugEnabled': os.getenv('JS_DEBUG', None) == 'True',
            'serverDebugEnabled': os.getenv('JS_LOG_TO_SERVER_DEBUG', None) == 'True',
            'webrtcDisabled': os.getenv('DISABLE_WEBRTC', None) == 'True',
            'streamSaverBlob': os.getenv('STREAMSAVER_BLOB', None) == 'True',
            'webrtcDisabledDetermined': False,
        }

        if not args:
            return flags

        debugParam = args.get('debug', [None])[0]
        if debugParam:
            if debugParam.lower() == 'server':
                flags['serverDebugEnabled'] = True
            elif self.parseURLBooleanParam(debugParam):
                flags['debugEnabled'] = True

        webrtcParam = args.get('webrtc', [None])[0]
        if webrtcParam:
            webrtcValue = self.parseURLBooleanParam(webrtcParam)
            if webrtcValue is False:
                flags['webrtcDisabled'] = True
            elif webrtcValue is True:
                flags['webrtcDisabled'] = False

            flags['webrtcDisabledDetermined'] = True

        return flags

    def _getWebRTCDebugOptions(self, args):
        """Collect WebRTC-specific debug/test options from URL params."""
        return {
            'simulateIceFailure': bool(args) and self.parseURLBooleanParam(args.get('simulate-ice-failure', [None])[0]),
            'simulateStall': bool(args) and self.parseURLBooleanParam(args.get('simulate-stall', [None])[0]),
            'stallAfterBytes': self._parsePositiveDebugIntArg(args, 'stall-after', default=50000),
        }

    def _truncateChunkForDebugOptions(self, data, written, debugOptions):
        """Trim the outgoing chunk so stall injection lands exactly on the requested byte offset."""
        stallAfterBytes = debugOptions.get('stallAfterBytes')
        if stallAfterBytes is None or written + len(data) <= stallAfterBytes:
            return data

        return data[:stallAfterBytes - written]

    def _handlePostWriteDebugOptions(self, written, debugOptions, logicalDl=None):
        """Execute post-write debug/test actions such as stall or forced disconnect."""
        stallAfterBytes = debugOptions.get('stallAfterBytes')
        if stallAfterBytes is not None and written >= stallAfterBytes:
            flushPrint(f"[Test] Stall injection: blocking after {written} bytes (stall-after={stallAfterBytes})")
            debugOptions['stallAfterBytes'] = None # Only stall once
            self.wfile.flush()
            while True:
                self._ensureLogicalDownloadStillActive(logicalDl)
                time.sleep(0.25)

        disconnectAfterBytes = debugOptions.get('disconnectAfterBytes')
        if disconnectAfterBytes is not None and written >= disconnectAfterBytes:
            flushPrint(
                f"[Test] Disconnect injection: closing connection after {written} bytes "
                f"(disconnect-after={disconnectAfterBytes})"
            )
            debugOptions['disconnectAfterBytes'] = None
            self.wfile.flush()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                logger.debug(f"Disconnect injection shutdown already closed socket: {e}")
            try:
                self.connection.close()
            except OSError as e:
                logger.debug(f"Disconnect injection close already closed socket: {e}")
            raise ConnectionResetError("Disconnect injection triggered")

    def _handleDownloadExceptionActions(self, exception):
        # Determine failure reason
        if isinstance(exception, FolderChangedException):
            # Folder content changed during transfer
            errorMsg = str(exception)
            filePath = getattr(exception, 'filePath', None)
            reason = 'folder-changed'

            # Notify sharer
            flushPrint(_('\n⚠️  TRANSFER ABORTED: {errorMsg}').format(errorMsg=errorMsg))
            flushPrint(_('The shared folder contents changed during the transfer.'))
            flushPrint(_('Please ensure the folder contents remain stable and try sharing again.\n'))

            # Set error state for status polling with error type for i18n
            self.session.lastError = {
                'type': 'folder_changed',
                'detail': errorMsg,
                'filePath': filePath,
                'exceptionClass': exception.__class__.__name__
            }
        elif isinstance(exception, (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError)):
            flushPrint(_('\nConnection disconnected, wait retrying.\n'))
            reason = 'connection-lost'
            errorMsg = 'Connection lost'
        elif isinstance(exception, OSError):
            flushPrint(_('\nUser closes the connection, please try again.\n'))
            reason = 'connection-closed'
            errorMsg = 'User closed connection'
        else:
            logger.debug(f'_handleDownloadExceptionActions: {exception}')
            reason = 'unknown'
            errorMsg = str(exception)

        # Trigger downloadFailed event
        FFLEvent.downloadFailed.trigger(
            downloadId=self._downloadId,
            reason=reason,
            error=errorMsg,
            bytesTransferred=0, # We don't track this in exception handler
            totalBytes=None,
            duration=time.time() - self._downloadStartTime
        )

    def _getLogicalDownloadId(self, args):
        if not args:
            return None

        logicalDl = args.get('dl', [None])[0]
        return logicalDl or None

    def _registerLogicalDownloadRequest(self, args, start, end):
        logicalDl = self._getLogicalDownloadId(args)
        if not logicalDl:
            return None

        supersededRequestIds = self.session.logicalDownloadRequestStore.register(
            logicalDl=logicalDl,
            requestId=self._downloadId,
            rangeStart=start,
            rangeEnd=end,
        )

        if supersededRequestIds:
            logger.info(
                f"Superseding {len(supersededRequestIds)} overlapping request(s) "
                f"for logical dl={logicalDl}: {', '.join(requestId[:8] for requestId in supersededRequestIds)}"
            )

        return logicalDl

    def _ensureLogicalDownloadStillActive(self, logicalDl):
        if not logicalDl:
            return

        if self.session.logicalDownloadRequestStore.isSuperseded(logicalDl, self._downloadId):
            try:
                self.wfile.flush()
            except OSError as e:
                logger.debug(f"Superseded logical download flush failed: {e}")

            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                logger.debug(f"Superseded logical download shutdown failed: {e}")

            try:
                self.connection.close()
            except OSError as e:
                logger.debug(f"Superseded logical download close failed: {e}")

            raise SupersededDownloadError(
                f"Superseded by newer overlapping request for logical dl={logicalDl}"
            )

    def _handleE2EEManifest(self, args):
        """Handle /e2ee/manifest endpoint - returns E2E encryption metadata"""
        logger.debug(f"[E2EE] Manifest request - e2eeEnabled={self.session.config.e2eeEnabled}")
        
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            self._handle404(f"[E2EE] E2EE not enabled, returning silent 404 for /e2ee/manifest")
            return

        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
        filename = name

        manifest = {
            'e2eeEnabled': True,
            'filename': filename,
            'filesize': CryptoHelper.normalizeFileSize(size),
            'chunkSize': self.session.e2eeManager.chunkSize
        }

        response = json.dumps(manifest).encode('utf-8')

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def _handleForbidden(self, message='Disabled by server policy'):
        self._handleForbiddenHead(message)
        self.wfile.write(message.encode('utf-8'))

    def _guardRequest(self) -> bool:
        """Return True if the request may proceed; otherwise send the error response and return False."""
        if self.session is None:
            self._handle404()
            return False
            
        if not self.handleAuthentication():
            return False
            
        if self._pathForbidden:
            self._handleForbidden()
            return False
            
        return True

    def _handle404(self, message=None):
        if message:
            logger.debug(message)

        content = str(HTTPStatus.NOT_FOUND)
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/html")
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())

    def _handleE2EETags(self, args):
        """Handle /e2ee/tags endpoint - returns tags for chunk range

        Query parameters:
            start: Starting chunk index
            count: Number of tags to return
            streamId: Stream identifier (optional, default: "global")
        """
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            self._handle404(f"[E2EE] E2EE not enabled, returning silent 404 for /e2ee/tags")
            return

        try:
            # Parse query parameters from args (already parsed by do_GET)
            startChunk = int(args.get('start', ['0'])[0])
            count = int(args.get('count', ['0'])[0])
            streamId = args.get('streamId', ['global'])[0] # Default to "global" for backwards compatibility

            logger.debug(f"[E2EE] Tags request: streamId={streamId}, start={startChunk}, count={count}")

            if count <= 0:
                logger.warning(f"[E2EE] Invalid count parameter: {count}")
                self.send_error(HTTPStatus.BAD_REQUEST, f"Invalid count parameter: {count}")
                return

            # Load all tags from E2EEManager for specified stream
            allTags = self.session.e2eeManager.getTags(streamId)
            logger.debug(f"[E2EE] Total tags available for stream '{streamId}': {len(allTags)}")

            # Filter tags by range
            endChunk = startChunk + count
            requestedTags = [tag for tag in allTags if startChunk <= tag['chunkIndex'] < endChunk]

            logger.debug(f"[E2EE] Returning {len(requestedTags)} tags for range [{startChunk}, {endChunk})")

            response = json.dumps({'tags': requestedTags}).encode('utf-8')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in E2EE tags endpoint")
        except Exception as e:
            logger.error(f"[E2EE] Tags endpoint error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def _handleE2EEInit(self, data):
        """Handle /e2ee/init endpoint - RSA key exchange for E2E encryption"""
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            self._handle404(f"[E2EE] E2EE not enabled, returning silent 404 for /e2ee/init")
            return

        try:
            publicKeyPem = data.get('publicKey')
            if not publicKeyPem:
                self.send_error(HTTPStatus.BAD_REQUEST, "Missing publicKey")
                return

            # Get file metadata
            path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
            filename = name

            # Delegate to E2EEManager
            responseData = self.session.e2eeManager.handleInit(publicKeyPem, filename, size)
            response = json.dumps(responseData).encode('utf-8')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in E2EE init endpoint")
        except Exception as e:
            logger.error(f"E2EE init error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def _parseCookie(self, name: str) -> Optional[str]:
        """Extract a single cookie value by name from the Cookie request header."""
        cookieHeader = self.headers.get('Cookie', '')
        for part in cookieHeader.split(';'):
            k, _, v = part.strip().partition('=')
            if k.strip() == name:
                return v.strip()

        return None

    def _sendRateLimitExceeded(self) -> None:
        """Send a 429 Too Many Requests response when the rate limiter is locked."""
        message = b'Too many failed attempts. Try again in 5 minutes.'
        self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(message)))
        self.send_header('Retry-After', str(AuthRateLimiter.LOCKOUT_DURATION))
        self.end_headers()
        self.wfile.write(message)

    def _sendAuthFailure(self, message: bytes) -> None:
        """Send a 401 Unauthorized response with a plain-text message."""
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        self.wfile.write(message)

    def _createAuthSession(self) -> None:
        """Create a download session or reuse the caller's existing valid session.

        This keeps browser-side auth retries idempotent: if the same client already
        holds a valid `ffl_dlk` cookie, return 204 again instead of failing with an
        "already claimed" error. A different client without that cookie still cannot
        claim the single-use session after the first successful auth.
        """
        existingDlk = self._parseCookie('ffl_dlk')
        if existingDlk and self.session.downloadSessionStore.validate(existingDlk):
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        try:
            dlk = self.session.downloadSessionStore.create()
        except RuntimeError:
            self._sendAuthFailure(b'Pickup already claimed.')
            return

        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header(
            'Set-Cookie',
            f'ffl_dlk={dlk}; HttpOnly; Secure; SameSite=Strict; '
            f'Max-Age={DownloadSessionStore.SESSION_TTL}; Path=/'
        )
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _verifyEmailOTP(self, email: str, otp: str, link: str) -> bool:
        """Verify email OTP by calling the FFL OTP verification API.

        The Python P2P server acts as a proxy: the browser sends the OTP it received
        via email, and the server forwards it to the FFL API for cryptographic verification.
        """
        recipientAuth = self.session.config.recipientAuth
        if not email or not otp or not recipientAuth or not recipientAuth.otpVerifyUrl:
            return False

        if not recipientAuth.isAllowedEmail(email):
            return False

        try:
            resp = requests.post(
                recipientAuth.otpVerifyUrl, json={
                    'email': email,
                    'otp': otp,
                    'link': link or ''
                }, timeout=10
            )
            return resp.ok and bool(resp.json().get('verificationToken'))
        except Exception as e:
            logger.warning(f'Email OTP verification failed: {e}')
            return False

    def _handleEmailOTPRequest(self, data):
        """POST /{uid}/email/request — proxy OTP send request to FFL API (avoids CORS).

        Browser posts {email, link} to the same-origin P2P server; this method
        forwards the request to the FFL API server-side and relays the response.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.requiresEmail() or not recipientAuth.otpRequestUrl:
            self.send_error(400, 'Email auth not enabled')
            return

        email = data.get('email') or recipientAuth.getPrimaryRecipientEmail()
        if not recipientAuth.isAllowedEmail(email):
            body = json.dumps({'error': 'This email address is not allowed to download this file.'}).encode('utf-8')
            self.send_response(HTTPStatus.FORBIDDEN)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        link = data.get('link', '')
        language = data.get('language')
        try:
            resp = requests.post(
                recipientAuth.otpRequestUrl, json={
                    'email': email,
                    'link': link,
                    'language': language
                }, timeout=10
            )
            self.send_response(resp.status_code)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            body = resp.content
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in email OTP request")
        except Exception as e:
            logger.warning(f'Email OTP request proxy failed: {e}')
            self.send_error(502, 'Failed to reach OTP service')

    def _handleAuth(self, data):
        """POST /{uid}/auth — exchange X-FFL-* credentials for a download session cookie.

        On success: 204 No Content (+ Set-Cookie when session is created).
        On failure: 401 Unauthorized.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.isEnabled():
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        rateLimiter = self.session.authRateLimiter
        code = self.headers.get('X-FFL-Pickup')
        proof = self.headers.get('X-FFL-Proof')
        emailOtp = self.headers.get('X-FFL-EmailOTP')
        emailAddr = self.headers.get('X-FFL-EmailAddress')
        emailLink = self.headers.get('X-FFL-EmailLink')
        verifyParam = data.get('verify')

        if verifyParam == 'code':
            if recipientAuth.verifyCode(code):
                rateLimiter.recordSuccess('pickup')
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header('Content-Length', '0')
                self.end_headers()
            elif rateLimiter.isLocked('pickup'):
                self._sendRateLimitExceeded()
            else:
                rateLimiter.recordFailure('pickup')
                self._sendAuthFailure(b'Invalid pickup code.')
            return

        if verifyParam == 'proof':
            if recipientAuth.verifyProof(proof):
                rateLimiter.recordSuccess('pubkey')
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header('Content-Length', '0')
                self.end_headers()
            elif rateLimiter.isLocked('pubkey'):
                self._sendRateLimitExceeded()
            else:
                rateLimiter.recordFailure('pubkey')
                self._sendAuthFailure(b'Invalid pubkey proof.')
            return

        if recipientAuth.requiresEmail():
            if self._verifyEmailOTP(emailAddr or recipientAuth.getPrimaryRecipientEmail(), emailOtp, emailLink):
                rateLimiter.recordSuccess('email')
                self._createAuthSession()
            elif rateLimiter.isLocked('email'):
                self._sendRateLimitExceeded()
            else:
                rateLimiter.recordFailure('email')
                self._sendAuthFailure(b'Invalid or expired email OTP.')
            return

        authType = recipientAuth.mode.value
        if recipientAuth.verify(code=code, proof=proof):
            rateLimiter.recordSuccess(authType)
            self._createAuthSession()
        elif rateLimiter.isLocked(authType):
            self._sendRateLimitExceeded()
        else:
            rateLimiter.recordFailure(authType)
            self._sendAuthFailure(b'Invalid credentials.')

    def _handleRecipientAuth(self, args: dict) -> bool:
        """Verify recipient credentials via session cookie or X-FFL-* headers.

        Accepts either:
        - ffl_dlk cookie (browser path — set after POST /auth)
        - X-FFL-Pickup / X-FFL-Proof headers (curl / CLI path)

        Returns False and sends 401 on failure.
        """
        recipientAuth = self.session.config.recipientAuth
        if not recipientAuth or not recipientAuth.isEnabled():
            return True

        # Cookie-based session (browser <a href> fallback path) — bypasses rate limit
        dlk = self._parseCookie('ffl_dlk')
        if dlk and self.session.downloadSessionStore.validate(dlk):
            return True

        rateLimiter = self.session.authRateLimiter
        authType = recipientAuth.mode.value

        # Direct header auth (curl / CLI path) — verify first, then rate-limit
        if recipientAuth.requiresEmail():
            emailOtp = self.headers.get('X-FFL-EmailOTP')
            emailAddr = self.headers.get('X-FFL-EmailAddress') or recipientAuth.getPrimaryRecipientEmail()
            emailLink = self.headers.get('X-FFL-EmailLink')
            ok = self._verifyEmailOTP(emailAddr, emailOtp, emailLink)
        else:
            code = self.headers.get('X-FFL-Pickup')
            proof = self.headers.get('X-FFL-Proof')
            ok = recipientAuth.verify(code=code, proof=proof)

        if ok:
            rateLimiter.recordSuccess(authType)
            return True

        if rateLimiter.isLocked(authType):
            self._sendRateLimitExceeded()
            return False

        rateLimiter.recordFailure(authType)
        self._sendAuthFailure(b'Invalid or missing credentials.')
        return False

    def _handleDownload(self, args):
        if not self._handleRecipientAuth(args):
            return

        debugOptions = self._getDownloadDebugOptions(args)

        # Get file info using existing helper method
        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
        self._appendDownloadRequestLog(args, name, size)

        requestedStart = self.range[0] if self.range else 0
        canResumeFromStart = reader.canResumeFrom(requestedStart)

        # Check if reader has already been consumed (for single-use sources like stdin)
        if reader.consumed and not canResumeFromStart:
            # Single-use reader already consumed - return 410 Gone
            self.send_response(HTTPStatus.GONE)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            message = "This resource has already been downloaded and is no longer available (single-use only)."
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message.encode('utf-8'))
            return

        # Start to download
        self._downloadStartTime = time.time()
        try:
            self._handleStartDownloadActions(size)
        except PermissionError as e:
            # File size or other validation error from enhanced handler
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return

        settingsGetter = SettingsGetter.getInstance()

        logicalDl = None
        written = 0
        totalSizeHeader = size if size is not None else '*'
        progress = Progress(
            size,
            sizeFormatter=formatSize,
            loggerCallback=flushPrint,
            logInterval=LOG_OUTPUT_DURATION,
            useBar=settingsGetter.isCLIMode(),
        )

        start = None
        end = None
        checksumSession = None
        shouldCommitChecksum = False

        try:
            # Handle range requests (only for files that support it)
            if self.range and not (reader.supportsRange or canResumeFromStart):
                # Directory streams don't support Range
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header("Content-Range", f'bytes */{totalSizeHeader}')
                self.end_headers()
                return

            if self.range:
                start, end = self.range
            else:
                # For unknown size (stdin, ZIP deflate), use None for end
                start = 0

            if size and size >= 0:
                end = end if end else size - 1

            # Determine if we should use chunked encoding
            useChunked = (size is None)
            logicalDl = self._registerLogicalDownloadRequest(args, start, end)

            # Send appropriate response headers
            if 'Range' in self.headers:
                if self.range and (reader.supportsRange or canResumeFromStart):
                    self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    if size is not None:
                        self.send_header("Content-Length", str(end - start + 1))
                        self.send_header("Content-Range", f'bytes {start}-{end}/{size}')
                    else:
                        self.send_header("Transfer-Encoding", "chunked")

                    if canResumeFromStart and not reader.supportsRange:
                        self.send_header("FFL-Resume-Mode", "handoff")
                        self.send_header("FFL-Resume-Start", str(start))
                        logger.info("Stdin handoff resume accepted at byte %s", start)
                else:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f'bytes */{totalSizeHeader}')
                    self.end_headers()
                    return
            else:
                self.send_response(HTTPStatus.OK)
                if size is not None:
                    self.send_header("Content-Length", str(size))
                else:
                    # For unknown size (stdin, ZIP deflate), use chunked transfer encoding
                    self.send_header("Transfer-Encoding", "chunked")

            viewMode = self.parseURLBooleanParam(args.get('view', [None])[0]) is True if args else False
            if viewMode:
                mediaType = self.guess_type(name)
                self.send_header("Content-type", mediaType)
                self.send_header("Content-Disposition", f"inline; filename={quote(name)}")
            else:
                self.send_header("Content-type", ctype)
                self.send_header("Content-Disposition", f"attachment; filename={quote(name)}")
            self.end_headers()

            written += start

            # Initialize E2E encryptor if enabled
            encryptor = None
            if self.session.config.e2eeEnabled:
                # Calculate starting chunk index for Range support
                startChunkIndex = start // self.session.e2eeManager.chunkSize
                # Only save tags if this is an aligned Range request (or full download)
                saveTags = (start % self.session.e2eeManager.chunkSize == 0)

                encryptor = self.session.e2eeManager.createEncryptor(
                    filename=name, filesize=size, startChunkIndex=startChunkIndex, saveTags=saveTags
                )

            checksumSession = self.session.checksumStore.begin(transport='http', e2ee=bool(encryptor))
            shouldCommitChecksum = (not self.range) and start == 0

            # Send file/directory data in chunks
            chunkSize = self.session.e2eeManager.chunkSize if self.session.config.e2eeEnabled else self.CHUNK_SIZE
            progressThrottler = Throttler(interval=1.0)

            for data in reader.iterChunks(chunkSize, start=start):
                self._ensureLogicalDownloadStillActive(logicalDl)

                # Ensure we don't send beyond the requested range (if known)
                if end is not None and written + len(data) > end + 1:
                    data = data[:end + 1 - written]

                # Debug/test injections are applied before encryption so any truncation
                # still produces a valid (shorter) plaintext chunk.
                data = self._truncateChunkForDebugOptions(data, written, debugOptions)

                # Encrypt if E2EE enabled
                if encryptor:
                    data = encryptor.encryptChunk(data)

                checksumSession.update(data)

                # Write using chunked encoding or direct write
                if useChunked:
                    self._writeChunk(data)
                else:
                    self.wfile.write(data)

                written += len(data)
                self.session.downloadProgressStore.update(self._downloadId, written)

                self._handlePostWriteDebugOptions(written, debugOptions, logicalDl=logicalDl)

                # Update progress periodically
                progress.update(written)

                # Trigger downloadProgress event (throttled)
                if progressThrottler.shouldTrigger():
                    currentTime = time.time()
                    percentage = (written * 100.0 / size) if size and size > 0 else 0
                    duration = currentTime - self._downloadStartTime
                    speed = int(written / duration) if duration > 0 else 0

                    FFLEvent.downloadProgress.trigger(
                        downloadId=self._downloadId,
                        bytesTransferred=written,
                        totalBytes=size,
                        percentage=percentage,
                        speed=speed,
                        connectionType='http',
                        elapsedTime=duration,
                        estimatedRemaining=((size - written) / speed) if (speed > 0 and size) else None
                    )

                # Break if we've reached the end (for known size)
                if end is not None and written > end:
                    break

            # Finish chunked encoding if used
            if useChunked:
                self._finishChunked()

            # Flush the output buffer
            self.wfile.flush()

            # Final progress update
            progress.update(written, forceLog=True, forceFinish=size is None)

            if shouldCommitChecksum:
                checksumSession.commit()

            # Wait for client to ACK receipt before triggering post-download actions.
            # Without this, server.shutdown() (on maxDownloads) can race the relay/tunnel
            # still draining buffered bytes to the client, truncating the download.
            self._waitForHTTPDownloadComplete()

            # Handle post-download actions
            self._handlePostDownloadActions(size)

        except FolderChangedException as e:
            self._handleDownloadExceptionActions(e)
        except (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError) as ce:
            self._handleDownloadExceptionActions(ce)
        except OSError as e:
            self._handleDownloadExceptionActions(e)
        finally:
            if checksumSession and not checksumSession.isClosed:
                checksumSession.abort()

            # Always clean up the completion state and progress tracking
            self.session.httpDownloadCompletionStore.unregister(self._downloadId)
            self.session.downloadProgressStore.unregister(self._downloadId)
            if logicalDl:
                self.session.logicalDownloadRequestStore.unregister(logicalDl, self._downloadId)

    def _buildTemplateContext(self, args) -> dict:
        """Build the Jinja2 template context for index.html.

        Subclasses override this to add or modify context variables,
        calling super()._buildTemplateContext(args) and updating the result.
        """
        settingsGetter = SettingsGetter.getInstance()
        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)

        mediaContentType = self.guess_type(name) or ctype or ''
        mediaType = mediaContentType.split('/')[0] if mediaContentType else ''
        sizeDisplay = formatSize(size) if size else ''
        ogTitle = f'{name} ({sizeDisplay})' if sizeDisplay else name

        if mediaType == 'video':
            metaDescription = _('Tap to watch {fileName}').format(fileName=name)
            ogType = 'video.other'
        elif mediaType == 'audio':
            metaDescription = _('Tap to listen to {fileName}').format(fileName=name)
            ogType = 'music.song'
        elif mediaType == 'image':
            metaDescription = _('Tap to view {fileName}').format(fileName=name)
            ogType = 'article'
        else:
            metaDescription = _('Tap to download {fileName}').format(fileName=name)
            ogType = 'article'

        recipientAuth = self.session.config.recipientAuth
        pubkeyChallenges = []
        if recipientAuth and recipientAuth.requiresPubkey():
            pubkeyChallenges = [
                base64.b64encode(challengeCiphertext).decode('ascii')
                for challengeCiphertext in recipientAuth.getChallengeCiphertexts()
            ]

        clientDebugFlags = self._getClientDebugFlags(args)
        webrtcDisabled = clientDebugFlags['webrtcDisabled']
        if not clientDebugFlags['webrtcDisabledDetermined'] and not self.session.config.defaultWebRTC:
            webrtcDisabled = True

        return {
            # Static assets
            'staticServer': settingsGetter.getStaticServer(),
            
            # Session
            'uid': self.session.uid,
            
            # File metadata
            'fileName': name,
            'fileSize': size if size is not None else -1,
            'fileContentType': mediaContentType,
            
            # Open Graph / meta
            'ogTitle': ogTitle,
            'metaDescription': metaDescription,
            'ogType': ogType,
            
            # Auth gates
            'pickupRequired': bool(recipientAuth and recipientAuth.requiresPickup()),
            'pubkeyRequired': bool(recipientAuth and recipientAuth.requiresPubkey()),
            'pubkeyChallenges': pubkeyChallenges,
            'emailRequired': bool(recipientAuth and recipientAuth.requiresEmail()),
            'recipientEmails': list(recipientAuth.recipientEmails) if recipientAuth else [],
            
            # Branding / content
            'copyright': settingsGetter.getCopyright(),
            'downloadNoteHtml': settingsGetter.getDownloadNote(),
            'receiptConfirmMessage': None,
            
            # JS flags
            'debug': clientDebugFlags['debugEnabled'],
            'serverDebug': clientDebugFlags['serverDebugEnabled'],
            'disableWebRTC': webrtcDisabled,
            'streamSaverBlob': 1 if clientDebugFlags['streamSaverBlob'] else 0,
            'statusPollingSeconds': 5 if self.session.config.torEnabled else 2,
            
            # Extension points — addons fill these via _buildTemplateContext override
            'extraHeadStyles': '',
            'pageHeader': '',
            'pageTitle': 'FastFileLink',
            'downloadContainerClass': 'main-banner',
            'titlePrimaryClass': '',
            'titleAccentClass': '',
            'pageFooterNote': '',
            'extraBodyContent': '',
        }

    @property
    def _jinja2Env(self):
        if DownloadHandler._jinja2EnvCache is None:
            settingsGetter = SettingsGetter.getInstance()
            DownloadHandler._jinja2EnvCache = Environment(
                loader=FileSystemLoader(os.path.join(settingsGetter.baseDir, 'static')),
                autoescape=False,
                keep_trailing_newline=True,
            )
        
        return DownloadHandler._jinja2EnvCache

    def _renderIndexTemplate(self, context: dict) -> bytes:
        """Render index.html using Jinja2 with the given context."""
        return self._jinja2Env.get_template('index.html').render(**context).encode('utf-8')

    def _handleStaticIndex(self, args):
        try:
            content = self._renderIndexTemplate(self._buildTemplateContext(args))

            if self.range:
                start, end = self.range
                end = end if end else len(content) - 1
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Length", str(end - start + 1))
                self.send_header('Content-Range', f'bytes {start}-{end}/{len(content)}')
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(content[start:end + 1])
            else:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(content)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected while serving static file")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _serveLocalStaticScript(self, requestHeaders=None):
        """Serve script from local filesystem."""
        self._extraHeaders = requestHeaders or {}
        super().do_GET()

    def _proxyStaticScript(self, scriptPath, requestHeaders=None, fallbackToLocal=False):
        """Generic method to proxy JavaScript files from static server

        Args:
            scriptPath: Relative path to script (e.g., "/static/js/E2EE.js")
            requestHeaders: Optional dict of additional headers to send with request
            fallbackToLocal: If True, fallback to local script when remote fetch fails
        """
        try:
            settingsGetter = SettingsGetter.getInstance()
            staticServer = settingsGetter.getStaticServer()
            remoteUrl = f"{staticServer}{scriptPath}"

            # Force identity encoding so the upstream returns plain bytes.
            # Copying remote Content-Encoding (zstd/gzip) while requests may have
            # already decoded the body causes Content-Length mismatches that break
            # HTTP/2 streams with INTERNAL_ERROR.
            headers = dict(requestHeaders or {})
            headers['Accept-Encoding'] = 'identity'

            response = requests.get(remoteUrl, headers=headers, timeout=10)
            response.raise_for_status()

            content = response.content
            contentType = response.headers.get('Content-Type', 'application/javascript')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', contentType)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        except requests.RequestException as e:
            if fallbackToLocal:
                logger.warning(
                    f"Failed to fetch {scriptPath} from {remoteUrl}, fallback to local script: {e}"
                )
                self._serveLocalStaticScript(requestHeaders=requestHeaders)
                return

            logger.error(f"Failed to fetch {scriptPath} from {remoteUrl}: {e}")
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Failed to fetch from remote server: {str(e)}")
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected while proxying static script")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleStaticScript(self, scriptPath, requestHeaders=None, fallbackToLocal=False):
        """Handle static script - proxy from remote or serve locally

        Args:
            scriptPath: Path to the script file
            requestHeaders: Headers to send with remote request (proxy mode) or set in response (local mode)
            fallbackToLocal: If True, fallback to local script when remote fetch fails
        """
        settingsGetter = SettingsGetter.getInstance()
        staticServer = settingsGetter.getStaticServer()

        # If static server is remote (starts with http), proxy the file
        if staticServer.startswith('http'):
            self._proxyStaticScript(scriptPath, requestHeaders, fallbackToLocal=fallbackToLocal)
        else:
            # Static server is local - serve from local filesystem
            self._serveLocalStaticScript(requestHeaders=requestHeaders)

    def _handleProgressServiceWorker(self, args):
        """Handle ProgressServiceWorker.js - proxy from remote or serve locally"""
        # Service worker requires special headers
        requestHeaders = {'Service-Worker': 'script', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/'}
        self._handleStaticScript("/static/js/ProgressServiceWorker.js", requestHeaders)

    def _handleChecksumScript(self, args):
        """Handle Checksum.js - proxy from remote or serve locally.
        Required for same-origin importScripts() in ProgressServiceWorker.js."""
        self._handleStaticScript("/static/js/Checksum.js")

    def _handleE2EEScript(self, args):
        """Handle E2EE.js - proxy from remote or serve locally"""
        self._handleStaticScript("/static/js/E2EE.js")

    def _handleStatus(self, args):
        """Handle status polling endpoint for error notifications and server-side stall detection.

        Each poll checks all active HTTP downloads for stalls.  When one is found,
        /diagnosis is called via the public tunnel URL (from the Host header of this
        very request) so the tunnel/relay also records the event.  The call is fired
        in a daemon thread so it never delays the /status response.

        DownloadHandler is instantiated per request, so self.headers already carries
        the current client's Host / X-Forwarded-Proto — no extra context needed.
        """
        try:
            # Resolve public base URL once from this request's headers.
            # Tunnel URLs always use HTTPS and contain dots; localhost/bare-IP is HTTP.
            host = self.headers.get('Host', '')
            scheme = self.headers.get('X-Forwarded-Proto', '')
            if not scheme:
                scheme = 'https' if (host and '.' in host and 'localhost' not in host) else 'http'

            publicBaseUrl = f'{scheme}://{host}' if host else f'http://localhost:{self.server.server_address[1]}'
            uid = self.session.uid

            for info in self.session.downloadProgressStore.getStalledDownloads():
                self.session.downloadProgressStore.markStallReported(info['downloadId'])

                downloadId = info['downloadId']
                written = info['written']
                total = info['total']
                stallMs = int((time.time() - info['lastUpdateTime']) * 1000)

                if written == 0:
                    phase = 'first-byte'
                elif total and total > 0 and written / total >= 0.95:
                    phase = 'tail'
                else:
                    phase = 'mid-stream'

                percent = f'{written / total * 100:.2f}' if total and total > 0 else 'unknown'
                diagnosisUrl = f'{publicBaseUrl}/{uid}/diagnosis'
                params = {
                    'type': 'http',
                    'phase': phase,
                    'delivered': str(written),
                    'total': str(total) if total is not None else '?',
                    'stall_ms': str(stallMs),
                    'percent': percent,
                    'probe_status': 'server-side',
                    'range_ok': '?',
                    'has_auth': '?',
                    'browser': '?',
                    'ff_pass': '?',
                    'e2ee': str(self.session.config.e2eeEnabled).lower(),
                    'resume': '?',
                    'dl': downloadId,
                    'source': 'server',
                }

                logger.warning(
                    f"[Status] Server-side stall | dl={downloadId[:8]} phase={phase}"
                    f" written={written}/{total} stall={stallMs}ms → {diagnosisUrl}"
                )

                def fire(url=diagnosisUrl, p=params):
                    try:
                        requests.get(url, params=p, timeout=10)
                    except Exception as exc:
                        logger.debug(f"[Status] /diagnosis call failed: {exc}")

                threading.Thread(target=fire, daemon=True).start()

            status = {'error': self.session.lastError if self.session.lastError else None}

            responseBody = json.dumps(status).encode('utf-8')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(responseBody)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(responseBody)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in status endpoint")
        except Exception as e:
            logger.exception(f"Status endpoint error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Status endpoint error")

    def _handleDiagnosis(self, args):
        """Handle stall diagnosis reports from the Service Worker or server-side stall detection.

        The SW sends this when it detects no data has flowed for stallMs milliseconds.
        The /status handler also fires this when it detects a server-side stall (source=server).
        Fields logged here help identify recurring stall patterns (browser, position, probe result, etc.).

        When FFL_DIAGNOSIS_LOG is set, each report is appended as a JSON line to that file.
        This is used by tests to verify that /diagnosis was called with the correct parameters.
        """

        def first(key, default=''):
            values = args.get(key)
            return values[0] if values else default

        transportType = first('type', 'unknown')
        phase = first('phase', 'unknown')
        delivered = first('delivered', '?')
        total = first('total', '?')
        stallMs = first('stall_ms', '?')
        percent = first('percent', '?')
        probeStatus = first('probe_status', '?')
        rangeOk = first('range_ok', '?')
        hasAuth = first('has_auth', '?')
        browser = first('browser', '?')
        ffPass = first('ff_pass', '?')
        e2ee = first('e2ee', '?')
        resume = first('resume', '?')
        downloadId = first('dl', '?')
        source = first('source', 'sw')
        userAgent = self.headers.get('User-Agent', 'unknown')

        dlShort = downloadId[:8] if len(downloadId) >= 8 else downloadId

        logger.warning(
            f"[Diagnosis] Stall | type={transportType} phase={phase}"
            f" delivered={delivered}/{total} ({percent}%)"
            f" stall={stallMs}ms probe={probeStatus} range_ok={rangeOk}"
            f" browser={browser} has_auth={hasAuth} ff_pass={ffPass} e2ee={e2ee} resume={resume}"
            f" source={source} dl={dlShort} ua={userAgent}"
        )

        diagLogPath = os.getenv('FFL_DIAGNOSIS_LOG', '')
        if diagLogPath:
            record = {
                'type': transportType,
                'phase': phase,
                'delivered': delivered,
                'total': total,
                'stall_ms': stallMs,
                'percent': percent,
                'probe_status': probeStatus,
                'range_ok': rangeOk,
                'has_auth': hasAuth,
                'browser': browser,
                'ff_pass': ffPass,
                'e2ee': e2ee,
                'resume': resume,
                'dl': downloadId,
                'source': source,
            }
            try:
                with open(diagLogPath, 'a', encoding='utf-8') as diagLog:
                    diagLog.write(json.dumps(record) + '\n')
                    diagLog.flush()
            except Exception as exc:
                logger.debug(f"[Diagnosis] Failed to write to FFL_DIAGNOSIS_LOG: {exc}")

        self._sendBytes(b'ok')

    def _handleChecksum(self, args):
        """Handle checksum polling endpoint for download integrity verification."""
        try:
            responseData = self.session.checksumStore.getResponseData()
            recipientAuth = self.session.config.recipientAuth
            if recipientAuth and recipientAuth.requiresPubkey():
                # Expose the RSA-OAEP challenge for CLI clients downloading via P2P.
                # The browser gets these challenges baked into index.html as PUBKEY_CHALLENGES
                # at serve time; CLI clients (ffl download <url>) cannot render HTML, so they
                # fetch /checksum to retrieve it dynamically and decrypt it with their private key.
                encryptedChallenges = [
                    base64.b64encode(challengeCiphertext).decode()
                    for challengeCiphertext in recipientAuth.getChallengeCiphertexts()
                ]
                responseData['encrypted_challenges'] = encryptedChallenges

            responseBody = json.dumps(responseData).encode('utf-8')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(responseBody)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(responseBody)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in checksum endpoint")
        except Exception as e:
            logger.exception(f"Checksum endpoint error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Checksum endpoint error")

    def _detectBrowser(self):
        """Detect browser type from User-Agent header for DTLS strategy selection"""
        user_agent = self.headers.get('User-Agent', '').lower()

        if 'firefox' in user_agent:
            return 'firefox'
        elif 'chrome' in user_agent:
            return 'chrome'
        elif 'edge' in user_agent:
            return 'edge'
        elif 'safari' in user_agent and 'chrome' not in user_agent:
            return 'safari'
        else:
            return 'unknown'

    def _handleWebRTCOffer(self, args):
        if not self._handleRecipientAuth(args):
            return

        try:
            # Check for debug simulation parameters
            debugOptions = self._getWebRTCDebugOptions(args)
            if debugOptions['simulateIceFailure']:
                logger.warning("Debug: Simulating ICE failure - returning 500 error")
                self.send_error(500, "Simulated ICE connection failure for testing")
                return

            if debugOptions['simulateStall']:
                stallAfter = debugOptions['stallAfterBytes']
                logger.warning(f"Debug: Simulating stall after {stallAfter} bytes - WebRTC will work initially")

            # Handle resume offset parameter
            offset = self._parseIntArg(args, 'offset', default=0)
            if offset:
                logger.info(f"Resume requested from offset: {offset}")

            path, name, size, ctype, reader = self._getFileInfo()

            # Detect browser for DTLS strategy selection
            browserHint = self._detectBrowser()
            logger.info(
                f"Detected browser: {browserHint} from User-Agent: {self.headers.get('User-Agent', 'N/A')[:100]}..."
            )

            # Pass E2EEManager if E2EE is enabled
            e2eeManager = self.session.e2eeManager if self.session.config.e2eeEnabled else None

            offer = self.session.webRTC.runAsync(
                self.session.webRTC.createOffer(
                    reader, size, formatSize, browserHint=browserHint, offset=offset, e2eeManager=e2eeManager
                )
            )

            # Trigger webrtcOfferReceived event
            FFLEvent.webrtcOfferReceived.trigger(
                peerId=offer.get('peerId'),
                sessionId=offer.get('sessionId'),
                timestamp=datetime.datetime.now().isoformat()
            )

            self._sendBytes(json.dumps(offer).encode(), "application/json; charset=utf-8")

        except WebRTCDisabledError as e:
            # Handle WebRTC policy enforcement - use 403 Forbidden
            logger.info(f"WebRTC offer rejected by policy: {e.reason}")
            self.send_error(HTTPStatus.FORBIDDEN, e.reason)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in WebRTC offer endpoint")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleWebRTCCandidatePolling(self, args):
        try:
            # Get peerId from query parameters
            peerId = args.get("peer", [""])[0] if "peer" in args else ""

            if not peerId:
                self._handle404("Missing peer parameter")
                return

            # Get candidate from WebRTC manager
            try:
                candidate = self.session.webRTC.getCandidates(peerId)
            except ValueError:
                self._handle404("Unknown peer")
                return

            if candidate:
                # Return candidate data as JSON
                self._sendBytes(json.dumps(candidate).encode(), "application/json; charset=utf-8")
            else:
                # No candidates available, return 204 No Content
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in WebRTC candidate polling")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def do_GET(self):
        if not self._guardRequest():
            return

        self._parseRange()

        # Get the appropriate handler for this path
        handler = self.getPathMap.get(self.path)
        logger.debug(f"[ROUTE] GET {self.path} -> handler={'found' if handler else 'NOT FOUND (using default)'}")
        if handler:
            handler(self._requestArgs)
        else:
            # Default handling for other paths
            try:
                super().do_GET()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                logger.debug("Client disconnected in GET handler")
            except Exception as e:
                logger.exception(e)
                self.send_error(500, str(e))

    def _sendBytes(self, payload: bytes, ctype: str = "text/plain; charset=utf-8", extraHeaders: dict = None):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        if extraHeaders:
            for key, value in extraHeaders.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(payload)

    # POST handlers
    def _handleWebRTCAnswer(self, data):
        result = self.session.webRTC.runAsync(self.session.webRTC.setAnswer(data))
        self._sendBytes(result.encode())

    def _handleWebRTCCandidate(self, data):
        result = self.session.webRTC.runAsync(self.session.webRTC.addCandidate(data), wait=False, name="addCandidate")
        self._sendBytes(b"OK")

    def _handleDownloadComplete(self, data):
        """Handle client notification that file download is complete.

        Handles two cases sharing this endpoint:
        - WebRTC P2P: payload contains peerId, unblocks sendFile() completion wait
        - HTTP relay:  payload contains downloadId, unblocks _waitForHTTPDownloadComplete()
        """
        clientInfo = {
            'userAgent': self.headers.get('User-Agent', 'Unknown'),
            'domain': self.headers.get('Host', 'Unknown'),
        }

        connectionType = None

        if 'peerId' in data:
            connectionType = 'webrtc'
            self.session.webRTC.runAsync(
                self.session.webRTC.notifyDownloadComplete(data), wait=False, name="notifyDownloadComplete"
            )
            FFLEvent.receiptCreated.trigger(downloadId=data['peerId'], connectionType='webrtc', clientInfo=clientInfo)

        downloadId = data.get('downloadId')
        if downloadId:
            connectionType = 'relay'

        payload, contentType = self._buildDownloadCompleteResponse(data)

        extraHeaders = {'FFL-CompleteType': connectionType} if connectionType else None
        self._sendBytes(payload, contentType, extraHeaders)

        # Acknowledge AFTER sending the response so the file-serving thread (which may call
        # _forceShutdown) cannot race the response delivery and close the connection first.
        if downloadId:
            ackStatus = self.session.httpDownloadCompletionStore.acknowledge(downloadId)
            if ackStatus == 'accepted':
                logger.debug(f"HTTP download complete ACK received for {downloadId[:8]}")
                FFLEvent.receiptCreated.trigger(downloadId=downloadId, connectionType='http', clientInfo=clientInfo)
            elif ackStatus == 'duplicate':
                logger.debug(f"HTTP download complete ACK duplicate ignored for {downloadId[:8]}")
            else:
                logger.debug(f"HTTP download complete ACK: unknown downloadId {downloadId[:8]}")

    def _buildDownloadCompleteResponse(self, data):
        """Return (payload, contentType) for the /complete response. Override to customise."""
        return b"OK", "text/plain; charset=utf-8"

    def _handleDebugLog(self, data):
        """
        Handle client-side debug log messages for mobile debugging
        
        Usage (follows same pattern as DEBUG and DISABLE_WEBRTC):
        1. Set environment variable: JS_LOG_TO_SERVER_DEBUG="True"
        2. Access URL with parameter: ?debug=server
        3. Server replaces 'const SERVER_DEBUG = false;' with 'const SERVER_DEBUG = true;'
        4. Client logs are forwarded to server stdout via flushPrint()
        
        This is useful for debugging on mobile devices where console access is limited.
        """
        try:
            # Extract log data from the request
            category = data.get('category', 'CLIENT')
            message = data.get('message', '')
            timestamp = data.get('timestamp', '')
            sessionId = data.get('sessionId', 'unknown')
            userAgent = self.headers.get('User-Agent', 'Unknown')

            # Format and print the debug message to server stdout
            logPrefix = f"[{timestamp}] [CLIENT-DEBUG] [{category}] [Session:{sessionId[:8]}]"
            flushPrint(f"{logPrefix} {message}")

            # Log user agent for context (only once per session)
            if sessionId not in self.session._debugUserAgentSessions:
                flushPrint(f"[CLIENT-DEBUG] [INFO] [Session:{sessionId[:8]}] User-Agent: {userAgent}")
                self.session._debugUserAgentSessions.add(sessionId)

            # Send success response
            response = {"status": "success"}
            self._sendBytes(json.dumps(response).encode(), "application/json; charset=utf-8")

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in debug log handler")
        except Exception as e:
            logger.exception(f"Error handling debug log: {e}")
            self.send_error(500, f"Debug log handler error: {str(e)}")

    def do_POST(self):
        if not self._guardRequest():
            return

        # Read and parse request body
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length)) if length else {}

        try:
            # Get the appropriate handler for this path
            handler = self.postPathMap.get(self.path)
            if handler:
                handler(data)
            else:
                self._handle404("Not Found")
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected in POST handler")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    # Override utility methods
    def send_response(self, code, message=None):
        if isinstance(message, str):
            self.send_response_only(code, utf8(message))
        else:
            self.send_response_only(code, message)

        self.send_header('Date', self.date_time_string())

    def log_error(self, format, *args):
        skipCode = {
            400: True,
            404: True,
        }

        # Never show 404/400. FIXME: This is kinda ugly way, but currently no idea to do it better.
        if format == "code %d, message %s" and args and args[0] in skipCode:
            return None

        return super().log_error(format, *args)

    # To let shutdown request can close server correctly
    def finish(self) -> None:
        super().finish()

        if self.server.stop:
            self.server.shutdown()

    def date_time_string(self, timestamp=None):
        if timestamp:
            return super().date_time_string(timestamp)
        else:
            return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def end_headers(self) -> None:
        self.send_header("Server", f"FFL Server/{PUBLIC_VERSION}")
        self.send_header("FFL-Server", PUBLIC_VERSION)
        self.send_header("FFL-DownloadId", self._downloadId)

        if self.session is not None:
            # Get file info first (needed for Last-Modified)
            path, name, size, ctype, reader = self._getFileInfo(quoteName=False)

            # Send Last-Modified header (use current time since reader doesn't provide mtime)
            self.send_header("Last-Modified", self.date_time_string())

            # Only advertise Range support for resources that actually support it (not stdin)
            if reader.supportsRange and size is not None:
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", str(self.etag)) # To let browser can resume downloads

            # Encode filename for HTTP header (use percent-encoding)
            # HTTP headers must be latin-1, so we URL-encode the filename
            # quote() handles both ASCII and non-ASCII filenames correctly
            self.send_header("FFL-FileName", quote(name))
            self.send_header("FFL-FileSize", str(size if size is not None else -1))

            # Indicate mode - P2P if WebRTC is enabled, otherwise HTTP, with E2EE if encrypted
            mode = "P2P" if self.session.config.defaultWebRTC else "HTTP"
            if self.session.config.e2eeEnabled:
                mode += "+E2EE"
                
            self.send_header("FFL-Mode", mode)

        # Add any extra headers if set (for static scripts like service workers)
        if self._extraHeaders:
            for header, value in self._extraHeaders.items():
                self.send_header(header, value)

            # Clear extra headers after use
            self._extraHeaders.clear()

        super().end_headers()

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected during request handling")
        except OSError as e:
            if "read() should have returned a bytes object" in str(e):
                # Ignore this error which does not affect the server
                pass
            else:
                raise


@dataclass
class ServerConfig:
    """Configuration for Server instance"""

    maxDownloads: int = 0 # Maximum number of downloads (0 = unlimited)
    timeout: int = 0 # Server timeout in seconds (0 = no timeout)
    authUser: Optional[str] = None # HTTP Basic auth username
    authPassword: Optional[str] = None # HTTP Basic auth password
    defaultWebRTC: bool = True # Enable WebRTC support by default
    e2eeEnabled: bool = False # Enable end-to-end encryption
    torEnabled: bool = False # Tor privacy mode enabled.
    recipientAuth: Optional[RecipientAuth] = None # Recipient authentication (e.g. pickup code)


class MultiShareServer(ThreadingHTTPServer):
    """HTTP server that hosts multiple ShareSessions under distinct UID path prefixes.

    Each session has its own reader, config, WebRTC, E2EE, and download stores.
    The handler routes each request to the correct session by extracting the UID
    from the first URL path segment.

    autoShutdown=True: server shuts down when the last session is removed (Core.py mode).
    autoShutdown=False: server stays alive even when empty (daemon mode).
    """

    request_queue_size = 128
    allow_reuse_address = True
    allow_reuse_port = True
    daemon_threads = True
    stop = False # The flag to let shutdown request can close server
    error = False # The flag to pass inner error message

    def __init__(self, serverAddress, requestHandlerClass=None, autoShutdown=False):
        if requestHandlerClass is None:
            requestHandlerClass = DownloadHandler

        self._sessions = {}
        self._sessionsLock = threading.Lock()
        self._doneEvent = threading.Event()
        self._startTime = time.time()
        self._autoShutdown = autoShutdown
        
        super().__init__(serverAddress, requestHandlerClass)

    def addSession(self, session, webRTCManagerClass=None):
        """Initialize per-session stores, WebRTC, and E2EE; register in routing table."""
        if webRTCManagerClass is None:
            webRTCManagerClass = WebRTCManager

        session.e2eeManager = None
        session.checksumStore = TransferChecksumStore()
        session.downloadSessionStore = DownloadSessionStore()
        session.authRateLimiter = AuthRateLimiter()
        session.downloadProgressStore = DownloadProgressStore()
        session.logicalDownloadRequestStore = LogicalDownloadRequestStore()
        
        # HTTP relay completion ACK tracking. Both page JS and Service Worker may
        # POST /complete; treat the first ACK as authoritative and ignore duplicates.
        session.httpDownloadCompletionStore = HTTPDownloadCompletionStore()

        if session.config.e2eeEnabled:
            session.e2eeManager = E2EEManager(WebRTCManager.CHUNK_SIZE)
            
            FFLEvent.e2eeInitialized.trigger(
                e2eeEnabled=True, mode='p2p', algorithm='AES-256-GCM', chunkSize=WebRTCManager.CHUNK_SIZE
            )
        
        requestHandlerClass = self.RequestHandlerClass

        # Create exception handler that will be called by WebRTC on errors
        def handleWebRTCException(exception):
            # Use a dummy handler object to call _handleDownloadExceptionActions
            class ExceptionHandler(requestHandlerClass):
                def __init__(self, server, session):
                    self.server = server
                    self.session = session
                    self._downloadId = str(uuid.uuid4())
                    self._downloadStartTime = time.time()

            ExceptionHandler(self, session)._handleDownloadExceptionActions(exception)

        session.webRTC = webRTCManagerClass(
            loggerCallback=flushPrint,
            downloadCallback=lambda: self.doAfterDownload(session.uid),
            exceptionCallback=handleWebRTCException,
            checksumStore=session.checksumStore,
        )

        config = session.config
        
        FFLEvent.sessionStarted.trigger(
            uid=session.uid,
            domain=session.domain,
            maxDownloads=config.maxDownloads,
            timeout=config.timeout,
            authEnabled=config.authPassword is not None,
            e2eeEnabled=config.e2eeEnabled,
            torEnabled=config.torEnabled,
            webrtcEnabled=config.defaultWebRTC,
        )

        with self._sessionsLock:
            self._sessions[session.uid] = session

        if config.timeout > 0:
            self._startTimeoutChecker(session.uid, config.timeout)

    def removeSession(self, uid):
        """Remove a session, shut down its WebRTC, and auto-stop server if empty."""
        with self._sessionsLock:
            session = self._sessions.pop(uid, None)
            isEmpty = len(self._sessions) == 0

        if session:
            session.stop()
            
            FFLEvent.sessionRemoved.trigger(
                uid=uid,
                downloadCount=session.downloadCount,
                status=session.status,
            )

        if isEmpty and self._autoShutdown:
            self._doneEvent.set()

    def getSession(self, uid):
        with self._sessionsLock:
            return self._sessions.get(uid)

    def getDefaultSession(self):
        with self._sessionsLock:
            sessions = list(self._sessions.values())
            
        if len(sessions) == 1:
            return sessions[0]
            
        return None

    def getSessionCount(self):
        with self._sessionsLock:
            return len(self._sessions)

    def _startTimeoutChecker(self, uid, timeout):

        def check():
            startTime = time.time()
            while True:
                if self.getSession(uid) is None:
                    return
                    
                if (time.time() - startTime) >= timeout:
                    session = self.getSession(uid)
                    downloadCount = session.downloadCount if session else 0
                    
                    flushPrint(_('Timeout ({timeout} seconds) reached. Shutting down server.').format(
                        timeout=timeout))
                        
                    FFLEvent.sessionTimeout.trigger(uid=uid, timeout=timeout, downloadCount=downloadCount)
                    
                    self.removeSession(uid)
                    return
                    
                time.sleep(0.5)

        threading.Thread(target=check, daemon=True, name=f'timeout-{uid}').start()

    def doAfterDownload(self, uid):
        session = self.getSession(uid)
        if session is None:
            return
            
        session.downloadCount += 1
        if session.config.maxDownloads > 0 and session.downloadCount >= session.config.maxDownloads:
            session.status = ShareStatus.COMPLETED
            
            flushPrint(_('Maximum downloads ({maxDownloads}) reached. Shutting down server.').format(
                maxDownloads=session.config.maxDownloads))
                
            FFLEvent.maxDownloadsReached.trigger(
                uid=uid,
                maxDownloads=session.config.maxDownloads,
                downloadCount=session.downloadCount,
            )
        
            self.removeSession(uid)

    def handle_error(self, request, client_address):
        logger.exception(sys.exception())
        if self.stop:
            if not self.error:
                return

    def start(self):
        self.serve_forever()
        if self.error:
            raise ChildProcessError()

    def shutdown(self):
        self.stop = True

        with self._sessionsLock:
            uids = list(self._sessions.keys())
            sessions = list(self._sessions.values())

        for uid in uids:
            self.removeSession(uid)

        super().shutdown()

        FFLEvent.serverShutdown.trigger(
            reason='normal',
            downloadCount=sum(s.downloadCount for s in sessions),
            uptime=time.time() - self._startTime,
        )


Server = MultiShareServer # backward compatibility alias


def createServer(reader, port, uid, domain, handlerClass=None, webRTCManagerClass=None, config: ServerConfig = None):
    """Factory that creates a single-session MultiShareServer (Core.py mode).

    Wraps the reader + config in a ShareSession and builds a MultiShareServer.
    The server stops when the session's maxDownloads is reached or its timeout
    expires; Core.py waits on that event and calls shutdown().
    """
    if config is None:
        config = ServerConfig()
        
    if handlerClass is None:
        handlerClass = DownloadHandler

    server = MultiShareServer(('127.0.0.1', port), handlerClass, autoShutdown=True)
    session = ShareSession(
        uid=uid,
        filePaths=[reader.file] if reader.file else [],
        createdAt=datetime.datetime.now().isoformat(),
        domain=domain,
        reader=reader,
        config=config,
    )
    server.addSession(session, webRTCManagerClass=webRTCManagerClass)

    FFLEvent.serverStarting.trigger(
        uid=session.uid,
        port=server.server_address[1],
        domain=session.domain,
        maxDownloads=config.maxDownloads,
        timeout=config.timeout,
        authEnabled=config.authPassword is not None,
        e2eeEnabled=config.e2eeEnabled,
        torEnabled=config.torEnabled,
        webrtcEnabled=config.defaultWebRTC,
    )

    return server
