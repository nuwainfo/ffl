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

# ================================================================
# Architecture note: why HTTP/1.1, not HTTP/2 or HTTP/3
# ================================================================
#
# A natural question is why this backend does not use a native HTTP/2 server or
# a modern ASGI server such as Hypercorn/Uvicorn.
#
# The local server stays on Python's stdlib HTTP/1.1 stack because the backend
# workload is dominated by large streaming responses, where a simple
# one-request/one-TCP-stream HTTP/1.1 path gives more predictable throughput than
# adding HTTP/2 multiplexing inside the tunnel.
#
# The deployment topology is:
#
#     browser -> nginx tunnel edge -> tunnel -> local Python server
#
# nginx is the browser-facing edge. It speaks HTTP/2 or HTTP/3 to browsers, where
# those protocols provide the most value: many small JS/CSS/API requests, browser
# per-origin connection limits, and client-side latency. After nginx has accepted
# those browser-facing streams, the local Python server receives private backend
# requests through the tunnel.
#
# The hot path of this product is large-file streaming with resumable Range
# requests. For this workload, HTTP/1.1 is already a strong backend protocol:
# one request maps to one long-lived response over one TCP stream, backpressure is
# simple, cancellation is direct, and the data path is easy to reason about.
# Throughput is usually limited by bandwidth, tunnel forwarding, congestion
# control, disk/file I/O, and client network conditions, not by HTTP/1.1 request
# parsing.
#
# HTTP/2 on the backend would mainly reduce connection count and help workloads
# with many small concurrent requests. It does not make a single large transfer
# inherently faster. When multiple large responses share one HTTP/2 connection,
# they also share the same underlying TCP connection; packet loss or congestion
# on that TCP connection can affect all multiplexed streams. For large file
# transfer, separate HTTP/1.1 streams can be more predictable than forcing
# multiple large responses through one multiplexed TCP connection.
#
# End-to-end HTTP/3 would be a different design. QUIC can avoid some TCP-level
# head-of-line blocking by giving streams transport-level independence, but it
# also requires UDP/QUIC support through the tunnel path. Many restricted
# networks still block or degrade UDP, so HTTP/3 often falls back to HTTP/2 or
# HTTP/1.1 at the edge. Terminating HTTP/3 at nginx gives the browser-facing
# benefit without pushing QUIC into the local file-serving path.
#
# The secondary benefit is portability and maintainability. The stdlib HTTP/1.1
# server keeps the local runtime pure Python, dependency-light, small, easy to
# audit, and compatible with constrained packaging targets such as APE /
# Cosmopolitan libc. Fewer protocol dependencies also reduce distribution size
# and long-term maintenance risk.

# Considering large-file transfer behavior, tunnel architecture, portability,
# and maintenance cost together, keeping the local backend on HTTP/1.1 while
# terminating HTTP/2/HTTP/3 at nginx is currently the best overall tradeoff.

import json
import os
import re
import socket
import sys
import uuid
import datetime
import threading
import time
import requests

from collections import OrderedDict
from typing import Optional
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse


from bases.Kernel import getLogger, PUBLIC_VERSION, FFLEvent, Throttler
from bases.Utils import flushPrint, utf8, formatSize
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.WebRTC import WebRTCManager
from bases.Progress import Progress
from bases.Auth import AuthMixin, HTTPAuth
from bases.E2EE import CryptoHelper, E2EEManager
from bases.Checksum import DEFAULT_CHECKSUM_ALGORITHM, TransferChecksumStore
from bases.Readers import FolderChangedException
from bases.I18n import _
from bases.HTTP import HTTPMethod, RangeResolver
from bases.SSE import EventHub, SSEMixin
from bases.Session import (
    ShareStatus, ShareSession, AuthRateLimiter, DownloadSessionStore, DownloadProgressStore,
    HTTPDownloadCompletionStore, LogicalDownloadRequestStore, SupersededDownloadError, ServerConfig
)

from bases.views import ViewsMixin
from bases.views.Auth import RecipientAuthView
from bases.views.Checksum import ChecksumView
from bases.views.Debug import DebugView
from bases.views.DownloadComplete import DownloadCompleteView
from bases.views.E2EE import E2EEView
from bases.views.Status import StatusView
from bases.views.WebRTC import WebRTCView

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


class SessionSSEMixin(SSEMixin):

    def _buildShareSnapshot(self):
        """Current server-side truth about this share, sent as the SSE share.snapshot event."""
        _path, name, size, _ctype, _reader = self._getFileInfo(quoteName=False)
        config = self.session.config
        remaining = (config.maxDownloads - self.session.downloadCount) if config.maxDownloads > 0 else None

        return {
            'fileName': name,
            'fileSize': size if size is not None else -1,
            'e2eeEnabled': config.e2eeEnabled,
            'maxDownloads': config.maxDownloads,
            'remainingDownloads': remaining,
        }

    @property
    def sseEventHub(self):
        return self.session.eventHub

    @property
    def initialSSEEvents(self):
        eventHub = self.sseEventHub
        return [
            eventHub.record('session.hello', {'uid': self.session.uid}),
            eventHub.record('share.snapshot', self._buildShareSnapshot()),
        ]



class DownloadHandler(AuthMixin, ViewsMixin, SessionSSEMixin, SimpleHTTPRequestHandler):

    # Feature modules that mount their own routes and/or guard existing ones.
    # See bases.views.BaseView for the contract.
    VIEWS = (
        RecipientAuthView, 
        ChecksumView, 
        E2EEView, 
        WebRTCView, 
        StatusView, 
        DebugView,
        DownloadCompleteView,
    )

    # Transfer chunk size - shared across WebRTC and HTTP downloads
    CHUNK_SIZE = TRANSFER_CHUNK_SIZE

    # POST bodies handled here are small JSON payloads (auth, WebRTC signaling,
    # e2ee init, debug logs) - 5 MiB is generous headroom, not a real payload size.
    MAX_POST_BODY_SIZE = 5 * 1024 * 1024

    byteRange = None

    # To let browser can resume downloads
    protocol_version = 'HTTP/1.1'
    etag = uuid.uuid4()

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
        self.mapHEADRoute('/download', self._handleDownloadHead)
        self.mapHEADRoute('/static/index.html', self._handleDefaultHead)
        self.mapHEADRoute('/', self._handleHeadRedirect)
        self.mapHEADRoute('', self._handleHeadRedirect)

        self.mapGETRoute('/download', self._handleDownload)
        self.mapGETRoute('/static/index.html', self._handleStaticIndex)
        self.mapGETRoute('/static/js/ProgressServiceWorker.js', self._handleProgressServiceWorker)
        self.mapGETRoute('/events', self._handleEvents)
        self.mapGETRoute('/', self._handleRedirect)
        self.mapGETRoute('', self._handleRedirect)

        self._mountViews()

        staticPassthroughPathPattern = re.compile(r'^/static(?:/(?!index\.html$).+)?$')
        self.mapGETRoute(staticPassthroughPathPattern, self._handleStatic)

        self._sessionLessPathMap = OrderedDict()
        self._sessionLessPathMap[staticPassthroughPathPattern] = True

        self.session = None
        self._requestQuery = ''
        self._requestArgs = {}
        self._pathForbidden = False

        # NOTE: __init__ runs once per TCP connection (socketserver creates one handler
        # instance per accepted connection), but under HTTP/1.1 keep-alive
        # handle_one_request() loops to serve multiple HTTP requests on that same
        # instance. Anything that must be scoped to a single HTTP request (download id,
        # Range, extra headers, ...) is (re)initialized in _resetPerHttpRequestState(),
        # which parse_request() calls for every request, not just here.
        self._resetPerHttpRequestState()

        settingsGetter = SettingsGetter.getInstance()

        # BaseRequestHandler.__init__() calls self.handle() synchronously, which
        # in turn loops over handle_one_request() for the entire keep-alive
        # lifetime of this connection — so catching here covers the whole
        # connection, not just a single request, and correctly stops handling
        # it the moment it breaks rather than risking handle()'s keep-alive
        # loop retrying reads on an already-broken socket.
        try:
            super().__init__(request, client_address, server, directory=settingsGetter.baseDir)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected during request handling")
        except OSError as e:
            if "read() should have returned a bytes object" in str(e):
                # Ignore this error which does not affect the server
                pass
            else:
                raise

    @property
    def auth(self) -> HTTPAuth:
        if self.session is None:
            return HTTPAuth()

        return HTTPAuth(user=self.session.config.authUser, password=self.session.config.authPassword)

    @property
    def _templateDirectory(self) -> str:
        return os.path.join(SettingsGetter.getInstance().baseDir, 'static')

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
        originalPathsByMethod = {method: set(self.paths[method].keys()) for method in HTTPMethod}
        routeMaps = {method: OrderedDict(self.paths[method]) for method in HTTPMethod}

        # Event kwarg names (getPathMap/postPathMap/headPathMap) are the
        # subscriber contract addons rely on -- kept as-is even though the
        # handler itself no longer owns three separate map attributes.
        FFLEvent.serverEndpointsRegister.trigger(
            handler=self,
            server=server,
            session=session,
            getPathMap=routeMaps[HTTPMethod.GET],
            postPathMap=routeMaps[HTTPMethod.POST],
            headPathMap=routeMaps[HTTPMethod.HEAD]
        )

        for method, routeMap in routeMaps.items():
            originalPaths = originalPathsByMethod[method]
            targetMap = self.paths[method]
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
            # No valid UID prefix — fall back to the single active session (FFL.py mode)
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

    def _resetPerHttpRequestState(self):
        """Reset state that must be scoped to a single HTTP request.

        socketserver creates one handler instance per accepted TCP connection
        (see BaseRequestHandler / StreamRequestHandler), not per HTTP request.
        BaseHTTPRequestHandler.handle() then loops calling handle_one_request()
        for as long as the HTTP/1.1 connection stays keep-alive, so this same
        instance serves every request on that connection. Fields like the
        download id or the parsed Range must therefore be refreshed for every
        request rather than left over from __init__ or a prior request on the
        same connection.
        """
        self.byteRange = None
        self._extraHeaders = {}
        self._downloadId = str(uuid.uuid4())
        self._downloadStartTime = None

    def parse_request(self):
        # Reset before delegating to super(): if super().parse_request() itself fails
        # (malformed request line, unsupported version, ...) it calls self.send_error()
        # internally, and that error response must not carry the previous request's
        # download id / extra headers from this same keep-alive connection.
        self._resetPerHttpRequestState()

        if not super().parse_request():
            return False

        try:
            self._prepareRequestContext()
        except Exception as e:
            logger.exception(f"Failed to prepare request context: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return False

        return True

    def _checkPathForbidden(self, path, session=None):
        # WebRTC paths are forbidden when WebRTC is disabled server-side (--force-relay for licensed users).
        # Derive the set from paths[HTTPMethod.HEAD] to avoid a separate list to maintain.
        if self.paths[HTTPMethod.HEAD].get(path) == self._handleForbiddenHead:
            return session is not None and not session.config.defaultWebRTC

        return False

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

        handler = self._resolveHEADHandler(redirectPath)
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

        headHandler = self._resolveHEADHandler(self.path)
        if not headHandler:
            headHandler = self._resolveGETHandler(self.path)

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

        handler = self._resolveGETHandler(redirectPath)
        if handler:
            handler(args)
        else:
            logger.error(f"No handler found for redirect path: {redirectPath}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Redirect handler not found")

    def _isLogicalCompletionRequest(self):
        """Whether this HTTP request represents (or completes) a whole logical download,
        as opposed to one segment of a larger transfer.

        A request with no Range header, or an open-ended tail Range
        (``Range: bytes=N-``), represents the entire file — including the case
        where it is the HTTP-resume tail that finishes a transfer started over
        WebRTC. Those must drive the session-level download lifecycle:
        registering for the /complete ACK, firing downloadCompleted, and
        counting toward maxDownloads.

        A bounded Range request (``Range: bytes=N-M``) is just one parallel
        chunk segment of a larger transfer (browsers/clients may issue several
        of these concurrently for the same logical download) and must NOT be
        mistaken for a full download on its own — otherwise the first segment
        to finish would prematurely ACK completion and tear down the session
        while sibling segments are still in flight.
        """
        return not self.byteRange or self.byteRange.end is None

    def _handleStartDownloadActions(self, size, isLogicalCompletionRequest):
        flushPrint(_('[{timestamp}] Downloading by user').format(timestamp=self.date_time_string()))

        # Track per-download progress for server-side stall detection
        self.session.downloadProgressStore.register(self._downloadId, size)

        # Register completion state so _waitForHTTPDownloadComplete can block until
        # client ACKs — only for requests that represent a whole logical download.
        # See _isLogicalCompletionRequest for why bounded Range segments are excluded.
        if isLogicalCompletionRequest:
            self.session.httpDownloadCompletionStore.register(self._downloadId)

        # Get client information
        userAgent = self.headers.get('User-Agent', 'Unknown')
        host = self.headers.get('Host', 'Unknown')

        # Trigger downloadStarted event
        FFLEvent.downloadStarted.trigger(
            timestamp=self.date_time_string(),
            shareId=self.session.uid,
            downloadId=self._downloadId,
            connectionType='http',
            clientInfo={
                'userAgent': userAgent,
                'domain': host
            },
            resumeOffset=self.byteRange.start if self.byteRange else 0,
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
            shareId=self.session.uid,
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

    def _getDownloadDebugOptions(self, args):
        """Collect download-specific debug/test injection options."""
        return {
            'stallAfterBytes': self._parsePositiveDebugIntArg(args, 'stall-after'),
            'disconnectAfterBytes': self._parsePositiveDebugIntArg(args, 'disconnect-after'),
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
            shareId=self.session.uid,
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

    def _guardRequest(self) -> bool:
        """Return True if the request may proceed; otherwise send the error response and return False."""
        if self.session is None:
            sessionlessAllowed = self._resolveHandler(self._sessionLessPathMap, self.path)
            if sessionlessAllowed is True:
                return True

            self._handle404()
            return False

        if not self.handleAuthentication():
            return False

        if self._pathForbidden:
            self._handleForbidden()
            return False

        return True

    def _handleDownload(self, args):
        if not self._checkViewAccess(self.path, args):
            return

        debugOptions = self._getDownloadDebugOptions(args)

        # Get file info using existing helper method
        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
        self._appendDownloadRequestLog(args, name, size)

        requestedStart = self.byteRange.start if self.byteRange else 0
        canResumeFromStart = reader.canResumeFrom(requestedStart)
        isLogicalCompletionRequest = self._isLogicalCompletionRequest()

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
            self._handleStartDownloadActions(size, isLogicalCompletionRequest)
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
            if self.byteRange and not (reader.supportsRange or canResumeFromStart):
                # Directory streams don't support Range
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header("Content-Range", f'bytes */{totalSizeHeader}')
                self.end_headers()
                return

            if self.byteRange:
                start, end = self.byteRange.start, self.byteRange.end
            else:
                # For unknown size (stdin, ZIP deflate), use None for end
                start = 0

            if size is not None and size >= 0:
                if self.byteRange:
                    resolved = RangeResolver.resolve(self.byteRange, size)
                    if not resolved.satisfiable:
                        self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                        self.send_header("Content-Range", f'bytes */{totalSizeHeader}')
                        self.end_headers()
                        return

                    end = resolved.end
                else:
                    end = size - 1

            # Determine if we should use chunked encoding
            useChunked = (size is None)
            logicalDl = self._registerLogicalDownloadRequest(args, start, end)

            # AES-GCM nonces are derived from a chunk index (CryptoHelper.buildNonce),
            # so a given index must always correspond to the same canonical,
            # chunkSize-aligned plaintext window -- otherwise two Range requests
            # landing in the same index would encrypt different-length plaintext
            # under an identical (key, nonce) pair (catastrophic GCM nonce reuse).
            # This applies to BOTH ends of the range: aligning only the start down
            # is not sufficient, since two finite ranges that floor-divide to the
            # same chunk index but have different ends (e.g. bytes=1000-2000 vs
            # bytes=1000-500000) would still encrypt different-length plaintext at
            # that index. So when E2EE is enabled, align the actual read down at
            # the start AND up at the end to the full containing chunks. The extra
            # leading/trailing ciphertext bytes still have to be transmitted (a
            # client can't tag-verify a truncated GCM block); the client is
            # responsible for cropping both ends after decrypting (bases/E2EE.py's
            # HTTPStreamDecryptor for the leading edge; the CLI's own requests are
            # always open-ended, so aligning the end is a no-op for it -- only a
            # genuinely finite Range request, e.g. a browser <video>/PDF seek via
            # the Service Worker, ever needs the trailing crop too).
            if self.session.config.e2eeEnabled:
                readStart, _ = CryptoHelper.alignChunkStart(start, self.session.e2eeManager.chunkSize)
                if size is not None:
                    readEnd = min(size - 1, CryptoHelper.alignChunkEnd(end, self.session.e2eeManager.chunkSize))
                else:
                    readEnd = end
            else:
                readStart = start
                readEnd = end

            # Send appropriate response headers
            if 'Range' in self.headers:
                if self.byteRange and (reader.supportsRange or canResumeFromStart):
                    self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    if size is not None:
                        self.send_header("Content-Length", str(readEnd - readStart + 1))
                        self.send_header("Content-Range", f'bytes {readStart}-{readEnd}/{size}')
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

            written += readStart

            # Initialize E2E encryptor if enabled
            encryptor = None
            if self.session.config.e2eeEnabled:
                # readStart is always chunkSize-aligned, so every encrypted chunk is
                # always the canonical one for its index -- its tag is always valid
                # for future retrieval, no more "skip saving for unaligned requests".
                startChunkIndex = readStart // self.session.e2eeManager.chunkSize
                encryptor = self.session.e2eeManager.createEncryptor(
                    fileName=name, fileSize=size, startChunkIndex=startChunkIndex, saveTags=True
                )

            checksumSession = self.session.checksumStore.begin(transport='http', e2ee=bool(encryptor))
            shouldCommitChecksum = (not self.byteRange) and start == 0

            # Send file/directory data in chunks
            chunkSize = self.session.e2eeManager.chunkSize if self.session.config.e2eeEnabled else self.CHUNK_SIZE
            progressThrottler = Throttler(interval=1.0)

            for data in reader.iterChunks(chunkSize, start=readStart):
                self._ensureLogicalDownloadStillActive(logicalDl)

                # Ensure we don't send beyond the (possibly chunk-aligned) range (if known)
                if readEnd is not None and written + len(data) > readEnd + 1:
                    data = data[:readEnd + 1 - written]

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
                        shareId=self.session.uid,
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
                if readEnd is not None and written > readEnd:
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

            # Only a request that represents the whole logical download drives the
            # session-level lifecycle. A bounded Range request is one parallel chunk
            # segment of a larger transfer - waiting for /complete or firing
            # downloadCompleted/doAfterDownload here would prematurely end the
            # session (or hang up to 5s) while sibling segments are still in flight.
            if isLogicalCompletionRequest:
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

        context = {
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

            # Branding / content
            'copyright': settingsGetter.getCopyright(),
            'downloadNoteHtml': settingsGetter.getDownloadNote(),
            'receiptConfirmMessage': None,

            # JS flags
            'streamSaverBlob': 1 if os.getenv('STREAMSAVER_BLOB', None) == 'True' else 0,
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
    
        # Get context from views.
        context.update(self._collectViewTemplateContext(args))

        return context

    def _handleStaticIndex(self, args):
        try:
            content = self._renderTemplate('index.html', **self._buildTemplateContext(args))

            if self.byteRange:
                resolved = RangeResolver.resolve(self.byteRange, len(content))
                if not resolved.satisfiable:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header('Content-Range', f'bytes */{len(content)}')
                    self.end_headers()
                    return

                start, end = resolved.start, resolved.end
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Length", str(resolved.contentLength))
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

    def _handleProgressServiceWorker(self, args):
        """Handle ProgressServiceWorker.js - proxy from remote or serve locally"""
        # Service worker requires special headers
        requestHeaders = {'Service-Worker': 'script', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/'}
        self._handleStaticScript("/static/js/ProgressServiceWorker.js", requestHeaders)

    def do_GET(self):
        if not self._guardRequest():
            return

        self.byteRange = RangeResolver.parse(self.headers.get('Range'))

        # Get the appropriate handler for this path
        handler = self._resolveGETHandler(self.path)
        logger.debug(f"[ROUTE] GET {self.path} -> handler={'found' if handler else 'NOT FOUND (using default)'}")
        if handler:
            try:
                handler(self._requestArgs)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                logger.debug("Client disconnected in GET handler")
            except Exception as e:
                # Unlike the no-handler-found branch below, a registered GET
                # handler may be a streaming one (e.g. _handleDownload,
                # _handleZipFile) that already sent headers/partial body before
                # failing -- calling send_error() here could write a second,
                # invalid status line into what the client expects to be pure
                # body bytes, corrupting the HTTP framing. Just log and let the
                # connection close, so the client observes a dropped/truncated
                # response (detectable) instead of a corrupted one.
                logger.exception(f"Unhandled error in GET handler for {self.path}: {e}")
        else:
            # Default handling for other paths
            try:
                super().do_GET()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                logger.debug("Client disconnected in GET handler")
            except Exception as e:
                logger.exception(e)
                self.send_error(500, str(e))

    # POST handlers
    def _buildDownloadCompleteResponse(self, data):
        """Return (payload, contentType) for the /complete response. Override to customise."""
        return b"OK", "text/plain; charset=utf-8"

    def do_POST(self):
        if not self._guardRequest():
            return

        # Read and parse request body. Malformed Content-Length or non-JSON bodies
        # must not raise past this point uncaught — that would skip send_error
        # entirely (the outer catch around super().__init__() only catches
        # connection/OSError-family exceptions), leaving the client with no
        # response at all.
        try:
            length = int(self.headers.get("Content-Length", "0"))

            # A negative length makes self.rfile.read() block reading until EOF instead
            # of the declared byte count, which on a keep-alive connection means it
            # blocks until the client disconnects. Neither case below drains the body,
            # so the connection must be closed rather than kept alive - otherwise
            # whatever bytes the client sent (or sends) get misparsed as the next
            # request line.
            if length < 0:
                self.close_connection = True
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
                return

            # An oversized length is rejected outright rather than reading it in full -
            # POST bodies here are always small JSON payloads (auth, WebRTC signaling,
            # e2ee init, debug logs).
            if length > self.MAX_POST_BODY_SIZE:
                self.close_connection = True
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "POST body too large")
                return

            data = json.loads(self.rfile.read(length)) if length else {}
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected while reading POST body")
            return
        except ValueError as e:
            # json.JSONDecodeError is a ValueError subclass, so malformed JSON lands here too.
            logger.warning(f"Malformed POST request body: {e}")
            self.send_error(HTTPStatus.BAD_REQUEST, "Malformed request body")
            return

        try:
            # Get the appropriate handler for this path
            handler = self._resolvePOSTHandler(self.path)
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


class MultiShareServer(ThreadingHTTPServer):
    """HTTP server that hosts multiple ShareSessions under distinct UID path prefixes.

    Each session has its own reader, config, WebRTC, E2EE, and download stores.
    The handler routes each request to the correct session by extracting the UID
    from the first URL path segment.

    autoShutdown=True: server shuts down when the last session is removed (FFL.py mode).
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

        # Session-wide SSE event bus (GET /events). See EventHub docstring.
        session.eventHub = EventHub()

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
            shareId=session.uid,
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
    """Factory that creates a single-session MultiShareServer (FFL.py mode).

    Wraps the reader + config in a ShareSession and builds a MultiShareServer.
    The server stops when the session's maxDownloads is reached or its timeout
    expires; FFL.py waits on that event and calls shutdown().
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
