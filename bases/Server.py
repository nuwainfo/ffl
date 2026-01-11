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

import io
import json
import os
import re
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

from bases.Kernel import getLogger, PUBLIC_VERSION
from bases.Utils import flushPrint, utf8, formatSize
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.WebRTC import WebRTCManager, WebRTCDisabledError
from bases.Progress import Progress
from bases.E2EE import E2EEManager
from bases.Reader import FolderChangedException
from bases.I18n import _

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


class AuthMixin:
    """
    A mixin to handle Basic Authentication for BaseHTTPRequestHandler.
    Provides authentication functionality for protecting HTTP resources.
    """
    REALM = 'FastFileLink Protected Resource'

    def handleAuthentication(self):
        """
        Checks the 'Authorization' header and validates user credentials.
        
        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        # Skip auth if not configured (password is required to enable auth)
        if not self.server.config.authPassword:
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

            # Verify credentials against server config
            if username == self.server.config.authUser and password == self.server.config.authPassword:
                logger.info(f"Authentication successful for user: '{username}'")
                return True
            else:
                logger.warning(f"Authentication failed: Invalid credentials for user '{username}'")
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
        html = b'<h1>401 Unauthorized</h1><p>Authentication required to access this resource.</p>'

        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', f'Basic realm="{self.REALM}"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()

        self.wfile.write(html)


class DownloadHandler(AuthMixin, SimpleHTTPRequestHandler):
    # Transfer chunk size - shared across WebRTC and HTTP downloads
    CHUNK_SIZE = TRANSFER_CHUNK_SIZE

    range = None

    # To let browser can resume downloads
    protocol_version = 'HTTP/1.1'
    etag = uuid.uuid4()

    def __init__(self, *args, **kwargs):
        # Define path handlers for HEAD, GET, and POST methods
        # HEAD is using to let server side get file information like filename, file size, etc.
        self.headPathMap = {
            '/download': self._handleDownloadHead,
            '/static/index.html': self._handleDefaultHead,
            '/': self._handleHeadRedirect,
            '': self._handleHeadRedirect,

            # WebRTC must startswith uid.
            '/offer': self._handleForbiddenHead,
            '/answer': self._handleForbiddenHead,
            '/candidate': self._handleForbiddenHead,
            '/complete': self._handleForbiddenHead
        }

        self.getPathMap = {
            '/download': self._handleDownload,
            '/static/index.html': self._handleStaticIndex,
            '/static/js/ProgressServiceWorker.js': self._handleProgressServiceWorker,
            '/static/js/E2EE.js': self._handleE2EEScript,
            '/offer': self._handleWebRTCOffer,
            '/candidate': self._handleWebRTCCandidatePolling,
            '/e2ee/manifest': self._handleE2EEManifest,
            '/e2ee/tags': self._handleE2EETags,
            '/status': self._handleStatus,
            '/': self._handleRedirect,
            '': self._handleRedirect
        }

        self.postPathMap = {
            '/answer': self._handleWebRTCAnswer,
            '/candidate': self._handleWebRTCCandidate,
            '/complete': self._handleWebRTCComplete,
            '/e2ee/init': self._handleE2EEInit,
        }

        # One request one handler, so _extraHeaders can be safely used in self.end_headers.
        self._extraHeaders = {}

        if os.getenv('JS_LOG_TO_SERVER_DEBUG') == 'True':
            self.postPathMap.update({
                '/debug/log': self._handleDebugLog,
            })

        settingsGetter = SettingsGetter.getInstance()

        super().__init__(directory=settingsGetter.baseDir, *args, **kwargs)

    def _normalizeRequestPath(self):
        pasedURL = urlparse(self.path)
        query = pasedURL.query
        path = pasedURL.path

        forbidden = self._checkPathForbidden(path)

        # Handle UID prefix if present
        if path.startswith(f'/{self.server.uid}'):
            path = path[len(self.server.uid) + 1:]

        return path, query, forbidden

    def _checkPathForbidden(self, path):
        return path in self.headPathMap and path != '/static/index.html'

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
        reader = self.server.reader
        path = os.path.join(self.server.directory, self.server.file) if self.server.directory else self.server.file

        if quoteName:
            name = quote(reader.contentName)
        else:
            name = reader.contentName

        size = reader.size # None means unknown length (e.g., stdin)
        ctype = reader.contentType

        return path, name, size, ctype, reader

    # HEAD handlers
    def _handleForbiddenHead(self):
        self.send_response(HTTPStatus.FORBIDDEN)
        self.end_headers()

    def _handleDefaultHead(self):
        super().do_HEAD()

    def _determineRedirectPath(self):
        """Determine redirect path based on User-Agent"""
        if 'User-Agent' not in self.headers:
            return '/download'
        elif 'Mozilla' not in self.headers['User-Agent']:
            return '/download'
        elif 'WindowsPowerShell' in self.headers['User-Agent']:
            return '/download'
        else:
            return '/static/index.html'

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

        self.send_header("Content-type", ctype)
        self.send_header("Content-Disposition", f"attachment; filename={name}")
        self.end_headers()

    # Add HTTP HEAD to let server can get Content-Disposition without triggered download
    def do_HEAD(self):
        # Check authentication first
        if not self.handleAuthentication():
            return

        self.path, query, forbidden = self._normalizeRequestPath()
        args = parse_qs(query)

        if forbidden:
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
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

    def _handlePostDownloadActions(self, size):
        flushPrint(_(
            'File sending is complete. '
            'Please wait for the recipient to finish downloading before you close the application.\n'
        ))
        self.server.doAfterDownload()

    def _handleDownloadExceptionActions(self, exception):
        if isinstance(exception, FolderChangedException):
            # Folder content changed during transfer
            errorMsg = str(exception)
            filePath = getattr(exception, 'filePath', None)

            # Notify sharer
            flushPrint(_('\n⚠️  TRANSFER ABORTED: {errorMsg}').format(errorMsg=errorMsg))
            flushPrint(_('The shared folder contents changed during the transfer.'))
            flushPrint(_('Please ensure the folder contents remain stable and try sharing again.\n'))

            # Set error state for status polling with error type for i18n
            self.server.lastError = {
                'type': 'folder_changed',
                'detail': errorMsg,
                'filePath': filePath,
                'exceptionClass': exception.__class__.__name__
            }
        elif isinstance(exception, (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError)):
            flushPrint(_('\nConnection disconnected, wait retrying.\n'))
        elif isinstance(exception, OSError):
            flushPrint(_('\nUser closes the connection, please try again.\n'))
        else:
            logger.debug(f'_handleDownloadExceptionActions: {exception}')

    def _handleE2EEManifest(self, args):
        """Handle /e2ee/manifest endpoint - returns E2E encryption metadata"""
        logger.debug(f"[E2EE] Manifest request - e2eeEnabled={self.server.config.e2eeEnabled}")
        if not self.server.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            self._handle404(f"[E2EE] E2EE not enabled, returning silent 404 for /e2ee/manifest")
            return

        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
        filename = name

        manifest = {
            'e2eeEnabled': True,
            'filename': filename,
            'filesize': size,
            'chunkSize': self.server.e2eeManager.chunkSize
        }

        response = json.dumps(manifest).encode('utf-8')

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

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
        """Handle /e2ee/tags endpoint - returns tags for chunk range"""
        if not self.server.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            self._handle404(f"[E2EE] E2EE not enabled, returning silent 404 for /e2ee/tags")
            return

        try:
            # Parse query parameters from args (already parsed by do_GET)
            startChunk = int(args.get('start', ['0'])[0])
            count = int(args.get('count', ['0'])[0])

            logger.debug(f"[E2EE] Tags request: start={startChunk}, count={count}")

            if count <= 0:
                logger.warning(f"[E2EE] Invalid count parameter: {count}")
                self.send_error(HTTPStatus.BAD_REQUEST, f"Invalid count parameter: {count}")
                return

            # Load all tags from E2EEManager
            allTags = self.server.e2eeManager.getTags("global")
            logger.debug(f"[E2EE] Total tags available: {len(allTags)}")

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

        except Exception as e:
            logger.error(f"[E2EE] Tags endpoint error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def _handleE2EEInit(self, data):
        """Handle /e2ee/init endpoint - RSA key exchange for E2E encryption"""
        if not self.server.config.e2eeEnabled:
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
            responseData = self.server.e2eeManager.handleInit(publicKeyPem, filename, size)
            response = json.dumps(responseData).encode('utf-8')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        except Exception as e:
            logger.error(f"E2EE init error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    def _handleDownload(self, args):
        # Get file info using existing helper method
        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)

        # Check if reader has already been consumed (for single-use sources like stdin)
        if reader.consumed:
            # Single-use reader already consumed - return 410 Gone
            self.send_response(HTTPStatus.GONE)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            message = "This resource has already been downloaded and is no longer available (single-use only)."
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message.encode('utf-8'))
            return

        # Start to download
        try:
            self._handleStartDownloadActions(size)
        except PermissionError as e:
            # File size or other validation error from enhanced handler
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return

        settingsGetter = SettingsGetter.getInstance()

        written = 0
        progress = Progress(
            size,
            sizeFormatter=formatSize,
            loggerCallback=flushPrint,
            logInterval=LOG_OUTPUT_DURATION,
            useBar=settingsGetter.isCLIMode(),
        )

        start = None
        end = None

        try:
            # Handle range requests (only for files that support it)
            if self.range and not reader.supportsRange:
                # Directory streams don't support Range
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header("Content-Range", f'bytes */{size}')
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
            useChunked = (size is None) and ('Range' not in self.headers)

            # Send appropriate response headers
            if 'Range' in self.headers:
                if self.range and reader.supportsRange:
                    self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    self.send_header("Content-Length", str(end - start + 1))
                    self.send_header("Content-Range", f'bytes {start}-{end}/{size}')
                else:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f'bytes */{size}')
                    self.end_headers()
                    return
            else:
                self.send_response(HTTPStatus.OK)
                if size is not None:
                    self.send_header("Content-Length", str(size))
                else:
                    # For unknown size (stdin, ZIP deflate), use chunked transfer encoding
                    self.send_header("Transfer-Encoding", "chunked")

            self.send_header("Content-type", ctype)
            self.send_header("Content-Disposition", f"attachment; filename={quote(name)}")
            self.end_headers()

            written += start

            # Initialize E2E encryptor if enabled
            encryptor = None
            if self.server.config.e2eeEnabled:
                # Calculate starting chunk index for Range support
                startChunkIndex = start // self.server.e2eeManager.chunkSize
                # Only save tags if this is an aligned Range request (or full download)
                saveTags = (start % self.server.e2eeManager.chunkSize == 0)

                encryptor = self.server.e2eeManager.createEncryptor(
                    filename=name, filesize=size, startChunkIndex=startChunkIndex, saveTags=saveTags
                )

            # Send file/directory data in chunks
            chunkSize = self.server.e2eeManager.chunkSize if self.server.config.e2eeEnabled else self.CHUNK_SIZE

            for data in reader.iterChunks(chunkSize, start=start):
                # Ensure we don't send beyond the requested range (if known)
                if end is not None and written + len(data) > end + 1:
                    data = data[:end + 1 - written]

                # Encrypt if E2EE enabled
                if encryptor:
                    data = encryptor.encryptChunk(data)

                # Write using chunked encoding or direct write
                if useChunked:
                    self._writeChunk(data)
                else:
                    self.wfile.write(data)

                written += len(data)

                # Update progress periodically
                progress.update(written)

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

            # Handle post-download actions
            self._handlePostDownloadActions(size)

        except FolderChangedException as e:
            self._handleDownloadExceptionActions(e)
        except (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError) as ce:
            self._handleDownloadExceptionActions(ce)
        except OSError as e:
            self._handleDownloadExceptionActions(e)

    def _handleStaticIndex(self, args):
        try:
            with open(self.translate_path('/static/index.html'), 'rb') as f:
                content = f.read()

                # Replace STATIC_SERVER
                settingsGetter = SettingsGetter.getInstance()
                staticServer = settingsGetter.getStaticServer()
                content = content.replace(b'{{ STATIC_SERVER }}', staticServer.encode())

                # Replace UID placeholder
                content = content.replace(b'uid=****', self.server.uid.encode())

                # Replace file_name, file_size placeholder
                path, name, size, ctype, reader = self._getFileInfo(quoteName=False)
                content = content.replace(b'{{ fileName }}', name.encode())
                content = content.replace(b'{{ fileSize }}', str(size if size is not None else -1).encode())

                # Replace COPYRIGHT placeholder
                settingsGetter = SettingsGetter.getInstance()
                copyright = settingsGetter.getCopyright()
                content = content.replace(b'{{ COPYRIGHT }}', copyright.encode())

                # Replace FOOTER_MESSAGE_HTML placeholder
                footerMessageHTML = settingsGetter.getFooterMessageHTML()
                content = content.replace(b'{{ FOOTER_MESSAGE_HTML }}', footerMessageHTML.encode())

                # Check for debug mode from environment variable or URL parameter
                # WebRTC priority system (highest to lowest priority), and other settings the same priority design:
                # 1. URL parameter (?webrtc=yes/no/1/0/true/false/on/off)
                # 2. Server defaultWebRTC setting (default WebRTC state from --force-relay/Tor mode)
                # 3. DISABLE_WEBRTC environment variable
                debugEnabled = os.getenv('JS_DEBUG', None) == 'True'
                serverDebugEnabled = os.getenv('JS_LOG_TO_SERVER_DEBUG', None) == 'True'
                webrtcDisabled = os.getenv('DISABLE_WEBRTC', None) == 'True'
                streamSaverBlob = os.getenv('STREAMSAVER_BLOB', None) == 'True'

                webrtcDisabledDetermined = False

                # Parse URL parameters for runtime control
                # These is priority 1, so overwrite environment variables setting.
                if args:
                    # Check debug parameter: ?debug=yes/1/true/on/server
                    debugParam = args.get('debug', [None])[0]
                    if debugParam:
                        debugValue = debugParam.lower()
                        if debugValue == 'server':
                            # Enable server-side logging only if both URL param and env var are set
                            serverDebugEnabled = True
                        else:
                            if self.parseURLBooleanParam(debugParam):
                                debugEnabled = True

                    # Check webrtc parameter: ?webrtc=no/0/false/off/yes/1/true/on
                    webrtcParam = args.get('webrtc', [None])[0]
                    if webrtcParam:
                        webrtcValue = self.parseURLBooleanParam(webrtcParam)
                        if webrtcValue is False:
                            webrtcDisabled = True
                        elif webrtcValue is True:
                            webrtcDisabled = False
                        else:
                            pass # If webrtcResult is None (unrecognized value), keep current state

                        webrtcDisabledDetermined = True

                # Apply priority system for WebRTC
                if not webrtcDisabledDetermined: # No URL parameter override
                    # Priority 2: Server defaultWebRTC setting
                    if not self.server.config.defaultWebRTC:
                        webrtcDisabled = True

                # Use default from environment variable (Priority 3)
                webrtcDisabledDetermined = True

                # Apply JavaScript variable replacements
                if debugEnabled:
                    content = content.replace(b'const DEBUG = false;', b'const DEBUG = true;')
                if webrtcDisabled:
                    content = content.replace(b'const DISABLE_WEBRTC = false;', b'const DISABLE_WEBRTC = true;')
                if serverDebugEnabled:
                    content = content.replace(b'const SERVER_DEBUG = false;', b'const SERVER_DEBUG = true;')
                if streamSaverBlob:
                    content = content.replace(b'{{ STREAMSAVER_BLOB }}', b'1')
                else:
                    content = content.replace(b'{{ STREAMSAVER_BLOB }}', b'0')

                if self.server.config.torEnabled:
                    # Use slow polling to increase stability
                    content = content.replace(
                        b'const STATUS_POLLING_SECONDS = 2;', b'const STATUS_POLLING_SECONDS = 5;'
                    )

            f = io.BytesIO(content)
            try:
                if self.range:
                    start, end = self.range
                    fullContent = f.read() # This is ok because static index.html is small.
                    end = end if end else len(fullContent) - 1

                    self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    self.send_header("Content-Length", str(end - start + 1))
                    self.send_header('Content-Range', f'bytes {start}-{end}/{len(fullContent)}')
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(fullContent[start:end + 1])
                else:
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.copyfile(f, self.wfile)
            finally:
                f.close()
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _proxyStaticScript(self, scriptPath, requestHeaders=None):
        """Generic method to proxy JavaScript files from static server

        Args:
            scriptPath: Relative path to script (e.g., "/static/js/E2EE.js")
            requestHeaders: Optional dict of additional headers to send with request
        """
        try:
            settingsGetter = SettingsGetter.getInstance()
            staticServer = settingsGetter.getStaticServer()
            remoteUrl = f"{staticServer}{scriptPath}"

            # Merge request headers if provided
            headers = requestHeaders or {}

            response = requests.get(remoteUrl, headers=headers, timeout=10)
            response.raise_for_status()

            # Send response
            self.send_response(HTTPStatus.OK)

            # Copy headers from the remote response
            for header, value in response.headers.items():
                self.send_header(header, value)

            self.end_headers()
            self.wfile.write(response.content)

        except requests.RequestException as e:
            logger.error(f"Failed to fetch {scriptPath} from {remoteUrl}: {e}")
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Failed to fetch from remote server: {str(e)}")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleStaticScript(self, scriptPath, requestHeaders=None):
        """Handle static script - proxy from remote or serve locally

        Args:
            scriptPath: Path to the script file
            requestHeaders: Headers to send with remote request (proxy mode) or set in response (local mode)
        """
        settingsGetter = SettingsGetter.getInstance()
        staticServer = settingsGetter.getStaticServer()

        # If static server is remote (starts with http), proxy the file
        if staticServer.startswith('http'):
            self._proxyStaticScript(scriptPath, requestHeaders)
        else:
            # Static server is local - serve from local filesystem
            # Store extra headers to be added by end_headers()
            self._extraHeaders = requestHeaders
            super().do_GET()

    def _handleProgressServiceWorker(self, args):
        """Handle ProgressServiceWorker.js - proxy from remote or serve locally"""
        # Service worker requires special headers
        requestHeaders = {'Service-Worker': 'script', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/'}
        self._handleStaticScript("/static/js/ProgressServiceWorker.js", requestHeaders)

    def _handleE2EEScript(self, args):
        """Handle E2EE.js - proxy from remote or serve locally"""
        self._handleStaticScript("/static/js/E2EE.js")

    def _handleStatus(self, args):
        """Handle status polling endpoint for error notifications"""
        try:
            # Check if there's a server error
            status = {'error': self.server.lastError if self.server.lastError else None}

            # Encode response
            responseBody = json.dumps(status).encode('utf-8')

            # Send headers with Content-Length
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(responseBody)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            # Send body
            self.wfile.write(responseBody)

        except Exception as e:
            logger.exception(f"Status endpoint error: {e}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Status endpoint error")

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
        try:
            # Check for debug simulation parameters
            simulateIceFailure = args and self.parseURLBooleanParam(args.get('simulate-ice-failure', [None])[0])
            if simulateIceFailure:
                logger.warning("Debug: Simulating ICE failure - returning 500 error")
                self.send_error(500, "Simulated ICE connection failure for testing")
                return

            simulateStall = args and self.parseURLBooleanParam(args.get('simulate-stall', [None])[0])
            if simulateStall:
                stallAfter = args.get('stall-after', ['50000'])[0]
                logger.warning(f"Debug: Simulating stall after {stallAfter} bytes - WebRTC will work initially")

            # Handle resume offset parameter
            offset = 0
            if args and 'offset' in args:
                try:
                    offset = int(args['offset'][0])
                    logger.info(f"Resume requested from offset: {offset}")
                except (ValueError, IndexError):
                    offset = 0

            path, name, size, ctype, reader = self._getFileInfo()

            # Detect browser for DTLS strategy selection
            browserHint = self._detectBrowser()
            logger.info(
                f"Detected browser: {browserHint} from User-Agent: {self.headers.get('User-Agent', 'N/A')[:100]}..."
            )

            # Pass E2EEManager if E2EE is enabled
            e2eeManager = self.server.e2eeManager if self.server.config.e2eeEnabled else None

            offer = self.server.webRTC.runAsync(
                self.server.webRTC.createOffer(
                    reader, size, formatSize, browserHint=browserHint, offset=offset, e2eeManager=e2eeManager
                )
            )
            self._sendBytes(json.dumps(offer).encode(), "application/json; charset=utf-8")

        except WebRTCDisabledError as e:
            # Handle WebRTC policy enforcement - use 403 Forbidden
            logger.info(f"WebRTC offer rejected by policy: {e.reason}")
            self.send_error(HTTPStatus.FORBIDDEN, e.reason)

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
                candidate = self.server.webRTC.getCandidates(peerId)
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

        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def do_GET(self):
        # Check authentication first
        if not self.handleAuthentication():
            return

        self.path, query, forbidden = self._normalizeRequestPath()
        args = parse_qs(query)

        if forbidden:
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return

        self._parseRange()

        # Get the appropriate handler for this path
        handler = self.getPathMap.get(self.path)
        logger.debug(f"[ROUTE] GET {self.path} -> handler={'found' if handler else 'NOT FOUND (using default)'}")
        if handler:
            handler(args)
        else:
            # Default handling for other paths
            try:
                super().do_GET()
            except Exception as e:
                logger.exception(e)
                self.send_error(500, str(e))

    def _sendBytes(self, payload: bytes, ctype: str = "text/plain; charset=utf-8"):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # POST handlers
    def _handleWebRTCAnswer(self, data):
        result = self.server.webRTC.runAsync(self.server.webRTC.setAnswer(data))
        self._sendBytes(result.encode())

    def _handleWebRTCCandidate(self, data):
        result = self.server.webRTC.runAsync(self.server.webRTC.addCandidate(data))
        self._sendBytes(result.encode())

    def _handleWebRTCComplete(self, data):
        """Handle browser notification that file download is complete"""
        result = self.server.webRTC.runAsync(self.server.webRTC.notifyDownloadComplete(data))
        self._sendBytes(result.encode())

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

            # Track User-Agent logging per session (not globally)
            if not hasattr(self.server, '_debugUserAgentSessions'):
                self.server._debugUserAgentSessions = set()

            # Log user agent for context (only once per session)
            if sessionId not in self.server._debugUserAgentSessions:
                flushPrint(f"[CLIENT-DEBUG] [INFO] [Session:{sessionId[:8]}] User-Agent: {userAgent}")
                self.server._debugUserAgentSessions.add(sessionId)

            # Send success response
            response = {"status": "success"}
            self._sendBytes(json.dumps(response).encode(), "application/json; charset=utf-8")

        except Exception as e:
            logger.exception(f"Error handling debug log: {e}")
            self.send_error(500, f"Debug log handler error: {str(e)}")

    def do_POST(self):
        # Check authentication first
        if not self.handleAuthentication():
            return

        self.path, query, forbidden = self._normalizeRequestPath()

        if forbidden:
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
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
            return

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

        # Get file info first (needed for Last-Modified)
        path, name, size, ctype, reader = self._getFileInfo(quoteName=False)

        # Send Last-Modified header (use current time since reader doesn't provide mtime)
        self.send_header("Last-Modified", self.date_time_string())

        # Only advertise Range support for resources that actually support it (not stdin)
        if reader.supportsRange and size is not None:
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", str(self.etag)) # To let browser can resume downloads

        # Add FFL-specific headers for share information
        self.send_header("FFL-Server", PUBLIC_VERSION)

        # Encode filename for HTTP header (use percent-encoding)
        # HTTP headers must be latin-1, so we URL-encode the filename
        # quote() handles both ASCII and non-ASCII filenames correctly
        self.send_header("FFL-FileName", quote(name))
        self.send_header("FFL-FileSize", str(size if size is not None else -1))

        # Indicate mode - P2P if WebRTC is enabled, otherwise HTTP, with E2EE if encrypted
        mode = "P2P" if self.server.config.defaultWebRTC else "HTTP"
        if self.server.config.e2eeEnabled:
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


class Server(ThreadingHTTPServer):

    request_queue_size = 128
    allow_reuse_address = True
    allow_reuse_port = True
    daemon_threads = True
    stop = False # The flag to let shutdown request can close server
    error = False # The flag to pass inner error message

    def __init__(
        self,
        reader,
        uid,
        domain,
        serverAddress,
        requestHandlerClass=None,
        webRTCManagerClass=None,
        config: ServerConfig = None
    ):
        # Use default config if not provided
        if config is None:
            config = ServerConfig()

        # Reader provides file and directory information
        self.reader = reader # SourceReader instance (required)
        self.directory = reader.directory
        self.file = reader.file
        self.uid = uid
        self.domain = domain
        self.config = config

        self.downloadCount = 0
        self.startTime = time.time()

        # Initialize error tracking for status polling
        self.lastError = None

        # Initialize E2E encryption if enabled
        if self.config.e2eeEnabled:
            # Get singleton instance (will auto-initialize keys on first call)
            self.e2eeManager = E2EEManager(WebRTCManager.CHUNK_SIZE)
            logger.info(
                f"[E2EE] E2E encryption ENABLED - using singleton manager "
                f"(e2eeEnabled={self.config.e2eeEnabled})"
            )
        else:
            self.e2eeManager = None
            logger.debug(f"[E2EE] E2E encryption DISABLED (e2eeEnabled={self.config.e2eeEnabled})")

        if requestHandlerClass is None:
            requestHandlerClass = DownloadHandler

        if webRTCManagerClass is None:
            webRTCManagerClass = WebRTCManager

        # Create exception handler that will be called by WebRTC on errors
        def handleWebRTCException(exception):
            # Use a dummy handler object to call _handleDownloadExceptionActions
            class ExceptionHandler(requestHandlerClass):

                def __init__(self, server):
                    self.server = server

            handler = ExceptionHandler(self)
            handler._handleDownloadExceptionActions(exception)

        self.webRTC = webRTCManagerClass(
            loggerCallback=flushPrint, downloadCallback=self.doAfterDownload, exceptionCallback=handleWebRTCException
        )

        super().__init__(serverAddress, requestHandlerClass)

    def serve_forever(self, pollInterval=0.5):
        """Handle one request at a time until shutdown, with timeout checking."""

        # Create a thread to periodically check the timeout
        def timeoutChecker():
            while not self.stop:
                if self.config.timeout > 0 and (time.time() - self.startTime) >= self.config.timeout:
                    flushPrint(_('Timeout ({timeout} seconds) reached. Shutting down server.').format(
                        timeout=self.config.timeout))
                    self.shutdown()
                    break

                time.sleep(pollInterval)

        if self.config.timeout > 0:
            timeoutThread = threading.Thread(target=timeoutChecker, daemon=True)
            timeoutThread.start()

        # Call the parent's serve_forever
        super().serve_forever(pollInterval)

    def doAfterDownload(self):
        # It increments the download count and checks for auto-shutdown conditions.
        self.downloadCount += 1
        if self.config.maxDownloads > 0 and self.downloadCount >= self.config.maxDownloads:
            flushPrint(_('Maximum downloads ({maxDownloads}) reached. Shutting down server.').format(
                maxDownloads=self.config.maxDownloads))
            self.shutdown()

    # Let normal shutdown not be printed
    def handle_error(self, request, client_address):
        logger.exception(sys.exception())

        if self.stop:
            if not self.error:
                return

    def start(self):
        # Start the given server instance
        self.serve_forever()

        if self.error:
            raise ChildProcessError()

    def shutdown(self):
        self.stop = True
        self.webRTC.closeWebRTC()
        super().shutdown()


def createServer(reader, port, uid, domain, handlerClass=None, webRTCManagerClass=None, config: ServerConfig = None):
    """
    Factory function to create a Server instance

    Args:
        reader: SourceReader instance (provides file and directory)
        port: Server port
        uid: Unique identifier for the server
        domain: Domain name
        handlerClass: Custom request handler class
        webRTCManagerClass: Custom WebRTC manager class
        config: ServerConfig instance with server configuration

    Returns:
        Server: Configured server instance
    """
    serverAddress = ('127.0.0.1', port)
    return Server(reader, uid, domain, serverAddress, handlerClass, webRTCManagerClass, config)
