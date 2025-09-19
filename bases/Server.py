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

import io
import json
import os
import re
import sys
import uuid
import datetime
import base64

import requests

from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from time import time
from urllib.parse import parse_qs, quote, urlparse

from bases.Kernel import getLogger
from bases.Utils import flushPrint, sendException, utf8, formatSize
from bases.Settings import SettingsGetter, STATIC_SERVER
from bases.WebRTC import WebRTCManager
from bases.Progress import Progress

DOWNLOAD_CHUNK = 65535
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
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    logger.warn("Unable to optimize event loop in platform")


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
        if not hasattr(self.server, 'authPassword') or not self.server.authPassword:
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
            if username == self.server.authUser and password == self.server.authPassword:
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
            '/offer': self._handleWebRTCOffer,
            '/candidate': self._handleWebRTCCandidatePolling,
            '/': self._handleRedirect,
            '': self._handleRedirect
        }

        self.postPathMap = {
            '/answer': self._handleWebRTCAnswer,
            '/candidate': self._handleWebRTCCandidate,
            '/complete': self._handleWebRTCComplete,
        }

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

    def _getFileInfo(self, quoteName=True):
        path = os.path.join(self.server.directory, self.server.file)
        if quoteName:
            name = quote(self.server.file)
        else:
            name = self.server.file
        size = os.path.getsize(path)
        ctype = self.guess_type(path)

        return path, name, size, ctype

    # HEAD handlers
    def _handleForbiddenHead(self):
        self.send_response(HTTPStatus.FORBIDDEN)
        self.end_headers()

    def _handleDefaultHead(self):
        super().do_HEAD()

    def _handleDownloadHead(self):
        path, name, size, ctype = self._getFileInfo()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-type", ctype)
        self.send_header("Content-Disposition", f"attachment; filename={name}")
        self.end_headers()

    # Add HTTP HEAD to let server can get Content-Disposition without triggered download
    def do_HEAD(self):
        # Check authentication first
        if not self.handleAuthentication():
            return

        path, query, forbidden = self._normalizeRequestPath()

        if forbidden:
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return

        handler = self.headPathMap.get(path)
        if handler:
            handler()
        else:
            super().do_HEAD()

        self.connection.close()

    # GET handlers
    def _handleRedirect(self, args):
        if 'User-Agent' not in self.headers:
            self._handleDownload(args)
        elif 'Mozilla' not in self.headers['User-Agent']:
            self._handleDownload(args)
        elif 'WindowsPowerShell' in self.headers['User-Agent']:
            self._handleDownload(args)
        else:
            self.path = '/static/index.html'
            self._handleStaticIndex(args)

    def _handleStartDownloadActions(self, size):
        flushPrint(f'[{self.date_time_string()}] Downloading by user')

    def _handlePostDownloadActions(self, size):
        flushPrint(
            'File sending is complete. '
            'Please wait for the recipient to finish downloading before you close the application.\n'
        )
        self.server.doAfterDownload()

    def _handleDownloadExceptionActions(self, exception):
        if isinstance(exception, (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError)):
            flushPrint('\nConnection disconnected, wait retrying.\n')
        elif isinstance(exception, OSError):
            flushPrint('\nUser closes the connection, please try again.\n')

    def _handleDownload(self, args):
        path = os.path.join(self.server.directory, self.server.file)
        size = os.path.getsize(path)
        ctype = self.guess_type(path)

        # Start to download.
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

        try:
            with open(path, 'rb') as f:
                # Handle range requests
                if self.range:
                    start, end = self.range
                else:
                    start, end = 0, size - 1
                end = end if end else size - 1

                # Send appropriate response headers
                if 'Range' in self.headers:
                    if self.range:
                        self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    else:
                        self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                        self.end_headers()
                        return
                else:
                    self.send_response(HTTPStatus.OK)

                self.send_header("Content-Length", str(end - start + 1))
                self.send_header("Content-Range", f'bytes {start}-{end}/{size}')
                self.send_header("Content-type", ctype)
                self.send_header("Content-Disposition", f"attachment; filename={quote(self.server.file)}")
                self.end_headers()

                f.seek(start)
                written += start

                # Send file data in chunks
                while True:
                    data = f.read(DOWNLOAD_CHUNK)
                    if not data:
                        break

                    # Ensure we don't send beyond the requested range
                    if f.tell() - 1 > end and size > end:
                        data = data[:end - f.tell() + 1]

                    self.wfile.write(data)
                    written += len(data)

                    # Update progress periodically
                    progress.update(written)

                    if f.tell() > end:
                        break

                # Final progress update
                progress.update(written, forceLog=True)

            # Handle post-download actions
            self._handlePostDownloadActions(size)

        except (ConnectionResetError, ConnectionAbortedError, ConnectionError, BrokenPipeError) as ce:
            self._handleDownloadExceptionActions(ce)
        except OSError as e:
            self._handleDownloadExceptionActions(e)

    def _handleStaticIndex(self, args):
        try:
            with open(self.translate_path('/static/index.html'), 'rb') as f:
                content = f.read()

                # Replace STATIC_SERVER
                staticServer = STATIC_SERVER
                content = content.replace(b'{{ STATIC_SERVER }}', staticServer.encode())

                # Replace UID placeholder
                content = content.replace(b'uid=****', self.server.uid.encode())

                # Replace file_name, file_size placeholder
                path, name, size, ctype = self._getFileInfo(quoteName=False)
                content = content.replace(b'{{ fileName }}', name.encode())
                content = content.replace(b'{{ fileSize }}', str(size).encode())

                # Check for debug mode from environment variable or URL parameter
                # WebRTC priority system (highest to lowest priority), and other settings the same priority design:
                # 1. URL parameter (?webrtc=yes/no/1/0/true/false/on/off)
                # 2. Server enableWebRTC setting (from --force-relay CLI option)
                # 3. DISABLE_WEBRTC environment variable
                debugEnabled = os.getenv('JS_DEBUG', None) == 'True'
                serverDebugEnabled = os.getenv('JS_LOG_TO_SERVER_DEBUG', None) == 'True'
                webrtcDisabled = os.getenv('DISABLE_WEBRTC', None) == 'True'

                webrtcDisabledDetermined = False

                # Parse URL parameters for runtime control
                # These is priority 1, so overwrite environment variables setting.
                if args:
                    # Check debug parameter: ?debug=yes/1/true/on/server
                    debugParam = args.get('debug', [None])[0]
                    if debugParam:
                        debugValue = debugParam.lower()
                        if debugValue in ('yes', '1', 'true', 'on'):
                            debugEnabled = True
                        elif debugValue == 'server':
                            # Enable server-side logging only if both URL param and env var are set
                            serverDebugEnabled = True
                        else:
                            pass

                    # Check webrtc parameter: ?webrtc=no/0/false/off/yes/1/true/on
                    webrtcParam = args.get('webrtc', [None])[0]
                    if webrtcParam:
                        webrtcValue = webrtcParam.lower()
                        if webrtcValue in ('no', '0', 'false', 'off'):
                            webrtcDisabled = True
                        elif webrtcValue in ('yes', '1', 'true', 'on'):
                            webrtcDisabled = False
                        else:
                            pass

                        webrtcDisabledDetermined = True

                # Apply priority system for WebRTC
                if not webrtcDisabledDetermined: # No URL parameter override
                    # Priority 2: Server enableWebRTC setting
                    if not self.server.enableWebRTC:
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

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(content)))

            f = io.BytesIO(content)
            try:
                if self.range:
                    start, end = self.range
                    content = f.read()
                    end = end if end else len(content)
                    # Must end_headers after all send_header calls.
                    self.send_header('Content-Range', f'bytes {start}-{end}/{len(content)}')
                    self.end_headers()
                    self.wfile.write(content[start:end + 1])
                else:
                    self.end_headers()
                    self.copyfile(f, self.wfile)
            finally:
                f.close()
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleProgressServiceWorker(self, args):
        """Handle ProgressServiceWorker.js with Service-Worker-Allowed header by proxying from STATIC_SERVER"""
        try:
            # Fetch the ProgressServiceWorker.js from remote STATIC_SERVER with browser headers
            remoteUrl = f"{STATIC_SERVER}/static/js/ProgressServiceWorker.js"

            # Simulate browser request headers for service worker
            headers = {'Service-Worker': 'script', 'Cache-Control': 'no-cache'}

            response = requests.get(remoteUrl, headers=headers, timeout=10)
            response.raise_for_status()

            # Send response with Service-Worker-Allowed header
            self.send_response(HTTPStatus.OK)

            # Copy headers from the remote response
            for header, value in response.headers.items():
                self.send_header(header, value)

            self.end_headers()
            self.wfile.write(response.content)

        except requests.RequestException as e:
            logger.error(f"Failed to fetch ProgressServiceWorker.js from {remoteUrl}: {e}")
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Failed to fetch from remote server: {str(e)}")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

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
            path, name, size, ctype = self._getFileInfo()

            # Detect browser for DTLS strategy selection
            browserHint = self._detectBrowser()
            logger.info(
                f"Detected browser: {browserHint} from User-Agent: {self.headers.get('User-Agent', 'N/A')[:100]}..."
            )

            offer = self.server.webRTC.runAsync(
                self.server.webRTC.createOffer(path, size, formatSize, browserHint=browserHint)
            )
            self._sendBytes(json.dumps(offer).encode(), "application/json; charset=utf-8")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleWebRTCCandidatePolling(self, args):
        try:
            # Get peerId from query parameters
            peerId = args.get("peer", [""])[0] if "peer" in args else ""

            if not peerId:
                self.send_error(HTTPStatus.NOT_FOUND, "Missing peer parameter")
                return

            # Get candidate from WebRTC manager
            try:
                candidate = self.server.webRTC.getCandidates(peerId)
            except ValueError:
                self.send_error(HTTPStatus.NOT_FOUND, "Unknown peer")
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
        if handler:
            handler(args)
        else:
            # Default handling for other paths
            try:
                super().do_GET()
            except Exception as e:
                logger.exception(e)
                self.send_error(500, str(e))

        self.connection.close()

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
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

        self.connection.close()

    # Override utility methods
    def send_response(self, code, message=None):
        self.send_response_only(code, utf8(message))
        self.send_header('Date', self.date_time_string())

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
        self.send_header("Last-Modified", self.date_time_string())
        self.send_header("Accept-Ranges", 'bytes')
        self.send_header("ETag", str(self.etag)) # To let browser can resume downloads
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


class Server(ThreadingHTTPServer):

    request_queue_size = 5
    allow_reuse_address = True
    allow_reuse_port = True
    daemon_threads = True
    stop = False # The flag to let shutdown request can close server
    error = False # The flag to pass inner error message

    def __init__(
        self,
        directory,
        file,
        uid,
        domain,
        serverAddress,
        requestHandlerClass=None,
        webRTCManagerClass=None,
        maxDownloads=0,
        timeout=0,
        authUser=None,
        authPassword=None,
        enableWebRTC=True
    ):
        self.directory = os.path.abspath(directory)
        self.file = file
        self.uid = uid
        self.domain = domain
        self.maxDownloads = maxDownloads
        self.timeout = timeout
        self.authUser = authUser
        self.authPassword = authPassword
        self.enableWebRTC = enableWebRTC

        self.downloadCount = 0
        self.startTime = time()

        if requestHandlerClass is None:
            requestHandlerClass = DownloadHandler

        if webRTCManagerClass is None:
            webRTCManagerClass = WebRTCManager

        self.webRTC = webRTCManagerClass(loggerCallback=flushPrint, downloadCallback=self.doAfterDownload)

        super().__init__(serverAddress, requestHandlerClass)

    def serve_forever(self, pollInterval=0.5):
        """Handle one request at a time until shutdown, with timeout checking."""
        import threading
        import time

        # Create a thread to periodically check the timeout
        def timeoutChecker():
            while not self.stop:
                if self.timeout > 0 and (time.time() - self.startTime) >= self.timeout:
                    flushPrint(f'Timeout ({self.timeout} seconds) reached. Shutting down server.')
                    self.shutdown()
                    break

                time.sleep(pollInterval)

        if self.timeout > 0:
            timeoutThread = threading.Thread(target=timeoutChecker, daemon=True)
            timeoutThread.start()

        # Call the parent's serve_forever
        super().serve_forever(pollInterval)

    def doAfterDownload(self):
        # It increments the download count and checks for auto-shutdown conditions.
        self.downloadCount += 1
        if self.maxDownloads > 0 and self.downloadCount >= self.maxDownloads:
            flushPrint(f'Maximum downloads ({self.maxDownloads}) reached. Shutting down server.')
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


def createServer(
    port,
    directory,
    file,
    uid,
    domain,
    handlerClass=None,
    webRTCManagerClass=None,
    maxDownloads=0,
    timeout=0,
    authUser=None,
    authPassword=None,
    enableWebRTC=True
):
    # Factory function to create a Server instance with specified handler and WebRTC manager
    if handlerClass is None:
        handlerClass = DownloadHandler

    serverAddress = ('127.0.0.1', port)
    return Server(
        directory, file, uid, domain, serverAddress, handlerClass, webRTCManagerClass, maxDownloads, timeout, authUser,
        authPassword, enableWebRTC
    )
