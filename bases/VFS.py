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
"""
VFS (Virtual File System) over HTTP protocol implementation.

Provides HTTP-based access to local filesystems with:
- ID-based protocol (O(1) operations)
- Single keep-alive connection
- HTTP Range support for efficient file streaming
- Compatible with Reader.py architecture
"""

import os
import time
import threading

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode

from bases.I18n import _
from bases.HTTP import HTTPRequestHandlerHelper, PathResolverMixin
from bases.Kernel import FFLEvent, getLogger
from bases.Auth import AuthMixin, HTTPAuth
from bases.Settings import SettingsGetter
from bases.Utils import copy2Clipboard

logger = getLogger(__name__)

# Server configuration
DEFAULT_VFS_HOST = "127.0.0.1"
DEFAULT_VFS_PORT = 0 # Random port


class VFSServer(ThreadingHTTPServer):
    """
    HTTP server exposing local filesystem via vfs:// protocol.

    Binds to loopback (127.0.0.1) by default for security.
    Uses id-based protocol where each file/dir has a unique ID.

    Endpoints:
    - GET /meta: Get root folder metadata
    - GET /list?id=<dirId>: List directory contents
    - GET /stat?id=<docId>: Get file/directory metadata
    - GET /open?id=<fileId>: Get file size (for opening)
    - GET /file?id=<docId>: Stream file with Range support
    """

    daemon_threads = True

    def __init__(
        self,
        rootPath: str,
        host: str = DEFAULT_VFS_HOST,
        port: int = DEFAULT_VFS_PORT,
        authUser: Optional[str] = None,
        authPassword: Optional[str] = None
    ):
        """
        Initialize VFS server.

        Args:
            rootPath: Root file or directory to expose
            host: Bind address (default: 127.0.0.1)
            port: Port number (default: 0 = random)
            authUser: Optional HTTP Basic Auth username
            authPassword: Optional HTTP Basic Auth password (enables auth if provided)

        Raises:
            ValueError: If rootPath does not exist
        """
        if not os.path.exists(rootPath):
            raise ValueError(f"Path does not exist: {rootPath}")

        self.rootPath = os.path.abspath(rootPath)
        self.isFile = os.path.isfile(rootPath)
        self.host = host
        self.authUser = authUser
        self.authPassword = authPassword
        self._thread = None
        self._running = False

        # ID mapping: id -> absolute path
        self._idToPath = {}
        self._pathToId = {}
        self._nextId = 1
        self._lock = threading.Lock()

        # Root ID is always "1"
        self._rootId = self._registerPath(self.rootPath)

        logger.debug(f"VfsServer initialized: root={self.rootPath}, rootId={self._rootId}, isFile={self.isFile}")

        # Create handler class and initialize HTTPServer
        handler = self._createHandler()
        super().__init__((host, port), handler)

    def _registerPath(self, path: str) -> str:
        """
        Register a path and return its ID.

        Args:
            path: Absolute path to register

        Returns:
            str: Unique ID for this path
        """
        path = os.path.abspath(path)

        with self._lock:
            if path in self._pathToId:
                return self._pathToId[path]

            docId = str(self._nextId)
            self._nextId += 1
            self._idToPath[docId] = path
            self._pathToId[path] = docId
            return docId

    def _getPathForId(self, docId: str) -> Optional[str]:
        """
        Get path for given ID.

        Args:
            docId: Document ID

        Returns:
            Absolute path or None if not found
        """
        with self._lock:
            return self._idToPath.get(docId)

    @property
    def rootName(self) -> str:
        """Get root file or folder display name"""
        if self.isFile:
            return os.path.basename(self.rootPath)
        return os.path.basename(self.rootPath.rstrip(os.sep)) or "folder"

    @property
    def clientUri(self) -> str:
        """Get client URI for connecting (vfs:// format)"""
        if not self._running:
            raise RuntimeError("Server not started")
        return f"vfs://{self.host}:{self.actualPort}"

    @property
    def actualPort(self) -> int:
        """Get actual bound port (useful when port=0)"""
        if not self._running:
            raise RuntimeError("Server not started")
        return self.server_port

    def start(self, blocking: bool = False) -> None:
        """
        Start VFS server.

        Args:
            blocking: If True, blocks until server stops (for testing)

        Raises:
            RuntimeError: If server already started
        """
        if self._running:
            raise RuntimeError("Server already started")

        self._running = True

        logger.info(f"VfsServer listening on {self.clientUri}")

        if blocking:
            self.serve_forever()
        else:
            self._thread = threading.Thread(target=self.serve_forever, daemon=True)
            self._thread.start()
            # Give server time to start
            time.sleep(0.1)

    def stop(self) -> None:
        """Stop VFS server"""
        if not self._running:
            return

        self._running = False

        self.shutdown()
        self.server_close()

        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

        logger.debug("VfsServer stopped")

    def _createHandler(self):
        """Create HTTP request handler class"""
        server = self

        class VFSHandler(PathResolverMixin, HTTPRequestHandlerHelper, AuthMixin, BaseHTTPRequestHandler):
            """HTTP request handler for VFS protocol"""

            REALM = 'VFS Protected Resource'

            def __init__(self, *args, **kwargs):
                self.mapGETRoute("/meta", self._handleMeta)
                self.mapGETRoute("/list", self._handleList)
                self.mapGETRoute("/stat", self._handleStat)
                self.mapGETRoute("/open", self._handleOpen)
                self.mapGETRoute("/file", self._handleFile)
                super().__init__(*args, **kwargs)

            def log_message(self, format, *args):
                """Override to use our logger"""
                logger.debug(f"VFS HTTP: {format % args}")

            @property
            def auth(self) -> HTTPAuth:
                """Return HTTPAuth from server for AuthMixin."""
                return HTTPAuth(user=server.authUser, password=server.authPassword)

            def _shouldKeepAlive(self) -> bool:
                """
                Determine if connection should be kept alive.

                HTTP/1.1 defaults to keep-alive unless Connection: close is specified.
                HTTP/1.0 defaults to close unless Connection: keep-alive is specified.
                """
                conn = self.headers.get("Connection", "").lower().strip()

                if conn == "close":
                    return False
                elif conn == "keep-alive":
                    return True

                # HTTP/1.1 defaults to keep-alive
                return self.request_version == "HTTP/1.1"

            def do_GET(self):
                """Handle GET requests"""
                # Check authentication first
                if not self.handleAuthentication():
                    return

                try:
                    parsed = urlparse(self.path)
                    query = parse_qs(parsed.query)
                    keepAlive = self._shouldKeepAlive()

                    handler = self._resolveGETHandler(parsed.path)
                    if handler:
                        handler(query, keepAlive)
                    else:
                        self._sendError(404, "Not Found", "Unknown endpoint", keepAlive)

                except Exception as e:
                    logger.exception(f"Error handling request: {e}")
                    self._sendError(500, "Internal Server Error", str(e), self._shouldKeepAlive())

            def _handleMeta(self, query: Dict, keepAlive: bool):
                """Handle /meta endpoint"""
                obj = {
                    "ok": True,
                    "folderName": server.rootName,
                    "rootId": server._rootId,
                    "rootIsDir": not server.isFile
                }
                self._sendJSON(200, obj, keepAlive)

            def _handleList(self, query: Dict, keepAlive: bool):
                """Handle /list endpoint"""
                dirId = query.get("id", [None])[0]
                if not dirId:
                    self._sendJSON(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                # Handle single-file mode: files have no children
                if server.isFile and dirId == server._rootId:
                    self._sendJSON(200, {"ok": True, "entries": []}, keepAlive)
                    return

                dirPath = server._getPathForId(dirId)
                if not dirPath or not os.path.exists(dirPath):
                    self._sendJSON(404, {"ok": False, "error": "directory not found"}, keepAlive)
                    return

                if not os.path.isdir(dirPath):
                    self._sendJSON(400, {"ok": False, "error": "not a directory"}, keepAlive)
                    return

                entries = []
                try:
                    for name in os.listdir(dirPath):
                        entryPath = os.path.join(dirPath, name)

                        # Register path and get ID
                        entryId = server._registerPath(entryPath)

                        # Get stat
                        try:
                            st = os.stat(entryPath)
                            isDir = os.path.isdir(entryPath)
                            size = 0 if isDir else st.st_size
                            mtime = st.st_mtime
                        except OSError as e:
                            # File disappeared or permission denied
                            logger.debug(f"Skipping entry {name}: {e}")
                            continue

                        entries.append({"id": entryId, "name": name, "isDir": isDir, "size": size, "mtime": mtime})

                    # Deterministic sorting: by name, then by id for tie-breaking
                    entries.sort(key=lambda e: (e["name"], e["id"]))

                except OSError as e:
                    self._sendJSON(500, {"ok": False, "error": f"list failed: {e}"}, keepAlive)
                    return

                self._sendJSON(200, {"ok": True, "entries": entries}, keepAlive)

            def _handleStat(self, query: Dict, keepAlive: bool):
                """Handle /stat endpoint"""
                docId = query.get("id", [None])[0]
                if not docId:
                    self._sendJSON(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                path = server._getPathForId(docId)
                if not path or not os.path.exists(path):
                    self._sendJSON(404, {"ok": False, "error": "not found"}, keepAlive)
                    return

                try:
                    st = os.stat(path)
                    isDir = os.path.isdir(path)
                    size = 0 if isDir else st.st_size
                    mtime = st.st_mtime

                    obj = {"ok": True, "id": docId, "isDir": isDir, "size": size, "mtime": mtime}
                    self._sendJSON(200, obj, keepAlive)

                except OSError as e:
                    self._sendJSON(500, {"ok": False, "error": f"stat failed: {e}"}, keepAlive)

            def _handleOpen(self, query: Dict, keepAlive: bool):
                """Handle /open endpoint - returns file size for opening"""
                docId = query.get("id", [None])[0]
                if not docId:
                    self._sendJSON(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                path = server._getPathForId(docId)
                if not path or not os.path.exists(path):
                    self._sendJSON(404, {"ok": False, "error": f"not a file: {docId}"}, keepAlive)
                    return

                if not os.path.isfile(path):
                    self._sendJSON(404, {"ok": False, "error": f"not a file: {docId}"}, keepAlive)
                    return

                try:
                    st = os.stat(path)
                    obj = {"ok": True, "size": st.st_size}
                    self._sendJSON(200, obj, keepAlive)

                except OSError as e:
                    self._sendJSON(500, {"ok": False, "error": f"stat failed: {e}"}, keepAlive)

            def _handleFile(self, query: Dict, keepAlive: bool):
                """Handle /file endpoint with Range support"""
                docId = query.get("id", [None])[0]
                if not docId:
                    self._sendText(400, "Bad Request", "missing id", keepAlive)
                    return

                path = server._getPathForId(docId)
                if not path or not os.path.exists(path):
                    self._sendText(404, "Not Found", "file not found", keepAlive)
                    return

                if not os.path.isfile(path):
                    self._sendText(400, "Bad Request", "not a file", keepAlive)
                    return

                try:
                    fileSize = os.path.getsize(path)
                except OSError as e:
                    self._sendText(500, "Internal Server Error", f"stat failed: {e}", keepAlive)
                    return

                self._streamFile(path, fileSize, rangeHeader=self.headers.get("Range"), keepAlive=keepAlive)

            def _sendError(self, code: int, reason: str, msg: str, keepAlive: bool):
                """Send error response"""
                self._sendText(code, reason, msg, keepAlive)

        return VFSHandler


def processVFS(args, reporter):
    output = reporter.output

    # VFS mode requires file or folder (already validated in CLI.py)
    if not os.path.isfile(args.file) and not os.path.isdir(args.file):
        output(_('Error: VFS mode requires a file or folder path'))
        return 1

    # Get port (VFS server uses specified port or random)
    vfsPort = args.port if args.port else 0
    
    authPassword = args.authPassword or os.getenv('FFL_AUTH_PASSWORD')
    authUser = args.authUser if authPassword else None

     # Start VFS server (supports both files and folders)
    vfsServer = VFSServer(args.file, host="127.0.0.1", port=vfsPort, authUser=authUser, authPassword=authPassword)
    vfsServer.start()

    vfsUri = vfsServer.clientUri
    
    reporter.vfsServerCreated(vfsServer, link=vfsUri, uid=args.uid)
    output(_("VFS server started successfully!\n"))

    shareType = 'file' if os.path.isfile(args.file) else 'folder'
    output(_("Please share the URI below to access the {type} remotely:\n").format(type=shareType))

    # Show auth info if enabled (password enables auth)
    if authPassword:
        output(_('Authentication enabled - Username: {authUser}\n').format(authUser=authUser))
    
    # Never include password in URI (security issue)
    output(f"{vfsUri}\n")
    if not args.disableClipboard:
        copy2Clipboard(vfsUri)

    output(_('VFS server is running on loopback (127.0.0.1) - only accessible from this machine.'))
    output(_('Please keep the application running for remote access.'))
    if SettingsGetter.getInstance().isCLIMode():
        output(_('Press Ctrl+C to stop the server.\n'))
    else:
        output('')

    shareLinkData = {
        'uid': args.uid,
        'link': vfsUri,
        'filePath': args.file,
        'contentName': os.path.basename(args.file),
        'fileSize': None, # VFS TAR size unknown
        'tunnelType': "vfs",
        'e2ee': False, # VFS doesn't support E2EE yet
        'reader': None,
    }
    FFLEvent.shareLinkCreate.trigger(**shareLinkData)
    
    reporter.shareLinkCreated(**shareLinkData)

    try:
        # Keep server running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        output(_('\nShutting down VFS server...'))
        FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')
    finally:
        vfsServer.stop()
        output(_('VFS server stopped.'))

    return 0
