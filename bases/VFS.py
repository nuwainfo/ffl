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
import json
import time
import threading

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

from bases.Kernel import getLogger
from bases.Server import AuthMixin, HTTPAuth

logger = getLogger(__name__)

# Transfer chunk sizes
CHUNK_SIZE = 256 * 1024 # General streaming chunk size
HTTP_READ_CHUNK = 1024 * 1024 # HTTP Range read chunk size

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

        class VfsHandler(AuthMixin, BaseHTTPRequestHandler):
            """HTTP request handler for VFS protocol"""

            REALM = 'VFS Protected Resource'

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
                    path = parsed.path
                    query = parse_qs(parsed.query)
                    keepAlive = self._shouldKeepAlive()

                    if path == "/meta":
                        self._handleMeta(keepAlive)
                    elif path == "/list":
                        self._handleList(query, keepAlive)
                    elif path == "/stat":
                        self._handleStat(query, keepAlive)
                    elif path == "/open":
                        self._handleOpen(query, keepAlive)
                    elif path == "/file":
                        self._handleFile(query, keepAlive)
                    else:
                        self._sendError(404, "Not Found", "Unknown endpoint", keepAlive)

                except Exception as e:
                    logger.exception(f"Error handling request: {e}")
                    self._sendError(500, "Internal Server Error", str(e), self._shouldKeepAlive())

            def _handleMeta(self, keepAlive: bool):
                """Handle /meta endpoint"""
                obj = {
                    "ok": True,
                    "folderName": server.rootName,
                    "rootId": server._rootId,
                    "rootIsDir": not server.isFile
                }
                self._sendJson(200, obj, keepAlive)

            def _handleList(self, query: Dict, keepAlive: bool):
                """Handle /list endpoint"""
                dirId = query.get("id", [None])[0]
                if not dirId:
                    self._sendJson(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                # Handle single-file mode: files have no children
                if server.isFile and dirId == server._rootId:
                    self._sendJson(200, {"ok": True, "entries": []}, keepAlive)
                    return

                dirPath = server._getPathForId(dirId)
                if not dirPath or not os.path.exists(dirPath):
                    self._sendJson(404, {"ok": False, "error": "directory not found"}, keepAlive)
                    return

                if not os.path.isdir(dirPath):
                    self._sendJson(400, {"ok": False, "error": "not a directory"}, keepAlive)
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
                    self._sendJson(500, {"ok": False, "error": f"list failed: {e}"}, keepAlive)
                    return

                self._sendJson(200, {"ok": True, "entries": entries}, keepAlive)

            def _handleStat(self, query: Dict, keepAlive: bool):
                """Handle /stat endpoint"""
                docId = query.get("id", [None])[0]
                if not docId:
                    self._sendJson(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                path = server._getPathForId(docId)
                if not path or not os.path.exists(path):
                    self._sendJson(404, {"ok": False, "error": "not found"}, keepAlive)
                    return

                try:
                    st = os.stat(path)
                    isDir = os.path.isdir(path)
                    size = 0 if isDir else st.st_size
                    mtime = st.st_mtime

                    obj = {"ok": True, "id": docId, "isDir": isDir, "size": size, "mtime": mtime}
                    self._sendJson(200, obj, keepAlive)

                except OSError as e:
                    self._sendJson(500, {"ok": False, "error": f"stat failed: {e}"}, keepAlive)

            def _handleOpen(self, query: Dict, keepAlive: bool):
                """Handle /open endpoint - returns file size for opening"""
                docId = query.get("id", [None])[0]
                if not docId:
                    self._sendJson(400, {"ok": False, "error": "missing id"}, keepAlive)
                    return

                path = server._getPathForId(docId)
                if not path or not os.path.exists(path):
                    self._sendJson(404, {"ok": False, "error": f"not a file: {docId}"}, keepAlive)
                    return

                if not os.path.isfile(path):
                    self._sendJson(404, {"ok": False, "error": f"not a file: {docId}"}, keepAlive)
                    return

                try:
                    st = os.stat(path)
                    obj = {"ok": True, "size": st.st_size}
                    self._sendJson(200, obj, keepAlive)

                except OSError as e:
                    self._sendJson(500, {"ok": False, "error": f"stat failed: {e}"}, keepAlive)

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

                # Parse Range header
                rangeHeader = self.headers.get("Range")
                if not rangeHeader:
                    self._streamFile(path, 0, fileSize - 1, fileSize, partial=False, keepAlive=keepAlive)
                    return

                # Parse "bytes=start-end"
                rangeMatch = self._parseRange(rangeHeader, fileSize)
                if not rangeMatch:
                    self.send_response(416, "Range Not Satisfiable")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Range", f"bytes */{fileSize}")
                    self.send_header("Connection", "keep-alive" if keepAlive else "close")
                    self.end_headers()
                    return

                start, end = rangeMatch
                self._streamFile(path, start, end, fileSize, partial=True, keepAlive=keepAlive)

            def _parseRange(self, rangeHeader: str, fileSize: int) -> Optional[Tuple[int, int]]:
                """Parse HTTP Range header"""
                if not rangeHeader.startswith("bytes="):
                    return None

                spec = rangeHeader[6:].strip()
                dashIdx = spec.find("-")
                if dashIdx < 0:
                    return None

                startStr = spec[:dashIdx].strip()
                endStr = spec[dashIdx + 1:].strip()

                if not startStr:
                    return None # Suffix range not supported

                try:
                    start = int(startStr)
                except ValueError as e:
                    logger.debug(f"Invalid Range start value '{startStr}': {e}")
                    return None

                if start < 0 or start >= fileSize:
                    return None

                if endStr:
                    try:
                        end = int(endStr)
                    except ValueError as e:
                        logger.debug(f"Invalid Range end value '{endStr}': {e}")
                        return None
                else:
                    end = fileSize - 1

                end = min(end, fileSize - 1)
                if end < start:
                    return None

                return (start, end)

            def _streamFile(self, path: str, start: int, end: int, fileSize: int, partial: bool, keepAlive: bool):
                """Stream file with Range support"""
                try:
                    with open(path, "rb") as f:
                        # Seek to start
                        if start > 0:
                            f.seek(start)

                        length = end - start + 1
                        status = 206 if partial else 200
                        reason = "Partial Content" if partial else "OK"

                        self.send_response(status, reason)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Length", str(length))
                        if partial:
                            self.send_header("Content-Range", f"bytes {start}-{end}/{fileSize}")
                        self.send_header("Connection", "keep-alive" if keepAlive else "close")
                        self.end_headers()

                        # Stream file data
                        remaining = length
                        while remaining > 0:
                            chunkSize = min(CHUNK_SIZE, remaining)
                            chunk = f.read(chunkSize)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)

                except OSError as e:
                    logger.error(f"Error streaming file {path}: {e}")

            def _sendJson(self, code: int, obj: dict, keepAlive: bool):
                """Send JSON response"""
                data = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "keep-alive" if keepAlive else "close")
                self.end_headers()
                self.wfile.write(data)

            def _sendText(self, code: int, reason: str, msg: str, keepAlive: bool):
                """Send text response"""
                data = msg.encode("utf-8")
                self.send_response(code, reason)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "keep-alive" if keepAlive else "close")
                self.end_headers()
                self.wfile.write(data)

            def _sendError(self, code: int, reason: str, msg: str, keepAlive: bool):
                """Send error response"""
                self._sendText(code, reason, msg, keepAlive)

        return VfsHandler
