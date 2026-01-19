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
FileSystem abstraction for Reader.py

Provides a unified interface for accessing files and directories from different sources:
- LocalFileSystem: Local filesystem (wraps os.* calls)
- HTTPFileSystem: Remote filesystem over HTTP (VFS protocol)

This allows Readers to work with both local and remote filesystems without changes.
"""

import base64
import io
import os
import json
import threading
import stat as _stat

from dataclasses import dataclass
from typing import BinaryIO, Dict, Iterable, List, Optional, Protocol, Tuple
from urllib.parse import urlparse, urlencode

from http.client import HTTPConnection, RemoteDisconnected

from bases.Kernel import getLogger

logger = getLogger(__name__)

# Transfer chunk size for HTTP reads
HTTP_READ_CHUNK = 1024 * 1024 # 1 MB


@dataclass
class Stat:
    """File/directory metadata"""
    size: int
    mtime: Optional[float]
    isDir: bool


class FileSystem(Protocol):
    """FileSystem protocol that all implementations must follow"""

    def rootName(self) -> str:
        ...

    def rootPath(self) -> str:
        ... # Root path to pass to walk()

    def rootIsDir(self) -> str:
        ...

    def walk(self, top: str) -> Iterable[Tuple[str, List[str], List[str]]]:
        ...

    def stat(self, path: str) -> Stat:
        ...

    def open(self, path: str) -> BinaryIO:
        ...

    def exists(self, path: str) -> bool:
        ...

    def isFile(self, path: str) -> bool:
        ...

    def isDir(self, path: str) -> bool:
        ...

    def getSize(self, path: str) -> int:
        ...

    # Path operations (FS-specific)
    def joinPath(self, parent: str, name: str) -> str:
        ...

    def relPath(self, path: str, base: str) -> str:
        ...

    def normPath(self, path: str) -> str:
        ...

    def baseName(self, path: str) -> str:
        ...

    def dirName(self, path: str) -> str:
        ...


class LocalFileSystem:
    """
    Local filesystem backend.

    Wraps os.* calls to provide FileSystem interface for local directories.
    """

    def __init__(self, root: str):
        """
        Initialize LocalFileSystem.

        Args:
            root: Absolute or relative path to root directory
        """
        self.root = os.path.abspath(root)

        logger.debug(f"LocalFileSystem initialized: {self.root}")

    def rootName(self) -> str:
        """Get root directory name"""
        return os.path.basename(self.root.rstrip(os.sep)) or "folder"

    @property
    def rootPath(self) -> str:
        """Get root path for walk()"""
        return self.root

    @property
    def rootIsDir(self) -> bool:
        """Check if root is a directory (True) or single file (False)"""
        return os.path.isdir(self.root)

    def walk(self, top: str) -> Iterable[Tuple[str, List[str], List[str]]]:
        """
        Walk directory tree.

        Args:
            top: Directory to walk (typically self.root)

        Yields:
            (dirpath, dirnames, filenames) tuples
        """
        yield from os.walk(top)

    def stat(self, path: str) -> Stat:
        """
        Get file/directory metadata.

        Args:
            path: Absolute path to file or directory

        Returns:
            Stat object with size, mtime, isDir
        """
        # Avoid os.path.isdir() here: it triggers an extra stat() call.
        # On "mounted" / FUSE-like filesystems (WSL2 /mnt, Android shared storage, etc.)
        # that extra syscall cost is huge and can stall the whole app.
        st = os.stat(path)
        isDir = _stat.S_ISDIR(st.st_mode)
        return Stat(size=int(st.st_size), mtime=float(st.st_mtime), isDir=isDir)

    def open(self, path: str) -> BinaryIO:
        """
        Open file for reading.

        Args:
            path: Absolute path to file

        Returns:
            Binary file object
        """
        return open(path, "rb")

    def exists(self, path: str) -> bool:
        """Check if path exists"""
        return os.path.exists(path)

    def isFile(self, path: str) -> bool:
        """Check if path is a file"""
        return os.path.isfile(path)

    def isDir(self, path: str) -> bool:
        """Check if path is a directory"""
        return os.path.isdir(path)

    def getSize(self, path: str) -> int:
        """Get file size"""
        return os.path.getsize(path)

    def joinPath(self, parent: str, name: str) -> str:
        """Join paths using OS-specific separator"""
        return os.path.join(parent, name)

    def relPath(self, path: str, base: str) -> str:
        """Get relative path from base to path"""
        rel = os.path.relpath(path, base)
        return "" if rel == "." else rel

    def normPath(self, path: str) -> str:
        """Normalize path"""
        return os.path.normpath(path)

    def baseName(self, path: str) -> str:
        """Get base name of path"""
        return os.path.basename(path)

    def dirName(self, path: str) -> str:
        """Get directory name of path"""
        return os.path.dirname(path)


class HttpSession:
    """
    HTTP session with single keep-alive connection.

    Reuses one HTTPConnection for all operations (meta/list/stat/file).
    This eliminates TCP handshake overhead.
    """

    def __init__(self, host: str, port: int, timeout: float = 30.0,
                 username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize HTTP session.

        Args:
            host: Server hostname
            port: Server port
            timeout: Socket timeout in seconds
            username: Optional HTTP Basic Auth username
            password: Optional HTTP Basic Auth password
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.username = username
        self.password = password
        self._conn: Optional[HTTPConnection] = None
        self._activeStream = False # Guards against concurrent file streams

    def _getConnection(self) -> HTTPConnection:
        """Get or create connection"""
        if not self._conn:
            logger.debug(f"HTTP connect {self.host}:{self.port}")
            self._conn = HTTPConnection(self.host, self.port, timeout=self.timeout)
        return self._conn

    def _resetConnection(self) -> None:
        """Reset connection after error"""
        if self._conn:
            try:
                self._conn.close()
            except Exception as e:
                logger.debug(f"Error closing connection during reset: {e}")
                
        self._conn = None
        self._activeStream = False

    def _addAuthHeader(self, headers: Dict[str, str]) -> None:
        """Add HTTP Basic Auth header if credentials are configured"""
        if self.username and self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"

    def request(self,
                method: str,
                path: str,
                headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        """
        Send HTTP request and read full response body.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path with query string
            headers: Optional request headers

        Returns:
            Tuple of (status_code, response_headers, body)

        Raises:
            RuntimeError: If request fails after retry
        """
        if self._activeStream:
            raise RuntimeError("Cannot issue request while file stream is active")

        headers = dict(headers or {})
        headers["Connection"] = "keep-alive"
        self._addAuthHeader(headers)

        for attempt in (1, 2):
            try:
                conn = self._getConnection()
                conn.request(method, path, headers=headers)
                response = conn.getresponse()
                body = response.read() # Must drain to reuse connection
                status = response.status
                responseHeaders = {k.lower(): v for k, v in response.getheaders()}
                return (status, responseHeaders, body)

            except (RemoteDisconnected, ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                logger.debug(f"HTTP request failed (attempt {attempt}): {e}")
                self._resetConnection()
                if attempt == 2:
                    raise RuntimeError(f"HTTP request failed: {e}")

        raise RuntimeError("Unreachable code")

    def getJson(self, path: str) -> dict:
        """
        Send GET request and parse JSON response.

        Args:
            path: Request path with query string

        Returns:
            Parsed JSON object

        Raises:
            RuntimeError: If request fails or response is not JSON
        """
        status, _, body = self.request("GET", path, headers={"Accept": "application/json"})
        if status != 200:
            raise RuntimeError(f"HTTP {status} for {path}")

        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise RuntimeError(f"Invalid JSON from {path}: {e}")

    def openStream(self, path: str, headers: Optional[Dict[str, str]] = None):
        """
        Open response stream for file download.

        Args:
            path: Request path with query string
            headers: Optional request headers (e.g., Range)

        Returns:
            Tuple of (response, response_headers)

        Raises:
            RuntimeError: If stream already active or request fails
        """
        if self._activeStream:
            raise RuntimeError("Another file stream is already active")

        headers = dict(headers or {})
        headers["Connection"] = "keep-alive"
        self._addAuthHeader(headers)

        for attempt in (1, 2):
            try:
                conn = self._getConnection()
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                status = response.status
                responseHeaders = {k.lower(): v for k, v in response.getheaders()}

                if status not in (200, 206):
                    # Drain body to keep connection alive
                    try:
                        response.read()
                    except Exception as e:
                        logger.debug(f"Error draining response body: {e}")
                        
                    raise RuntimeError(f"HTTP {status} for {path}")

                self._activeStream = True
                return (response, responseHeaders)

            except (RemoteDisconnected, ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as e:
                logger.debug(f"HTTP openStream failed (attempt {attempt}): {e}")
                self._resetConnection()
                if attempt == 2:
                    raise RuntimeError(f"HTTP openStream failed: {e}")

        raise RuntimeError("Unreachable code")

    def closeStream(self, response) -> None:
        """
        Close response stream.

        Must be called after reading stream to allow connection reuse.

        Args:
            response: Response object from openStream()
        """
        try:
            # Drain any remaining data
            try:
                response.read()
            except Exception as e:
                logger.debug(f"Error draining stream data: {e}")

            try:
                response.close()
            except Exception as e:
                logger.debug(f"Error closing response: {e}")
        finally:
            self._activeStream = False

    def close(self) -> None:
        """Close session and connection"""
        self._resetConnection()


class HttpFile(io.RawIOBase):
    """
    File-like object that reads via HTTP with Range support.

    Uses single keep-alive connection for all Range requests.
    Automatically opens new Range when current chunk exhausted.
    """

    def __init__(self, session: HttpSession, fileId: str, size: int):
        """
        Initialize HTTP file.

        Args:
            session: HTTP session to use
            fileId: File document ID
            size: Total file size
        """
        super().__init__()
        self._session = session
        self._fileId = fileId
        self._size = int(size)
        self._pos = 0
        self._response = None
        self._responseLeft = 0
        self._closed = False

        # Open initial range
        self._openAt(0)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            newPos = offset
        elif whence == io.SEEK_CUR:
            newPos = self._pos + offset
        elif whence == io.SEEK_END:
            newPos = self._size + offset
        else:
            raise ValueError("Invalid whence")

        newPos = max(0, min(self._size, int(newPos)))
        if newPos != self._pos:
            self._openAt(newPos)
        return self._pos

    def _closeResponse(self) -> None:
        """Close current response"""
        if self._response:
            try:
                self._session.closeStream(self._response)
            except Exception as e:
                logger.debug(f"Error closing stream via session: {e}")
                try:
                    self._response.close()
                except Exception as e2:
                    logger.debug(f"Error closing response directly: {e2}")
            self._response = None
            self._responseLeft = 0

    def _openAt(self, pos: int) -> None:
        """Open Range at given position"""
        self._closeResponse()
        self._pos = pos

        if self._pos >= self._size:
            return

        query = urlencode({"id": self._fileId})
        path = f"/file?{query}"

        end = min(self._size - 1, self._pos + HTTP_READ_CHUNK - 1)
        headers = {"Range": f"bytes={self._pos}-{end}"}

        response, responseHeaders = self._session.openStream(path, headers=headers)

        # Get content length
        contentLength = responseHeaders.get("content-length")
        if contentLength:
            self._responseLeft = int(contentLength)
        else:
            self._responseLeft = end - self._pos + 1

        self._response = response

    def readinto(self, b) -> int:
        if self._closed:
            return 0
        if self._pos >= self._size:
            return 0

        want = len(b)
        if want <= 0:
            return 0

        # Open new range if needed
        if not self._response or self._responseLeft <= 0:
            self._openAt(self._pos)
            if not self._response:
                return 0

        # Read from current range
        toRead = min(want, self._responseLeft)
        try:
            data = self._response.read(toRead)
        except TimeoutError:
            raise

        if not data:
            # EOF unexpectedly
            self._closeResponse()
            return 0

        n = len(data)
        b[:n] = data
        self._pos += n
        self._responseLeft -= n

        # Close range if exhausted
        if self._pos >= self._size or self._responseLeft <= 0:
            self._closeResponse()

        return n

    def close(self) -> None:
        if not self._closed:
            self._closeResponse()
            self._closed = True
        super().close()


class _ThreadLocalSession(threading.local):
    """
    Thread-local storage for HttpSession with guaranteed initialization.

    Subclassing threading.local ensures __init__ is called for each thread,
    so 'session' attribute always exists (no hasattr/getattr needed).
    """

    def __init__(self):
        super().__init__()
        self.session = None


class HTTPFileSystem:
    """
    Remote filesystem over HTTP (VFS protocol).

    Key optimizations:
    - ID-based protocol for O(1) operations
    - Client-side caching (path->id, stat cache)
    - Thread-local keep-alive HTTP connections (one per thread)
    - File reads use HTTP Range requests

    Thread Safety:
    - Each thread gets its own HttpSession via _ThreadLocalSession
    - This allows concurrent file downloads from ThreadingHTTPServer
    - Path/stat caches are shared (read-heavy, write-once pattern)
    """

    def __init__(self, vfsUri: str, timeout: float = 30.0):
        """
        Initialize HTTPFileSystem.

        Args:
            vfsUri: vfs://[user:pass@]host:port or http://[user:pass@]host:port URI
            timeout: HTTP socket timeout in seconds

        Authentication priority:
            1. Credentials in URI (vfs://user:pass@host:port)
            2. Environment variables (FFL_VFS_AUTH_USER, FFL_VFS_AUTH_PASSWORD)
            3. If password set but no user, defaults to 'user'
        """
        # Parse URI
        parsed = urlparse(vfsUri if "://" in vfsUri else f"http://{vfsUri}")

        # Convert vfs:// to http:// (preserves user:pass@host:port)
        if parsed.scheme == "vfs":
            parsed = urlparse(f"http://{parsed.netloc}")

        if not parsed.hostname or not parsed.port:
            raise ValueError(f"Invalid vfs URI: {vfsUri}")

        self._host = parsed.hostname
        self._port = parsed.port
        self._timeout = timeout

        # Extract credentials: URI first, then environment variables
        username = parsed.username
        password = parsed.password

        # Fallback to environment variables if not in URI
        if not password:
            password = os.getenv('FFL_VFS_AUTH_PASSWORD')
            if password:
                username = os.getenv('FFL_VFS_AUTH_USER') or 'user'

        self._username = username
        self._password = password

        # Thread-local storage for sessions (one HttpSession per thread)
        self._tls = _ThreadLocalSession()

        # Get metadata from server
        meta = self._session.getJson("/meta")
        if not meta.get("ok"):
            raise RuntimeError(meta.get("error") or "meta request failed")

        self._rootName = meta.get("folderName") or "folder"
        self._rootId = meta.get("rootId")
        if not self._rootId:
            raise RuntimeError("Server did not provide rootId")

        self._rootIsDir = meta.get("rootIsDir", True) # True = directory, False = single file

        # Caches
        self._pathToId: Dict[str, str] = {"/": self._rootId}
        self._statCache: Dict[str, Stat] = {}

        logger.debug(f"HTTPFileSystem connected: {vfsUri} (root: {self._rootName}, isDir: {self._rootIsDir})")

    @property
    def rootIsDir(self) -> bool:
        """Check if root is a directory (True) or single file (False)"""
        return self._rootIsDir

    def rootName(self) -> str:
        """Get root name"""
        return self._rootName

    @property
    def rootPath(self) -> str:
        """Get root path for walk() - always "/" for HTTP"""
        return "/"

    @property
    def _session(self) -> HttpSession:
        """
        Get or create thread-local HttpSession.

        Each thread gets its own HttpSession instance, allowing concurrent
        file downloads without blocking on _activeStream flag.

        Returns:
            HttpSession: Thread-local session instance
        """
        if self._tls.session is None:
            self._tls.session = HttpSession(
                self._host, self._port,
                timeout=self._timeout,
                username=self._username,
                password=self._password
            )
            logger.debug("Created new thread-local HttpSession for thread %s", threading.current_thread().name)
        return self._tls.session

    def exists(self, path: str) -> bool:
        """Check if path exists"""
        try:
            self.stat(path)
            return True
        except FileNotFoundError:
            return False

    def isFile(self, path: str) -> bool:
        """Check if path is a file"""
        try:
            stat = self.stat(path)
            return not stat.isDir
        except FileNotFoundError:
            return False

    def isDir(self, path: str) -> bool:
        """Check if path is a directory"""
        try:
            stat = self.stat(path)
            return stat.isDir
        except FileNotFoundError:
            return False

    def getSize(self, path: str) -> int:
        """Get file size"""
        stat = self.stat(path)
        return stat.size

    def joinPath(self, parent: str, name: str) -> str:
        """Join POSIX paths"""
        parent = self._normPath(parent)
        if parent == "/":
            return "/" + name
        return parent.rstrip("/") + "/" + name

    def relPath(self, path: str, base: str) -> str:
        """Get relative POSIX path from base to path"""
        path = self._normPath(path)
        base = self._normPath(base)

        if path == base:
            return ""

        # Remove base prefix
        if path.startswith(base):
            rel = path[len(base):]
            return rel.lstrip("/")

        # Not under base
        return path.lstrip("/")

    def normPath(self, path: str) -> str:
        """Normalize POSIX path"""
        return self._normPath(path)

    def baseName(self, path: str) -> str:
        """Get base name of POSIX path"""
        path = self._normPath(path)
        return path.rstrip("/").split("/")[-1]

    def dirName(self, path: str) -> str:
        """Get directory name of POSIX path"""
        path = self._normPath(path).rstrip("/")
        if "/" not in path or path == "/":
            return "/"
        return "/".join(path.split("/")[:-1]) or "/"

    def _idForPath(self, path: str) -> str:
        """
        Resolve POSIX path to document ID.

        Args:
            path: POSIX-style path (e.g., "/subdir/file.txt")

        Returns:
            Document ID

        Raises:
            FileNotFoundError: If path does not exist
        """
        path = self._normPath(path)
        if path in self._pathToId:
            return self._pathToId[path]

        # Walk path segments to find ID
        curPath = "/"
        curId = self._pathToId["/"]

        for seg in [s for s in path.strip("/").split("/") if s]:
            # List current directory
            entries = self._listById(curId)
            found = None
            for entry in entries:
                if entry["name"] == seg:
                    found = entry
                    break

            if not found:
                raise FileNotFoundError(path)

            curId = found["id"]
            curPath = self._joinPath(curPath, seg)
            self._pathToId[curPath] = curId

        return curId

    def _listById(self, dirId: str) -> List[dict]:
        """List directory contents by ID"""
        query = urlencode({"id": dirId})
        obj = self._session.getJson(f"/list?{query}")
        if not obj.get("ok"):
            raise RuntimeError(obj.get("error") or "list failed")

        return list(obj.get("entries", []))

    def _statById(self, docId: str) -> Stat:
        """Get file/directory metadata by ID"""
        if docId in self._statCache:
            return self._statCache[docId]

        query = urlencode({"id": docId})
        obj = self._session.getJson(f"/stat?{query}")
        if not obj.get("ok"):
            raise FileNotFoundError(obj.get("error") or "stat failed")

        mtime = obj.get("mtime")
        stat = Stat(
            size=int(obj.get("size") or 0),
            mtime=float(mtime) if mtime is not None else None,
            isDir=bool(obj.get("isDir"))
        )
        self._statCache[docId] = stat

        return stat

    def _normPath(self, path: str) -> str:
        """Normalize POSIX path"""
        path = (path or "/").strip()
        if path == "" or path == ".":
            return "/"

        if not path.startswith("/"):
            path = "/" + path

        # Collapse multiple slashes
        path = "/" + "/".join([x for x in path.split("/") if x])

        return path if path != "" else "/"

    def _joinPath(self, parent: str, name: str) -> str:
        """Join POSIX paths"""
        parent = self._normPath(parent)
        if parent == "/":
            return "/" + name

        return parent.rstrip("/") + "/" + name

    def walk(self, top: str) -> Iterable[Tuple[str, List[str], List[str]]]:
        """
        Walk directory tree (POSIX paths).

        Args:
            top: Root path to walk (typically "/")

        Yields:
            (dirpath, dirnames, filenames) tuples where dirpath is POSIX path
        """
        top = self._normPath(top)
        rootId = self._idForPath(top)

        stack: List[Tuple[str, str]] = [(top, rootId)]

        while stack:
            dirPath, dirId = stack.pop()
            entries = self._listById(dirId)

            dirs = []
            files = []

            for entry in entries:
                childPath = self._joinPath(dirPath, entry["name"])
                self._pathToId[childPath] = entry["id"]

                if entry.get("isDir"):
                    dirs.append(entry["name"])
                    stack.append((childPath, entry["id"]))
                else:
                    files.append(entry["name"])
                    # Seed stat cache from list response
                    mtime = entry.get("mtime")
                    self._statCache[entry["id"]] = Stat(
                        size=int(entry.get("size") or 0),
                        mtime=float(mtime) if mtime is not None else None,
                        isDir=False
                    )

            yield dirPath, dirs, files

    def stat(self, path: str) -> Stat:
        """
        Get file/directory metadata.

        Args:
            path: POSIX-style path

        Returns:
            Stat object
        """
        docId = self._idForPath(path)
        return self._statById(docId)

    def open(self, path: str) -> BinaryIO:
        """
        Open file for reading (with HTTP Range support).

        Args:
            path: POSIX-style path

        Returns:
            Binary file object

        Raises:
            IsADirectoryError: If path is a directory
        """
        fileId = self._idForPath(path)
        stat = self._statById(fileId)

        if stat.isDir:
            raise IsADirectoryError(path)

        # Create HttpFile with Range support (uses thread-local session)
        return io.BufferedReader(
            HttpFile(self._session, fileId, stat.size),
            buffer_size=256 * 1024 # 256 KB buffer
        )
