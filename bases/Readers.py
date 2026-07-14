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

import os
import struct
import zlib
import hashlib
import json
import time
import datetime
import sys
import tempfile
import threading
import uuid

from dataclasses import dataclass, field
from typing import Iterator, Optional, Protocol

from bases.Kernel import getLogger, FFLEvent
from bases.FileSystems import ExcludeFilter, HTTPFileSystem, LocalFileSystem, VirtualFileSystem
from bases.Utils import ONE_MB
from bases.Zip import SegmentIndex, SegmentType, ZipMixin

logger = getLogger(__name__)


@dataclass
class GrowingFileState:
    """
    Shared state for reading a file that is still being written.

    Used by FileSourceReader in follow mode to wait for new data
    instead of stopping at EOF.
    """
    cond: threading.Condition = field(default_factory=threading.Condition)
    written: int = 0
    done: bool = False
    error: Optional[BaseException] = None

    def signalDone(self, error: Optional[BaseException] = None):
        """Signal that writing is complete and notify waiting readers"""
        with self.cond:
            if error is not None:
                self.error = error
            self.done = True
            self.cond.notify_all()

    def signalProgress(self, bytesWritten: int):
        """Signal progress and notify waiting readers"""
        with self.cond:
            self.written += bytesWritten
            self.cond.notify_all()


class FolderChangedException(RuntimeError):
    """Exception raised when folder contents change during transfer"""

    def __init__(self, message: str, filePath: str = None):
        super().__init__(message)
        self.filePath = filePath


class StdinHandoffTakenOver(RuntimeError):
    """Raised when stdin streaming ownership moves from WebRTC to HTTP fallback."""


class StdinHandoffWindow:
    """
    Bounded in-memory replay window for stdin handoff.

    This is intentionally not a general cache:
    - no disk I/O
    - no multi-download replay
    - only enough buffered history to bridge a WebRTC -> HTTP handoff
    """

    def __init__(self, maxBytes: int):
        self.maxBytes = max(0, int(maxBytes))
        self._buffer = bytearray()
        self.startOffset = 0
        self.endOffset = 0

    def append(self, chunk: bytes):
        if not self.maxBytes or not chunk:
            self.endOffset += len(chunk)
            self.startOffset = self.endOffset
            return

        self._buffer.extend(chunk)
        self.endOffset += len(chunk)

        overflow = len(self._buffer) - self.maxBytes
        if overflow > 0:
            del self._buffer[:overflow]
            self.startOffset += overflow

    def canResumeFrom(self, start: int) -> bool:
        return self.startOffset <= start <= self.endOffset

    def read(self, start: int, maxLength: int) -> bytes:
        if not self.canResumeFrom(start):
            raise RuntimeError(
                f"Requested resume offset {start} is outside stdin handoff window "
                f"[{self.startOffset}, {self.endOffset}]"
            )

        length = min(maxLength, self.endOffset - start)
        if length <= 0:
            return b''

        relativeStart = start - self.startOffset
        relativeEnd = relativeStart + length
        return bytes(self._buffer[relativeStart:relativeEnd])


class SourceReaderProgressReporter(Protocol):
    """Generic progress callback interface for reader-side work."""

    def start(self, operation: str, total: Optional[int] = None, unit: str = "items") -> None:
        ...

    def advance(self, amount: int = 1, processedBytes: Optional[int] = None) -> None:
        ...

    def finish(self) -> None:
        ...


class CachingMixin:
    """
    Mixin class for caching stream data to temp file

    Provides functionality to:
    - Stream data to client immediately
    - Simultaneously cache to temp file for subsequent reads
    - Allow multiple reads if caching succeeds
    - Gracefully handle caching failures
    - Automatic cleanup on application shutdown via event system
    """

    # Class-level registry to track all instances for cleanup
    _instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cachedFile = None # Path to cached temp file
        self._cacheSuccess = False # Whether caching succeeded
        self._cacheTempFile = None # File object for writing cache
        self._cacheEnabled = True # Can be disabled if disk space issues
        self._growState: Optional[GrowingFileState] = None # Shared state for follow mode

        # Register this instance for shutdown cleanup
        CachingMixin._instances.append(self)

        # Subscribe to shutdown event - subscribe() is idempotent (skips if already connected)
        FFLEvent.applicationShutdown.subscribe(CachingMixin._cleanupAllInstances)

    @classmethod
    def _cleanupAllInstances(cls, **kwargs):
        """
        Class method to cleanup all cached files from all instances

        Called by the shutdown event to ensure all temp files are removed

        Args:
            **kwargs: Event system passes context and other parameters
        """
        logger.debug("[CachingMixin] Cleaning up %s cached file(s)", len(cls._instances))

        for instance in cls._instances:
            try:
                instance._cleanupCacheFile()
            except Exception as e:
                logger.debug("[CachingMixin] Error cleaning up cache: %s", e)

        # Clear the instances list
        cls._instances.clear()

    def _createTempFile(self, prefix: str = 'cache_', suffix: str = '.bin') -> Optional[object]:
        """
        Create a temporary file for caching data

        Args:
            prefix: Filename prefix for temp file
            suffix: Filename suffix for temp file

        Returns:
            File object or None if creation fails
        """
        try:
            # Create temp file that will be auto-deleted when closed
            tempFile = tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix=prefix, suffix=suffix)
            self._cachedFile = tempFile.name
            logger.debug("[%s] Created temp cache file: %s", self.__class__.__name__, self._cachedFile)
            return tempFile
        except (OSError, IOError) as e:
            logger.debug("[%s] Failed to create temp file for caching: %s", self.__class__.__name__, e)
            return None

    def _closeTempFile(self, tempFile):
        """Close temp file with error handling (fail silently)"""
        if tempFile:
            try:
                tempFile.close()
            except Exception as e:
                logger.debug("[%s] Unable to close cached file: %s", self.__class__.__name__, e)

    def _cleanupCacheFile(self):
        """Clean up cached temp file (fail silently)

        Also signals growState.done to wake up any waiting follow mode readers.
        """
        # Signal done BEFORE cleanup to wake up any waiting readers
        if self._growState:
            self._growState.signalDone()

        if self._cachedFile and os.path.exists(self._cachedFile):
            try:
                os.unlink(self._cachedFile)
                logger.debug("[%s] Cleaned up cache file: %s", self.__class__.__name__, self._cachedFile)
            except Exception as e:
                logger.debug("[%s] Unable to delete cached file: %s", self.__class__.__name__, e)
            finally:
                self._cachedFile = None

    def _hasCache(self) -> bool:
        """Check if cache is complete and available for reading"""
        return self._cacheSuccess and self._cachedFile and os.path.exists(self._cachedFile)

    def _hasCacheInProgress(self) -> bool:
        """Check if cache is being written (can read in follow mode)"""
        return (
            self._growState is not None and not self._growState.done and self._cachedFile and
            os.path.exists(self._cachedFile)
        )

    def _startCaching(self, prefix: str = 'cache_', suffix: str = '.bin') -> bool:
        """
        Start caching process by creating temp file

        Args:
            prefix: Filename prefix for temp file
            suffix: Filename suffix for temp file

        Returns:
            bool: True if caching started successfully, False otherwise
        """
        if not self._cacheEnabled:
            return False

        self._cacheTempFile = self._createTempFile(prefix, suffix)
        if self._cacheTempFile is not None:
            # Initialize grow state for follow mode readers
            self._growState = GrowingFileState()
            return True

        return False

    def _cacheChunk(self, chunk: bytes) -> bool:
        """
        Cache a chunk of data to temp file

        Args:
            chunk: Data chunk to cache

        Returns:
            bool: True if caching succeeded, False if caching failed
        """
        if not self._cacheTempFile:
            return False

        try:
            self._cacheTempFile.write(chunk)
            self._cacheTempFile.flush() # Flush so readers can see data immediately

            # Notify waiting readers of new data
            if self._growState:
                self._growState.signalProgress(len(chunk))

            return True
        except (OSError, IOError) as e:
            # Caching failed - notify readers and clean up
            logger.debug("[%s] Cache write failed: %s", self.__class__.__name__, e)
            if self._growState:
                self._growState.signalDone(error=e)

            self._closeTempFile(self._cacheTempFile)
            self._cleanupCacheFile()
            self._cacheTempFile = None
            return False

    def _finalizeCache(self) -> bool:
        """
        Finalize caching after all data has been written

        Returns:
            bool: True if caching finalized successfully, False otherwise
        """
        if not self._cacheTempFile:
            return False

        try:
            # Notify readers that writing is complete
            if self._growState:
                self._growState.signalDone()

            self._closeTempFile(self._cacheTempFile)
            self._cacheSuccess = True

            logger.debug("[%s] Successfully finalized cache: %s", self.__class__.__name__, self._cachedFile)
            return True
        except (OSError, IOError) as e:
            logger.debug("[%s] Failed to finalize cache: %s", self.__class__.__name__, e)

            # Notify readers of error
            if self._growState:
                self._growState.signalDone(error=e)

            self._cleanupCacheFile()
            return False
        finally:
            self._cacheTempFile = None

    def _readFromCache(self, chunkSize: int, start: int = 0) -> Iterator[bytes]:
        """
        Read from cached temp file

        Supports reading from a file that is still being written (follow mode).
        When cache is in progress, readers will wait for new data instead of
        stopping at EOF.

        Args:
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset

        Yields:
            bytes: Content chunks from cached file
        """
        reader = None

        # Determine if we should use follow mode
        if self._hasCacheInProgress():
            # Cache still being written - use follow mode
            reader = FileSourceReader(self._cachedFile, follow=True, growState=self._growState)
        elif self._hasCache():
            # Cache complete - normal mode
            reader = FileSourceReader(self._cachedFile)
        else:
            raise RuntimeError("Cache is not available")

        yield from reader.iterChunks(chunkSize, start)

    def __del__(self):
        """
        Clean up temp file when object is destroyed (fallback)

        Note: Primary cleanup is via applicationShutdown event (more reliable).
        This __del__ serves as a fallback for edge cases.
        """
        self._cleanupCacheFile()


class SourceReader:
    """Unified reading interface for files and folders (as ZIP streams)"""
    contentName: str # Display/download filename (e.g., file.bin / folder.zip)
    contentType: str # MIME type
    size: Optional[int] # Total content length (None if unknown)
    supportsRange: bool # Whether offset/Range resume is supported (for downloads)
    supportsUploadResume: bool # Whether upload resume is supported

    def __init__(self, path: str, fileName=None):
        """
        Initialize SourceReader with path and fileName handling

        Args:
            path: File/directory path, or "-" for stdin
            fileName: Custom filename (string), callable that returns filename, or None for default
        """
        self.path = path

        # Use default method if fileName not provided
        if fileName is None:
            fileName = self._getDefaultFileName

        # Handle fileName: callable or string
        if callable(fileName):
            self.contentName = fileName() # Call once to get deterministic name
        else:
            self.contentName = fileName

    def _getDefaultFileName(self):
        """Get default filename - subclasses should override this"""
        raise NotImplementedError

    @property
    def file(self) -> str:
        """File name for server identification (default: returns contentName)"""
        return self.contentName

    @property
    def directory(self) -> str:
        """Directory path for server identification"""
        raise NotImplementedError

    @property
    def consumed(self) -> bool:
        """Whether the reader has been consumed and cannot be read again"""
        raise NotImplementedError

    @property
    def supportManifest(self) -> bool:
        """Whether this reader supports /zip/manifest endpoint"""
        return False

    @property
    def supportFileAccess(self) -> bool:
        """Whether this reader supports /zip/file endpoint"""
        return False

    @classmethod
    def build(
        cls, path, fileName: str = None, compression: str = None, excludeFilter: ExcludeFilter = None,
        progressReporter: Optional[SourceReaderProgressReporter] = None, stdinCache: bool = True
    ) -> 'SourceReader':
        """
        Factory method to create appropriate SourceReader.

        Args:
            path: One of:
                  - str: single file/folder path, "-" for stdin, or "vfs://" URI
                  - list[str]: multiple file/folder paths → packaged as VirtualFileSystem ZIP
            fileName: Custom download filename
            compression: "store" or "deflate" (default: READER_FOLDER_COMPRESSION env var → "store")
            excludeFilter: Optional filter to exclude files/dirs by name during walk
            progressReporter: Optional progress reporter for reader-side preprocessing
            stdinCache: If False, disable stdin caching (only applies when path == "-")

        Returns:
            SourceReader: Appropriate reader for the path type
        """
        # Handle stdin
        if path == "-":
            return StdinSourceReader(path, fileName=fileName, stdinCache=stdinCache)

        # Determine FileSystem
        flatRoot = False

        if isinstance(path, list):
            if not path:
                raise ValueError("Path list is empty")

            fileSystem = VirtualFileSystem(path, rootName="archive", excludeFilter=excludeFilter)
            flatRoot = True
        elif path.startswith("vfs://"):
            fileSystem = HTTPFileSystem(path, excludeFilter=excludeFilter)
        else:
            fileSystem = LocalFileSystem(path, excludeFilter=excludeFilter)

        # Use FileSystem to determine file vs directory
        if fileSystem.rootIsDir:
            # Directory: create ZIP
            if compression is None:
                compression = os.getenv('READER_FOLDER_COMPRESSION', 'store')
            return ZipDirSourceReader(
                fileSystem.rootPath, fileName=fileName, compression=compression, fileSystem=fileSystem, flatRoot=flatRoot,
                progressReporter=progressReporter
            )

        # Single file
        return FileSourceReader(fileSystem.rootPath, fileName=fileName, fileSystem=fileSystem)

    def iterChunks(self, chunkSize: int, start: int = 0) -> Iterator[bytes]:
        """
        Iterate over content in chunks

        Args:
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset (0 for new transfer)

        Yields:
            bytes: Content chunks

        Raises:
            RuntimeError: If start > 0 and supportsRange is False
        """
        raise NotImplementedError

    def canResumeFrom(self, start: int) -> bool:
        """
        Return whether this reader can continue a download from byte offset ``start``.

        Default behavior follows regular Range-capable readers.
        Special readers such as stdin can override this to expose bounded handoff support
        without advertising general multi-read capability.
        """
        return self.supportsRange and start >= 0

    def validateIntegrity(
        self, storedSize: int, storedMtime: float, storedHash: str = None, raiseOnError: bool = False
    ) -> bool:
        """
        Validate that content hasn't changed since the stored metadata was captured

        Args:
            storedSize: Previously stored size
            storedMtime: Previously stored modification time
            storedHash: Previously stored hash (optional, for folders)
            raiseOnError: If True, raise exception on validation failure instead of returning False

        Returns:
            bool: True if content is unchanged, False otherwise

        Raises:
            FolderChangedException: If raiseOnError=True and validation fails (for folders)
            RuntimeError: If raiseOnError=True and validation fails (for files)
        """
        raise NotImplementedError

    def getMetadataHash(self) -> Optional[str]:
        """
        Get metadata hash for content validation

        Returns:
            str: Hash string (filename+size+mtime for files, folder structure for folders)
                 None if content doesn't exist or can't be hashed
        """
        raise NotImplementedError

    def getManifestEntry(self, fileName: str) -> dict:
        """
        Get manifest entry by fileName
        Only available for readers with supportFileAccess=True

        Args:
            fileName: Name of the file to get entry for

        Returns:
            dict: Entry dict with metadata

        Raises:
            NotImplementedError: If supportFileAccess is False
            FileNotFoundError: If fileName doesn't exist
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support file access")

    def iterFileChunks(self, fileName: str, chunkSize: int, start: int = 0, end: int = None):
        """
        Iterate over chunks of a specific file within the content
        Only available for readers with supportFileAccess=True

        Args:
            fileName: Name of the file to extract
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset within the file (default: 0)
            end: Ending byte offset within the file (inclusive, default: end of file)

        Yields:
            bytes: Chunks of the requested file

        Raises:
            NotImplementedError: If supportFileAccess is False
            FileNotFoundError: If fileName doesn't exist in the content
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support file access")


class FileSourceReader(SourceReader):
    """SourceReader implementation for regular files"""

    def _getDefaultFileName(self):
        """Get default filename from filesystem root name"""
        return self.fileSystem.rootName()

    # Default timeout for waiting on growing file data (seconds)
    FOLLOW_WAIT_TIMEOUT = 30.0
    # Total timeout for follow mode (prevents hanging forever if writer never finishes)
    FOLLOW_TOTAL_TIMEOUT = 300.0 # 5 minutes max

    def __init__(
        self,
        path: str,
        fileName=None,
        fileSystem=None,
        follow: bool = False,
        growState: Optional[GrowingFileState] = None
    ):
        """
        Initialize FileSourceReader

        Args:
            path: File path (FS-specific)
            fileName: Custom filename (string), callable that returns filename, or None for default
            fileSystem: FileSystem instance (default: LocalFileSystem)
            follow: If True, wait for more data at EOF instead of stopping (for growing files)
            growState: Shared state from writer (required if follow=True)
        """
        if fileSystem is None:
            fileSystem = LocalFileSystem(os.path.dirname(path) or ".")

        self.fileSystem = fileSystem

        if not self.fileSystem.isFile(path):
            raise ValueError(f"Not a file: {path}")

        super().__init__(path, fileName)
        self.contentType = "application/octet-stream"
        self.size = self.fileSystem.getSize(path)
        self.supportsRange = True
        self.supportsUploadResume = True

        # Follow mode for reading files that are still being written
        self._follow = follow
        self._growState = growState

    @property
    def directory(self) -> str:
        """Directory path for server identification"""
        return self.fileSystem.dirName(self.path)

    @property
    def consumed(self) -> bool:
        """Files can be read multiple times"""
        return False

    def _waitUntilAvailable(self, offset: int):
        """
        Wait until growState.written >= offset (follow mode only)

        Args:
            offset: Byte offset to wait for

        Raises:
            RuntimeError: If writer failed with error
            TimeoutError: If total timeout exceeded waiting for data
        """
        deadline = time.time() + self.FOLLOW_TOTAL_TIMEOUT

        with self._growState.cond:
            while True:
                if self._growState.error is not None:
                    raise RuntimeError(f"Cache writing failed: {self._growState.error}") from self._growState.error

                if self._growState.written >= offset:
                    return

                if self._growState.done:
                    # Writer finished but didn't reach offset - client requested beyond actual size
                    return

                # Check total timeout
                if time.time() > deadline:
                    raise TimeoutError(
                        f"Follow mode timeout: waited {self.FOLLOW_TOTAL_TIMEOUT}s for offset {offset}, "
                        f"only {self._growState.written} bytes available"
                    )

                self._growState.cond.wait(timeout=self.FOLLOW_WAIT_TIMEOUT)

    def iterChunks(self, chunkSize: int, start: int = 0) -> Iterator[bytes]:
        """
        Iterate over file chunks

        In follow mode, waits for new data at EOF instead of stopping.
        This allows reading from a file that is still being written.

        Args:
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset

        Yields:
            bytes: File content chunks
        """
        # Follow mode: use direct file open to support growing files
        if self._follow and self._growState is not None:
            # Wait until start offset is available
            if start > 0:
                self._waitUntilAvailable(start)

            deadline = time.time() + self.FOLLOW_TOTAL_TIMEOUT

            with open(self.path, 'rb') as f:
                if start > 0:
                    f.seek(start)

                while True:
                    chunk = f.read(chunkSize)
                    if chunk:
                        # Reset deadline on successful read (writer is making progress)
                        deadline = time.time() + self.FOLLOW_TOTAL_TIMEOUT
                        yield chunk
                        continue

                    # EOF - check if we should wait for more data
                    with self._growState.cond:
                        if self._growState.error is not None:
                            raise RuntimeError(
                                f"Cache writing failed: {self._growState.error}"
                            ) from self._growState.error

                        pos = f.tell()
                        # Writer done and we've read everything - real EOF
                        if self._growState.done and pos >= self._growState.written:
                            break

                        # Check total timeout
                        if time.time() > deadline:
                            raise TimeoutError(
                                f"Follow mode timeout: no new data for {self.FOLLOW_TOTAL_TIMEOUT}s, "
                                f"read {pos} bytes, written {self._growState.written} bytes"
                            )

                        # Wait for more data
                        self._growState.cond.wait(timeout=self.FOLLOW_WAIT_TIMEOUT)
                        # Loop back to read again
        else:
            # Normal mode: use filesystem abstraction
            with self.fileSystem.open(self.path) as f:
                if start > 0:
                    f.seek(start)

                while True:
                    chunk = f.read(chunkSize)
                    if not chunk:
                        break
                    yield chunk

    def getMetadataHash(self) -> Optional[str]:
        """Get metadata hash for file validation (filename + size + mtime)"""
        if not self.fileSystem.exists(self.path):
            return None

        stat = self.fileSystem.stat(self.path)

        # Create hash from filename + size + mtime
        hasher = hashlib.sha256()
        hasher.update(self.fileSystem.baseName(self.path).encode('utf-8'))
        hasher.update(struct.pack('Q', stat.size)) # 8-byte unsigned
        mtimeNs = int((stat.mtime or 0) * 1_000_000_000)
        hasher.update(struct.pack('q', mtimeNs)) # 8-byte signed

        return hasher.hexdigest()

    def validateIntegrity(
        self, storedSize: int, storedMtime: float, storedHash: str = None, raiseOnError: bool = False
    ) -> bool:
        """
        Validate file hasn't changed

        Returns:
            bool: True if unchanged, False if changed (when raiseOnError=False)
        """
        if not self.fileSystem.exists(self.path):
            if raiseOnError:
                raise RuntimeError(f"File no longer exists: {self.path}")
            return False

        # Use hash if provided, otherwise fall back to size/mtime check
        if storedHash:
            currentHash = self.getMetadataHash()
            if currentHash != storedHash:
                if raiseOnError:
                    raise RuntimeError(f"File modified: {self.path}")
                return False
        else:
            stat = self.fileSystem.stat(self.path)

            if stat.size != storedSize:
                if raiseOnError:
                    raise RuntimeError(f"File size changed: {self.path}")
                return False

            if stat.mtime != storedMtime:
                if raiseOnError:
                    raise RuntimeError(f"File modified: {self.path}")
                return False

        return True


class StdinSourceReader(CachingMixin, SourceReader):
    """
    SourceReader implementation for stdin streaming

    Characteristics:
    - First read streams directly from stdin (no delay)
    - Simultaneously caches data to temp file for subsequent reads (via CachingMixin)
    - If caching succeeds, allows multiple reads
    - If caching fails, falls back to single-use behavior
    - No Range/resume support for direct stdin
    - Cached file supports Range/resume

    Usage: python FFL.py --cli -
    """

    def _getDefaultFileName(self):
        """Generate default stdin filename with timestamp to avoid conflicts"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"stdin-{timestamp}.bin"

    def __init__(self, path: str, fileName=None, stdinCache=True):
        """
        Initialize StdinSourceReader

        Args:
            path: Path (should be "-" for stdin)
            fileName: Custom filename (string), callable that returns filename, or None for default
            stdinCache: If False, disable caching; a second read will raise RuntimeError
        """
        super().__init__(path, fileName) # CachingMixin -> SourceReader
        if not stdinCache:
            self._cacheEnabled = False
            
        self.stdin = sys.stdin.buffer # Binary mode for file data
        self.contentType = "application/octet-stream"
        self.size = None # Unknown size for streaming input
        self.supportsRange = False # stdin is not seekable (direct stream)
        self.supportsUploadResume = False # Cannot resume stdin
        self._consumed = False # Track if stdin has been consumed
        self._streamCond = threading.Condition()
        self._streamOwner = None
        self._streamOffset = 0
        self._streamEOF = False
        self._streamError = None
        self._streamOwnerCounter = 0
        self._handoffEnabled = not stdinCache
        
        handoffWindowMB = int(os.getenv('READER_STDIN_HANDOFF_WINDOW_MB', '32'))
        self._handoffWindow = StdinHandoffWindow(int(handoffWindowMB * ONE_MB)) if self._handoffEnabled else None

    @property
    def directory(self) -> str:
        """Directory path for server identification"""
        return ""

    @property
    def consumed(self) -> bool:
        """Check if stdin has been consumed and no cache available"""
        # Not consumed if cache is complete or still being written
        return self._consumed and not self._hasCache() and not self._hasCacheInProgress()

    def canResumeFrom(self, start: int) -> bool:
        if start < 0:
            return False

        if self._hasCache() or self._hasCacheInProgress():
            return True

        if not self._handoffWindow:
            return False

        with self._streamCond:
            return self._handoffWindow.canResumeFrom(start)

    def _nextStreamOwnerId(self) -> int:
        with self._streamCond:
            self._streamOwnerCounter += 1
            return self._streamOwnerCounter

    def _claimStreamOwner(self, ownerId: int):
        with self._streamCond:
            self._streamOwner = ownerId
            self._streamCond.notify_all()

    def _assertStreamOwner(self, ownerId: int):
        with self._streamCond:
            if self._streamOwner != ownerId:
                raise StdinHandoffTakenOver("stdin stream ownership was transferred to HTTP fallback")

    def _recordStreamChunk(self, chunk: bytes):
        with self._streamCond:
            self._streamOffset += len(chunk)
            if self._handoffWindow:
                self._handoffWindow.append(chunk)
                
            self._streamCond.notify_all()

    def _markStreamEOF(self):
        with self._streamCond:
            self._streamEOF = True
            self.size = self._streamOffset
            self._streamCond.notify_all()

    def _iterHandoffChunks(self, chunkSize: int, start: int) -> Iterator[bytes]:
        ownerId = self._nextStreamOwnerId()
        self._claimStreamOwner(ownerId)
        logger.info("[StdinSourceReader] Stdin handoff resume from offset %s", start)

        cursor = start
        read = self.stdin.read1 if hasattr(self.stdin, 'read1') else self.stdin.read

        while True:
            chunk = None
            shouldReadFromStdin = False

            with self._streamCond:
                if self._streamError is not None:
                    raise self._streamError

                if not self._handoffWindow or not self._handoffWindow.canResumeFrom(cursor):
                    raise RuntimeError(
                        f"stdin handoff window no longer covers offset {cursor}; "
                        f"available range is [{self._handoffWindow.startOffset if self._handoffWindow else 0}, "
                        f"{self._handoffWindow.endOffset if self._handoffWindow else 0}]"
                    )

                if cursor < self._streamOffset:
                    chunk = self._handoffWindow.read(cursor, chunkSize)
                    cursor += len(chunk)
                elif self._streamEOF:
                    break
                else:
                    shouldReadFromStdin = True

            if chunk:
                yield chunk
                continue

            if not shouldReadFromStdin:
                continue

            self._assertStreamOwner(ownerId)
            data = read(chunkSize)
            self._assertStreamOwner(ownerId)
            if not data:
                self._markStreamEOF()
                break

            self._recordStreamChunk(data)
            cursor += len(data)
            yield data

    def iterChunks(self, chunkSize: int, start: int = 0) -> Iterator[bytes]:
        """
        Iterate over stdin chunks

        First read: Streams directly from stdin while caching to temp file
        Subsequent reads: Use cached file if available (supports follow mode for in-progress cache)

        Args:
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset (0 for direct stdin, >0 for cached file)

        Yields:
            bytes: Content chunks

        Raises:
            RuntimeError: If start > 0 but no cached file available
            RuntimeError: If stdin consumed and no cache available
        """
        if self._consumed and start > 0 and self._handoffWindow and self.canResumeFrom(start):
            yield from self._iterHandoffChunks(chunkSize, start)
            return

        # Second+ read: Use cached file if available (complete or in-progress)
        if self._consumed:
            if self._hasCache() or self._hasCacheInProgress():
                logger.debug(
                    "[StdinSourceReader] Reading from cached file: %s (in_progress=%s)", self._cachedFile,
                    self._hasCacheInProgress()
                )
                yield from self._readFromCache(chunkSize, start)
                return
            else:
                # Known gap (not fixed): if WebRTC opened the data channel and read at least one
                # stdin chunk (_consumed=True) but the client received 0 bytes before the drop,
                # HTTP fallback arrives here with start=0 and no cache (--stdin-cache off).
                # The `start > 0` guard above intentionally skips _iterHandoffChunks for start=0,
                # so we fall through and raise.  In practice this requires the connection to die
                # in the narrow window between the server's first executor read and the client's
                # first onMessage — extremely unlikely over a reliable TCP tunnel, and no current
                # test exercises this path.
                raise RuntimeError("Stdin has already been consumed and caching failed")

        # First read: Stream from stdin with simultaneous caching
        if start > 0:
            raise RuntimeError("Stdin does not support Range/offset resume (not seekable)")

        self._consumed = True
        ownerId = self._nextStreamOwnerId()
        self._claimStreamOwner(ownerId)

        logger.debug("[StdinSourceReader] Starting to read stdin with chunkSize=%s", chunkSize)
        totalRead = 0

        # Start caching (may fail silently)
        self._startCaching(prefix='stdin_cache_', suffix='.bin')

        # Use read1 for realtime streaming, but read1 might not exist if stdin is io.TextIOWrapper
        read = self.stdin.read1 if hasattr(self.stdin, 'read1') else self.stdin.read
        try:
            while True:
                self._assertStreamOwner(ownerId)
                chunk = read(chunkSize)
                if not chunk:
                    logger.debug("[StdinSourceReader] EOF reached, total read: %s bytes", totalRead)
                    break

                totalRead += len(chunk)
                logger.debug("[StdinSourceReader] Read chunk: %s bytes, total: %s", len(chunk), totalRead)

                # Cache chunk (fail silently via mixin)
                self._cacheChunk(chunk)
                self._recordStreamChunk(chunk)

                # Stream chunk to client immediately
                yield chunk

            logger.debug("[StdinSourceReader] Finished reading %s bytes from stdin", totalRead)
            self._markStreamEOF()

            # Finalize caching if successful
            if self._finalizeCache():
                self.size = totalRead # Now we know the size
                logger.debug("[StdinSourceReader] Successfully cached %s bytes", totalRead)

        except Exception as e:
            # Clean up temp file on error (mixin handles cleanup in __del__)
            with self._streamCond:
                self._streamError = e
                self._streamCond.notify_all()
                
            self._cleanupCacheFile()
            raise

    def getMetadataHash(self) -> Optional[str]:
        """
        Get metadata hash for stdin (not supported)

        Returns:
            None: stdin has no stable metadata
        """
        return None

    def validateIntegrity(
        self, storedSize: int, storedMtime: float, storedHash: str = None, raiseOnError: bool = False
    ) -> bool:
        """
        Validate stdin integrity (not supported)

        Returns:
            bool: Always True (cannot validate stdin)
        """
        return True


class ZipDirSourceReader(CachingMixin, ZipMixin, SourceReader):
    """
    SourceReader implementation for directories (streams as ZIP file)

    Supports two modes:
    - store: No compression, exact Content-Length known, Windows-friendly
    - deflate: Compression, size unknown (requires HTTP chunked), smaller files,
              caches output for subsequent reads (via CachingMixin)

    Notes:
    - Does not support Range/offset resume for directories
    - Filename encoding: UTF-8
    - Symlinks stored as regular files (target content)
    """

    # Class-level cache for scan results (keyed by absolute path)
    _scanCache = {}

    @classmethod
    def clearCache(cls, path: str = None):
        """
        Clear the scan cache

        Args:
            path: Optional specific path to clear. If None, clears entire cache.
        """
        if path is None:
            cls._scanCache.clear()
            logger.debug("Cleared entire ZipDirSourceReader scan cache")
        else:
            absPath = os.path.abspath(path)
            if absPath in cls._scanCache:
                del cls._scanCache[absPath]
                logger.debug("Cleared scan cache for %s", absPath)

    @classmethod
    def getCacheStats(cls):
        """
        Get cache statistics

        Returns:
            dict: Cache statistics including size and paths
        """
        return {'size': len(cls._scanCache), 'paths': list(cls._scanCache.keys())}

    def _getDefaultFileName(self):
        """Get default filename (foldername.zip)"""
        # Get folder name from path
        folder = self.fileSystem.rootName()
        # Fallback to 'archive' if folder name is empty or invalid
        if not folder or folder in ('.', '..'):
            folder = 'archive'
        return f"{folder}.zip"

    def __init__(
        self, path: str, fileName=None, compression: str = "store", strictMode: bool = None, fileSystem=None,
        flatRoot: bool = False, progressReporter: Optional[SourceReaderProgressReporter] = None
    ):
        """
        Initialize ZIP directory reader

        Args:
            path: Path to directory (FS-specific)
            fileName: Custom download filename (string), callable that returns filename, or None for default
            compression: "store" (no compression) or "deflate" (compressed)
            strictMode: If True, abort on file size/mtime changes during streaming.
                       If None, defaults to True for store mode, False for deflate mode.
            fileSystem: FileSystem instance (default: LocalFileSystem)
            flatRoot: If True, entries are placed at ZIP root (no root folder prefix).
                      Use for multi-file archives where a synthetic root name is meaningless.
            progressReporter: Optional progress reporter for directory scanning/preprocessing
        """
        if fileSystem is None:
            fileSystem = LocalFileSystem(path)

        self.fileSystem = fileSystem

        if not self.fileSystem.isDir(path):
            raise ValueError(f"Not a directory: {path}")

        if compression not in ("store", "deflate"):
            raise ValueError(f"Invalid compression: {compression}")

        self.compression = compression

        # Default strict mode: True for store (needs exact size), False for deflate
        if strictMode is None:
            self.strictMode = (compression == "store")
        else:
            self.strictMode = strictMode

        self.flatRoot = flatRoot
        self._progressReporter = progressReporter

        super().__init__(path, fileName) # CachingMixin -> SourceReader
        self.path = self.fileSystem.normPath(self.path) # Normalize path

        # Ensure folder downloads always have .zip extension
        if not self.contentName.endswith('.zip'):
            # Check if it has any extension
            _, ext = os.path.splitext(self.contentName)
            if ext:
                # Has a non-zip extension - append .zip (e.g., abc.jpg -> abc.jpg.zip)
                self.contentName = f"{self.contentName}.zip"
            else:
                # No extension - add .zip (e.g., myarchive -> myarchive.zip)
                self.contentName = f"{self.contentName}.zip"

        self.contentType = "application/zip"
        self.supportsUploadResume = (compression == "store") # Only store mode supports upload resume
        self.supportsRange = False # Will be set to True for store mode after index is built
        self._segmentIndex = None # For store mode cold-start resume (-2.5)
        self._entries = None
        self._needsZip64 = False
        self.size = None
        self._metadataHash = None # Deterministic folder snapshot fingerprint (store mode)

        # --- Store-mode CRC sidecar manifest (for faster resume at Central Directory) ---
        # Purpose: allow resume that starts in CENTRAL_DIR/EOCD to avoid re-reading all files just to compute CRC.
        # IMPORTANT: manifest MUST NOT be written inside the folder, otherwise folder metadata hash changes.
        self._crcManifestEnabled = (os.getenv('READER_STORE_CRC_MANIFEST', '1') not in ('0', 'false', 'False'))
        self._crcManifestPath = None
        self._crcMap = {} # {arcname(str): crc32(int)}
        self._crcDirty = False
        self._crcUpdateCount = 0
        self._crcLastFlush = 0.0
        self._crcFlushEvery = int(os.getenv('READER_CRC_MANIFEST_FLUSH_EVERY', '50'))
        self._crcFlushIntervalSec = float(os.getenv('READER_CRC_MANIFEST_FLUSH_INTERVAL', '2.0'))

        if compression == "store":
            # Build SegmentIndex for cold-start resume capability (-2.5)
            # IMPORTANT: Layout must be deterministic across restarts, otherwise resume offsets break
            cacheKey = self.path
            rawEntries = self._scanDirectory()
            currentHash = SegmentIndex.computeMetadataHash(rawEntries)

            segmentIndex = self._scanCache.get(cacheKey)
            if segmentIndex and segmentIndex.metadataHash == currentHash:
                logger.debug("Using cached SegmentIndex for %s (metadata hash matched)", self.path)
            else:
                logger.debug("Building SegmentIndex for %s (no cache or metadata hash changed)", self.path)
                segmentIndex = SegmentIndex.build(
                    rawEntries,
                    makeLocalFileHeaderLength=self._calculateLocalFileHeaderLength,
                    makeDataDescriptorLength=self._calculateDataDescriptorLength,
                    makeCentralDirHeaderLength=self._calculateCentralDirHeaderLength,
                    makeZip64Lengths=self._calculateZip64Lengths
                )
                self._scanCache[cacheKey] = segmentIndex

            self._segmentIndex = segmentIndex
            self._entries = segmentIndex.entries
            self._metadataHash = segmentIndex.metadataHash

            # Initialize / load CRC manifest for faster resume (store mode only)
            if self._crcManifestEnabled:
                self._crcManifestPath = self._getCRCManifestPath()
                self._loadCRCManifest()
                self._applyCRCMapToEntries()

            self.size = segmentIndex.totalSize
            self.supportsRange = True # Store mode with index supports Range resume

            # Determine if Zip64 is needed
            self._needsZip64 = (
                self._hasAnyLargeFiles(self._entries) or
                self._exceedsEntryCountLimit(len(self._entries)) or
                self._exceedsZip64Limit(segmentIndex.centralDirSize)
            ) # yapf: disable
        else:
            # Deflate mode - no index, size unknown
            self._segmentIndex = None
            self._entries = None
            self._needsZip64 = False
            self.size = None
            self.supportsRange = False

    @property
    def file(self) -> str:
        """File name for server identification (directory base name)"""
        return os.path.basename(self.path)

    @property
    def directory(self) -> str:
        """Directory path for server identification (parent of shared directory)"""
        dirPath = os.path.dirname(self.path)
        return os.path.abspath(dirPath) if dirPath else ""

    @property
    def consumed(self) -> bool:
        """Directories can be read multiple times"""
        return False

    @property
    def supportManifest(self) -> bool:
        return True

    @property
    def supportFileAccess(self) -> bool:
        return True

    @property
    def manifest(self):
        return self._entries if self._entries else []

    def getManifestEntry(self, fileName: str) -> dict:
        """
        Get manifest entry by fileName (O(1) lookup)

        Args:
            fileName: File path within ZIP (arcname)

        Returns:
            dict: Entry dict with metadata (size, data_offset, etc.)

        Raises:
            FileNotFoundError: If fileName doesn't exist in manifest
        """
        if not self._segmentIndex:
            raise FileNotFoundError(f"No index available (deflate mode)")

        return self._segmentIndex.getEntry(fileName)

    def iterFileChunks(self, fileName: str, chunkSize: int, start: int = 0, end: int = None):
        """
        Iterate over chunks of a specific file within the ZIP

        Args:
            fileName: File path within ZIP (arcname)
            chunkSize: Size of each chunk in bytes
            start: Starting byte offset within the file (default: 0)
            end: Ending byte offset within the file (inclusive, default: end of file)

        Yields:
            bytes: Chunks of the requested file

        Raises:
            FileNotFoundError: If fileName doesn't exist in the ZIP
        """
        # Get entry using O(1) map lookup
        entry = self.getManifestEntry(fileName)

        # Get file metadata from entry
        fileSize = entry.get('size', 0)
        dataOffset = entry.get('dataOffset', 0) # Offset within ZIP stream

        # Calculate byte range within file
        fileStart = start if start is not None else 0
        fileEnd = end if end is not None else fileSize - 1

        # Validate range
        if fileStart >= fileSize:
            raise ValueError(f"Start offset {fileStart} beyond file size {fileSize}")

        if fileEnd >= fileSize:
            fileEnd = fileSize - 1

        # Calculate ZIP stream offsets
        zipStart = dataOffset + fileStart
        zipEnd = dataOffset + fileEnd

        # Stream requested bytes from ZIP
        bytesToRead = zipEnd - zipStart + 1
        bytesRead = 0

        for chunk in self.iterChunks(chunkSize, start=zipStart):
            # Don't yield more than requested
            if bytesRead + len(chunk) > bytesToRead:
                chunk = chunk[:bytesToRead - bytesRead]

            yield chunk
            bytesRead += len(chunk)

            # Stop when we've read all requested bytes
            if bytesRead >= bytesToRead:
                break

    def _yieldChunks(self, buffer, chunkSize):
        """
        Yield chunks from buffer and remove yielded data

        Args:
            buffer: bytearray to yield from
            chunkSize: size of chunks to yield

        Yields:
            bytes: chunks of exactly chunkSize
        """
        while len(buffer) >= chunkSize:
            yield bytes(buffer[:chunkSize])
            del buffer[:chunkSize]

    def _processFileDataStore(self, entry: dict, buffer: bytearray, chunkSize: int):
        """
        Process file data in store mode (no compression)

        Args:
            entry: Entry dictionary with 'path', 'size'
            buffer: Buffer to write data to
            chunkSize: Chunk size for reading and yielding

        Yields:
            bytes: Chunks when buffer is full

        Returns:
            tuple: (crc, bytesWritten, bytesWritten) - uncompressed = compressed for store
        """
        crc = 0
        bytesWritten = 0

        try:
            with self.fileSystem.open(entry['fsPath']) as f:
                while True:
                    data = f.read(chunkSize)
                    if not data:
                        break

                    crc = zlib.crc32(data, crc)
                    buffer.extend(data)
                    bytesWritten += len(data)

                    yield from self._yieldChunks(buffer, chunkSize)
        except OSError as e:
            logger.error("Error reading file %s: %s", entry['path'], e)
            # Write zeros for unreadable files
            zeros = b'\x00' * entry['size']
            buffer.extend(zeros)
            crc = zlib.crc32(zeros)
            bytesWritten = entry['size']

        return crc, bytesWritten, bytesWritten

    def _processFileDataDeflate(self, entry: dict, buffer: bytearray, chunkSize: int):
        """
        Process file data in deflate mode (with compression)

        Args:
            entry: Entry dictionary with 'path'
            buffer: Buffer to write compressed data to
            chunkSize: Chunk size for reading and yielding

        Yields:
            bytes: Chunks when buffer is full

        Returns:
            tuple: (crc, compressedSize, uncompressedSize)
        """
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        crc = 0
        uncompressedSize = 0
        compressedSize = 0

        try:
            with self.fileSystem.open(entry['fsPath']) as f:
                while True:
                    data = f.read(chunkSize)
                    if not data:
                        break

                    crc = zlib.crc32(data, crc)
                    uncompressedSize += len(data)

                    compressed = compressor.compress(data)
                    if compressed:
                        compressedSize += len(compressed)
                        buffer.extend(compressed)
                        yield from self._yieldChunks(buffer, chunkSize)

            # Flush compressor
            compressed = compressor.flush()
            if compressed:
                compressedSize += len(compressed)
                buffer.extend(compressed)
        except OSError as e:
            logger.error("Error reading file %s: %s", entry['path'], e)
            crc = 0
            uncompressedSize = 0
            compressedSize = 0

        return crc, compressedSize, uncompressedSize

    def _scanDirectory(self):
        """
        Scan directory and collect all files/directories with metadata

        Returns:
            list: List of entry dicts with path, arcname, isDir, size, mtime
        """
        logger.debug("Scan directory START: %s", self.path)
        entries = []
        progressReporter = self._progressReporter
        totalScannedBytes = 0

        rootName = self.fileSystem.rootName()
        rootPath = self.fileSystem.rootPath
        if progressReporter:
            progressReporter.start("scan", total=None, unit="entries")

        try:
            for dirPath, dirNames, fileNames in self.fileSystem.walk(rootPath):

                # Deterministic traversal order (critical for resume correctness)
                dirNames.sort()
                fileNames.sort()

                # Compute relative directory path for arcname
                relDir = self.fileSystem.relPath(dirPath, rootPath)
                if self.flatRoot:
                    arcDir = (relDir + "/" if relDir else "").replace("\\", "/")
                else:
                    arcDir = (rootName + ("/" + relDir if relDir else "")).replace("\\", "/")

                if arcDir and not arcDir.endswith("/"):
                    arcDir += "/"

                scannedCount = 0
                scannedBytes = 0

                # Add subdirectory entries.
                # NOTE: We intentionally avoid stat() calls for directories.
                # On mounted / FUSE-like filesystems, directory metadata syscalls are
                # disproportionately expensive (and we don't currently use dir mtime for
                # anything in streaming). Skipping these stats drastically reduces the
                # amount of metadata traffic on e.g. WSL2 /mnt, Android shared storage.
                for d in dirNames:
                    dirFullPath = self.fileSystem.joinPath(dirPath, d)
                    dirArcname = f"{arcDir}{d}/"
                    entries.append({
                        'path': dirFullPath,
                        'arcname': dirArcname,
                        'isDir': True,
                        'size': 0,
                        'mtime': None,
                    })
                    scannedCount += 1

                # Add file entries
                for f in fileNames:
                    fileFullPath = self.fileSystem.joinPath(dirPath, f)
                    relFile = self.fileSystem.relPath(fileFullPath, rootPath)
                    arcname = (relFile if self.flatRoot else f"{rootName}/{relFile}").replace("\\", "/")
                    realOsPath = self.fileSystem.realPath(fileFullPath)

                    try:
                        stat = self.fileSystem.stat(fileFullPath)
                        scannedBytes += stat.size
                        entries.append({
                            'path': realOsPath,
                            'fsPath': fileFullPath,
                            'arcname': arcname,
                            'isDir': False,
                            'size': stat.size,
                            'mtime': stat.mtime
                        })
                    except OSError as e:
                        logger.warning("Cannot access file %s: %s", fileFullPath, e)
                        # Add entry anyway for deflate mode compatibility
                        entries.append({
                            'path': realOsPath,
                            'fsPath': fileFullPath,
                            'arcname': arcname,
                            'isDir': False,
                            'size': 0,
                            'mtime': None,
                        })
                    scannedCount += 1

                if progressReporter and scannedCount > 0:
                    totalScannedBytes += scannedBytes
                    progressReporter.advance(scannedCount, processedBytes=totalScannedBytes)
        finally:
            if progressReporter:
                progressReporter.finish()

        # Ensure global determinism even if os.walk behavior differs
        entries.sort(key=lambda e: e['arcname'])
        logger.debug("Scan directory END: %s entries found", len(entries))
        return entries

    def _scanAndCalculateSize(self):
        """
        Scan directory and calculate exact ZIP file size for store mode

        Also captures file metadata (size, mtime) for change detection during streaming.
        Accurately simulates the streaming process to include Zip64 extra fields and
        handle offset-triggered Zip64 requirements.

        Returns:
            tuple: (entries, needsZip64, totalSize)
        """
        logger.debug("Calculate ZIP size START")
        entries = self._scanDirectory()

        # Simulate streaming to calculate exact offsets and sizes
        offset = 0
        cdEntries = []

        for entry in entries:
            arcnameBytes = entry['arcname'].encode('utf-8')

            # Local file header: 30 bytes + filename
            headerSize = 30 + len(arcnameBytes)
            offset += headerSize

            # Track this entry's offset for CD
            entryOffset = offset - headerSize
            compressedSize = entry['size'] if not entry['isDir'] else 0
            uncompressedSize = entry['size'] if not entry['isDir'] else 0

            if not entry['isDir']:
                # File data (uncompressed size for store mode)
                offset += entry['size']

                # Data descriptor: always use Zip64 descriptor if file >= 4GiB
                # We'll refine this later based on global needsZip64
                descriptorSize = 24 if self._exceedsZip64Limit(entry['size']) else 16
                offset += descriptorSize

            # Record for Central Directory calculation
            cdEntries.append({
                'arcnameBytes': arcnameBytes,
                'offset': entryOffset,
                'compressedSize': compressedSize,
                'uncompressedSize': uncompressedSize,
                'isDir': entry['isDir']
            })

        # Calculate Central Directory size with Zip64 extra fields
        centralDirStart = offset
        centralDirSize = 0

        for cdEntry in cdEntries:
            # Check if this CD entry needs Zip64 extra field
            needsZip64Extra = self._needsZip64ForCentralDirHeader(
                cdEntry['compressedSize'], cdEntry['uncompressedSize'], cdEntry['offset']
            )

            # Base CD header: 46 bytes + filename
            cdHeaderSize = 46 + len(cdEntry['arcnameBytes'])

            # Add Zip64 extra field if needed
            if needsZip64Extra:
                # Zip64 extra field: tag(2) + size(2) + data
                extraSize = 4 # tag + size field
                if self._exceedsZip64Limit(cdEntry['uncompressedSize']):
                    extraSize += 8
                if self._exceedsZip64Limit(cdEntry['compressedSize']):
                    extraSize += 8
                if self._exceedsZip64Limit(cdEntry['offset']):
                    extraSize += 8
                cdHeaderSize += extraSize

            centralDirSize += cdHeaderSize

        offset += centralDirSize

        # Determine if Zip64 EOCD/locator needed
        needsZip64 = self._needsZip64ForArchive(entries, centralDirSize, centralDirStart, offset, sizeKey='size')

        # Add EOCD sizes
        if needsZip64:
            offset += 56 # Zip64 EOCD
            offset += 20 # Zip64 EOCD locator
        offset += 22 # Standard EOCD

        totalSize = offset

        logger.debug(
            "Calculate ZIP size END: totalSize=%s, needsZip64=%s, entries=%s", totalSize, needsZip64, len(entries)
        )
        return entries, needsZip64, totalSize

    def getMetadataHash(self) -> Optional[str]:
        """
        Get metadata hash for folder validation (store mode only)

        Returns the pre-computed hash stored during initialization.
        No recalculation needed - uses cached value from SegmentIndex.

        Returns:
            str: Hexadecimal hash string, or None if deflate mode
        """
        if self.compression != 'store':
            return None
        return self._metadataHash

    def validateIntegrity(
        self, storedSize: int, storedMtime: float, storedHash: str = None, raiseOnError: bool = False
    ) -> bool:
        """
        Validate folder contents haven't changed

        Returns:
            bool: True if unchanged, False if changed (when raiseOnError=False)
        """
        if self.compression != 'store':
            return True # Deflate mode: can't validate (size unknown)

        # Store mode: validate using metadata hash
        if not storedHash:
            return True # No hash provided - assume valid

        currentHash = self.getMetadataHash()
        if currentHash != storedHash:
            if raiseOnError:
                raise FolderChangedException(
                    "Folder contents have changed (files added/removed/modified)", filePath=self.path
                )
            return False

        return True

    # --------------------
    # CRC sidecar manifest
    # --------------------
    def _getCRCManifestPath(self) -> str:
        """Return the sidecar manifest path for this folder snapshot.

        We intentionally write the manifest OUTSIDE the folder being zipped so the
        folder contents (and thus metadata hash) won't change.

        Priority of directory:
          1) READER_CRC_MANIFEST_DIR (if set)
          2) system temp directory
          3) parent directory of the folder 
        """
        folder = os.path.basename(self.path) or 'archive'

        # Add path hash to avoid collision when different paths have same folder name + content
        # Example: /a/data and /b/data with identical content would collide without path hash
        absPath = os.path.abspath(self.path)
        pathHash = hashlib.blake2b(absPath.encode('utf-8', errors='surrogateescape'), digest_size=8).hexdigest()

        name = f".{folder}.{pathHash}.zipcrc.{self._metadataHash}.json"

        candidates = []
        envDir = os.getenv('READER_CRC_MANIFEST_DIR')
        if envDir:
            candidates.append(envDir)

        # Prefer tempdir / cache-like locations by default.
        # DO NOT default to putting manifests next to the shared folder, because that folder may be on a
        # mounted / emulated filesystem where create+rename is very slow.
        candidates.append(tempfile.gettempdir())

        candidates.append(os.path.dirname(self.path))
        for base in candidates:
            try:
                if base and not os.path.exists(base):
                    os.makedirs(base, exist_ok=True)

                # quick writeability check (create+remove tiny temp file)
                testPath = os.path.join(base, f".crc_test_{os.getpid()}")
                with open(testPath, 'wb') as _:
                    pass
                os.unlink(testPath)

                return os.path.join(base, name)
            except Exception as e:
                logger.debug(f"CRC manifest location {base} not writable: {e}")
                continue

        # As a last resort, just return a path in tempdir (may still fail on write)
        return os.path.join(tempfile.gettempdir(), name)

    def _loadCRCManifest(self) -> None:
        """Load CRC sidecar manifest into self._crcMap (best-effort)."""
        if not self._crcManifestPath:
            return

        if not os.path.exists(self._crcManifestPath):
            return

        try:
            with open(self._crcManifestPath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if data.get('metadataHash') != self._metadataHash:
                return

            entries = data.get('entries') or {}
            if isinstance(entries, dict):
                # Ensure crc values are int
                self._crcMap = {k: int(v) & 0xFFFFFFFF for k, v in entries.items()}
        except Exception as e:
            logger.debug("[ZipDirSourceReader] Failed to load CRC manifest %s: %s", self._crcManifestPath, e)

    def _applyCRCMapToEntries(self) -> None:
        """Apply loaded CRC map to in-memory SegmentIndex entries."""
        if not self._crcMap or not self._entries:
            return

        applied = 0
        for entry in self._entries:
            if entry.get('isDir'):
                entry['crc'] = 0
                continue
            crc = self._crcMap.get(entry.get('arcname'))
            if crc is not None:
                entry['crc'] = int(crc) & 0xFFFFFFFF
                applied += 1

        if applied:
            logger.debug("[ZipDirSourceReader] Applied %s CRC(s) from manifest", applied)

    def _recordCRC(self, entry: dict, crc: int) -> None:
        """Record CRC for an entry and flush manifest occasionally (best-effort)."""
        if not self._crcManifestEnabled or self.compression != 'store':
            return

        if not self._metadataHash:
            return

        if entry.get('isDir'):
            return

        arcname = entry.get('arcname')
        if not arcname:
            return

        crc = int(crc) & 0xFFFFFFFF
        if self._crcMap.get(arcname) == crc:
            return

        self._crcMap[arcname] = crc
        self._crcDirty = True
        self._crcUpdateCount += 1
        self._maybeFlushCRCManifest(force=False)

    def _maybeFlushCRCManifest(self, force: bool = False) -> None:
        if not self._crcManifestEnabled or not self._crcDirty:
            return

        now = time.monotonic()
        if force or self._crcUpdateCount >= self._crcFlushEvery or (
            now - self._crcLastFlush
        ) >= self._crcFlushIntervalSec:
            self._flushCRCManifest()

    def _flushCRCManifest(self) -> None:
        """Write manifest atomically (best-effort)."""
        if not self._crcManifestEnabled or not self._crcDirty:
            return

        if not self._metadataHash:
            return

        if not self._crcManifestPath:
            self._crcManifestPath = self._getCRCManifestPath()

        payload = {
            'version': 1,
            'metadataHash': self._metadataHash,
            'folder': self.path,
            'updatedAt': datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
            'entries': self._crcMap,
        }

        path = self._crcManifestPath

        # IMPORTANT: tmpPath must be unique per concurrent transfer.
        # Using only PID collides across threads, especially with multiple WebRTC sessions.
        tmpPath = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}"

        try:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            with open(tmpPath, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False) #, sort_keys=True)
            os.replace(tmpPath, path)

            self._crcDirty = False
            self._crcUpdateCount = 0
            self._crcLastFlush = time.monotonic()
        except Exception as e:
            try:
                if os.path.exists(tmpPath):
                    os.unlink(tmpPath)
            except Exception as e2:
                logger.debug(f"[ZipDirSourceReader] Failed to cleanup temp file {tmpPath}: {e2}")

            logger.debug("[ZipDirSourceReader] Failed to flush CRC manifest %s: %s", path, e)

    def _validateFileUnchanged(self, entry: dict) -> None:
        """
        Validate that file hasn't changed since scan

        Args:
            entry: Entry dictionary with 'path', 'size', 'mtime'

        Raises:
            RuntimeError: If file has changed and strictMode is True
        """
        if entry['isDir']:
            return # Skip directories

        path = entry['path']
        fsPath = entry.get('fsPath', path)
        expectedSize = entry['size']
        expectedMtime = entry.get('mtime')

        def handleValidationError(msg: str):
            """Helper to handle validation errors based on strictMode"""
            if self.strictMode:
                logger.error(msg)
                raise FolderChangedException(msg, filePath=path)
            else:
                logger.warning(msg)

        try:
            stat = self.fileSystem.stat(fsPath)
            currentSize = stat.size
            currentMtime = stat.mtime

            # Check for changes
            if currentSize != expectedSize:
                handleValidationError(
                    f"File size changed during transfer: {path} (expected {expectedSize}, got {currentSize})"
                )
                return # Only reached if not strict mode

            if expectedMtime is not None and currentMtime != expectedMtime:
                handleValidationError(f"File modified during transfer: {path} (mtime changed)")

        except FileNotFoundError:
            handleValidationError(f"File disappeared during transfer: {path}")
        except OSError as e:
            handleValidationError(f"Cannot access file during transfer: {path}: {e}")

    def iterChunks(self, chunkSize: int, start: int = 0) -> Iterator[bytes]:
        """
        Iterate over ZIP stream chunks with optional cold-start resume support (-2.5)

        Args:
            chunkSize: Size of each chunk
            start: Starting offset for resume (store mode only, cold-start capable)

        Raises:
            RuntimeError: If start > 0 for deflate mode
        """
        if start > 0 and self.compression != "store":
            raise RuntimeError("Range/offset resume only supported for store mode")

        if start < 0:
            raise RuntimeError("Negative offset not supported")

        logger.debug(
            "ZIP build START: mode=%s, chunkSize=%s, folder=%s, start=%s", self.compression, chunkSize, self.path, start
        )

        if self.compression == "store":
            # Store mode: use SegmentIndex for cold-start resume (-2.5)
            if not self._segmentIndex:
                raise RuntimeError("SegmentIndex not available for store mode")

            # Cold-start capable: can start from any offset
            yield from self._iterZipStoreWithResume(chunkSize, start)
        else:
            # Deflate mode: no resume support
            if start > 0:
                raise RuntimeError("Resume not supported for deflate mode")
            yield from self._iterZipDeflate(chunkSize)

        logger.debug("ZIP build END: mode=%s", self.compression)

    def _iterZipStoreWithResume(self, chunkSize: int, start: int) -> Iterator[bytes]:
        """
        Generate ZIP stream for store mode with cold-start resume support (-2.5)

        This is the key -2.5 method: uses SegmentIndex to locate position,
        then calls existing generation methods (_makeLocalFileHeader, etc.)
        to generate data on-demand. Keeps separation of concerns.

        Args:
            chunkSize: Size of chunks to yield
            start: Starting byte offset (0 for full, >0 for resume)

        Yields:
            bytes: ZIP stream chunks starting from start offset
        """
        if start >= self._segmentIndex.totalSize:
            return # Nothing to stream

        buffer = bytearray()

        # Use index to find where to start
        if start == 0:
            startSegmentIndex = 0
            offsetInSegment = 0
        else:
            location = self._segmentIndex.locate(start)
            startSegmentIndex = location['segmentIndex']
            offsetInSegment = location['offsetInSegment']

        # Iterate through segments starting from resume point
        try:
            for segmentIndex in range(startSegmentIndex, len(self._segmentIndex.segments)):
                segment = self._segmentIndex.segments[segmentIndex]
                segmentType = segment['type']
                entry = None

                entryIndex = segment.get('entryIndex')
                if entryIndex is not None:
                    entry = self._segmentIndex.entries[entryIndex]

                # Calculate skip for first segment
                skip = offsetInSegment if segmentIndex == startSegmentIndex else 0

                # Generate segment data based on type
                if segmentType == SegmentType.LFH:
                    # Generate LFH on-demand using existing method
                    lfhBytes = self._makeLocalFileHeader(
                        entry['arcnameBytes'],
                        entry['dataLength'],
                        entry['isDir'],
                        useDeflate=False,
                        mtime=entry.get('mtime'),
                        offset=entry['lfhOffset']
                    )
                    if skip > 0:
                        lfhBytes = lfhBytes[skip:]
                    buffer.extend(lfhBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.FILE_DATA:
                    # Validate file unchanged before streaming (snapshot validation)
                    self._validateFileUnchanged(entry)
                    # Stream file data with efficient seeking
                    yield from self._streamFileDataSegment(entry, chunkSize, skip, buffer)

                elif segmentType == SegmentType.DESCRIPTOR:
                    # Generate descriptor on-demand (need CRC)
                    crc = self._computeCRC(entry)
                    descriptorBytes = self._makeDataDescriptor(
                        crc,
                        entry['dataLength'],
                        entry['needsZip64Descriptor'],
                        uncompressedSize=entry['dataLength']
                    )
                    if skip > 0:
                        descriptorBytes = descriptorBytes[skip:]
                    buffer.extend(descriptorBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.CENTRAL_DIR:
                    # Generate CD header on-demand
                    crc = self._computeCRC(entry)
                    cdBytes = self._makeCentralDirHeader(
                        entry['arcnameBytes'],
                        crc,
                        entry['dataLength'],
                        entry['dataLength'],
                        entry['lfhOffset'],
                        entry['isDir'],
                        useDeflate=False,
                        mtime=entry.get('mtime')
                    )
                    if skip > 0:
                        cdBytes = cdBytes[skip:]
                    buffer.extend(cdBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.ZIP64_EOCD:
                    # Generate Zip64 EOCD on-demand
                    zip64EocdBytes = self._makeZip64EndOfCentralDir(
                        len(self._segmentIndex.entries), self._segmentIndex.centralDirSize,
                        self._segmentIndex.centralDirStart
                    )
                    if skip > 0:
                        zip64EocdBytes = zip64EocdBytes[skip:]
                    buffer.extend(zip64EocdBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.ZIP64_LOCATOR:
                    # Generate Zip64 locator on-demand
                    zip64LocatorBytes = self._makeZip64Locator(
                        self._segmentIndex.centralDirStart + self._segmentIndex.centralDirSize
                    )
                    if skip > 0:
                        zip64LocatorBytes = zip64LocatorBytes[skip:]
                    buffer.extend(zip64LocatorBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.EOCD:
                    # Generate EOCD on-demand
                    eocdBytes = self._makeEndOfCentralDir(
                        len(self._segmentIndex.entries), self._segmentIndex.centralDirSize,
                        self._segmentIndex.centralDirStart
                    )
                    if skip > 0:
                        eocdBytes = eocdBytes[skip:]
                    buffer.extend(eocdBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                else:
                    raise RuntimeError(f"Unknown segment type: {segmentType}")

            # Yield final buffer
            if buffer:
                yield bytes(buffer)
        finally:
            # Persist any CRCs we've computed so far, even if the caller aborts mid-stream.
            self._maybeFlushCRCManifest(force=True)

    def _handleIOError(self, error: OSError, path: str, operation: str):
        """
        Handle I/O errors with strictMode-aware logic

        Args:
            error: The OSError that occurred
            path: Path to the file that caused the error
            operation: Description of the operation (e.g., "File read", "CRC computation")

        Raises:
            FolderChangedException: In strict mode
        """
        if self.strictMode:
            raise FolderChangedException(
                f"{operation} failed in strict mode (permissions/I/O error): {path}"
            ) from error

        # Lenient mode: just log the error
        logger.error("Error during %s for %s: %s", operation.lower(), path, error)

    def _streamFileDataSegment(self, entry: dict, chunkSize: int, skip: int, buffer: bytearray):
        """
        Stream file data segment with efficient seeking (for resume)

        Optimized to compute CRC during streaming when skip==0 (full file read),
        avoiding the need for a second I/O pass in _computeCRC().

        Args:
            entry: Entry dict with file metadata
            chunkSize: Chunk size for reading
            skip: Bytes to skip at start of this segment
            buffer: Buffer to accumulate data

        Yields:
            bytes: Chunks via _yieldChunks
        """
        fileSize = entry['dataLength']
        if fileSize == 0 or skip >= fileSize:
            # Cache CRC for empty files when reading from start
            if fileSize == 0 and skip == 0 and 'crc' not in entry:
                entry['crc'] = 0
                self._recordCRC(entry, 0)
            return

        path = entry.get('fsPath', entry['path'])

        # Only compute CRC if reading from start (skip==0)
        # This avoids incorrect CRC for partial reads during resume
        computeCRC = (skip == 0)
        crc = 0

        try:
            with self.fileSystem.open(path) as f:
                # Efficient O(1) seek to skip position
                if skip > 0:
                    f.seek(skip)

                # Stream remaining data
                bytesRead = 0
                while True:
                    chunk = f.read(chunkSize)
                    if not chunk:
                        break

                    # Compute CRC while streaming (only if skip==0)
                    if computeCRC:
                        crc = zlib.crc32(chunk, crc)

                    buffer.extend(chunk)
                    bytesRead += len(chunk)
                    yield from self._yieldChunks(buffer, chunkSize)

                # Cache CRC only if we read the complete file from start
                if computeCRC and bytesRead == fileSize:
                    entry['crc'] = crc
                    self._recordCRC(entry, crc)

        except OSError as e:
            # Handle I/O error with strictMode-aware logic
            self._handleIOError(e, path, "File read")

            # Lenient mode: stream zeros for unreadable files
            # IMPORTANT: Must compute CRC for ALL zeros to match actual output
            remaining = fileSize - skip

            while remaining > 0:
                zeroSize = min(chunkSize, remaining)
                zeroChunk = b'\x00' * zeroSize

                # Update CRC for each zero chunk to match actual output
                if computeCRC:
                    crc = zlib.crc32(zeroChunk, crc)

                buffer.extend(zeroChunk)
                yield from self._yieldChunks(buffer, chunkSize)
                remaining -= zeroSize

            # Cache the actual CRC of all zeros (not 0!)
            # This ensures ZIP descriptor/central dir matches the data we sent
            if computeCRC:
                entry['crc'] = crc
                self._recordCRC(entry, crc)

    def _computeCRC(self, entry: dict) -> int:
        """
        Compute CRC32 for entry (cached after first computation)

        Args:
            entry: Entry dict

        Returns:
            int: CRC32 value
        """
        # Return cached CRC if available
        if 'crc' in entry and entry['crc'] is not None:
            return entry['crc']

        # Directories have CRC=0
        if entry['isDir']:
            entry['crc'] = 0
            return 0

        # Empty files have CRC=0
        if entry['dataLength'] == 0:
            entry['crc'] = 0
            self._recordCRC(entry, 0)
            return 0

        # Compute CRC by reading file
        path = entry.get('fsPath', entry['path'])
        crc = 0

        try:
            with self.fileSystem.open(path) as f:
                while True:
                    chunk = f.read(1024 * 1024) # 1MB chunks
                    if not chunk:
                        break
                    crc = zlib.crc32(chunk, crc)
        except OSError as e:
            # Handle I/O error with strictMode-aware logic
            self._handleIOError(e, path, "CRC computation")

            # Lenient mode: use CRC=0 for unreadable files
            crc = 0

        # Cache the result
        entry['crc'] = crc
        self._recordCRC(entry, crc)
        return crc

    def _iterZip(self, chunkSize: int, entries: list, useDeflate: bool) -> Iterator[bytes]:
        """
        Unified ZIP stream generation with compression strategy

        Args:
            chunkSize: Size of chunks to yield
            entries: List of entries to process
            useDeflate: True for deflate compression, False for store mode

        Yields:
            bytes: Chunks of ZIP stream data
        """
        buffer = bytearray()
        centralDir = []
        offset = 0

        for entry in entries:
            # Validate file hasn't changed before processing
            self._validateFileUnchanged(entry)

            arcnameBytes = entry['arcname'].encode('utf-8')

            # Write local file header (pass offset for Zip64 version detection)
            localHeader = self._makeLocalFileHeader(
                arcnameBytes,
                0 if useDeflate else entry['size'],
                entry['isDir'],
                useDeflate=useDeflate,
                mtime=entry.get('mtime'),
                offset=offset
            )
            buffer.extend(localHeader)
            headerSize = len(localHeader)

            if not entry['isDir']:
                # Process file data with appropriate strategy
                if useDeflate:
                    crc, compressedSize, uncompressedSize = yield from self._processFileDataDeflate(
                        entry, buffer, chunkSize
                    )
                else:
                    crc, compressedSize, uncompressedSize = yield from self._processFileDataStore(
                        entry, buffer, chunkSize
                    )

                # Write data descriptor (use Zip64 if sizes >= 4GiB)
                useZip64Descriptor = (
                    self._exceedsZip64Limit(compressedSize) or
                    (useDeflate and self._exceedsZip64Limit(uncompressedSize))
                )
                descriptor = self._makeDataDescriptor(
                    crc, compressedSize, useZip64Descriptor, uncompressedSize if useDeflate else None
                )
                buffer.extend(descriptor)
            else:
                # Directory entry - no data, no descriptor
                crc = 0
                compressedSize = 0
                uncompressedSize = 0
                descriptor = b''

            # Record central directory info
            centralDir.append({
                'arcname': arcnameBytes,
                'offset': offset,
                'crc': crc,
                'compressedSize': compressedSize,
                'uncompressedSize': uncompressedSize if useDeflate else compressedSize,
                'isDir': entry['isDir'],
                'mtime': entry.get('mtime')
            })

            offset += headerSize + compressedSize + len(descriptor)

        # Write central directory
        centralDirStart = offset
        for cdHeader in self._writeCentralDirectoryHeaders(centralDir, useDeflate=useDeflate):
            cdHeaderSize = len(cdHeader)
            buffer.extend(cdHeader)
            offset += cdHeaderSize
            # Yield chunks during CD writing
            yield from self._yieldChunks(buffer, chunkSize)

        centralDirSize = offset - centralDirStart

        # Write End of Central Directory (auto-detect Zip64 based on actual offsets/sizes)
        self._writeEndOfCentralDirectory(buffer, centralDir, centralDirSize, centralDirStart, offset, needsZip64=None)

        # Yield final buffer
        if buffer:
            yield bytes(buffer)

    def _iterZipDeflate(self, chunkSize: int) -> Iterator[bytes]:
        """
        Generate ZIP stream with deflate compression mode

        Uses caching to avoid re-compression on subsequent reads
        """
        # Check if we have cached deflate output from previous read
        if self._hasCache():
            logger.debug("[ZipDirSourceReader] Reading deflate ZIP from cache: %s", self._cachedFile)
            yield from self._readFromCache(chunkSize, start=0)
            return

        # First read - generate and cache
        logger.debug("[ZipDirSourceReader] Generating deflate ZIP (will cache for subsequent reads)")

        # Start caching
        self._startCaching(prefix='zip_deflate_', suffix='.zip')

        try:
            # Generate ZIP stream
            entries = self._scanDirectory()
            totalCached = 0

            for chunk in self._iterZip(chunkSize, entries, useDeflate=True):
                # Cache chunk (fail silently via mixin)
                if self._cacheChunk(chunk):
                    totalCached += len(chunk)

                # Stream chunk to client immediately
                yield chunk

            # Finalize caching
            if self._finalizeCache():
                self.size = totalCached # Now we know the compressed size
                logger.debug("[ZipDirSourceReader] Successfully cached deflate ZIP: %s bytes", totalCached)

        except Exception:
            # Clean up temp file on error (mixin handles cleanup in __del__)
            self._cleanupCacheFile()
            raise

