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
import zipfile
import hashlib
import json
import time
import datetime
import sys
import tempfile
import threading
import uuid

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator, Optional

from bases.Kernel import getLogger, FFLEvent
from bases.FileSystems import HTTPFileSystem, LocalFileSystem

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


class SegmentType(Enum):
    """ZIP segment types for SegmentIndex"""
    LFH = auto() # Local File Header
    FILE_DATA = auto() # File data content
    DESCRIPTOR = auto() # Data descriptor
    CENTRAL_DIR = auto() # Central directory header
    ZIP64_EOCD = auto() # Zip64 End of Central Directory
    ZIP64_LOCATOR = auto() # Zip64 End of Central Directory Locator
    EOCD = auto() # End of Central Directory


class FolderChangedException(RuntimeError):
    """Exception raised when folder contents change during transfer"""

    def __init__(self, message: str, filePath: str = None):
        super().__init__(message)
        self.filePath = filePath


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
    _shutdownSubscribed = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cachedFile = None # Path to cached temp file
        self._cacheSuccess = False # Whether caching succeeded
        self._cacheTempFile = None # File object for writing cache
        self._cacheEnabled = True # Can be disabled if disk space issues
        self._growState: Optional[GrowingFileState] = None # Shared state for follow mode

        # Register this instance for shutdown cleanup
        CachingMixin._instances.append(self)

        # Subscribe to shutdown event (do this only once for the class)
        if not CachingMixin._shutdownSubscribed:
            FFLEvent.applicationShutdown.subscribe(CachingMixin._cleanupAllInstances)
            CachingMixin._shutdownSubscribed = True

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


class SegmentIndex:
    """
    Thin segment index for ZIP download resume support (-2.5 architecture)

    This is a pure coordinate table - it ONLY calculates offsets, does NOT generate data.

    Responsibilities:
    - Calculate offset/length of every segment (LFH, DATA, DD, CD, EOCD)
    - Provide locate(offset) to find which segment contains a given byte offset
    - Store deterministic metadata (lfh_len, descriptor_len, needs_zip64)

    Does NOT:
    - Generate ZIP data (that's ZipDirSourceReader's job)
    - Have iterChunks() method
    - Store pre-built header bytes

    This keeps separation of concerns: Index = coordinates, Reader = generation
    """

    # ZIP64 threshold constant (decoupled from ZipDirSourceReader)
    ZIP64_LIMIT = 0xFFFFFFFF # 4GiB - 1

    def __init__(
        self,
        entries: list,
        segments: list,
        totalSize: int,
        centralDirStart: int,
        centralDirSize: int,
        metadataHash: str = None
    ):
        """
        Initialize with pre-calculated segment coordinates

        Args:
            entries: List of entry dicts with deterministic metadata
            segments: List of segment dicts with offset/length/type
            totalSize: Total ZIP archive size
            centralDirStart: Offset where central directory starts
            centralDirSize: Size of central directory
            metadataHash: Deterministic fingerprint of folder content (arcname/size/mtime)
        """
        self.entries = entries
        self.segments = segments
        self.totalSize = totalSize
        self.centralDirStart = centralDirStart
        self.centralDirSize = centralDirSize
        # Deterministic fingerprint of folder content for resume validation
        self.metadataHash = metadataHash

    @classmethod
    def computeMetadataHash(cls, rawEntries: list) -> str:
        """
        Compute deterministic hash for folder snapshot validation

        This creates a fingerprint based on (arcname, size, mtime) for all entries.
        ANY change to folder structure (add/delete/rename/size/mtime) will change this hash.

        Args:
            rawEntries: List of raw entry dicts from _scanDirectory()

        Returns:
            str: Hexadecimal hash string (SHA-256)
        """
        hasher = hashlib.sha256()

        # Sort by arcname to ensure deterministic order
        for entry in sorted(rawEntries, key=lambda e: e['arcname']):
            # Hash: arcname + size + mtime
            hasher.update(entry['arcname'].encode('utf-8'))
            hasher.update(struct.pack('Q', entry['size'])) # 8-byte unsigned

            if entry['mtime'] is not None:
                # Hash mtime as integer nanoseconds for precision
                mtimeNs = int(entry['mtime'] * 1_000_000_000)
                hasher.update(struct.pack('q', mtimeNs)) # 8-byte signed

        return hasher.hexdigest()

    @classmethod
    def build(
        cls, rawEntries: list, makeLocalFileHeaderLength, makeDataDescriptorLength, makeCentralDirHeaderLength,
        makeZip64Lengths
    ) -> "SegmentIndex":
        """
        Build segment index by calculating all offsets (does NOT generate data)

        This is the key method for -2.5 cold-start capability. It only calculates
        coordinates by simulating the layout, without generating actual bytes.

        Args:
            rawEntries: List of raw entry dicts from _scanDirectory()
            makeLocalFileHeaderLength: Function(entry) -> int (LFH length)
            makeDataDescriptorLength: Function(fileSize) -> int (16 or 24)
            makeCentralDirHeaderLength: Function(entry) -> int (CD header length)
            makeZip64Lengths: Function(entries, cdSize, cdStart) -> (zip64EocdLen, zip64LocatorLen, eocdLen)

        Returns:
            SegmentIndex: Index with all segment coordinates pre-calculated
        """
        # Pre-compute deterministic metadata hash (fingerprint for resume validation)
        metadataHash = cls.computeMetadataHash(rawEntries)

        entries = []
        segments = []
        offset = 0

        # Phase 1: Calculate LFH + DATA + DD segments for each entry
        for index, rawEntry in enumerate(rawEntries):
            arcnameBytes = rawEntry['arcname'].encode('utf-8')
            fileSize = rawEntry['size'] if not rawEntry['isDir'] else 0

            # Calculate LFH length (deterministic based on name and size)
            lfhLength = makeLocalFileHeaderLength(rawEntry, arcnameBytes, fileSize, offset)

            # Enrich entry with deterministic metadata
            entry = dict(rawEntry)
            entry.update({
                'index': index,
                'arcname_bytes': arcnameBytes,
                'lfh_offset': offset,
                'lfh_length': lfhLength,
                'data_offset': None,
                'data_length': fileSize,
                'descriptor_offset': None,
                'descriptor_length': 0,
                'needs_zip64_descriptor': False,
            })

            # Add LFH segment
            segments.append({
                'type': SegmentType.LFH,
                'offset': offset,
                'length': lfhLength,
                'entry_index': index,
            })
            offset += lfhLength

            # Add DATA segment (if file)
            if not rawEntry['isDir']:
                entry['data_offset'] = offset
                if fileSize > 0:
                    segments.append({
                        'type': SegmentType.FILE_DATA,
                        'offset': offset,
                        'length': fileSize,
                        'entry_index': index,
                    })
                offset += fileSize

                # Calculate descriptor length (16 or 24 bytes based on file size)
                # SegmentIndex should not depend on ZipDirSourceReader
                needsZip64Descriptor = (fileSize >= cls.ZIP64_LIMIT)
                descriptorLength = makeDataDescriptorLength(fileSize)

                entry['descriptor_offset'] = offset
                entry['descriptor_length'] = descriptorLength
                entry['needs_zip64_descriptor'] = needsZip64Descriptor

                # Add DD segment
                segments.append({
                    'type': SegmentType.DESCRIPTOR,
                    'offset': offset,
                    'length': descriptorLength,
                    'entry_index': index,
                })
                offset += descriptorLength

            entries.append(entry)

        # Phase 2: Calculate CD segments
        centralDirStart = offset
        centralDirSize = 0

        for entry in entries:
            # Calculate CD header length (deterministic)
            cdHeaderLength = makeCentralDirHeaderLength(entry)

            entry['central_dir_offset'] = offset
            entry['central_dir_length'] = cdHeaderLength

            segments.append({
                'type': SegmentType.CENTRAL_DIR,
                'offset': offset,
                'length': cdHeaderLength,
                'entry_index': entry['index'],
            })

            offset += cdHeaderLength
            centralDirSize += cdHeaderLength

        # Phase 3: Calculate EOCD segments (Zip64 if needed)
        zip64EocdLen, zip64LocatorLen, eocdLen = makeZip64Lengths(entries, centralDirSize, centralDirStart, offset)

        if zip64EocdLen > 0:
            segments.append({
                'type': SegmentType.ZIP64_EOCD,
                'offset': offset,
                'length': zip64EocdLen,
                'entry_index': None,
            })
            offset += zip64EocdLen

            segments.append({
                'type': SegmentType.ZIP64_LOCATOR,
                'offset': offset,
                'length': zip64LocatorLen,
                'entry_index': None,
            })
            offset += zip64LocatorLen

        segments.append({
            'type': SegmentType.EOCD,
            'offset': offset,
            'length': eocdLen,
            'entry_index': None,
        })
        offset += eocdLen

        totalSize = offset

        logger.debug(
            "SegmentIndex built: totalSize=%s, entries=%s, segments=%s", totalSize, len(entries), len(segments)
        )

        return cls(entries, segments, totalSize, centralDirStart, centralDirSize, metadataHash=metadataHash)

    def locate(self, offset: int) -> dict:
        """
        Find which segment contains the given offset (binary search)

        Args:
            offset: Byte offset in ZIP stream

        Returns:
            dict: {
                'segment': segment dict,
                'entry': entry dict or None,
                'offset_in_segment': bytes from start of this segment
            }

        Raises:
            ValueError: If offset is out of range
        """
        if offset < 0 or offset >= self.totalSize:
            raise ValueError(f"Offset {offset} out of range [0, {self.totalSize})")

        # Binary search
        left, right = 0, len(self.segments) - 1

        while left <= right:
            mid = (left + right) // 2
            segment = self.segments[mid]

            segStart = segment['offset']
            segEnd = segStart + segment['length']

            if offset < segStart:
                right = mid - 1
            elif offset >= segEnd:
                left = mid + 1
            else:
                # Found the segment
                entry = None
                entryIndex = segment.get('entry_index')
                if entryIndex is not None:
                    entry = self.entries[entryIndex]

                return {
                    'segment': segment,
                    'entry': entry,
                    'offset_in_segment': offset - segStart,
                    'segment_index': mid
                }

        raise ValueError(f"No segment found for offset {offset}")


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

    @classmethod
    def build(cls, path: str, fileName: str = None, compression: str = None) -> 'SourceReader':
        """
        Factory method to create appropriate SourceReader

        Args:
            path: File or directory path, "-" for stdin, or vfs:// URI for remote VFS
            fileName: Custom download filename (default: original filename for files,
                       foldername.zip for folders, stdin-YYYYMMDD-HHMMSS.bin for stdin)
            compression: For directories - "store" (no compression) or "deflate" (compressed)
                        If None, uses FOLDER_COMPRESSION environment variable (default: "store")

        Returns:
            SourceReader: Appropriate reader for the path type
        """
        # Handle stdin
        if path == "-":
            return StdinSourceReader(path, fileName=fileName)

        # Create appropriate FileSystem
        if path.startswith("vfs://"):
            fileSystem = HTTPFileSystem(path)
        else:
            fileSystem = LocalFileSystem(path)

        # Use FileSystem to determine file vs directory
        if fileSystem.rootIsDir:
            # Directory: create ZIP
            if compression is None:
                compression = os.getenv('READER_FOLDER_COMPRESSION', 'store')

            return ZipDirSourceReader(
                fileSystem.rootPath, fileName=fileName, compression=compression, fileSystem=fileSystem
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

    Usage: python Core.py --cli -
    """

    def _getDefaultFileName(self):
        """Generate default stdin filename with timestamp to avoid conflicts"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"stdin-{timestamp}.bin"

    def __init__(self, path: str, fileName=None):
        """
        Initialize StdinSourceReader

        Args:
            path: Path (should be "-" for stdin)
            fileName: Custom filename (string), callable that returns filename, or None for default
        """
        super().__init__(path, fileName) # CachingMixin -> SourceReader
        self.stdin = sys.stdin.buffer # Binary mode for file data
        self.contentType = "application/octet-stream"
        self.size = None # Unknown size for streaming input
        self.supportsRange = False # stdin is not seekable (direct stream)
        self.supportsUploadResume = False # Cannot resume stdin
        self._consumed = False # Track if stdin has been consumed

    @property
    def directory(self) -> str:
        """Directory path for server identification"""
        return ""

    @property
    def consumed(self) -> bool:
        """Check if stdin has been consumed and no cache available"""
        # Not consumed if cache is complete or still being written
        return self._consumed and not self._hasCache() and not self._hasCacheInProgress()

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
                raise RuntimeError("Stdin has already been consumed and caching failed")

        # First read: Stream from stdin with simultaneous caching
        if start > 0:
            raise RuntimeError("Stdin does not support Range/offset resume (not seekable)")

        self._consumed = True

        logger.debug("[StdinSourceReader] Starting to read stdin with chunkSize=%s", chunkSize)
        totalRead = 0

        # Start caching (may fail silently)
        self._startCaching(prefix='stdin_cache_', suffix='.bin')

        # Use read1 for realtime streaming, but read1 might not exist if stdin is io.TextIOWrapper
        read = self.stdin.read1 if hasattr(self.stdin, 'read1') else self.stdin.read
        try:
            while True:
                chunk = read(chunkSize)
                if not chunk:
                    logger.debug("[StdinSourceReader] EOF reached, total read: %s bytes", totalRead)
                    break

                totalRead += len(chunk)
                logger.debug("[StdinSourceReader] Read chunk: %s bytes, total: %s", len(chunk), totalRead)

                # Cache chunk (fail silently via mixin)
                self._cacheChunk(chunk)

                # Stream chunk to client immediately
                yield chunk

            logger.debug("[StdinSourceReader] Finished reading %s bytes from stdin", totalRead)

            # Finalize caching if successful
            if self._finalizeCache():
                self.size = totalRead # Now we know the size
                logger.debug("[StdinSourceReader] Successfully cached %s bytes", totalRead)

        except Exception as e:
            # Clean up temp file on error (mixin handles cleanup in __del__)
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


class ZipDirSourceReader(CachingMixin, SourceReader):
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

    # ZIP format constants (from PKZIP APPNOTE.TXT specification)
    # Signature constants - these are not exposed in zipfile module, but defined in ZIP spec
    LOCAL_FILE_HEADER_SIGNATURE = struct.unpack('<I', zipfile.stringFileHeader)[0] # 0x04034b50
    CENTRAL_DIR_SIGNATURE = struct.unpack('<I', zipfile.stringCentralDir)[0] # 0x02014b50
    END_OF_CENTRAL_DIR_SIGNATURE = struct.unpack('<I', zipfile.stringEndArchive)[0] # 0x06054b50
    ZIP64_END_OF_CENTRAL_DIR_SIGNATURE = 0x06064b50 # ZIP64 extension (not in zipfile module)
    ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIGNATURE = 0x07064b50 # ZIP64 extension (not in zipfile module)

    # Compression methods (from zipfile module)
    STORE = zipfile.ZIP_STORED # 0
    DEFLATE = zipfile.ZIP_DEFLATED # 8

    # General purpose bit flags
    DATA_DESCRIPTOR_FLAG = 0x0008 # Bit 3: sizes/CRC in data descriptor
    UTF8_FLAG = 0x0800 # Bit 11: filename and comment UTF-8 encoded

    # Class-level cache for scan results (keyed by absolute path)
    _scanCache = {}

    # ZIP64 threshold constants
    ZIP64_LIMIT = 0xFFFFFFFF # 4GiB - 1
    ZIP64_ENTRY_COUNT_LIMIT = 65535 # Maximum entries in standard ZIP

    # ZIP64 detection helper methods (DRY)
    @staticmethod
    def _exceedsZip64Limit(value: int) -> bool:
        """Check if a single value exceeds ZIP64 threshold (>= 4GiB)"""
        return value >= ZipDirSourceReader.ZIP64_LIMIT

    @staticmethod
    def _exceedsEntryCountLimit(count: int) -> bool:
        """Check if entry count exceeds ZIP64 threshold (> 65535)"""
        return count > ZipDirSourceReader.ZIP64_ENTRY_COUNT_LIMIT

    @staticmethod
    def _needsZip64ForLocalHeader(size: int, offset: int) -> bool:
        """
        Check if local file header needs ZIP64

        Args:
            size: File size in bytes
            offset: File offset in ZIP archive

        Returns:
            bool: True if ZIP64 is needed
        """
        return (ZipDirSourceReader._exceedsZip64Limit(size) or
                ZipDirSourceReader._exceedsZip64Limit(offset)) # yapf: disable

    @staticmethod
    def _needsZip64ForCentralDirHeader(compressedSize: int, uncompressedSize: int, offset: int) -> bool:
        """
        Check if central directory header needs ZIP64 extra field

        Args:
            compressedSize: Compressed file size
            uncompressedSize: Uncompressed file size
            offset: File offset in ZIP archive

        Returns:
            bool: True if ZIP64 extra field is needed
        """
        return (ZipDirSourceReader._exceedsZip64Limit(compressedSize) or
                ZipDirSourceReader._exceedsZip64Limit(uncompressedSize) or
                ZipDirSourceReader._exceedsZip64Limit(offset)) # yapf: disable

    @staticmethod
    def _hasAnyLargeFiles(entries: list, sizeKey: str = 'data_length') -> bool:
        """
        Check if any files in entries exceed 4GiB

        Args:
            entries: List of entry dicts
            sizeKey: Key to check for file size (default: 'data_length', can be 'size')

        Returns:
            bool: True if any file >= 4GiB
        """
        return any(
            e.get(sizeKey, 0) >= ZipDirSourceReader.ZIP64_LIMIT
            for e in entries
            if not e.get('isDir', False)
        ) # yapf: disable

    @staticmethod
    def _needsZip64ForArchive(
        entries: list, centralDirSize: int, centralDirStart: int, offset: int, sizeKey: str = 'data_length'
    ) -> bool:
        """
        Check if entire ZIP archive needs ZIP64 format

        This is the comprehensive check for archive-level ZIP64 requirements.

        Args:
            entries: List of entry dicts
            centralDirSize: Size of central directory
            centralDirStart: Offset where central directory starts
            offset: Current offset in ZIP file
            sizeKey: Key to check for file size (default: 'data_length', can be 'size')

        Returns:
            bool: True if ZIP64 is needed for the archive
        """
        return (
            ZipDirSourceReader._exceedsEntryCountLimit(len(entries)) or
            ZipDirSourceReader._exceedsZip64Limit(centralDirSize) or
            ZipDirSourceReader._exceedsZip64Limit(centralDirStart) or
            ZipDirSourceReader._exceedsZip64Limit(offset) or
            ZipDirSourceReader._hasAnyLargeFiles(entries, sizeKey)
        ) # yapf: disable

    @staticmethod
    def _unixToDosTime(timestamp):
        """
        Convert Unix timestamp to DOS time and date format

        Args:
            timestamp: Unix timestamp (seconds since epoch) or None

        Returns:
            tuple: (dosTime, dosDate) - both as 16-bit integers

        DOS time format (16 bits):
            bits 0-4: seconds / 2 (0-29)
            bits 5-10: minutes (0-59)
            bits 11-15: hours (0-23)

        DOS date format (16 bits):
            bits 0-4: day (1-31)
            bits 5-8: month (1-12)
            bits 9-15: year - 1980 (0-127, representing 1980-2107)
        """
        if timestamp is None or timestamp <= 0:
            # Return default date: 1980-01-01 00:00:00
            return 0, (1 << 5) | 1 # dosTime=0, dosDate=(month=1, day=1, year=1980)

        try:
            dt = datetime.datetime.fromtimestamp(timestamp)

            # DOS date range is 1980-2107
            year = max(1980, min(2107, dt.year))

            dosTime = ((dt.hour & 0x1F) << 11) | ((dt.minute & 0x3F) << 5) | ((dt.second // 2) & 0x1F)
            dosDate = (((year - 1980) & 0x7F) << 9) | ((dt.month & 0x0F) << 5) | (dt.day & 0x1F)

            return dosTime, dosDate
        except (ValueError, OSError):
            # Return default date on error
            return 0, (1 << 5) | 1

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

    def __init__(self, path: str, fileName=None, compression: str = "store", strictMode: bool = None, fileSystem=None):
        """
        Initialize ZIP directory reader

        Args:
            path: Path to directory (FS-specific)
            fileName: Custom download filename (string), callable that returns filename, or None for default
            compression: "store" (no compression) or "deflate" (compressed)
            strictMode: If True, abort on file size/mtime changes during streaming.
                       If None, defaults to True for store mode, False for deflate mode.
            fileSystem: FileSystem instance (default: LocalFileSystem)
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
                self._crcManifestPath = self._getCrcManifestPath()
                self._loadCrcManifest()
                self._applyCrcMapToEntries()

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
            with self.fileSystem.open(entry['path']) as f:
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
            with self.fileSystem.open(entry['path']) as f:
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

    def _calculateLocalFileHeaderLength(self, rawEntry: dict, arcnameBytes: bytes, fileSize: int, offset: int) -> int:
        """
        Calculate LFH length without generating bytes (for SegmentIndex)

        Args:
            rawEntry: Raw entry from _scanDirectory()
            arcnameBytes: Encoded filename
            fileSize: File size in bytes
            offset: Current offset (for Zip64 detection)

        Returns:
            int: Length of LFH in bytes
        """
        # LFH: 30 bytes fixed + filename length + extra field length
        # For store mode with data descriptor, extra field is 0
        return 30 + len(arcnameBytes)

    def _calculateDataDescriptorLength(self, fileSize: int) -> int:
        """
        Calculate data descriptor length (16 or 24 bytes)

        Args:
            fileSize: File size in bytes

        Returns:
            int: 24 if file >= 4GiB (Zip64), otherwise 16
        """
        return 24 if self._exceedsZip64Limit(fileSize) else 16

    def _calculateCentralDirHeaderLength(self, entry: dict) -> int:
        """
        Calculate CD header length without generating bytes

        Args:
            entry: Entry dict with metadata

        Returns:
            int: Length of CD header in bytes
        """
        # Base CD header: 46 bytes + filename
        cdHeaderLength = 46 + len(entry['arcname_bytes'])

        # Add Zip64 extra field if needed
        fileSize = entry['data_length']
        offset = entry['lfh_offset']

        needsZip64Extra = self._needsZip64ForLocalHeader(fileSize, offset)

        if needsZip64Extra:
            # Zip64 extra field: tag(2) + size(2) + data
            extraSize = 4 # tag + size field
            if self._exceedsZip64Limit(fileSize):
                extraSize += 16 # uncompressed + compressed (both 8 bytes, same for store)
            if self._exceedsZip64Limit(offset):
                extraSize += 8
            cdHeaderLength += extraSize

        return cdHeaderLength

    def _calculateZip64Lengths(self, entries: list, centralDirSize: int, centralDirStart: int, offset: int) -> tuple:
        """
        Calculate Zip64 EOCD/locator/EOCD lengths

        Args:
            entries: List of enriched entries
            centralDirSize: Size of central directory
            centralDirStart: Offset where CD starts
            offset: Current offset

        Returns:
            tuple: (zip64EocdLen, zip64LocatorLen, eocdLen)
        """
        # Determine if Zip64 is needed
        needsZip64 = self._needsZip64ForArchive(entries, centralDirSize, centralDirStart, offset)

        if needsZip64:
            return (56, 20, 22) # Zip64 EOCD, Zip64 locator, standard EOCD
        else:
            return (0, 0, 22) # Only standard EOCD

    def _scanDirectory(self):
        """
        Scan directory and collect all files/directories with metadata

        Returns:
            list: List of entry dicts with path, arcname, isDir, size, mtime
        """
        logger.debug("Scan directory START: %s", self.path)
        entries = []

        rootName = self.fileSystem.rootName()
        rootPath = self.fileSystem.rootPath

        for dirPath, dirNames, fileNames in self.fileSystem.walk(rootPath):

            # Deterministic traversal order (critical for resume correctness)
            dirNames.sort()
            fileNames.sort()

            # Compute relative directory path for arcname
            relDir = self.fileSystem.relPath(dirPath, rootPath)
            arcDir = (rootName + ("/" + relDir if relDir else "")).replace("\\", "/")
            if not arcDir.endswith("/"):
                arcDir += "/"

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

            # Add file entries
            for f in fileNames:
                fileFullPath = self.fileSystem.joinPath(dirPath, f)
                relFile = self.fileSystem.relPath(fileFullPath, rootPath)
                arcname = f"{rootName}/{relFile}".replace("\\", "/")

                try:
                    stat = self.fileSystem.stat(fileFullPath)
                    entries.append({
                        'path': fileFullPath,
                        'arcname': arcname,
                        'isDir': False,
                        'size': stat.size,
                        'mtime': stat.mtime
                    })
                except OSError as e:
                    logger.warning("Cannot access file %s: %s", fileFullPath, e)
                    # Add entry anyway for deflate mode compatibility
                    entries.append({
                        'path': fileFullPath,
                        'arcname': arcname,
                        'isDir': False,
                        'size': 0,
                        'mtime': None,
                    })

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
    def _getCrcManifestPath(self) -> str:
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

    def _loadCrcManifest(self) -> None:
        """Load CRC sidecar manifest into self._crcMap (best-effort)."""
        if not self._crcManifestPath:
            return

        if not os.path.exists(self._crcManifestPath):
            return

        try:
            with open(self._crcManifestPath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if data.get('metadata_hash') != self._metadataHash:
                return

            entries = data.get('entries') or {}
            if isinstance(entries, dict):
                # Ensure crc values are int
                self._crcMap = {k: int(v) & 0xFFFFFFFF for k, v in entries.items()}
        except Exception as e:
            logger.debug("[ZipDirSourceReader] Failed to load CRC manifest %s: %s", self._crcManifestPath, e)

    def _applyCrcMapToEntries(self) -> None:
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

    def _recordCrc(self, entry: dict, crc: int) -> None:
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
        self._maybeFlushCrcManifest(force=False)

    def _maybeFlushCrcManifest(self, force: bool = False) -> None:
        if not self._crcManifestEnabled or not self._crcDirty:
            return

        now = time.monotonic()
        if force or self._crcUpdateCount >= self._crcFlushEvery or (
            now - self._crcLastFlush
        ) >= self._crcFlushIntervalSec:
            self._flushCrcManifest()

    def _flushCrcManifest(self) -> None:
        """Write manifest atomically (best-effort)."""
        if not self._crcManifestEnabled or not self._crcDirty:
            return

        if not self._metadataHash:
            return

        if not self._crcManifestPath:
            self._crcManifestPath = self._getCrcManifestPath()

        payload = {
            'version': 1,
            'metadata_hash': self._metadataHash,
            'folder': self.path,
            'updated_at': datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
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
            stat = self.fileSystem.stat(path)
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
            startSegmentIndex = location['segment_index']
            offsetInSegment = location['offset_in_segment']

        # Iterate through segments starting from resume point
        try:
            for segmentIndex in range(startSegmentIndex, len(self._segmentIndex.segments)):
                segment = self._segmentIndex.segments[segmentIndex]
                segmentType = segment['type']
                entry = None

                entryIndex = segment.get('entry_index')
                if entryIndex is not None:
                    entry = self._segmentIndex.entries[entryIndex]

                # Calculate skip for first segment
                skip = offsetInSegment if segmentIndex == startSegmentIndex else 0

                # Generate segment data based on type
                if segmentType == SegmentType.LFH:
                    # Generate LFH on-demand using existing method
                    lfhBytes = self._makeLocalFileHeader(
                        entry['arcname_bytes'],
                        entry['data_length'],
                        entry['isDir'],
                        useDeflate=False,
                        mtime=entry.get('mtime'),
                        offset=entry['lfh_offset']
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
                        entry['data_length'],
                        entry['needs_zip64_descriptor'],
                        uncompressedSize=entry['data_length']
                    )
                    if skip > 0:
                        descriptorBytes = descriptorBytes[skip:]
                    buffer.extend(descriptorBytes)
                    yield from self._yieldChunks(buffer, chunkSize)

                elif segmentType == SegmentType.CENTRAL_DIR:
                    # Generate CD header on-demand
                    crc = self._computeCRC(entry)
                    cdBytes = self._makeCentralDirHeader(
                        entry['arcname_bytes'],
                        crc,
                        entry['data_length'],
                        entry['data_length'],
                        entry['lfh_offset'],
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
            self._maybeFlushCrcManifest(force=True)

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
        fileSize = entry['data_length']
        if fileSize == 0 or skip >= fileSize:
            # Cache CRC for empty files when reading from start
            if fileSize == 0 and skip == 0 and 'crc' not in entry:
                entry['crc'] = 0
                self._recordCrc(entry, 0)
            return

        path = entry['path']

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
                    self._recordCrc(entry, crc)

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
                self._recordCrc(entry, crc)

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
        if entry['data_length'] == 0:
            entry['crc'] = 0
            self._recordCrc(entry, 0)
            return 0

        # Compute CRC by reading file
        path = entry['path']
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
        self._recordCrc(entry, crc)
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

    def _writeCentralDirectoryHeaders(self, centralDir, useDeflate=False):
        """
        Generate central directory headers

        Args:
            centralDir: list of CD entry dicts
            useDeflate: whether using deflate compression

        Returns:
            Iterator[bytes]: central directory headers
        """
        for cdEntry in centralDir:
            cdHeader = self._makeCentralDirHeader(
                cdEntry['arcname'],
                cdEntry['crc'],
                cdEntry['compressedSize'],
                cdEntry['uncompressedSize'],
                cdEntry['offset'],
                cdEntry['isDir'],
                useDeflate=useDeflate,
                mtime=cdEntry.get('mtime')
            )
            yield cdHeader

    def _writeEndOfCentralDirectory(self, buffer, centralDir, centralDirSize, centralDirStart, offset, needsZip64=None):
        """
        Write EOCD (and Zip64 EOCD/locator if needed) to buffer

        Args:
            buffer: bytearray buffer to write to
            centralDir: list of CD entries (for count)
            centralDirSize: size of central directory
            centralDirStart: offset where central directory starts
            offset: current offset in ZIP file
            needsZip64: explicitly specify if Zip64 is needed, or None to auto-detect

        Returns:
            int: new offset after writing EOCD
        """
        # Auto-detect Zip64 if not specified
        if needsZip64 is None:
            # EOCD-level check (no file size check, only counts/offsets/sizes)
            needsZip64 = (
                self._exceedsEntryCountLimit(len(centralDir)) or
                self._exceedsZip64Limit(centralDirSize) or
                self._exceedsZip64Limit(centralDirStart) or
                self._exceedsZip64Limit(offset)
            ) # yapf: disable

        # Write Zip64 EOCD and locator if needed
        if needsZip64:
            zip64Eocd = self._makeZip64EndOfCentralDir(len(centralDir), centralDirSize, centralDirStart)
            buffer.extend(zip64Eocd)
            offset += len(zip64Eocd)

            zip64Locator = self._makeZip64Locator(offset - len(zip64Eocd))
            buffer.extend(zip64Locator)

        # Write End of Central Directory
        eocd = self._makeEndOfCentralDir(len(centralDir), centralDirSize, centralDirStart)
        buffer.extend(eocd)

        return offset

    def _makeLocalFileHeader(
        self, arcnameBytes: bytes, size: int, isDir: bool, useDeflate: bool = False, mtime=None, offset: int = 0
    ):
        """Create ZIP local file header"""
        compressionMethod = self.DEFLATE if useDeflate else self.STORE

        # Directories don't have data descriptors (no data segment)
        if isDir:
            flags = self.UTF8_FLAG
        else:
            flags = self.DATA_DESCRIPTOR_FLAG | self.UTF8_FLAG

        # For directories, use trailing slash
        externalAttr = 0x10 if isDir else 0 # MS-DOS directory attribute

        # Convert mtime to DOS format
        dosTime, dosDate = self._unixToDosTime(mtime)

        # Determine if Zip64 is needed for this entry
        # - File size >= 4GiB (for store mode, deflate uses data descriptor)
        # - Local header offset >= 4GiB
        needsZip64 = self._needsZip64ForLocalHeader(size, offset)
        versionNeeded = 45 if needsZip64 else 20

        header = struct.pack(
            '<I', # Signature
            self.LOCAL_FILE_HEADER_SIGNATURE
        )
        header += struct.pack(
            '<H', # Version needed to extract (2.0 or 4.5 for Zip64)
            versionNeeded
        )
        header += struct.pack(
            '<H', # General purpose bit flag
            flags
        )
        header += struct.pack(
            '<H', # Compression method
            compressionMethod
        )
        header += struct.pack(
            '<H', # File last modification time
            dosTime
        )
        header += struct.pack(
            '<H', # File last modification date
            dosDate
        )
        header += struct.pack(
            '<I', # CRC-32 (0 for data descriptor)
            0
        )
        header += struct.pack(
            '<I', # Compressed size (0 for data descriptor)
            0
        )
        header += struct.pack(
            '<I', # Uncompressed size (0 for data descriptor)
            0
        )
        header += struct.pack(
            '<H', # Filename length
            len(arcnameBytes)
        )
        header += struct.pack(
            '<H', # Extra field length
            0
        )
        header += arcnameBytes

        return header

    def _makeDataDescriptor(self, crc: int, compressedSize: int, useZip64: bool, uncompressedSize: int = None):
        """Create ZIP data descriptor"""
        if uncompressedSize is None:
            uncompressedSize = compressedSize

        if useZip64:
            # Zip64 data descriptor
            descriptor = struct.pack('<I', 0x08074b50) # Optional signature
            descriptor += struct.pack('<I', crc & 0xFFFFFFFF)
            descriptor += struct.pack('<Q', compressedSize)
            descriptor += struct.pack('<Q', uncompressedSize)
        else:
            # Standard data descriptor
            descriptor = struct.pack('<I', 0x08074b50) # Optional signature
            descriptor += struct.pack('<I', crc & 0xFFFFFFFF)
            descriptor += struct.pack('<I', compressedSize & 0xFFFFFFFF)
            descriptor += struct.pack('<I', uncompressedSize & 0xFFFFFFFF)

        return descriptor

    def _makeCentralDirHeader(
        self,
        arcnameBytes: bytes,
        crc: int,
        compressedSize: int,
        uncompressedSize: int,
        offset: int,
        isDir: bool,
        useDeflate: bool = False,
        mtime=None
    ):
        """Create ZIP central directory header with Zip64 support"""
        compressionMethod = self.DEFLATE if useDeflate else self.STORE

        # Directories don't have data descriptors (no data segment)
        if isDir:
            flags = self.UTF8_FLAG
        else:
            flags = self.DATA_DESCRIPTOR_FLAG | self.UTF8_FLAG

        externalAttr = 0x10 if isDir else 0x20 # Directory or archive attribute

        # Convert mtime to DOS format
        dosTime, dosDate = self._unixToDosTime(mtime)

        # Determine if Zip64 extra field is needed
        needsZip64 = self._needsZip64ForCentralDirHeader(compressedSize, uncompressedSize, offset)

        # Build Zip64 extra field if needed
        extraField = b''
        if needsZip64:
            extraField = struct.pack('<H', 0x0001) # Zip64 extended information extra field tag
            extraData = b''

            # Add fields in order: uncompressed size, compressed size, relative header offset
            if self._exceedsZip64Limit(uncompressedSize):
                extraData += struct.pack('<Q', uncompressedSize)
            if self._exceedsZip64Limit(compressedSize):
                extraData += struct.pack('<Q', compressedSize)
            if self._exceedsZip64Limit(offset):
                extraData += struct.pack('<Q', offset)

            extraField += struct.pack('<H', len(extraData)) # Size of extra block
            extraField += extraData

        # Use version 45 for Zip64
        versionMadeBy = 45 if needsZip64 else 20
        versionNeeded = 45 if needsZip64 else 20

        # Use 0xFFFFFFFF markers for Zip64 fields
        cdCompressedSize = self.ZIP64_LIMIT if self._exceedsZip64Limit(compressedSize) else compressedSize
        cdUncompressedSize = self.ZIP64_LIMIT if self._exceedsZip64Limit(uncompressedSize) else uncompressedSize
        cdOffset = self.ZIP64_LIMIT if self._exceedsZip64Limit(offset) else offset

        header = struct.pack('<I', self.CENTRAL_DIR_SIGNATURE)
        header += struct.pack('<H', versionMadeBy) # Version made by
        header += struct.pack('<H', versionNeeded) # Version needed to extract
        header += struct.pack('<H', flags) # General purpose bit flag
        header += struct.pack('<H', compressionMethod) # Compression method
        header += struct.pack('<H', dosTime) # Last mod file time
        header += struct.pack('<H', dosDate) # Last mod file date
        header += struct.pack('<I', crc & 0xFFFFFFFF) # CRC-32
        header += struct.pack('<I', cdCompressedSize) # Compressed size
        header += struct.pack('<I', cdUncompressedSize) # Uncompressed size
        header += struct.pack('<H', len(arcnameBytes)) # Filename length
        header += struct.pack('<H', len(extraField)) # Extra field length
        header += struct.pack('<H', 0) # File comment length
        header += struct.pack('<H', 0) # Disk number start
        header += struct.pack('<H', 0) # Internal file attributes
        header += struct.pack('<I', externalAttr) # External file attributes
        header += struct.pack('<I', cdOffset) # Relative offset of local header
        header += arcnameBytes
        header += extraField # Append Zip64 extra field if present

        return header

    def _makeZip64EndOfCentralDir(self, entryCount: int, centralDirSize: int, centralDirStart: int):
        """Create Zip64 end of central directory record"""
        record = struct.pack('<I', self.ZIP64_END_OF_CENTRAL_DIR_SIGNATURE)
        record += struct.pack('<Q', 44) # Size of zip64 end of central directory record
        record += struct.pack('<H', 45) # Version made by
        record += struct.pack('<H', 45) # Version needed to extract
        record += struct.pack('<I', 0) # Number of this disk
        record += struct.pack('<I', 0) # Disk where central directory starts
        record += struct.pack('<Q', entryCount) # Number of entries on this disk
        record += struct.pack('<Q', entryCount) # Total number of entries
        record += struct.pack('<Q', centralDirSize) # Size of central directory
        record += struct.pack('<Q', centralDirStart) # Offset of start of central directory

        return record

    def _makeZip64Locator(self, zip64EocdOffset: int):
        """Create Zip64 end of central directory locator"""
        locator = struct.pack('<I', self.ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIGNATURE)
        locator += struct.pack('<I', 0) # Disk number with zip64 EOCD
        locator += struct.pack('<Q', zip64EocdOffset) # Offset of zip64 EOCD
        locator += struct.pack('<I', 1) # Total number of disks

        return locator

    def _makeEndOfCentralDir(self, entryCount: int, centralDirSize: int, centralDirStart: int):
        """Create end of central directory record"""
        # For Zip64, use 0xFFFF/0xFFFFFFFF as markers
        maxEntries = min(entryCount, self.ZIP64_ENTRY_COUNT_LIMIT)
        maxSize = min(centralDirSize, self.ZIP64_LIMIT)
        maxOffset = min(centralDirStart, self.ZIP64_LIMIT)

        eocd = struct.pack('<I', self.END_OF_CENTRAL_DIR_SIGNATURE)
        eocd += struct.pack('<H', 0) # Number of this disk
        eocd += struct.pack('<H', 0) # Disk where central directory starts
        eocd += struct.pack('<H', maxEntries) # Number of entries on this disk
        eocd += struct.pack('<H', maxEntries) # Total number of entries
        eocd += struct.pack('<I', maxSize) # Size of central directory
        eocd += struct.pack('<I', maxOffset) # Offset of start of central directory
        eocd += struct.pack('<H', 0) # Comment length

        return eocd
