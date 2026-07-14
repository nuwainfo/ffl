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
Pure ZIP format knowledge: SegmentType, SegmentIndex, and ZipMixin (ZIP64 detection,
DOS time conversion, SegmentIndex-length calculation callbacks, and LFH/DD/CD/EOCD
byte building).
"""

import struct
import zipfile
import hashlib
import datetime

from enum import Enum, auto

from bases.Kernel import getLogger

logger = getLogger(__name__)


class SegmentType(Enum):
    """ZIP segment types for SegmentIndex"""
    LFH = auto() # Local File Header
    FILE_DATA = auto() # File data content
    DESCRIPTOR = auto() # Data descriptor
    CENTRAL_DIR = auto() # Central directory header
    ZIP64_EOCD = auto() # Zip64 End of Central Directory
    ZIP64_LOCATOR = auto() # Zip64 End of Central Directory Locator
    EOCD = auto() # End of Central Directory


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
        metadataHash: str = None,
        entriesMap: dict = None
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
            entriesMap: Pre-built map of arcname -> entry for O(1) lookup (optional)
        """
        self.entries = entries
        self.segments = segments
        self.totalSize = totalSize
        self.centralDirStart = centralDirStart
        self.centralDirSize = centralDirSize
        # Deterministic fingerprint of folder content for resume validation
        self.metadataHash = metadataHash
        # O(1) lookup map: arcname -> entry (built during index construction)
        self._entriesMap = entriesMap if entriesMap is not None else {}

    def getEntry(self, arcname: str) -> dict:
        """
        Get entry by arcname (O(1) lookup)

        Args:
            arcname: File path within ZIP

        Returns:
            dict: Entry dict with metadata (size, data_offset, etc.)

        Raises:
            FileNotFoundError: If arcname doesn't exist
        """
        entry = self._entriesMap.get(arcname)
        if entry is None:
            raise FileNotFoundError(f"File not found in ZIP: {arcname}")
        return entry

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
        entriesMap = {} # Build map while building entries (O(1) lookup)
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
                'arcnameBytes': arcnameBytes,
                'lfhOffset': offset,
                'lfhLength': lfhLength,
                'dataOffset': None,
                'dataLength': fileSize,
                'descriptorOffset': None,
                'descriptorLength': 0,
                'needsZip64Descriptor': False,
            })

            # Add LFH segment
            segments.append({
                'type': SegmentType.LFH,
                'offset': offset,
                'length': lfhLength,
                'entryIndex': index,
            })
            offset += lfhLength

            # Add DATA segment (if file)
            if not rawEntry['isDir']:
                entry['dataOffset'] = offset
                if fileSize > 0:
                    segments.append({
                        'type': SegmentType.FILE_DATA,
                        'offset': offset,
                        'length': fileSize,
                        'entryIndex': index,
                    })
                offset += fileSize

                # Calculate descriptor length (16 or 24 bytes based on file size)
                # SegmentIndex should not depend on ZipDirSourceReader
                needsZip64Descriptor = (fileSize >= cls.ZIP64_LIMIT)
                descriptorLength = makeDataDescriptorLength(fileSize)

                entry['descriptorOffset'] = offset
                entry['descriptorLength'] = descriptorLength
                entry['needsZip64Descriptor'] = needsZip64Descriptor

                # Add DD segment
                segments.append({
                    'type': SegmentType.DESCRIPTOR,
                    'offset': offset,
                    'length': descriptorLength,
                    'entryIndex': index,
                })
                offset += descriptorLength

            entries.append(entry)
            entriesMap[entry['arcname']] = entry # Add to map for O(1) lookup

        # Phase 2: Calculate CD segments
        centralDirStart = offset
        centralDirSize = 0

        for entry in entries:
            # Calculate CD header length (deterministic)
            cdHeaderLength = makeCentralDirHeaderLength(entry)

            entry['centralDirOffset'] = offset
            entry['centralDirLength'] = cdHeaderLength

            segments.append({
                'type': SegmentType.CENTRAL_DIR,
                'offset': offset,
                'length': cdHeaderLength,
                'entryIndex': entry['index'],
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
                'entryIndex': None,
            })
            offset += zip64EocdLen

            segments.append({
                'type': SegmentType.ZIP64_LOCATOR,
                'offset': offset,
                'length': zip64LocatorLen,
                'entryIndex': None,
            })
            offset += zip64LocatorLen

        segments.append({
            'type': SegmentType.EOCD,
            'offset': offset,
            'length': eocdLen,
            'entryIndex': None,
        })
        offset += eocdLen

        totalSize = offset

        logger.debug(
            "SegmentIndex built: totalSize=%s, entries=%s, segments=%s", totalSize, len(entries), len(segments)
        )

        return cls(
            entries,
            segments,
            totalSize,
            centralDirStart,
            centralDirSize,
            metadataHash=metadataHash,
            entriesMap=entriesMap
        )

    def locate(self, offset: int) -> dict:
        """
        Find which segment contains the given offset (binary search)

        Args:
            offset: Byte offset in ZIP stream

        Returns:
            dict: {
                'segment': segment dict,
                'entry': entry dict or None,
                'offsetInSegment': bytes from start of this segment
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
                entryIndex = segment.get('entryIndex')
                if entryIndex is not None:
                    entry = self.entries[entryIndex]

                return {
                    'segment': segment,
                    'entry': entry,
                    'offsetInSegment': offset - segStart,
                    'segmentIndex': mid
                }

        raise ValueError(f"No segment found for offset {offset}")


class ZipMixin:
    """
    Mixin providing pure ZIP format knowledge: ZIP64 detection, DOS time conversion,
    SegmentIndex-length calculation callbacks, and LFH/DD/CD/EOCD byte building.
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

    # ZIP64 threshold constants
    ZIP64_LIMIT = 0xFFFFFFFF # 4GiB - 1
    ZIP64_ENTRY_COUNT_LIMIT = 65535 # Maximum entries in standard ZIP

    # ZIP64 detection helper methods (DRY)
    @staticmethod
    def _exceedsZip64Limit(value: int) -> bool:
        """Check if a single value exceeds ZIP64 threshold (>= 4GiB)"""
        return value >= ZipMixin.ZIP64_LIMIT

    @staticmethod
    def _exceedsEntryCountLimit(count: int) -> bool:
        """Check if entry count exceeds ZIP64 threshold (> 65535)"""
        return count > ZipMixin.ZIP64_ENTRY_COUNT_LIMIT

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
        return (ZipMixin._exceedsZip64Limit(size) or
                ZipMixin._exceedsZip64Limit(offset)) # yapf: disable

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
        return (ZipMixin._exceedsZip64Limit(compressedSize) or
                ZipMixin._exceedsZip64Limit(uncompressedSize) or
                ZipMixin._exceedsZip64Limit(offset)) # yapf: disable

    @staticmethod
    def _hasAnyLargeFiles(entries: list, sizeKey: str = 'dataLength') -> bool:
        """
        Check if any files in entries exceed 4GiB

        Args:
            entries: List of entry dicts
            sizeKey: Key to check for file size (default: 'dataLength', can be 'size')

        Returns:
            bool: True if any file >= 4GiB
        """
        return any(
            e.get(sizeKey, 0) >= ZipMixin.ZIP64_LIMIT
            for e in entries
            if not e.get('isDir', False)
        ) # yapf: disable

    @staticmethod
    def _needsZip64ForArchive(
        entries: list, centralDirSize: int, centralDirStart: int, offset: int, sizeKey: str = 'dataLength'
    ) -> bool:
        """
        Check if entire ZIP archive needs ZIP64 format

        This is the comprehensive check for archive-level ZIP64 requirements.

        Args:
            entries: List of entry dicts
            centralDirSize: Size of central directory
            centralDirStart: Offset where central directory starts
            offset: Current offset in ZIP file
            sizeKey: Key to check for file size (default: 'dataLength', can be 'size')

        Returns:
            bool: True if ZIP64 is needed for the archive
        """
        return (
            ZipMixin._exceedsEntryCountLimit(len(entries)) or
            ZipMixin._exceedsZip64Limit(centralDirSize) or
            ZipMixin._exceedsZip64Limit(centralDirStart) or
            ZipMixin._exceedsZip64Limit(offset) or
            ZipMixin._hasAnyLargeFiles(entries, sizeKey)
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
        cdHeaderLength = 46 + len(entry['arcnameBytes'])

        # Add Zip64 extra field if needed
        fileSize = entry['dataLength']
        offset = entry['lfhOffset']

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
