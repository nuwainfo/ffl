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

import base64
import hmac
import hashlib
import os
import struct
import re
import threading
import zlib
import json

from typing import Optional, Callable, Tuple

import requests

from bases.crypto import CryptoInterface
from bases.Kernel import getLogger
from bases.I18n import _

logger = getLogger(__name__)

# E2EE wire-protocol version, advertised to clients via /e2ee/manifest so they
# can negotiate capabilities against older servers.
E2EE_PROTOCOL_VERSION = 2

# ============================================================================
# Shared cryptographic utilities
# ============================================================================


class CryptoHelper:
    """Shared cryptographic operations for E2E encryption/decryption

    Provides unified AAD and nonce construction for both WebRTC and HTTP modes.
    """

    UNKNOWN_FILE_SIZE = -1

    @staticmethod
    def normalizeFileSize(fileSize: Optional[int]) -> int:
        """Convert optional file sizes into a stable integer for crypto metadata."""
        if fileSize is None:
            return CryptoHelper.UNKNOWN_FILE_SIZE

        return int(fileSize)

    @staticmethod
    def alignChunkStart(start: int, chunkSize: int) -> Tuple[int, int]:
        """Align a byte offset down to its containing chunk boundary.

        AES-GCM nonces are derived from a chunk index (buildNonce), so a given
        index must always correspond to the same fixed, chunkSize-aligned
        plaintext window -- otherwise two Range requests that floor-divide to
        the same chunk index would encrypt different plaintext under an
        identical (key, nonce) pair, which breaks AES-GCM's security entirely
        (plaintext-XOR recovery and tag forgery, the "two-time pad" failure).
        Aligning every read down to the chunk boundary guarantees a given
        chunk index always corresponds to the same canonical byte range,
        regardless of what start a client happens to request.

        Returns:
            (alignedStart, discardLeading): alignedStart is the chunk-aligned
            byte offset to actually read/encrypt from; discardLeading is how
            many leading plaintext bytes of the first produced chunk must be
            skipped to recover the originally-requested start.
        """
        alignedStart = (start // chunkSize) * chunkSize
        return alignedStart, start - alignedStart

    @staticmethod
    def alignChunkEnd(end: int, chunkSize: int) -> int:
        """Align an inclusive byte end up to the end of its containing chunk.

        Mirrors alignChunkStart, and for the same reason: a finite Range's
        actual read must extend through the end of the chunk containing `end`,
        not stop partway through it. Without this, two finite-range requests
        landing in the same chunk index but with different ends (e.g.
        bytes=1000-2000 vs bytes=1000-500000, both chunk index 0) would
        encrypt different-length plaintext under the identical (key, nonce)
        pair -- the same nonce-reuse break alignChunkStart alone doesn't
        prevent once the end is also allowed to vary.

        Callers must clamp the result to the resource size themselves -- this
        function has no way to know it.
        """
        return ((end // chunkSize) + 1) * chunkSize - 1

    @staticmethod
    def buildNonce(nonceBase: bytes, chunkIndex: int) -> bytes:
        """Build 12-byte nonce for AES-GCM

        Nonce format: nonce_base[0:8] (8 bytes) || chunk_index(4 bytes BE)

        Args:
            nonceBase: Nonce base (uses first 8 bytes only, though typically 12 bytes)
            chunkIndex: Chunk index (0-based)

        Returns:
            12-byte nonce
        """
        return nonceBase[:8] + struct.pack("!I", chunkIndex)

    @staticmethod
    def buildAAD(fileName: str, fileSize: int, chunkIndex: int, useStructFormat: bool = True) -> bytes:
        """Build Additional Authenticated Data for AES-GCM

        Two formats supported:
        1. Struct format (HTTP): fileName(utf-8) || fileSize(8 BE) || chunkIndex(4 BE)
        2. String format (WebRTC): fileName(utf-8) | fileSize(ascii) | chunkIndex(ascii)

        Args:
            fileName: Original filename
            fileSize: Original file size in bytes
            chunkIndex: Chunk index (0-based)
            useStructFormat: True for struct format (HTTP), False for string format (WebRTC)

        Returns:
            AAD bytes
        """
        if useStructFormat:
            # HTTP format: binary packed
            return (fileName.encode('utf-8') + struct.pack("!q", fileSize) + struct.pack("!I", chunkIndex))
        else:
            # WebRTC format: text separated with '|'
            return (
                fileName.encode('utf-8') + b'|' + str(fileSize).encode('ascii') + b'|' +
                str(chunkIndex).encode('ascii')
            )

    @staticmethod
    def buildCommitment(
        contentKey: bytes, chunkSize: int, fileSize: int, fileName: str, crypto: CryptoInterface
    ) -> bytes:
        """Build key commitment tag (HMAC-SHA256)

        Binds the content key to file metadata to prevent key substitution attacks.

        Args:
            contentKey: AES-256 content key (32 bytes)
            chunkSize: Chunk size for encryption
            fileSize: Original file size
            fileName: Original filename
            crypto: CryptoInterface instance

        Returns:
            32-byte commitment HMAC
        """
        commitHeader = (
            b"commit" + b"AES-256-GCM" + struct.pack("!Q", chunkSize) + struct.pack("!q", fileSize) +
            fileName.encode('utf-8')
        )

        # Derive HMAC key from content key using HKDF
        commitKeyMaterial = crypto.deriveKey(contentKey, length=32, salt=b"commit-hmac", info=b"key-commitment-v1")

        # Compute HMAC-SHA256 commitment
        return hmac.new(commitKeyMaterial, commitHeader, hashlib.sha256).digest()

    @staticmethod
    def verifyCommitment(
        contentKey: bytes, commitment: bytes, chunkSize: int, fileSize: int, fileName: str, crypto: CryptoInterface
    ) -> bool:
        """Verify key commitment tag

        Args:
            contentKey: AES-256 content key (32 bytes)
            commitment: Received commitment tag
            chunkSize: Chunk size from server
            fileSize: File size from server
            fileName: Filename from server
            crypto: CryptoInterface instance

        Returns:
            True if commitment is valid, False otherwise
        """
        expectedCommitment = CryptoHelper.buildCommitment(contentKey, chunkSize, fileSize, fileName, crypto)
        return hmac.compare_digest(commitment, expectedCommitment)


# ============================================================================
# Storage
# ============================================================================


class EncryptionMetaStorage:
    """Storage for encryption metadata (tags, chunk info) - index-based for Range support"""

    def __init__(self):
        self._storage = {} # streamId -> dict of {chunkIndex: tag}
        # HTTP requests run on separate threads (ThreadingHTTPServer), and a
        # concurrent /download (save) and /e2ee/tags (load) for the same stream
        # can otherwise race: sorted(tagDict.items()) can raise "dictionary
        # changed size during iteration" if save() mutates the same dict mid-sort.
        self._lock = threading.Lock()

    def save(self, streamId, chunkIndex, tag):
        """Save/overwrite a tag for a specific chunk index"""
        with self._lock:
            if streamId not in self._storage:
                self._storage[streamId] = {}

            # Store by index (overwrites if exists - safe for Range/concurrent requests)
            self._storage[streamId][chunkIndex] = base64.b64encode(tag).decode()

    def load(self, streamId):
        """Load all tags for a stream, sorted by chunk_index"""
        with self._lock:
            if streamId not in self._storage:
                return []

            # Snapshot while holding the lock; sort outside it so the lock is
            # held only long enough to copy, not to sort.
            tagDict = dict(self._storage[streamId])

        return [{'chunkIndex': idx, 'tag': tag} for idx, tag in sorted(tagDict.items())]

    def exists(self, streamId):
        """Check if stream exists"""
        with self._lock:
            return streamId in self._storage


# ============================================================================
# WebRTC Frame Processing
# ============================================================================


class E2EEFramerBase:
    """Base constants for E2EE TLV frame protocol"""
    
    MAGIC = b'\xFF\x4C' # Magic bytes for TLV frames
    VERSION = 1 # Protocol version
    TAG_LENGTH = 16 # GCM authentication tag length (bytes)
    HEADER_SIZE = 2 + 1 + 8 + 4 + 16 # Magic(2) + Ver(1) + ChunkIdx(8) + CipherLen(4) + Tag(16) = 31 bytes
    
    # Generous upper bound on one frame's ciphertext -- actual chunks are bounded
    # by the sender's own chunkSize (typically 256 KiB), so this is headroom, not
    # a real payload size. Rejects a corrupted/malicious CipherLen field before it
    # can grow a decoder's buffer without bound (see WebRTCStreamDecryptor.processChunk).
    MAX_CIPHERTEXT_SIZE = 16 * 1024 * 1024

    @staticmethod
    def parseHeader(buffer: bytes) -> Tuple[int, int, bytes]:
        """Validate and parse a TLV frame header from the front of buffer.

        Validates magic bytes, protocol version, and an upper bound on the
        ciphertext length before any caller trusts cipherLen to size a read or
        buffer -- an untrusted peer could otherwise supply a bogus, huge
        cipherLen that grows a decoder's buffer without bound while waiting
        for a frame that will never complete.

        Args:
            buffer: At least HEADER_SIZE bytes, with the header at the front.

        Returns:
            (chunkIndex, cipherLen, tag)

        Raises:
            ValueError: If magic, version, or the cipherLen bound is violated.
        """
        magic = buffer[0:2]
        if magic != E2EEFramerBase.MAGIC:
            raise ValueError(f"Invalid magic bytes: {magic.hex()}")

        version = buffer[2]
        if version != E2EEFramerBase.VERSION:
            raise ValueError(f"Invalid version: {version}")

        cipherLen = struct.unpack("!I", buffer[11:15])[0]
        if cipherLen > E2EEFramerBase.MAX_CIPHERTEXT_SIZE:
            raise ValueError(
                f"CipherLen {cipherLen} exceeds maximum allowed frame size {E2EEFramerBase.MAX_CIPHERTEXT_SIZE}"
            )

        chunkIndex = struct.unpack("!Q", buffer[3:11])[0]
        tag = buffer[15:31]
        return chunkIndex, cipherLen, tag


class E2EEFramer(E2EEFramerBase):
    """E2E encryption framer for WebRTC - encodes chunks as TLV frames with inline tags

    IMPORTANT: Uses string-format AAD (useStructFormat=False). Tags from this framer
    are NOT compatible with HTTP mode tags (which use struct-format AAD).
    Do NOT mix WebRTC and HTTP decryption paths.
    """

    def __init__(self, contentKey: bytes, nonceBase: bytes, chunkSize: int, fileName: str, fileSize: int):
        """Initialize E2EE framer

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes, uses first 8 bytes for nonce construction)
            chunkSize: Size of plaintext chunks
            fileName: Original filename
            fileSize: Original file size
        """
        self.contentKey = contentKey
        self.nonceBase = nonceBase
        self.chunkSize = chunkSize
        self.fileName = fileName
        self.fileSize = fileSize

        self.crypto = CryptoInterface()
        self.aesgcm = self.crypto.createAESGCM(contentKey)

    def packFrame(self, chunkIndex: int, plaintext: bytes) -> bytes:
        """Pack plaintext chunk into encrypted TLV frame

        Frame format:
        | Magic(2) | Ver(1) | ChunkIndex(8, uint64 BE) |
        | CipherLen(4, uint32 BE) | Tag(16 bytes) |
        | Ciphertext (CipherLen bytes) |

        Args:
            chunkIndex: Chunk index (0-based)
            plaintext: Plaintext chunk data

        Returns:
            Encrypted TLV frame bytes
        """
        nonce = CryptoHelper.buildNonce(self.nonceBase, chunkIndex)
        aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, chunkIndex, useStructFormat=False)

        # Encrypt with AES-GCM
        _, ciphertextWithTag = self.crypto.encryptAESGCM(self.aesgcm, plaintext, nonce, aad)

        # Split ciphertext and tag
        ciphertext = ciphertextWithTag[:-self.TAG_LENGTH]
        tag = ciphertextWithTag[-self.TAG_LENGTH:]

        # Build TLV header
        header = (
            self.MAGIC + bytes([self.VERSION]) + struct.pack("!Q", chunkIndex) + struct.pack("!I", len(ciphertext)) +
            tag
        )

        return header + ciphertext


class E2EEUnframer(E2EEFramerBase):
    """E2E decryption unframer for WebRTC - decodes TLV frames

    IMPORTANT: Uses string-format AAD (useStructFormat=False). Tags from this unframer
    are NOT compatible with HTTP mode tags (which use struct-format AAD).
    """

    def __init__(self, contentKey: bytes, nonceBase: bytes, fileName: str, fileSize: int):
        """Initialize E2EE unframer

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes, uses first 8 bytes for nonce construction)
            fileName: Original filename
            fileSize: Original file size
        """
        self.contentKey = contentKey
        self.nonceBase = nonceBase
        self.fileName = fileName
        self.fileSize = fileSize

        self.crypto = CryptoInterface()
        self.aesgcm = self.crypto.createAESGCM(contentKey)

    def unpackFrame(self, frame: bytes) -> tuple[int, bytes]:
        """Unpack and decrypt TLV frame

        Args:
            frame: Encrypted TLV frame bytes

        Returns:
            Tuple of (chunk_index, plaintext)

        Raises:
            ValueError: If frame format is invalid
        """
        if len(frame) < self.HEADER_SIZE:
            raise ValueError(f"Frame too short: {len(frame)} < {self.HEADER_SIZE}")

        chunkIndex, cipherLen, tag = self.parseHeader(frame)

        # Extract ciphertext
        if len(frame) < self.HEADER_SIZE + cipherLen:
            raise ValueError(f"Frame incomplete: expected {self.HEADER_SIZE + cipherLen}, got {len(frame)}")

        ciphertext = frame[self.HEADER_SIZE:self.HEADER_SIZE + cipherLen]

        # Decrypt with AES-GCM
        nonce = CryptoHelper.buildNonce(self.nonceBase, chunkIndex)
        aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, chunkIndex, useStructFormat=False)
        ciphertextWithTag = ciphertext + tag

        plaintext = self.crypto.decryptAESGCM(self.aesgcm, nonce, ciphertextWithTag, aad)

        return (chunkIndex, plaintext)


# ============================================================================
# HTTP Stream Processing
# ============================================================================


class E2EEChunkReader:
    """Adapts a source reader to the canonical chunk boundaries required by E2EE."""

    def __init__(self, sourceReader, chunkSize):
        self.sourceReader = sourceReader
        self.chunkSize = chunkSize

    def __getattr__(self, name):
        """Delegate the SourceReader interface not specialized for E2EE."""
        return getattr(self.sourceReader, name)

    def iterChunks(self, chunkSize, start=0):
        chunkBuffer = bytearray()
        for data in self.sourceReader.iterChunks(chunkSize, start=start):
            chunkBuffer.extend(data)
            while len(chunkBuffer) >= self.chunkSize:
                yield bytes(chunkBuffer[:self.chunkSize])
                del chunkBuffer[:self.chunkSize]

        if chunkBuffer:
            yield bytes(chunkBuffer)


class StreamEncryptor:
    """Stream encryptor for HTTP downloads - compatible with PAKE project

    Encrypts chunks and stores tags separately for HTTP Range resume support.

    IMPORTANT: Uses struct-format AAD (useStructFormat=True). Tags from this encryptor
    are NOT compatible with WebRTC mode tags (which use string-format AAD).
    Do NOT mix WebRTC and HTTP decryption paths.
    """

    def __init__(
        self,
        contentKey: bytes,
        nonceBase: bytes,
        fileName: str,
        fileSize: int,
        tagStorage,
        chunkSize,
        startChunkIndex=0,
        saveTags=True,
        streamId="global"
    ):
        """Initialize stream encryptor

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes)
            fileName: Original filename
            fileSize: Original file size
            tagStorage: Tag storage object with save() method
            chunkSize: Plaintext size for each authenticated encryption chunk
            startChunkIndex: Starting chunk index (for Range support)
            saveTags: Whether to save tags (False for unaligned Range requests)
            streamId: Stream identifier for tag storage (default: "global")
        """
        self.contentKey = contentKey
        self.nonceBase = nonceBase
        self.fileName = fileName
        self.fileSize = fileSize
        self.tagStorage = tagStorage
        self.chunkSize = chunkSize
        self.chunkIndex = startChunkIndex
        self.saveTags = saveTags
        self.streamId = streamId

        self.crypto = CryptoInterface()
        self.aesgcm = self.crypto.createAESGCM(contentKey)

    def buildReader(self, sourceReader):
        """Build a reader that preserves the encryption chunk boundaries."""
        return E2EEChunkReader(sourceReader, self.chunkSize)

    def encryptChunk(self, plaintext: bytes) -> bytes:
        """Encrypt a chunk and store its tag separately

        Args:
            plaintext: Plaintext chunk data

        Returns:
            Ciphertext only (tag stored separately)
        """
        nonce = CryptoHelper.buildNonce(self.nonceBase, self.chunkIndex)
        aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, self.chunkIndex, useStructFormat=True)

        # Encrypt with AES-GCM
        _, ciphertextWithTag = self.crypto.encryptAESGCM(self.aesgcm, plaintext, nonce, aad)

        # Split ciphertext and tag
        ciphertext = ciphertextWithTag[:-16]
        tag = ciphertextWithTag[-16:]

        # Store tag if save_tags is True (prevents unaligned Range from polluting)
        if self.saveTags:
            self.tagStorage.save(self.streamId, self.chunkIndex, tag)

        # Increment chunk index for next call
        self.chunkIndex += 1

        return ciphertext


class StreamDecryptor:
    """Stream decryptor for HTTP downloads - compatible with PAKE project

    Decrypts chunks using separately fetched tags.

    IMPORTANT: Uses struct-format AAD (useStructFormat=True). This decryptor expects
    tags from HTTP mode (StreamEncryptor). Do NOT use with WebRTC mode tags.
    """

    def __init__(self, contentKey: bytes, nonceBase: bytes, fileName: str, fileSize: int):
        """Initialize stream decryptor

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes)
            fileName: Original filename
            fileSize: Original file size
        """
        self.contentKey = contentKey
        self.nonceBase = nonceBase
        self.fileName = fileName
        self.fileSize = fileSize

        self.crypto = CryptoInterface()

    def decryptChunk(self, chunkIndex: int, ciphertext: bytes, tag: bytes) -> bytes:
        """Decrypt a chunk with its tag

        Args:
            chunkIndex: Chunk index
            ciphertext: Ciphertext data
            tag: GCM authentication tag (16 bytes)

        Returns:
            Plaintext bytes
        """
        nonce = CryptoHelper.buildNonce(self.nonceBase, chunkIndex)
        aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, chunkIndex, useStructFormat=True)
        ciphertextWithTag = ciphertext + tag

        # Debug logging
        logger.debug(
            f"[E2EE] decryptChunk: chunkIndex={chunkIndex}, fileName={self.fileName!r}, "
            f"fileSize={self.fileSize}, nonceBase={self.nonceBase.hex()[:16]}..., tag={tag.hex()[:16]}..., "
            f"ciphertext_len={len(ciphertext)}"
        )
        logger.debug(f"[E2EE] decryptChunk: nonce={nonce.hex()}, aad_len={len(aad)}, aad={aad.hex()[:32]}...")

        plaintext = self.crypto.decryptAESGCM(self.contentKey, nonce, ciphertextWithTag, aad)

        plaintextHash = hashlib.sha256(plaintext).hexdigest()[:16]
        logger.debug(f"[E2EE] decryptChunk: plaintext_len={len(plaintext)}, "
                     f"plaintext_hash={plaintextHash}...")

        return plaintext


# ============================================================================
# Server-side Manager
# ============================================================================


class E2EEManager:
    """Manager for E2E encryption operations - per-session instance

    Ensures all clients for a given session receive the same content key (Kc)
    wrapped with their individual public keys (Ki). Each session gets its own
    E2EEManager instance to prevent cross-session key leakage.
    """

    def __init__(self, chunkSize):
        self.chunkSize = chunkSize
        self.encryptionMetaStorage = EncryptionMetaStorage()
        self.crypto = CryptoInterface()

        # Generate content key and nonce base (only once for all clients!)
        self.contentKey = os.urandom(32) # AES-256 key (Kc)
        self.nonceBase = os.urandom(12) # GCM nonce base

        logger.debug(
            f"[E2EE] Generated keys - contentKey={len(self.contentKey)} bytes, nonceBase={len(self.nonceBase)} bytes"
        )

    def handleInit(self, clientPublicKeyPEM, fileName, fileSize):
        """Handle E2EE initialization request from client

        Wraps the existing content key with the client's public key.
        All clients receive the SAME content key (Kc), just encrypted differently.

        Args:
            clientPublicKeyPEM: Client's RSA public key in PEM format string
            fileName: Original filename
            fileSize: Original file size

        Returns:
            dict: Response with encrypted content key, nonce base, and commitment tag
        """
        logger.debug(f"[E2EE] handleInit called for file={fileName}, size={fileSize}")
        normalizedFileSize = CryptoHelper.normalizeFileSize(fileSize)

        # Load client's public key
        clientPublicKey = self.crypto.loadRSAPublicKeyFromPEM(clientPublicKeyPEM)

        # Encrypt content key with client's public key using RSA-OAEP
        encryptedContentKey = self.crypto.encryptRSAOAEP(clientPublicKey, self.contentKey)

        # Encrypt nonce base with client's public key using RSA-OAEP
        encryptedNonceBase = self.crypto.encryptRSAOAEP(clientPublicKey, self.nonceBase)

        # Generate commitment tag using shared helper
        commitment = CryptoHelper.buildCommitment(
            self.contentKey, self.chunkSize, normalizedFileSize, fileName, self.crypto
        )

        return {
            'wrappedContentKey': base64.b64encode(encryptedContentKey).decode(),
            'nonceBase': base64.b64encode(encryptedNonceBase).decode(),
            'fileName': fileName,
            'fileSize': normalizedFileSize,
            'chunkSize': self.chunkSize,
            'commitment': base64.b64encode(commitment).decode(),
        }

    def createEncryptor(self, fileName, fileSize, startChunkIndex=0, saveTags=True, streamId="global"):
        """Create a stream encryptor for HTTP downloads

        Args:
            fileName: Original filename
            fileSize: Original file size
            startChunkIndex: Starting chunk index (for Range support)
            saveTags: Whether to save tags (False for unaligned Range requests)
            streamId: Stream identifier for tag storage (default: "global")

        Returns:
            StreamEncryptor: Configured stream encryptor instance
        """
        if not self.contentKey or not self.nonceBase:
            raise RuntimeError("E2EE not initialized - call handleInit() first")

        normalizedFileSize = CryptoHelper.normalizeFileSize(fileSize)
        return StreamEncryptor(
            self.contentKey, self.nonceBase, fileName, normalizedFileSize, self.encryptionMetaStorage, self.chunkSize,
            startChunkIndex, saveTags, streamId
        )

    def getTags(self, streamId):
        """Get encryption tags for a stream

        Args:
            streamId: Stream identifier

        Returns:
            list: Sorted list of tag metadata
        """
        return self.encryptionMetaStorage.load(streamId)

    def getContext(self, fileName, fileSize):
        """Get E2EE context for encryption operations

        Args:
            fileName: Original filename
            fileSize: Original file size

        Returns:
            dict: E2EE context with contentKey, nonceBase, fileName, fileSize, chunkSize
            None: If E2EE not initialized
        """
        if not self.contentKey or not self.nonceBase:
            return None

        normalizedFileSize = CryptoHelper.normalizeFileSize(fileSize)
        return {
            'contentKey': self.contentKey,
            'nonceBase': self.nonceBase,
            'fileName': fileName,
            'fileSize': normalizedFileSize,
            'chunkSize': self.chunkSize
        }

    def createWebRTCEncryptor(self, fileName, fileSize, startChunkIndex=0):
        """Create WebRTC stream encryptor for sending encrypted data

        Args:
            fileName: Original filename
            fileSize: Original file size
            startChunkIndex: Starting chunk index (for resume support)

        Returns:
            WebRTCStreamEncryptor instance
        """
        keyStatus = 'SET' if self.contentKey else 'NONE'
        nonceStatus = 'SET' if self.nonceBase else 'NONE'
        logger.debug(f"[E2EE] createWebRTCEncryptor called - "
                     f"contentKey={keyStatus}, nonceBase={nonceStatus}")

        if not self.contentKey or not self.nonceBase:
            hasKey = self.contentKey is not None
            hasNonce = self.nonceBase is not None
            logger.error(f"[E2EE] E2EE not initialized - "
                         f"contentKey={hasKey}, nonceBase={hasNonce}")
            raise RuntimeError("E2EE not initialized - call handleInit() first")

        normalizedFileSize = CryptoHelper.normalizeFileSize(fileSize)
        return WebRTCStreamEncryptor(
            contentKey=self.contentKey,
            nonceBase=self.nonceBase,
            fileName=fileName,
            fileSize=normalizedFileSize,
            chunkSize=self.chunkSize,
            startChunkIndex=startChunkIndex
        )


# ============================================================================
# Client-side Handler
# ============================================================================


class E2EEClient:
    """Client-side E2E encryption handler for downloads"""

    def __init__(self, buildURLCallback: Callable, makeHeadersCallback: Callable):
        """Initialize E2EE client

        Args:
            buildURLCallback: Callback to build URLs (baseURL, path) -> url
            makeHeadersCallback: Callback to create HTTP headers (credentials) -> headers dict
        """
        self.buildURL = buildURLCallback
        self.makeHeaders = makeHeadersCallback
        self.crypto = CryptoInterface()

        # Upload mode E2EE data (populated by checkManifest for upload mode)
        self._embeddedTags = []
        self._embeddedNonceBase = None
        self._embeddedCommitment = None

    def extractEmbeddedE2EEData(self, baseURL: str) -> Optional[dict]:
        """Extract embedded E2EE data from upload page HTML

        For upload mode E2EE, the server embeds all E2EE data (manifest + tags)
        in the HTML page as EMBEDDED_E2EE_DATA (compressed JSON).

        Args:
            baseURL: Base URL of the share

        Returns:
            dict with 'manifest', 'tags', 'nonceBase', 'commitment' if found, None otherwise
        """
        try:
            # Fetch the download page HTML (remove trailing slash for index page)
            pageURL = baseURL.rstrip('/')
            response = requests.get(pageURL, headers=self.makeHeaders(None), timeout=10)
            if response.status_code != 200:
                logger.debug(f"[E2EE] Failed to fetch page: HTTP {response.status_code}")
                return None

            html = response.text

            # Extract EMBEDDED_E2EE_DATA from JavaScript
            # Pattern: const EMBEDDED_E2EE_DATA = "base64string";
            match = re.search(r'EMBEDDED_E2EE_DATA\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', html)
            if not match:
                logger.debug("[E2EE] No EMBEDDED_E2EE_DATA found in page")
                return None

            compressedB64 = match.group(1)
            logger.debug(f"[E2EE] Found EMBEDDED_E2EE_DATA ({len(compressedB64)} bytes)")

            # Decode base64 and decompress (same as pako.inflate in JS)
            compressedData = base64.b64decode(compressedB64)
            decompressed = zlib.decompress(compressedData)
            # Parse JSON properly (not eval - would fail on JavaScript true/false/null)
            e2eeData = json.loads(decompressed.decode('utf-8'))

            manifestKeys = list(e2eeData.get('manifest', {}).keys())
            tagsCount = len(e2eeData.get('tags', []))
            logger.debug(
                f"[E2EE] Decompressed embedded data: "
                f"manifest keys={manifestKeys}, tags count={tagsCount}"
            )

            return e2eeData

        except requests.exceptions.HTTPError as e:
            logger.debug(f"[E2EE] HTTP error fetching page: {e}")
            return None
        except (ValueError, KeyError) as e:
            logger.debug(f"[E2EE] Invalid embedded data format: {e}")
            return None

    def checkManifest(self, baseURL: str, isUploadMode: bool = False) -> Optional[dict]:
        """Check if E2E encryption is enabled

        For upload mode: Extract embedded E2EE data from page HTML
        For P2P mode: Fetch /e2ee/manifest endpoint

        Args:
            baseURL: Base URL of the share
            isUploadMode: True if this is an uploaded file (not P2P)

        Returns:
            E2EE manifest dict if E2EE is enabled, None otherwise
        """
        # For upload mode, extract embedded data from HTML page
        if isUploadMode:
            logger.debug(f"[E2EE] Upload mode - extracting embedded E2EE data from page")
            embeddedData = self.extractEmbeddedE2EEData(baseURL)
            if embeddedData and 'manifest' in embeddedData:
                # Store tags and other data for later use
                self._embeddedTags = embeddedData.get('tags', [])
                self._embeddedNonceBase = embeddedData.get('nonceBase')
                self._embeddedCommitment = embeddedData.get('commitment')
                logger.debug(f"[E2EE] Upload mode E2EE enabled - {len(self._embeddedTags)} tags embedded")
                return embeddedData['manifest']
            return None

        # For P2P mode, use /e2ee/manifest endpoint
        try:
            manifestURL = self.buildURL(baseURL, "/e2ee/manifest")
            logger.debug(f"[E2EE] Checking manifest at: {manifestURL}")

            response = requests.get(manifestURL, headers=self.makeHeaders(None), timeout=5)
            logger.debug(f"[E2EE] Manifest response: status={response.status_code}")

            if response.status_code == 404:
                logger.debug(f"[E2EE] Manifest endpoint returned 404 - E2EE not enabled")
                return None

            if response.status_code == 200:
                manifest = response.json()
                logger.debug(f"[E2EE] Manifest data: {manifest}")
                if manifest.get('e2eeEnabled'):
                    logger.debug(f"[E2EE] E2E encryption is ENABLED")
                    return manifest
                else:
                    logger.debug(f"[E2EE] E2E encryption DISABLED in manifest (e2eeEnabled=False)")

            logger.debug(f"[E2EE] No valid manifest found")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"[E2EE] Manifest check failed (network error or endpoint doesn't exist): {e}")
            return None

    def performKeyExchange(self, baseURL: str, manifest: dict) -> dict:
        """Perform E2EE key exchange with server using RSA envelope encryption

        Args:
            baseURL: Base URL of the share
            manifest: E2EE manifest from server

        Returns:
            E2EE context dict with contentKey, nonceBase, fileName, fileSize, chunkSize

        Raises:
            RuntimeError: If key exchange fails or commitment verification fails
        """
        # Generate RSA key pair for client
        privateKey, publicKey = self.crypto.generateRSAKeyPair(2048)
        publicKeyPem = self.crypto.serializeRSAPublicKey(publicKey)

        # Send public key to server and receive wrapped content key
        initURL = self.buildURL(baseURL, "/e2ee/init")
        headers = self.makeHeaders(None)
        headers["Content-Type"] = "application/json"

        response = requests.post(initURL, json={"publicKey": publicKeyPem}, headers=headers, timeout=10)

        if response.status_code != 200:
            raise RuntimeError(f"E2EE key exchange failed: HTTP {response.status_code}")

        initData = response.json()

        # Extract wrapped key, nonce base, and commitment
        wrappedKcB64 = initData.get('wrappedContentKey')
        nonceBaseB64 = initData.get('nonceBase')
        commitmentB64 = initData.get('commitment')

        if not wrappedKcB64 or not nonceBaseB64 or not commitmentB64:
            raise RuntimeError("E2EE init response missing required fields")

        # Decode base64
        wrappedKc = base64.b64decode(wrappedKcB64)
        wrappedNonceBase = base64.b64decode(nonceBaseB64)
        commitment = base64.b64decode(commitmentB64)

        # Unwrap content key and nonce base using RSA private key
        contentKey = self.crypto.decryptRSAOAEP(privateKey, wrappedKc)
        nonceBase = self.crypto.decryptRSAOAEP(privateKey, wrappedNonceBase)

        # Verify commitment tag using shared helper
        fileName = manifest['fileName']
        fileSize = CryptoHelper.normalizeFileSize(manifest['fileSize'])
        chunkSize = manifest['chunkSize']

        if not CryptoHelper.verifyCommitment(contentKey, commitment, chunkSize, fileSize, fileName, self.crypto):
            raise RuntimeError("E2EE commitment verification failed - possible MITM attack")

        return {
            'contentKey': contentKey,
            'nonceBase': nonceBase,
            'fileName': fileName,
            'fileSize': fileSize,
            'chunkSize': chunkSize,
            'baseURL': baseURL # Include baseURL for tag fetching
        }

    def createHTTPDecryptor(self, context: dict, resumePosition: int = 0) -> 'HTTPStreamDecryptor':
        """Create HTTP stream decryptor with on-demand tag fetching or embedded tags

        Args:
            context: E2EE context from performKeyExchange()
            resumePosition: Byte position to resume from (default: 0)

        Returns:
            HTTPStreamDecryptor instance
        """
        # The server always encrypts/sends the full chunkSize-aligned chunk
        # containing resumePosition (see CryptoHelper.alignChunkStart), so the
        # decryptor must start at that same aligned chunk index and discard the
        # leading bytes the resume didn't actually ask for.
        chunkSize = context['chunkSize']
        alignedStart, discardLeading = CryptoHelper.alignChunkStart(resumePosition, chunkSize)
        startChunkIndex = alignedStart // chunkSize

        # Check if we have embedded tags from upload mode
        if self._embeddedTags:
            logger.debug(f"[E2EE] Using embedded tags for HTTP decryptor ({len(self._embeddedTags)} tags)")

            # Create HTTPStreamDecryptor with pre-populated tag map
            decryptor = HTTPStreamDecryptor(
                contentKey=context['contentKey'],
                nonceBase=context['nonceBase'],
                fileName=context['fileName'],
                fileSize=context['fileSize'],
                chunkSize=context['chunkSize'],
                tagFetcher=None, # No fetching needed
                startChunkIndex=startChunkIndex,
                discardLeading=discardLeading
            )

            # Pre-populate tag map from embedded data
            for tagEntry in self._embeddedTags:
                decryptor.tagMap[tagEntry['chunkIndex']] = base64.b64decode(tagEntry['tag'])

            return decryptor

        # P2P mode - use tag fetcher with /e2ee/tags endpoint
        baseURL = context.get('baseURL')
        if not baseURL:
            raise ValueError("baseURL not found in E2EE context")

        def tagFetcher(startChunk: int, count: int) -> list:
            return self.fetchTags(baseURL, startChunk, count)

        return HTTPStreamDecryptor(
            contentKey=context['contentKey'],
            nonceBase=context['nonceBase'],
            fileName=context['fileName'],
            fileSize=context['fileSize'],
            chunkSize=context['chunkSize'],
            tagFetcher=tagFetcher,
            startChunkIndex=startChunkIndex,
            discardLeading=discardLeading
        )

    def createWebRTCDecryptor(self, context: dict) -> 'WebRTCStreamDecryptor':
        """Create WebRTC stream decryptor

        Args:
            context: E2EE context from performKeyExchange()

        Returns:
            WebRTCStreamDecryptor instance
        """
        return WebRTCStreamDecryptor(
            contentKey=context['contentKey'],
            nonceBase=context['nonceBase'],
            fileName=context['fileName'],
            fileSize=context['fileSize']
        )

    def buildE2EEContext(self, baseURL: str, isUploadMode: bool, contentKey: bytes = None) -> Optional[dict]:
        """Build E2EE context for download (handles both upload and P2P modes)

        Args:
            baseURL: Base URL of the share
            isUploadMode: True for upload mode (zero-knowledge), False for P2P mode
            contentKey: User-provided encryption key (required for upload mode, ignored for P2P)

        Returns:
            E2EE context dict if E2EE is enabled, None if E2EE is not enabled

        Raises:
            RuntimeError: If manifest is invalid or key verification fails
        """
        # Check if E2EE is enabled
        manifest = self.checkManifest(baseURL, isUploadMode=isUploadMode)
        if not manifest:
            return None

        if isUploadMode:
            # Upload mode: Use client-provided key (zero-knowledge)
            if not contentKey:
                raise ValueError("contentKey is required for upload mode")
            return self.buildUploadModeContext(manifest, contentKey, baseURL)
        else:
            # P2P mode: Perform RSA key exchange with server
            return self.performKeyExchange(baseURL, manifest)

    def buildUploadModeContext(self, manifest: dict, contentKey: bytes, baseURL: str) -> dict:
        """Build E2EE context for upload mode

        Upload mode uses client-generated encryption key (zero-knowledge server).
        The key is shared out-of-band with recipients.

        Args:
            manifest: E2EE manifest from checkManifest(isUploadMode=True)
            contentKey: User-provided encryption key (32 bytes)
            baseURL: Base URL for the share

        Returns:
            E2EE context dict with contentKey, nonceBase, fileName, fileSize, chunkSize, baseURL

        Raises:
            RuntimeError: If embedded data is invalid or key verification fails
        """
        # Validate embedded data
        if not self._embeddedNonceBase:
            raise RuntimeError("E2EE embedded data missing nonceBase for upload mode")

        # Decode nonce base
        nonceBase = base64.b64decode(self._embeddedNonceBase)

        # Get fileName from manifest (required for AAD verification)
        fileName = manifest.get('fileName')
        if not fileName:
            raise RuntimeError("E2EE manifest missing fileName (required for AAD verification)")

        # Build context
        context = {
            'contentKey': contentKey,
            'nonceBase': nonceBase,
            'fileName': fileName,
            'fileSize': manifest['fileSize'],
            'chunkSize': manifest['chunkSize'],
            'baseURL': baseURL
        }

        # Commitment verification is mandatory, not opportunistic: it's the only
        # thing that stops a tampered page (with a substituted contentKey/manifest)
        # from silently succeeding. A missing commitment must fail closed, not be
        # treated as "nothing to verify".
        if not self._embeddedCommitment:
            raise RuntimeError("E2EE embedded data missing commitment - cannot verify encryption key")

        if not self.verifyUploadModeKey(
            contentKey, self._embeddedCommitment, context['chunkSize'], context['fileSize'], context['fileName']
        ):
            raise RuntimeError("Encryption key verification failed - incorrect key provided")

        return context

    def verifyUploadModeKey(
        self, contentKey: bytes, commitment: bytes, chunkSize: int, fileSize: int, fileName: str
    ) -> bool:
        """Verify encryption key against commitment for upload mode

        Args:
            contentKey: Content key provided by user (32 bytes)
            commitment: Commitment tag from server (base64-encoded string or bytes)
            chunkSize: Chunk size from manifest
            fileSize: File size from manifest
            fileName: Filename from manifest

        Returns:
            True if key is valid, False otherwise
        """
        # Handle commitment as either base64 string or raw bytes
        if isinstance(commitment, str):
            commitmentBytes = base64.b64decode(commitment)
        else:
            commitmentBytes = commitment

        return CryptoHelper.verifyCommitment(contentKey, commitmentBytes, chunkSize, fileSize, fileName, self.crypto)

    def fetchTags(self, baseURL: str, startChunk: int, count: int) -> list:
        """Fetch encryption tags from server

        Args:
            baseURL: Base URL of the share
            startChunk: Starting chunk index
            count: Number of tags to fetch

        Returns:
            List of tag dicts with chunkIndex and tag (base64)

        Raises:
            RuntimeError: If tag fetching fails
        """
        tagsURL = self.buildURL(baseURL, "/e2ee/tags")
        params = {'start': startChunk, 'count': count}

        logger.debug(f"[E2EE] fetchTags: startChunk={startChunk}, count={count}, tagsURL={tagsURL}")

        response = requests.get(tagsURL, params=params, headers=self.makeHeaders(None), timeout=10)

        logger.debug(f"[E2EE] fetchTags: status={response.status_code}, final_url={response.url}")

        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch E2EE tags: HTTP {response.status_code}")

        data = response.json()
        return data.get('tags', [])


# ============================================================================
# Stream Handlers
# ============================================================================


class WebRTCStreamHandler:
    """Base class for WebRTC stream processing (encryption/decryption)"""

    def processChunk(self, data: bytes) -> bytes:
        """Process a chunk of data

        Args:
            data: Raw chunk data

        Returns:
            Processed chunk data
        """
        raise NotImplementedError("Subclass must implement processChunk()")

    def flush(self) -> bytes:
        """Flush any remaining buffered data

        Returns:
            Any remaining processed data, or empty bytes if none
        """
        return b''


class WebRTCStreamEncryptor(WebRTCStreamHandler):
    """WebRTC stream encryptor - encrypts and frames chunks for transmission"""

    def __init__(
        self, contentKey: bytes, nonceBase: bytes, fileName: str, fileSize: int, chunkSize: int, startChunkIndex=0
    ):
        """Initialize WebRTC stream encryptor

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes)
            fileName: Original filename
            fileSize: Original file size
            chunkSize: Chunk size for encryption
            startChunkIndex: Starting chunk index (for resume support) -- must
                match the chunk index the resumed byte offset actually falls
                on, or the same (key, nonceBase, chunkIndex) triple ends up
                encrypting two different plaintext windows across attempts
                (see CryptoHelper.alignChunkStart for the HTTP-side version of
                this same nonce-reuse hazard).
        """
        self.framer = E2EEFramer(contentKey, nonceBase, chunkSize, fileName, fileSize)
        self.chunkIndex = startChunkIndex

    def processChunk(self, data: bytes) -> bytes:
        """Encrypt and frame a chunk

        Args:
            data: Plaintext chunk data

        Returns:
            Encrypted TLV frame
        """
        frame = self.framer.packFrame(self.chunkIndex, data)
        self.chunkIndex += 1
        return frame


class WebRTCStreamDecryptor(WebRTCStreamHandler):
    """WebRTC stream decryptor - unframes and decrypts chunks from transmission"""

    def __init__(self, contentKey: bytes, nonceBase: bytes, fileName: str, fileSize: int):
        """Initialize WebRTC stream decryptor

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes)
            fileName: Original filename
            fileSize: Original file size
        """
        self.unframer = E2EEUnframer(contentKey, nonceBase, fileName, fileSize)
        self.frameBuffer = b''

    def processChunk(self, data: bytes) -> bytes:
        """Accumulate and unframe encrypted chunks

        Args:
            data: Encrypted frame data (may be partial)

        Returns:
            Decrypted plaintext data (may be empty if frame incomplete)
        """
        logger.debug(
            f"[E2EE] WebRTCStreamDecryptor.processChunk: "
            f"received {len(data)} bytes, buffer has {len(self.frameBuffer)} bytes"
        )
        self.frameBuffer += data
        plaintext = b''
        framesProcessed = 0

        # Try to unpack complete frames from buffer
        while len(self.frameBuffer) >= E2EEFramerBase.HEADER_SIZE:
            # Validate magic/version/cipherLen bound before trusting cipherLen to
            # decide how much more data to wait for -- an untrusted peer's bogus,
            # huge cipherLen would otherwise grow frameBuffer without bound while
            # waiting for a frame that will never complete.
            _, cipherLen, _ = E2EEFramerBase.parseHeader(self.frameBuffer)
            frameSize = E2EEFramerBase.HEADER_SIZE + cipherLen
            bufferLen = len(self.frameBuffer)
            logger.debug(
                f"[E2EE] Frame header parsed: cipherLen={cipherLen}, "
                f"frameSize={frameSize}, bufferLen={bufferLen}"
            )

            if len(self.frameBuffer) >= frameSize:
                # Extract complete frame
                frame = self.frameBuffer[:frameSize]
                self.frameBuffer = self.frameBuffer[frameSize:]

                # Decrypt frame
                chunkIndex, decryptedChunk = self.unframer.unpackFrame(frame)
                plaintext += decryptedChunk
                framesProcessed += 1
                logger.debug(f"[E2EE] Decrypted frame {chunkIndex}: {len(decryptedChunk)} bytes plaintext")
            else:
                # Need more data
                logger.debug(f"[E2EE] Incomplete frame: need {frameSize} bytes, have {len(self.frameBuffer)} bytes")
                break

        remainingBytes = len(self.frameBuffer)
        logger.debug(
            f"[E2EE] processChunk complete: processed {framesProcessed} frames, "
            f"returning {len(plaintext)} bytes plaintext, {remainingBytes} bytes remain in buffer"
        )
        return plaintext

    def flush(self) -> bytes:
        """Process any remaining data in buffer

        Returns:
            Any remaining decrypted data

        Raises:
            RuntimeError: If incomplete frame remains in buffer (data corruption/truncation)
        """
        logger.debug(f"[E2EE] WebRTCStreamDecryptor.flush() called with {len(self.frameBuffer)} bytes in buffer")

        if self.frameBuffer:
            bufferLen = len(self.frameBuffer)
            logger.debug(f"[E2EE] flush: buffer has {bufferLen} bytes, checking for incomplete frames...")

            # If buffer has partial header, it's incomplete
            if bufferLen < E2EEFramerBase.HEADER_SIZE:
                logger.error(
                    f"[E2EE] flush: INCOMPLETE FRAME - partial header ({bufferLen} < {E2EEFramerBase.HEADER_SIZE})"
                )
                raise RuntimeError(
                    f"Incomplete frame at end-of-stream: {bufferLen} bytes remaining "
                    f"(minimum {E2EEFramerBase.HEADER_SIZE} bytes required for header). "
                    f"Data may be truncated or corrupted."
                )

            # Parse header to check expected frame size
            try:
                _, cipherLen, _ = E2EEFramerBase.parseHeader(self.frameBuffer)
                expectedFrameSize = E2EEFramerBase.HEADER_SIZE + cipherLen
                logger.debug(
                    f"[E2EE] flush: parsed header - cipherLen={cipherLen}, expectedFrameSize={expectedFrameSize}"
                )

                # Only raise error if we have incomplete frame
                if bufferLen < expectedFrameSize:
                    logger.error(
                        f"[E2EE] flush: INCOMPLETE FRAME - partial ciphertext ({bufferLen} < {expectedFrameSize})"
                    )
                    raise RuntimeError(
                        f"Incomplete frame at end-of-stream: {bufferLen} bytes remaining, "
                        f"expected {expectedFrameSize} bytes for complete frame. "
                        f"Data may be truncated or corrupted."
                    )

                # If we reach here, we have complete frame(s) that weren't processed
                # This should not happen in normal flow (processChunk should handle it)
                logger.warning(
                    f"[E2EE] flush: Complete frame(s) in buffer at flush: {bufferLen} bytes "
                    f"(expected {expectedFrameSize} bytes). Processing now..."
                )
                # Let processChunk handle it (should not happen, but handle gracefully)
                result = self.processChunk(b'')
                logger.debug(
                    f"[E2EE] flush: processChunk returned {len(result)} bytes after processing buffered frames"
                )
                return result

            except (struct.error, ValueError) as e:
                logger.error(f"[E2EE] flush: MALFORMED HEADER: {e}")
                raise RuntimeError(
                    f"Malformed frame header at end-of-stream: {bufferLen} bytes remaining, "
                    f"failed to parse header: {e}"
                )

        logger.debug("[E2EE] flush: buffer empty, returning empty bytes")
        return b''


class HTTPStreamDecryptor(WebRTCStreamHandler):
    """HTTP stream decryptor - handles chunk buffering, tag lookup, and decryption for HTTP downloads"""

    def __init__(
        self,
        contentKey: bytes,
        nonceBase: bytes,
        fileName: str,
        fileSize: int,
        chunkSize: int,
        tagFetcher,
        startChunkIndex: int = 0,
        discardLeading: int = 0
    ):
        """Initialize HTTP stream decryptor

        Args:
            contentKey: AES-256 content key (32 bytes)
            nonceBase: Nonce base for GCM (12 bytes)
            fileName: Original filename
            fileSize: Original file size
            chunkSize: Encryption chunk size
            tagFetcher: Callable(startChunk, count) -> list of tag dicts
            startChunkIndex: Starting chunk index for resume (default: 0)
            discardLeading: Leading plaintext bytes of the first decrypted chunk
                to discard -- the server always encrypts/sends the full
                chunkSize-aligned chunk containing a resumed Range's start (a
                partial GCM block can't be tag-verified), so an unaligned
                resume gets a few extra bytes at the front that must be
                dropped after decryption, before the caller sees "new" data.
        """
        self.decryptor = StreamDecryptor(contentKey, nonceBase, fileName, fileSize)
        self.chunkSize = chunkSize
        self.chunkBuffer = b''
        self.currentChunkIndex = startChunkIndex
        self.tagFetcher = tagFetcher
        self._discardLeading = discardLeading

        # Tag cache for fetched tags
        self.tagMap = {}
        self.tagBatchSize = 100 # Fetch 100 tags at a time

    def _applyDiscard(self, plaintext: bytes) -> bytes:
        """Trim any still-pending Range-alignment discard off newly decrypted plaintext."""
        if self._discardLeading <= 0:
            return plaintext

        if len(plaintext) <= self._discardLeading:
            self._discardLeading -= len(plaintext)
            return b''

        trimmed = plaintext[self._discardLeading:]
        self._discardLeading = 0
        return trimmed

    def _fetchTagsIfNeeded(self, chunkIndex: int):
        """Fetch tags from server if not in cache"""
        if chunkIndex not in self.tagMap:
            # If no tag fetcher (upload mode with embedded tags), tag must already be in map
            if self.tagFetcher is None:
                return # Tag should already be in tagMap from embedded data

            # Fetch a batch of tags starting from this chunk
            tags = self.tagFetcher(chunkIndex, self.tagBatchSize)
            # Cache all fetched tags
            for tagEntry in tags:
                self.tagMap[tagEntry['chunkIndex']] = base64.b64decode(tagEntry['tag'])

    def processChunk(self, data: bytes) -> bytes:
        """Accumulate and decrypt chunks with tag lookup

        Args:
            data: Encrypted chunk data (may be partial or multiple chunks)

        Returns:
            Decrypted plaintext data
        """
        self.chunkBuffer += data
        plaintext = b''

        # Process complete encrypted chunks
        while len(self.chunkBuffer) >= self.chunkSize:
            encryptedChunk = self.chunkBuffer[:self.chunkSize]
            self.chunkBuffer = self.chunkBuffer[self.chunkSize:]

            # Fetch tag if not in cache
            self._fetchTagsIfNeeded(self.currentChunkIndex)

            # Get tag for this chunk
            tag = self.tagMap.get(self.currentChunkIndex)
            if not tag:
                raise RuntimeError(f"Missing tag for chunk {self.currentChunkIndex}")

            # Decrypt chunk
            decryptedChunk = self.decryptor.decryptChunk(self.currentChunkIndex, encryptedChunk, tag)
            plaintext += decryptedChunk
            self.currentChunkIndex += 1

        return self._applyDiscard(plaintext)

    def flush(self) -> bytes:
        """Process final partial chunk in buffer

        Returns:
            Decrypted final chunk data
        """
        if self.chunkBuffer:
            # Fetch tag if not in cache
            self._fetchTagsIfNeeded(self.currentChunkIndex)

            # Get tag for final chunk
            tag = self.tagMap.get(self.currentChunkIndex)
            if not tag:
                raise RuntimeError(f"Missing tag for final chunk {self.currentChunkIndex}")

            # Decrypt final partial chunk
            plaintext = self.decryptor.decryptChunk(self.currentChunkIndex, self.chunkBuffer, tag)
            self.chunkBuffer = b''
            self.currentChunkIndex += 1
            return self._applyDiscard(plaintext)

        return b''


# ============================================================================
# Upload Encryption Support
# ============================================================================


class UploadStreamEncryptor:
    """Client-side stream encryptor for uploads - collects tags in memory

    Used for --e2ee --upload mode where client encrypts file before upload.
    Server never receives the content key - user shares it out-of-band with recipients.
    """

    def __init__(self, contentKey: bytes, nonceBase: bytes, fileName: str, fileSize: int, chunkSize: int):
        """Initialize upload stream encryptor

        Args:
            contentKey: AES-256 content key (32 bytes) - NEVER sent to server
            nonceBase: Nonce base for GCM (12 bytes) - sent to server in plaintext
            fileName: Original filename
            fileSize: Original file size
            chunkSize: Chunk size for encryption
        """
        self.contentKey = contentKey
        self.nonceBase = nonceBase
        self.fileName = fileName
        self.fileSize = fileSize
        self.chunkSize = chunkSize
        self.chunkIndex = 0
        self._tags = [] # Private: Collect tags in memory for upload
        self._tagsSorted = True # Private: Track if tags are sorted (starts True with empty list)

        self.crypto = CryptoInterface()
        self.aesgcm = self.crypto.createAESGCM(contentKey)

    def getKeyCommitment(self) -> str:
        return hashlib.sha256(self.contentKey).hexdigest()

    def encryptChunk(self, plaintext: bytes, explicitChunkIndex: int = None) -> bytes:
        """Encrypt chunk and store tag in memory

        Args:
            plaintext: Plaintext chunk data
            explicitChunkIndex: Explicit chunk index to use (for resume). If None, uses internal counter.

        Returns:
            Ciphertext only (tag stored in self.tags)
        """
        # Use explicit chunk index if provided (for resume), otherwise use internal counter
        currentChunkIndex = explicitChunkIndex if explicitChunkIndex is not None else self.chunkIndex

        # Check if we already have a tag for this chunk index (from resume)
        existingTag = next((tag for tag in self._tags if tag['chunkIndex'] == currentChunkIndex), None)
        if existingTag:
            logger.debug(f"E2EE upload: chunk {currentChunkIndex} already encrypted (using cached tag from resume)")
            # Re-encrypt to get the ciphertext (we don't store ciphertext, only tags)
            nonce = CryptoHelper.buildNonce(self.nonceBase, currentChunkIndex)
            aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, currentChunkIndex, useStructFormat=True)
            _, ciphertextWithTag = self.crypto.encryptAESGCM(self.aesgcm, plaintext, nonce, aad)
            ciphertext = ciphertextWithTag[:-16]
            return ciphertext

        nonce = CryptoHelper.buildNonce(self.nonceBase, currentChunkIndex)
        aad = CryptoHelper.buildAAD(self.fileName, self.fileSize, currentChunkIndex, useStructFormat=True)

        # Debug logging
        nonceHex = self.nonceBase.hex()[:16]
        logger.debug(
            f"[E2EE] encryptChunk: chunkIndex={currentChunkIndex}, fileName={self.fileName!r}, "
            f"fileSize={self.fileSize}, nonceBase={nonceHex}..., plaintext_len={len(plaintext)}"
        )
        logger.debug(f"[E2EE] encryptChunk: nonce={nonce.hex()}, aad_len={len(aad)}, aad={aad.hex()[:32]}...")

        # Encrypt with AES-GCM
        _, ciphertextWithTag = self.crypto.encryptAESGCM(self.aesgcm, plaintext, nonce, aad)

        # Split ciphertext and tag
        ciphertext = ciphertextWithTag[:-16]
        tag = ciphertextWithTag[-16:]

        tagHex = tag.hex()[:16]
        ciphertextHash = hashlib.sha256(ciphertext).hexdigest()[:16]
        logger.debug(
            f"[E2EE] encryptChunk: tag={tagHex}..., ciphertext_len={len(ciphertext)}, "
            f"ciphertext_hash={ciphertextHash}..."
        )

        # Store tag with chunkIndex (for server upload)
        self._tags.append({'chunkIndex': currentChunkIndex, 'tag': base64.b64encode(tag).decode()})

        # Invalidate sorted cache when appending new tag
        self._tagsSorted = False

        # Only increment internal counter if we didn't use explicit index
        if explicitChunkIndex is None:
            self.chunkIndex += 1

        return ciphertext

    @property
    def tags(self) -> list:
        """Return all collected tags for upload to server, sorted by chunkIndex

        Tags are sorted on first access after modification and cached for subsequent calls.
        This ensures frontend always receives tags in correct order.

        Returns:
            List of tag dicts sorted by chunkIndex: [{'chunkIndex': 0, 'tag': 'base64...'}, ...]
        """
        if not self._tagsSorted:
            # Sort tags by chunkIndex
            self._tags.sort(key=lambda t: t['chunkIndex'])
            self._tagsSorted = True
            logger.debug(f"E2EE upload: sorted {len(self._tags)} tags by chunkIndex")

        return self._tags

    @tags.setter
    def tags(self, value: list):
        """Set tags (used when restoring from resume state)

        Automatically invalidates sorted cache when tags are set externally.

        Args:
            value: List of tag dicts to set
        """
        self._tags = value
        self._tagsSorted = False # Invalidate sorted cache when tags are set externally

    def getContentKeyBase64(self) -> str:
        """Return content key as base64 for user display

        This is shown to the user after upload for sharing with recipients.

        Returns:
            Base64-encoded content key
        """
        return base64.b64encode(self.contentKey).decode()

    def getNonceBaseBase64(self) -> str:
        """Return nonce base as base64 (sent to server in plaintext)

        Returns:
            Base64-encoded nonce base
        """
        return base64.b64encode(self.nonceBase).decode()

    def buildCommitment(self) -> str:
        """Build commitment tag for key verification

        Commitment is sent to server and used by recipients to verify the
        user-provided encryption key is correct.

        Returns:
            Base64-encoded commitment tag
        """
        commitment = CryptoHelper.buildCommitment(
            self.contentKey, self.chunkSize, self.fileSize, self.fileName, self.crypto
        )
        return base64.b64encode(commitment).decode()

    def getTagForChunk(self, chunkNumber: int) -> dict:
        """Get authentication tag for a specific chunk

        Args:
            chunkNumber: Chunk number (1-based, as used in upload logic)

        Returns:
            Tag dict with 'chunkIndex' and 'tag' keys, or None if not found
        """
        encryptionIndex = chunkNumber - 1
        return next((tag for tag in self._tags if tag['chunkIndex'] == encryptionIndex), None)


class E2EEUploadHelper:
    """Helper utilities for E2EE upload operations"""

    SEPARATE_LINE_WIDTH = 67 # 70 makes Apple version with 2 == in newline.

    @staticmethod
    def generateKeys() -> tuple:
        """Generate content key and nonce base for upload encryption

        Returns:
            tuple: (contentKey, nonceBase) - both as bytes
        """
        contentKey = os.urandom(32) # AES-256 key
        nonceBase = os.urandom(12) # GCM nonce base
        return contentKey, nonceBase

    @staticmethod
    def getKeyCommitment(contentKey) -> str:
        return hashlib.sha256(contentKey).hexdigest()

    @staticmethod
    def formatKeyForDisplay(contentKey: bytes) -> str:
        """Format encryption key for user display

        Args:
            contentKey: AES-256 content key (32 bytes)

        Returns:
            Base64-encoded key for display/sharing
        """
        return base64.b64encode(contentKey).decode()

    @staticmethod
    def formatKeyWarning() -> str:
        """Return warning message for user about key security

        Returns:
            Formatted warning message string
        """
        lines = [
            "",
            "=" * E2EEUploadHelper.SEPARATE_LINE_WIDTH,
            _("⚠️  IMPORTANT: ENCRYPTION KEY"),
            "=" * E2EEUploadHelper.SEPARATE_LINE_WIDTH,
            _("This file has been encrypted. You MUST share the encryption key below"),
            _("with recipients via a SECURE CHANNEL (not the same as the download link)."),
            "",
            _("Without this key, the file CANNOT be decrypted."),
            _("Note: Appending #<key> to the URL works but is less secure and not recommended."),
            "=" * E2EEUploadHelper.SEPARATE_LINE_WIDTH,
        ]
        return "\n".join(lines)

    @staticmethod
    def formatResumeComplete() -> str:
        """Return message for resumed E2EE upload completion

        Returns:
            Formatted completion message string
        """
        lines = []
        return "\n".join(lines)

    @staticmethod
    def formatEncryptionKey(encryptionKey: str) -> str:
        """Format encryption key display with separators

        Args:
            encryptionKey: Base64-encoded encryption key

        Returns:
            Formatted key display string
        """
        lines = [
            _("Encryption Key: {encryptionKey}").format(encryptionKey=encryptionKey),
            "=" * E2EEUploadHelper.SEPARATE_LINE_WIDTH,
            ""
        ]
        return "\n".join(lines)
