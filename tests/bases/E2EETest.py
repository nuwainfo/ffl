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
"""
Unit tests for E2E (end-to-end) encryption functionality.

The browser tests verify that E2E decryption works correctly in real browsers
using the JavaScript implementation (E2E.js) with both WebRTC and HTTP fallback modes.
The HTTP fallback tests use DISABLE_WEBRTC to force the browser to use Service Worker
based decryption instead of WebRTC.
"""

import os
import unittest
import hashlib
import urllib.request
import urllib.error
import requests
import json
import time

from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import serialization

from bases.crypto import CryptoInterface

from tests.CoreTestBase import getFileHash
from tests.ResumeTestBase import ResumeTestBase, ResumeBrowserTestBase
from tests.BrowserTestBase import CONCURRENT_WEBRTC_DOWNLOADS

LOG_CONFIG_UPLOAD = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'presets', 'UploadDebugLogging.json'))


class E2EEUploadTestBase:
    """Common base class for E2EE upload tests

    Provides shared functionality for tests that upload files with E2EE encryption
    and need to extract encryption keys from logs.
    """

    @staticmethod
    def _extractEncryptionKey(logText):
        """Extract encryption key from upload log text

        Args:
            logText: Log output from upload process

        Returns:
            str: Base64-encoded encryption key, or None if not found
        """
        if not logText:
            return None
        for line in logText.splitlines():
            if "Encryption Key:" in line:
                return line.split("Encryption Key:", 1)[1].strip()
        return None

    def _uploadWithE2EE(self, extraArgs=None, useTestServer=False, captureOutputIn=None):
        """Upload file with E2EE and return share link, encryption key, and optional test server process

        Args:
            extraArgs: Additional arguments to pass to upload
            useTestServer: Whether to use local test server
            captureOutputIn: Dict to capture output

        Returns:
            tuple: (shareLink, encryptionKey, testServerProcess or None)
        """
        uploadArgs = ['--e2ee', '--upload', '24 hours']
        if extraArgs:
            uploadArgs.extend(extraArgs)

        result = self._startFastFileLink(
            p2p=False, extraArgs=uploadArgs, captureOutputIn=captureOutputIn, useTestServer=useTestServer
        )

        # Extract share link and test server process from tuple
        testServerProcess = None
        if isinstance(result, tuple):
            shareLink, testServerProcess = result
        else:
            shareLink = result

        # Extract encryption key from upload output
        uploadLog = self._updateCapturedOutput(captureOutputIn)
        encryptionKey = self._extractEncryptionKey(uploadLog)
        if not encryptionKey:
            print(f"[Test] Upload log:\n{uploadLog[-2000:]}")
            raise AssertionError("Encryption key not found in upload logs")

        return shareLink, encryptionKey, testServerProcess


class E2EEDownloadTest(ResumeTestBase):
    """Test E2E encryption with HTTP download via CLI"""

    def __init__(self, methodName='runTest'):
        # Use 1MB file for E2E tests (faster)
        super().__init__(methodName, fileSizeBytes=1 * 1024 * 1024)

    def testE2EEHttpFullDownload(self):
        """Test E2E encrypted HTTP download (full file)"""
        print("\n[TEST] E2E HTTP full download")

        # Start server with E2E encryption enabled
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"], captureOutputIn=outputCapture)
        print(f"[Test] Share link with E2E: {shareLink}")

        # Download file using CLI with WebRTC disabled (forces HTTP)
        downloadedPath = os.path.join(self.tempDir, "downloaded_e2e.bin")
        try:
            self._downloadWithCore(shareLink, downloadedPath, extraEnvVars={'DISABLE_WEBRTC': 'True'})
        except AssertionError as e:
            # Print server log on failure
            outputText = self._updateCapturedOutput(outputCapture)
            with open("test_server_log.txt", "w", encoding="utf-8", errors="replace") as f:
                f.write(outputText)
            print(f"\n[Test] Download failed. Server log saved to test_server_log.txt")
            # Print only the E2E messages
            for line in outputText.split('\n'):
                if '[E2E' in line:
                    print(line)
            raise

        # Verify downloaded file matches original
        downloadedHash = getFileHash(downloadedPath)
        self.assertEqual(downloadedHash, self.originalFileHash, "E2E decrypted file should match original")

        downloadedSize = os.path.getsize(downloadedPath)
        self.assertEqual(downloadedSize, self.originalFileSize, "E2E decrypted file size should match original")

        # Verify HTTP was used (WebRTC should be disabled)
        outputText = self._updateCapturedOutput(outputCapture)
        if "WebRTC" in outputText or "P2P direct" in outputText:
            print(f"[Test] WARNING: WebRTC was used despite DISABLE_WEBRTC=True")
            print(f"[Test] Output:\n{outputText[-1000:]}")
        else:
            print(f"[Test] Confirmed HTTP download was used")

        print(f"[Test] [OK] E2EE HTTP download successful")
        print(f"[Test]   Hash: {downloadedHash}")
        print(f"[Test]   Size: {downloadedSize} bytes")

    def testE2EEHttpResumeDownload(self):
        """Test E2E encrypted HTTP download with resume"""
        print("\n[TEST] E2EE HTTP resume download")

        # Start server with E2E encryption enabled
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2EE: {shareLink}")

        # Create partial download by truncating a full download
        # (simulates interrupted download with partial plaintext)
        partialPath = os.path.join(self.tempDir, "partial_e2e.bin")
        partialSize = 512 * 1024 # 512KB (half of 1MB test file)

        # First do a complete download to a temp location (force HTTP)
        tempFullPath = os.path.join(self.tempDir, "temp_full_e2e.bin")
        self._downloadWithCore(shareLink, tempFullPath, extraEnvVars={'DISABLE_WEBRTC': 'True'})

        # Truncate to create partial file (first 512KB of plaintext)
        with open(tempFullPath, 'rb') as src:
            with open(partialPath, 'wb') as dst:
                dst.write(src.read(partialSize))

        # Clean up temp full download
        os.unlink(tempFullPath)

        print(f"[Test] Created partial file: {partialSize} bytes")
        self.assertEqual(os.path.getsize(partialPath), partialSize, "Partial file should be exactly 512KB")

        # Resume download using CLI with --resume flag (force HTTP)
        print("[Test] Resuming download with CLI...")
        self._downloadWithCore(shareLink, partialPath, extraArgs=["--resume"], extraEnvVars={'DISABLE_WEBRTC': 'True'})

        # Verify resumed file matches original
        resumedHash = getFileHash(partialPath)
        self.assertEqual(resumedHash, self.originalFileHash, "E2EE resumed file should match original")

        resumedSize = os.path.getsize(partialPath)
        self.assertEqual(resumedSize, self.originalFileSize, "E2EE resumed file size should match original")

        print(f"[Test] [OK] E2EE HTTP resume successful")
        print(f"[Test]   Hash: {resumedHash}")
        print(f"[Test]   Size: {resumedSize} bytes")

    def testE2EEWebRTCDownload(self):
        """Test E2E encrypted WebRTC download (P2P via CLI)"""
        print("\n[TEST] E2EE WebRTC P2P download")

        # Start server with E2E encryption enabled
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"], captureOutputIn=outputCapture)
        print(f"[Test] Share link with E2E: {shareLink}")

        # Download file via CLI (uses WebRTC P2P with E2EE)
        downloadedPath = os.path.join(self.tempDir, "downloaded_webrtc_e2e.bin")
        try:
            self._downloadWithCore(shareLink, downloadedPath, extraEnvVars={'DISABLE_HTTP_FALLBACK': 'True'})
        except AssertionError as e:
            # Print server log on failure
            outputText = self._updateCapturedOutput(outputCapture)
            print(f"\n[Test] Download failed. Server log:\n{outputText}")
            raise

        # Verify downloaded file matches original
        downloadedHash = getFileHash(downloadedPath)
        self.assertEqual(downloadedHash, self.originalFileHash, "E2EE WebRTC decrypted file should match original")

        downloadedSize = os.path.getsize(downloadedPath)
        self.assertEqual(downloadedSize, self.originalFileSize, "E2EE WebRTC decrypted file size should match original")

        # Check server log for errors
        outputText = self._updateCapturedOutput(outputCapture)
        if "Traceback" in outputText or "Error" in outputText:
            print(f"[Test] Server errors found:")
            print(outputText[-2000:]) # Last 2000 chars

        # Check that WebRTC was used (not HTTP fallback)
        if "HTTP fallback" in outputText:
            print(f"[Test] WARNING: Used HTTP fallback instead of WebRTC")
            print(f"[Test] Server output:\n{outputText[-1000:]}")
        else:
            print(f"[Test] Confirmed WebRTC P2P was used")

        print(f"[Test] [OK] E2E WebRTC download successful")
        print(f"[Test]   Hash: {downloadedHash}")
        print(f"[Test]   Size: {downloadedSize} bytes")

    def testE2EEHttpFallback(self):
        """Test E2E encrypted download with WebRTC ICE failure → HTTP fallback"""
        print("\n[TEST] E2EE HTTP fallback (ICE failure)")

        # Start server with E2E encryption enabled
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"], captureOutputIn=outputCapture)
        print(f"[Test] Share link with E2EE: {shareLink}")

        # Download file via CLI with ICE failure simulation to trigger HTTP fallback
        downloadedPath = os.path.join(self.tempDir, "downloaded_e2e_fallback.bin")
        downloadOutputCapture = {}
        try:
            self._downloadWithCore(
                shareLink,
                downloadedPath,
                extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"},
                captureOutputIn=downloadOutputCapture
            )
        except AssertionError as e:
            # Print server log on failure
            outputText = self._updateCapturedOutput(outputCapture)
            with open("test_server_log.txt", "w", encoding="utf-8", errors="replace") as f:
                f.write(outputText)
            print(f"\n[Test] Download failed. Server log saved to test_server_log.txt")
            raise

        # Verify HTTP fallback was triggered
        downloadOutputText = self._updateCapturedOutput(downloadOutputCapture)
        if "HTTP fallback" not in downloadOutputText:
            print(f"[Test] ERROR: HTTP fallback not found in download output")
            print(f"[Test] Download output:\n{downloadOutputText}")
            raise AssertionError("HTTP fallback should be triggered on ICE failure")

        # Verify downloaded file matches original
        downloadedHash = getFileHash(downloadedPath)
        self.assertEqual(
            downloadedHash, self.originalFileHash, "E2EE HTTP fallback decrypted file should match original"
        )

        downloadedSize = os.path.getsize(downloadedPath)
        self.assertEqual(
            downloadedSize, self.originalFileSize, "E2EE HTTP fallback decrypted file size should match original"
        )

        print(f"[Test] [OK] E2EE HTTP fallback successful")
        print(f"[Test]   Hash: {downloadedHash}")
        print(f"[Test]   Size: {downloadedSize} bytes")

    def testE2EEHttpFallbackWithResume(self):
        """Test E2E encrypted download with resume: partial WebRTC → ICE failure → HTTP fallback with resume"""
        print("\n[TEST] E2EE HTTP fallback with resume")

        # Start server with E2E encryption enabled
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2EE: {shareLink}")

        # Create partial download by truncating a full download
        # (simulates interrupted download with partial plaintext)
        partialPath = os.path.join(self.tempDir, "partial_e2e_fallback.bin")
        partialSize = 512 * 1024 # 512KB (half of 1MB test file)

        # First do a complete download to a temp location
        tempFullPath = os.path.join(self.tempDir, "temp_full_e2e_fallback.bin")
        self._downloadWithCore(shareLink, tempFullPath, extraEnvVars={'DISABLE_WEBRTC': 'True'})

        # Truncate to create partial file (first 512KB of plaintext)
        with open(tempFullPath, 'rb') as src:
            with open(partialPath, 'wb') as dst:
                dst.write(src.read(partialSize))

        # Clean up temp full download
        os.unlink(tempFullPath)

        print(f"[Test] Created partial file: {partialSize} bytes")
        self.assertEqual(os.path.getsize(partialPath), partialSize, "Partial file should be exactly 512KB")

        # Resume download with --resume flag and ICE failure to force HTTP fallback
        print("[Test] Resuming download with CLI and ICE failure to trigger HTTP fallback...")
        downloadOutputCapture = {}
        self._downloadWithCore(
            shareLink,
            partialPath,
            extraArgs=["--resume"],
            extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"},
            captureOutputIn=downloadOutputCapture
        )

        # Verify HTTP fallback was triggered
        downloadOutputText = self._updateCapturedOutput(downloadOutputCapture)
        if "HTTP fallback" not in downloadOutputText:
            print(f"[Test] ERROR: HTTP fallback not found in download output")
            print(f"[Test] Download output:\n{downloadOutputText}")
            raise AssertionError("HTTP fallback should be triggered on ICE failure during resume")

        # Verify resume happened from the correct position
        if "Resuming from" not in downloadOutputText:
            print(f"[Test] WARNING: Resume message not found in output")

        # Verify resumed file matches original
        resumedHash = getFileHash(partialPath)
        self.assertEqual(resumedHash, self.originalFileHash, "E2EE HTTP fallback resumed file should match original")

        resumedSize = os.path.getsize(partialPath)
        self.assertEqual(
            resumedSize, self.originalFileSize, "E2EE HTTP fallback resumed file size should match original"
        )

        print(f"[Test] [OK] E2EE HTTP fallback with resume successful")
        print(f"[Test]   Hash: {resumedHash}")
        print(f"[Test]   Size: {resumedSize} bytes")

    def _downloadRange(self, url: str, start: int = None, end: int = None) -> tuple[bytes, int, dict]:
        """Helper: Download data from URL with optional Range header

        Returns:
            tuple[bytes, int, dict]: (data, status_code, headers)
        """
        headers = {}
        if start is not None:
            if end is not None:
                headers['Range'] = f'bytes={start}-{end}'
            else:
                headers['Range'] = f'bytes={start}-'

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                status = response.status
                responseHeaders = dict(response.headers)

                # Read data in chunks to handle large files
                chunks = []
                while True:
                    chunk = response.read(65536) # 64KB chunks
                    if not chunk:
                        break
                    chunks.append(chunk)

                data = b''.join(chunks)
                return data, status, responseHeaders
        except urllib.error.HTTPError as e:
            # Return error status
            return b'', e.code, dict(e.headers) if hasattr(e, 'headers') else {}
        except Exception as e:
            print(f"[Test] Download error: {type(e).__name__}: {e}")
            raise

    def testE2EEEncryptedDownloadEndpoint(self):
        """Test downloading encrypted ciphertext directly from /download endpoint"""
        print("\n[TEST] E2E encrypted download endpoint")

        # Start server with E2E encryption enabled in P2P mode (keep server running)
        # In P2P mode, local server serves encrypted file through tunnel
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2EE: {shareLink}")

        # Extract download URL: https://host/uid → https://host/uid/download
        downloadUrl = shareLink.rstrip('/') + '/download'
        print(f"[Test] Download URL: {downloadUrl}")

        # Download encrypted ciphertext directly from /download endpoint
        data, status, headers = self._downloadRange(downloadUrl)

        self.assertEqual(status, 200, "Should return 200 OK for full download")

        # In E2E mode, /download returns encrypted ciphertext (same size as plaintext)
        # Tags are fetched separately via /e2ee/tags endpoint
        self.assertEqual(len(data), self.originalFileSize, "Encrypted ciphertext should be same size as plaintext")

        # Verify the data is NOT the plaintext (it should be encrypted)
        plaintextHash = self.originalFileHash
        encryptedHash = hashlib.sha256(data).hexdigest()
        self.assertNotEqual(encryptedHash, plaintextHash, "Encrypted ciphertext should NOT match plaintext hash")

        print(f"[Test] [OK] E2E encrypted download endpoint successful")
        print(f"[Test]   Encrypted size: {len(data)} bytes (matches plaintext)")
        print(f"[Test]   Plaintext hash: {plaintextHash}")
        print(f"[Test]   Encrypted hash: {encryptedHash} (different)")

    def testE2EEEncryptedResumeAligned(self):
        """Test encrypted download resume from chunk-aligned offset"""
        print("\n[TEST] E2E encrypted resume (aligned)")

        # Start server with E2E encryption enabled in P2P mode (keep server running)
        # In P2P mode, local server serves encrypted file through tunnel
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2E: {shareLink}")

        # Extract download URL: https://host/uid → https://host/uid/download
        downloadUrl = shareLink.rstrip('/') + '/download'

        # Use chunk size of 256KB (standard E2E chunk size)
        chunkSize = 256 * 1024
        resumeOffset = chunkSize * 2 # Skip 2 chunks (512KB)

        # Download first part (0 to resumeOffset-1)
        part1, status1, headers1 = self._downloadRange(downloadUrl, start=0, end=resumeOffset - 1)
        self.assertEqual(status1, 206, "First part should return 206 Partial Content")
        self.assertEqual(len(part1), resumeOffset, f"First part should be {resumeOffset} bytes")

        # Resume from aligned offset
        part2, status2, headers2 = self._downloadRange(downloadUrl, start=resumeOffset)
        self.assertEqual(status2, 206, "Resume should return 206 Partial Content")

        # Combine parts
        combined = part1 + part2
        self.assertEqual(
            len(combined), self.originalFileSize, "Combined encrypted data should match original file size"
        )

        # Download full file for comparison
        fullData, statusFull, _ = self._downloadRange(downloadUrl)
        self.assertEqual(statusFull, 200, "Full download should return 200 OK")

        # Verify combined parts match full download
        self.assertEqual(combined, fullData, "Combined parts should match full encrypted download")

        print(f"[Test] [OK] E2E encrypted resume (aligned) successful")
        print(f"[Test]   Part 1: {len(part1)} bytes (0-{resumeOffset-1})")
        print(f"[Test]   Part 2: {len(part2)} bytes ({resumeOffset}-end)")
        print(f"[Test]   Combined: {len(combined)} bytes")

    def testE2EEEncryptedResumeUnaligned(self):
        """Test encrypted download resume from non-aligned offset (mid-chunk)"""
        print("\n[TEST] E2E encrypted resume (unaligned)")

        # Start server with E2E encryption enabled in P2P mode (keep server running)
        # In P2P mode, local server serves encrypted file through tunnel
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2E: {shareLink}")

        # Extract download URL: https://host/uid → https://host/uid/download
        downloadUrl = shareLink.rstrip('/') + '/download'

        # Use chunk size of 256KB
        chunkSize = 256 * 1024
        resumeOffset = chunkSize + 12345 # Mid-chunk offset (non-aligned)

        # Download first part (0 to resumeOffset-1)
        part1, status1, headers1 = self._downloadRange(downloadUrl, start=0, end=resumeOffset - 1)
        self.assertEqual(status1, 206, "First part should return 206 Partial Content")
        self.assertEqual(len(part1), resumeOffset, f"First part should be {resumeOffset} bytes")

        # Resume from unaligned offset - server should accept it
        # Note: Combined parts won't match full download because each resume
        # creates a new encryptor starting at different chunk index
        try:
            part2, status2, headers2 = self._downloadRange(downloadUrl, start=resumeOffset)
            self.assertEqual(status2, 206, "Server should accept unaligned resume with 206")
            print(f"[Test] [OK] Part 2: {len(part2)} bytes (server accepted unaligned)")
        except Exception as e:
            self.fail(f"Server should accept unaligned resume offset, but got error: {e}")

        print(f"[Test] [OK] E2E encrypted resume (unaligned) successful")
        print(f"[Test]   Part 1: {len(part1)} bytes (0-{resumeOffset-1})")
        print(f"[Test]   Part 2: {len(part2)} bytes ({resumeOffset}-end)")
        print(f"[Test]   Resume offset: {resumeOffset} (unaligned, mid-chunk)")

    def testE2EEMultipleClientsKcKi(self):
        """Test that multiple clients get same encrypted content (Kc) but different wrapped keys (Ki)"""
        print("\n[TEST] E2E multiple clients Kc/Ki verification")

        # Start server with E2E encryption enabled (keep server running)
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])
        print(f"[Test] Share link with E2E: {shareLink}")

        # Extract base URL and UID
        downloadUrl = shareLink.rstrip('/') + '/download'
        e2eInitUrl = shareLink.rstrip('/') + '/e2ee/init'

        # Simulate Client 1: Download encrypted content from /download
        print(f"[Test] Client 1: Downloading from /download")
        client1Data, status1, _ = self._downloadRange(downloadUrl)
        self.assertEqual(status1, 200, "Client 1 download should return 200 OK")
        client1Hash = hashlib.sha256(client1Data).hexdigest()
        print(f"[Test]   Client 1 encrypted data hash: {client1Hash}")

        # Simulate Client 2: Download encrypted content from /download
        print(f"[Test] Client 2: Downloading from /download")
        client2Data, status2, _ = self._downloadRange(downloadUrl)
        self.assertEqual(status2, 200, "Client 2 download should return 200 OK")
        client2Hash = hashlib.sha256(client2Data).hexdigest()
        print(f"[Test]   Client 2 encrypted data hash: {client2Hash}")

        # Verify both clients received SAME encrypted content (same Kc)
        self.assertEqual(client1Data, client2Data, "Both clients should receive identical encrypted content (same Kc)")
        print(f"[Test] [OK] Both clients received identical encrypted content")

        # Now test /e2ee/init endpoint - simulate two clients with different public keys
        crypto = CryptoInterface()

        # Generate Client 1's RSA key pair
        client1PrivKey, client1PubKey = crypto.generateRSAKeyPair()
        client1PubPEM = client1PubKey.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Generate Client 2's RSA key pair
        client2PrivKey, client2PubKey = crypto.generateRSAKeyPair()
        client2PubPEM = client2PubKey.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Client 1 calls /e2e/init
        print(f"[Test] Client 1: Calling /e2ee/init")
        response1 = requests.post(e2eInitUrl, json={'publicKey': client1PubPEM}, timeout=10)
        self.assertEqual(response1.status_code, 200, "Client 1 /e2ee/init should return 200")
        init1Data = response1.json()
        print(f"[Test]   Client 1 wrappedContentKey: {init1Data['wrappedContentKey'][:32]}...")

        # Client 2 calls /e2ee/init
        print(f"[Test] Client 2: Calling /e2ee/init")
        response2 = requests.post(e2eInitUrl, json={'publicKey': client2PubPEM}, timeout=10)
        self.assertEqual(response2.status_code, 200, "Client 2 /e2ee/init should return 200")
        init2Data = response2.json()
        print(f"[Test]   Client 2 wrappedContentKey: {init2Data['wrappedContentKey'][:32]}...")

        # Verify wrapped keys are DIFFERENT (different Ki)
        self.assertNotEqual(
            init1Data['wrappedContentKey'], init2Data['wrappedContentKey'],
            "Wrapped content keys should be different (different Ki for each client)"
        )
        print(f"[Test] [OK] Each client received different wrapped key (Ki)")

        # Verify other metadata is the same
        self.assertEqual(init1Data['filename'], init2Data['filename'], "Both clients should receive same filename")
        self.assertEqual(init1Data['filesize'], init2Data['filesize'], "Both clients should receive same filesize")
        self.assertEqual(init1Data['chunkSize'], init2Data['chunkSize'], "Both clients should receive same chunkSize")

        print(f"[Test] [OK] E2E Kc/Ki verification successful")
        print(f"[Test]   Same encrypted content (Kc): {client1Hash == client2Hash}")
        print(
            f"[Test]   Different wrapped keys (Ki): {init1Data['wrappedContentKey'] != init2Data['wrappedContentKey']}"
        )


class E2EEBrowserTest(ResumeBrowserTestBase):
    """Test E2E encryption with browser-based WebRTC downloads (JavaScript decryption)"""

    def __init__(self, methodName='runTest'):
        # Use 5MB file for browser E2E tests
        super().__init__(methodName, fileSizeBytes=5 * 1024 * 1024)

    def _runE2EBrowserDownloadTest(self, browserName, extraEnvVars=None):
        """Run E2E encrypted download test with specified browser

        Args:
            browserName: 'chrome' or 'firefox'
            extraEnvVars: Optional dict of environment variables to pass to Core.py
        """
        try:
            # Use JSON output to verify E2E status
            jsonOutputPath = os.path.join(self.tempDir, "share_info.json")

            # Start FastFileLink with E2E encryption enabled
            outputCapture = {}
            shareLink = self._startFastFileLink(
                p2p=True,
                output=False,
                extraArgs=['--e2ee', '--json', jsonOutputPath],
                captureOutputIn=outputCapture,
                extraEnvVars=extraEnvVars
            )

            drivers = []
            downloadDirs = []
            for idx in range(CONCURRENT_WEBRTC_DOWNLOADS):
                if browserName == 'chrome':
                    downloadDir = self._getBrowserDownloadDir('chrome', idx)
                    driver = self._setupChromeDriver(downloadDir)
                elif browserName == 'firefox':
                    downloadDir = self._getBrowserDownloadDir('firefox', idx)
                    driver = self._setupFirefoxDriver(downloadDir)
                else:
                    raise ValueError(f"Unsupported browser: {browserName}")

                drivers.append(driver)
                downloadDirs.append(downloadDir)

            expectedFilename = "testfile.bin"

            disableBrowserFallback = not (extraEnvVars and extraEnvVars.get('DISABLE_WEBRTC') == 'True')

            def downloadJob(index):
                driver = drivers[index]
                downloadDir = downloadDirs[index]
                return self._downloadWithBrowser(
                    driver, shareLink, downloadDir, expectedFilename, disableFallback=disableBrowserFallback
                )

            if CONCURRENT_WEBRTC_DOWNLOADS > 1:
                with ThreadPoolExecutor(max_workers=CONCURRENT_WEBRTC_DOWNLOADS) as executor:
                    futures = [executor.submit(downloadJob, idx) for idx in range(CONCURRENT_WEBRTC_DOWNLOADS)]
                    downloadedFiles = [f.result() for f in futures]
            else:
                downloadedFiles = [downloadJob(0)]

            # Verify each downloaded file matches original (proves JavaScript E2E decryption worked)
            for downloadedFile in downloadedFiles:
                self._verifyDownloadedFile(downloadedFile)

            print(
                f"[Test] Completed {CONCURRENT_WEBRTC_DOWNLOADS} concurrent "
                f"{browserName} download{'s' if CONCURRENT_WEBRTC_DOWNLOADS > 1 else ''} successfully"
            )

            # Verify E2E was enabled via JSON output
            with open(jsonOutputPath, 'r', encoding='utf-8') as f:
                shareInfo = json.load(f)

            if not shareInfo.get('e2ee', False):
                raise AssertionError("E2E encryption not enabled in JSON output (e2ee field is false or missing)")

            mode = "HTTP fallback" if extraEnvVars and extraEnvVars.get('DISABLE_WEBRTC') else "WebRTC"
            print(f"[Test] E2E {mode} confirmed - {browserName} successfully decrypted file with JavaScript!")
            print(f"[Test] JSON output verified: e2ee=true")

        finally:
            self._terminateProcess()

    def testE2EEBrowserDownloadWithChrome(self):
        """Test E2E encrypted WebRTC download using Chrome browser (JavaScript E2EE.js decryption)"""
        self._runE2EBrowserDownloadTest('chrome')

    def testE2EEBrowserDownloadWithFirefox(self):
        """Test E2E encrypted WebRTC download using Firefox browser (JavaScript E2EE.js decryption)"""
        self._runE2EBrowserDownloadTest('firefox')

    def testE2EEBrowserHTTPFallbackWithChrome(self):
        """Test E2E encrypted HTTP fallback using Chrome browser (JavaScript E2EE.js HTTP decryption via Service Worker)"""
        self._runE2EBrowserDownloadTest('chrome', extraEnvVars={'DISABLE_WEBRTC': 'True'})

    def testE2EEBrowserHTTPFallbackWithFirefox(self):
        """Test E2E encrypted HTTP fallback using Firefox browser (JavaScript E2EE.js HTTP decryption via Service Worker)"""
        self._runE2EBrowserDownloadTest('firefox', extraEnvVars={'DISABLE_WEBRTC': 'True'})

    def testE2EEHttpResumeWithFallbackChrome(self):
        """Test E2EE HTTP resume when WebRTC connection stalls and falls back to HTTP with Chrome"""
        self._testHttpResumeWithFallback('chrome', extraArgs=['--e2ee'])

    def testE2EEHttpResumeWithFallbackFirefox(self):
        """Test E2EE HTTP resume when WebRTC connection stalls and falls back to HTTP with Firefox"""
        self._testHttpResumeWithFallback('firefox', extraArgs=['--e2ee'])


class E2EEUploadResumeBrowserTest(E2EEUploadTestBase, ResumeBrowserTestBase):
    """Browser-based validation of E2EE upload resume using the test server"""

    def testE2EEUploadResumeWithChromeUsingServer(self):
        print("\n[TEST] E2E upload resume with test server via Chrome")

        pauseOutput = {}
        resumeOutput = {}
        testServerProcess = None

        try:
            loggingArgs = ['--log-level', LOG_CONFIG_UPLOAD]

            testServerProcess, pauseLog = self._pauseUpload(
                pausePercentage=40, outputCapture=pauseOutput, extraArgs=['--e2ee', *loggingArgs], useTestServer=True
            )
            print(f"[Test] Pause log: {pauseLog.strip()}")

            resumeShareLink, resumeLog = self._resumeUpload(
                outputCapture=resumeOutput,
                extraArgs=['--e2ee', *loggingArgs],
                extraEnv={'FILESHARE_TEST': 'http://localhost:5000'}
            )
            print(f"[Test] Resume log: {resumeLog.strip()}")

            encryptionKey = self._extractEncryptionKey(pauseLog) or self._extractEncryptionKey(resumeLog)
            if not encryptionKey:
                raise AssertionError("Encryption key not found in upload logs")

            linkWithKey = f"{resumeShareLink}#{encryptionKey}"

            time.sleep(2)

            downloadDir = self._getBrowserDownloadDir('chrome', 0)
            driver = self._setupChromeDriver(downloadDir)

            downloadedFile = self._downloadWithBrowser(
                driver, linkWithKey, downloadDir, "testfile.bin", disableFallback=True
            )
            self._verifyDownloadedFile(downloadedFile)
            print("[Test] E2E upload resume download verified via browser")

        finally:
            self._terminateProcess()
            if testServerProcess:
                self._stopTestServer(testServerProcess)


class E2EEUploadDownloadTest(E2EEUploadTestBase, ResumeTestBase):
    """Test E2EE upload to test server and download with Core.py

    This test validates the complete E2EE upload workflow:
    1. Upload an encrypted file to the test server
    2. Extract the encryption key from the upload output
    3. Download the file using Core.py with the encryption key
    4. Verify the downloaded file matches the original

    Note: This test uses the local TestServer.py to avoid dependencies on external services.
    The test reuses common E2EE upload functionality from E2EEUploadTestBase following DRY principles.
    """

    def __init__(self, methodName='runTest'):
        # Use 1MB file for faster testing
        super().__init__(methodName, fileSizeBytes=1 * 1024 * 1024)

    def testE2EEUploadAndDownloadWithCore(self):
        """Test E2EE upload to test server and download using Core.py CLI

        This test verifies that:
        - Files can be uploaded with E2EE encryption
        - Encryption keys are properly generated and displayed
        - Files can be downloaded and decrypted using Core.py with the encryption key
        - Decrypted files match the original plaintext
        """
        print("\n[TEST] E2E upload to test server and download with Core.py")

        uploadOutput = {}
        testServerProcess = None

        try:
            # Upload file with E2EE to test server using common helper
            shareLink, encryptionKey, testServerProcess = self._uploadWithE2EE(
                useTestServer=True, captureOutputIn=uploadOutput
            )

            print(f"[Test] Share link: {shareLink}")
            print(f"[Test] Encryption key: {encryptionKey}")

            # Construct URL with encryption key in fragment
            linkWithKey = f"{shareLink}#{encryptionKey}"
            print(f"[Test] Download URL with key: {linkWithKey}")

            # Download using Core.py with encryption key
            downloadedPath = os.path.join(self.tempDir, "downloaded_upload_e2e.bin")
            self._downloadWithCore(
                linkWithKey,
                downloadedPath,
                extraEnvVars={
                    'DISABLE_WEBRTC': 'True',
                    'FILESHARE_TEST': 'http://localhost:5000'
                }
            )

            # Verify downloaded file matches original
            downloadedHash = getFileHash(downloadedPath)
            self.assertEqual(downloadedHash, self.originalFileHash, "Downloaded file should match original")

            downloadedSize = os.path.getsize(downloadedPath)
            self.assertEqual(downloadedSize, self.originalFileSize, "Downloaded file size should match original")

            print(f"[Test] [OK] E2E upload and download successful")
            print(f"[Test]   Hash: {downloadedHash}")
            print(f"[Test]   Size: {downloadedSize} bytes")

        finally:
            self._terminateProcess()
            if testServerProcess:
                self._stopTestServer(testServerProcess)


if __name__ == '__main__':
    unittest.main()
