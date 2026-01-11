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
import sys
import time
import json
import unittest
import zipfile
import hashlib
import tempfile
import shutil
import subprocess
import io

from unittest.mock import patch

from tests.CoreTestBase import FastFileLinkTestBase, getFileHash

from bases.Kernel import FFLEvent
from bases.Reader import SourceReader, ZipDirSourceReader, FolderChangedException, StdinSourceReader, CachingMixin


def calculateFolderHash(folderPath):
    """Calculate a hash of all files in a folder recursively"""
    sha256 = hashlib.sha256()

    # Walk through directory in sorted order for consistent hashing
    for root, dirs, files in os.walk(folderPath):
        # Sort to ensure consistent order
        dirs.sort()
        files.sort()

        for filename in files:
            filePath = os.path.join(root, filename)
            relativePath = os.path.relpath(filePath, folderPath)

            # Hash the relative path
            sha256.update(relativePath.encode('utf-8'))

            # Hash the file contents
            with open(filePath, 'rb') as f:
                for block in iter(lambda: f.read(65536), b''):
                    sha256.update(block)

    return sha256.hexdigest()


class FolderReaderTest(unittest.TestCase):
    """Direct test of folder reader without HTTP transfer"""

    def testBasicFolderReading(self):
        """Test that folder reader generates valid ZIP"""
        import tempfile
        import shutil
        from bases.Reader import SourceReader

        # Create test folder
        tmpdir = tempfile.mkdtemp()
        try:
            testFolder = os.path.join(tmpdir, 'test_folder')
            os.makedirs(testFolder)

            # Add test files
            with open(os.path.join(testFolder, 'file1.txt'), 'w') as f:
                f.write('Hello World')
            with open(os.path.join(testFolder, 'file2.txt'), 'w') as f:
                f.write('Test Content')

            # Create reader
            reader = SourceReader.build(testFolder, compression='store')

            # Verify properties
            self.assertEqual(reader.contentName, 'test_folder.zip')
            self.assertEqual(reader.contentType, 'application/zip')
            self.assertIsNotNone(reader.size)
            # Store mode supports Range resume via SegmentIndex (-2.5 architecture)
            self.assertTrue(reader.supportsRange)

            # Read all data
            data = b''.join(reader.iterChunks(1024))

            # Verify it's a valid ZIP
            self.assertTrue(data.startswith(b'PK\x03\x04'), "Should start with ZIP magic bytes")

            # Write to file and verify with zipfile module
            zipPath = os.path.join(tmpdir, 'output.zip')
            with open(zipPath, 'wb') as f:
                f.write(data)

            # Verify ZIP is valid and contains expected files
            with zipfile.ZipFile(zipPath, 'r') as zipf:
                names = zipf.namelist()
                self.assertIn('test_folder/file1.txt', names)
                self.assertIn('test_folder/file2.txt', names)

                # Verify content
                self.assertEqual(zipf.read('test_folder/file1.txt'), b'Hello World')
                self.assertEqual(zipf.read('test_folder/file2.txt'), b'Test Content')

            print("[Test] Direct folder reader test passed!")

        finally:
            shutil.rmtree(tmpdir)


class FolderTransferTest(FastFileLinkTestBase):
    """Test class for folder transfer functionality using ZIP streaming"""

    def setUp(self):
        """Set up test environment with a test folder structure"""
        # Call parent setUp first
        super().setUp()

        # Create a test folder with multiple files
        self.testFolderPath = os.path.join(self.tempDir, "test_folder")
        os.makedirs(self.testFolderPath)

        # Create some test files with different sizes
        self.testFiles = {
            "file1.txt": b"Hello, World! This is the first file.",
            "file2.bin": os.urandom(1024 * 10), # 10KB random data
            "file3.dat": os.urandom(1024 * 50), # 50KB random data
        }

        # Create a subfolder with nested files
        subfolderPath = os.path.join(self.testFolderPath, "subfolder")
        os.makedirs(subfolderPath)
        self.testFiles["subfolder/nested.txt"] = b"This is a nested file in a subfolder."
        self.testFiles["subfolder/data.bin"] = os.urandom(1024 * 5) # 5KB

        # Write all test files
        for relativePath, content in self.testFiles.items():
            fullPath = os.path.join(self.testFolderPath, relativePath)
            with open(fullPath, 'wb') as f:
                f.write(content)

        # Calculate hash of original folder
        self.originalFolderHash = calculateFolderHash(self.testFolderPath)

        print(f"[Test] Created test folder: {self.testFolderPath}")
        print(f"[Test] Folder contains {len(self.testFiles)} files")
        print(f"[Test] Folder hash: {self.originalFolderHash}")

        # Override testFilePath to point to the folder
        self.testFilePath = self.testFolderPath

        # Calculate expected ZIP size using Reader abstraction
        # This is what Core.py will report in the JSON
        from bases.Reader import SourceReader
        reader = SourceReader.build(self.testFolderPath, compression='store')
        self.originalFileSize = reader.size if reader.size is not None else 0
        print(f"[Test] Expected ZIP size (Store mode): {self.originalFileSize} bytes")

    def _verifyDownloadedZipFile(self, downloadedZipPath):
        """
        Verify that the downloaded ZIP file contains all expected files

        Args:
            downloadedZipPath (str): Path to the downloaded ZIP file
        """
        print(f"[Test] Verifying downloaded ZIP file: {downloadedZipPath}")

        if not os.path.exists(downloadedZipPath):
            raise AssertionError(f"Downloaded ZIP file does not exist: {downloadedZipPath}")

        # Extract the ZIP to a temporary directory
        extractPath = os.path.join(self.tempDir, "extracted_folder")
        os.makedirs(extractPath, exist_ok=True)

        with zipfile.ZipFile(downloadedZipPath, 'r') as zipf:
            zipf.extractall(extractPath)

        print(f"[Test] Extracted ZIP to: {extractPath}")

        # List extracted files
        extractedFiles = []
        for root, dirs, files in os.walk(extractPath):
            for filename in files:
                filePath = os.path.join(root, filename)
                relativePath = os.path.relpath(filePath, extractPath)
                extractedFiles.append(relativePath)
                print(f"[Test] Extracted: {relativePath}")

        # Verify all original files are present
        for originalRelativePath in self.testFiles.keys():
            found = False
            for extractedPath in extractedFiles:
                # Handle both direct match and folder-prefixed match
                if extractedPath == originalRelativePath or extractedPath.endswith(
                    os.sep + originalRelativePath.replace('/', os.sep)
                ):
                    found = True
                    break

            if not found:
                raise AssertionError(f"File missing in ZIP: {originalRelativePath}")

        print(f"[Test] All {len(self.testFiles)} files found in ZIP")

        # Calculate hash of extracted folder - need to hash from the subfolder
        # because ZIP includes the folder name in the archive (e.g., test_folder/)
        folderName = os.path.basename(self.testFilePath)
        extractedFolderPath = os.path.join(extractPath, folderName)
        if os.path.exists(extractedFolderPath):
            extractedFolderHash = calculateFolderHash(extractedFolderPath)
        else:
            extractedFolderHash = calculateFolderHash(extractPath)

        print(f"[Test] Original folder hash: {self.originalFolderHash}")
        print(f"[Test] Extracted folder hash: {extractedFolderHash}")

        if extractedFolderHash != self.originalFolderHash:
            raise AssertionError("Extracted folder content doesn't match original folder")

        print("[Test] Folder verification successful!")

    def testFolderTransferP2P(self):
        """Test folder transfer in P2P mode using Store compression (default)"""
        print("\n[Test] Testing folder transfer in P2P mode (Store compression)")

        try:
            # Start FastFileLink with folder
            shareLink = self._startFastFileLink(p2p=True)

            # Download the ZIP file
            downloadedZipPath = self._getDownloadedFilePath("test_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)

            # Verify the downloaded ZIP
            self._verifyDownloadedZipFile(downloadedZipPath)

        finally:
            self._terminateProcess()

    def testFolderTransferServer(self):
        """Test folder transfer in server mode using Store compression (default)"""
        print("\n[Test] Testing folder transfer in server mode (Store compression)")

        try:
            # Start FastFileLink with folder in server mode
            shareLink = self._startFastFileLink(p2p=False)

            # Download the ZIP file
            downloadedZipPath = self._getDownloadedFilePath("test_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)

            # Verify the downloaded ZIP
            self._verifyDownloadedZipFile(downloadedZipPath)

        finally:
            self._terminateProcess()

    def _testFolderTransferWithDeflateCompression(self): # FIXME: Disabled, not supported yet.
        """Test folder transfer with Deflate compression enabled"""
        print("\n[Test] Testing folder transfer with Deflate compression")

        try:
            # Set environment variables to use deflate compression and local test server
            extraEnvVars = {
                'READER_FOLDER_COMPRESSION': 'deflate',
                #'FILESHARE_TEST': 'True'  # Use local server for deflate test (size=0 not supported by production)
            }

            # Update originalFileSize to 0 for deflate mode (size is unknown until compressed)
            self.originalFileSize = 0
            print(f"[Test] Deflate mode: size is unknown (set to 0)")

            # Start FastFileLink with folder and deflate compression
            shareLink, testServerProcess = self._startFastFileLink(
                p2p=True, extraEnvVars=extraEnvVars, useTestServer=True
            )

            try:
                # Download the ZIP file - use longer timeout for deflate compression
                downloadedZipPath = self._getDownloadedFilePath("test_folder.zip")

                # Download with streaming and longer timeout for deflate
                print("[Test] Attempting to download deflate-compressed ZIP (may take longer)...")
                import requests
                response = requests.get(shareLink, stream=True, timeout=120)
                if response.status_code == 200:
                    with open(downloadedZipPath, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    print(f"[Test] File downloaded successfully to {downloadedZipPath}")
                else:
                    raise AssertionError(f"Download failed with status code: {response.status_code}")

                # Verify the downloaded ZIP
                self._verifyDownloadedZipFile(downloadedZipPath)

                # Verify the ZIP actually uses deflate compression
                with zipfile.ZipFile(downloadedZipPath, 'r') as zipf:
                    for info in zipf.infolist():
                        if not info.is_dir():
                            if info.compress_type == zipfile.ZIP_STORED:
                                print(f"[Test] Warning: {info.filename} uses STORE compression (expected DEFLATE)")
                            elif info.compress_type == zipfile.ZIP_DEFLATED:
                                print(f"[Test] {info.filename} uses DEFLATE compression ✓")
            finally:
                # Stop test server
                self._stopTestServer(testServerProcess)

        finally:
            self._terminateProcess()

    def testEmptyFolder(self):
        """Test transfer of an empty folder"""
        print("\n[Test] Testing empty folder transfer")

        # Create an empty folder
        emptyFolderPath = os.path.join(self.tempDir, "empty_folder")
        os.makedirs(emptyFolderPath)
        self.testFilePath = emptyFolderPath

        # Update originalFileSize to match empty folder's ZIP size
        from bases.Reader import SourceReader
        reader = SourceReader.build(emptyFolderPath, compression='store')
        self.originalFileSize = reader.size if reader.size is not None else 0
        print(f"[Test] Empty folder ZIP size: {self.originalFileSize} bytes")

        try:
            # Start FastFileLink with empty folder
            shareLink = self._startFastFileLink(p2p=True)

            # Download the ZIP file
            downloadedZipPath = self._getDownloadedFilePath("empty_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)

            # Verify the ZIP exists and is valid
            if not os.path.exists(downloadedZipPath):
                raise AssertionError("Downloaded ZIP file does not exist")

            # Check if it's a valid ZIP
            with zipfile.ZipFile(downloadedZipPath, 'r') as zipf:
                fileList = zipf.namelist()
                print(f"[Test] Empty folder ZIP contains {len(fileList)} entries")

            print("[Test] Empty folder transfer successful!")

        finally:
            self._terminateProcess()

    def testLargeFolderStructure(self):
        """Test transfer of a folder with many files"""
        print("\n[Test] Testing large folder structure transfer")

        # Create a folder with many files
        largeFolderPath = os.path.join(self.tempDir, "large_folder")
        os.makedirs(largeFolderPath)

        # Create 50 small files
        for i in range(50):
            filePath = os.path.join(largeFolderPath, f"file_{i:03d}.txt")
            with open(filePath, 'w') as f:
                f.write(f"This is file number {i}\n" * 10)

        # Calculate original hash
        originalHash = calculateFolderHash(largeFolderPath)
        self.testFilePath = largeFolderPath
        self.originalFolderHash = originalHash

        # Update originalFileSize to match large folder's ZIP size
        from bases.Reader import SourceReader
        reader = SourceReader.build(largeFolderPath, compression='store')
        self.originalFileSize = reader.size if reader.size is not None else 0
        print(f"[Test] Large folder ZIP size: {self.originalFileSize} bytes")

        try:
            # Start FastFileLink with large folder
            shareLink = self._startFastFileLink(p2p=True)

            # Download the ZIP file
            downloadedZipPath = self._getDownloadedFilePath("large_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)

            # Verify the ZIP
            extractPath = os.path.join(self.tempDir, "extracted_large")
            os.makedirs(extractPath, exist_ok=True)

            with zipfile.ZipFile(downloadedZipPath, 'r') as zipf:
                zipf.extractall(extractPath)

            # Count files
            fileCount = sum([len(files) for _, _, files in os.walk(extractPath)])
            print(f"[Test] Extracted {fileCount} files from ZIP")

            if fileCount != 50:
                raise AssertionError(f"Expected 50 files, found {fileCount}")

            # Verify hash - need to hash from the subfolder (large_folder)
            # because ZIP includes the folder name in the archive
            extractedFolderPath = os.path.join(extractPath, "large_folder")
            if os.path.exists(extractedFolderPath):
                extractedHash = calculateFolderHash(extractedFolderPath)
            else:
                extractedHash = calculateFolderHash(extractPath)

            print(f"[Test] Original folder hash: {originalHash}")
            print(f"[Test] Extracted folder hash: {extractedHash}")

            if extractedHash != originalHash:
                raise AssertionError("Large folder content doesn't match original")

            print("[Test] Large folder transfer successful!")

        finally:
            self._terminateProcess()

    def testFolderChangeNotificationToClient(self):
        """Test that client receives folder change error notification via status polling"""
        print("\n[Test] Testing folder change notification to client during download")

        # Create a smaller test folder for more reliable timing
        testFolder = os.path.join(self.tempDir, "test_folder_change")
        os.makedirs(testFolder)

        # Create multiple files (total ~10MB) to ensure download takes a few seconds
        print("[Test] Creating test folder with files...")
        for i in range(20):
            filePath = os.path.join(testFolder, f"file{i:03d}.bin")
            with open(filePath, 'wb') as f:
                f.write(os.urandom(500 * 1024)) # 500KB per file = 10MB total

        # Create a file that will be modified during download
        targetFilePath = os.path.join(testFolder, "target_file.txt")
        with open(targetFilePath, 'w') as f:
            f.write("Original content\n" * 1000)

        print(f"[Test] Created test folder: {testFolder}")
        print(f"[Test] Target file for modification: {targetFilePath}")

        self.testFilePath = testFolder

        reader = SourceReader.build(testFolder, compression='store')
        self.originalFileSize = reader.size
        print(f"[Test] Folder ZIP size: {self.originalFileSize} bytes")

        import threading
        modificationDone = threading.Event()

        def modifyFileDuringDownload():
            """Modify file after a delay to trigger change detection mid-download"""
            print("[Test] Modification thread: Waiting 2 seconds before modifying file...")
            time.sleep(2) # Wait 2 seconds for download to start
            try:
                print(f"[Test] Modification thread: Modifying {targetFilePath}...")
                with open(targetFilePath, 'w') as f:
                    f.write("MODIFIED CONTENT - This change should be detected!\n" * 2000)
                print("[Test] Modification thread: File modified successfully")
            except Exception as e:
                print(f"[Test] Modification thread: Error modifying file: {e}")
            finally:
                modificationDone.set()

        try:
            # Start FastFileLink with test folder in P2P mode
            serverOutputCapture = {}
            shareLink = self._startFastFileLink(p2p=True, captureOutputIn=serverOutputCapture)

            # Start modification thread
            modThread = threading.Thread(target=modifyFileDuringDownload, daemon=True)
            modThread.start()
            print("[Test] Started background thread to modify file during download")

            # Download the folder
            downloadOutputCapture = {}
            downloadedZipPath = os.path.join(self.tempDir, "downloaded_folder.zip")

            # Download should FAIL due to folder change - don't raise assertion
            try:
                self._downloadWithCore(shareLink, downloadedZipPath, captureOutputIn=downloadOutputCapture)
                downloadFailed = False
            except AssertionError as e:
                # Expected - download should fail
                downloadFailed = True
                print(f"[Test] Download failed as expected")
                # Print exception details for debugging
                exceptionStr = str(e)
                if len(exceptionStr) > 5000:
                    print(f"[Test] Exception details (first 2500 chars):\n{exceptionStr[:2500]}")
                    print(f"[Test] Exception details (last 2500 chars):\n{exceptionStr[-2500:]}")
                else:
                    print(f"[Test] Exception details:\n{exceptionStr}")

            # Wait for modification thread to complete
            modThread.join(timeout=5)
            if modificationDone.is_set():
                print("[Test] Modification thread completed successfully")
            else:
                print("[Test] WARNING: Modification thread did not complete in time")

            # Verify download failed
            if not downloadFailed:
                # Print FULL captured output for debugging
                clientOutput = self._updateCapturedOutput(downloadOutputCapture)
                print(f"[Test] ERROR: Download succeeded when it should have failed!")
                print(f"[Test] ===== FULL CLIENT OUTPUT ({len(clientOutput)} chars) =====")
                print(clientOutput)
                print(f"[Test] ===== END FULL CLIENT OUTPUT =====")
                self.fail("Download should have failed due to folder change, but succeeded")

            print("[Test] Download correctly failed [OK]")

            # Check server-side output for folder change detection
            serverOutput = self._updateCapturedOutput(serverOutputCapture)
            serverDetected = "TRANSFER ABORTED" in serverOutput and "File size changed during transfer" in serverOutput
            print(f"[Test] Server detected folder change: {serverDetected}")

            if not serverDetected:
                print(f"[Test] ===== FULL SERVER OUTPUT ({len(serverOutput)} chars) =====")
                print(serverOutput)
                print(f"[Test] ===== END FULL SERVER OUTPUT =====")
                self.fail("Server did not detect folder change")

            print("[Test] Server correctly detected folder change [OK]")

            # Check client-side output for error notification
            clientOutput = self._updateCapturedOutput(downloadOutputCapture)

            # Client should receive FolderChangedException message
            clientReceivedError = "folder contents changed during the transfer" in clientOutput.lower()
            clientGotGuidance = "contact the person who shared the file" in clientOutput.lower()

            print(f"[Test] Client received folder change error: {clientReceivedError}")
            print(f"[Test] Client got guidance message: {clientGotGuidance}")

            if not clientReceivedError:
                print(f"[Test] ===== FULL CLIENT OUTPUT ({len(clientOutput)} chars) =====")
                print(clientOutput)
                print(f"[Test] ===== END FULL CLIENT OUTPUT =====")
                self.fail("Client did not receive folder change error notification")

            if not clientGotGuidance:
                print(f"[Test] ===== FULL CLIENT OUTPUT ({len(clientOutput)} chars) =====")
                print(clientOutput)
                print(f"[Test] ===== END FULL CLIENT OUTPUT =====")
                self.fail("Client error message should include guidance to contact sharer")

            print("[Test] Client correctly received FolderChangedException with guidance [OK]")

        finally:
            self._terminateProcess()
            # Cleanup handled by tempDir (test folder and downloaded ZIP are in tempDir)


class FolderChangeDetectionTest(unittest.TestCase):
    """Test folder change detection during ZIP streaming"""

    def setUp(self):
        """Create temporary test folder"""
        self.tempDir = tempfile.mkdtemp()
        self.testFolder = os.path.join(self.tempDir, "test_folder")
        os.makedirs(self.testFolder)

        # Create initial test files
        self.file1 = os.path.join(self.testFolder, "file1.txt")
        self.file2 = os.path.join(self.testFolder, "file2.txt")

        with open(self.file1, 'w') as f:
            f.write("Original content 1")
        with open(self.file2, 'w') as f:
            f.write("Original content 2")

        # Small delay to ensure mtime is different
        time.sleep(0.01)

    def tearDown(self):
        """Clean up temporary folder"""
        if os.path.exists(self.tempDir):
            shutil.rmtree(self.tempDir)

    def testStrictModeFileSizeChange(self):
        """Test that strict mode aborts on file size change"""
        print("\n[Test] Testing strict mode with file size change")

        # Create reader in strict mode (default for store)
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Simulate file size change by modifying file1
        # We'll do this by monkey-patching the validation to change the file after scanning
        originalValidate = reader._validateFileUnchanged

        def validateWithChange(entry):
            if not entry['isDir'] and entry['path'] == self.file1:
                # Change file size before validation
                with open(self.file1, 'w') as f:
                    f.write("Modified content that is longer than original")
            return originalValidate(entry)

        reader._validateFileUnchanged = validateWithChange

        # Should raise RuntimeError on file size change
        with self.assertRaises(RuntimeError) as ctx:
            data = b''.join(reader.iterChunks(1024))

        self.assertIn("File size changed", str(ctx.exception))
        print(f"[Test] Strict mode correctly caught file size change: {ctx.exception}")

    def testStrictModeFileMtimeChange(self):
        """Test that strict mode aborts on file mtime change"""
        print("\n[Test] Testing strict mode with file mtime change")

        # Create reader in strict mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Simulate mtime change
        originalValidate = reader._validateFileUnchanged

        def validateWithChange(entry):
            if not entry['isDir'] and entry['path'] == self.file1:
                # Modify file to change mtime (same size to test mtime detection)
                time.sleep(0.02) # Ensure time passes
                with open(self.file1, 'w') as f:
                    f.write("Modified content!") # Same length as original
            return originalValidate(entry)

        reader._validateFileUnchanged = validateWithChange

        # Should raise RuntimeError on file change (either size or mtime)
        with self.assertRaises(RuntimeError) as ctx:
            data = b''.join(reader.iterChunks(1024))

        # Accept either "File modified" (mtime) or "File size changed" (both indicate change)
        exceptionStr = str(ctx.exception)
        self.assertTrue(
            "File modified" in exceptionStr or "File size changed" in exceptionStr,
            f"Expected change detection error, got: {exceptionStr}"
        )
        print(f"[Test] Strict mode correctly caught file change: {ctx.exception}")

    def testStrictModeFileDisappears(self):
        """Test that strict mode aborts when file disappears"""
        print("\n[Test] Testing strict mode with file disappearance")

        # Create reader in strict mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Simulate file disappearance
        originalValidate = reader._validateFileUnchanged

        def validateWithChange(entry):
            if not entry['isDir'] and entry['path'] == self.file1:
                # Delete the file
                os.remove(self.file1)
            return originalValidate(entry)

        reader._validateFileUnchanged = validateWithChange

        # Should raise RuntimeError on file disappearance
        with self.assertRaises(RuntimeError) as ctx:
            data = b''.join(reader.iterChunks(1024))

        self.assertIn("File disappeared", str(ctx.exception))
        print(f"[Test] Strict mode correctly caught file disappearance: {ctx.exception}")

    def testLenientModeWarnsButContinues(self):
        """Test that lenient mode warns but continues on changes"""
        print("\n[Test] Testing lenient mode with file changes")

        # Create reader in lenient mode (default for deflate)
        reader = ZipDirSourceReader(self.testFolder, compression='deflate', strictMode=False)

        # Count files processed
        filesProcessed = 0
        originalValidate = reader._validateFileUnchanged

        def validateWithChange(entry):
            nonlocal filesProcessed
            if not entry['isDir']:
                filesProcessed += 1
                if entry['path'] == self.file1:
                    # Change file size (should warn but not abort)
                    with open(self.file1, 'w') as f:
                        f.write("Modified content")
            return originalValidate(entry)

        reader._validateFileUnchanged = validateWithChange

        # Should NOT raise exception in lenient mode
        try:
            data = b''.join(reader.iterChunks(1024))
            print(f"[Test] Lenient mode continued despite changes (processed {filesProcessed} files)")
            self.assertGreater(len(data), 0, "Should produce output despite changes")
        except RuntimeError:
            self.fail("Lenient mode should not raise RuntimeError on file changes")

    def testStoreModeDefaultsToStrict(self):
        """Test that store mode defaults to strict"""
        print("\n[Test] Testing store mode defaults to strict")

        reader = ZipDirSourceReader(self.testFolder, compression='store')
        self.assertTrue(reader.strictMode, "Store mode should default to strict")

    def testDeflateModeDefaultsToLenient(self):
        """Test that deflate mode defaults to lenient"""
        print("\n[Test] Testing deflate mode defaults to lenient")

        reader = ZipDirSourceReader(self.testFolder, compression='deflate')
        self.assertFalse(reader.strictMode, "Deflate mode should default to lenient")

    def testExplicitStrictModeOverride(self):
        """Test explicit strict mode override"""
        print("\n[Test] Testing explicit strict mode override")

        # Force deflate mode to use strict
        reader = ZipDirSourceReader(self.testFolder, compression='deflate', strictMode=True)
        self.assertTrue(reader.strictMode, "Should honor explicit strictMode=True")

        # Force store mode to use lenient
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=False)
        self.assertFalse(reader.strictMode, "Should honor explicit strictMode=False")

    def testNoChangesSucceeds(self):
        """Test that transfer succeeds when no changes occur"""
        print("\n[Test] Testing transfer with no changes")

        # Create reader in strict mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Should complete successfully without changes
        try:
            data = b''.join(reader.iterChunks(1024))
            self.assertGreater(len(data), 0, "Should produce valid ZIP")
            self.assertTrue(data.startswith(b'PK\x03\x04'), "Should be valid ZIP")
            print("[Test] Transfer succeeded with no changes")
        except RuntimeError as e:
            self.fail(f"Should not raise error when no changes occur: {e}")

    def testStrictModeIOErrorOnFileRead(self):
        """Test that strict mode raises FolderChangedException on I/O errors during file reading"""
        print("\n[Test] Testing strict mode with I/O error during file read")

        # Create reader in strict mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Mock open() to raise OSError when reading file1 for streaming
        # We need to skip CRC computation by pre-caching CRC values
        originalOpen = open

        # Pre-compute CRCs so they're cached
        for entry in reader._segmentIndex.entries:
            if not entry['isDir']:
                reader._computeCRC(entry)

        openCallCount = 0

        def mockOpenWithIOError(path, mode='r', *args, **kwargs):
            nonlocal openCallCount
            # Now fail on file data streaming (CRCs are already cached)
            if 'rb' in mode and str(path) == self.file1:
                openCallCount += 1
                # Fail immediately since CRC is already cached
                raise OSError("Permission denied during streaming (simulated)")
            return originalOpen(path, mode, *args, **kwargs)

        # Should raise FolderChangedException on I/O error
        with patch('builtins.open', side_effect=mockOpenWithIOError):
            try:
                data = b''.join(reader.iterChunks(1024))
                self.fail("Should raise FolderChangedException on I/O error in strict mode")
            except FolderChangedException as e:
                self.assertIn("File read failed in strict mode", str(e))
                print(f"[Test] Strict mode correctly raised FolderChangedException on I/O error: {e}")

    def testStrictModeIOErrorOnCRCComputation(self):
        """Test that strict mode raises FolderChangedException on I/O errors during CRC computation"""
        print("\n[Test] Testing strict mode with I/O error during CRC computation")

        # Create reader in strict mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=True)

        # Mock open() to raise OSError when computing CRC for file2
        # Track which phase we're in based on open call order
        originalOpen = open
        openPhase = {'file2_opens': 0}

        def mockOpenWithIOError(path, mode='r', *args, **kwargs):
            # Fail only on first open for file2 (CRC phase, before streaming)
            if 'rb' in mode and str(path) == self.file2:
                openPhase['file2_opens'] += 1
                if openPhase['file2_opens'] == 1:
                    # First open is for CRC computation
                    raise OSError("Permission denied during CRC (simulated)")
            return originalOpen(path, mode, *args, **kwargs)

        # Should raise FolderChangedException on CRC I/O error
        with patch('builtins.open', side_effect=mockOpenWithIOError):
            try:
                data = b''.join(reader.iterChunks(1024))
                self.fail("Should raise FolderChangedException on CRC I/O error in strict mode")
            except FolderChangedException as e:
                # Accept both CRC and File read errors since they both indicate I/O failure
                self.assertTrue(
                    "CRC computation failed in strict mode" in str(e) or "File read failed in strict mode" in str(e),
                    f"Expected I/O error in strict mode, got: {e}"
                )
                print(f"[Test] Strict mode correctly raised FolderChangedException on I/O error: {e}")

    def testLenientModeIOErrorStreamsZeros(self):
        """Test that lenient mode streams zeros on I/O errors instead of failing"""
        print("\n[Test] Testing lenient mode with I/O error (should stream zeros)")

        # Create reader in lenient mode
        reader = ZipDirSourceReader(self.testFolder, compression='store', strictMode=False)

        # Mock open() to raise OSError when reading file1 for streaming (not CRC)
        originalOpen = open
        openCallCount = 0

        def mockOpenWithIOError(path, mode='r', *args, **kwargs):
            nonlocal openCallCount
            if 'rb' in mode and str(path) == self.file1:
                openCallCount += 1
                # Fail on second open (first is for CRC, second is for streaming)
                if openCallCount >= 2:
                    raise OSError("Permission denied (simulated)")
            return originalOpen(path, mode, *args, **kwargs)

        # Should NOT raise exception in lenient mode
        with patch('builtins.open', side_effect=mockOpenWithIOError):
            try:
                data = b''.join(reader.iterChunks(1024))
                self.assertGreater(len(data), 0, "Should produce output despite I/O error")
                print("[Test] Lenient mode continued despite I/O error (streamed zeros)")
            except FolderChangedException:
                self.fail("Lenient mode should not raise FolderChangedException on I/O errors")


class StdinStreamingTest(FastFileLinkTestBase):
    """Test stdin streaming with chunked transfer encoding (functional tests)"""

    def testStdinStreamingBasic(self):
        """Test basic stdin streaming: `cat file | python Core.py --cli -`"""
        print("\n[Test] Testing stdin streaming with chunked encoding")

        try:
            # Start stdin streaming
            shareLink = self._startStdinStreaming(self.testFilePath)

            # Download the file
            downloadedFilePath = self._getDownloadedFilePath("stdin")
            self.downloadFileWithRequests(shareLink, downloadedFilePath)

            # Verify downloaded file matches original
            downloadedHash = getFileHash(downloadedFilePath)
            self.assertEqual(downloadedHash, self.originalFileHash, "Downloaded file hash should match original")

            print("[Test] Stdin streaming successful - file verified")

        finally:
            self._terminateProcess()

    def testStdinStreamingWithCustomName(self):
        """Test stdin streaming with custom filename: `cat file | python Core.py --cli - --name custom.bin`"""
        print("\n[Test] Testing stdin streaming with custom filename")

        customName = "my-custom-file.bin"

        try:
            # Start stdin streaming with custom name
            shareLink = self._startStdinStreaming(self.testFilePath, customName=customName)

            # Verify content_name in JSON output
            with open(self.jsonOutputPath, 'r', encoding='utf-8') as f:
                jsonOutput = json.load(f)

            self.assertEqual(
                jsonOutput['content_name'], customName, f"content_name should be '{customName}' in JSON output"
            )
            print(f"[Test] Verified content_name in JSON: {jsonOutput['content_name']}")

            # Download the file and verify Content-Disposition header
            downloadedFilePath = self._getDownloadedFilePath("stdin_custom")
            self.downloadFileWithRequests(shareLink, downloadedFilePath, expectedFileName=customName)

            # Verify downloaded file matches original
            downloadedHash = getFileHash(downloadedFilePath)
            self.assertEqual(downloadedHash, self.originalFileHash, "Downloaded file hash should match original")

            print(f"[Test] Stdin streaming with custom name '{customName}' successful")

        finally:
            self._terminateProcess()

    def testStdinStreamingWithCurl(self):
        """Test stdin streaming download with curl (simulates real usage)"""
        print("\n[Test] Testing stdin streaming download with curl")

        try:
            # Start stdin streaming
            shareLink = self._startStdinStreaming(self.testFilePath)

            # Download with curl
            downloadedFilePath = self._getDownloadedFilePath("stdin_curl")

            curlCmd = ["curl", "-L", "-o", downloadedFilePath, shareLink]
            print(f"[Test] Running: {' '.join(curlCmd)}")

            result = subprocess.run(curlCmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                print(f"[Test] curl stderr: {result.stderr}")
                raise AssertionError(f"curl failed with exit code {result.returncode}")

            # Verify file was downloaded
            if not os.path.exists(downloadedFilePath):
                raise AssertionError("curl did not create output file")

            # Verify downloaded file matches original
            downloadedHash = getFileHash(downloadedFilePath)
            self.assertEqual(downloadedHash, self.originalFileHash, "Downloaded file hash should match original")

            print("[Test] curl download successful - no HTTP/2 stream errors")

        finally:
            self._terminateProcess()

    def testStdinStreamingLargeFile(self):
        """Test stdin streaming with larger file (multiple chunks)"""
        print("\n[Test] Testing stdin streaming with large file")

        # Create larger test file (10MB)
        largeFilePath = os.path.join(self.tempDir, "large_testfile.bin")
        print("[Test] Generating 10MB test file...")
        from tests.CoreTestBase import generateRandomFile
        generateRandomFile(largeFilePath, 10 * 1024 * 1024)
        largeFileHash = getFileHash(largeFilePath)

        try:
            # Start stdin streaming with large file
            shareLink = self._startStdinStreaming(largeFilePath)

            # Download the file
            downloadedFilePath = self._getDownloadedFilePath("stdin_large")
            self.downloadFileWithRequests(shareLink, downloadedFilePath)

            # Verify downloaded file matches original
            downloadedHash = getFileHash(downloadedFilePath)
            self.assertEqual(downloadedHash, largeFileHash, "Large file hash should match original")

            print("[Test] Large file stdin streaming successful")

        finally:
            self._terminateProcess()

    def testStdinStreamingMultipleReads(self):
        """Test that stdin caching allows multiple reads"""
        print("\n[Test] Testing stdin caching for multiple reads")

        try:
            # Start stdin streaming
            shareLink = self._startStdinStreaming(self.testFilePath)

            # First download should succeed and cache the data
            downloadedFilePath1 = self._getDownloadedFilePath("stdin_first")
            self.downloadFileWithRequests(shareLink, downloadedFilePath1)
            downloadedHash1 = getFileHash(downloadedFilePath1)
            print("[Test] First download successful")

            # Second download should succeed using cached data
            downloadedFilePath2 = self._getDownloadedFilePath("stdin_second")
            self.downloadFileWithRequests(shareLink, downloadedFilePath2)
            downloadedHash2 = getFileHash(downloadedFilePath2)
            print("[Test] Second download successful (from cache)")

            # Verify both downloads match
            self.assertEqual(downloadedHash1, downloadedHash2, "Second download should match first download")
            self.assertEqual(downloadedHash1, self.originalFileHash, "Both downloads should match original file")

            print("[Test] Multiple reads successful with caching")

        finally:
            self._terminateProcess()


class DeflateModeStreamingTest(FastFileLinkTestBase):
    """Test deflate compression mode with chunked transfer encoding"""

    def setUp(self):
        """Set up test folder instead of test file"""
        super().setUp()

        # Create test folder with files
        self.testFolderPath = os.path.join(self.tempDir, "test_folder")
        os.makedirs(self.testFolderPath)

        # Create test files
        for i in range(5):
            filePath = os.path.join(self.testFolderPath, f"file{i}.txt")
            with open(filePath, 'w') as f:
                f.write(f"Test content {i}\n" * 100)

        # Override testFilePath to point to folder
        self.testFilePath = self.testFolderPath

        # Update originalFileSize to -1 for deflate mode (size unknown until compressed)
        # This is used by _startFastFileLink to validate the JSON output
        self.originalFileSize = -1

    def testDeflateModeDownload(self):
        """Test folder download with deflate compression (chunked encoding)"""
        print("\n[Test] Testing deflate mode with chunked encoding")

        try:
            # Set deflate compression mode
            extraEnvVars = {'READER_FOLDER_COMPRESSION': 'deflate'}

            # Start FastFileLink with folder (P2P mode)
            shareLink = self._startFastFileLink(p2p=True, extraEnvVars=extraEnvVars)

            # Download the ZIP file
            downloadedZipPath = self._getDownloadedFilePath("test_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)

            # Verify it's a valid ZIP
            with zipfile.ZipFile(downloadedZipPath, 'r') as zipf:
                fileList = zipf.namelist()
                self.assertGreater(len(fileList), 0, "ZIP should contain files")

                # Verify files are in the ZIP
                for i in range(5):
                    expectedFile = f"test_folder/file{i}.txt"
                    self.assertIn(expectedFile, fileList, f"{expectedFile} should be in ZIP")

            print("[Test] Deflate mode download successful with chunked encoding")

        finally:
            self._terminateProcess()


class StdinCachingTest(unittest.TestCase):
    """Test StdinSourceReader caching functionality for multiple reads"""

    def testStdinTwiceRead(self):
        """Test that stdin can be read twice using cache"""

        # Create mock stdin data
        testData = b"Hello World from stdin! " * 1000 # ~24KB of data
        mockStdin = io.BytesIO(testData)

        # Create reader and replace stdin
        reader = StdinSourceReader('-')
        reader.stdin = mockStdin

        # First read - should stream from stdin and cache
        firstReadData = b''.join(reader.iterChunks(chunkSize=1024))
        self.assertEqual(firstReadData, testData, "First read should return all stdin data")
        self.assertTrue(reader._consumed, "Stdin should be marked as consumed")
        self.assertTrue(reader._hasCache(), "Cache should be available after first read")
        self.assertIsNotNone(reader.size, "Size should be known after first read")
        self.assertEqual(reader.size, len(testData), "Size should match data length")

        # Second read - should read from cache
        secondReadData = b''.join(reader.iterChunks(chunkSize=1024))
        self.assertEqual(secondReadData, testData, "Second read should return same data from cache")
        self.assertEqual(firstReadData, secondReadData, "Both reads should return identical data")

        # Verify cache file exists
        self.assertTrue(os.path.exists(reader._cachedFile), "Cache file should exist")

        # Cleanup
        cacheFilePath = reader._cachedFile # Save path before cleanup
        reader._cleanupCacheFile()
        if cacheFilePath:
            self.assertFalse(os.path.exists(cacheFilePath), "Cache file should be cleaned up")

        print("[Test] StdinSourceReader twice read successful with caching")

    def testStdinTwiceReadWithOffset(self):
        """Test that cached stdin supports Range/offset reads"""

        # Create mock stdin data
        testData = b"0123456789" * 100 # 1000 bytes
        mockStdin = io.BytesIO(testData)

        # Create reader and replace stdin
        reader = StdinSourceReader('-')
        reader.stdin = mockStdin

        # First read - cache all data
        firstReadData = b''.join(reader.iterChunks(chunkSize=256))
        self.assertEqual(firstReadData, testData)
        self.assertTrue(reader._hasCache())

        # Second read with offset - should read from cache starting at offset 500
        secondReadData = b''.join(reader.iterChunks(chunkSize=256, start=500))
        self.assertEqual(secondReadData, testData[500:], "Should read from offset 500")

        # Third read with different offset
        thirdReadData = b''.join(reader.iterChunks(chunkSize=256, start=100))
        self.assertEqual(thirdReadData, testData[100:], "Should read from offset 100")

        # Cleanup
        reader._cleanupCacheFile()

        print("[Test] StdinSourceReader Range/offset read from cache successful")


class DeflateCachingTest(unittest.TestCase):
    """Test ZipDirSourceReader deflate mode caching functionality"""

    def testDeflateTwiceRead(self):
        """Test that deflate ZIP can be read twice using cache (avoids re-compression)"""
        # Create test folder
        tmpdir = tempfile.mkdtemp()
        try:
            testFolder = os.path.join(tmpdir, 'test_folder')
            os.makedirs(testFolder)

            # Add test files
            for i in range(10):
                filePath = os.path.join(testFolder, f'file{i}.txt')
                with open(filePath, 'w') as f:
                    f.write(f'Test content {i}\n' * 1000) # ~17KB per file

            # Create reader with deflate compression
            reader = ZipDirSourceReader(testFolder, compression='deflate')

            # Verify initial state
            self.assertIsNone(reader.size, "Deflate mode should have unknown size initially")
            self.assertFalse(reader._hasCache(), "Should not have cache initially")

            # First read - should compress and cache
            firstReadData = b''.join(reader.iterChunks(chunkSize=8192))
            self.assertGreater(len(firstReadData), 0, "Should generate compressed ZIP data")
            self.assertTrue(reader._hasCache(), "Cache should be available after first read")
            self.assertIsNotNone(reader.size, "Size should be known after compression")
            self.assertEqual(reader.size, len(firstReadData), "Size should match compressed data length")

            # Verify it's a valid ZIP
            zipPath = os.path.join(tmpdir, 'test1.zip')
            with open(zipPath, 'wb') as f:
                f.write(firstReadData)
            with zipfile.ZipFile(zipPath, 'r') as zipf:
                fileList = zipf.namelist()
                self.assertEqual(len(fileList), 10, "ZIP should contain 10 files")

            # Second read - should read from cache (no re-compression)
            secondReadData = b''.join(reader.iterChunks(chunkSize=8192))
            self.assertEqual(len(secondReadData), len(firstReadData), "Second read should return same size data")
            self.assertEqual(firstReadData, secondReadData, "Both reads should return identical compressed data")

            # Verify second read is also valid ZIP
            zipPath2 = os.path.join(tmpdir, 'test2.zip')
            with open(zipPath2, 'wb') as f:
                f.write(secondReadData)
            with zipfile.ZipFile(zipPath2, 'r') as zipf:
                fileList = zipf.namelist()
                self.assertEqual(len(fileList), 10, "Second ZIP should also contain 10 files")

            # Verify cache file exists
            self.assertTrue(os.path.exists(reader._cachedFile), "Cache file should exist")

            print(f"[Test] Deflate ZIP twice read successful (size: {reader.size} bytes, "
                  f"compressed from ~170KB)")

        finally:
            shutil.rmtree(tmpdir)

    def testDeflateCachePersistence(self):
        """Test that deflate cache persists across multiple reads"""

        # Create test folder
        tmpdir = tempfile.mkdtemp()
        try:
            testFolder = os.path.join(tmpdir, 'test_folder')
            os.makedirs(testFolder)

            # Add test file
            with open(os.path.join(testFolder, 'file.txt'), 'w') as f:
                f.write('Test content\n' * 100)

            # Create reader
            reader = ZipDirSourceReader(testFolder, compression='deflate')

            # First read - cache
            data1 = b''.join(reader.iterChunks(chunkSize=1024))
            cacheFile1 = reader._cachedFile

            # Multiple subsequent reads - all from cache
            for i in range(5):
                dataN = b''.join(reader.iterChunks(chunkSize=1024))
                self.assertEqual(dataN, data1, f"Read {i+2} should match first read")
                self.assertEqual(reader._cachedFile, cacheFile1, "Cache file should remain same")

            print("[Test] Deflate cache persistence verified across 6 reads")

        finally:
            shutil.rmtree(tmpdir)


class ShutdownCleanupTest(unittest.TestCase):
    """Test CachingMixin shutdown event cleanup"""

    def testShutdownEventCleanup(self):
        """Test that shutdown event triggers cleanup of all cached files"""

        # Create test folder for ZipDirSourceReader
        tmpdir = tempfile.mkdtemp()
        try:
            testFolder = os.path.join(tmpdir, 'test_folder')
            os.makedirs(testFolder)
            with open(os.path.join(testFolder, 'file.txt'), 'w') as f:
                f.write('Test content\n' * 100)

            # Clear existing instances from previous tests
            CachingMixin._instances.clear()

            # Create multiple readers that will cache data
            readers = []

            # Reader 1: Stdin
            stdinReader = StdinSourceReader('-')
            stdinReader.stdin = io.BytesIO(b"Test data from stdin" * 100)
            list(stdinReader.iterChunks(1024)) # Trigger caching
            readers.append(stdinReader)
            self.assertTrue(stdinReader._hasCache(), "Stdin should have cache")

            # Reader 2: Deflate ZIP
            deflateReader = ZipDirSourceReader(testFolder, compression='deflate')
            list(deflateReader.iterChunks(1024)) # Trigger caching
            readers.append(deflateReader)
            self.assertTrue(deflateReader._hasCache(), "Deflate should have cache")

            # Reader 3: Another stdin
            stdinReader2 = StdinSourceReader('-')
            stdinReader2.stdin = io.BytesIO(b"More test data" * 100)
            list(stdinReader2.iterChunks(1024)) # Trigger caching
            readers.append(stdinReader2)
            self.assertTrue(stdinReader2._hasCache(), "Stdin2 should have cache")

            # Verify all readers have cache files
            self.assertEqual(len(CachingMixin._instances), 3, "Should have 3 cached instances")
            cacheFiles = [r._cachedFile for r in readers]
            for cacheFile in cacheFiles:
                self.assertTrue(os.path.exists(cacheFile), f"Cache file {cacheFile} should exist")

            # Trigger shutdown event
            FFLEvent.applicationShutdown.trigger()

            # Verify all cache files are cleaned up
            for cacheFile in cacheFiles:
                self.assertFalse(os.path.exists(cacheFile), f"Cache file {cacheFile} should be removed")

            # Verify instances list is cleared
            self.assertEqual(len(CachingMixin._instances), 0, "Instances list should be cleared")

            print(f"[Test] Shutdown event cleanup successful (cleaned up 3 cache files)")

        finally:
            shutil.rmtree(tmpdir)

    def testShutdownEventIdempotent(self):
        """Test that shutdown event can be triggered multiple times safely"""

        # Trigger shutdown multiple times - should not crash
        FFLEvent.applicationShutdown.trigger()
        FFLEvent.applicationShutdown.trigger()
        FFLEvent.applicationShutdown.trigger()

        print("[Test] Shutdown event is idempotent (multiple triggers work)")


if __name__ == '__main__':
    unittest.main()
