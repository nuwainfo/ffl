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

import os
import time
import unittest
import zipfile
import hashlib
import tempfile
import shutil
from unittest.mock import patch

from tests.CoreTestBase import FastFileLinkTestBase
from bases.Reader import ZipDirSourceReader, FolderChangedException


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
            "file2.bin": os.urandom(1024 * 10),  # 10KB random data
            "file3.dat": os.urandom(1024 * 50),  # 50KB random data
        }

        # Create a subfolder with nested files
        subfolderPath = os.path.join(self.testFolderPath, "subfolder")
        os.makedirs(subfolderPath)
        self.testFiles["subfolder/nested.txt"] = b"This is a nested file in a subfolder."
        self.testFiles["subfolder/data.bin"] = os.urandom(1024 * 5)  # 5KB

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
                if extractedPath == originalRelativePath or extractedPath.endswith(os.sep + originalRelativePath.replace('/', os.sep)):
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
            shareLink, testServerProcess = self._startFastFileLink(p2p=True, extraEnvVars=extraEnvVars, useTestServer=True)

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

        # Use current folder - create [FolderName].zip first, then download will overwrite it
        currentFolder = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        folderName = os.path.basename(currentFolder)

        # Create empty [FolderName].zip file in the folder being shared
        # This file will be in the snapshot and will be modified during download
        placeholderZipPath = os.path.join(currentFolder, f"{folderName}.zip")
        with open(placeholderZipPath, 'wb') as f:
            f.write(b"PK\x03\x04")  # ZIP magic bytes placeholder

        print(f"[Test] Created placeholder ZIP: {placeholderZipPath}")

        self.testFilePath = currentFolder

        from bases.Reader import SourceReader
        reader = SourceReader.build(currentFolder, compression='store')
        self.originalFileSize = reader.size
        print(f"[Test] Sharing current folder: {self.originalFileSize} bytes")

        try:
            # Start FastFileLink with current folder in P2P mode
            serverOutputCapture = {}
            shareLink = self._startFastFileLink(p2p=True, captureOutputIn=serverOutputCapture)

            # Download into current folder with same name as placeholder
            # This will overwrite the existing [FolderName].zip file, triggering change detection
            downloadOutputCapture = {}
            downloadedZipPath = placeholderZipPath  # Same file that's in the snapshot

            # Download should FAIL due to folder change - don't raise assertion
            try:
                self._downloadWithCore(shareLink, downloadedZipPath, captureOutputIn=downloadOutputCapture)
                downloadFailed = False
            except AssertionError as e:
                # Expected - download should fail
                downloadFailed = True
                print(f"[Test] Download failed as expected: {e}")

            # Verify download failed
            if not downloadFailed:
                self.fail("Download should have failed due to folder change, but succeeded")

            print("[Test] Download correctly failed [OK]")

            # Check server-side output for folder change detection
            serverOutput = self._updateCapturedOutput(serverOutputCapture)
            serverDetected = "TRANSFER ABORTED" in serverOutput and "File size changed during transfer" in serverOutput
            print(f"[Test] Server detected folder change: {serverDetected}")

            if not serverDetected:
                print(f"[Test] Server output length: {len(serverOutput)} chars")
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
                print(f"[Test] Client output length: {len(clientOutput)} chars")
                self.fail("Client did not receive folder change error notification")

            if not clientGotGuidance:
                self.fail("Client error message should include guidance to contact sharer")

            print("[Test] Client correctly received FolderChangedException with guidance [OK]")

        finally:
            self._terminateProcess()
            # Clean up placeholder/downloaded ZIP file
            if 'placeholderZipPath' in locals() and os.path.exists(placeholderZipPath):
                print(f"[Test] Cleaning up ZIP file: {placeholderZipPath}")
                try:
                    os.remove(placeholderZipPath)
                except Exception as e:
                    print(f"[Test] Failed to remove ZIP: {e}")


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
                time.sleep(0.02)  # Ensure time passes
                with open(self.file1, 'w') as f:
                    f.write("Modified content!")  # Same length as original
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
                    "CRC computation failed in strict mode" in str(e) or
                    "File read failed in strict mode" in str(e),
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


if __name__ == '__main__':
    unittest.main()
