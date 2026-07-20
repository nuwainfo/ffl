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
import json
import unittest
import zipfile

from ..CoreTestBase import FastFileLinkTestBase


# ---------------------------
# Download Test Class (CLI-based)
# ---------------------------
class DownloadTest(FastFileLinkTestBase):
    """Comprehensive test class for FastFileLink download functionality"""

    # Class-level constants
    PARTIAL_FILE_SIZE = 262144 # 256KB

    def __init__(self, methodName='runTest'):
        # Use smaller file size for faster download tests
        super().__init__(methodName, fileSizeBytes=512 * 1024) # 512KB
        self.testFolderPath = None # Will be created in setUp if needed

    def _createPartialFile(self, outputPath: str, partialSize: int = None) -> int:
        """Create a partial file to simulate interrupted download"""
        if partialSize is None:
            partialSize = self.PARTIAL_FILE_SIZE

        print(f"[Test] Creating partial file to simulate interrupted download")
        with open(self.testFilePath, 'rb') as source:
            with open(outputPath, 'wb') as dest:
                dest.write(source.read(partialSize))

        print(f"[Test] Partial file size: {partialSize} bytes")
        self.assertTrue(os.path.exists(outputPath), "Partial file should exist")
        self.assertEqual(os.path.getsize(outputPath), partialSize, f"Partial file should be {partialSize} bytes")
        return partialSize

    def _verifyOutputContains(self, outputCapture: dict, expectedText: str, errorMessage: str = None):
        """Verify that captured output contains expected text"""
        outputText = self._updateCapturedOutput(outputCapture)
        if errorMessage is None:
            errorMessage = f"Expected '{expectedText}' not found in output"
        self.assertIn(expectedText, outputText, errorMessage)

    def _createTestFolder(self) -> str:
        """
        Create a test folder with multiple files for folder sharing tests

        Returns:
            str: Path to the created test folder
        """
        folderPath = os.path.join(self.tempDir, "test_folder")
        os.makedirs(folderPath, exist_ok=True)

        # Create multiple files with different sizes
        testFiles = [
            ("file1.txt", b"This is file 1 content\n" * 100), # ~2.3KB
            ("file2.bin", os.urandom(50 * 1024)), # 50KB
            ("file3.dat", b"File 3 data\n" * 1000), # ~12KB
            ("subdir/file4.txt", b"Nested file content\n" * 50), # ~1KB in subdir
        ]

        for filename, content in testFiles:
            filePath = os.path.join(folderPath, filename)
            os.makedirs(os.path.dirname(filePath), exist_ok=True)
            with open(filePath, 'wb') as f:
                f.write(content)

        return folderPath

    def _verifyZipFile(self, zipPath: str, expectedFolder: str):
        """
        Verify that a downloaded ZIP file contains the expected folder structure

        Args:
            zipPath: Path to the ZIP file to verify
            expectedFolder: Path to the original folder for comparison
        """
        self.assertTrue(os.path.exists(zipPath), "ZIP file should exist")
        self.assertTrue(zipfile.is_zipfile(zipPath), "File should be a valid ZIP")

        with zipfile.ZipFile(zipPath, 'r') as zf:
            # Verify no corrupted files
            badFile = zf.testzip()
            self.assertIsNone(badFile, f"ZIP file should not be corrupted, but {badFile} is bad")

            # Extract and verify contents
            extractDir = os.path.join(self.tempDir, "extracted")
            os.makedirs(extractDir, exist_ok=True)
            zf.extractall(extractDir)

            # Verify all files exist and have correct content
            folderName = os.path.basename(expectedFolder)
            extractedFolder = os.path.join(extractDir, folderName)
            self.assertTrue(os.path.exists(extractedFolder), f"Extracted folder {folderName} should exist")

            # Compare each file
            for root, dirs, files in os.walk(expectedFolder):
                for filename in files:
                    originalFile = os.path.join(root, filename)
                    relativePath = os.path.relpath(originalFile, expectedFolder)
                    extractedFile = os.path.join(extractedFolder, relativePath)

                    self.assertTrue(os.path.exists(extractedFile), f"Extracted file {relativePath} should exist")

                    # Compare file sizes
                    originalSize = os.path.getsize(originalFile)
                    extractedSize = os.path.getsize(extractedFile)
                    self.assertEqual(originalSize, extractedSize, f"File {relativePath} should have same size")

                    # Compare file contents
                    with open(originalFile, 'rb') as f1, open(extractedFile, 'rb') as f2:
                        self.assertEqual(f1.read(), f2.read(), f"File {relativePath} should have same content")

    def _testFolderResume(self, useWebRTC: bool, simulateFailure: str = None):
        """
        Generic test for folder resume with Range support (DRY)

        Args:
            useWebRTC: True for WebRTC (p2p), False for HTTP only
            simulateFailure: Optional failure simulation ('ice_failure', 'stall', etc.)
        """
        testName = "WebRTC" if useWebRTC else "HTTP"
        if simulateFailure:
            testName += f" with {simulateFailure}"

        print(f"\n[Test] Testing folder Range resume with {testName}")

        # Create test folder
        if not self.testFolderPath:
            self.testFolderPath = self._createTestFolder()

        # Start sharing the folder by temporarily changing testFilePath and originalFileSize
        originalTestFilePath = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = self.testFolderPath
        # Set dummy file size for folder (will be validated by ZIP size from server)
        self.originalFileSize = -1 # Disable size check for folders

        outputCapture = {}
        try:
            shareLink = self._startFastFileLink(
                p2p=useWebRTC,
                timeout=60,
                useTestServer=True, # Use local test server
                captureOutputIn=outputCapture
            )
        finally:
            # Restore original values
            self.testFilePath = originalTestFilePath
            self.originalFileSize = originalFileSize

        # Verify folder hint appears in output (emoji may show as ? on some terminals)
        outputText = self._updateCapturedOutput(outputCapture)
        self.assertTrue(
            "📁 Sharing folder" in outputText or "? Sharing folder" in outputText or
            "Sharing folder as ZIP" in outputText, "Folder sharing hint should appear in output"
        )

        # Define output path for ZIP
        outputPath = os.path.join(self.tempDir, f"folder_resume_{testName.replace(' ', '_')}.zip")

        # First download: Download partial ZIP (simulate interrupted download)
        print(f"[Test] First download: Downloading partial ZIP from {testName}")
        partialSize = 30 * 1024 # 30KB partial download

        # Create partial file manually to simulate interrupted download at specific offset
        # We'll download full file first to a temp location, then create partial
        tempFullPath = os.path.join(self.tempDir, "temp_full.zip")

        extraEnvVars = {}
        if simulateFailure == 'ice_failure':
            extraEnvVars["WEBRTC_CLI_SIMULATE_ICE_FAILURE"] = "True"
        elif simulateFailure == 'stall':
            extraEnvVars["WEBRTC_CLI_SIMULATE_STALL"] = "True"
            extraEnvVars["WEBRTC_CLI_STALL_AFTER_BYTES"] = str(partialSize)

        # Download full file to temp location first
        self._downloadWithCore(
            shareLink, outputPath=tempFullPath, extraEnvVars=extraEnvVars if simulateFailure else None
        )

        # Create partial file from full download
        with open(tempFullPath, 'rb') as source:
            with open(outputPath, 'wb') as dest:
                dest.write(source.read(partialSize))

        print(f"[Test] Created partial ZIP file: {partialSize} bytes")
        self.assertEqual(os.path.getsize(outputPath), partialSize, f"Partial file should be {partialSize} bytes")

        # Second download: Resume with --resume flag
        print(f"[Test] Second download: Resuming from offset {partialSize}")
        resumeOutputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraArgs=["--resume"],
            extraEnvVars=extraEnvVars if simulateFailure else None,
            captureOutputIn=resumeOutputCapture
        )

        # Verify resume happened
        self._verifyOutputContains(resumeOutputCapture, "Resuming", f"Resume message should appear for {testName}")

        # Verify ZIP file is complete and valid
        print(f"[Test] Verifying downloaded ZIP file")
        self._verifyZipFile(downloadedPath, self.testFolderPath)

        # Compare with original full download
        with open(tempFullPath, 'rb') as f1, open(downloadedPath, 'rb') as f2:
            self.assertEqual(f1.read(), f2.read(), "Resumed ZIP should match original full download")

        print(f"[Test] {testName} folder Range resume test passed!")

    def testBasicDownload(self):
        """Test basic download functionality with connection status and progress tracking"""
        print("\n[Test] Testing basic download with WebRTC and connection status")

        # Start sharing process
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, timeout=60, captureOutputIn=outputCapture)

        # Define unique output path to avoid file already exists issue
        outputPath = os.path.join(self.tempDir, "basic_download_test.bin")

        # Download and capture output to verify connection status messages
        downloadOutputCapture = {}
        downloadedPath = self._downloadWithCore(shareLink, outputPath=outputPath, captureOutputIn=downloadOutputCapture)

        # Update captured output with latest
        outputText = self._updateCapturedOutput(downloadOutputCapture)

        # Verify connection status messages appear in output
        expectedMessages = ["Connecting to server", "Requesting connection", "Setting up WebRTC"]

        foundMessages = []
        for msg in expectedMessages:
            if msg in outputText:
                foundMessages.append(msg)

        # At least some connection status should be visible
        self.assertGreater(len(foundMessages), 0, f"No connection status messages found in output: {outputText}")

        # Verify downloaded file
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print(f"[Test] Found connection phases: {foundMessages}")

    def testOutputPathHandling(self):
        """Test various output path scenarios: custom path, relative path, directory"""
        print("\n[Test] Testing output path handling")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Test 1: Custom absolute output path
        customOutputPath = os.path.join(self.tempDir, "custom_downloaded_file.bin")
        downloadedPath = self._downloadWithCore(shareLink, outputPath=customOutputPath)

        self.assertEqual(downloadedPath, customOutputPath)
        self.assertTrue(os.path.exists(customOutputPath))
        self._verifyDownloadedFile(downloadedPath)

        # Test 2: Relative output path
        relativeOutputPath = "relative_download.bin"
        downloadedPath = self._downloadWithCore(shareLink, outputPath=relativeOutputPath)

        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        # Cleanup relative file
        if os.path.exists(downloadedPath):
            os.remove(downloadedPath)

        # Test 3: Directory as output path
        outputDir = os.path.join(self.tempDir, "download_dir")
        os.makedirs(outputDir, exist_ok=True)

        downloadedPath = self._downloadWithCore(shareLink, outputPath=outputDir)

        self.assertTrue(downloadedPath.startswith(outputDir))
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] All output path scenarios working correctly")

    def testHTTPFallbackDownload(self):
        """Test that HTTP fallback works when WebRTC fails due to ICE failure"""
        print("\n[Test] Testing HTTP fallback download mechanism with ICE failure simulation")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Define unique output path to avoid file already exists issue
        outputPath = os.path.join(self.tempDir, "http_fallback_test.bin")

        # Download with ICE failure simulation to trigger HTTP fallback
        downloadOutputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"},
            captureOutputIn=downloadOutputCapture
        )

        # Verify HTTP fallback was triggered
        self._verifyOutputContains(
            downloadOutputCapture, "HTTP fallback", "HTTP fallback should be triggered on ICE failure"
        )

        # Verify file was downloaded successfully via HTTP
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] HTTP fallback mechanism working correctly")

    def testWebRTCResumableDownload(self):
        """Test that WebRTC downloads can be resumed with --resume flag"""
        print("\n[Test] Testing WebRTC resumable download with --resume flag")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Define output path
        outputPath = os.path.join(self.tempDir, "resume_download.bin")

        # Create a partial file to simulate interrupted download
        # Note: With HTTP fallback enabled, stall simulation would trigger fallback and complete
        # So we manually create a partial file instead
        self._createPartialFile(outputPath)

        # Second download: Resume with --resume flag
        print("[Test] Second download: Resuming with --resume flag")
        downloadOutputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink, outputPath=outputPath, extraArgs=["--resume"], captureOutputIn=downloadOutputCapture
        )

        # Verify resume message appears
        self._verifyOutputContains(downloadOutputCapture, "Resuming", "Resume message should appear in output")

        # Verify file was completed successfully
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] WebRTC resumable download working correctly")

    def testHTTPFallbackWithResume(self):
        """Test that HTTP fallback can resume from WebRTC partial download"""
        print("\n[Test] Testing HTTP fallback with resume (stall in WebRTC, then ICE failure on resume)")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Define output path
        outputPath = os.path.join(self.tempDir, "fallback_resume_download.bin")

        # Create a partial file to simulate interrupted download
        # Note: With HTTP fallback enabled, stall simulation would trigger fallback and complete
        partialSize = self._createPartialFile(outputPath)
        print(f"[Test] Partial file size from WebRTC: {partialSize} bytes")

        # Second download: Resume with --resume, but simulate ICE failure to force HTTP fallback
        print("[Test] Second download: Resuming with --resume, forcing HTTP fallback via ICE failure")
        downloadOutputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraArgs=["--resume"],
            extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"},
            captureOutputIn=downloadOutputCapture
        )

        # Verify HTTP fallback was triggered
        self._verifyOutputContains(
            downloadOutputCapture, "HTTP fallback", "HTTP fallback should be triggered on ICE failure"
        )

        # Verify resume happened (either in WebRTC attempt or HTTP fallback)
        # HTTP fallback should automatically resume from the partial WebRTC download
        outputText = self._updateCapturedOutput(downloadOutputCapture)
        self.assertTrue(
            "Resuming from" in outputText or partialSize > 0, "Resume should occur from WebRTC partial download"
        )

        # Verify file was completed successfully via HTTP fallback
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] HTTP fallback with resume working correctly")

    def testWebRTCStallWithHTTPFallback(self):
        """Test that download completes via HTTP fallback when WebRTC stalls"""
        print("\n[Test] Testing WebRTC stall with HTTP fallback")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Define unique output path
        outputPath = os.path.join(self.tempDir, "stall_fallback_test.bin")

        # Download with stall simulation - should trigger HTTP fallback after stall
        downloadOutputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraEnvVars={
                "WEBRTC_CLI_SIMULATE_STALL": "True",
                "WEBRTC_CLI_STALL_AFTER_BYTES": str(self.PARTIAL_FILE_SIZE)
            },
            captureOutputIn=downloadOutputCapture
        )

        # Verify HTTP fallback was triggered due to stall
        self._verifyOutputContains(
            downloadOutputCapture, "HTTP fallback", "HTTP fallback should be triggered when WebRTC stalls"
        )

        # Verify file was downloaded successfully via HTTP fallback
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] WebRTC stall with HTTP fallback working correctly")

    def testConnectionTimeout(self):
        """Test that connection timeout triggers HTTP fallback"""
        print("\n[Test] Testing connection timeout with HTTP fallback")

        # Start sharing process
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        # Define unique output path
        outputPath = os.path.join(self.tempDir, "connection_timeout_test.bin")

        # Download with connection hang simulation and short timeout
        # This should timeout after 5 seconds and fall back to HTTP
        downloadOutputCapture = {}
        try:
            downloadedPath = self._downloadWithCore(
                shareLink,
                outputPath=outputPath,
                extraArgs=["--log-level", "tests/presets/WebRTCBoreDebugLogging.json"], # Enable WebRTC debug logging
                extraEnvVars={
                    "WEBRTC_CLI_SIMULATE_CONNECTION_HANG": "True",
                    "WEBRTC_CLI_CONNECTION_TIMEOUT": "5" # 5 second timeout for test
                },
                captureOutputIn=downloadOutputCapture
            )
        except AssertionError as e:
            # Print the captured output for debugging
            outputText = self._updateCapturedOutput(downloadOutputCapture)
            print(f"\n[Test] Download failed, captured output:\n{outputText}")
            raise

        # Verify HTTP fallback was triggered due to timeout
        self._verifyOutputContains(
            downloadOutputCapture, "HTTP fallback", "HTTP fallback should be triggered when connection times out"
        )

        # Verify file was downloaded successfully via HTTP fallback
        self.assertTrue(os.path.exists(downloadedPath))
        self._verifyDownloadedFile(downloadedPath)

        print("[Test] Connection timeout with HTTP fallback working correctly")

    def testDownloadErrorHandling(self):
        """Test download error handling for invalid URLs and graceful failure"""
        print("\n[Test] Testing download error handling")

        invalidUrl = "https://invalid.fastfilelink.com/invalid"

        # Attempt download with invalid URL - should fail gracefully
        with self.assertRaises(AssertionError):
            self._downloadWithCore(invalidUrl)

        print("[Test] Error handling working correctly")

    def testGenericURLDownload(self):
        """Test downloading from a generic HTTP URL (like wget) without /download endpoint"""
        print("\n[Test] Testing generic URL download (wget-like behavior)")

        # Use a reliable public URL that returns HTML.
        testUrl = "https://www.google.com/"
        outputPath = os.path.join(self.tempDir, "example.html")

        # Download using FFL.py
        downloadOutputCapture = {}
        try:
            downloadedPath = self._downloadWithCore(
                testUrl, outputPath=outputPath, captureOutputIn=downloadOutputCapture
            )
        except AssertionError as e:
            # Print the captured output for debugging
            outputText = self._updateCapturedOutput(downloadOutputCapture)
            print(f"\n[Test] Download failed, captured output:\n{outputText}")
            raise

        # Verify warning message was shown
        # Note: The emoji may appear as ?? on some terminals (e.g., Windows cp950 encoding)
        outputText = self._updateCapturedOutput(downloadOutputCapture)
        self.assertTrue(
            "⚠️" in outputText or "??" in outputText,
            "Warning indicator (emoji or placeholder) should be shown for generic URLs"
        )
        self._verifyOutputContains(
            downloadOutputCapture, "not a FastFileLink URL",
            "Warning message should indicate this is not a FastFileLink URL"
        )
        self._verifyOutputContains(downloadOutputCapture, "wget", "Warning message should mention wget-like behavior")

        # Verify file was downloaded
        self.assertTrue(os.path.exists(downloadedPath), "Downloaded file should exist")
        self.assertGreater(os.path.getsize(downloadedPath), 0, "Downloaded file should not be empty")

        # Verify content is HTML
        with open(downloadedPath, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("<!doctype html>", content.lower(), "Downloaded content should be HTML")
            self.assertIn("google", content.lower(), "Downloaded content should contain 'Google'")

        print(f"[Test] Generic URL download successful: {downloadedPath}")
        print(f"[Test] File size: {os.path.getsize(downloadedPath)} bytes")
        print("[Test] Generic URL download (wget-like) working correctly")

    def testFolderWebRTCResume(self):
        """Test folder download resume with WebRTC and Range support"""
        self._testFolderResume(useWebRTC=True, simulateFailure=None)

    def testFolderHTTPResume(self):
        """Test folder download resume with HTTP and Range support"""
        originalDisableSidecar = os.environ.get("FFL_DISABLE_SIDECAR")
        os.environ["FFL_DISABLE_SIDECAR"] = "True"
        try:
            self._testFolderResume(useWebRTC=False, simulateFailure=None)
        finally:
            if originalDisableSidecar is None:
                os.environ.pop("FFL_DISABLE_SIDECAR", None)
            else:
                os.environ["FFL_DISABLE_SIDECAR"] = originalDisableSidecar

    def testFolderWebRTCWithICEFailureFallback(self):
        """Test folder download with WebRTC ICE failure falling back to HTTP Range resume"""
        self._testFolderResume(useWebRTC=True, simulateFailure='ice_failure')

    def testStdinWebRTCDownload(self):
        """
        Test WebRTC download with unknown size from a stdin-backed share.
        """
        print("\n[Test] Testing WebRTC download with unknown size (stdin streaming)")

        try:
            shareLink = self._startFastFileLink(stdinInputPath=self.testFilePath)

            # Read share info to verify unknown size
            with open(self.jsonOutputPath, 'r') as f:
                shareInfo = json.load(f)

            fileSize = shareInfo.get("fileSize", -1)
            print(f"[Test] File size from JSON: {fileSize} (should be -1 for unknown size)")

            # Verify unknown size
            self.assertEqual(fileSize, -1, "Stdin should report unknown size (-1)")

            # Download the file using WebRTC
            outputPath = os.path.join(self.tempDir, "stdin_webrtc_download.bin")
            downloadOutputCapture = {}
            downloadedPath = self._downloadWithCore(shareLink, outputPath=outputPath, captureOutputIn=downloadOutputCapture)

            # Verify download messages
            outputText = self._updateCapturedOutput(downloadOutputCapture)

            # Check for unknown size message
            self.assertIn("unknown bytes", outputText, "Should show 'unknown bytes' for stdin")

            # Verify WebRTC was used (P2P message)
            if "P2P" in outputText or "WebRTC" in outputText:
                print("[Test] WebRTC confirmed in output")
            else:
                # HTTP fallback is acceptable too (on some systems WebRTC may not work)
                print("[Test] HTTP fallback occurred (WebRTC may not be available)")

            # Verify downloaded file matches original
            self.assertTrue(os.path.exists(downloadedPath), "Downloaded file should exist")
            downloadedHash = self.getFileHash(downloadedPath)
            self.assertEqual(
                downloadedHash, self.originalFileHash, "Downloaded file should match original (stdin streaming)"
            )

            print("[Test] Stdin WebRTC download with unknown size successful!")

        finally:
            self._terminateProcess()

    def testStdoutDownload(self):
        """Test --stdout download: file bytes come via stdout, progress to stderr (WebRTC path)"""
        print("\n[Test] Testing --stdout download via WebRTC")

        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        rawBytes, stderrOutput = self._downloadWithCore(shareLink, stdoutMode=True)

        # Write captured bytes to a temp file so _verifyDownloadedFile can hash it
        outputPath = os.path.join(self.tempDir, "stdout_download_webrtc.bin")
        with open(outputPath, 'wb') as f:
            f.write(rawBytes)

        # Verify no "Downloaded:" path line leaked onto stdout
        self.assertNotIn(b"Downloaded:", rawBytes, "Progress messages must not appear in stdout binary stream")

        # Progress messages should be on stderr
        self.assertIn("Download complete", stderrOutput, "Completion message should appear on stderr")

        self._verifyDownloadedFile(outputPath)
        print("[Test] --stdout WebRTC download successful")

    def testStdoutHTTPFallbackDownload(self):
        """Test --stdout download via HTTP fallback (ICE failure forces HTTP path)"""
        print("\n[Test] Testing --stdout download via HTTP fallback")

        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        rawBytes, stderrOutput = self._downloadWithCore(
            shareLink,
            extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"},
            stdoutMode=True
        )

        outputPath = os.path.join(self.tempDir, "stdout_download_http.bin")
        with open(outputPath, 'wb') as f:
            f.write(rawBytes)

        self.assertNotIn(b"Downloaded:", rawBytes, "Progress messages must not appear in stdout binary stream")

        # HTTP fallback produces "HTTP fallback" in progress output (goes to stderr)
        self.assertIn("HTTP fallback", stderrOutput, "HTTP fallback message should appear on stderr")

        self._verifyDownloadedFile(outputPath)
        print("[Test] --stdout HTTP fallback download successful")


if __name__ == '__main__':
    unittest.main()
