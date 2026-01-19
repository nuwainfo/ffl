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
VFS (Virtual File System) high-level integration tests.

Tests the complete VFS workflow:
1. Share file via --vfs to get vfs:// link
2. Share the vfs:// link as a file to get HTTP link
3. Download and verify file integrity
"""

import os
import unittest
import zipfile
import threading
import concurrent.futures

from ..CoreTestBase import FastFileLinkTestBase, getFileHash


class VFSIntegrationTest(FastFileLinkTestBase):
    """High-level integration tests for VFS mode"""

    def __init__(self, methodName='runTest'):
        # Use smaller file size for faster tests (1 MB)
        super().__init__(methodName, fileSizeBytes=1024 * 1024)
        self.vfsProcess = None
        self.vfsOutputCapture = None

    def tearDown(self):
        """Clean up VFS process before base tearDown"""
        # Terminate VFS server process
        if self.vfsProcess:
            if self.vfsProcess.poll() is None:
                print("[Test] Cleaning up VFS server process...")
                self.vfsProcess.terminate()
                try:
                    self.vfsProcess.wait(timeout=5)
                except:
                    self.vfsProcess.kill()
                    self.vfsProcess.wait()
            else:
                print(f"[Test] VFS server already terminated with code {self.vfsProcess.returncode}")
                if self.vfsOutputCapture and self.vfsProcess.returncode != 0:
                    output = self._updateCapturedOutput(self.vfsOutputCapture)
                    print(f"[Test] VFS server output:\n{output}")

        # Close VFS output capture log file to avoid Windows file locking
        if self.vfsOutputCapture:
            logFile = self.vfsOutputCapture.get('_logFile')
            if logFile:
                try:
                    logFile.close()
                except Exception:
                    pass
            self.vfsOutputCapture = None

        super().tearDown()

    def testVFSBasicFileSharing(self):
        """
        Test complete VFS workflow:
        1. Share file with --vfs to get vfs://
        2. Share the vfs:// link to get HTTP link
        3. Download and verify integrity
        """
        print("\n[Test] ========== VFS Basic File Sharing Test ==========")

        # Step 1: Share file via VFS to get vfs:// link
        print("\n[Test] Step 1: Starting VFS server...")
        vfsLink = self._startVFSServer(self.testFilePath, extraArgs=["--timeout", "120"])
        print(f"[Test] VFS link: {vfsLink}")

        # Step 2: Share vfs:// link to get HTTP link
        print("\n[Test] Step 2: Sharing VFS link to get HTTP URL...")
        httpShareLink = self._shareVfsLink(vfsLink)
        print(f"[Test] HTTP link: {httpShareLink}")

        # Step 3: Download and verify
        print("\n[Test] Step 3: Downloading and verifying file...")
        downloadedFile = self._getDownloadedFilePath("vfs_basic.bin")
        self.downloadFileWithRequests(httpShareLink, downloadedFile)
        self._verifyDownloadedFile(downloadedFile)

        print("\n[Test] ========== VFS Basic Test PASSED ==========")

    def testVFSFolderSharing(self):
        """
        Test VFS with folder:
        1. Share folder via VFS
        2. Share vfs:// link to get HTTP link
        3. Download ZIP and verify contents
        """
        print("\n[Test] ========== VFS Folder Sharing Test ==========")

        # Create test folder
        testFolder = os.path.join(self.tempDir, "test_folder")
        os.makedirs(testFolder)

        file1Path = os.path.join(testFolder, "file1.txt")
        file2Path = os.path.join(testFolder, "file2.txt")
        with open(file1Path, 'w') as f:
            f.write("Hello World from file1\n" * 100)
        with open(file2Path, 'w') as f:
            f.write("Test content from file2\n" * 100)

        file1Hash = getFileHash(file1Path)
        file2Hash = getFileHash(file2Path)
        print(f"[Test] Created test folder with 2 files")

        # Step 1: Share folder via VFS
        print("\n[Test] Step 1: Starting VFS server for folder...")
        vfsLink = self._startVFSServer(testFolder, extraArgs=["--timeout", "120"])
        print(f"[Test] VFS link: {vfsLink}")

        # Step 2: Share vfs:// link
        print("\n[Test] Step 2: Sharing VFS link...")
        httpShareLink = self._shareVfsLink(vfsLink)

        # Step 3: Download ZIP and verify
        print("\n[Test] Step 3: Downloading ZIP file...")
        downloadedZip = self._getDownloadedFilePath("vfs_folder.zip")
        self.downloadFileWithRequests(httpShareLink, downloadedZip)

        # Extract and verify
        print("[Test] Extracting and verifying ZIP contents...")
        self.assertTrue(zipfile.is_zipfile(downloadedZip), "Not a valid ZIP file")

        extractDir = os.path.join(self.tempDir, "extracted")
        os.makedirs(extractDir)
        with zipfile.ZipFile(downloadedZip, 'r') as zipf:
            zipf.extractall(extractDir)

        extractedFile1 = os.path.join(extractDir, "test_folder", "file1.txt")
        extractedFile2 = os.path.join(extractDir, "test_folder", "file2.txt")

        self.assertTrue(os.path.exists(extractedFile1), "file1.txt not in ZIP")
        self.assertTrue(os.path.exists(extractedFile2), "file2.txt not in ZIP")

        self.assertEqual(getFileHash(extractedFile1), file1Hash, "file1 hash mismatch")
        self.assertEqual(getFileHash(extractedFile2), file2Hash, "file2 hash mismatch")

        print("\n[Test] ========== VFS Folder Test PASSED ==========")

    def testVFSWithAuthentication(self):
        """
        Test VFS with HTTP Basic Authentication:
        1. Share file with --vfs --auth-password
        2. Verify auth is enabled and password not shown
        3. Share vfs:// link with credentials
        4. Download and verify
        """
        print("\n[Test] ========== VFS Authentication Test ==========")

        authUser = "testuser"
        authPassword = "testpass123"

        # Step 1: Start VFS with auth
        print("\n[Test] Step 1: Starting VFS server with authentication...")
        vfsLink = self._startVFSServer(
            self.testFilePath,
            extraArgs=["--auth-user", authUser, "--auth-password", authPassword, "--timeout", "120"],
            captureOutput=True # Capture output for verification
        )

        # Verify auth in logs
        print("[Test] Verifying authentication output...")
        self._verifyVFSAuthOutput(authUser, authPassword)

        # VFS link should NOT contain password
        self.assertNotIn(authPassword, vfsLink, "Password in VFS link!")
        print(f"[Test] VFS link (without password): {vfsLink}")

        # Step 2: Create authenticated VFS URI
        from urllib.parse import urlparse
        parsed = urlparse(vfsLink)
        vfsLinkWithAuth = f"vfs://{authUser}:{authPassword}@{parsed.netloc}"
        print(f"[Test] Authenticated VFS URI created")

        # Step 3: Share authenticated vfs:// link
        print("\n[Test] Step 2: Sharing authenticated VFS link...")
        httpShareLink = self._shareVfsLink(vfsLinkWithAuth)

        # Step 4: Download and verify
        print("\n[Test] Step 3: Downloading and verifying...")
        downloadedFile = self._getDownloadedFilePath("vfs_auth.bin")
        self.downloadFileWithRequests(httpShareLink, downloadedFile)
        self._verifyDownloadedFile(downloadedFile)

        print("\n[Test] ========== VFS Authentication Test PASSED ==========")

    # Helper methods for VFS testing

    def _startVFSServer(self, path, extraArgs=None, captureOutput=False):
        """
        Start VFS server and return vfs:// link.

        Args:
            path: File or folder path to share
            extraArgs: Additional CLI arguments
            captureOutput: If True, capture output for verification

        Returns:
            str: vfs:// link
        """
        # Temporarily replace testFilePath and originalFileSize
        originalPath = self.testFilePath
        originalSize = self.originalFileSize
        self.testFilePath = path
        self.originalFileSize = -1  # VFS returns unknown size (-1)

        try:
            # Build args with --vfs
            args = ["--vfs"]
            if extraArgs:
                args.extend(extraArgs)

            # Prepare output capture if needed
            outputCapture = {} if captureOutput else None

            # Use base class method to start VFS server
            vfsLink = self._startFastFileLink(p2p=True, extraArgs=args, captureOutputIn=outputCapture)

            # Save VFS process separately (base class stores in self.coreProcess)
            self.vfsProcess = self.coreProcess
            self.coreProcess = None # Clear so base tearDown doesn't kill VFS server prematurely

            # Save output capture for verification
            if captureOutput:
                self.vfsOutputCapture = outputCapture

            # Verify it's a vfs:// link
            self.assertIsNotNone(vfsLink, "No VFS link returned")
            self.assertTrue(vfsLink.startswith('vfs://'), f"Invalid VFS link: {vfsLink}")

            return vfsLink
        finally:
            self.testFilePath = originalPath
            self.originalFileSize = originalSize

    def _shareVfsLink(self, vfsLink):
        """
        Share a vfs:// link to get HTTP share link.

        Args:
            vfsLink: vfs:// URI to share

        Returns:
            str: HTTP share link
        """
        # Temporarily replace testFilePath, originalFileSize, and jsonOutputPath
        originalPath = self.testFilePath
        originalSize = self.originalFileSize
        originalJsonPath = self.jsonOutputPath

        self.testFilePath = vfsLink
        self.originalFileSize = -1  # VFS link also returns unknown size
        self.jsonOutputPath = os.path.join(self.tempDir, "share_vfs_link.json")  # Use different JSON file

        try:
            # Reuse base class method with longer timeout (needs to stay alive for download)
            shareLink = self._startFastFileLink(p2p=True, extraArgs=["--timeout", "120"])
            return shareLink
        finally:
            self.testFilePath = originalPath
            self.originalFileSize = originalSize
            self.jsonOutputPath = originalJsonPath

    def testVFSWithEnvAuthentication(self):
        """
        Test VFS with environment variable authentication:
        1. Share file with --vfs --auth-password
        2. Set FFL_VFS_AUTH_USER and FFL_VFS_AUTH_PASSWORD env vars
        3. Share vfs:// link (without credentials in URI)
        4. Download and verify
        """
        print("\n[Test] ========== VFS Environment Variable Auth Test ==========")

        authUser = "envuser"
        authPassword = "envpass456"

        # Step 1: Start VFS with auth
        print("\n[Test] Step 1: Starting VFS server with authentication...")
        vfsLink = self._startVFSServer(
            self.testFilePath,
            extraArgs=["--auth-user", authUser, "--auth-password", authPassword, "--timeout", "120"],
            captureOutput=True
        )

        # VFS link should NOT contain password
        self.assertNotIn(authPassword, vfsLink, "Password in VFS link!")
        print(f"[Test] VFS link (without credentials): {vfsLink}")

        # Step 2: Share vfs:// link using environment variables for auth
        print("\n[Test] Step 2: Sharing VFS link with env var authentication...")
        httpShareLink = self._shareVfsLinkWithEnvAuth(vfsLink, authUser, authPassword)
        print(f"[Test] HTTP link: {httpShareLink}")

        # Step 3: Download and verify
        print("\n[Test] Step 3: Downloading and verifying...")
        downloadedFile = self._getDownloadedFilePath("vfs_env_auth.bin")
        self.downloadFileWithRequests(httpShareLink, downloadedFile)
        self._verifyDownloadedFile(downloadedFile)

        print("\n[Test] ========== VFS Environment Variable Auth Test PASSED ==========")

    def testVFSConcurrentDownloads(self):
        """
        Test concurrent downloads from VFS via HTTPFileSystem.

        This tests the thread-local HttpSession fix - before the fix,
        concurrent downloads would block each other due to shared _activeStream flag.

        1. Share file via VFS
        2. Share vfs:// link to get HTTP link
        3. Download same file simultaneously from multiple threads
        4. Verify all downloads complete successfully with correct hash
        """
        print("\n[Test] ========== VFS Concurrent Downloads Test ==========")

        numConcurrent = 5  # Number of simultaneous downloads

        # Step 1: Share file via VFS
        print("\n[Test] Step 1: Starting VFS server...")
        vfsLink = self._startVFSServer(self.testFilePath, extraArgs=["--timeout", "180"])
        print(f"[Test] VFS link: {vfsLink}")

        # Step 2: Share vfs:// link to get HTTP link
        print("\n[Test] Step 2: Sharing VFS link to get HTTP URL...")
        httpShareLink = self._shareVfsLink(vfsLink)
        print(f"[Test] HTTP link: {httpShareLink}")

        # Step 3: Concurrent downloads
        print(f"\n[Test] Step 3: Starting {numConcurrent} concurrent downloads...")

        results = {}
        errors = {}
        lock = threading.Lock()

        def downloadWorker(threadId):
            """Worker function for concurrent download"""
            downloadPath = self._getDownloadedFilePath(f"concurrent_{threadId}.bin")
            try:
                print(f"[Test] Thread-{threadId}: Starting download...")
                self.downloadFileWithRequests(httpShareLink, downloadPath)
                fileHash = getFileHash(downloadPath)
                fileSize = os.path.getsize(downloadPath)
                print(f"[Test] Thread-{threadId}: Completed (size={fileSize}, hash={fileHash[:16]}...)")

                with lock:
                    results[threadId] = {
                        'path': downloadPath,
                        'hash': fileHash,
                        'size': fileSize
                    }
            except Exception as e:
                print(f"[Test] Thread-{threadId}: FAILED - {e}")
                with lock:
                    errors[threadId] = str(e)

        # Use ThreadPoolExecutor for concurrent downloads
        with concurrent.futures.ThreadPoolExecutor(max_workers=numConcurrent) as executor:
            futures = [executor.submit(downloadWorker, i) for i in range(numConcurrent)]
            concurrent.futures.wait(futures)

        # Step 4: Verify results
        print(f"\n[Test] Step 4: Verifying results...")
        print(f"[Test] Successful: {len(results)}, Failed: {len(errors)}")

        # Check no errors
        if errors:
            for threadId, error in errors.items():
                print(f"[Test] Thread-{threadId} error: {error}")
            self.fail(f"Some downloads failed: {errors}")

        # Check all downloads succeeded
        self.assertEqual(len(results), numConcurrent, f"Expected {numConcurrent} results")

        # Get expected hash from original file
        expectedHash = getFileHash(self.testFilePath)
        print(f"[Test] Expected hash: {expectedHash[:16]}...")

        # Verify all downloads have correct hash
        for threadId, result in results.items():
            self.assertEqual(
                result['hash'], expectedHash,
                f"Thread-{threadId}: Hash mismatch (got {result['hash'][:16]}...)"
            )

        print(f"\n[Test] All {numConcurrent} concurrent downloads verified successfully!")
        print("\n[Test] ========== VFS Concurrent Downloads Test PASSED ==========")

    def _shareVfsLinkWithEnvAuth(self, vfsLink, username, password):
        """
        Share a vfs:// link using environment variables for authentication.

        Args:
            vfsLink: vfs:// URI (without credentials)
            username: Auth username to set in FFL_VFS_AUTH_USER
            password: Auth password to set in FFL_VFS_AUTH_PASSWORD

        Returns:
            str: HTTP share link
        """
        # Temporarily replace testFilePath, originalFileSize, and jsonOutputPath
        originalPath = self.testFilePath
        originalSize = self.originalFileSize
        originalJsonPath = self.jsonOutputPath

        self.testFilePath = vfsLink
        self.originalFileSize = -1
        self.jsonOutputPath = os.path.join(self.tempDir, "share_vfs_env_auth.json")

        try:
            # Use extraEnvVars to pass auth credentials via environment variables
            extraEnvVars = {
                'FFL_VFS_AUTH_USER': username,
                'FFL_VFS_AUTH_PASSWORD': password
            }
            shareLink = self._startFastFileLink(p2p=True, extraArgs=["--timeout", "120"], extraEnvVars=extraEnvVars)
            return shareLink
        finally:
            self.testFilePath = originalPath
            self.originalFileSize = originalSize
            self.jsonOutputPath = originalJsonPath

    def _verifyVFSAuthOutput(self, username, password):
        """Verify VFS auth enabled in logs but password not exposed"""
        if not self.vfsOutputCapture:
            return

        # Get captured output using base class method
        output = self._updateCapturedOutput(self.vfsOutputCapture)

        # Filter out CorePatched debug logs (command-line args contain password)
        # Only check actual application output
        appOutput = '\n'.join(line for line in output.split('\n')
                             if not line.startswith('[CorePatched]'))

        self.assertIn("Authentication enabled", appOutput, "Auth not enabled")
        self.assertIn(username, appOutput, f"Username '{username}' not shown")
        self.assertNotIn(password, appOutput, "Password exposed in application output!")
        print(f"[Test] Authentication verified - password NOT exposed")


if __name__ == '__main__':
    unittest.main()
