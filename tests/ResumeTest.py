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

import subprocess
import sys
import time
import unittest

from .CoreTestBase import FastFileLinkTestBase


# ---------------------------
# Resume Download Test Class
# ---------------------------
class ResumeDownloadTest(FastFileLinkTestBase):
    """Test class specifically for testing resume download functionality"""

    def __init__(self, methodName='runTest'):
        # Use larger file size for resume testing to make the test more meaningful
        super().__init__(methodName, fileSizeBytes=10 * 1024 * 1024) # 10MB

    def _downloadFileWithCurl(self, shareLink, outputPath, incomplete=False):
        """Download file using curl command"""
        if sys.platform.startswith('win'):
            curl = 'curl.exe'
        else:
            curl = 'curl'

        if incomplete:
            # Use limit-rate and max-time options to make download incomplete
            print("[Test] Start the cURL request which cannot download completely")
            result = subprocess.run(
                f"{curl} -L {shareLink} -o {outputPath} --limit-rate 1K --max-time 60",
                shell=True,
                capture_output=True,
                text=True
            )
            print(result.stderr)
            if 'Operation timed out' not in result.stderr:
                raise AssertionError("Expected timeout did not occur")
            print("[Test] Partial download completed (timed out as expected)")
        else:
            # Resume download
            result = subprocess.run(
                f"{curl} -L -C - {shareLink} -o {outputPath}", shell=True, capture_output=True, text=True
            )
            print(result.stderr)
            if result.returncode != 0:
                raise AssertionError(f"Curl download failed: {result.stderr}")
            print(f"[Test] File downloaded successfully to {outputPath}")
            if '** Resuming transfer from byte position' in result.stderr:
                print("[Test] Download was resumed from previous attempt")

    def _testResumingDownload(self, p2p=True):
        """Test resuming download functionality using curl"""
        try:
            shareLink = self._startFastFileLink(p2p)
            downloadedFilePath = self._getDownloadedFilePath()

            # First, download incompletely
            self._downloadFileWithCurl(shareLink, downloadedFilePath, incomplete=True)

            # Then, resume the download
            self._downloadFileWithCurl(shareLink, downloadedFilePath, incomplete=False)

            # Verify the final downloaded file
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Resuming download successfully!")
        finally:
            self._terminateProcess()

    # Public test methods
    def testResumingDownloadByP2P(self):
        """Test resuming download functionality with P2P mode"""
        self._testResumingDownload(p2p=True)

    def testResumingDownloadByServer(self):
        """Test resuming download functionality with Server mode"""
        self._testResumingDownload(p2p=False)


# ---------------------------
# Upload Network Instability Test Class
# ---------------------------
class UploadInstabilityTest(FastFileLinkTestBase):
    """Test class specifically for testing upload functionality with network instability simulation"""

    def __init__(self, methodName='runTest'):
        # Default to medium file size
        super().__init__(methodName, fileSizeBytes=100 * 1024 * 1024) # 100MB

    # File size constants
    SMALL_FILE_SIZE = 10 * 1024 * 1024 # 10MB
    MEDIUM_FILE_SIZE = 100 * 1024 * 1024 # 100MB
    LARGE_FILE_SIZE = 1200 * 1024 * 1024 # 1.2GB

    def _testUploadWithNetworkInstability(
        self, fileSize, failureRate, maxConsecutiveFailures=3, showOutput=True, timeout=None, expectFailure=False
    ):
        """
         Test upload with network instability for given parameters

         Args:
             fileSize (int): Size of test file in bytes
             failureRate (float): Network failure rate (0.0 to 1.0)
             maxConsecutiveFailures (int): Maximum consecutive failures
             showOutput (bool): Whether to show real-time process output
             timeout (int): Custom timeout in seconds
             expectFailure (bool): Whether to expect the upload to fail
         """
        # Update file size for this test
        self.fileSizeBytes = fileSize

        # Regenerate test file with new size
        fileSizeMB = fileSize / (1024 * 1024)
        print(f"[Test] Testing upload with {fileSizeMB:.1f}MB file")
        print(
            f"[Test] Network conditions: {failureRate * 100:.1f}% failure rate, max {maxConsecutiveFailures} consecutive failures"
        )
        print(f"[Test] Expected outcome: {'FAILURE' if expectFailure else 'SUCCESS'}")
        self.setUp() # This will regenerate the file with new size

        testServerProcess = None
        try:
            # Prepare extra environment variables to disable retry fallback
            extraEnvVars = {
                'UPLOAD_NO_RETRY': 'True' # Disable fallback to pull mode
            }

            # Start upload with network instability simulation using test server
            result = self._startFastFileLink(
                p2p=False,  # Server upload only
                networkFailureRate=failureRate,
                maxConsecutiveFailures=maxConsecutiveFailures,
                showOutput=showOutput,
                useTestServer=True,  # Use local test server
                extraEnvVars=extraEnvVars,  # Disable retry fallback,
                timeout=timeout,
            )

            # If we reach here and expectFailure is True, it's unexpected
            if expectFailure:
                print("[Test] WARNING: Expected failure but upload succeeded - this is unexpected!")
                return

            # Unpack result based on whether test server was used
            if isinstance(result, tuple):
                shareLink, testServerProcess = result
            else:
                shareLink = result

            # Verify we can download the uploaded file
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2) # In Linux, this is too fast that server doesn't assemble file yet, just wait a while.            
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print(f"[Test] Upload instability test completed successfully!")

        except AssertionError as e:
            if expectFailure:
                # Check if this is the expected type of failure
                errorMessage = str(e)
                if (
                    "JSON output file was not created" in errorMessage or
                    "Upload cancelled due to chunk failure" in errorMessage or "Upload failed" in errorMessage
                ):
                    print("[Test] Expected failure occurred - test passed!")
                    return
                else:
                    print(f"[Test] Unexpected failure type: {errorMessage}")
                    raise
            else:
                # Unexpected failure
                print(f"[Test] Unexpected failure: {str(e)}")
                raise
        finally:
            self._terminateProcess()
            # Stop test server after all operations are complete
            if testServerProcess:
                self._stopTestServer(testServerProcess)

    # Test methods for predefined scenarios
    def testStableUpload(self):
        """Test normal upload without any network instability"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.0, 0, timeout=60)

    def testLightInstabilitySmallFile(self):
        """Test small file upload with light network instability"""
        self._testUploadWithNetworkInstability(self.SMALL_FILE_SIZE, 0.08, 2, timeout=45)

    def testLightInstabilityMediumFile(self):
        """Test medium file upload with light network instability"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.08, 2, timeout=90)

    def testLightInstabilityLargeFile(self):
        """Test large file upload with light network instability"""
        # TODO: We should hint user, network instability should retry in better network.
        self._testUploadWithNetworkInstability(self.LARGE_FILE_SIZE, 0.08, 2, timeout=180, expectFailure=True)

    def testModerateInstabilitySmallFile(self):
        """Test small file upload with moderate network instability"""
        self._testUploadWithNetworkInstability(self.SMALL_FILE_SIZE, 0.15, 3, timeout=60)

    def testModerateInstabilityMediumFile(self):
        """Test medium file upload with moderate network instability"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.15, 3, timeout=120)

    def testHeavyInstabilitySmallFile(self):
        """Test small file upload with heavy network instability"""
        self._testUploadWithNetworkInstability(self.SMALL_FILE_SIZE, 0.35, 4, timeout=90)

    def testHeavyInstabilityMediumFile(self):
        """Test medium file upload with heavy network instability"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.35, 4, timeout=150)

    def testExtremeInstabilitySmallFile(self):
        """Test small file upload with extreme network instability (should likely fail)"""
        self._testUploadWithNetworkInstability(self.SMALL_FILE_SIZE, 0.8, 5, timeout=30, expectFailure=True)

    def testFailFastMechanism(self):
        """Test that fail-fast mechanism works correctly"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.95, 3, timeout=30, expectFailure=True)

    # Test methods with custom parameters for manual testing
    def testCustomLowFailureRate(self):
        """Test with custom low failure rate (10%)"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.10, 2, timeout=75)

    def testCustomHighFailureRate(self):
        """Test with custom high failure rate (50%)"""
        self._testUploadWithNetworkInstability(self.MEDIUM_FILE_SIZE, 0.50, 4, timeout=45, expectFailure=True)

    def testCustomParameters(self):
        """Test with completely custom parameters - modify this method for ad-hoc testing"""
        # Modify these parameters for specific testing scenarios
        customFileSize = self.MEDIUM_FILE_SIZE # Change this
        customFailureRate = 0.20 # Change this (0.0 to 1.0)
        customMaxFailures = 3 # Change this
        customTimeout = 600 # Change this
        customExpectFailure = False # Change this

        print(
            f"[Test] Running custom test with {customFileSize/(1024*1024):.1f}MB file, "
            f"{customFailureRate*100:.1f}% failure rate, max {customMaxFailures} consecutive failures, "
            f"timeout: {customTimeout}s, expect failure: {customExpectFailure}"
        )

        self._testUploadWithNetworkInstability(
            customFileSize,
            customFailureRate,
            customMaxFailures,
            timeout=customTimeout,
            expectFailure=customExpectFailure
        )


if __name__ == '__main__':
    unittest.main()
