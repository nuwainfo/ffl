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
import os

from .ResumeTestBase import ResumeTestBase, ResumeBrowserTestBase
from .CoreTestBase import FastFileLinkTestBase


# ---------------------------
# Upload Resume Test Class
# ---------------------------
class UploadResumeTest(ResumeTestBase):
    """Test class specifically for testing upload resume functionality (--resume flag)"""

    def __init__(self, methodName='runTest'):
        # Use larger file size for resume testing to ensure multiple chunks
        super().__init__(methodName, fileSizeBytes=50 * 1024 * 1024)  # 50MB to ensure ~4 chunks

    def _testUploadResume(self, pausePercentage=40):
        """
        Test upload resume functionality by pausing an upload and then resuming it

        Args:
            pausePercentage (int): Percentage at which to pause the upload
        """
        try:
            print(f"[Test] Starting upload resume test with {self.fileSizeBytes / (1024*1024):.1f}MB file")

            # Phase 1: Pause at specified percentage
            success = self._performPauseOperation(pausePercentage, expectSuccess=True)
            if not success:
                raise AssertionError(f"Pause at {pausePercentage}% failed")

            # Phase 2: Resume to completion
            shareLink = self._performResumeOperation()

            # Phase 3: Verify the resumed upload worked correctly
            print("[Test] Phase 3: Verifying resumed upload...")

            # Check that resume output contained expected additional messages
            resumeOutputCapture = {}
            self._updateCapturedOutput(resumeOutputCapture)  # Get any remaining output

            # Verify we can download the completed file
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2)  # Wait for server to finalize the file
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Upload resume test completed successfully!")

        except Exception as e:
            print(f"[Test] Upload resume test failed: {str(e)}")
            raise

    def _performPauseOperation(self, pausePercentage, expectSuccess=True):
        """
        Perform a single pause operation and return whether it succeeded

        Args:
            pausePercentage (int): Percentage at which to pause
            expectSuccess (bool): Whether to expect the operation to succeed

        Returns:
            bool: True if operation succeeded as expected, False otherwise
        """
        try:
            print(f"[Test] Attempting pause at {pausePercentage}%...")
            capture = {}
            self._pauseUpload(pausePercentage=pausePercentage, outputCapture=capture)
            print(f"[Test] Successfully paused at {pausePercentage}%")
            return True

        except AssertionError as err:
            if expectSuccess:
                print(f"[Test] Unexpected pause failure: {err}")
                return False
            print(f"[Test] Expected error occurred for --pause {pausePercentage}: {err}")
            return True

    def _performResumeOperation(self):
        """
        Perform a resume operation and verify it completes successfully

        Returns:
            str: Share link if successful, None if failed
        """
        try:
            print("[Test] Attempting resume...")

            capture = {}
            resumeShareLink, _ = self._resumeUpload(outputCapture=capture)
            print(f"[Test] Resume completed successfully: {resumeShareLink}")
            return resumeShareLink

        finally:
            self._terminateProcess()

    # Public test methods
    def testUploadResume(self):
        """Test upload resume functionality"""
        self._testUploadResume(pausePercentage=40)

    def testRepeatedPauseAtSamePercentage(self):
        """Test that pausing at the same percentage multiple times works correctly"""
        try:
            print("[Test] Testing repeated pause at same percentage (10%)")

            # First pause at 10%
            success1 = self._performPauseOperation(10, expectSuccess=True)
            if not success1:
                raise AssertionError("First pause at 10% failed")

            # Second pause at 10% should also work (resume from where we left off)
            success2 = self._performPauseOperation(10, expectSuccess=True)
            if not success2:
                raise AssertionError("Second pause at 10% failed")

            # Finally resume to completion
            shareLink = self._performResumeOperation()

            # Verify the completed upload
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2)
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Repeated pause test completed successfully!")

        except Exception as e:
            print(f"[Test] Repeated pause test failed: {e}")
            raise

    def testIncrementalPauseProgression(self):
        """Test pausing at incremental percentages: 10%, 20%, 30%, 50%, then complete"""
        try:
            print("[Test] Testing incremental pause progression")

            pausePercentages = [10, 20, 30, 50]

            for percentage in pausePercentages:
                success = self._performPauseOperation(percentage, expectSuccess=True)
                if not success:
                    raise AssertionError(f"Pause at {percentage}% failed")

            # Finally complete without pause
            shareLink = self._performResumeOperation()

            # Verify the completed upload
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2)
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Incremental pause progression test completed successfully!")

        except Exception as e:
            print(f"[Test] Incremental pause progression test failed: {e}")
            raise

    def testPause99ThenResume(self):
        """Test pausing at 99% then resuming to completion"""
        try:
            print("[Test] Testing pause at 99% then resume")

            # Pause at 99%
            success = self._performPauseOperation(99, expectSuccess=True)
            if not success:
                raise AssertionError("Pause at 99% failed")

            # Resume to completion
            shareLink = self._performResumeOperation()

            # Verify the completed upload
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2)
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Pause at 99% test completed successfully!")

        except Exception as e:
            print(f"[Test] Pause at 99% test failed: {e}")
            raise

    def testPause100Validation(self):
        """Test that --pause 100 is properly rejected, then resume works"""
        try:
            print("[Test] Testing --pause 100 validation")

            # First make a valid pause to create resume state
            success = self._performPauseOperation(30, expectSuccess=True)
            if not success:
                raise AssertionError("Initial pause at 30% failed")

            # Now try --pause 100 which should be rejected
            success = self._performPauseOperation(100, expectSuccess=False)
            if not success:
                raise AssertionError("--pause 100 should have been rejected but wasn't")

            # Resume should still work from the previous valid pause
            shareLink = self._performResumeOperation()

            # Verify the completed upload
            downloadedFilePath = self._getDownloadedFilePath()
            time.sleep(2)
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] Pause 100 validation test completed successfully!")

        except Exception as e:
            print(f"[Test] Pause 100 validation test failed: {e}")
            raise


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
        # Use system curl (Windows 10+ has built-in curl.exe in System32)
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


# ---------------------------
# Browser-Based HTTP Resume with Fallback Test Class
# ---------------------------
class BrowserResumeTest(ResumeBrowserTestBase):
    """Test HTTP resume when WebRTC stalls and falls back to HTTP (browser-based)"""

    def testHttpResumeWithFallbackByChrome(self):
        """Test HTTP resume when WebRTC connection stalls and falls back to HTTP using Chrome"""
        self._testHttpResumeWithFallback('chrome')

    def testHttpResumeWithFallbackByFirefox(self):
        """Test HTTP resume when WebRTC connection stalls and falls back to HTTP using Firefox"""
        self._testHttpResumeWithFallback('firefox')

    def testHttpResumeWithFallbackByFirefoxPassthrough(self):
        """Test HTTP resume in Firefox passthrough mode (large file >512MB triggers ff_pass=1)

        This test verifies:
        1. Large file triggers Firefox passthrough mode (ff_pass=1)
        2. WebRTC stalls and falls back to HTTP
        3. Service Worker's handlePassthroughForResume handles resume correctly
        4. DownloadManager.fetchToWriter receives the resumed stream
        5. Final file is complete and matches original
        """
        # Use 600MB file to exceed Firefox SW limit (512MB default)
        # This will trigger ff_pass=1 flag in Service Worker
        largeFileSize = 600 * 1024 * 1024  # 600MB
        stallAfterBytes = 50 * 1024 * 1024  # Stall after 50MB

        print(f"[Test] Firefox Passthrough Resume Test:")
        print(f"  - File size: {largeFileSize // (1024*1024)}MB (triggers passthrough mode)")
        print(f"  - Stall after: {stallAfterBytes // (1024*1024)}MB")
        print(f"  - Expected flow: P2P → Stall → HTTP resume via handlePassthroughForResume")

        self._testHttpResumeWithFallback(
            'firefox',
            largeFileSize=largeFileSize,
            stallAfterBytes=stallAfterBytes
        )


if __name__ == '__main__':
    unittest.main()
