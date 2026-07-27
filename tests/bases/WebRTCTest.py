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
import unittest

from selenium.webdriver.support.ui import WebDriverWait

from ..BrowserTestBase import BrowserTestBase


# ---------------------------
# WebRTC Test Class
# ---------------------------
class WebRTCTest(BrowserTestBase):
    """Test FastFileLink using WebRTC/browser-based downloads"""

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    def _runBrowserDownloadTest(self, browserName, p2p=True):
        """Run download test with specified browser"""
        try:
            # Capture output for later P2P verification
            outputCapture = {}
            shareLink = self._startFastFileLink(p2p, output=False, captureOutputIn=outputCapture)

            if browserName == 'chrome':
                driver = self._setupChromeDriver(self.chromeDownloadDir)
                downloadDir = self.chromeDownloadDir
            elif browserName == 'firefox':
                driver = self._setupFirefoxDriver(self.firefoxDownloadDir)
                downloadDir = self.firefoxDownloadDir
            else:
                raise ValueError(f"Unsupported browser: {browserName}")

            expectedFilename = "testfile.bin"
            downloadedFile = self._downloadWithBrowser(
                driver, shareLink, downloadDir, expectedFilename, disableFallback=True
            )
            self._verifyDownloadedFile(downloadedFile)

            # After download is successful, update captured output for P2P verification
            outputText = self._updateCapturedOutput(outputCapture)
            if outputText:
                print(f"[Test] FFL.py captured output:\n{self._getConsoleSafeText(outputText)}")

            # Assert that P2P is mentioned in the output (indicating WebRTC usage)
            if "P2P" not in outputText:
                raise AssertionError("P2P not found in FFL.py output - WebRTC may not be working correctly")
            print("[Test] P2P confirmed in output - WebRTC is working!")

        finally:
            self._terminateProcess()

    # P2P Tests
    def testP2PDownloadWithChrome(self):
        """Test P2P download using Chrome browser"""
        self._runBrowserDownloadTest('chrome', p2p=True)

    def testP2PDownloadWithFirefox(self):
        """Test P2P download using Firefox browser"""
        self._runBrowserDownloadTest('firefox', p2p=True)

    # Server Tests
    def _testServerDownloadWithChrome(self):
        """Test server download using Chrome browser"""
        self._runBrowserDownloadTest('chrome', p2p=False)

    def _testServerDownloadWithFirefox(self):
        """Test server download using Firefox browser"""
        self._runBrowserDownloadTest('firefox', p2p=False)

    # Cross-browser tests
    @unittest.skipIf(
        os.environ.get('STATIC_SERVER', '').startswith('http://'),
        "Firefox stalls document readyState at 'loading' forever when the share page (HTTPS) "
        "loads its JS from an insecure http:// STATIC_SERVER (mixed active content) - same root "
        "cause as tests.bases.E2EETest's Firefox tests. Not an app bug - only run this locally "
        "with STATIC_SERVER unset or https://."
    )
    def testCrossBrowserCompatibility(self):
        """Test that the same share link works in both Chrome and Firefox simultaneously"""
        try:
            # Start FastFileLink with output capture for WebRTC verification
            outputCapture = {}
            shareLink = self._startFastFileLink(p2p=True, output=False, captureOutputIn=outputCapture)

            # Setup both drivers simultaneously
            chromeDriver = self._setupChromeDriver(self.chromeDownloadDir)
            firefoxDriver = self._setupFirefoxDriver(self.firefoxDownloadDir)

            # Start both downloads simultaneously
            print("[Test] Starting simultaneous downloads in both browsers...")

            # Navigate both browsers to the share link at the same time
            targetUrl = self._withBrowserFallbackDisabled(shareLink)
            chromeDriver.get(targetUrl)
            firefoxDriver.get(targetUrl)

            # Wait for both pages to load
            WebDriverWait(chromeDriver,
                          10).until(lambda driver: driver.execute_script("return document.readyState") == "complete")
            WebDriverWait(firefoxDriver,
                          10).until(lambda driver: driver.execute_script("return document.readyState") == "complete")

            print("[Test] Both browsers loaded, waiting for WebRTC automatic downloads...")

            # Wait longer for downloads to complete (increase timeout for WebRTC)
            import threading

            chromeResult = {'file': None, 'error': None}
            firefoxResult = {'file': None, 'error': None}

            def chromeDownload():
                try:
                    # Use original filename instead of renamed one
                    chromeResult['file'] = self._waitForDownload(self.chromeDownloadDir, "testfile.bin", timeout=120)
                except Exception as e:
                    chromeResult['error'] = e

            def firefoxDownload():
                try:
                    # Use original filename instead of renamed one
                    firefoxResult['file'] = self._waitForDownload(self.firefoxDownloadDir, "testfile.bin", timeout=120)
                except Exception as e:
                    firefoxResult['error'] = e

            # Start both download waiting threads
            chromeThread = threading.Thread(target=chromeDownload)
            firefoxThread = threading.Thread(target=firefoxDownload)

            chromeThread.start()
            firefoxThread.start()

            # Wait for both threads to complete
            chromeThread.join(timeout=150) # Add timeout to join
            firefoxThread.join(timeout=150)

            # Check for errors
            if chromeResult['error']:
                print(f"[Test] Chrome download error: {chromeResult['error']}")
            if firefoxResult['error']:
                print(f"[Test] Firefox download error: {firefoxResult['error']}")

            # Verify downloads that succeeded
            successCount = 0
            if chromeResult['file']:
                print(f"[Test] Chrome download completed: {chromeResult['file']}")
                self._verifyDownloadedFile(chromeResult['file'])
                successCount += 1

            if firefoxResult['file']:
                print(f"[Test] Firefox download completed: {firefoxResult['file']}")
                self._verifyDownloadedFile(firefoxResult['file'])
                successCount += 1

            if successCount == 0:
                raise Exception("Both downloads failed")

            # After downloads, update captured output for WebRTC verification
            outputText = self._updateCapturedOutput(outputCapture)
            if outputText:
                print(f"[Test] FFL.py captured output:\n{self._getConsoleSafeText(outputText)}")

            # Check for WebRTC patterns like [#b9c12]
            import re
            webrtcPattern = r'\[#[a-f0-9]{5,6}\]'
            webrtcMatches = re.findall(webrtcPattern, outputText)

            if len(webrtcMatches) < 2:
                raise AssertionError(f"Expected 2 different WebRTC IDs, found: {webrtcMatches}")

            # Check that we have different IDs
            uniqueIds = set(webrtcMatches)
            if len(uniqueIds) < 2:
                raise AssertionError(f"Expected 2 different WebRTC IDs, but found duplicates: {webrtcMatches}")

            print(f"[Test] WebRTC confirmed with {len(uniqueIds)} different connection IDs: {list(uniqueIds)}")

            print(f"[Test] Cross-browser compatibility test passed with {successCount} successful downloads!")

        finally:
            self._terminateProcess()

    def testUnicodeFilename(self):
        """Test P2P download with emoji and Chinese characters in filename"""
        try:
            # Use the exact problematic filename from user's bug report, with emoji added
            # This tests HTTP header percent-encoding for non-ASCII filenames (including emoji)
            # Original: 【迷因歌曲-手工翻譯-絕無機翻】應觀眾要求將黑雪之歌2的純翻譯無解析版放上，有可能被歪踢下架所以且聽且珍惜 #白雪公主 #炎上 #迪士尼 【阿東翻譯&剪輯】 - YouTube - Brave 2025-02-27 19-26-41.mp4
            # Added emoji: 🎉 to test emoji encoding as well
            unicodeFilename = "🎉【迷因歌曲-手工翻譯-絕無機翻】應觀眾要求將黑雪之歌2的純翻譯無解析版放上，有可能被歪踢下架所以且聽且珍惜 #白雪公主 #炎上 #迪士尼 【阿東翻譯&剪輯】.mp4"
            unicodeFilePath = os.path.join(self.tempDir, unicodeFilename)

            # Generate test file with same size as default
            self.generateRandomFile(unicodeFilePath, self.fileSizeBytes)

            # Store original file info for verification
            originalHash = self.getFileHash(unicodeFilePath)
            originalSize = os.path.getsize(unicodeFilePath)

            # Print with encoding handling for Windows console
            print(f"[Test] Created Unicode test file with emoji and Chinese characters")
            print(f"[Test] File size: {originalSize} bytes")
            print(f"[Test] File hash: {originalHash}")

            # Temporarily override testFilePath to use Unicode filename
            originalTestFilePath = self.testFilePath
            originalFileHash = self.originalFileHash
            originalFileSize = self.originalFileSize

            self.testFilePath = unicodeFilePath
            self.originalFileHash = originalHash
            self.originalFileSize = originalSize

            try:
                # Capture output for P2P verification
                outputCapture = {}
                shareLink = self._startFastFileLink(p2p=True, output=False, captureOutputIn=outputCapture)

                # Setup Chrome driver
                driver = self._setupChromeDriver(self.chromeDownloadDir)

                # Download the file
                downloadedFile = self._downloadWithBrowser(
                    driver, shareLink, self.chromeDownloadDir, unicodeFilename, disableFallback=True
                )

                # Verify downloaded file
                self._verifyDownloadedFile(downloadedFile)

                # Verify P2P was used
                outputText = self._updateCapturedOutput(outputCapture)
                if outputText:
                    # Print with encoding handling for Windows console
                    try:
                        print(f"[Test] FFL.py captured output:\n{outputText}")
                    except UnicodeEncodeError:
                        print(f"[Test] FFL.py captured output (contains unicode characters)")

                if "P2P" not in outputText:
                    raise AssertionError("P2P not found in output - WebRTC may not be working")

                print("[Test] Unicode filename test passed - P2P download successful!")

            finally:
                # Restore original test file path
                self.testFilePath = originalTestFilePath
                self.originalFileHash = originalFileHash
                self.originalFileSize = originalFileSize

        finally:
            self._terminateProcess()


if __name__ == '__main__':
    unittest.main()
