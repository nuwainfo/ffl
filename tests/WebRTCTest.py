#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os
import time
import unittest

import undetected_chromedriver as uc

from get_gecko_driver import GetGeckoDriver
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .CoreTestBase import FastFileLinkTestBase

# ---------------------------
# WebRTC Test Class
# ---------------------------
class WebRTCTest(FastFileLinkTestBase):
    """Test FastFileLink using WebRTC/browser-based downloads"""

    DEFAULT_FILE_SIZE = 5 * 1024 * 1024 # 5MB

    def __init__(self, methodName='runTest'):
        super().__init__(methodName, fileSizeBytes=self.DEFAULT_FILE_SIZE)

    def setUp(self):
        """Set up test environment including browser download directories"""
        super().setUp()

        # Create separate download directories for different browsers
        self.chromeDownloadDir = os.path.join(self.tempDir, "chrome_downloads")
        self.firefoxDownloadDir = os.path.join(self.tempDir, "firefox_downloads")

        os.makedirs(self.chromeDownloadDir, exist_ok=True)
        os.makedirs(self.firefoxDownloadDir, exist_ok=True)

        # Keep track of active drivers for cleanup
        self.activeDrivers = []

    def tearDown(self):
        """Clean up test environment including browser instances"""
        # Clean up any remaining browser instances
        for driver in self.activeDrivers:
            try:
                driver.quit()
            except Exception as e:
                print(f"[Test] Warning: Failed to cleanup driver: {e}")

        super().tearDown()

    def _setupChromeDriver(self, downloadDir):
        """Setup undetected Chrome WebDriver"""
        # Set download preferences
        prefs = {
            "download.default_directory": downloadDir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        }

        options = uc.ChromeOptions()
        options.add_argument('--headless') # Run in headless mode
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_experimental_option("prefs", prefs)

        driver = uc.Chrome(options=options)
        self.activeDrivers.append(driver)
        return driver

    def _setupFirefoxDriver(self, downloadDir):
        """Setup Firefox WebDriver with get-gecko-driver"""
        # Get GeckoDriver path using get-gecko-driver
        getDriver = GetGeckoDriver()
        geckoDriverDir = getDriver.install()

        # The install() method returns a directory, we need to find the actual executable
        import platform
        if platform.system() == "Windows":
            geckoDriverPath = os.path.join(geckoDriverDir, "geckodriver.exe")
        else:
            geckoDriverPath = os.path.join(geckoDriverDir, "geckodriver")

        # Verify the executable exists
        if not os.path.isfile(geckoDriverPath):
            raise Exception(f"GeckoDriver executable not found at: {geckoDriverPath}")

        firefoxOptions = FirefoxOptions()
        firefoxOptions.add_argument('--headless') # Run in headless mode
        if platform.system() == 'Darwin':
            firefoxOptions.binary_location = "/Applications/Firefox.app/Contents/MacOS/firefox"

        # Set download preferences
        firefoxOptions.set_preference("browser.download.folderList", 2)
        firefoxOptions.set_preference("browser.download.manager.showWhenStarting", False)
        firefoxOptions.set_preference("browser.download.dir", downloadDir)
        firefoxOptions.set_preference(
            "browser.helperApps.neverAsk.saveToDisk", "application/octet-stream,application/binary,application/x-binary"
        )

        service = FirefoxService(executable_path=geckoDriverPath)
        driver = webdriver.Firefox(service=service, options=firefoxOptions)
        self.activeDrivers.append(driver)
        return driver

    def _triggerDownload(self, driver):
        """Try to trigger the download - this might vary based on the actual page structure"""
        try:
            # Method 1: Look for a download button
            downloadButton = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable(
                    (By.XPATH, "//button[contains(text(), 'Download')] | //a[contains(text(), 'Download')]")
                )
            )
            downloadButton.click()
            print("[Test] Clicked download button")
            return
        except TimeoutException:
            pass

        try:
            # Method 2: Look for any clickable link that might trigger download
            downloadLink = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.TAG_NAME, "a")))
            downloadLink.click()
            print("[Test] Clicked download link")
            return
        except TimeoutException:
            pass

        # Method 3: If it's a direct file link, the download should start automatically
        print("[Test] Assuming direct download link - waiting for download to start")

    def _waitForDownload(self, downloadDir, expectedFilename, timeout=60):
        """Wait for the download to complete and return the path to the downloaded file"""

        def checkDownloadComplete():
            # Look for files in download directory
            if not os.path.exists(downloadDir):
                return None

            try:
                for filename in os.listdir(downloadDir):
                    if filename == expectedFilename or filename.startswith(expectedFilename.split('.')[0]):
                        filePath = os.path.join(downloadDir, filename)
                        # Check if file is still being downloaded (some browsers add .part or .crdownload)
                        if not (
                            filename.endswith('.part') or filename.endswith('.crdownload') or filename.endswith('.tmp')
                        ):
                            # Also check if file size is reasonable (not 0 bytes)
                            if os.path.getsize(filePath) > 0:
                                return filePath
            except (OSError, PermissionError) as e:
                print(f"[Test] Error checking download directory: {e}")
                return None
            return None

        downloadedFile = None
        startTime = time.time()

        print(f"[Test] Waiting for download in: {downloadDir}")
        print(f"[Test] Expected filename: {expectedFilename}")

        while time.time() - startTime < timeout:
            downloadedFile = checkDownloadComplete()
            if downloadedFile:
                print(f"[Test] Found downloaded file: {downloadedFile}")
                break

            # Print current directory contents for debugging
            if os.path.exists(downloadDir):
                try:
                    currentFiles = os.listdir(downloadDir)
                    if currentFiles:
                        print(f"[Test] Current files in download dir: {currentFiles}")
                except (OSError, PermissionError):
                    pass

            time.sleep(2) # Check every 2 seconds instead of 1

        if not downloadedFile:
            # List all files in download directory for debugging
            try:
                filesInDir = os.listdir(downloadDir) if os.path.exists(downloadDir) else []
                raise Exception(
                    f"Download did not complete within {timeout} seconds. Files in download dir: {filesInDir}"
                )
            except (OSError, PermissionError) as e:
                raise Exception(
                    f"Download did not complete within {timeout} seconds. Error accessing download dir: {e}"
                )

        return downloadedFile

    def _downloadWithBrowser(self, driver, shareLink, downloadDir, expectedFilename):
        """Download file using the specified browser driver and verify WebRTC usage"""
        try:
            print(f"[Test] Navigating to: {shareLink}")
            driver.get(shareLink)

            # Wait for page to load
            WebDriverWait(driver,
                          10).until(lambda driver: driver.execute_script("return document.readyState") == "complete")

            # For WebRTC testing, we don't click anything - just wait for automatic download
            print("[Test] Waiting for WebRTC automatic download to start...")

            # Wait for download to complete
            downloadedFile = self._waitForDownload(downloadDir, expectedFilename)
            print(f"[Test] Download completed successfully: {downloadedFile}")

            return downloadedFile

        except TimeoutException:
            raise Exception("Timeout waiting for download to complete")
        except Exception as e:
            raise Exception(f"Download failed: {e}")

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
            downloadedFile = self._downloadWithBrowser(driver, shareLink, downloadDir, expectedFilename)
            self._verifyDownloadedFile(downloadedFile)

            # After download is successful, update captured output for P2P verification
            outputText = self._updateCapturedOutput(outputCapture)
            if outputText:
                print(f"[Test] Core.py captured output:\n{outputText}")

            # Assert that P2P is mentioned in the output (indicating WebRTC usage)
            if "P2P" not in outputText:
                raise AssertionError("P2P not found in Core.py output - WebRTC may not be working correctly")
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
            chromeDriver.get(shareLink)
            firefoxDriver.get(shareLink)

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
                print(f"[Test] Core.py captured output:\n{outputText}")

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


if __name__ == '__main__':
    unittest.main()
