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
import argparse
import platform
import shutil
import subprocess
import sys
import time
import unittest
import json

import psutil
import requests

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

if __package__ in (None, ""):
    repoRoot = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repoRoot not in sys.path:
        sys.path.insert(0, repoRoot)

from bases.Settings import SettingsGetter
from bases.Utils import StallResilientAdapter, getEnv, parseSizeString
from bases.Kernel import StorageLocator

from selenium.webdriver.support.ui import WebDriverWait

try:
    from .ResumeTestBase import ResumeBrowserTestBase
    from .CoreTestBase import getFileHash
except ImportError:
    if repoRoot not in sys.path:
        sys.path.insert(0, repoRoot)
        
    from tests.ResumeTestBase import ResumeBrowserTestBase
    from tests.CoreTestBase import getFileHash

DIRECT_RUN = __name__ == "__main__"

@unittest.skipUnless(
    DIRECT_RUN or getEnv("FFL_ENABLE_LARGE_FILE_TESTS", False),
    "Set FFL_ENABLE_LARGE_FILE_TESTS=1 to run manual large-file browser integration tests.",
)
class LargeFileTest(ResumeBrowserTestBase):
    """Manual configurable large-file integration tests for HTTP/WebRTC/browser download and upload flows."""

    DEFAULT_FILE_SIZE = 1
    DISK_SPACE_BUFFER = parseSizeString(os.getenv("FFL_LARGE_FILE_DISK_BUFFER", "512M"))
    BROWSER_MIN_AVAILABLE_MEMORY = parseSizeString(os.getenv("FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY", "512M"))
    BROWSER_MAX_SWAP_USED_PERCENT = float(os.getenv("FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT", "80"))
    LARGE_FILE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_SIZE", "20G"))
    DEFAULT_BROWSER = os.getenv("FFL_LARGE_FILE_BROWSER", "chrome").strip().lower()
    STALL_AFTER_BYTES = parseSizeString(os.getenv("FFL_LARGE_FILE_STALL_AFTER", "96M"))
    SHARE_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_SHARE_TIMEOUT", "900"))
    UPLOAD_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_UPLOAD_TIMEOUT", "43200"))
    DOWNLOAD_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_DOWNLOAD_TIMEOUT", "43200"))
    FALLBACK_TIMEOUT_MS = int(os.getenv("FFL_LARGE_FILE_FALLBACK_MS", "120000"))
    REQUEST_CHUNK_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_CHUNK_SIZE", "4M"))
    REQUEST_LOG_INTERVAL = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_LOG_INTERVAL", "512M"))
    REQUEST_SOCKET_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_REQUEST_SOCKET_TIMEOUT", "900"))
    VERIFY_HASH = getEnv("FFL_LARGE_FILE_VERIFY_HASH", False)

    @classmethod
    def configureFromEnvironment(cls):
        cls.DISK_SPACE_BUFFER = parseSizeString(os.getenv("FFL_LARGE_FILE_DISK_BUFFER", "512M"))
        cls.BROWSER_MIN_AVAILABLE_MEMORY = parseSizeString(
            os.getenv("FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY", "512M")
        )
        cls.BROWSER_MAX_SWAP_USED_PERCENT = float(
            os.getenv("FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT", "80")
        )
        cls.LARGE_FILE_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_SIZE", "20G"))
        cls.DEFAULT_BROWSER = os.getenv("FFL_LARGE_FILE_BROWSER", "chrome").strip().lower()
        cls.STALL_AFTER_BYTES = parseSizeString(os.getenv("FFL_LARGE_FILE_STALL_AFTER", "96M"))
        cls.SHARE_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_SHARE_TIMEOUT", "900"))
        cls.UPLOAD_READY_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_UPLOAD_TIMEOUT", "43200"))
        cls.DOWNLOAD_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_DOWNLOAD_TIMEOUT", "43200"))
        cls.FALLBACK_TIMEOUT_MS = int(os.getenv("FFL_LARGE_FILE_FALLBACK_MS", "120000"))
        cls.REQUEST_CHUNK_SIZE = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_CHUNK_SIZE", "4M"))
        cls.REQUEST_LOG_INTERVAL = parseSizeString(os.getenv("FFL_LARGE_FILE_REQUEST_LOG_INTERVAL", "512M"))
        cls.REQUEST_SOCKET_TIMEOUT = int(os.getenv("FFL_LARGE_FILE_REQUEST_SOCKET_TIMEOUT", "900"))
        cls.VERIFY_HASH = getEnv("FFL_LARGE_FILE_VERIFY_HASH", False)

    def setUp(self):
        self.configureFromEnvironment()
        super().setUp()

        self._cleanupPaths = set()
        self.largeFilePath = self._prepareLargeFile()
        self.testFilePath = self.largeFilePath
        self.originalFileSize = os.path.getsize(self.largeFilePath)
        self.fileSizeBytes = self.originalFileSize
        self.expectedFilename = os.path.basename(self.largeFilePath)

        if self.VERIFY_HASH:
            print("[Test] Computing full SHA-256 for the large test file...")
            self.originalFileHash = getFileHash(self.largeFilePath)
            print(f"[Test] Large file SHA-256: {self.originalFileHash}")
        else:
            self.originalFileHash = None
            print("[Test] Full hash verification disabled for large-file test (size-only verification).")

        print(f"[Test] Large file path: {self.largeFilePath}")
        print(f"[Test] Large file size: {self.originalFileSize} bytes")
        print(f"[Test] Browser: {self.DEFAULT_BROWSER}")

    def prepareTestConfigDir(self, tempConfigDir):
        preparedDir = super().prepareTestConfigDir(tempConfigDir)
        self._writeBuiltinTunnelConfig(preparedDir)
        return preparedDir

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            self._cleanupLargeArtifacts()

    def _prepareLargeFile(self):
        existingPath = os.getenv("FFL_LARGE_FILE_PATH")
        if existingPath:
            existingPath = os.path.abspath(existingPath)
            if not os.path.exists(existingPath):
                raise AssertionError(f"FFL_LARGE_FILE_PATH does not exist: {existingPath}")

            actualSize = os.path.getsize(existingPath)
            if actualSize != self.LARGE_FILE_SIZE:
                raise AssertionError(
                    f"Expected {self.LARGE_FILE_SIZE} bytes at FFL_LARGE_FILE_PATH, got {actualSize}: {existingPath}"
                )
            return existingPath

        outputDir = os.path.abspath(os.getenv("FFL_LARGE_FILE_DIR", self.tempDir))
        os.makedirs(outputDir, exist_ok=True)
        self._assertDiskSpaceAvailable(
            outputDir,
            self.LARGE_FILE_SIZE,
            "large file source directory",
            envVarName="FFL_LARGE_FILE_DIR",
        )

        filePath = os.path.join(outputDir, f"large_{self.LARGE_FILE_SIZE}_bytes.bin")
        if os.path.exists(filePath):
            currentSize = os.path.getsize(filePath)
            if currentSize == self.LARGE_FILE_SIZE:
                print(f"[Test] Reusing existing large file: {filePath}")
                return filePath

            print(f"[Test] Replacing stale large file with wrong size ({currentSize} bytes): {filePath}")
            os.remove(filePath)

        self._createLargePlaceholderFile(filePath, self.LARGE_FILE_SIZE)
        return filePath

    def _createLargePlaceholderFile(self, filePath, sizeBytes):
        print(f"[Test] Creating {sizeBytes} byte large file placeholder: {filePath}")

        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["fsutil", "file", "createnew", filePath, str(sizeBytes)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=True
                )
                if result.stdout.strip():
                    print(f"[Test] fsutil: {result.stdout.strip()}")
                return
            except Exception as exc:
                print(f"[Test] fsutil file creation failed, falling back to sparse seek: {exc}")

        else:
            try:
                subprocess.run(["truncate", "-s", str(sizeBytes), filePath], timeout=120, check=True)
                return
            except Exception as exc:
                print(f"[Test] truncate failed, falling back to sparse seek: {exc}")

        with open(filePath, "wb") as handle:
            if sizeBytes > 0:
                handle.seek(sizeBytes - 1)
                handle.write(b"\0")

    def _writeBuiltinTunnelConfig(self, configDir):
        configPath = os.path.join(configDir, "tunnels.json")
        tunnelDomain = (
            os.getenv("FFL_TUNNEL_DOMAIN")
            or os.getenv("BUILTIN_TUNNEL")
            or "33.fastfilelink.com"
        ).strip()
        config = {
            "tunnels": {},
            "settings": {
                "preferred_tunnel": "default",
                "fallback_order": ["default"],
            },
            "_comment": (
                "LargeFileTest pins builtin tunnel usage so isolated test configs do not "
                "auto-create a cloudflare-preferred tunnels.json."
            ),
        }
        with open(configPath, "w", encoding="utf-8") as configFile:
            json.dump(config, configFile, indent=2)
        print(f"[Test] Wrote builtin-only tunnel config to {configPath} for {tunnelDomain}")

    def _cleanupLargeArtifacts(self):
        cleanupTargets = sorted(self._cleanupPaths, key=lambda path: len(path), reverse=True)
        for targetPath in cleanupTargets:
            if not targetPath:
                continue

            try:
                if os.path.isdir(targetPath):
                    print(f"[Test] Cleaning download directory: {targetPath}")
                    shutil.rmtree(targetPath, ignore_errors=True)
                elif os.path.exists(targetPath):
                    print(f"[Test] Removing downloaded file: {targetPath}")
                    os.remove(targetPath)
            except Exception as exc:
                print(f"[Test] Warning: failed to clean large-file artifact {targetPath}: {exc}")

    def _registerCleanupPath(self, path):
        if path:
            self._cleanupPaths.add(os.path.abspath(path))

    def _assertDiskSpaceAvailable(self, targetPath, requiredBytes, purpose, envVarName):
        targetPath = os.path.abspath(targetPath)
        usage = shutil.disk_usage(targetPath)
        requiredWithBuffer = requiredBytes + self.DISK_SPACE_BUFFER
        print(
            f"[Test] Disk check for {purpose}: path={targetPath}, "
            f"free={usage.free} bytes, required={requiredBytes} bytes, buffer={self.DISK_SPACE_BUFFER} bytes"
        )
        if usage.free >= requiredWithBuffer:
            return

        raise AssertionError(
            f"Insufficient free space for {purpose}: path={targetPath}, free={usage.free} bytes, "
            f"required at least {requiredWithBuffer} bytes "
            f"(file size {requiredBytes} + buffer {self.DISK_SPACE_BUFFER}). "
            f"Set {envVarName} to a larger filesystem."
        )

    def _getLargeDownloadRoot(self):
        rootPath = os.path.abspath(os.getenv("FFL_LARGE_FILE_DOWNLOAD_DIR", self.tempDir))
        os.makedirs(rootPath, exist_ok=True)
        self._assertDiskSpaceAvailable(
            rootPath,
            self.LARGE_FILE_SIZE,
            "large file download directory",
            envVarName="FFL_LARGE_FILE_DOWNLOAD_DIR",
        )
        return rootPath

    def _prepareDownloadDir(self, browserName):
        downloadDir = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{browserName}_downloads")
        if os.path.isdir(downloadDir):
            shutil.rmtree(downloadDir, ignore_errors=True)
        os.makedirs(downloadDir, exist_ok=True)
        self._registerCleanupPath(downloadDir)
        return downloadDir

    def _setupBrowserAndDir(self):
        self._cleanupStaleBrowserProcesses()
        self._assertBrowserHostResourcesHealthy()
        browserName = self.DEFAULT_BROWSER
        downloadDir = self._prepareDownloadDir(browserName)

        if browserName == "chrome":
            driver = self._setupChromeDriver(downloadDir)
        elif browserName == "firefox":
            driver = self._setupFirefoxDriver(downloadDir)
        else:
            raise ValueError(f"Unsupported FFL_LARGE_FILE_BROWSER: {browserName}")

        return driver, downloadDir

    def _assertBrowserHostResourcesHealthy(self):
        virtualMemory = psutil.virtual_memory()
        swapMemory = psutil.swap_memory()

        print(
            f"[Test] Browser host resource check: "
            f"available_mem={virtualMemory.available} bytes, "
            f"swap_used={swapMemory.used} bytes, "
            f"swap_percent={swapMemory.percent:.1f}%"
        )

        if virtualMemory.available < self.BROWSER_MIN_AVAILABLE_MEMORY:
            raise AssertionError(
                "Host resources are too constrained to start a browser large-file case safely: "
                f"available memory is {virtualMemory.available} bytes, which is below the required "
                f"{self.BROWSER_MIN_AVAILABLE_MEMORY} bytes. "
                "Wait for previous browser processes to exit, reboot/clean the host, or lower "
                "FFL_LARGE_FILE_BROWSER_MIN_AVAILABLE_MEMORY if you intentionally want to proceed."
            )

        if swapMemory.total > 0 and swapMemory.percent >= self.BROWSER_MAX_SWAP_USED_PERCENT:
            raise AssertionError(
                "Host swap usage is already too high to start another browser large-file case safely: "
                f"swap usage is {swapMemory.percent:.1f}% ({swapMemory.used}/{swapMemory.total} bytes), "
                f"threshold is {self.BROWSER_MAX_SWAP_USED_PERCENT:.1f}%. "
                "Clean up stuck browser/test processes, reboot the host, or raise "
                "FFL_LARGE_FILE_BROWSER_MAX_SWAP_USED_PERCENT if you intentionally want to proceed."
            )

    def _cleanupStaleBrowserProcesses(self):
        killedPids = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdlineList = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdlineList).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if not cmdline:
                continue

            isHeadlessChrome = (
                name in ("chrome.exe", "chrome", "google-chrome", "google-chrome-stable")
                and "--headless" in cmdline
            )
            isTestChrome = (
                isHeadlessChrome
                and (
                    "--test-type" in cmdline
                    or "localhost:8000" in cmdline
                    or "fastfilelink.com" in cmdline
                    or "127.0.0.1" in cmdline
                )
            )
            isTestDriver = name in (
                "undetected_chromedriver.exe",
                "chromedriver.exe",
                "undetected_chromedriver",
                "chromedriver",
            )

            if not (isTestChrome or isTestDriver):
                continue

            try:
                proc.kill()
                killedPids.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                print(f"[Test] Warning: failed to kill stale browser process {proc.info['pid']}: {exc}")

        if killedPids:
            print(f"[Test] Cleaned stale browser/driver processes: {killedPids}")

    def _addQueryParams(self, url, **params):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for key, value in params.items():
            query[key] = str(value)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _downloadUrlFromShareLink(self, shareLink):
        return shareLink.rstrip("/") + "/download"

    def _createDownloadSession(self):
        try:
            SettingsGetter.getInstance()
        except RuntimeError:
            SettingsGetter(platform=platform.system(), exePath=sys.executable)

        session = requests.Session()
        adapter = StallResilientAdapter(
            chunkSize=self.REQUEST_CHUNK_SIZE,
            allowedMethods={"GET"},
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _getObservedRequestUrls(self, driver):
        urls = []
        try:
            for entry in driver.get_log("performance"):
                try:
                    message = json.loads(entry["message"])["message"]
                except Exception:
                    continue

                params = message.get("params", {})
                requestUrl = params.get("request", {}).get("url")
                responseUrl = params.get("response", {}).get("url")
                if requestUrl:
                    urls.append(requestUrl)
                elif responseUrl:
                    urls.append(responseUrl)
        except Exception as exc:
            print(f"[Test] Warning: failed to collect browser request URLs: {exc}")
        return urls

    def _createBrowserEvidence(self):
        return {
            "observedUrls": set(),
            "fallbackDetected": False,
            "resumeDetected": False,
            "writerUsed": False,
            "baseBytes": 0,
        }

    def _updateBrowserEvidence(self, driver, evidence):
        if not driver or evidence is None:
            return evidence

        for url in self._getObservedRequestUrls(driver):
            evidence["observedUrls"].add(url)

        analysis = self._analyzeBrowserLogsForResume(driver)
        evidence["fallbackDetected"] = evidence["fallbackDetected"] or analysis["fallbackDetected"]
        evidence["resumeDetected"] = evidence["resumeDetected"] or analysis["resumeDetected"]
        evidence["writerUsed"] = evidence["writerUsed"] or analysis["writerUsed"]
        evidence["baseBytes"] = max(evidence["baseBytes"], analysis["baseBytes"])
        return evidence

    def _analysisFromEvidence(self, evidence):
        if not evidence:
            return {
                "resumeDetected": False,
                "fallbackDetected": False,
                "writerUsed": False,
                "baseBytes": 0,
                "logs": [],
            }

        return {
            "resumeDetected": evidence["resumeDetected"],
            "fallbackDetected": evidence["fallbackDetected"],
            "writerUsed": evidence["writerUsed"],
            "baseBytes": evidence["baseBytes"],
            "logs": [],
        }

    def _printTransferSummary(self, label, totalBytes, elapsedSeconds):
        if elapsedSeconds <= 0:
            print(f"[Test] {label} summary: elapsed time too small to calculate throughput")
            return

        mibPerSecond = (totalBytes / (1024 * 1024)) / elapsedSeconds
        mbps = (totalBytes * 8) / elapsedSeconds / 1_000_000
        print(
            f"[Test] {label} summary: {totalBytes} bytes in {elapsedSeconds:.1f}s "
            f"({mibPerSecond:.2f} MiB/s, {mbps:.1f} Mbps)"
        )

    def _waitForLargeDownload(self, downloadDir, expectedFilename, timeout, driver=None, evidence=None):
        partialSuffixes = (".part", ".crdownload", ".tmp")
        stem = os.path.splitext(expectedFilename)[0]

        def findFinishedFile():
            if not os.path.isdir(downloadDir):
                return None

            for fileName in os.listdir(downloadDir):
                if fileName == expectedFilename or fileName.startswith(stem):
                    filePath = os.path.join(downloadDir, fileName)
                    if not fileName.endswith(partialSuffixes) and os.path.isfile(filePath):
                        if os.path.getsize(filePath) > 0:
                            return filePath
            return None

        def getLargestPartial():
            largestPath = None
            largestSize = 0
            if not os.path.isdir(downloadDir):
                return largestPath, largestSize

            for fileName in os.listdir(downloadDir):
                if not (fileName == expectedFilename or fileName.startswith(stem)):
                    continue

                if not fileName.endswith(partialSuffixes):
                    continue

                filePath = os.path.join(downloadDir, fileName)
                try:
                    size = os.path.getsize(filePath)
                except OSError:
                    continue

                if size > largestSize:
                    largestPath = filePath
                    largestSize = size

            return largestPath, largestSize

        startTime = time.time()
        lastLoggedSize = -1
        lastProgressTime = startTime
        lastProgressSize = 0

        print(f"[Test] Waiting for large download in: {downloadDir}")
        print(f"[Test] Expected filename: {expectedFilename}")
        print(f"[Test] Timeout: {timeout} seconds")

        while time.time() - startTime < timeout:
            self._updateBrowserEvidence(driver, evidence)

            downloadedFile = findFinishedFile()
            if downloadedFile:
                self._updateBrowserEvidence(driver, evidence)
                elapsed = time.time() - startTime
                finalSize = os.path.getsize(downloadedFile)
                print(f"[Test] Large download completed: {downloadedFile}")
                self._printTransferSummary("Browser download", finalSize, elapsed)
                return downloadedFile

            partialPath, partialSize = getLargestPartial()
            now = time.time()

            if partialSize > lastProgressSize:
                lastProgressSize = partialSize
                lastProgressTime = now

            if partialSize != lastLoggedSize:
                if partialPath:
                    print(f"[Test] Partial progress: {partialSize} bytes ({partialPath})")
                elif not os.path.isdir(downloadDir):
                    print(f"[Test] Download directory not created yet: {downloadDir}")
                lastLoggedSize = partialSize

            stallDuration = now - lastProgressTime
            if partialSize > 0 and stallDuration >= 300:
                print(
                    f"[Test] WARNING: Large download stalled for {stallDuration:.0f}s at {partialSize} bytes"
                )
                lastProgressTime = now

            time.sleep(5)

        if driver is not None:
            try:
                self._updateBrowserEvidence(driver, evidence)
                self._printBrowserLogs(driver=driver, title="Browser logs at large-download timeout")
            except Exception as exc:
                print(f"[Test] Failed to print browser logs after timeout: {exc}")

        raise AssertionError(f"Large download did not complete within {timeout} seconds")

    def _downloadWithBrowserTimeout(self, driver, shareUrl, downloadDir, expectedFilename, timeout, evidence=None):
        print(f"[Test] Navigating browser to: {shareUrl}")
        driver.get(shareUrl)
        WebDriverWait(driver, 20).until(lambda d: d.execute_script("return document.readyState") == "complete")

        try:
            capabilities = driver.capabilities
            if "firefox" in capabilities.get("browserName", "").lower():
                self._attachConsoleMirror(driver)
        except Exception:
            pass

        return self._waitForLargeDownload(downloadDir, expectedFilename, timeout, driver=driver, evidence=evidence)

    def _downloadWithRequests(self, requestUrl, outputPath, timeout):
        self._registerCleanupPath(outputPath)
        os.makedirs(os.path.dirname(outputPath), exist_ok=True)

        totalBytes = 0
        lastLoggedThreshold = 0
        startTime = time.time()
        socketTimeout = max(60, min(timeout, self.REQUEST_SOCKET_TIMEOUT))

        print(f"[Test] Starting direct HTTP download: {requestUrl}")
        print(f"[Test] Request chunk size: {self.REQUEST_CHUNK_SIZE} bytes")
        print(f"[Test] Direct download output: {outputPath}")
        print(f"[Test] Direct HTTP socket timeout: {socketTimeout} seconds")

        session = self._createDownloadSession()
        try:
            with session.get(
                requestUrl,
                stream=True,
                timeout=(60, socketTimeout),
                headers={"Cache-Control": "no-cache"},
            ) as response:
                response.raise_for_status()
                print(f"[Test] Direct HTTP status: {response.status_code}")
                print(f"[Test] Final URL: {response.url}")
                print(f"[Test] Content-Length: {response.headers.get('Content-Length')}")

                with open(outputPath, "wb") as outputHandle:
                    for chunk in response.iter_content(chunk_size=self.REQUEST_CHUNK_SIZE):
                        if not chunk:
                            continue

                        outputHandle.write(chunk)
                        totalBytes += len(chunk)

                        if totalBytes - lastLoggedThreshold >= self.REQUEST_LOG_INTERVAL:
                            elapsed = time.time() - startTime
                            print(
                                f"[Test] Direct HTTP progress: {totalBytes} bytes in {elapsed:.1f}s"
                            )
                            lastLoggedThreshold = totalBytes
        finally:
            session.close()

        elapsed = time.time() - startTime
        print(f"[Test] Direct HTTP download completed: {totalBytes} bytes in {elapsed:.1f}s")
        self._printTransferSummary("Direct HTTP download", totalBytes, elapsed)
        return outputPath

    def _verifyLargeDownloadedFile(self, downloadedFilePath):
        if not os.path.exists(downloadedFilePath):
            raise AssertionError(f"Downloaded file does not exist: {downloadedFilePath}")

        downloadedFileSize = os.path.getsize(downloadedFilePath)
        print(f"[Test] Downloaded large file size: {downloadedFileSize} bytes")

        if downloadedFileSize != self.originalFileSize:
            raise AssertionError(
                f"Downloaded file size ({downloadedFileSize}) does not match expected ({self.originalFileSize})"
            )

        if self.originalFileHash:
            print("[Test] Computing downloaded file SHA-256...")
            downloadedHash = getFileHash(downloadedFilePath)
            print(f"[Test] Downloaded file SHA-256: {downloadedHash}")
            if downloadedHash != self.originalFileHash:
                raise AssertionError("Downloaded large file hash does not match the original")

        print("[Test] Large file verification successful")

    def _startLargeShare(self, p2p=True, timeout=None):
        shareEnv = self._getLargeShareEnv()
        binaryCommand = os.getenv("FFL_LARGE_FILE_BINARY", "").strip() or None
        outputCapture = {}
        shareLink = self._startFastFileLink(
            p2p=p2p,
            output=False,
            timeout=timeout or (self.SHARE_READY_TIMEOUT if p2p else self.UPLOAD_READY_TIMEOUT),
            captureOutputIn=outputCapture,
            extraEnvVars=shareEnv,
            extraArgs=["--preferred-tunnel", "default"],
            binaryCommand=binaryCommand,
        )
        return shareLink, outputCapture

    def _getLargeShareEnv(self):
        env = {}
        for key in (
            "FILESHARE_TEST",
            "STATIC_SERVER",
            "BUILTIN_TUNNEL",
            "FFL_TUNNEL_DOMAIN",
            "ONLY_BUILTIN_TUNNEL",
            "TUNNEL_TOKEN_SERVER_URL",
        ):
            value = os.getenv(key)
            if value:
                env[key] = value
        return env

    def _runBrowserLargeDownload(self, shareUrl, extraQueryParams=None):
        driver, downloadDir = self._setupBrowserAndDir()
        finalUrl = self._addQueryParams(shareUrl, **extraQueryParams) if extraQueryParams else shareUrl
        evidence = self._createBrowserEvidence()
        downloadedFile = self._downloadWithBrowserTimeout(
            driver,
            finalUrl,
            downloadDir,
            self.expectedFilename,
            self.DOWNLOAD_TIMEOUT,
            evidence=evidence,
        )
        self._updateBrowserEvidence(driver, evidence)
        return downloadedFile, driver, evidence

    def _shouldRequireResumeEvidence(self):
        return self.originalFileSize > self.USE_BLOB_THRESHOLD and self.STALL_AFTER_BYTES < self.originalFileSize

    def _shouldUseRequestsForUploadDownload(self):
        return self.DEFAULT_BROWSER == "chrome" and self._isHeadlessEnabled()

    def _printHeadlessUploadWarning(self):
        print("[Test] WARNING: Large upload browser verification under Chrome headless is known to be unreliable.")
        print("[Test] WARNING: This is a Chrome headless limitation rather than a product download failure.")
        print("[Test] WARNING: Falling back to direct requests download verification for the upload scenario.")

    def _assertUploadCredentialAvailable(self):
        credentialPath = None
        if self._testConfigDir:
            credentialPath = os.path.join(self._testConfigDir, ".credential")
            if os.path.exists(credentialPath):
                print(f"[Test] Upload credential available in test config: {credentialPath}")
                return

            print(
                "[Test] Upload scenario did not find a copied .credential in the test config; "
                "trying _provisionLocalTestServerCredential() fallback."
            )
            self._provisionLocalTestServerCredential()
            if os.path.exists(credentialPath):
                print(
                    "[Test] Upload credential provisioned via local test-server fixture fallback: "
                    f"{credentialPath}"
                )
                print(
                    "[Test] NOTE: This fallback relies on the shared test@nuwainfo.com fixture and "
                    "is intended for development/testing convenience."
                )
                return

        originalStorageDir = None
        try:
            originalStorageDir = StorageLocator.getInstance().storageDir
        except Exception:
            originalStorageDir = None

        message = (
            "Upload scenario requires a valid login credential, but no .credential file was found "
            f"in the test config{f' ({credentialPath})' if credentialPath else ''}."
        )
        if originalStorageDir:
            message += (
                f" Original storage location is: {originalStorageDir}. "
                "Please run `ffl login` (or place a valid .credential there) before running the upload scenario."
            )
        else:
            message += " Please run `ffl login` before running the upload scenario."

        raise AssertionError(message)

    def testLargeHttpRequestDownload(self):
        """Large-file direct HTTP verification using requests without browser involvement."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)

            outputPath = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{self.expectedFilename}")
            downloadedFile = self._downloadWithRequests(
                shareLink,
                outputPath,
                self.DOWNLOAD_TIMEOUT
            )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadHttpOnly(self):
        """Large-file browser download forced to pure HTTP path via ?webrtc=0."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                shareLink,
                extraQueryParams={"debug": 1, "webrtc": 0}
            )
            observedUrls = sorted(evidence["observedUrls"])
            offerUrls = [url for url in observedUrls if "/offer" in url]
            downloadUrls = [url for url in observedUrls if "/download" in url]

            self.assertFalse(
                offerUrls,
                f"Expected no WebRTC /offer request for pure HTTP browser path, observed: {offerUrls}"
            )
            self.assertTrue(
                downloadUrls,
                f"Expected HTTP /download request for pure HTTP browser path, observed URLs: {observedUrls}"
            )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadWebRTCOnly(self):
        """Large-file P2P browser download with browser-side HTTP fallback disabled."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                self._withBrowserFallbackDisabled(shareLink)
            )

            serverOutput = self._updateCapturedOutput(outputCapture)
            self.assertIn("P2P", serverOutput, "Expected P2P marker in sharer output for pure WebRTC scenario")
            self._verifyLargeDownloadedFile(downloadedFile)
        finally:
            self._terminateProcess()

    def testLargeBrowserDownloadAfterWebRTCDisconnect(self):
        """Large-file browser download after simulated WebRTC disconnect, resuming through HTTP relay."""
        try:
            shareLink, outputCapture = self._startLargeShare(p2p=True)
            downloadedFile, driver, evidence = self._runBrowserLargeDownload(
                shareLink,
                extraQueryParams={
                    "debug": 1,
                    "simulate-stall": "true",
                    "stall-after": self.STALL_AFTER_BYTES,
                    "fallback-ms": self.FALLBACK_TIMEOUT_MS,
                }
            )

            observedUrls = sorted(evidence["observedUrls"])
            analysis = self._analysisFromEvidence(evidence)
            resumeUrls = [
                url for url in observedUrls
                if "/download" in url and ("resume_start=" in url or "resume_base=" in url)
            ]
            self._printDiagnosticSummary(analysis)
            if resumeUrls:
                print(f"[Test] Resume-related download URLs observed: {resumeUrls}")

            self.assertTrue(analysis["fallbackDetected"], "Expected browser logs to show HTTP fallback")
            if self._shouldRequireResumeEvidence():
                self.assertTrue(
                    analysis["baseBytes"] > 0 or analysis["resumeDetected"] or bool(resumeUrls),
                    (
                        "Expected either browser resume logs or resume_* query parameters in the observed "
                        "HTTP download request after simulated WebRTC disconnect"
                    )
                )
            else:
                print(
                    "[Test] Resume evidence not required for this small-file smoke run; "
                    "download completion after fallback is sufficient."
                )

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()

    def testLargeUploadAndBrowserDownload(self):
        """Large-file upload-mode share followed by browser download."""
        try:
            self._assertUploadCredentialAvailable()
            shareLink, outputCapture = self._startLargeShare(p2p=False)
            if self._shouldUseRequestsForUploadDownload():
                self._printHeadlessUploadWarning()
                outputPath = os.path.join(self._getLargeDownloadRoot(), f"{self._testMethodName}_{self.expectedFilename}")
                downloadedFile = self._downloadWithRequests(
                    shareLink,
                    outputPath,
                    self.DOWNLOAD_TIMEOUT
                )
            else:
                downloadedFile, driver, evidence = self._runBrowserLargeDownload(shareLink)

            self._verifyLargeDownloadedFile(downloadedFile)
            self._printServerOutput(outputCapture, lastNLines=80)
        finally:
            self._terminateProcess()


SCENARIO_TO_TEST = {
    "http-request": "testLargeHttpRequestDownload",
    "http-browser": "testLargeBrowserDownloadHttpOnly",
    "webrtc": "testLargeBrowserDownloadWebRTCOnly",
    "fallback": "testLargeBrowserDownloadAfterWebRTCDisconnect",
    "upload": "testLargeUploadAndBrowserDownload",
}


def buildArgumentParser():
    parser = argparse.ArgumentParser(description="Run manual large-file FastFileLink scenarios.")
    parser.add_argument(
        "--scenario",
        choices=[*SCENARIO_TO_TEST.keys(), "all"],
        nargs="+",
        default=["all"],
        help="Scenario(s) to run. Default: all",
    )
    parser.add_argument("--binary", help="External share command prefix, e.g. ./ffl.com or 'python Core.py --cli'")
    parser.add_argument("--size", help="Override FFL_LARGE_FILE_SIZE, e.g. 20M, 100G")
    parser.add_argument("--browser", choices=["chrome", "firefox"], help="Override browser for browser scenarios")
    parser.add_argument("--file", dest="filePath", help="Override FFL_LARGE_FILE_PATH")
    parser.add_argument("--download-dir", dest="downloadDir", help="Override FFL_LARGE_FILE_DOWNLOAD_DIR")
    parser.add_argument("--tunnel", help="Override BUILTIN_TUNNEL and FFL_TUNNEL_DOMAIN")
    return parser


def hasHelpfulBaselineEnv():
    baselineKeys = (
        "FILESHARE_TEST",
        "STATIC_SERVER",
        "FFL_LARGE_FILE_PATH",
        "FFL_LARGE_FILE_SIZE",
    )
    return any(os.getenv(key) for key in baselineKeys)


def printDirectRunExamples():
    examples = [
        (
            "Local JS + old tunnel quick smoke",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_DOWNLOAD_DIR='D:\\LargeFileTest\\downloads'",
                "python tests/LargeFileTest.py --scenario http-request --size 20M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "HTTP browser smoke with local JS",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_DOWNLOAD_DIR='D:\\LargeFileTest\\downloads'",
                "python tests/LargeFileTest.py --scenario http-browser --size 20M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "Fallback/resume smoke with local JS",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "$env:FFL_LARGE_FILE_STALL_AFTER='96M'",
                "$env:FFL_LARGE_FILE_FALLBACK_MS='2000'",
                "python tests/LargeFileTest.py --scenario fallback --size 100M --tunnel 33.fastfilelink.com",
            ],
        ),
        (
            "Upload smoke using external artifact",
            [
                "$env:FILESHARE_TEST='True'",
                "$env:STATIC_SERVER='http://localhost:8000'",
                "python tests/LargeFileTest.py --scenario upload --size 20M --tunnel 33.fastfilelink.com --binary \"C:\\Users\\Naga\\miniconda3\\envs\\fileshare\\python.exe Core.py --cli\"",
            ],
        ),
    ]

    print("LargeFileTest needs environment setup before direct execution.")
    print("")
    print("Copy/paste examples (PowerShell):")
    print("")
    for title, commands in examples:
        print(f"# {title}")
        for command in commands:
            print(command)
        print("")


def applyDirectRunArgs(args):
    os.environ["FFL_ENABLE_LARGE_FILE_TESTS"] = "1"

    if args.binary:
        os.environ["FFL_LARGE_FILE_BINARY"] = args.binary
    if args.size:
        os.environ["FFL_LARGE_FILE_SIZE"] = args.size
    if args.browser:
        os.environ["FFL_LARGE_FILE_BROWSER"] = args.browser
    if args.filePath:
        os.environ["FFL_LARGE_FILE_PATH"] = args.filePath
    if args.downloadDir:
        os.environ["FFL_LARGE_FILE_DOWNLOAD_DIR"] = args.downloadDir
    if args.tunnel:
        os.environ["BUILTIN_TUNNEL"] = args.tunnel
        os.environ["FFL_TUNNEL_DOMAIN"] = args.tunnel
        os.environ["ONLY_BUILTIN_TUNNEL"] = "True"


def runSelectedScenarios(args):
    applyDirectRunArgs(args)
    LargeFileTest.configureFromEnvironment()

    requestedScenarios = args.scenario
    if "all" in requestedScenarios:
        requestedScenarios = list(SCENARIO_TO_TEST.keys())

    suite = unittest.TestSuite()
    for scenario in requestedScenarios:
        suite.addTest(LargeFileTest(SCENARIO_TO_TEST[scenario]))

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if len(sys.argv) == 1 and not hasHelpfulBaselineEnv():
        printDirectRunExamples()
        sys.exit(0)

    sys.exit(runSelectedScenarios(buildArgumentParser().parse_args()))
