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
import subprocess

from tests.CoreTestBase import FastFileLinkTestBase


class ResumeTestBase(FastFileLinkTestBase):
    """Shared helpers for upload pause/resume scenarios."""

    def _waitForCoreCompletion(self, timeout):
        if not self.coreProcess:
            return
        try:
            self.coreProcess.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"Process did not complete within {timeout} seconds") from exc

    def _pauseUpload(
        self,
        pausePercentage=40,
        outputCapture=None,
        extraArgs=None,
        extraEnv=None,
        useTestServer=False,
    ):
        """Start an upload with --pause and wait until it exits."""
        capture = outputCapture if outputCapture is not None else {}
        args = list(extraArgs or [])
        args.extend(['--pause', str(pausePercentage)])

        serverHandle = self._startFastFileLink(
            p2p=False,
            extraArgs=args,
            captureOutputIn=capture,
            extraEnvVars=extraEnv,
            useTestServer=useTestServer,
            waitForCompletion=False,
        )

        capture.setdefault('_process', self.coreProcess)
        capture.setdefault('_logPath', getattr(self, 'procLogPath', None))
        capture.setdefault('_logFile', getattr(self, '_procLogFile', None))

        testServerProcess = None
        if useTestServer:
            if isinstance(serverHandle, tuple):
                _, testServerProcess = serverHandle
            else:
                testServerProcess = serverHandle

        fileSizeMB = self.fileSizeBytes / (1024 * 1024)
        pauseTimeout = max(60, int(fileSizeMB * 3))
        self._waitForCoreCompletion(pauseTimeout)

        pauseLog = self._updateCapturedOutput(capture)
        if "Upload paused at" not in pauseLog:
            raise AssertionError(f"Expected pause confirmation, log:\n{pauseLog}")

        self._terminateProcess()
        if self._procLogFile:
            try:
                self._procLogFile.close()
            finally:
                self._procLogFile = None
        return testServerProcess, pauseLog

    def _resumeUpload(
        self,
        outputCapture=None,
        extraArgs=None,
        extraEnv=None,
        useTestServer=False,
    ):
        """Resume an interrupted upload and return share link plus log."""
        capture = outputCapture if outputCapture is not None else {}
        args = list(extraArgs or [])
        if '--resume' not in args:
            args.append('--resume')

        resumeResult = self._startFastFileLink(
            p2p=False,
            extraArgs=args,
            captureOutputIn=capture,
            extraEnvVars=extraEnv,
            useTestServer=useTestServer,
        )

        if isinstance(resumeResult, tuple):
            resumeShareLink = resumeResult[0]
        else:
            resumeShareLink = resumeResult

        resumeLog = self._updateCapturedOutput(capture)
        if "Resuming upload:" not in resumeLog:
            raise AssertionError(f"Expected resume confirmation, log:\n{resumeLog}")

        if self._procLogFile:
            try:
                self._procLogFile.close()
            finally:
                self._procLogFile = None
        return resumeShareLink, resumeLog


import re
import signal
import threading
from selenium.webdriver.support.ui import WebDriverWait

from tests.BrowserTestBase import BrowserTestBase
from tests.CoreTestBase import generateRandomFile, getFileHash


class TestTimeoutError(Exception):
    """Custom exception for test timeouts"""
    pass


class ResumeBrowserTestBase(BrowserTestBase, ResumeTestBase):
    """Mix-in combining browser setup with upload resume helpers."""

    def setUp(self):
        BrowserTestBase.setUp(self)

    def tearDown(self):
        BrowserTestBase.tearDown(self)

    @staticmethod
    def _resumeRelatedLogFilter(message, level):
        """Filter for resume-related logs: errors (except 404) and resume keywords"""
        if "SEVERE" in level or "ERROR" in level or level == 'error':
            return "404" not in message
        return any(keyword in message for keyword in ["resume", "Fallback", "Resume calculation", "Writer closed successfully"])

    def _analyzeBrowserLogsForResume(self, driver):
        """Analyze browser logs for resume evidence and return summary

        Returns:
            dict: {
                'resumeDetected': bool,
                'fallbackDetected': bool,
                'writerUsed': bool,
                'baseBytes': int,
                'logs': list
            }
        """
        resumeDetected = False
        fallbackDetected = False
        writerUsed = False
        baseBytes = 0

        try:
            browserLogs = self._getBrowserLogs(driver)

            # Process each log entry (handle both Chrome and Firefox formats)
            for logEntry in browserLogs:
                message, level = self._normalizeLogEntry(logEntry)

                # Check for resume calculation
                if "Resume calculation" in message and "baseBytes=" in message:
                    resumeDetected = True
                    # Extract base bytes from resume calculation
                    baseMatch = re.search(r"baseBytes=(\d+)", message)
                    if baseMatch:
                        baseBytes = int(baseMatch.group(1))

                # Check for fallback trigger
                if (
                    "Switching to HTTP download" in message or "DownloadManager started" in message or
                    "Successfully transitioned from P2P to HTTP" in message or "Fallback" in message
                ):
                    fallbackDetected = True

                # Check for writer being used to write HTTP bytes
                if "Writer closed successfully, HTTP bytes written:" in message:
                    writerUsed = True

            return {
                'resumeDetected': resumeDetected,
                'fallbackDetected': fallbackDetected,
                'writerUsed': writerUsed,
                'baseBytes': baseBytes,
                'logs': browserLogs
            }
        except Exception as e:
            print(f"[Test] Could not analyze browser logs: {e}")
            return {'resumeDetected': False, 'fallbackDetected': False, 'writerUsed': False, 'baseBytes': 0, 'logs': []}

    def _printDiagnosticSummary(self, analysis):
        """Print diagnostic summary of resume test analysis

        Args:
            analysis: Dict returned by _analyzeBrowserLogsForResume
        """
        print(f"\n[Test] Diagnostic summary:")
        print(f"  - Fallback triggered: {analysis['fallbackDetected']}")
        print(f"  - Resume detected: {analysis['resumeDetected']}")
        print(f"  - Writer used: {analysis['writerUsed']}")
        print(f"  - Base bytes: {analysis['baseBytes']} ({analysis['baseBytes'] / (1024*1024):.1f} MB)")
        if analysis['fallbackDetected'] and not analysis['writerUsed']:
            print(f"  - Issue: Fallback triggered but HTTP download didn't complete")
        elif not analysis['fallbackDetected']:
            print(f"  - Issue: Fallback was not triggered within timeout")

    def _printServerOutput(self, outputCapture, lastNLines=100):
        """Print last N lines of server output from captured output

        Args:
            outputCapture: Dict containing captured output from _startFastFileLink
            lastNLines: Number of lines to print from end, or None to print all lines
        """
        if lastNLines is None:
            print(f"\n[Test] Core.py server output (all):")
        else:
            print(f"\n[Test] Core.py server output (last {lastNLines} lines):")

        serverOutput = self._updateCapturedOutput(outputCapture)
        if serverOutput:
            lines = serverOutput.split('\n')
            linesToPrint = lines if lastNLines is None else lines[-lastNLines:]
            for line in linesToPrint:
                if line.strip():
                    try:
                        print(f"  {line}")
                    except UnicodeEncodeError:
                        print(f"  <line contains unicode characters>")
        else:
            print("  (No server output captured)")

    def _testHttpResumeWithFallback(
        self,
        browserName,
        largeFileSize=100 * 1024 * 1024,
        stallAfterBytes=20 * 1024 * 1024,
        extraEnvVars=None,
        extraArgs=None
    ):
        """Test HTTP resume when WebRTC connection stalls and falls back to HTTP

        This method creates a large test file, starts FastFileLink with P2P mode,
        navigates a browser to trigger WebRTC download with simulated stall,
        waits for fallback to HTTP with resume, and verifies the writer-based resume worked.

        Args:
            browserName: 'chrome' or 'firefox'
            largeFileSize: Size of test file in bytes
            stallAfterBytes: Number of bytes to transfer before simulating stall
            extraEnvVars: Optional dict of extra environment variables (e.g., {'JS_DEBUG': 'True'})
            extraArgs: Optional list of extra arguments to pass to _startFastFileLink (e.g., ['--e2ee'])
        """        
        # Wait for download to complete with reasonable timeout
        # Reduced for debugging: 60s base + 1s per MB
        # Usually every 1-2 seconds should have progress
        downloadTimeoutSeconds = 60 + int(largeFileSize / (1024 * 1024))
        print(f"[Test] Download timeout: {downloadTimeoutSeconds} seconds")        
        
        # Set up hard timeout for entire test (to prevent infinite hangs)
        maxTestTimeout = downloadTimeoutSeconds + 30 # 30s buffer
        print(f"[Test] Setting hard timeout for entire test: {maxTestTimeout} seconds")
        
        timerTriggered = threading.Event()

        def hardTimeout():
            timerTriggered.set()
            print(f"\n[Test] HARD TIMEOUT TRIGGERED after {maxTestTimeout} seconds!")
            print("[Test] Test is taking too long - forcing failure to prevent infinite hang")
            # Don't raise here - will be checked in main thread

        timer = threading.Timer(maxTestTimeout, hardTimeout)
        timer.daemon = True
        timer.start()

        try:
            # Create large test file for resume testing
            largeFilePath = os.path.join(self.tempDir, "resume_test.bin")
            generateRandomFile(largeFilePath, largeFileSize)

            originalHash = getFileHash(largeFilePath)
            originalSize = os.path.getsize(largeFilePath)

            print(f"[Test] Created large test file for resume testing")
            print(f"[Test] File size: {originalSize} bytes ({originalSize // (1024*1024)} MB)")
            print(f"[Test] File hash: {originalHash}")

            # Temporarily override test file
            originalTestFilePath = self.testFilePath
            originalFileHash = self.originalFileHash
            originalFileSize = self.originalFileSize

            self.testFilePath = largeFilePath
            self.originalFileHash = originalHash
            self.originalFileSize = originalSize

            try:
                # Capture output for verification
                outputCapture = {}

                # Merge extra env vars
                envVars = os.environ
                if extraEnvVars:
                    envVars.update(extraEnvVars)
                
                # Or in Jenkins + Chrome, writer.write will stuck, unknown why...:(
                if browserName == 'chrome' and 'JENKINS_HOME' in os.environ:
                    envVars['STREAMSAVER_BLOB'] = 'True'

                shareLink = self._startFastFileLink(
                    p2p=True,
                    output=False,
                    captureOutputIn=outputCapture,
                    timeout=600,
                    extraEnvVars=envVars,
                    extraArgs=extraArgs or []
                )

                # Setup browser driver
                if browserName == 'chrome':
                    driver = self._setupChromeDriver(self.chromeDownloadDir)
                    downloadDir = self.chromeDownloadDir
                elif browserName == 'firefox':
                    driver = self._setupFirefoxDriver(self.firefoxDownloadDir)
                    downloadDir = self.firefoxDownloadDir
                else:
                    raise ValueError(f"Unsupported browser: {browserName}")

                # Add debug parameters to simulate WebRTC stall after specified bytes
                # Use 1 minute (60000ms) fallback timeout - sufficient for testing
                debugUrl = (
                    f"{shareLink}?debug=1"
                    f"&simulate-stall=true&stall-after={stallAfterBytes}&fallback-ms=60000"
                )

                print(f"[Test] Navigating to: {debugUrl}")
                driver.get(debugUrl)

                # Wait for page to load
                WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")

                # Attach console mirror for Firefox (Chrome uses native get_log)
                try:
                    caps = driver.capabilities
                    if 'firefox' in caps.get('browserName', '').lower():
                        self._attachConsoleMirror(driver)
                except Exception:
                    pass

                print("[Test] Waiting for WebRTC to start, stall, fallback to HTTP, and complete download...")

                downloadedFile = None
                try:
                    # Check for hard timeout before waiting
                    if timerTriggered.is_set():
                        raise TestTimeoutError("Hard timeout triggered before download wait")

                    downloadedFile = self._waitForDownload(
                        downloadDir, "resume_test.bin", timeout=downloadTimeoutSeconds
                    )

                    # Check for hard timeout after download
                    if timerTriggered.is_set():
                        raise TestTimeoutError("Hard timeout triggered during download wait")

                except Exception as e:
                    # Get browser logs for debugging before re-raising
                    print(f"[Test] Download failed or timed out: {e}")
                    print("[Test] Analyzing browser logs for failure diagnosis...")

                    # Analyze logs using common method
                    analysis = self._analyzeBrowserLogsForResume(driver)

                    # Print ALL browser logs on failure (no filtering) - use cached logs from analysis
                    self._printBrowserLogs(logs=analysis['logs'], title="Browser logs at time of failure (all logs)")

                    # Print diagnostic summary
                    self._printDiagnosticSummary(analysis)

                    # Print ALL server output on failure (no line limit)
                    self._printServerOutput(outputCapture, lastNLines=None)

                    raise

                print("[Test] Download completed - now checking browser logs for all resume evidence...")

                # Analyze logs using common method
                analysis = self._analyzeBrowserLogsForResume(driver)

                # Print ALL browser logs on success - use cached logs from analysis
                self._printBrowserLogs(logs=analysis['logs'], title="Browser logs (all logs)")

                # Print filtered browser logs (errors and resume-related messages only)
                # self._printBrowserLogs(logs=analysis['logs'], logFilter=self._resumeRelatedLogFilter,
                #                      title="Browser logs (filtered: errors except 404, and resume-related messages)")

                # Print diagnostic summary (same as failure path, but for success verification)
                self._printDiagnosticSummary(analysis)

                # Print analysis results
                if analysis['resumeDetected']:
                    print("[Test] PASS: Resume calculation detected in browser logs")
                    print(f"[Test]   Resume base bytes: {analysis['baseBytes']} ({analysis['baseBytes'] // (1024*1024)} MB)")
                if analysis['fallbackDetected']:
                    print("[Test] PASS: HTTP fallback detected")
                if analysis['writerUsed']:
                    print("[Test] PASS: Writer was used for HTTP download (resume successful)")

                # Assert ALL resume conditions - verify resume by checking logs and file integrity
                if not analysis['resumeDetected']:
                    raise AssertionError(
                        "Resume calculation was not logged - bytesWritten may be 0. "
                        "Check browser logs for 'Resume calculation' message"
                    )
                if not analysis['fallbackDetected']:
                    raise AssertionError("HTTP fallback was not triggered")
                if analysis['baseBytes'] == 0:
                    raise AssertionError(
                        "Resume reported zero initial bytes - WebRTC may have transferred nothing before stall"
                    )
                if not analysis['writerUsed']:
                    raise AssertionError(
                        "Writer was not used for HTTP download - resume may have failed to use existing writer"
                    )

                # Verify downloaded file
                self._verifyDownloadedFile(downloadedFile)

                # Print server output for final verification
                self._printServerOutput(outputCapture, lastNLines=50)

                print("[Test] HTTP resume test passed - file downloaded and verified!")

            finally:
                # Restore original test file
                self.testFilePath = originalTestFilePath
                self.originalFileHash = originalFileHash
                self.originalFileSize = originalFileSize

        finally:
            # Cancel the hard timeout timer
            if 'timer' in locals():
                timer.cancel()

            # Check if hard timeout was triggered
            if timerTriggered.is_set():
                print(f"\n[Test] Test exceeded maximum timeout of {maxTestTimeout} seconds")
                print("[Test] Forcing cleanup and failure...")

            self._terminateProcess()
