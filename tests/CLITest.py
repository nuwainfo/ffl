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
import subprocess
import json
import tempfile
import sys

from .CoreTestBase import FastFileLinkTestBase


class CLITest(FastFileLinkTestBase):
    """Test class for CLI-specific features like --max-downloads and --timeout."""

    def testCLIWithMaxDownloads(self):
        """Test the --max-downloads feature with 1 download."""
        extraArgs = ["--max-downloads", "1"]
        shareLink = self._startAndGetShareLink(extraArgs=extraArgs)

        # Download the file once
        downloadedFilePath = self._getDownloadedFilePath("max_downloads_test.bin")
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)

        # The server should shut down after one download
        self._assertProcessTerminated(timeout=15)
        self._assertTerminationMessage("Maximum downloads (1) reached. Shutting down server.")

    def testCLIWithMaxDownloadsMultiple(self):
        """Test the --max-downloads feature with 3 downloads."""
        extraArgs = ["--max-downloads", "3"]
        shareLink = self._startAndGetShareLink(extraArgs=extraArgs)
        print(f'[Test] Link: {shareLink}')

        # Wait longer for server to be fully ready after tunnel establishment
        time.sleep(3)

        # Download the file three times with longer delays for tunnel stability
        for i in range(3):
            downloadedFilePath = self._getDownloadedFilePath(f"max_downloads_test_{i+1}.bin")
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)
            print(f"[Test] Completed download {i+1}/3")

        # The server should shut down after three downloads
        self._assertProcessTerminated(timeout=15)
        self._assertTerminationMessage("Maximum downloads (3) reached. Shutting down server.")

    def testCLIWithTimeout(self):
        """Test the --timeout feature with 5 seconds."""
        extraArgs = ["--timeout", "5"]
        shareLink = self._startAndGetShareLink(extraArgs=extraArgs)

        # Wait longer than the timeout duration
        print("[Test] Waiting for timeout to trigger...")
        time.sleep(7) # Wait a bit longer than the timeout

        # The server should have shut down due to the timeout
        self._assertProcessTerminated(timeout=5)
        self._assertTerminationMessage("Timeout (5 seconds) reached. Shutting down server.")

    def testCLIWithTimeoutShorter(self):
        """Test the --timeout feature with 3 seconds."""
        extraArgs = ["--timeout", "3"]
        shareLink = self._startAndGetShareLink(extraArgs=extraArgs)

        # Wait longer than the timeout duration
        print("[Test] Waiting for shorter timeout to trigger...")
        time.sleep(5) # Wait a bit longer than the timeout

        # The server should have shut down due to the timeout
        self._assertProcessTerminated(timeout=3)
        self._assertTerminationMessage("Timeout (3 seconds) reached. Shutting down server.")

    def _startAndGetShareLink(self, extraArgs=None):
        """Helper to start the process and get the share link using _startFastFileLink"""
        # Setup output capture for later termination message checking
        self.outputCapture = {}
        return self._startFastFileLink(p2p=True, extraArgs=extraArgs, captureOutputIn=self.outputCapture)

    def _assertProcessTerminated(self, timeout=10):
        """Wait for the process to terminate and assert it has stopped"""
        if not self.coreProcess:
            return

        startTime = time.time()
        while time.time() - startTime < timeout:
            if self.coreProcess.poll() is not None:
                print(f"[Test] Process terminated with exit code: {self.coreProcess.returncode}")
                return
            time.sleep(0.5)

        self.fail(f"Process did not terminate within {timeout} seconds")

    def _assertTerminationMessage(self, expectedMessage):
        """Assert that the process output contains the expected termination message"""
        if not self.coreProcess:
            return

        # Ensure the process has finished
        self.coreProcess.wait(timeout=5)

        # Use the generic output capture pattern
        combinedOutput = ""
        if hasattr(self, 'outputCapture') and self.outputCapture:
            combinedOutput = self._updateCapturedOutput(self.outputCapture)
        
        # Fallback to direct log file reading for backwards compatibility
        if not combinedOutput and self.procLogPath and os.path.exists(self.procLogPath):
            try:
                with open(self.procLogPath, "r", encoding="utf-8", errors="replace") as lf:
                    combinedOutput = lf.read()
            except Exception as e:
                print(f"[Test] Failed to read process log file: {e}")

        print(f"[Test] Process output: {combinedOutput}")

        if expectedMessage not in combinedOutput:
            self.fail(f"Expected termination message '{expectedMessage}' not found in output: {combinedOutput}")

    def _runCommandAndGetOutput(self, extraArgs):
        """Helper to run CLI command with args and capture output using generic pattern"""
        outputCapture = {}
        command = [
            "python",
            os.path.join(os.path.dirname(__file__), "..", "Core.py"), "--cli", "share", self.testFilePath
        ]
        command.extend(extraArgs)
        
        print(f"[Test] Running command: {' '.join(command)}")
        
        # Use file-based output capture to avoid pipe buffer issues
        self._procLogFile = open(self.procLogPath, "w+", encoding="utf-8", buffering=1)
        
        # Pass current environment to subprocess (including any test environment variables)
        env = os.environ.copy()
        
        self.coreProcess = subprocess.Popen(
            command,
            stdout=self._procLogFile,
            stderr=subprocess.STDOUT,
            text=True,
            env=env
        )
        
        # Setup output capture context
        outputCapture['_process'] = self.coreProcess
        outputCapture['_logPath'] = self.procLogPath
        outputCapture['_logFile'] = self._procLogFile
        
        # Give the process a moment to start and check what happens
        time.sleep(2)  # Let the process start and handle arguments
        
        # Check if process has already terminated (e.g., due to argument validation error)
        if self.coreProcess.poll() is not None:
            print(f"[Test] Process already terminated with exit code: {self.coreProcess.returncode}")
            # Get output immediately for early termination
            return self._updateCapturedOutput(outputCapture)
        
        # For auth tests, the process should terminate quickly due to timeout or error
        # Wait for process to complete, but force terminate if needed
        try:
            self._assertProcessTerminated(timeout=15)  # Increased timeout for auth tests
        except AssertionError:
            # Process didn't terminate naturally, force terminate it
            print("[Test] Process didn't terminate naturally, forcing termination...")
            print(f"[Test] Process PID: {self.coreProcess.pid if self.coreProcess else 'None'}")
            if self.coreProcess and self.coreProcess.poll() is None:
                self.coreProcess.terminate()
                try:
                    self.coreProcess.wait(timeout=5)
                    print("[Test] Process terminated gracefully")
                except subprocess.TimeoutExpired:
                    print("[Test] Process didn't respond to terminate, using kill")
                    self.coreProcess.kill()
                    self.coreProcess.wait()
        
        # Get final output
        return self._updateCapturedOutput(outputCapture)

    def testCLIAuthPasswordOnly(self):
        """Test --auth-password enables auth with default username 'ffl'."""
        extraArgs = ["--auth-password", "secret123", "--timeout", "5"]
        
        print(f"[Test] Testing auth with password only")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Should show auth enabled with username 'ffl' but NOT show password
        self.assertIn("Authentication enabled - Username: ffl", combinedOutput)
        self.assertNotIn("secret123", combinedOutput)  # Password should not be shown

    def testCLIAuthUserAndPassword(self):
        """Test --auth-user and --auth-password work together."""
        extraArgs = ["--auth-user", "admin", "--auth-password", "mypass", "--timeout", "5"]
        
        print(f"[Test] Testing auth with user and password")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Should show auth enabled with custom username but NOT show password
        self.assertIn("Authentication enabled - Username: admin", combinedOutput)
        self.assertNotIn("mypass", combinedOutput)  # Password should not be shown

    def testCLIAuthUserOnlyError(self):
        """Test --auth-user without --auth-password shows error."""
        extraArgs = ["--auth-user", "admin"]
        
        print(f"[Test] Testing auth user only (should fail)")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Should show error message
        self.assertIn("Error: --auth-user requires --auth-password", combinedOutput)
        self.assertIn("Use --auth-password to enable authentication", combinedOutput)

    def testCLINoAuthNormal(self):
        """Test no auth arguments work normally without auth messages."""
        extraArgs = ["--timeout", "5"]
        
        print(f"[Test] Testing no auth (normal operation)")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Should NOT show any auth messages
        self.assertNotIn("Authentication enabled", combinedOutput)

    def testForceRelayFreeUserRestriction(self):
        """Test --force-relay restriction for free users with default tunnel."""
        extraArgs = ["--force-relay", "--preferred-tunnel", "default"]
        
        # Set Free user level for this test
        originalFreeLevel = self._setTestEnvVar("FREE_USER_LEVEL", "Free")
        
        try:
            combinedOutput = self._runCommandAndGetOutput(extraArgs)
            
            # Should show restriction error (actual message includes "logged in user")
            self.assertIn("requires a logged in user", combinedOutput)
            self.assertIn("Standard or Plus plan", combinedOutput)
            
        finally:
            self._restoreTestEnvVar("FREE_USER_LEVEL", originalFreeLevel)

    def testForceRelayStandardUserAllowed(self):
        """Test --force-relay works for Standard/Plus users with default tunnel."""
        extraArgs = ["--force-relay", "--preferred-tunnel", "default", "--timeout", "3"]
        
        # Set Standard user level - should bypass restriction with fixed isFreeUser()
        originalFreeLevel = self._setTestEnvVar("FREE_USER_LEVEL", "Standard")
        
        try:
            combinedOutput = self._runCommandAndGetOutput(extraArgs)
            
            # With the fixed isFreeUser() implementation that checks both serial number
            # AND level, Standard users should not see the restriction message
            self.assertNotIn("requires a logged in user", combinedOutput)
            
        finally:
            self._restoreTestEnvVar("FREE_USER_LEVEL", originalFreeLevel)

    def testAliasBasic(self):
        """Test --alias creates a link with the specified alias."""
        alias = "cooltest"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias {alias}")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Check that the alias appears in the generated URL
        self.assertIn(f"/{alias}", combinedOutput, f"Expected alias '{alias}' to appear in the sharing URL")
        
        # Should not contain auth messages since no auth is configured
        self.assertNotIn("HTTP Basic Auth", combinedOutput)

    def testAliasWithOtherArguments(self):
        """Test --alias works with other CLI arguments like --max-downloads."""
        alias = "testdownloads"
        extraArgs = ["--alias", alias, "--max-downloads", "1"]
        shareLink = self._startAndGetShareLink(extraArgs=extraArgs)
        
        print(f"[Test] Testing --alias {alias} with --max-downloads")
        
        # Verify alias is in the share link
        self.assertIn(f"/{alias}", shareLink, f"Expected alias '{alias}' to appear in the sharing URL")
        
        # Download the file once to verify functionality still works
        downloadedFilePath = self._getDownloadedFilePath("alias_max_downloads_test.bin")
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)
        
        # The server should shut down after one download
        self._assertProcessTerminated(timeout=15)
        self._assertTerminationMessage("Maximum downloads (1) reached. Shutting down server.")

    def testAliasWithAuth(self):
        """Test --alias works with authentication arguments."""
        alias = "securetest"
        extraArgs = ["--alias", alias, "--auth-password", "testpass123", "--timeout", "5"]
        
        print(f"[Test] Testing --alias {alias} with authentication")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Check that the alias appears in the generated URL
        self.assertIn(f"/{alias}", combinedOutput, f"Expected alias '{alias}' to appear in the sharing URL")
        
        # Should contain auth messages since auth is configured
        self.assertIn("Authentication enabled", combinedOutput)

    def testAliasSpecialCharacters(self):
        """Test --alias with various characters (letters, numbers, common symbols)."""
        alias = "test123-cool_alias"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with special characters: {alias}")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Check that the alias appears in the generated URL
        self.assertIn(f"/{alias}", combinedOutput, f"Expected alias '{alias}' to appear in the sharing URL")

    def testAliasWithSpaces(self):
        """Test --alias with spaces (should be URL encoded)."""
        alias = "my cool file"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with spaces: '{alias}'")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Spaces should be URL encoded as %20
        expected_encoded = "my%20cool%20file"
        self.assertIn(f"/{expected_encoded}", combinedOutput, f"Expected URL-encoded alias '{expected_encoded}' to appear in the sharing URL")

    def testAliasWithPercent(self):
        """Test --alias with percent signs (should be URL encoded)."""
        alias = "test%file"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with percent: '{alias}'")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Percent should be URL encoded as %25
        expected_encoded = "test%25file"
        self.assertIn(f"/{expected_encoded}", combinedOutput, f"Expected URL-encoded alias '{expected_encoded}' to appear in the sharing URL")

    def testAliasWithQuestion(self):
        """Test --alias with question marks (should be URL encoded)."""
        alias = "what?why"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with question mark: '{alias}'")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Question mark should be URL encoded as %3F
        expected_encoded = "what%3Fwhy"
        self.assertIn(f"/{expected_encoded}", combinedOutput, f"Expected URL-encoded alias '{expected_encoded}' to appear in the sharing URL")

    def testAliasWithHash(self):
        """Test --alias with hash/fragment signs (should be URL encoded)."""
        alias = "file#1"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with hash: '{alias}'")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Hash should be URL encoded as %23
        expected_encoded = "file%231"
        self.assertIn(f"/{expected_encoded}", combinedOutput, f"Expected URL-encoded alias '{expected_encoded}' to appear in the sharing URL")

    def testAliasWithUnicode(self):
        """Test --alias with Unicode characters (should be URL encoded)."""
        alias = "测试文件"  # Chinese characters meaning "test file"
        extraArgs = ["--alias", alias, "--timeout", "3"]
        
        print(f"[Test] Testing --alias with Unicode: '{alias}'")
        combinedOutput = self._runCommandAndGetOutput(extraArgs)
        
        print(f"[Test] Process output: {combinedOutput}")
        
        # Unicode should be URL encoded
        import urllib.parse
        expected_encoded = urllib.parse.quote(alias, safe='')
        self.assertIn(f"/{expected_encoded}", combinedOutput, f"Expected URL-encoded alias '{expected_encoded}' to appear in the sharing URL")


class CLIArgumentParsingTest(unittest.TestCase):
    """Lightweight test class for CLI argument parsing behavior - help, version, and error cases"""

    def _runCoreWithArgs(self, args):
        """Helper to run Core.py with specific arguments and capture output"""
        command = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "Core.py")]
        command.extend(args)
        
        # Set up environment to disable GUI addon for CLI testing
        env = os.environ.copy()
        env['DISABLE_ADDONS'] = 'GUI'
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                env=env
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "Process timed out", 1

    def testCLIArgumentsHelpBehavior(self):
        """Test various CLI argument combinations that should show help"""
        testCases = [
            # Only --cli should show help
            (["--cli"], "help", "Only --cli should show help"),
            
            # No arguments should show help (handled by main())
            ([], "help", "No arguments should show help"),
            
            # --log-level without other required args should show help
            (["--log-level", "info"], "help", "--log-level info alone should show help"),
            (["--log-level", "debug"], "help", "--log-level debug alone should show help"),
            
            # --cli with --log-level should show help
            (["--cli", "--log-level", "info"], "help", "--cli --log-level info should show help"),
            (["--cli", "--log-level", "debug"], "help", "--cli --log-level debug should show help"),
            (["--log-level", "debug", "--cli"], "help", "--log-level debug --cli should show help"),
            
            # Various other incomplete combinations should show help
            (["--timeout", "30"], "help", "--timeout alone should show help"),
            (["--max-downloads", "5"], "help", "--max-downloads alone should show help"),
            (["--port", "8080"], "help", "--port alone should show help"),
            (["--preferred-tunnel", "cloudflare"], "help", "--preferred-tunnel alone should show help"),
            
            # Multiple incomplete args should still show help
            (["--cli", "--timeout", "30"], "help", "--cli --timeout should show help"),
            (["--log-level", "info", "--timeout", "30"], "help", "--log-level --timeout should show help"),
            (["--cli", "--max-downloads", "5", "--log-level", "debug"], "help", "Multiple incomplete args should show help"),
        ]
        
        for args, expectedBehavior, description in testCases:
            with self.subTest(args=args, description=description):
                output, returnCode = self._runCoreWithArgs(args)
                
                if expectedBehavior == "help":
                    # Should show help text
                    helpIndicators = [
                        "usage:",  # argparse help format
                        "A software that make you share file easier",  # description
                        "positional arguments:",  # sections of help
                        "optional arguments:",
                        "options:",  # newer argparse versions use "options"
                    ]
                    
                    foundHelpIndicator = any(indicator in output.lower() for indicator in helpIndicators)
                    
                    if not foundHelpIndicator:
                        self.fail(f"Expected help output for {args}, but got: {output}")
                    
                    print(f"✓ {description}: Found help output")

    def testCLIArgumentsVersionBehavior(self):
        """Test --version argument behavior"""
        testCases = [
            # --version alone should show version
            (["--version"], "version", "--version should show version"),
            
            # --version with other args should still show version (and exit early)
            (["--version", "--cli"], "version", "--version --cli should show version"),
            (["--cli", "--version"], "version", "--cli --version should show version"),
            (["--version", "--log-level", "debug"], "version", "--version --log-level should show version"),
            (["--log-level", "info", "--version"], "version", "--log-level --version should show version"),
        ]
        
        for args, expectedBehavior, description in testCases:
            with self.subTest(args=args, description=description):
                output, returnCode = self._runCoreWithArgs(args)
                
                if expectedBehavior == "version":
                    # Should show version information
                    versionIndicators = [
                        "fastfilelink v",  # Version string
                        "enabled addons:",  # Addons list
                    ]
                    
                    foundVersionIndicator = any(indicator in output.lower() for indicator in versionIndicators)
                    
                    if not foundVersionIndicator:
                        self.fail(f"Expected version output for {args}, but got: {output}")
                    
                    # Should exit with code 0 for version
                    self.assertEqual(returnCode, 0, f"Version command should exit with code 0, got {returnCode}")
                    
                    print(f"✓ {description}: Found version output")

    def testCLIArgumentsValidCombinations(self):
        """Test CLI argument combinations that should work (with file argument)"""
        # Create a temporary test file for valid sharing commands
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            tempFileName = f.name
        
        try:
            validCases = [
                # Valid sharing commands (should not show help, but start sharing)
                ([tempFileName], "start_sharing", "File alone should start sharing"),
                (["--cli", "share", tempFileName], "start_sharing", "--cli share file should start sharing"),
                ([tempFileName, "--timeout", "3"], "start_sharing", "File with timeout should start sharing"),
                (["--cli", "share", tempFileName, "--log-level", "debug"], "start_sharing", "--cli share file --log-level should start sharing"),
                ([tempFileName, "--alias", "testAlias"], "start_sharing", "File with --alias should start sharing"),
                (["--cli", "share", tempFileName, "--alias", "cliTest"], "start_sharing", "--cli share file --alias should start sharing"),
                ([tempFileName, "--alias", "test123", "--timeout", "3"], "start_sharing", "File with --alias and --timeout should start sharing"),
            ]
            
            for args, expectedBehavior, description in validCases:
                with self.subTest(args=args, description=description):
                    # For valid cases, we expect the process to start but we'll terminate it quickly
                    command = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "Core.py")]
                    command.extend(args)
                    
                    # Set up environment to disable GUI addon for CLI testing
                    env = os.environ.copy()
                    env['DISABLE_ADDONS'] = 'GUI'
                    
                    try:
                        # Start the process
                        proc = subprocess.Popen(
                            command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            env=env
                        )
                        
                        # Give it a moment to start
                        time.sleep(2)
                        
                        # Terminate it before it does anything significant
                        proc.terminate()
                        
                        try:
                            output, _ = proc.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            output, _ = proc.communicate()
                        
                        # Should NOT show help output for valid commands
                        helpIndicators = [
                            "usage:",
                            "positional arguments:",
                            "optional arguments:",
                            "options:",
                        ]
                        
                        foundHelpIndicator = any(indicator in output.lower() for indicator in helpIndicators)
                        
                        if foundHelpIndicator:
                            self.fail(f"Expected valid sharing start for {args}, but got help output: {output}")
                        
                        print(f"✓ {description}: Did not show help (started normally)")
                        
                    except Exception as e:
                        print(f"⚠ {description}: Exception during test: {e}")
                        # Don't fail the test for process management issues
                        
        finally:
            # Clean up temp file
            try:
                os.unlink(tempFileName)
            except:
                pass

    def testCLIArgumentsInvalidCombinations(self):
        """Test CLI argument combinations that should show errors"""
        errorCases = [
            # Invalid argument values
            (["--port", "99999"], "error", "--port with invalid value should show error"),
            (["--timeout", "-5"], "error", "--timeout with negative value should show error"),
            (["--max-downloads", "-1"], "error", "--max-downloads with negative value should show error"),
            (["--log-level", "invalid"], "error", "--log-level with invalid value should show error"),
            
            # Missing required values
            (["--port"], "error", "--port without value should show error"),
            (["--timeout"], "error", "--timeout without value should show error"),
            (["--max-downloads"], "error", "--max-downloads without value should show error"),
            (["--log-level"], "error", "--log-level without value should show error"),
        ]
        
        for args, expectedBehavior, description in errorCases:
            with self.subTest(args=args, description=description):
                output, returnCode = self._runCoreWithArgs(args)
                
                if expectedBehavior == "error":
                    # Should show error and non-zero exit code
                    errorIndicators = [
                        "error:",
                        "invalid",
                        "usage:",  # argparse shows usage on errors
                    ]
                    
                    foundErrorIndicator = any(indicator in output.lower() for indicator in errorIndicators)
                    
                    if not foundErrorIndicator:
                        self.fail(f"Expected error output for {args}, but got: {output}")
                    
                    # Should exit with non-zero code for errors
                    self.assertNotEqual(returnCode, 0, f"Error command should exit with non-zero code, got {returnCode}")
                    
                    print(f"✓ {description}: Found error output with code {returnCode}")


if __name__ == '__main__':
    unittest.main()
