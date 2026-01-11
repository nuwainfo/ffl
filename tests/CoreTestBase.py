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

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import requests
import socket
import shutil

import psutil


# ---------------------------
# File I/O helpers
# ---------------------------
def generateRandomFile(path, sizeBytes):
    """Generate a random file of the specified size"""
    with open(path, 'wb') as f:
        f.write(os.urandom(sizeBytes))


def getFileHash(path):
    """Get the SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            sha256.update(block)
    return sha256.hexdigest()


def isProcessRunning(pid):
    """Check if a process is running"""
    try:
        process = psutil.Process(pid)
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except Exception as e:
        print(f"[Test] Error checking process status: {e}")
        return True


# ---------------------------
# Base test class
# ---------------------------
class FastFileLinkTestBase(unittest.TestCase):
    """Base class for FastFileLink tests"""

    def __init__(self, methodName='runTest', fileSizeBytes=1024 * 1024, testConfigVars=None):
        super().__init__(methodName)
        self._ownsTempDir = True
        self._tempDirObj = tempfile.TemporaryDirectory()
        self.tempDir = self._tempDirObj.name
        self.coreProcess = None
        self.fileSizeBytes = fileSizeBytes # Store the file size
        self.procLogPath = os.path.join(self.tempDir, "ffl_proc.log")
        self._procLogFile = None

        # Test config management - always enabled
        self.testConfigVars = testConfigVars or {}
        self._testConfigDir = None
        self._originalEnvVars = None

    def setUp(self):
        """Set up the test environment"""
        assert isinstance(self.tempDir, str), "tempDir must be a path string"

        # Always setup test config
        self._setupTestConfig()

        # Generate a random test file with specified size
        self.testFilePath = os.path.join(self.tempDir, "testfile.bin")
        generateRandomFile(self.testFilePath, self.fileSizeBytes)

        # Create paths for output JSON
        self.jsonOutputPath = os.path.join(self.tempDir, "share_info.json")

        # Calculate hash of the original file for later comparison
        self.originalFileHash = getFileHash(self.testFilePath)
        self.originalFileSize = os.path.getsize(self.testFilePath)

        print(f"[Test] Generated test file: {self.testFilePath}")
        print(f"[Test] File size: {self.originalFileSize} bytes ({self.originalFileSize / (1024*1024):.2f} MB)")
        print(f"[Test] File hash: {self.originalFileHash}")

    def tearDown(self):
        """Clean up after the test"""
        self._terminateProcess()

        # Clean up process log file
        if self._procLogFile:
            try:
                self._procLogFile.close()
            except Exception:
                pass
            self._procLogFile = None

        # Always restore environment variables
        if self._originalEnvVars is not None:
            self._teardownTestConfig()

        # If we created the temp directory, clean it up
        if self._ownsTempDir:
            self._tempDirObj.cleanup()

    def _updateCapturedOutput(self, captureOutputIn):
        """Update captured output with latest process output"""
        if captureOutputIn is None:
            return

        outputText = ""
        logPath = captureOutputIn.get('_logPath')
        logFile = captureOutputIn.get('_logFile')

        if logPath and os.path.exists(logPath):
            try:
                # Ensure log file is flushed before reading
                if logFile:
                    logFile.flush()
                with open(logPath, "r", encoding="utf-8", errors="replace") as lf:
                    outputText = lf.read()
            except Exception as e:
                print(f"[Test] Failed to update captured output: {e}")

        captureOutputIn['output'] = outputText
        return outputText

    def _terminateProcess(self):
        """Terminate the FastFileLink process gracefully"""
        if self.coreProcess:
            # Check if process is still running
            if self.coreProcess.poll() is None:
                print("[Test] Process is still running, sending Ctrl+C signal")
                try:
                    if sys.platform == 'win32':
                        import signal
                        # On Windows, this might not work in all cases
                        os.kill(self.coreProcess.pid, signal.CTRL_C_EVENT)
                    else:
                        import signal
                        # On Unix-like systems, send SIGINT
                        os.kill(self.coreProcess.pid, signal.SIGINT)

                    # Give the process some time to handle the signal
                    for _ in range(5): # Wait up to 5 seconds
                        time.sleep(1)
                        if self.coreProcess.poll() is not None:
                            print("[Test] Process terminated after Ctrl+C")
                            break
                except KeyboardInterrupt:
                    print("Catched KeyboardInterrupt")
                    time.sleep(2)
                except Exception as e:
                    print(f"[Test] Failed to send Ctrl+C signal: {e}")

            # If process is still running after Ctrl+C, terminate it
            if isProcessRunning(self.coreProcess.pid):
                try:
                    self.coreProcess.terminate()

                    # Wait for termination
                    try:
                        self.coreProcess.wait(timeout=5)
                        print("[Test] Process terminated after explicit termination")
                    except subprocess.TimeoutExpired:
                        print("[Test] Process didn't terminate, killing it")
                        self.coreProcess.kill()
                        self.coreProcess.wait()
                except KeyboardInterrupt:
                    pass
                except Exception as e:
                    print(f"[Test] Failed terminate: {e}")
            else:
                print("[Test] Process already terminated")

    def downloadFileWithRequests(self, shareLink, outputPath, expectedFileName=None):
        """
        Download file using requests library with retry logic

        Args:
            shareLink: URL to download from
            outputPath: Local path to save downloaded file
            expectedFileName: If provided, verify Content-Disposition header matches this filename
        """
        print("[Test] Attempting to download file through share link...")

        # Try multiple times in case it takes a while for the link to be active
        for attempt in range(3):
            try:
                print(f"[Test] Download attempt {attempt + 1}")
                response = requests.get(shareLink, timeout=30)
                if response.status_code == 200:
                    # Verify Content-Disposition header if expectedFileName provided
                    if expectedFileName:
                        contentDisposition = response.headers.get('Content-Disposition', '')
                        print(f"[Test] Content-Disposition header: {contentDisposition}")

                        # Parse filename from Content-Disposition header
                        # Format: attachment; filename="myfile.txt" or attachment; filename=myfile.txt
                        actualFileName = None
                        if 'filename=' in contentDisposition:
                            # Extract filename (handle both quoted and unquoted)
                            filenamePart = contentDisposition.split('filename=')[1].split(';')[0].strip()
                            actualFileName = filenamePart.strip('"\'')

                        if actualFileName:
                            print(f"[Test] Extracted filename from header: {actualFileName}")
                            if actualFileName != expectedFileName:
                                raise AssertionError(
                                    f"Content-Disposition filename mismatch: expected '{expectedFileName}', got '{actualFileName}'"
                                )
                            print(f"[Test] Content-Disposition filename matches: {expectedFileName}")
                        else:
                            raise AssertionError(
                                f"Content-Disposition header missing filename (header: {contentDisposition})"
                            )

                    with open(outputPath, 'wb') as f:
                        f.write(response.content)
                    print(f"[Test] File downloaded successfully to {outputPath}")
                    return
                else:
                    print(f"[Test] Received status code: {response.status_code}")
            except Exception as e:
                print(f"[Test] Download attempt failed: {e}")
            time.sleep(2)

        raise AssertionError("Failed to download file through share link")

    def _downloadWithCore(self, shareLink, outputPath=None, extraArgs=None, extraEnvVars=None, captureOutputIn=None):
        """
        Download file using Core.py directly

        Args:
            shareLink (str): The share link to download from
            outputPath (str, optional): Output path for downloaded file
            extraArgs (list, optional): Additional command line arguments
            extraEnvVars (dict, optional): Additional environment variables
            captureOutputIn (dict, optional): Dictionary to capture process output

        Returns:
            str: Path to the downloaded file
        """
        print(f"[Test] Downloading file using Core.py from: {shareLink}")

        # Prepare download command
        downloadArgs = [sys.executable, "Core.py", "--cli"]

        # Separate global args (like --log-level) from download-specific args (like --resume)
        globalArgs = []
        downloadSpecificArgs = []
        if extraArgs:
            for arg in extraArgs:
                # Global arguments that must come before URL
                if arg in ["--log-level", "--version"] or (arg.startswith("tests/") or arg.startswith("../")):
                    globalArgs.append(arg)
                else:
                    # Download-specific arguments that must come after URL
                    downloadSpecificArgs.append(arg)

        # Add global arguments before URL
        if globalArgs:
            downloadArgs.extend(globalArgs)

        # Add the share link
        downloadArgs.append(shareLink)

        # Add download-specific arguments after URL (like --resume)
        if downloadSpecificArgs:
            downloadArgs.extend(downloadSpecificArgs)

        # Add output path if specified
        if outputPath:
            downloadArgs.extend(["-o", outputPath])

        # Prepare environment variables
        downloadEnv = os.environ.copy()
        if extraEnvVars:
            downloadEnv.update(extraEnvVars)

        # Prepare output capture
        logPath = None
        logFile = None
        if captureOutputIn is not None:
            logPath = os.path.join(self.tempDir, "download_log.txt")
            logFile = open(logPath, "w")
            captureOutputIn["logPath"] = logPath
            captureOutputIn["logFile"] = logFile

        try:
            # Run download process
            print(f"[Test] Running download command: {' '.join(downloadArgs)}")

            if logFile:
                downloadProcess = subprocess.Popen(
                    downloadArgs,
                    cwd=os.path.dirname(os.path.abspath(__file__ + "/..")),
                    env=downloadEnv,
                    stdout=logFile,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            else:
                downloadProcess = subprocess.Popen(
                    downloadArgs,
                    cwd=os.path.dirname(os.path.abspath(__file__ + "/..")),
                    env=downloadEnv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )

            # Wait for download to complete
            stdout, stderr = downloadProcess.communicate(timeout=120)

            if downloadProcess.returncode != 0:
                error_msg = f"Download process failed with exit code {downloadProcess.returncode}"

                # Read from log file if output was captured to file
                if logFile:
                    logFile.close()
                    try:
                        with open(logPath, 'r', encoding='utf-8', errors='replace') as f:
                            output = f.read()
                        if output:
                            error_msg += f"\n--- Full Client Output ---\n{output}\n--- End Output ---"
                    except Exception as e:
                        error_msg += f"\n(Failed to read log file: {e})"
                else:
                    # Read from stdout/stderr if captured directly
                    if stdout:
                        error_msg += f"\nOutput: {stdout}"
                    if stderr:
                        error_msg += f"\nError: {stderr}"

                raise AssertionError(error_msg)

            print("[Test] Download completed successfully")

            # Determine the downloaded file path
            # Always parse output to get actual path (handles directory case)
            if logFile:
                logFile.close()
                try:
                    with open(logPath, 'r') as f:
                        output = f.read()
                except Exception as e:
                    with open(logPath, 'r', encoding='utf-8') as f: # Try again.
                        output = f.read()
            else:
                output = stdout or ""

            # Look for "Downloaded: <path>" pattern
            downloadedPath = None
            for line in output.split('\n'):
                if "Downloaded:" in line:
                    downloadedPath = line.split(":", 1)[1].strip()
                    break

            # Fallback to outputPath if provided and not a directory
            if not downloadedPath:
                if outputPath and not os.path.isdir(outputPath):
                    downloadedPath = outputPath
                else:
                    # Last resort fallback
                    downloadedPath = os.path.join(os.getcwd(), "downloaded_file")

            if not os.path.exists(downloadedPath):
                raise AssertionError(f"Downloaded file not found at expected path: {downloadedPath}")

            print(f"[Test] Downloaded file saved to: {downloadedPath}")
            return downloadedPath

        except subprocess.TimeoutExpired:
            downloadProcess.kill()
            raise AssertionError("Download process timed out")
        finally:
            if logFile and not logFile.closed:
                logFile.close()

    def _updateCapturedOutput(self, captureDict):
        """
        Update captured output dictionary with latest process output

        Args:
            captureDict (dict): Dictionary containing capture information

        Returns:
            str: Current output text
        """
        if not captureDict:
            return ""

        # Support both logPath (download) and _logPath (upload) naming conventions
        logPath = captureDict.get("logPath") or captureDict.get("_logPath")
        if not logPath:
            return ""

        logFile = captureDict.get("logFile") or captureDict.get("_logFile")

        if os.path.exists(logPath):
            # Flush log file before reading if available
            if logFile:
                try:
                    logFile.flush()
                except Exception:
                    pass

            with open(logPath, "r", encoding="utf-8", errors="replace") as f:
                outputText = f.read()
            captureDict['output'] = outputText
            return outputText
        return ""

    def _startTestServer(self):
        """Start the test server for upload testing"""
        try:
            testServerScript = "TestServer.py"
            testServerPath = os.path.join(os.path.dirname(__file__), testServerScript)

            if not os.path.exists(testServerPath):
                raise AssertionError(f"{testServerScript} not found. Please ensure it's in the same directory.")

            print(f"[Test] Starting test server: {testServerPath}")

            # Check if port 5000 is already in use
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', 5000))
            sock.close()

            if result == 0:
                print(f"[Test] Port 5000 is already in use, attempting to kill the process...")

                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == 5000 and conn.status == psutil.CONN_LISTEN:
                        try:
                            proc = psutil.Process(conn.pid)
                            print(f"[Test] Killing process on port 5000: PID {conn.pid} ({proc.name()})")
                            proc.terminate()
                            proc.wait(timeout=3)
                        except Exception as e:
                            print(f"[Test] Failed to kill process {conn.pid}: {e}")
                time.sleep(1) # Give the system a moment to release the port

            # Prepare environment with UTF-8 encoding
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8' # Force UTF-8 encoding for Python I/O
            if sys.platform.startswith('win'):
                env['PYTHONUTF8'] = '1' # Enable UTF-8 mode on Windows (Python 3.7+)

            # Get the directory where TestServer.py is located
            testServerDir = os.path.dirname(testServerPath)

            # Start test server process with UTF-8 environment and correct working directory
            testServerProcess = subprocess.Popen(
                [sys.executable, testServerScript, "--host", "localhost", "--port", "5000"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env, # Use UTF-8 environment
                cwd=testServerDir # Set working directory to TestServer.py location
            )

            # Wait for server to start (check if port is available)
            startTime = time.time()
            serverReady = False

            while time.time() - startTime < 15: # Increase timeout to 15 seconds
                # Check if process has terminated
                if testServerProcess.poll() is not None:
                    stdout, stderr = testServerProcess.communicate()
                    print(f"[Test] Test server process terminated early")
                    print(f"[Test] Exit code: {testServerProcess.returncode}")
                    if stdout:
                        print(f"[Test] Test server stdout:\n{stdout[:1000]}...") # Limit output
                    if stderr:
                        print(f"[Test] Test server stderr:\n{stderr[:1000]}...") # Limit output
                    raise AssertionError("Test server process terminated unexpectedly")

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('localhost', 5000))
                    sock.close()

                    if result == 0: # Port is open
                        serverReady = True
                        break
                except Exception:
                    pass
                time.sleep(0.5)

            if not serverReady:
                # Get server output for debugging
                if testServerProcess.poll() is None:
                    testServerProcess.terminate()
                    stdout, stderr = testServerProcess.communicate(timeout=5)
                else:
                    stdout, stderr = testServerProcess.communicate()

                print(f"[Test] Test server failed to start within 15 seconds")
                if stdout:
                    print(f"[Test] Test server stdout:\n{stdout[:1000]}...")
                if stderr:
                    print(f"[Test] Test server stderr:\n{stderr[:1000]}...")
                raise AssertionError("Test server failed to start within 15 seconds")

            print(f"[Test] Test server started successfully on localhost:5000")
            return testServerProcess

        except Exception as e:
            print(f"[Test] Failed to start test server: {e}")
            raise

    def _stopTestServer(self, testServerProcess):
        """Stop the test server"""
        try:
            if testServerProcess is None:
                print(f"[Test] Test server was already running, not stopping")
                return

            if testServerProcess and testServerProcess.poll() is None:
                print(f"[Test] Stopping test server...")
                testServerProcess.terminate()

                # Wait for graceful shutdown
                try:
                    testServerProcess.wait(timeout=5)
                    print(f"[Test] Test server stopped gracefully")
                except subprocess.TimeoutExpired:
                    print(f"[Test] Test server didn't stop gracefully, killing it")
                    testServerProcess.kill()
                    testServerProcess.wait()

        except Exception as e:
            print(f"[Test] Error stopping test server: {e}")

    def _startFastFileLink(
        self,
        p2p=True,
        output=False,
        networkFailureRate=0.0,
        maxConsecutiveFailures=1,
        timeout=None,
        showOutput=False,
        useTestServer=False,
        extraEnvVars=None,
        extraArgs=None,
        captureOutputIn=None,
        waitForCompletion=True
    ):
        """
        Start the FastFileLink process and wait for the share link to be ready

        Args:
            p2p (bool): True for P2P mode, False for server mode
            output (bool): True to print process output, False to suppress
            networkFailureRate (float): Network failure rate for upload testing (0.0 to 1.0)
            maxConsecutiveFailures (int): Maximum consecutive failures for network simulation
            timeout (int): Custom timeout in seconds, defaults based on mode and file size
            showOutput (bool): Whether to show real-time process output
            useTestServer (bool): Whether to start local test server and use it
            extraEnvVars (dict): Additional environment variables to set
            extraArgs (list): Additional command line arguments to pass to the process
            captureOutputIn (dict): Optional dict to capture process output in ['output'] key

        Returns:
            tuple: (share_link, test_server_process) if useTestServer=True, otherwise just share_link
        """
        # Start test server if requested
        testServerProcess = None
        if useTestServer:
            testServerProcess = self._startTestServer()

        try:
            # Determine which core script to use
            useNetworkSimulation = networkFailureRate > 0.0
            coreScript = "CorePatched.py" # Always use CorePatched.py now
            coreScriptPath = os.path.join(os.path.dirname(__file__), coreScript)

            if not os.path.exists(coreScriptPath):
                raise AssertionError(f"{coreScript} not found. Please ensure it's in the same directory.")

            modeDesc = "with network simulation" if useNetworkSimulation else "normal mode"
            serverDesc = " + test server" if useTestServer else ""
            print(f"[Test] Starting FastFileLink in CLI mode using {coreScript} ({modeDesc}{serverDesc})...")
            if useNetworkSimulation:
                print(
                    f"[Test] Network simulation: {networkFailureRate * 100:.1f}% failure rate, max {maxConsecutiveFailures} consecutive failures"
                )
            print(f"[Test] Mode: {'P2P' if p2p else 'Server'}")

            # Prepare the command - use 'share' subcommand for file sharing
            command = [
                sys.executable, coreScriptPath, "--cli", "share", self.testFilePath, "--json", self.jsonOutputPath
            ]

            # Add network instability parameters if needed
            if useNetworkSimulation:
                command.extend([
                    "--network-failure-rate",
                    str(networkFailureRate),
                    "--max-consecutive-failures",
                    str(maxConsecutiveFailures),
                ])

            # Use debug logging tests to help diagnose issues
            if os.getenv("TEST_CASE_DEBUG") == "True":
                command.extend([
                    "--log-level",
                    os.path.join(os.path.dirname(__file__), "presets", "TestCaseDebugLogging.json")
                ])

            # Add mode-specific parameters
            if not p2p:
                command.extend(["--upload", "3 hours"])

            # Add extra arguments if provided
            if extraArgs:
                command.extend(extraArgs)

            # Print command with encoding handling for Windows console
            try:
                print(f"[Test] Command: {' '.join(command)}")
            except UnicodeEncodeError:
                print(f"[Test] Command: <contains unicode characters>")
            if showOutput:
                print(f"[Test] Real-time output enabled - you will see live progress...")

            # Prepare environment variables
            env = os.environ.copy()

            # Add environment variable to force output flushing
            env['PYTHONUNBUFFERED'] = '1'

            # Add test server environment variable if using test server
            if useTestServer:
                env['FILESHARE_TEST'] = 'http://localhost:5000'
                print(f"[Test] Using test server: FILESHARE_TEST=http://localhost:5000")

            # Add extra environment variables if provided
            if extraEnvVars:
                for key, value in extraEnvVars.items():
                    env[key] = str(value)
                    print(f"[Test] Extra env var: {key}={value}")

            # Launch in a separate process with conditional output capture
            if showOutput:
                # Real-time output: don't capture stdout/stderr, let them show directly
                # Force line buffering to ensure output appears immediately
                self.coreProcess = subprocess.Popen(
                    command,
                    text=True,
                    env=env,
                    bufsize=1, # Line buffered
                    universal_newlines=True
                )
            else:
                # File-based output: redirect stdout/stderr to log file to avoid pipe buffer deadlock
                self._procLogFile = open(self.procLogPath, "w+", encoding="utf-8", buffering=1)
                self.coreProcess = subprocess.Popen(
                    command,
                    stdout=self._procLogFile,
                    stderr=subprocess.STDOUT, # Merge stderr into stdout
                    text=True,
                    env=env,
                    bufsize=1 # Line buffered
                )

            # Determine appropriate timeout
            if timeout is None:
                if p2p:
                    timeout = 30 # P2P is usually quick
                else:
                    # Server upload timeout based on file size and network conditions
                    fileSizeMB = self.originalFileSize / (1024 * 1024)
                    baseTimeout = max(120, fileSizeMB * 3) # At least 2 minutes, or 3 seconds per MB

                    if useNetworkSimulation:
                        # Increase timeout significantly for network simulation
                        # Higher failure rate = more retries = more time needed
                        multiplier = 2 + (networkFailureRate * 8) # 2x to 10x for 0% to 100% failure rate
                        baseTimeout *= multiplier

                    timeout = int(baseTimeout)

            print(f"[Test] Process PID: {self.coreProcess.pid}")

            # Early return if not waiting for completion
            if not waitForCompletion:
                print("[Test] Process started, not waiting for completion")
                return testServerProcess if useTestServer else None

            print(f"[Test] Waiting up to {timeout} seconds for completion...")

            # Wait for the JSON file to be created
            jsonFileCreated = False
            startTime = time.time()
            lastStatusTime = startTime

            while time.time() - startTime < timeout:
                currentTime = time.time()

                if os.path.exists(self.jsonOutputPath):
                    jsonFileCreated = True
                    break

                # Check if process is still running
                if self.coreProcess and self.coreProcess.poll() is not None:
                    # Process has terminated
                    returnCode = self.coreProcess.returncode
                    print(f"[Test] Process terminated early with return code: {returnCode}")
                    break

                # Print status every 10 seconds
                if currentTime - lastStatusTime >= 10:
                    elapsed = currentTime - startTime
                    if self.coreProcess:
                        processStatus = "running" if self.coreProcess.poll(
                        ) is None else f"terminated ({self.coreProcess.returncode})"
                        print(
                            f"[Test] Status after {elapsed:.0f}s: Process {processStatus}, JSON file exists: {os.path.exists(self.jsonOutputPath)}"
                        )
                    lastStatusTime = currentTime

                time.sleep(1)

            if not jsonFileCreated:
                # Try to get some diagnostic information about the process failure
                processStatus = "unknown"
                if self.coreProcess:
                    if self.coreProcess.poll() is not None:
                        processStatus = f"terminated with return code {self.coreProcess.returncode}"
                    else:
                        processStatus = "still running"

                print(f"[Test] Process status: {processStatus}")

                if not showOutput and self._procLogFile:
                    # Ensure log file is flushed before reading
                    self._procLogFile.flush()
                    try:
                        with open(self.procLogPath, "r", encoding="utf-8", errors="replace") as lf:
                            logContent = lf.read()
                            print(f"[Test] Process combined log:\n{logContent}")
                    except Exception as e:
                        print(f"[Test] Failed to read process log: {e}")
                else:
                    print(f"[Test] JSON output file was not created (process output was shown above)")

                    # For showOutput mode, try to capture any remaining process output if process terminated
                    if self.coreProcess and self.coreProcess.poll() is not None:
                        try:
                            # Try to get stdout/stderr if available (won't work if process was started with showOutput=True, but worth trying)
                            stdout, stderr = self.coreProcess.communicate(timeout=5)
                            if stdout:
                                print(f"[Test] Process stdout: {stdout}")
                            if stderr:
                                print(f"[Test] Process stderr: {stderr}")
                        except Exception as e:
                            print(f"[Test] Could not capture process output: {e}")

                        # Try to read CorePatched debug file
                        try:
                            import tempfile
                            debugFile = os.path.join(tempfile.gettempdir(), "corepatched_debug.log")
                            if os.path.exists(debugFile):
                                with open(debugFile, "r", encoding="utf-8") as f:
                                    debugContent = f.read()
                                    print(f"[Test] CorePatched debug log:\n{debugContent}")
                                # Clean up debug file
                                os.remove(debugFile)
                            else:
                                print(f"[Test] No CorePatched debug file found at: {debugFile}")
                        except Exception as e:
                            print(f"[Test] Failed to read CorePatched debug file: {e}")

                        # Try to read FastFileLink application debug log
                        try:
                            # Look for debug file in the working directory where Core.py runs
                            appDebugFile = "fastfilelink_test_debug.log"
                            appDebugPaths = [
                                appDebugFile, # Current working directory
                                os.path.join(os.getcwd(), appDebugFile), # Explicit current dir
                                os.path.join(os.path.dirname(__file__), "..", appDebugFile), # Core.py directory
                            ]

                            debugFound = False
                            for debugPath in appDebugPaths:
                                if os.path.exists(debugPath):
                                    with open(debugPath, "r", encoding="utf-8") as f:
                                        appDebugContent = f.read()
                                        print(
                                            f"[Test] FastFileLink application debug log (from {debugPath}):\n{appDebugContent}"
                                        )
                                    # Clean up debug file
                                    os.remove(debugPath)
                                    debugFound = True
                                    break

                            if not debugFound:
                                print(f"[Test] No FastFileLink debug file found in any of these locations:")
                                for debugPath in appDebugPaths:
                                    print(f"  - {debugPath}")
                        except Exception as e:
                            print(f"[Test] Failed to read FastFileLink debug file: {e}")

                raise AssertionError(f"JSON output file was not created within {timeout} seconds")

            # Load and validate the JSON file
            with open(self.jsonOutputPath, 'r') as f:
                shareInfo = json.load(f)

            print(f"[Test] Operation completed successfully!")
            # Print share info with encoding handling for Windows console
            try:
                print(f"[Test] Share info loaded from JSON: {shareInfo}")
            except UnicodeEncodeError:
                print(f"[Test] Share info loaded from JSON (filename contains unicode characters)")

            # Verify the JSON contains the expected data
            requiredFields = ["link", "file", "file_size", "user"]
            for field in requiredFields:
                if field not in shareInfo:
                    raise AssertionError(f"JSON missing '{field}' field")

            # Verify file size is correct (skip if originalFileSize is -1, used for folders)
            if self.originalFileSize != -1 and shareInfo["file_size"] != self.originalFileSize:
                raise AssertionError(
                    f"File size in JSON ({shareInfo['file_size']}) doesn't match original file ({self.originalFileSize})"
                )

            shareLink = shareInfo["link"]
            print(f"[Test] Share link: {shareLink}")

            # Print process output if requested (only works when output was captured)
            if output and not showOutput:
                stdout, stderr = self.coreProcess.communicate()
                if stdout:
                    print(f"[Test] Process stdout:\n{stdout}")
                if stderr:
                    print(f"[Test] Process stderr:\n{stderr}")
            elif output and showOutput:
                print(f"[Test] Note: Process output was already shown in real-time")

            # Setup output capture context if requested
            if captureOutputIn is not None:
                captureOutputIn['_process'] = self.coreProcess
                captureOutputIn['_logPath'] = self.procLogPath
                captureOutputIn['_logFile'] = self._procLogFile
                # Initialize with current output (mainly for immediate reading scenarios)
                outputText = ""
                if self.procLogPath and os.path.exists(self.procLogPath):
                    try:
                        if self._procLogFile:
                            self._procLogFile.flush()
                        with open(self.procLogPath, "r", encoding="utf-8", errors="replace") as lf:
                            outputText = lf.read()
                    except Exception as e:
                        print(f"[Test] Failed to read initial process log: {e}")
                captureOutputIn['output'] = outputText

            # Return test server process along with share link if using test server
            if useTestServer:
                return shareLink, testServerProcess
            else:
                return shareLink

        except Exception as e:
            # Only stop test server on error, not on success
            if testServerProcess:
                self._stopTestServer(testServerProcess)
            raise

    def _startStdinStreaming(self, inputFilePath, customName=None, extraArgs=None, extraEnvVars=None):
        """
        Start Core.py with stdin input (cat file | python Core.py --cli -)

        Args:
            inputFilePath: Path to file to pipe as stdin
            customName: Custom filename to use with --name argument
            extraArgs: Additional command line arguments
            extraEnvVars: Additional environment variables

        Returns:
            str: Share link
        """
        # Prepare command: cat file | python Core.py --cli - --json output.json
        coreArgs = [sys.executable, "Core.py", "--cli", "-", "--json", self.jsonOutputPath]

        if customName:
            coreArgs.extend(["--name", customName])

        if extraArgs:
            coreArgs.extend(extraArgs)

        # Prepare environment
        env = os.environ.copy()
        if extraEnvVars:
            env.update(extraEnvVars)

        print(f"[Test] Input file: {inputFilePath}")
        print(f"[Test] Input file exists: {os.path.exists(inputFilePath)}")
        print(f"[Test] JSON output path: {self.jsonOutputPath}")
        
        # Working directory should be the project root (where Core.py is)
        # __file__ is tests/CoreTestBase.py, so two dirname calls get us to the project root
        workingDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        coreScriptPath = os.path.join(workingDir, "Core.py")
        
        print(f"[Test] Working directory: {workingDir}")
        print(f"[Test] Core.py exists: {os.path.exists(coreScriptPath)}")
        print(f"[Test] Command: {' '.join(coreArgs)}")

        # Open input file for piping
        with open(inputFilePath, 'rb') as inputFile:
            print(f"[Test] Starting stdin streaming...")

            # Start Core.py with stdin from file
            self.coreProcess = subprocess.Popen(
                coreArgs,
                cwd=workingDir,
                stdin=inputFile,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env
            )

            print(f"[Test] Process started with PID: {self.coreProcess.pid}")

        # Wait for JSON output file
        maxWaitTime = 30
        startTime = time.time()
        checkCount = 0
        while not os.path.exists(self.jsonOutputPath):
            checkCount += 1
            elapsed = time.time() - startTime

            # Check if process is still running
            processStatus = self.coreProcess.poll()
            if processStatus is not None:
                # Process has terminated
                stdout, stderr = self.coreProcess.communicate()
                print(f"[Test] Process terminated with exit code: {processStatus}")
                print(f"[Test] Process stdout/stderr output:")
                print("=" * 80)
                print(stdout if stdout else "(no output)")
                print("=" * 80)
                raise RuntimeError(
                    f"Core.py process terminated unexpectedly with exit code {processStatus}\n"
                    f"Output: {stdout[:500] if stdout else '(no output)'}"
                )

            if elapsed > maxWaitTime:
                # Capture output before raising error
                self.coreProcess.terminate()
                stdout, stderr = self.coreProcess.communicate(timeout=5)
                print(f"[Test] Timeout! Process output:")
                print("=" * 80)
                print(stdout if stdout else "(no output)")
                print("=" * 80)
                raise TimeoutError(
                    f"JSON output file not created after {maxWaitTime}s\n"
                    f"Output: {stdout[:500] if stdout else '(no output)'}"
                )

            if checkCount % 10 == 0:
                print(f"[Test] Still waiting for JSON file... ({elapsed:.1f}s elapsed)")

            time.sleep(0.5)

        print(f"[Test] JSON file created after {time.time() - startTime:.1f}s")

        # Read share info
        with open(self.jsonOutputPath, 'r') as f:
            shareInfo = json.load(f)

        shareLink = shareInfo["link"]
        print(f"[Test] Share link: {shareLink}")

        return shareLink

    def _verifyDownloadedFile(self, downloadedFilePath):
        """
        Verify that the downloaded file matches the original file
        
        Args:
            downloadedFilePath (str): Path to the downloaded file
        """
        if not os.path.exists(downloadedFilePath):
            raise AssertionError(f"Downloaded file does not exist: {downloadedFilePath}")

        # Calculate hash of downloaded file
        downloadedFileHash = getFileHash(downloadedFilePath)
        downloadedFileSize = os.path.getsize(downloadedFilePath)

        print(f"[Test] Downloaded file size: {downloadedFileSize} bytes")
        print(f"[Test] Downloaded file hash: {downloadedFileHash}")

        # Verify the file size and content match
        if downloadedFileSize != self.originalFileSize:
            raise AssertionError(
                f"Downloaded file size ({downloadedFileSize}) doesn't match original ({self.originalFileSize})"
            )
        if downloadedFileHash != self.originalFileHash:
            raise AssertionError("Downloaded file content doesn't match original")

        print("[Test] File verification successful!")

    def _getDownloadedFilePath(self, filename="downloaded.bin"):
        """Get path for downloaded file in temp directory"""
        return os.path.join(self.tempDir, filename)

    @property
    def testConfigDir(self):
        """Get the test config directory path"""
        return self._testConfigDir

    def _setupTestConfig(self):
        """Internal method to setup test configuration during setUp"""
        # Create a test config directory within the temp directory
        self._testConfigDir = os.path.join(self.tempDir, "test_config")
        self.prepareTestConfigDir(self._testConfigDir)

        # Setup environment variables
        self._originalEnvVars = self.setupTestEnvironmentVars(self._testConfigDir, self.testConfigVars)

    def _teardownTestConfig(self):
        """Internal method to teardown test configuration during tearDown"""
        if self._originalEnvVars is not None:
            self.restoreEnvironmentVars(self._originalEnvVars)
            self._originalEnvVars = None

    def prepareTestConfigDir(self, tempConfigDir):
        """
        Prepare test configuration directory with necessary files

        Args:
            tempConfigDir (str): Path to temporary config directory

        Returns:
            str: Path to the prepared config directory
        """
        # Ensure the config directory exists
        os.makedirs(tempConfigDir, exist_ok=True)

        # Import StorageLocator to find original credential file
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        try:
            from bases.Kernel import StorageLocator

            # CRITICAL: Find original credential file BEFORE setting FFL_STORAGE_LOCATION
            # Otherwise StorageLocator will return the test directory path as fallback
            # Save current FFL_STORAGE_LOCATION and temporarily clear it
            originalFflStorageLocation = os.environ.get('FFL_STORAGE_LOCATION')
            if 'FFL_STORAGE_LOCATION' in os.environ:
                del os.environ['FFL_STORAGE_LOCATION']

            try:
                # Find original .credential file with clean environment
                storageLocator = StorageLocator.getInstance()
                storageLocator.initialize('fastfilelink') # Reinitialize to clear any cached env paths
                originalCredentialPath = storageLocator.findStorage(".credential")
            finally:
                # Restore original FFL_STORAGE_LOCATION
                if originalFflStorageLocation:
                    os.environ['FFL_STORAGE_LOCATION'] = originalFflStorageLocation

            if os.path.exists(originalCredentialPath):
                # Copy .credential file to test config directory
                testCredentialPath = os.path.join(tempConfigDir, ".credential")
                shutil.copy2(originalCredentialPath, testCredentialPath)
                print(f"[Test] Copied credential file from {originalCredentialPath} to {testCredentialPath}")
            else:
                print(f"[Test] No existing credential file found at {originalCredentialPath}")

        except ImportError as e:
            print(f"[Test] Warning: Could not import StorageLocator: {e}")
        except Exception as e:
            print(f"[Test] Warning: Error copying credential file: {e}")
        finally:
            # Remove the path we added
            if sys.path[0] == os.path.join(os.path.dirname(__file__), ".."):
                sys.path.pop(0)

        return tempConfigDir

    def setupTestEnvironmentVars(self, tempConfigDir, extraVars=None):
        """
        Setup test environment variables for isolated testing
        
        Args:
            tempConfigDir (str): Path to temporary config directory
            extraVars (dict): Additional environment variables to set
            
        Returns:
            dict: Dictionary of original environment variable values for restoration
        """
        originalVars = {}

        # Set FFL_STORAGE_LOCATION to use test config directory
        originalVars['FFL_STORAGE_LOCATION'] = os.environ.get('FFL_STORAGE_LOCATION')
        os.environ['FFL_STORAGE_LOCATION'] = tempConfigDir
        print(f"[Test] Set FFL_STORAGE_LOCATION={tempConfigDir}")

        # Set additional environment variables if provided
        if extraVars:
            for key, value in extraVars.items():
                originalVars[key] = os.environ.get(key)
                os.environ[key] = str(value)
                print(f"[Test] Set {key}={value}")

        return originalVars

    def restoreEnvironmentVars(self, originalVars):
        """
        Restore original environment variables
        
        Args:
            originalVars (dict): Dictionary of original environment variable values
        """
        for key, originalValue in originalVars.items():
            if originalValue is not None:
                os.environ[key] = originalValue
            elif key in os.environ:
                del os.environ[key]
            print(f"[Test] Restored {key} to original value")

    def _setTestEnvVar(self, key, value):
        """Helper to set environment variable and return original value for restoration"""
        originalValue = os.environ.get(key)
        os.environ[key] = value
        return originalValue

    def _restoreTestEnvVar(self, key, originalValue):
        """Helper to restore environment variable to original value"""
        if originalValue is not None:
            os.environ[key] = originalValue
        elif key in os.environ:
            del os.environ[key]
