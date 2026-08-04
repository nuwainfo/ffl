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

import email as email_lib
import hashlib
import importlib
import imaplib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
import requests
import socket
import shutil

from urllib.parse import urlsplit, urlunsplit

import psutil

import addons.API as apiModule
import addons.Features as featuresModule
from bases.Kernel import EventService, Singleton
from bases.Settings import SettingsGetter


# ---------------------------
# Test server
# ---------------------------
LOCAL_TEST_SERVER_PORT = 5000
LOCAL_TEST_SERVER_URL = f'http://localhost:{LOCAL_TEST_SERVER_PORT}'

# Sentinel distinguishing "use the default cwd" from "explicitly pass cwd=None"
# (None is a legitimate value, meaning "inherit the caller's own cwd").
_UNSET = object()


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
        self._managedTestServerProcesses = []

        # Test config management - always enabled
        self.testConfigVars = testConfigVars or {}
        self._testConfigDir = None
        self._originalEnvVars = None
        self._downloadChecksumByPath = {}

    @classmethod
    def getBuiltinTunnels(cls):
        response = requests.get("https://fastfilelink.com/api/tunnels", timeout=5)
        response.raise_for_status()
        return response.json()

    def setUp(self):
        """Set up the test environment"""
        print(f"\n[Test] Running: {self.id()}")

        assert isinstance(self.tempDir, str), "tempDir must be a path string"

        # Always setup test config
        self._setupTestConfig()

        # Generate a random test file with specified size
        self.testFilePath = os.path.join(self.tempDir, "testfile.bin")
        self.generateRandomFile(self.testFilePath, self.fileSizeBytes)

        # Create paths for output JSON
        self.jsonOutputPath = os.path.join(self.tempDir, "share_info.json")

        # Calculate hash of the original file for later comparison
        self.originalFileHash = self.getFileHash(self.testFilePath)
        self.originalFileSize = os.path.getsize(self.testFilePath)

        print(f"[Test] Generated test file: {self.testFilePath}")
        print(f"[Test] File size: {self.originalFileSize} bytes ({self.originalFileSize / (1024*1024):.2f} MB)")
        print(f"[Test] File hash: {self.originalFileHash}")

    def tearDown(self):
        """Clean up after the test"""
        self._terminateProcess()
        self._stopManagedTestServers()

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

    def _registerManagedTestServer(self, testServerProcess):
        if testServerProcess:
            self._managedTestServerProcesses.append(testServerProcess)

    def _unregisterManagedTestServer(self, testServerProcess):
        if not testServerProcess:
            return

        try:
            self._managedTestServerProcesses.remove(testServerProcess)
        except ValueError:
            pass

    def _stopManagedTestServers(self):
        while self._managedTestServerProcesses:
            testServerProcess = self._managedTestServerProcesses.pop()
            try:
                self._stopTestServer(testServerProcess)
            except Exception as e:
                print(f"[Test] Warning: failed to stop managed test server: {e}")

    def _getConsoleSafeText(self, value):
        if isinstance(value, bytes):
            value = value.decode(errors='replace')
        return str(value).encode('unicode_escape').decode('ascii')

    def reloadFeatureRuntime(self):
        """Reload import-time API configuration after a test changes its environment."""
        self._resetSingletonsByModulePrefix('addons.Features', 'addons.auth')
        importlib.reload(apiModule)
        importlib.reload(featuresModule)
        self._resetSingletonsByModulePrefix('addons.Features', 'addons.auth')
        SettingsGetter.getInstance()._featureManager = None
        self._reattachFeatureManagerEvents()

    def _reattachFeatureManagerEvents(self):
        """Re-apply the eventService.attach() patches that addons.Features.load()
        installs once at addon startup.

        importlib.reload(featuresModule) rebuilds the FeatureManager class from
        scratch, so its methods are the original, unpatched versions again --
        attach() replaces a method on the class object directly (see
        EventService.attach in bases/Kernel.py), it doesn't register a
        removable subscription. Since this reload doesn't re-run any addon's
        load(), those patches are silently lost, and the corresponding
        FeatureEvent.*ClassCreate events never fire again for the rest of the
        process's life -- meaning any addon that enhances a class through one
        of these events (e.g. addons/Preview.py adding ZIP manifest/file/thumb
        routes via downloadHandlerClassCreate) silently stops working for
        every share created afterwards, regardless of what's being shared.
        Re-running the same attach() calls addons.Features.load() makes keeps
        this in sync; if load() ever attaches a new FeatureManager method,
        it must be added here too.
        """
        eventService = EventService.getInstance()
        FeatureEvent = featuresModule.FeatureEvent
        FeatureManager = featuresModule.FeatureManager
        eventService.attach(FeatureEvent.downloadHandlerClassCreate.key, FeatureManager.getDownloadHandlerClass)
        eventService.attach(FeatureEvent.webrtcManagerClassCreate.key, FeatureManager.getWebRTCManagerClass)
        eventService.attach(FeatureEvent.tunnelRunnerClassCreate.key, FeatureManager.getTunnelRunnerClass)
        eventService.attach(FeatureEvent.uidGeneratorClassCreate.key, FeatureManager.getUIDGeneratorClass)
        eventService.attach(FeatureEvent.shareRequestClassCreate.key, FeatureManager.getShareRequestClass)

    def _resetSingletonsByModulePrefix(self, *modulePrefixes):
        for singletonClass in list(Singleton._instances):
            moduleName = singletonClass.__module__
            if any(moduleName == prefix or moduleName.startswith(prefix + '.') for prefix in modulePrefixes):
                Singleton._instances.pop(singletonClass)

    @staticmethod
    def generateRandomFile(path, sizeBytes):
        """Generate a random file of the specified size"""
        with open(path, 'wb') as fileHandle:
            fileHandle.write(os.urandom(sizeBytes))

    @staticmethod
    def getFileHash(path):
        """Get the SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as fileHandle:
            for block in iter(lambda: fileHandle.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()

    @staticmethod
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

    def _terminateProcess(self):
        """Terminate the FastFileLink process gracefully"""
        if not self.coreProcess:
            return

        process = self.coreProcess
        pid = process.pid

        try:
            # Check if process is still running
            if process.poll() is None:
                print("[Test] Process is still running, sending graceful shutdown signal")
                try:
                    if sys.platform == 'win32':
                        import signal
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        import signal
                        os.kill(pid, signal.SIGINT)

                    # Give the process some time to handle the signal
                    for _i in range(5): # Wait up to 5 seconds
                        time.sleep(1)
                        if process.poll() is not None:
                            print("[Test] Process terminated after graceful shutdown signal")
                            break
                except KeyboardInterrupt:
                    print("Catched KeyboardInterrupt")
                    time.sleep(2)
                except Exception as e:
                    print(f"[Test] Failed to send graceful shutdown signal: {e}")

            if self.isProcessRunning(pid):
                self._terminateProcessTree(pid)

                try:
                    process.wait(timeout=5)
                    print("[Test] Process tree terminated")
                except subprocess.TimeoutExpired:
                    print("[Test] Process handle still active after tree termination")
                except Exception as e:
                    print(f"[Test] Failed waiting for process exit: {e}")
            else:
                print("[Test] Process already terminated")
        finally:
            for streamName in ('stdout', 'stderr', 'stdin'):
                stream = getattr(process, streamName, None)
                if stream:
                    try:
                        stream.close()
                    except Exception:
                        pass

            self.coreProcess = None

    def _terminateProcessTree(self, pid, waitTimeout=5):
        """Terminate a process and its descendants, with a hard kill fallback."""
        try:
            rootProcess = psutil.Process(pid)
            processTree = rootProcess.children(recursive=True)        
        except psutil.NoSuchProcess:
            return
        except Exception as e:
            print(f"[Test] Failed to inspect process tree for PID {pid}: {e}")
            return

        processTree.append(rootProcess)
        liveProcesses = []

        for proc in processTree:
            try:
                if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                    liveProcesses.append(proc)
            except psutil.NoSuchProcess:
                continue
            except Exception as e:
                print(f"[Test] Failed to inspect process {getattr(proc, 'pid', '?')}: {e}")

        if not liveProcesses:
            return

        for proc in reversed(liveProcesses):
            try:
                proc.terminate()
            except psutil.NoSuchProcess:
                continue
            except Exception as e:
                print(f"[Test] Failed to terminate process {proc.pid}: {e}")

        _gone, aliveProcesses = psutil.wait_procs(liveProcesses, timeout=waitTimeout)
        if not aliveProcesses:
            return

        print(f"[Test] Force killing remaining processes: {[proc.pid for proc in aliveProcesses]}")
        for proc in reversed(aliveProcesses):
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                continue
            except Exception as e:
                print(f"[Test] Failed to kill process {proc.pid}: {e}")

        _gone, aliveProcesses = psutil.wait_procs(aliveProcesses, timeout=waitTimeout)
        if aliveProcesses and sys.platform == 'win32':
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
            except Exception as e:
                print(f"[Test] taskkill fallback failed for PID {pid}: {e}")

    def _getChecksumUrl(self, shareLink):
        parsedLink = urlsplit(shareLink)
        checksumPath = parsedLink.path.rstrip('/') + '/checksum'
        return urlunsplit((parsedLink.scheme, parsedLink.netloc, checksumPath, '', ''))

    def _getB2sumCommand(self):
        if sys.platform == 'win32':
            b2sumExePath = os.path.join(os.path.dirname(__file__), "fixtures", "b2sum.exe")
            if os.path.exists(b2sumExePath):
                return b2sumExePath
            raise AssertionError(f"b2sum.exe not found at expected path: {b2sumExePath}")

        b2sumCommand = shutil.which("b2sum")
        if b2sumCommand:
            return b2sumCommand

        raise AssertionError("b2sum command not found in PATH")

    def _calculateBlake2b(self, filePath):
        b2sumCommand = self._getB2sumCommand()
        try:
            result = subprocess.run(
                [b2sumCommand, filePath],
                capture_output=True,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            raise AssertionError(f"b2sum failed for {filePath}: {e.stderr or e.stdout or e}") from e

        output = (result.stdout or "").strip()
        if not output:
            # Some Windows b2sum builds do not handle Unicode paths reliably.
            hasher = hashlib.blake2b()
            with open(filePath, 'rb') as inputFile:
                for chunk in iter(lambda: inputFile.read(1024 * 1024), b''):
                    hasher.update(chunk)
            return hasher.hexdigest().lower()

        checksum = output.split()[0].strip().lower()
        if not checksum:
            raise AssertionError(f"Failed to parse checksum from b2sum output: {output}")
        return checksum

    def _provisionLocalTestServerCredential(self):
        """Write deterministic credentials that match the localhost test server's seeded device keypair."""
        if not self._testConfigDir:
            print("[Test] Skipping localhost credential provisioning: test config directory is not initialized")
            return

        fixtureCandidates = [
            os.path.join(os.path.dirname(__file__), "fixtures", "FreeKeypair.json"),
            os.path.join(os.path.dirname(__file__), "..", "FreeKeypair.json"),
        ]
        fixturePath = next((path for path in fixtureCandidates if os.path.exists(path)), None)
        if not fixturePath:
            print(
                "[Test] Skipping localhost credential provisioning: "
                f"fixture not found in {fixtureCandidates}"
            )
            return

        repoRoot = os.path.join(os.path.dirname(__file__), "..")
        sys.path.insert(0, repoRoot)
        try:
            try:
                from addons.auth.CredentialStore import CredentialStore
                from addons.auth.Device import Device
                from bases.crypto import CryptoInterface
            except ImportError as e:
                print(f"[Test] Skipping localhost credential provisioning: auth modules unavailable ({e})")
                return

            with open(fixturePath, "r", encoding="utf-8") as fixtureFile:
                fixture = json.load(fixtureFile)

            deviceId = Device.generateId()
            publicDeviceId = hashlib.blake2b(deviceId.encode(), digest_size=16).hexdigest()

            crypto = CryptoInterface()
            clientPrivateKey = fixture["privateKey"]
            clientPublicKey = crypto.derivePublicKeyFromPrivate(clientPrivateKey)
            if not clientPublicKey:
                print("[Test] Skipping localhost credential provisioning: failed to derive public key from fixture")
                return

            credentialStore = CredentialStore(crypto, storageDir=self._testConfigDir)
            success = credentialStore.saveCredentials(
                deviceId=deviceId,
                publicDeviceId=publicDeviceId,
                email=fixture["email"],
                clientPrivateKey=clientPrivateKey,
                clientPublicKey=clientPublicKey,
                serialNumber=fixture["serialNumber"],
                serverPublicKey=fixture["serverPublicKey"]
            )
            if not success:
                print("[Test] Skipping localhost credential provisioning: failed to write credential")
                return

            print(f"[Test] Provisioned localhost test credential at {credentialStore.credentialFilePath}")
        finally:
            if sys.path and sys.path[0] == repoRoot:
                sys.path.pop(0)

    def _fetchChecksumData(self, shareLink, requireReady=True, retries=10, retryInterval=0.2):
        checksumUrl = self._getChecksumUrl(shareLink)
        lastResponseData = None
        lastStatusCode = None

        for attemptIndex in range(retries):
            response = requests.get(checksumUrl, timeout=30)
            lastStatusCode = response.status_code
            if response.status_code != 200:
                if attemptIndex + 1 < retries:
                    time.sleep(retryInterval)
                    continue
                raise AssertionError(f"Checksum endpoint should return 200, got {response.status_code}")

            responseData = response.json()
            lastResponseData = responseData
            if not requireReady or responseData.get('ready'):
                return responseData

            if attemptIndex + 1 < retries:
                time.sleep(retryInterval)

        if requireReady:
            raise AssertionError(f"Checksum should be ready, got {lastResponseData}")
        return lastResponseData if lastResponseData is not None else {'ready': False}

    def _generateKeypair(self, name='recipient', share=False, extraArgs=None, preferredTunnel=None):
        """Generate a keypair via the CLI keypair subcommand.

        Returns (privKeyPath, pubKeyPath) as absolute paths in tempDir.
        When share=True, returns (privKeyPath, pubKeyPath, shareLink).
        """
        basePath = os.path.join(self.tempDir, name)
        privKeyPath = f"{basePath}.fflkey"
        pubKeyPath = f"{basePath}.fflpub"
        keygenArgs = ["--cli", "keygen", "--name", basePath]
        if extraArgs:
            keygenArgs.extend(extraArgs)

        if not share:
            output, returnCode = self._runCoreCommand(
                keygenArgs,
                disableGuiAddon=False,
                timeout=30,
            )
            self.assertEqual(returnCode, 0, f"keypair command failed:\n{output}")
            self.assertTrue(os.path.exists(privKeyPath), f"Private key file not created: {privKeyPath}")
            self.assertTrue(os.path.exists(pubKeyPath), f"Public key file not created: {pubKeyPath}")
            return privKeyPath, pubKeyPath

        if extraArgs and '--preferred-tunnel' in extraArgs and preferredTunnel is not None:
            raise AssertionError("Use preferredTunnel=... instead of passing --preferred-tunnel in extraArgs")

        if preferredTunnel is not None:
            keygenArgs.extend(["--preferred-tunnel", preferredTunnel])

        keygenArgs.extend(["--share", "--json", self.jsonOutputPath])
        self._procLogFile = open(self.procLogPath, "w", encoding="utf-8", errors="replace")
        creationFlags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
        self.coreProcess = self._runCoreCommand(
            keygenArgs,
            extraEnvVars={"PYTHONIOENCODING": "utf-8"},
            disableGuiAddon=False,
            outputTarget=self._procLogFile,
            wait=False,
            creationFlags=creationFlags,
        )

        startTime = time.time()
        while time.time() - startTime < 60:
            if os.path.exists(self.jsonOutputPath):
                break

            if self.coreProcess.poll() is not None:
                self._procLogFile.flush()
                with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as f:
                    output = f.read()
                raise AssertionError(
                    f"keypair --share exited early (code {self.coreProcess.returncode}):\n{output}"
                )
            time.sleep(0.5)

        self.assertTrue(os.path.exists(self.jsonOutputPath), "keypair --share did not create JSON output")
        self.assertTrue(os.path.exists(privKeyPath), f"Private key file not created: {privKeyPath}")
        self.assertTrue(os.path.exists(pubKeyPath), f"Public key file not created: {pubKeyPath}")
        with open(self.jsonOutputPath, 'r', encoding='utf-8') as f:
            shareInfo = json.load(f)
        return privKeyPath, pubKeyPath, shareInfo['link']

    def downloadFileWithRequests(self, shareLink, outputPath, expectedFileName=None, headers=None, expectedStatus=200, auth=None):
        """
        Download file using requests library with retry logic

        Args:
            shareLink: URL to download from
            outputPath: Local path to save downloaded file
            expectedFileName: If provided, verify Content-Disposition header matches this filename
            headers: Optional request headers (e.g., Range)
            expectedStatus: Expected HTTP status code
            auth: Optional requests auth tuple, e.g. ('user', 'password')

        Returns:
            str: Incremental blake2b checksum of received bytes
        """
        print("[Test] Attempting to download file through share link...")

        maxAttempts = self._getDownloadRetryCount(shareLink)
        retryDelaySeconds = self._getDownloadRetryDelaySeconds(shareLink)

        # Try multiple times in case it takes a while for the link or DNS to become active
        for attempt in range(maxAttempts):
            try:
                print(f"[Test] Download attempt {attempt + 1}")
                with requests.get(shareLink, headers=headers or {}, auth=auth, stream=True, timeout=30) as response:
                    if response.status_code == expectedStatus:
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

                        transferHasher = hashlib.blake2b()
                        with open(outputPath, 'wb') as outputFile:
                            for chunk in response.iter_content(chunk_size=65536):
                                if not chunk:
                                    continue
                                transferHasher.update(chunk)
                                outputFile.write(chunk)

                        transferChecksum = transferHasher.hexdigest()
                        print(f"[Test] File downloaded successfully to {outputPath}")
                        print(f"[Test] Transfer checksum (blake2b): {transferChecksum}")

                        if expectedStatus == 200:
                            self._downloadChecksumByPath[os.path.abspath(outputPath)] = {
                                'shareLink': shareLink,
                                'transferChecksum': transferChecksum
                            }
                        return transferChecksum
                    else:
                        print(f"[Test] Received status code: {response.status_code}")
            except Exception as e:
                print(f"[Test] Download attempt failed: {e}")
            time.sleep(retryDelaySeconds)

        raise AssertionError("Failed to download file through share link")

    def _getDownloadRetryCount(self, shareLink):
        hostname = (urlsplit(shareLink).hostname or '').lower()
        if hostname.endswith('.trycloudflare.com'):
            return 15
            
        return 3

    def _getDownloadRetryDelaySeconds(self, shareLink):
        hostname = (urlsplit(shareLink).hostname or '').lower()
        if hostname.endswith('.trycloudflare.com'):
            return 4
            
        return 2

    def _downloadWithCore(
        self,
        shareLink,
        outputPath=None,
        extraArgs=None,
        extraEnvVars=None,
        captureOutputIn=None,
        stdoutMode=False
    ):
        """
        Download file using FFL.py directly

        Args:
            shareLink (str): The share link to download from
            outputPath (str, optional): Output path for downloaded file
            extraArgs (list, optional): Additional command line arguments
            extraEnvVars (dict, optional): Additional environment variables
            captureOutputIn (dict, optional): Dictionary to capture process output
            stdoutMode (bool): If True, pass `--stdout` and return file bytes plus
                stderr text instead of saving to a file.

        Returns:
            str: Path to the downloaded file when stdoutMode=False
            tuple[bytes, str]: Raw stdout bytes and decoded stderr text when stdoutMode=True
        """
        print(f"[Test] Downloading file using FFL.py from: {shareLink}")
        if stdoutMode and outputPath:
            raise AssertionError("outputPath cannot be used with stdoutMode=True")

        # Build download args: --cli [globalArgs] <shareLink> [downloadSpecificArgs] [-o outputPath]
        downloadArgs = ["--cli"]

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
        elif stdoutMode:
            downloadArgs.append("--stdout")

        logPath = None
        if captureOutputIn is not None:
            logPath = os.path.join(self.tempDir, "download_log.txt")
            captureOutputIn["logPath"] = logPath
            captureOutputIn["logFile"] = None

        maxAttempts = self._getDownloadRetryCount(shareLink)
        retryDelaySeconds = self._getDownloadRetryDelaySeconds(shareLink)
        lastErrorMessage = None

        for attempt in range(maxAttempts):
            logFile = None
            output = ''
            returnCode = 0

            if logPath and not stdoutMode:
                logFile = open(logPath, "w", encoding="utf-8", errors="replace")
                captureOutputIn["logFile"] = logFile

            try:
                if stdoutMode:
                    command = self._buildCoreCommand(downloadArgs)
                    downloadEnv = self._buildCoreEnv(extraEnvVars=extraEnvVars)
                    downloadProcess = subprocess.Popen(
                        command,
                        cwd=self._projectRootDir(),
                        env=downloadEnv,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    try:
                        rawBytes, stderrOutput = downloadProcess.communicate(timeout=120)
                    except subprocess.TimeoutExpired:
                        downloadProcess.kill()
                        raise AssertionError("Stdout download process timed out")

                    output = stderrOutput.decode(errors='replace')
                    returnCode = downloadProcess.returncode
                else:
                    output, returnCode = self._runCoreCommand(
                        downloadArgs,
                        extraEnvVars=extraEnvVars,
                        timeout=120,
                        outputTarget=logFile,
                    )
            finally:
                if logFile and not logFile.closed:
                    logFile.close()
                    
                if captureOutputIn is not None:
                    captureOutputIn["logFile"] = None

            if logPath and stdoutMode:
                with open(logPath, "w", encoding="utf-8", errors="replace") as f:
                    f.write(output)

            if returnCode == 0:
                print("[Test] Download completed successfully")
                if stdoutMode:
                    print(f"[Test] Stderr output:\n{self._getConsoleSafeText(stderrOutput)}")
                    return rawBytes, output

                if logPath:
                    with open(logPath, 'r', encoding='utf-8', errors='replace') as f:
                        output = f.read()
                        
                downloadedPath = self._extractDownloadedPath(output, outputPath)
                if not os.path.exists(downloadedPath):
                    raise AssertionError(f"Downloaded file not found at expected path: {downloadedPath}")
                    
                print(f"[Test] Downloaded file saved to: {downloadedPath}")
                return downloadedPath

            errorMessage = f"Download process failed with exit code {returnCode}"
            
            if logPath:
                try:
                    with open(logPath, 'r', encoding='utf-8', errors='replace') as f:
                        fileOutput = f.read()
                        if fileOutput:
                            errorMessage += f"\n--- Full Client Output ---\n{fileOutput}\n--- End Output ---"
                except Exception as e:
                    errorMessage += f"\n(Failed to read log file: {e})"
            elif output:
                errorMessage += f"\nOutput: {output}"

            lastErrorMessage = errorMessage
            if attempt + 1 < maxAttempts and self._isRetryableTryCloudflareFailure(shareLink, errorMessage):
                print(f"[Test] Core download attempt {attempt + 1} failed during tunnel DNS warmup, retrying...")
                time.sleep(retryDelaySeconds)
                continue

            raise AssertionError(errorMessage)

        raise AssertionError(lastErrorMessage or "Download process failed")

    def _extractDownloadedPath(self, output, outputPath):
        downloadedPath = None
        for line in output.split('\n'):
            if "Downloaded:" in line:
                downloadedPath = line.split(":", 1)[1].strip()
                break
                
        if downloadedPath:
            return downloadedPath
            
        if outputPath and not os.path.isdir(outputPath):
            return outputPath
            
        return os.path.join(os.getcwd(), "downloaded_file")

    def _isRetryableTryCloudflareFailure(self, shareLink, errorMessage):
        hostname = (urlsplit(shareLink).hostname or '').lower()
        if not hostname.endswith('.trycloudflare.com'):
            return False
            
        loweredMessage = str(errorMessage or '').lower()
        return 'failed to resolve' in loweredMessage or 'getaddrinfo failed' in loweredMessage

    # -----------------------------------------------------------------
    # Shared FFL CLI process runner
    # -----------------------------------------------------------------
    # _runCoreCommand() is the one place that knows how to build the command
    # line / environment and launch FFL.py (or an external FFL binary).
    # _downloadWithCore() (the `download` subcommand) and _startFastFileLink()
    # (the `share` subcommand) both delegate to it, adding only their own
    # command-specific argument placement and result parsing on top.

    def _buildTestCommandArgs(self, args):
        commandArgs = list(args)
        isShareCommand = (
            (len(commandArgs) >= 1 and commandArgs[0] == 'share')
            or (len(commandArgs) >= 2 and commandArgs[0] == '--cli' and commandArgs[1] == 'share')
        )

        if isShareCommand and '--disable-clipboard' not in commandArgs:
            commandArgs.append('--disable-clipboard')

        return commandArgs

    def _buildCoreCommand(self, args, commandPrefix=None):
        """Build the full command line: a prefix (default: `python FFL.py`) plus args."""
        prefix = list(commandPrefix) if commandPrefix else [sys.executable, "FFL.py"]
        return prefix + self._buildTestCommandArgs(args)

    def _buildCoreEnv(self, extraEnvVars=None, disableGuiAddon=True):
        """Build the environment dict for launching an FFL CLI subprocess."""
        return self._augmentSubprocessEnv(os.environ.copy(), extraEnvVars, disableGuiAddon)

    def _augmentSubprocessEnv(self, env, extraEnvVars=None, disableGuiAddon=False):
        """Apply shared subprocess environment settings for test child processes."""
        env = dict(env)
        env['PYTHONIOENCODING'] = 'utf-8'
        if sys.platform.startswith('win'):
            env['PYTHONUTF8'] = '1'

        if disableGuiAddon:
            env['DISABLE_ADDONS'] = 'GUI'

        if extraEnvVars:
            for key, value in extraEnvVars.items():
                env[key] = str(value)

        return env

    def _projectRootDir(self):
        """Absolute path to the project root (where FFL.py lives)."""
        return os.path.dirname(os.path.abspath(__file__ + "/.."))

    def _startSubprocess(
        self,
        command,
        extraEnvVars=None,
        env=None,
        cwd=_UNSET,
        stdin=None,
        stdout=None,
        stderr=None,
        text=True,
        bufsize=1,
        creationFlags=0,
        shell=False,
        disableGuiAddon=False,
        **kwargs,
    ):
        """Start a non-core subprocess using the shared test environment defaults."""
        runCwd = self._projectRootDir() if cwd is _UNSET else cwd
        childEnv = self._augmentSubprocessEnv(env or os.environ.copy(), extraEnvVars, disableGuiAddon)
        return subprocess.Popen(
            command,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            text=text,
            bufsize=bufsize,
            creationflags=creationFlags,
            shell=shell,
            env=childEnv,
            cwd=runCwd,
            **kwargs,
        )

    def _runCoreCommand(
        self,
        args,
        commandPrefix=None,
        extraEnvVars=None,
        disableGuiAddon=True,
        cwd=_UNSET,
        timeout=30,
        stdin=None,
        inputData=None,
        outputTarget=None,
        passthrough=False,
        wait=True,
        bufsize=1,
        creationFlags=0,
    ):
        """
        Build an FFL command line + environment and launch it.

        This is the shared low-level primitive behind:
          - _downloadWithCore (the `download` subcommand): wait=True, parses the
            "Downloaded:" line from the captured output.
          - _startFastFileLink (the `share` subcommand): wait=False, since the
            process is a long-running server that must be polled for a JSON
            marker file while it keeps running, rather than waited on.
          - One-shot subcommands (`shell`, `keygen`, `--version`, ...): the
            wait=True default returns (output, returncode) directly.

        Args:
            args (list): CLI arguments appended after the command prefix
            commandPrefix (list, optional): Override for [sys.executable, "FFL.py"]
                (e.g. an external binary like ["./ffl.com"])
            extraEnvVars (dict, optional): Additional/overriding environment variables
            disableGuiAddon (bool): Set DISABLE_ADDONS=GUI. Most one-shot
                subcommands want this; `download`/`share` don't need it since
                `--cli` already forces CLI mode.
            cwd (str, optional): Working directory; defaults to the project root.
                Pass explicit None to inherit the caller's own working directory.
            timeout (int): Seconds to wait when wait=True
            stdin: Optional file handle to pipe into stdin
            inputData (str, optional): Text passed to process.communicate() when
                wait=True, for interactive one-shot commands.
            outputTarget: Optional open file object to redirect combined
                stdout+stderr into, instead of capturing via pipe (avoids
                pipe-buffer deadlocks for long-running/large-output processes)
            passthrough (bool): Let stdout/stderr inherit the parent console
                instead of being captured at all (only meaningful with wait=False)
            wait (bool): If True, block until the process exits and return
                (output, returncode). If False, return the started
                subprocess.Popen immediately so the caller can poll/manage a
                long-running process itself.
            bufsize, creationFlags: Passed through to subprocess.Popen

        Returns:
            (output, returncode) if wait=True, otherwise the live subprocess.Popen.
        """
        command = self._buildCoreCommand(args, commandPrefix)
        env = self._buildCoreEnv(extraEnvVars, disableGuiAddon)
        runCwd = self._projectRootDir() if cwd is _UNSET else cwd

        try:
            print(f"[Test] Running command: {' '.join(command)}")
        except UnicodeEncodeError:
            print("[Test] Running command: <contains unicode characters>")

        popenKwargs = dict(stdin=stdin, env=env, cwd=runCwd, text=True, bufsize=bufsize, creationflags=creationFlags)
        if passthrough:
            popenKwargs['universal_newlines'] = True
        else:
            popenKwargs.update(
                stdout=outputTarget or subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding='utf-8',
                errors='replace',
            )

        process = subprocess.Popen(command, **popenKwargs)

        if not wait:
            return process

        try:
            stdout, _ = process.communicate(input=inputData, timeout=timeout)
            return stdout or "", process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return "Process timed out", 1
        finally:
            if process.stdin:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

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

    def _startTestServer(self, extraEnvVars=None, captureOutput=False):
        """Start the test server for upload testing"""
        try:
            testServerScript = "TestServer.py"
            testServerPath = os.path.join(os.path.dirname(__file__), testServerScript)

            if not os.path.exists(testServerPath):
                raise AssertionError(f"{testServerScript} not found. Please ensure it's in the same directory.")

            print(f"[Test] Starting test server: {testServerPath}")

            # Check if port is already in use
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', LOCAL_TEST_SERVER_PORT))
            sock.close()

            if result == 0:
                print(f"[Test] Port {LOCAL_TEST_SERVER_PORT} is already in use, attempting to kill the process...")

                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == LOCAL_TEST_SERVER_PORT and conn.status == psutil.CONN_LISTEN:
                        try:
                            proc = psutil.Process(conn.pid)
                            print(f"[Test] Killing process on port {LOCAL_TEST_SERVER_PORT}: PID {conn.pid} ({proc.name()})")
                            proc.terminate()
                            proc.wait(timeout=3)
                        except Exception as e:
                            print(f"[Test] Failed to kill process {conn.pid}: {e}")
                time.sleep(1) # Give the system a moment to release the port

            # Prepare environment with UTF-8 encoding
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8' # Force UTF-8 encoding for Python I/O
            env['PYTHONUNBUFFERED'] = '1'
            if sys.platform.startswith('win'):
                env['PYTHONUTF8'] = '1' # Enable UTF-8 mode on Windows (Python 3.7+)
                
            if extraEnvVars:
                for key, value in extraEnvVars.items():
                    env[key] = str(value)

            # Get the directory where TestServer.py is located
            testServerDir = os.path.dirname(testServerPath)

            testServerLogFile = None
            testServerLogPath = None
            popenStdout = subprocess.PIPE if captureOutput else None
            popenStderr = subprocess.PIPE if captureOutput else None

            if not captureOutput:
                testServerLogPath = os.path.join(self.tempDir, "test_server.log")
                testServerLogFile = open(testServerLogPath, "w+", encoding="utf-8", buffering=1)
                popenStdout = testServerLogFile
                popenStderr = testServerLogFile

            # Start test server process with UTF-8 environment and correct working directory
            testServerProcess = subprocess.Popen(
                [sys.executable, testServerScript, "--host", "localhost", "--port", str(LOCAL_TEST_SERVER_PORT)],
                stdout=popenStdout,
                stderr=popenStderr,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace',
                env=env, # Use UTF-8 environment
                cwd=testServerDir # Set working directory to TestServer.py location
            )
            testServerProcess._logFile = testServerLogFile
            testServerProcess._logPath = testServerLogPath

            # Wait for server to start (check if port is available)
            startTime = time.time()
            serverReady = False

            while time.time() - startTime < 15: # Increase timeout to 15 seconds
                # Check if process has terminated
                if testServerProcess.poll() is not None:
                    if captureOutput:
                        stdout, stderr = testServerProcess.communicate()
                    else:
                        stdout = stderr = ""
                        if testServerLogFile:
                            testServerLogFile.flush()
                        if testServerLogPath and os.path.exists(testServerLogPath):
                            with open(testServerLogPath, "r", encoding="utf-8", errors="replace") as f:
                                stdout = f.read()
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
                    result = sock.connect_ex(('localhost', LOCAL_TEST_SERVER_PORT))
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
                    if captureOutput:
                        stdout, stderr = testServerProcess.communicate(timeout=5)
                    else:
                        stdout = stderr = ""
                        if testServerLogFile:
                            testServerLogFile.flush()
                        if testServerLogPath and os.path.exists(testServerLogPath):
                            with open(testServerLogPath, "r", encoding="utf-8", errors="replace") as f:
                                stdout = f.read()
                else:
                    if captureOutput:
                        stdout, stderr = testServerProcess.communicate()
                    else:
                        stdout = stderr = ""
                        if testServerLogFile:
                            testServerLogFile.flush()
                        if testServerLogPath and os.path.exists(testServerLogPath):
                            with open(testServerLogPath, "r", encoding="utf-8", errors="replace") as f:
                                stdout = f.read()

                print(f"[Test] Test server failed to start within 15 seconds")
                if stdout:
                    print(f"[Test] Test server stdout:\n{stdout[:1000]}...")
                if stderr:
                    print(f"[Test] Test server stderr:\n{stderr[:1000]}...")
                raise AssertionError("Test server failed to start within 15 seconds")

            print(f"[Test] Test server started successfully on {LOCAL_TEST_SERVER_URL}")
            return testServerProcess

        except Exception as e:
            print(f"[Test] Failed to start test server: {e}")
            raise

    def _canReuseRunningTestServer(self):
        try:
            from bases.Kernel import PUBLIC_VERSION

            response = requests.get(f'{LOCAL_TEST_SERVER_URL}/version', params={'format': 'json'}, timeout=3)
            response.raise_for_status()
            data = response.json()
            version = data.get('version')
            if version == PUBLIC_VERSION:
                print(f"[Test] Reusing existing test server at {LOCAL_TEST_SERVER_URL} (version {version})")
                return True

            print(
                f"[Test] Existing server at {LOCAL_TEST_SERVER_URL} has version {version}, "
                f"expected {PUBLIC_VERSION}; starting managed test server instead"
            )
            return False
        except Exception as e:
            print(f"[Test] Existing server at {LOCAL_TEST_SERVER_URL} is not reusable: {e}")
            return False

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
        finally:
            if testServerProcess:
                if testServerProcess.stdin:
                    testServerProcess.stdin.close()
                if testServerProcess.stdout:
                    testServerProcess.stdout.close()
                if testServerProcess.stderr:
                    testServerProcess.stderr.close()
                logFile = getattr(testServerProcess, '_logFile', None)
                if logFile:
                    logFile.close()

    def _normalizeCommandSpec(self, commandSpec):
        """Normalize command spec into argv list."""
        if commandSpec is None:
            return None

        if isinstance(commandSpec, (list, tuple)):
            return [str(part) for part in commandSpec]

        if isinstance(commandSpec, str):
            posixMode = not sys.platform.startswith('win')
            return shlex.split(commandSpec, posix=posixMode)

        raise TypeError(f"Unsupported command spec type: {type(commandSpec).__name__}")

    def _adaptExternalCommandForPlatform(self, commandPrefix):
        """Adjust external command prefixes for platform-specific launcher requirements."""
        if not commandPrefix:
            return commandPrefix

        if sys.platform.startswith('win'):
            return commandPrefix

        launcher = os.path.basename(commandPrefix[0]).lower()
        if launcher in ('bash', 'sh'):
            return commandPrefix

        if commandPrefix[0].lower().endswith('.com'):
            return ['bash', *commandPrefix]

        return commandPrefix

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
        waitForCompletion=True,
        binaryCommand=None,
        stdinInputPath=None,
        stdinFileName=None,
        preferredTunnel='default',
        workingDirectory=None,
        serverTimeout=None,
        inputData=None,
        autoConfirmUpload=True,
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
            binaryCommand (str|list): Optional external command prefix, e.g. "./ffl.com" or "python FFL.py --cli"
            stdinInputPath (str): Optional path to pipe into stdin instead of sharing self.testFilePath directly
            stdinFileName (str): Optional filename to advertise when stdinInputPath is used
            preferredTunnel (str|None): Preferred tunnel passed via `--preferred-tunnel`.
                Defaults to `default`; pass None to omit the flag entirely.
            workingDirectory (str): Optional working directory for the launched sharing process
            serverTimeout (int): Optional `share --timeout` guard. When omitted, tests
                get a finite timeout so abandoned share processes cannot live forever.
            inputData (str): Optional interactive input passed to the share process.
            autoConfirmUpload (bool): Add `--yes` automatically for upload-mode shares.

        Returns:
            str | None: share link when waiting for completion; otherwise None
        """
        # Start test server if requested
        testServerProcess = None
        if useTestServer:
            self._provisionLocalTestServerCredential()
            if not self._canReuseRunningTestServer():
                testServerProcess = self._startTestServer()
                self._registerManagedTestServer(testServerProcess)

        try:
            if self._procLogFile:
                try:
                    self._procLogFile.close()
                except Exception:
                    pass
                self._procLogFile = None

            useNetworkSimulation = networkFailureRate > 0.0
            modeDesc = "with network simulation" if useNetworkSimulation else "normal mode"
            serverDesc = " + test server" if useTestServer else ""

            commandPrefix = None
            runnerLabel = None
            if binaryCommand:
                if useNetworkSimulation:
                    raise AssertionError("networkFailureRate simulation is only supported with the patched Python runner")
                    
                commandPrefix = self._normalizeCommandSpec(binaryCommand)
                if not commandPrefix:
                    raise AssertionError("binaryCommand resolved to an empty command")
                    
                commandPrefix = self._adaptExternalCommandForPlatform(commandPrefix)
                runnerLabel = " ".join(commandPrefix)
            else:
                coreScript = "CorePatched.py" # Always use CorePatched.py now
                coreScriptPath = os.path.join(os.path.dirname(__file__), coreScript)
                if not os.path.exists(coreScriptPath):
                    raise AssertionError(f"{coreScript} not found. Please ensure it's in the same directory.")
                    
                commandPrefix = [sys.executable, coreScriptPath, "--cli"]
                runnerLabel = coreScript

            print(f"[Test] Starting FastFileLink in CLI mode using {runnerLabel} ({modeDesc}{serverDesc})...")
            if useNetworkSimulation:
                print(
                    f"[Test] Network simulation: {networkFailureRate * 100:.1f}% failure rate, max {maxConsecutiveFailures} consecutive failures"
                )
            print(f"[Test] Mode: {'P2P' if p2p else 'Server'}")

            # Prepare the args - use 'share' subcommand for file sharing
            # (commandPrefix is prepended by _runCoreCommand)
            sourcePath = "-" if stdinInputPath else self.testFilePath
            coreArgs = ["share", sourcePath, "--json", self.jsonOutputPath]
            if stdinInputPath and stdinFileName:
                coreArgs.extend(["--name", stdinFileName])

            # Add network instability parameters if needed
            if useNetworkSimulation:
                coreArgs.extend([
                    "--network-failure-rate",
                    str(networkFailureRate),
                    "--max-consecutive-failures",
                    str(maxConsecutiveFailures),
                ])

            # Use debug logging tests to help diagnose issues
            if os.getenv("TEST_CASE_DEBUG") == "True":
                coreArgs.extend([
                    "--log-level",
                    os.path.join(os.path.dirname(__file__), "presets", "TestCaseDebugLogging.json")
                ])

            # Add mode-specific parameters
            if not p2p:
                coreArgs.extend(["--upload", "3 hours"])
                if autoConfirmUpload:
                    coreArgs.append("--yes")

            if extraArgs and '--preferred-tunnel' in extraArgs and preferredTunnel is not None:
                raise AssertionError("Use preferredTunnel=... instead of passing --preferred-tunnel in extraArgs")

            if preferredTunnel is not None:
                coreArgs.extend(["--preferred-tunnel", preferredTunnel])

            # Add extra arguments if provided
            if extraArgs:
                coreArgs.extend(extraArgs)

            hasExplicitServerTimeout = '--timeout' in coreArgs
            if not hasExplicitServerTimeout:
                effectiveServerTimeout = serverTimeout if serverTimeout is not None else 180
                coreArgs.extend(["--timeout", str(effectiveServerTimeout)])

            if showOutput:
                print(f"[Test] Real-time output enabled - you will see live progress...")

            # Build the environment overrides specific to this long-running share/upload process
            # (PYTHONUNBUFFERED for prompt output, Xvfb DISPLAY auto-detection on Linux, the test
            # server URL, and finally the caller's own extraEnvVars, which can override any of these)
            mergedEnvVars = {'PYTHONUNBUFFERED': '1'}

            # Auto-detect Xvfb display for wx support on Linux (when DISPLAY not already set)
            if sys.platform.startswith('linux') and 'DISPLAY' not in os.environ:
                import glob as _glob
                for xLock in sorted(_glob.glob('/tmp/.X*-lock')):
                    displayNum = xLock.replace('/tmp/.X', '').replace('-lock', '')
                    mergedEnvVars['DISPLAY'] = f':{displayNum}'
                    break

            # Add test server environment variable if using test server
            if useTestServer:
                mergedEnvVars['FILESHARE_TEST'] = LOCAL_TEST_SERVER_URL
                print(f"[Test] Using test server: FILESHARE_TEST={LOCAL_TEST_SERVER_URL}")

            # Add extra environment variables if provided
            if extraEnvVars:
                for key, value in extraEnvVars.items():
                    mergedEnvVars[key] = str(value)
                    # Test diagnostics must never disclose credentials copied
                    # from the caller's environment.
                    safeValue = '[redacted]' if any(marker in key.upper() for marker in ('SECRET', 'PASSWORD', 'TOKEN', 'KEY')) else value
                    print(f"[Test] Extra env var: {key}={safeValue}")

            if not showOutput:
                # File-based output: redirect stdout/stderr to log file to avoid pipe buffer deadlock
                self._procLogFile = open(self.procLogPath, "w+", encoding="utf-8", buffering=1)

            # Launch in a separate process with conditional output capture.
            # Keep GUI addon disabled explicitly for CLI test subprocesses to avoid
            # GUI/WebView side effects leaking into unattended test runs.
            # wait=False: this is a long-running server process, polled below for the JSON
            # marker file rather than waited on for completion.
            creationFlags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            stdinFileHandle = open(stdinInputPath, 'rb') if stdinInputPath else None
            stdinHandle = subprocess.PIPE if inputData is not None else stdinFileHandle
            try:
                self.coreProcess = self._runCoreCommand(
                    coreArgs,
                    commandPrefix=commandPrefix,
                    extraEnvVars=mergedEnvVars,
                    disableGuiAddon=True,
                    cwd=workingDirectory,
                    stdin=stdinHandle,
                    inputData=inputData,
                    outputTarget=None if showOutput else self._procLogFile,
                    passthrough=showOutput,
                    wait=False,
                    creationFlags=creationFlags,
                )
            finally:
                if stdinFileHandle:
                    stdinFileHandle.close()

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

            if inputData is not None and self.coreProcess.stdin:
                self.coreProcess.stdin.write(inputData)
                self.coreProcess.stdin.flush()
                self.coreProcess.stdin.close()

            # Setup output capture context immediately after process start
            # This ensures captureOutputIn is populated even if JSON wait fails
            if captureOutputIn is not None:
                captureOutputIn['_process'] = self.coreProcess
                captureOutputIn['_logPath'] = self.procLogPath
                captureOutputIn['_logFile'] = self._procLogFile

            # Early return if not waiting for completion
            if not waitForCompletion:
                print("[Test] Process started, not waiting for completion")
                return None

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

            # Re-check for JSON after loop exit (handles race where process writes JSON and exits immediately)
            if not jsonFileCreated and os.path.exists(self.jsonOutputPath):
                jsonFileCreated = True

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
                            # Encode-safe print for consoles that can't handle all unicode (e.g., cp950)
                            safeContent = logContent.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8', errors='replace')
                            print(f"[Test] Process combined log:\n{safeContent}")
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
                            # Look for debug file in the working directory where FFL.py runs
                            appDebugFile = "fastfilelink_test_debug.log"
                            appDebugPaths = [
                                appDebugFile, # Current working directory
                                os.path.join(os.getcwd(), appDebugFile), # Explicit current dir
                                os.path.join(os.path.dirname(__file__), "..", appDebugFile), # FFL.py directory
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
            if stdinInputPath is None and self.originalFileSize != -1 and shareInfo["file_size"] != self.originalFileSize:
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

            # Update captured output with latest content (captureOutputIn was set up earlier)
            if captureOutputIn is not None:
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

            return shareLink

        except Exception as e:
            if testServerProcess:
                self._unregisterManagedTestServer(testServerProcess)
                self._stopTestServer(testServerProcess)
            raise

    def _verifyDownloadedFile(self, downloadedFilePath, shareLink=None, transferChecksum=None, verifyOriginalContent=True):
        """
        Verify that the downloaded file matches the original file
        
        Args:
            downloadedFilePath (str): Path to the downloaded file
            shareLink (str): Optional FastFileLink share URL for /checksum verification
            transferChecksum (str): Optional incremental checksum returned from downloadFileWithRequests
            verifyOriginalContent (bool): Whether to verify file matches original source file
        """
        if not os.path.exists(downloadedFilePath):
            raise AssertionError(f"Downloaded file does not exist: {downloadedFilePath}")

        # Calculate hash of downloaded file
        downloadedFileHash = self.getFileHash(downloadedFilePath)
        downloadedFileSize = os.path.getsize(downloadedFilePath)
        downloadedBlake2b = self._calculateBlake2b(downloadedFilePath)

        print(f"[Test] Downloaded file size: {downloadedFileSize} bytes")
        print(f"[Test] Downloaded file hash: {downloadedFileHash}")
        print(f"[Test] Downloaded file checksum (blake2b): {downloadedBlake2b}")

        rememberedDownload = self._downloadChecksumByPath.get(os.path.abspath(downloadedFilePath))
        if rememberedDownload:
            if not transferChecksum:
                transferChecksum = rememberedDownload.get('transferChecksum')

        # Verify the file size and content match
        if verifyOriginalContent:
            if downloadedFileSize != self.originalFileSize:
                raise AssertionError(
                    f"Downloaded file size ({downloadedFileSize}) doesn't match original ({self.originalFileSize})"
                )
            if downloadedFileHash != self.originalFileHash:
                raise AssertionError("Downloaded file content doesn't match original")

        if transferChecksum:
            transferChecksum = transferChecksum.lower()
            if transferChecksum != downloadedBlake2b.lower():
                raise AssertionError(
                    f"Returned transfer checksum ({transferChecksum}) should equal full file checksum ({downloadedBlake2b})"
                )

        if shareLink:
            checksumData = self._fetchChecksumData(shareLink, requireReady=True)
            remoteChecksum = checksumData.get('checksum')
            if not remoteChecksum:
                raise AssertionError(f"Checksum endpoint should include checksum: {checksumData}")

            remoteChecksum = remoteChecksum.lower()
            if transferChecksum:
                if transferChecksum != remoteChecksum:
                    raise AssertionError(
                        f"downloadFileWithRequests checksum ({transferChecksum}) should equal /checksum ({remoteChecksum})"
                    )

            if downloadedBlake2b.lower() != remoteChecksum:
                raise AssertionError(
                    f"Full file checksum ({downloadedBlake2b}) should equal /checksum ({remoteChecksum})"
                )

            remoteSize = checksumData.get('size')
            if isinstance(remoteSize, int) and remoteSize >= 0 and remoteSize != downloadedFileSize:
                raise AssertionError(
                    f"Checksum endpoint size ({remoteSize}) should equal downloaded size ({downloadedFileSize})"
                )

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


# ---------------------------
# IMAP test helpers
# ---------------------------
class IMAPTestMixin:
    """Mixin for tests that need to read email via IMAP.

    Subclasses must set before use:
        self.IMAP_EMAIL    — the mailbox login address
        self.IMAP_HOST     — IMAP server hostname
        self.IMAP_PORT     — IMAP port (default: 993)
        self.IMAP_PASSWORD — IMAP account password
    """

    IMAP_EMAIL = None
    IMAP_HOST = None
    IMAP_PORT = 993
    IMAP_PASSWORD = None

    def _connectIMAP(self):
        """Return an authenticated, INBOX-selected IMAP4_SSL connection."""
        imap = imaplib.IMAP4_SSL(self.IMAP_HOST, self.IMAP_PORT)
        imap.login(self.IMAP_EMAIL, self.IMAP_PASSWORD)
        imap.select('INBOX')
        return imap

    @staticmethod
    def _extractBody(msg):
        """Return the plain-text body of an email.Message object."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    return part.get_payload(decode=True).decode(errors='replace')
            return ''
        return msg.get_payload(decode=True).decode(errors='replace')

    def _deleteEmailsBySubject(self, subjectKeyword):
        """Delete all inbox messages whose subject contains *subjectKeyword*."""
        try:
            with self._connectIMAP() as imap:
                _, msgIds = imap.search(None, 'SUBJECT', f'"{subjectKeyword}"')
                for msgId in msgIds[0].split():
                    imap.store(msgId, '+FLAGS', '\\Deleted')
                imap.expunge()
        except Exception as e:
            print(f'[Test] Warning: could not clean IMAP inbox: {e}')

    def _deleteTestEmails(self):
        """Delete all FastFileLink emails from the inbox (convenience wrapper)."""
        self._deleteEmailsBySubject('FastFileLink')

    def _pollInbox(self, subjectKeyword, timeout, extractFn):
        """Poll IMAP until *extractFn* returns a truthy value or *timeout* expires.

        *extractFn(body: str) -> value* is called for each matching unseen message.
        Returns the first truthy value returned by *extractFn*.
        Raises TimeoutError if nothing is found within *timeout* seconds.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with self._connectIMAP() as imap:
                    _, msgIds = imap.search(None, 'UNSEEN', 'SUBJECT', f'"{subjectKeyword}"')
                    for msgId in reversed(msgIds[0].split()):
                        _, data = imap.fetch(msgId, '(RFC822)')
                        msg = email_lib.message_from_bytes(data[0][1])
                        body = self._extractBody(msg)
                        result = extractFn(body)
                        if result:
                            return result
            except Exception as e:
                print(f'[Test] IMAP poll error: {e}')
            time.sleep(5)
        raise TimeoutError(f'Expected email with subject "{subjectKeyword}" not received within {timeout}s')

    def _fetchEmailBody(self, subjectKeyword, timeout=90):
        """Return the plain-text body of the first matching unseen email."""
        return self._pollInbox(subjectKeyword, timeout, lambda body: body or None)

    def _fetchOTPFromEmail(self, timeout=90):
        """Poll IMAP until a FastFileLink OTP email arrives; return the 6-digit code."""
        def extractOTP(body):
            match = re.search(r'\b(\d{6})\b', body)
            return match.group(1) if match else None

        return self._pollInbox('FastFileLink', timeout, extractOTP)
