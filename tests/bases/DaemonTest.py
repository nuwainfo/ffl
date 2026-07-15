#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys
import time
import unittest

import psutil

from bases.Daemon import DaemonClient

from ..CoreTestBase import FastFileLinkTestBase, LOCAL_TEST_SERVER_URL


class DaemonTest(FastFileLinkTestBase):
    """Functional tests for the background daemon and multi-session share management."""

    def setUp(self):
        super().setUp()
        self._daemonPid = None
        self._daemonEnvOverrides = {}
        self._testServerProcesses = []
        self._startDaemon()

    def tearDown(self):
        while self._testServerProcesses:
            self._stopTestServer(self._testServerProcesses.pop())
        self._stopDaemon()
        super().tearDown()

    # ------------------------------------------------------------------
    # Daemon lifecycle helpers
    # ------------------------------------------------------------------

    def _coreScriptPath(self):
        return os.path.join(os.path.dirname(__file__), '..', 'CorePatched.py')

    def _projectRoot(self):
        return os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..'))

    def _coreEnv(self):
        env = {'PYTHONUNBUFFERED': '1'}
        env.update(self._daemonEnvOverrides)
        return env

    def _runPatchedCoreCommand(self, args, timeout=30):
        return self._runCoreCommand(
            args,
            commandPrefix=[sys.executable, self._coreScriptPath()],
            extraEnvVars=self._coreEnv(),
            cwd=self._projectRoot(),
            timeout=timeout,
        )

    def _startDaemon(self):
        """Run `ffl daemon` and wait until daemon.json appears in FFL_STORAGE_LOCATION."""
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'daemon'], timeout=30)
        self.assertEqual(returnCode, 0, f"Daemon start failed:\n{output}")
        print(f"[Test] daemon start output: {output.strip()}")

        # Wait for daemon.json to appear
        deadline = time.time() + 15
        while time.time() < deadline:
            if os.path.exists(daemonJsonPath):
                with open(daemonJsonPath, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                self._daemonPid = state.get('pid')
                print(f"[Test] Daemon running: PID={self._daemonPid}, port={state.get('port')}")
                return
            time.sleep(0.3)

        raise AssertionError("Daemon did not write daemon.json within 15 seconds")

    def _stopDaemon(self):
        """Send `ffl daemon --stop` then kill forcefully if needed."""
        if not self._daemonPid:
            return

        try:
            self._runPatchedCoreCommand(['--cli', 'daemon', '--stop'], timeout=15)
        except Exception as e:
            print(f"[Test] Error sending daemon --stop: {e}")

        # Forcefully kill if still running
        try:
            proc = psutil.Process(self._daemonPid)
            if proc.is_running():
                proc.kill()
                proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            pass
        except Exception as e:
            print(f"[Test] Error killing daemon: {e}")

        self._daemonPid = None

    def _assertDaemonRunning(self):
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')
        self.assertTrue(os.path.exists(daemonJsonPath), "daemon.json should exist")
        with open(daemonJsonPath, 'r', encoding='utf-8') as f:
            state = json.load(f)
        pid = state.get('pid')
        self.assertIsNotNone(pid, "daemon.json should have pid")
        try:
            proc = psutil.Process(pid)
            self.assertTrue(proc.is_running(), f"Daemon process {pid} should be running")
        except psutil.NoSuchProcess:
            self.fail(f"Daemon process {pid} is not running")

    def _assertDaemonNotRunning(self):
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')
        self.assertFalse(os.path.exists(daemonJsonPath), "daemon.json should not exist after daemon stops")

    def _getFirstManagedShareId(self):
        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=10)
        self.assertEqual(returnCode, 0, f"shares list failed: {output}")
        output = output.strip()
        print(f"[Test] shares list: {output}")

        lines = [line.strip() for line in output.split('\n') if line.strip() and line.strip() != 'Active shares:']
        self.assertTrue(lines, "Should have at least one share listed")
        return lines[0].split()[0]

    def _waitForFirstManagedShareId(self, timeout=20):
        client = DaemonClient()
        deadline = time.time() + timeout
        while time.time() < deadline:
            shares = client.listShares()
            if shares:
                print(f"[Test] daemon shares during wait: {shares}")
                return shares[0]['id']

            time.sleep(0.3)

        raise AssertionError("Timed out waiting for daemon-managed share to appear")

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def testDaemonStartStop(self):
        """Test that daemon starts (idempotent) and stops cleanly."""
        self._assertDaemonRunning()

        # Starting daemon again should be idempotent
        output, returnCode = self._runPatchedCoreCommand(['--cli', 'daemon'], timeout=15)
        self.assertEqual(returnCode, 0, f"Second daemon start should succeed: {output}")
        self.assertIn('already running', output.lower(), "Should report already running")

        # Stop daemon
        output, returnCode = self._runPatchedCoreCommand(['--cli', 'daemon', '--stop'], timeout=15)
        self.assertEqual(returnCode, 0, f"Daemon stop failed: {output}")
        print(f"[Test] daemon stop output: {output.strip()}")

        # Wait for daemon.json to disappear
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')
        deadline = time.time() + 10
        while time.time() < deadline:
            if not os.path.exists(daemonJsonPath):
                break
            time.sleep(0.3)

        self._assertDaemonNotRunning()
        self._daemonPid = None  # already stopped, skip _stopDaemon cleanup

    def testDaemonStatus(self):
        """Test `ffl daemon --status` reports running correctly."""
        output, returnCode = self._runPatchedCoreCommand(['--cli', 'daemon', '--status'], timeout=10)
        self.assertEqual(returnCode, 0, f"daemon --status failed: {output}")
        output = output.lower()
        self.assertIn('running', output, "Status output should say 'running'")
        self.assertIn('pid', output, "Status should show PID")
        self.assertIn('port', output, "Status should show port")
        print(f"[Test] daemon --status output: {output.strip()}")

    def testDaemonShare(self):
        """Test sharing a file via --background routes to daemon and download works."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        print(f"[Test] Daemon share link: {shareLink}")

        downloadedFilePath = self._getDownloadedFilePath('daemon_share_test.bin')
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)

    def testDaemonUploadShare(self):
        """Test daemon-managed background upload returns a hosted link and preserves upload metadata."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer()
        self._testServerProcesses.append(testServerProcess)
        self._daemonEnvOverrides = {'FILESHARE_TEST': LOCAL_TEST_SERVER_URL}
        self._startDaemon()

        shareLink = self._startFastFileLink(p2p=False, extraArgs=['--background'])
        print(f"[Test] Daemon upload link: {shareLink}")

        with open(self.jsonOutputPath, 'r', encoding='utf-8') as fileHandle:
            shareInfo = json.load(fileHandle)
        self.assertEqual(shareInfo.get('upload_mode'), 'server', f"Expected server upload JSON output: {shareInfo}")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=10)
        self.assertEqual(returnCode, 0, f"shares list failed after daemon upload: {output}")
        self.assertIn(shareLink, output, f"Expected daemon upload share to remain listed: {output}")
        self.assertIn('completed', output.lower(), f"Expected daemon upload share to be listed as completed: {output}")

        downloadedFilePath = self._getDownloadedFilePath('daemon_upload_share_test.bin')
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath, shareLink=shareLink)

    def testDaemonUploadShareStop(self):
        """Test stopping an in-flight daemon upload cancels it and removes it from active shares."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer()
        self._testServerProcesses.append(testServerProcess)
        self._daemonEnvOverrides = {
            'FILESHARE_TEST': LOCAL_TEST_SERVER_URL,
            'UPLOAD_CHUNK_SIZE': '1',
            'UPLOAD_CONCURRENCY': '1',
        }
        self._startDaemon()

        largeFileSize = 128 * 1024 * 1024
        self.generateRandomFile(self.testFilePath, largeFileSize)
        self.originalFileHash = self.getFileHash(self.testFilePath)
        self.originalFileSize = os.path.getsize(self.testFilePath)
        print(f"[Test] Regenerated larger upload file: {self.originalFileSize} bytes")

        self._startFastFileLink(
            p2p=False,
            extraArgs=['--background'],
            waitForCompletion=False,
        )

        shareId = self._waitForFirstManagedShareId()
        print(f"[Test] Stopping daemon upload share: {shareId}")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'stop', shareId], timeout=10)
        self.assertEqual(returnCode, 0, f"shares stop failed: {output}")
        self.assertIn(shareId, output, "Output should mention the stopped share ID")

        self.coreProcess.wait(timeout=120)

        if self._procLogFile:
            self._procLogFile.flush()
        with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as logFile:
            output = logFile.read()

        self.assertEqual(
            self.coreProcess.returncode,
            0,
            f"CorePatched.py currently exits 0 unless it raises; unexpected process failure:\n{output}"
        )

        self.assertIn('Waiting for share link...', output)
        self.assertIn('Failed to get share link from daemon', output)
        self.assertFalse(os.path.exists(self.jsonOutputPath), "Stopped upload should not write share_info.json")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=10)
        self.assertEqual(returnCode, 0, f"shares list after stop failed: {output}")
        self.assertIn('No active shares', output, "Stopped daemon upload should be removed from active shares")

    def testDaemonBackgroundUploadWithoutYesPromptsThenRoutesToDaemon(self):
        """Test explicit --background upload prompts first, then submits to daemon."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer()
        self._testServerProcesses.append(testServerProcess)

        output, returnCode = self._runCoreCommand(
            [
                '--cli', 'share', self.testFilePath,
                '--json', self.jsonOutputPath,
                '--upload', '3 hours',
                '--background',
            ],
            commandPrefix=[sys.executable, self._coreScriptPath()],
            extraEnvVars={
                'PYTHONUNBUFFERED': '1',
                'FILESHARE_TEST': LOCAL_TEST_SERVER_URL,
            },
            cwd=self._projectRoot(),
            stdin=subprocess.PIPE,
            inputData='yes\n',
            timeout=120,
        )

        self.assertEqual(returnCode, 0, f"Expected background daemon upload to succeed after confirmation: {output}")
        self.assertIn('Upload requires', output)
        self.assertIn('Continue with upload?', output)
        self.assertIn('Waiting for share link...', output)
        self.assertNotIn('Cannot prompt for confirmation in non-interactive mode. Use --yes.', output)
        self.assertNotIn('Upload cancelled before transfer started.', output)
        self.assertTrue(os.path.exists(self.jsonOutputPath), "Expected upload to complete and write share_info.json")

        with open(self.jsonOutputPath, 'r', encoding='utf-8') as fileHandle:
            shareInfo = json.load(fileHandle)
        self.assertEqual(shareInfo.get('upload_mode'), 'server', f"Expected server upload JSON output: {shareInfo}")

    def testDaemonRunningUploadWithoutYesPromptsThenRoutesToDaemon(self):
        """Test upload prompts in foreground, then routes to daemon after confirmation."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer()
        self._testServerProcesses.append(testServerProcess)
        self._daemonEnvOverrides = {'FILESHARE_TEST': LOCAL_TEST_SERVER_URL}
        self._startDaemon()

        output, returnCode = self._runCoreCommand(
            [
                '--cli', 'share', self.testFilePath,
                '--json', self.jsonOutputPath,
                '--upload', '3 hours',
            ],
            commandPrefix=[sys.executable, self._coreScriptPath()],
            extraEnvVars={
                'PYTHONUNBUFFERED': '1',
                'FILESHARE_TEST': LOCAL_TEST_SERVER_URL,
            },
            cwd=self._projectRoot(),
            stdin=subprocess.PIPE,
            inputData='yes\n',
            timeout=120,
        )

        self.assertEqual(returnCode, 0, f"Expected daemon upload to succeed after confirmation: {output}")
        self.assertIn('Upload requires', output)
        self.assertIn('Continue with upload?', output)
        self.assertIn('Waiting for share link...', output)
        self.assertNotIn('Cannot prompt for confirmation in non-interactive mode. Use --yes.', output)
        self.assertNotIn('Upload cancelled before transfer started.', output)
        self.assertTrue(os.path.exists(self.jsonOutputPath), "Expected upload to complete and write share_info.json")

        with open(self.jsonOutputPath, 'r', encoding='utf-8') as fileHandle:
            shareInfo = json.load(fileHandle)
        self.assertEqual(shareInfo.get('upload_mode'), 'server', f"Expected server upload JSON output: {shareInfo}")

    def testDaemonSharesList(self):
        """Test `ffl shares list` shows the active share after --background."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        print(f"[Test] Share link: {shareLink}")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=10)
        self.assertEqual(returnCode, 0, f"shares list failed: {output}")
        print(f"[Test] shares list output: {output.strip()}")
        self.assertIn('online', output.lower(), "Share should be listed as online")

    def testDaemonShareStop(self):
        """Test stopping a specific share via `ffl shares stop <id>`."""
        self._startFastFileLink(p2p=True, extraArgs=['--background'])
        shareId = self._getFirstManagedShareId()
        print(f"[Test] Stopping share: {shareId}")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'stop', shareId], timeout=10)
        self.assertEqual(returnCode, 0, f"shares stop failed: {output}")
        self.assertIn(shareId, output, "Output should mention the stopped share ID")

    def testDaemonSharePickupRecipientAuth(self):
        """Test daemon-managed background share still enforces pickup recipient auth after merge."""
        pickupCode = '482951'
        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=['--background', '--recipient-auth', 'pickup', '--pickup-code', pickupCode]
        )
        print(f"[Test] Daemon pickup-auth share link: {shareLink}")

        downloadedFilePath = self._getDownloadedFilePath('daemon_pickup_share_test.bin')
        self.downloadFileWithRequests(
            shareLink,
            downloadedFilePath,
            headers={'X-FFL-Pickup': pickupCode},
        )
        self._verifyDownloadedFile(downloadedFilePath)

    def testDaemonShareQr(self):
        """Test `ffl shares qr <id>` renders a QR code and includes the share link."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        shareId = self._getFirstManagedShareId()

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'qr', shareId], timeout=20)
        self.assertEqual(returnCode, 0, f"shares qr failed: {output}")
        self.assertIn(shareLink, output, "QR output should include the share link")

    def testDaemonShareStopAll(self):
        """Test `ffl shares stop --all` stops all managed shares."""
        self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()
        self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'stop', '--all'], timeout=30)
        self.assertEqual(returnCode, 0, f"shares stop --all failed: {output}")
        self.assertIn('Stopped', output, "Output should report stopped shares")

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=20)
        self.assertEqual(returnCode, 0, f"shares list after stop --all failed: {output}")
        self.assertIn('No active shares', output, "All shares should be stopped")

    def testDaemonForegroundBypassesDaemon(self):
        """Test that --foreground runs normally in the foreground, ignoring the daemon."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--foreground'])
        print(f"[Test] Foreground share link: {shareLink}")

        # Should produce a valid share link and the process should still be running (not exited)
        self.assertIsNotNone(shareLink)
        self.assertTrue(shareLink.startswith('http'), "Should be a valid HTTPS/HTTP link")

        # Verify the foreground process is still alive (it's serving, not exited like background mode)
        if self.coreProcess:
            self.assertIsNone(
                self.coreProcess.poll(),
                "Foreground process should still be running (not exited like background mode)"
            )

        # Can still download the file
        downloadedFilePath = self._getDownloadedFilePath('foreground_share_test.bin')
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)

if __name__ == '__main__':
    unittest.main()
