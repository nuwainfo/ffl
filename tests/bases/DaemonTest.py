#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys
import time
import unittest

import psutil

from ..CoreTestBase import FastFileLinkTestBase


class DaemonTest(FastFileLinkTestBase):
    """Functional tests for the background daemon and multi-session share management."""

    def setUp(self):
        super().setUp()
        self._daemonPid = None
        self._startDaemon()

    def tearDown(self):
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
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        return env

    def _startDaemon(self):
        """Run `ffl daemon` and wait until daemon.json appears in FFL_STORAGE_LOCATION."""
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'daemon']
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=self._coreEnv(),
            cwd=self._projectRoot(),
        )
        self.assertEqual(result.returncode, 0, f"Daemon start failed:\n{result.stdout}\n{result.stderr}")
        print(f"[Test] daemon start output: {result.stdout.strip()}")

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
            cmd = [sys.executable, self._coreScriptPath(), '--cli', 'daemon', '--stop']
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                env=self._coreEnv(),
                cwd=self._projectRoot(),
            )
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
        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'list']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares list failed: {result.stderr}")
        output = result.stdout.strip()
        print(f"[Test] shares list: {output}")

        lines = [line.strip() for line in output.split('\n') if line.strip() and line.strip() != 'Active shares:']
        self.assertTrue(lines, "Should have at least one share listed")
        return lines[0].split()[0]

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def testDaemonStartStop(self):
        """Test that daemon starts (idempotent) and stops cleanly."""
        self._assertDaemonRunning()

        # Starting daemon again should be idempotent
        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'daemon']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"Second daemon start should succeed: {result.stdout} {result.stderr}")
        self.assertIn('already running', result.stdout.lower(), "Should report already running")

        # Stop daemon
        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'daemon', '--stop']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"Daemon stop failed: {result.stdout} {result.stderr}")
        print(f"[Test] daemon stop output: {result.stdout.strip()}")

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
        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'daemon', '--status']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"daemon --status failed: {result.stdout} {result.stderr}")
        output = result.stdout.lower()
        self.assertIn('running', output, "Status output should say 'running'")
        self.assertIn('pid', output, "Status should show PID")
        self.assertIn('port', output, "Status should show port")
        print(f"[Test] daemon --status output: {result.stdout.strip()}")

    def testDaemonShare(self):
        """Test sharing a file via --background routes to daemon and download works."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        print(f"[Test] Daemon share link: {shareLink}")

        downloadedFilePath = self._getDownloadedFilePath('daemon_share_test.bin')
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)

    def testDaemonSharesList(self):
        """Test `ffl shares list` shows the active share after --background."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        print(f"[Test] Share link: {shareLink}")

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'list']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares list failed: {result.stdout} {result.stderr}")
        output = result.stdout
        print(f"[Test] shares list output: {output.strip()}")
        self.assertIn('online', output.lower(), "Share should be listed as online")

    def testDaemonShareStop(self):
        """Test stopping a specific share via `ffl shares stop <id>`."""
        self._startFastFileLink(p2p=True, extraArgs=['--background'])
        shareId = self._getFirstManagedShareId()
        print(f"[Test] Stopping share: {shareId}")

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'stop', shareId]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares stop failed: {result.stdout} {result.stderr}")
        self.assertIn(shareId, result.stdout, "Output should mention the stopped share ID")

    def testDaemonShareQr(self):
        """Test `ffl shares qr <id>` renders a QR code and includes the share link."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        shareId = self._getFirstManagedShareId()

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'qr', shareId]
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding='utf-8', timeout=10,
            env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares qr failed: {result.stdout} {result.stderr}")
        self.assertIn(shareLink, result.stdout, "QR output should include the share link")

    def testDaemonShareStopAll(self):
        """Test `ffl shares stop --all` stops all managed shares."""
        self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._startFastFileLink(p2p=True, extraArgs=['--background'])

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'stop', '--all']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares stop --all failed: {result.stdout} {result.stderr}")
        self.assertIn('Stopped', result.stdout, "Output should report stopped shares")

        cmd = [sys.executable, self._coreScriptPath(), '--cli', 'shares', 'list']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=self._coreEnv(), cwd=self._projectRoot()
        )
        self.assertEqual(result.returncode, 0, f"shares list after stop --all failed: {result.stdout} {result.stderr}")
        self.assertIn('No active shares', result.stdout, "All shares should be stopped")

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
