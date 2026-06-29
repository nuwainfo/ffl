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

"""
Tests for the ShellIntegration addon.

ShellIntegrationUnitTest
    Pure unit tests — no OS changes.  Always runnable on every platform.

ShellIntegrationCLITest
    CLI subprocess tests: `ffl shell --install / --uninstall / --help`.
    Exercises the real install/uninstall path end-to-end via the CLI, which
    supersedes testing the same lifecycle through the internal Python API.

ShellIntegrationDirectTest (Windows-only)
    Reads the registered command from the Windows registry and invokes it
    with the test file — exactly what Explorer does.  No pyautogui needed.

ShellIntegrationExplorerTest (Windows + pyautogui + display)
    Full UI walkthrough: open Explorer → right-click → click menu item.

Run all:
    python -m unittest tests.addons.ShellIntegrationTest
"""

import hashlib
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import requests

from addons.ShellIntegration import _WINDOWS_REG_PATH
from ..CoreTestBase import FastFileLinkTestBase

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_CORE_PATH = os.path.normcase(os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'Core.py')
))
_PYTHON_EXE = os.path.normcase(os.path.abspath(sys.executable))
_DEV_COMMAND_ARGS = [_PYTHON_EXE, _CORE_PATH, '--cli']

_FIXTURES_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'fixtures'))
_CONTEXT_MENU_IMAGE = os.path.join(_FIXTURES_DIR, 'ContextMenu.png')

_IS_WINDOWS = sys.platform == 'win32'
_IS_JENKINS = 'JENKINS_HOME' in os.environ


def _pyAutoGuiAvailable():
    try:
        import pyautogui  # noqa: F401
        import pyperclip  # noqa: F401
        return True
    except Exception:
        # ImportError when packages missing; Xlib.error.XauthError on headless
        # servers without ~/.Xauthority (e.g. Jenkins CI)
        return False


_PYAUTOGUI_AVAILABLE = _pyAutoGuiAvailable()

if _PYAUTOGUI_AVAILABLE:
    import pyautogui
    import pyperclip


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _captureFlushPrint(func, *args, **kwargs):
    """Call func(*args, **kwargs) and return everything printed via flushPrint."""
    captured = []
    with mock.patch('addons.ShellIntegration.flushPrint', side_effect=captured.append):
        func(*args, **kwargs)
    return '\n'.join(str(s) for s in captured)


def _runShellCLI(subArgs, timeout=30):
    """Run `python Core.py --cli shell [subArgs...]` and return (returnCode, output)."""
    cmd = [sys.executable, _CORE_PATH, '--cli', 'shell'] + list(subArgs)
    env = {**os.environ, 'DISABLE_ADDONS': 'GUI', 'FFL_YES': 'True'}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 1, 'Process timed out'


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _isValidShareLink(text):
    return isinstance(text, str) and text.startswith('http') and '.' in text


def _killFFLProcesses():
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline') or []
                if any('Core.py' in arg or 'CorePatched.py' in arg for arg in cmdline):
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
            except Exception:
                pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# CLI tests — subprocess, tests the full `ffl shell` command pipeline
# ---------------------------------------------------------------------------

class ShellIntegrationCLITest(FastFileLinkTestBase):
    """
    Functional CLI tests for `ffl shell --install / --uninstall`.
    Runs Core.py as a subprocess with DISABLE_ADDONS=GUI, via the shared
    FastFileLinkTestBase._runCoreCommand() runner (isolated tempDir/test-config
    setup comes from the base class too).
    setUp/tearDown always clean up the context menu entry.
    """

    def setUp(self):
        super().setUp()
        self._runShellCLI(['--uninstall'])

    def tearDown(self):
        try:
            self._runShellCLI(['--uninstall'])
        finally:
            super().tearDown()

    def _runShellCLI(self, subArgs, timeout=30):
        """Run `python Core.py --cli shell [subArgs...]` and return (returnCode, output)."""
        output, returnCode = self._runCoreCommand(['--cli', 'shell'] + list(subArgs), timeout=timeout)
        return returnCode, output

    def testShellCommandStatus(self):
        returnCode, output = self._runShellCLI([])
        self.assertIn('OS Context Menu Integration', output)
        self.assertEqual(returnCode, 0)

    def testShellCommandStatusShowsPlatform(self):
        returnCode, output = self._runShellCLI([])
        self.assertTrue(any(label in output for label in ('Windows', 'macOS', 'Linux')))
        self.assertEqual(returnCode, 0)

    def testShellCommandStatusNotInstalledWhenClean(self):
        returnCode, output = self._runShellCLI([])
        self.assertIn('Not installed', output)
        self.assertEqual(returnCode, 0)

    def testShellCommandInstall(self):
        returnCode, output = self._runShellCLI(['--install'])
        self.assertIn('installed', output.lower())
        self.assertEqual(returnCode, 0)

    def testShellCommandInstallIdempotent(self):
        self._runShellCLI(['--install'])
        returnCode, output = self._runShellCLI(['--install'])
        self.assertIn('installed', output.lower())
        self.assertEqual(returnCode, 0)

    def testShellCommandUninstall(self):
        self._runShellCLI(['--install'])
        returnCode, output = self._runShellCLI(['--uninstall'])
        self.assertIn('removed', output.lower())
        self.assertEqual(returnCode, 0)

    def testShellCommandUninstallIdempotent(self):
        returnCode, output = self._runShellCLI(['--uninstall'])
        self.assertEqual(returnCode, 0)

    def testShellCommandHelp(self):
        returnCode, output = self._runShellCLI(['--help'])
        self.assertIn('usage', output.lower())
        self.assertIn('--install', output)
        self.assertIn('--uninstall', output)
        self.assertIn('context menu', output.lower())
        self.assertEqual(returnCode, 0)

    def testShellCommandInstallAndUninstallAreMutuallyExclusive(self):
        returnCode, output = self._runShellCLI(['--install', '--uninstall'])
        self.assertNotEqual(returnCode, 0)


# ---------------------------------------------------------------------------
# OS-level end-to-end tests (Windows only)
# ---------------------------------------------------------------------------

@unittest.skipUnless(_IS_WINDOWS, 'Windows-only tests')
class _ShellIntegrationOSBase(unittest.TestCase):
    """
    Base for Windows end-to-end tests.
    Installs the context menu, creates a temp test file, and cleans up after.
    """

    def setUp(self):
        # Whether --install actually succeeded is ShellIntegrationCLITest's concern
        # (testShellCommandInstall); here it's just setup for the end-to-end test below,
        # which will fail on its own (e.g. registry key not found) if install didn't work.
        _runShellCLI(['--install'])

        self.tempDir = tempfile.mkdtemp(prefix='ffl_cm_test_')
        self.testFilePath = os.path.join(self.tempDir, 'share_test.bin')
        with open(self.testFilePath, 'wb') as f:
            f.write(os.urandom(512 * 1024))
        self.testFileHash = _sha256(self.testFilePath)
        self.fflProc = None

    def tearDown(self):
        if self.fflProc:
            try:
                self.fflProc.terminate()
                self.fflProc.wait(timeout=5)
            except Exception:
                pass
        _killFFLProcesses()
        _runShellCLI(['--uninstall'])
        shutil.rmtree(self.tempDir, ignore_errors=True)

    def _downloadAndVerify(self, shareLink):
        downloadPath = os.path.join(self.tempDir, 'downloaded.bin')
        response = requests.get(shareLink, stream=True, timeout=60)
        response.raise_for_status()
        with open(downloadPath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
        self.assertEqual(
            self.testFileHash, _sha256(downloadPath),
            f'SHA-256 mismatch after download from {shareLink}'
        )


class ShellIntegrationDirectTest(_ShellIntegrationOSBase):
    """
    Reads the registered command from the Windows registry and invokes it
    directly — exactly what Explorer does when the user clicks the menu item.
    No pyautogui or screenshots required.
    """

    def setUp(self):
        super().setUp()
        if _PYAUTOGUI_AVAILABLE:
            pyperclip.copy('')

    def testContextMenuShareByDirectInvocation(self):
        import winreg
        path = _WINDOWS_REG_PATH + r'\shell\01_Share\command'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            cmdTemplate = winreg.QueryValueEx(key, None)[0]

        cmdLine = cmdTemplate.replace('"%1"', f'"{self.testFilePath}"')
        if _PYAUTOGUI_AVAILABLE:
            pyperclip.copy('')

        creationFlags = subprocess.CREATE_NEW_PROCESS_GROUP if _IS_WINDOWS else 0
        self.fflProc = subprocess.Popen(
            cmdLine,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationFlags,
        )

        shareLink = self._findShareLink(timeout=90)
        self._downloadAndVerify(shareLink)

    def _findShareLink(self, timeout=90):
        lineQueue = queue.Queue()

        def _readStdout():
            try:
                for raw in self.fflProc.stdout:
                    line = raw.strip()
                    if line:
                        lineQueue.put(line)
            except Exception:
                pass

        threading.Thread(target=_readStdout, daemon=True).start()

        accumulated = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            while not lineQueue.empty():
                line = lineQueue.get_nowait()
                accumulated.append(line)
                if _isValidShareLink(line):
                    return line

            if _PYAUTOGUI_AVAILABLE:
                try:
                    text = pyperclip.paste()
                    if _isValidShareLink(text):
                        return text
                except Exception:
                    pass

            if self.fflProc.poll() is not None:
                while not lineQueue.empty():
                    line = lineQueue.get_nowait()
                    accumulated.append(line)
                    if _isValidShareLink(line):
                        return line
                raise AssertionError(
                    f'FFL process exited (code {self.fflProc.returncode}) '
                    f'without producing a share link.\nOutput:\n' + '\n'.join(accumulated)
                )

            time.sleep(0.5)

        raise AssertionError(
            f'Share link not found in stdout or clipboard within {timeout}s.\n'
            f'Stdout so far:\n' + '\n'.join(accumulated)
        )


@unittest.skipIf(_IS_JENKINS, 'JENKINS_HOME set — headless environment')
@unittest.skipUnless(_PYAUTOGUI_AVAILABLE, 'pyautogui/pyperclip not installed')
@unittest.skipUnless(os.path.exists(_CONTEXT_MENU_IMAGE), f'ContextMenu.png not found at {_CONTEXT_MENU_IMAGE}')
class ShellIntegrationExplorerTest(_ShellIntegrationOSBase):
    """
    Full UI test: opens Windows Explorer, right-clicks via Shift+F10
    (classic context menu), and clicks "Share with FastFileLink".
    """

    def setUp(self):
        try:
            shot = pyautogui.screenshot()
            if shot is None:
                raise RuntimeError('screenshot returned None')
        except Exception as e:
            self.skipTest(
                f'Screenshot capture unavailable ({e}). '
                f'Use ShellIntegrationDirectTest for headless coverage.'
            )
        super().setUp()
        pyautogui.FAILSAFE = False
        pyautogui.PAUSE = 0.3
        screenW, screenH = pyautogui.size()
        pyautogui.moveTo(screenW // 2, screenH // 2)
        pyperclip.copy('')
        self.explorerProc = None

    def tearDown(self):
        if self.explorerProc:
            try:
                self.explorerProc.terminate()
            except Exception:
                pass
        super().tearDown()

    def _forceActivateWindow(self, win):
        import ctypes
        hwnd = win._hWnd
        ctypes.windll.user32.ShowWindow(hwnd, 9)
        fgWnd = ctypes.windll.user32.GetForegroundWindow()
        fgTid = ctypes.windll.user32.GetWindowThreadProcessId(fgWnd, None)
        tgtTid = ctypes.windll.user32.GetWindowThreadProcessId(hwnd, None)
        if fgTid != tgtTid:
            ctypes.windll.user32.AttachThreadInput(fgTid, tgtTid, True)
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            ctypes.windll.user32.AttachThreadInput(fgTid, tgtTid, False)
        else:
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        time.sleep(0.3)

    def _clickContextMenuItem(self, imagePath, confidence=0.8, timeout=15):
        screenshotEverFailed = False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                loc = pyautogui.locateOnScreen(imagePath, confidence=confidence)
                if loc:
                    cx, cy = pyautogui.center(loc)
                    pyautogui.click(cx, cy)
                    time.sleep(0.5)
                    return
            except Exception as e:
                if 'screen grab' in str(e).lower() or 'screenshot' in str(e).lower():
                    screenshotEverFailed = True
                    break
            time.sleep(0.5)

        if screenshotEverFailed:
            pyautogui.press('s')
            time.sleep(0.3)
            pyautogui.press('enter')
            time.sleep(0.5)
            return

        raise AssertionError(f'Image not found on screen within {timeout}s: {imagePath}')

    def _waitForExplorerWindow(self, folderPath, timeout=15):
        folderName = os.path.basename(folderPath)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for win in pyautogui.getAllWindows():
                    title = win.title
                    if folderName in title or 'File Explorer' in title or 'Explorer' in title:
                        return win
            except Exception:
                pass
            time.sleep(0.5)
        return None

    def testContextMenuShareByExplorer(self):
        self.explorerProc = subprocess.Popen(['explorer', self.tempDir])
        time.sleep(2)

        win = self._waitForExplorerWindow(self.tempDir, timeout=15)
        self.assertIsNotNone(win, 'Explorer window did not appear within 15s')
        self._forceActivateWindow(win)

        listX = win.left + int(win.width * 0.65)
        listY = win.top + int(win.height * 0.55)
        pyautogui.click(listX, listY)
        time.sleep(0.5)
        pyautogui.press('f6')
        time.sleep(0.3)
        pyautogui.hotkey('ctrl', 'a')
        time.sleep(0.5)
        pyautogui.hotkey('shift', 'f10')
        time.sleep(2)

        self._clickContextMenuItem(_CONTEXT_MENU_IMAGE, confidence=0.8, timeout=10)

        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                text = pyperclip.paste()
                if _isValidShareLink(text):
                    self._downloadAndVerify(text)
                    return
            except Exception:
                pass
            time.sleep(1)
        raise AssertionError('Share link did not appear in clipboard within 90s')


if __name__ == '__main__':
    unittest.main()
