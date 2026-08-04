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
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import requests
import psutil

from addons.ShellIntegration import ShellIntegration, WindowsIntegration, _WINDOWS_REG_PATH
from bases.Daemon import DaemonClient, DaemonStateFile
from ..CoreTestBase import FastFileLinkTestBase

_FIXTURES_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'fixtures'))
_CONTEXT_MENU_IMAGE = os.path.join(_FIXTURES_DIR, 'ContextMenu.png')
_GUI_EXECUTABLE_FIXTURE = os.path.join(_FIXTURES_DIR, 'FFL.exe')

_IS_WINDOWS = sys.platform == 'win32'
_IS_WINDOWS_11 = _IS_WINDOWS and sys.getwindowsversion().build >= 22000
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
                if any('FFL.py' in arg or 'CorePatched.py' in arg for arg in cmdline):
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

@unittest.skipUnless(_IS_WINDOWS, 'Windows-only test')
class ShellIntegrationWindowsStoreTest(unittest.TestCase):

    def testUsesPackagedExecutable(self):
        class Settings:

            def isCLIMode(self):
                return False

            def isRunOnDevelopment(self):
                return False

            exePath = r'C:\Program Files\WindowsApps\NuwaInformation.FastFileLink_4.0.3.0_x64__gzmdmehqhdsge\VFS\Local AppData\FastFileLink\FastFileLink.exe'

        with mock.patch('addons.ShellIntegration.StoreHelper.isWindowsStore', return_value=True), \
             mock.patch('os.path.isfile', return_value=True):
            integration = WindowsIntegration.create(Settings())

        self.assertEqual(integration.identity['target'], os.path.normcase(Settings.exePath))
        self.assertEqual(
            integration._commandValue,
            f'"{os.path.normcase(Settings.exePath)}" "--cli" "--background-gui" "%1"',
        )


class ShellIntegrationCLITest(FastFileLinkTestBase):
    """
    Functional CLI tests for `ffl shell --install / --uninstall`.
    Runs FFL.py as a subprocess with DISABLE_ADDONS=GUI, via the shared
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
        """Run `python FFL.py --cli shell [subArgs...]` and return (returnCode, output)."""
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
class _ShellIntegrationOSBase(FastFileLinkTestBase):
    """
    Base for Windows end-to-end tests.
    Installs the context menu, creates a temp test file, and cleans up after.
    """

    def setUp(self):
        super().setUp()
        # Whether --install actually succeeded is ShellIntegrationCLITest's concern
        # (testShellCommandInstall); here it's just setup for the end-to-end test below,
        # which will fail on its own (e.g. registry key not found) if install didn't work.
        self._runShellCLI(['--install'])
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
        try:
            _killFFLProcesses()
            self._runShellCLI(['--uninstall'])
        finally:
            super().tearDown()

    def _runShellCLI(self, subArgs, timeout=30):
        output, returnCode = self._runCoreCommand(['--cli', 'shell'] + list(subArgs), timeout=timeout)
        return returnCode, output

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
        self.fflProc = self._startSubprocess(
            cmdLine,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationFlags=creationFlags,
            disableGuiAddon=False,
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


# ---------------------------------------------------------------------------
# GUI shell integration end-to-end tests (Windows only)
# ---------------------------------------------------------------------------

@unittest.skipUnless(_IS_WINDOWS, 'Windows-only tests')
class _ShellIntegrationGUIBase(FastFileLinkTestBase):
    """Exercises the GUI registration command exactly as Explorer invokes it."""

    def setUp(self):
        super().setUp()
        self.guiProcess = None
        self._integration = ShellIntegration.build()
        self._integration.setEnabled(True)

    def tearDown(self):
        try:
            daemonState = DaemonStateFile().load()
            if DaemonClient.isRunning():
                DaemonClient().stopDaemon()
            if daemonState:
                daemonProcess = psutil.Process(daemonState['pid'])
                daemonProcess.terminate()
                daemonProcess.wait(timeout=5)
            if self.guiProcess and self.guiProcess.poll() is None:
                self.guiProcess.terminate()
                self.guiProcess.wait(timeout=5)
        finally:
            self._integration.setEnabled(False)
            super().tearDown()

    def _waitForDaemon(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if DaemonClient.isRunning():
                return
            time.sleep(0.2)
        self.fail('GUI shell command did not start an in-process daemon')

    def _waitForShare(self, filePath, timeout=30):
        expectedPath = os.path.normcase(os.path.abspath(filePath))
        deadline = time.time() + timeout
        while time.time() < deadline:
            for share in DaemonClient().listShares():
                sharePaths = [os.path.normcase(os.path.abspath(path)) for path in share['filePaths']]
                if expectedPath in sharePaths:
                    return share
            time.sleep(0.2)
        self.fail(f'GUI daemon did not create a share for {filePath}')

    def _readShareCommand(self):
        import winreg
        path = _WINDOWS_REG_PATH + r'\shell\01_Share\command'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            return winreg.QueryValueEx(key, None)[0]

    def _invokeCommand(self, commandTemplate, filePath):
        commandLine = commandTemplate.replace('"%1"', f'"{filePath}"')
        return self._startSubprocess(
            commandLine,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationFlags=subprocess.CREATE_NEW_PROCESS_GROUP,
            disableGuiAddon=False,
        )


class ShellIntegrationGUIDirectTest(_ShellIntegrationGUIBase):
    """Python-source GUI registration launches/uses the GUI-owned daemon."""

    def testContextMenuShareStartsGUIAndRoutesLaterRequestsToItsDaemon(self):
        commandTemplate = self._readShareCommand()
        self.assertIn('--cli', commandTemplate)
        self.assertIn('--background-gui', commandTemplate)

        self.guiProcess = self._invokeCommand(commandTemplate, self.testFilePath)
        self._waitForDaemon()
        firstShare = self._waitForShare(self.testFilePath)

        state = DaemonStateFile().load()
        self.assertEqual(state['pid'], self.guiProcess.pid)

        secondFilePath = os.path.join(self.tempDir, 'second_share.bin')
        with open(secondFilePath, 'wb') as fileHandle:
            fileHandle.write(os.urandom(4096))

        secondProcess = self._invokeCommand(commandTemplate, secondFilePath)
        self.assertEqual(secondProcess.wait(timeout=30), 0)
        secondShare = self._waitForShare(secondFilePath)

        self.assertNotEqual(firstShare['id'], secondShare['id'])
        self.assertEqual(DaemonStateFile().load()['pid'], self.guiProcess.pid)


@unittest.skipUnless(_IS_WINDOWS, 'Windows-only tests')
@unittest.skipUnless(os.path.isfile(_GUI_EXECUTABLE_FIXTURE), 'GUI executable fixture is not available')
class ShellIntegrationGUIExecutableTest(_ShellIntegrationGUIBase):
    """The packaged GUI executable accepts the same shell request contract."""

    def testPackagedExecutableStartsGUIManagedShellShare(self):
        self.guiProcess = self._startSubprocess(
            [_GUI_EXECUTABLE_FIXTURE, '--cli', '--background-gui', self.testFilePath],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationFlags=subprocess.CREATE_NEW_PROCESS_GROUP,
            disableGuiAddon=False,
        )

        self._waitForDaemon()
        self._waitForShare(self.testFilePath)
        self.assertTrue(DaemonStateFile().load()['pid'])


@unittest.skipIf(_IS_JENKINS, 'JENKINS_HOME set — headless environment')
@unittest.skipIf(_IS_WINDOWS_11, 'Windows 11 requires a Show more options UI fixture before this visual test can run')
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
        self.explorerProc = self._startSubprocess(['explorer', self.tempDir], disableGuiAddon=False)
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
