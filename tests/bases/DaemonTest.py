#!/usr/bin/env python
# -*- coding: utf-8 -*-

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import unittest

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from bases.Daemon import DaemonClient, InProcessDaemonManager, InProcessShareManager, ProcessDaemonManager
from bases.Kernel import FFLEvent
from bases.Session import createSession
from bases.Share import ShareExecutionContext, ShareReporter, ShareStatus, createShareRequest

from ..BrowserTestBase import BrowserTestBase
from ..CoreTestBase import FastFileLinkTestBase, LOCAL_TEST_SERVER_URL

try:
    # tests/addons is not part of the open-source CLI-only release, so this
    # (and DaemonPreviewBrowserTest below, which needs it) must degrade to
    # "not available" rather than fail to import the whole module there.
    from ..addons.PreviewTest import PreviewBrowserE2EETest, SKIP_GUI_TEST
except ImportError:
    PreviewBrowserE2EETest = None
    SKIP_GUI_TEST = True


class DaemonPauseResumeTest(unittest.TestCase):

    @staticmethod
    def _createWorker(manager):
        shareRequest = createShareRequest({'file': [__file__], 'upload': '3 hours'})
        session = createSession(shareRequest)
        context = ShareExecutionContext(
            reporter=ShareReporter(outputCallback=lambda text: None),
            session=session,
            runtime=manager._runtime,
        )
        worker = manager.ShareWorker(session=session, shareRequest=shareRequest, context=context)
        manager._workers[session.uid] = worker
        return worker

    def testPauseMarksRequestOnlyWhenWorkerCanPause(self):
        manager = InProcessShareManager()
        worker = self._createWorker(manager)

        self.assertFalse(manager.pauseShare(worker.session.uid))

        worker.session.pauseSupported = True
        self.assertTrue(manager.pauseShare(worker.session.uid))
        self.assertTrue(worker.context.isPauseRequested())

    def testResumeRestartsSamePausedWorkerWithoutDialogState(self):
        manager = InProcessShareManager()
        worker = self._createWorker(manager)
        worker.session.status = ShareStatus.PAUSED
        worker.context.paused = True
        worker.context.pauseEvent.set()
        worker.encryptionKey = 'existing-encryption-key'

        with mock.patch.object(manager, '_startWorker') as startWorker:
            self.assertTrue(manager.resumeShare(worker.session.uid))

        self.assertEqual(worker.session.status, ShareStatus.CREATING)
        self.assertTrue(worker.shareRequest.resume)
        self.assertFalse(worker.context.paused)
        self.assertFalse(worker.context.isPauseRequested())
        self.assertEqual(worker.encryptionKey, 'existing-encryption-key')
        startWorker.assert_called_once_with(worker)


class DaemonLifecycleMixin:
    """Daemon start/stop and shares-management helpers, shared by any test class
    that needs a running background daemon (e.g. DaemonTest, DaemonBrowserTest,
    DaemonPreviewBrowserTest).

    Expects to be combined with FastFileLinkTestBase (uses self._testConfigDir,
    self._runCoreCommand, self._procLogFile, self.procLogPath, self._stopTestServer)."""

    daemonManagerClass = ProcessDaemonManager

    def setUp(self):
        super().setUp()
        self._daemonEnvOverrides = {}
        self._daemonEnvironmentOriginalValues = None
        self._daemonManager = self.daemonManagerClass()
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
        """Start the selected daemon host and verify its shared REST API is ready."""
        self._applyDaemonEnvironmentOverrides()
        if self._daemonEnvOverrides and isinstance(self._daemonManager, InProcessDaemonManager):
            self.reloadFeatureRuntime()

        if isinstance(self._daemonManager, InProcessDaemonManager):
            # InProcessDaemonManager hosts the daemon -- including the built-in
            # tunnel's AsyncTunnelThread -- as a thread in this same process. Real
            # GUI usage of this mode is mostly idle while the daemon runs, but this
            # test process also drives Selenium and spawns/polls CLI subprocesses
            # on the same GIL, which can starve the tunnel thread's scheduling badly
            # enough to cause spurious tunnel-relay 404s/reconnects under load
            # (confirmed: default 5ms switch interval let scheduling delays reach
            # 677ms and a test take 3.5x longer under synthetic contention; 1ms
            # eliminated the delays and roughly halved the slowdown). Not a
            # production fix -- production in-process hosting doesn't create this
            # contention -- so it's scoped to test setup only.
            #
            # Registered via addCleanup(), not a plain restore in _stopDaemon(),
            # because tearDown() (and thus _stopDaemon()) is never called by
            # unittest if anything below this point in setUp() raises -- that
            # would otherwise leak the lowered switch interval, at full 5x
            # context-switch overhead, into every later test in the whole suite
            # process for the rest of the run. addCleanup() runs regardless.
            originalSwitchInterval = sys.getswitchinterval()
            sys.setswitchinterval(0.001)
            self.addCleanup(sys.setswitchinterval, originalSwitchInterval)

        self._daemonManager.start()
        self._assertDaemonRunning()

    def _stopDaemon(self):
        try:
            if self._daemonManager.ownsDaemon:
                self._daemonManager.stop()
            else:
                ProcessDaemonManager.stopRunningDaemon(force=True)
        finally:
            self._restoreDaemonEnvironmentOverrides()

    def _applyDaemonEnvironmentOverrides(self):
        environmentKeys = set(self._daemonEnvOverrides)
        if 'FILESHARE_TEST' in environmentKeys and isinstance(self._daemonManager, InProcessDaemonManager):
            environmentKeys.add('TUNNEL_TOKEN_SERVER_URL')

        self._daemonEnvironmentOriginalValues = {
            key: os.environ.get(key)
            for key in environmentKeys
        }
        os.environ.update(self._daemonEnvOverrides)

    def _restoreDaemonEnvironmentOverrides(self):
        if self._daemonEnvironmentOriginalValues is None:
            return

        for key, value in self._daemonEnvironmentOriginalValues.items():
            if value is None:
                os.environ.pop(key)
            else:
                os.environ[key] = value

        self._daemonEnvironmentOriginalValues = None
        if self._daemonEnvOverrides and isinstance(self._daemonManager, InProcessDaemonManager):
            self.reloadFeatureRuntime()

    def _assertDaemonRunning(self):
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')
        self.assertTrue(os.path.exists(daemonJsonPath), "daemon.json should exist")
        with open(daemonJsonPath, 'r', encoding='utf-8') as f:
            state = json.load(f)
        pid = state.get('pid')
        self.assertIsNotNone(pid, "daemon.json should have pid")
        self.assertTrue(DaemonClient.isRunning(), f"Daemon API for PID {pid} should be running")

    def _assertDaemonNotRunning(self):
        daemonJsonPath = os.path.join(self._testConfigDir, 'daemon.json')
        self.assertFalse(os.path.exists(daemonJsonPath), "daemon.json should not exist after daemon stops")

    def _getFirstManagedShareId(self):
        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'list'], timeout=10)
        self.assertEqual(returnCode, 0, f"shares list failed: {output}")
        output = output.strip()
        print(f"[Test] shares list: {output}")

        # Skip blank lines, the header, and any unrelated log noise (e.g. wx's
        # "HH:MM:SS: Debug: ..." image-handler chatter) that can land on stdout
        # ahead of the real share line and would otherwise be mistaken for it.
        lines = [
            line.strip()
            for line in output.split('\n')
            if line.strip() and line.strip() != 'Active shares:' and 'Debug:' not in line
        ]
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

    def _waitForUploadTransferStart(self, testServerProcess, shareId, timeout=30):
        collectedLines = []
        logPath = getattr(testServerProcess, '_logPath', None)
        if logPath:
            deadline = time.time() + timeout
            offset = 0
            while time.time() < deadline:
                logFileHandle = getattr(testServerProcess, '_logFile', None)
                if logFileHandle:
                    logFileHandle.flush()

                if os.path.exists(logPath):
                    with open(logPath, 'r', encoding='utf-8', errors='replace') as logFile:
                        logFile.seek(offset)
                        newText = logFile.read()
                        offset = logFile.tell()

                    for line in newText.splitlines():
                        collectedLines.append(line)
                        print(f"[Test] test server output: {line}")
                        if 'Delaying upload chunk response' in line and f'for {shareId}' in line:
                            return

                if testServerProcess.poll() is not None:
                    break

                time.sleep(0.5)

            raise AssertionError(
                f"Timed out waiting for upload transfer to start for share {shareId}. "
                f"Recent test server output: {collectedLines[-10:]}"
            )

        outputQueue = queue.Queue()
        matchedEvent = threading.Event()

        def readTestServerOutput():
            streams = [stream for stream in (testServerProcess.stdout, testServerProcess.stderr) if stream is not None]
            while not matchedEvent.is_set():
                readAny = False
                for stream in streams:
                    line = stream.readline()
                    if not line:
                        continue

                    readAny = True
                    outputQueue.put(line.rstrip())

                if not readAny and testServerProcess.poll() is not None:
                    break

        readerThread = threading.Thread(target=readTestServerOutput, daemon=True, name='test-server-upload-watch')
        readerThread.start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            if testServerProcess.poll() is not None:
                break

            try:
                line = outputQueue.get(timeout=0.5)
            except queue.Empty:
                continue

            collectedLines.append(line)
            print(f"[Test] test server output: {line}")

            if 'Delaying upload chunk response' in line and f'for {shareId}' in line:
                matchedEvent.set()
                return

        matchedEvent.set()
        raise AssertionError(
            f"Timed out waiting for upload transfer to start for share {shareId}. "
            f"Recent test server output: {collectedLines[-10:]}"
        )

    def _waitForManagedShareCount(self, expectedCount, timeout=20):
        client = DaemonClient()
        deadline = time.time() + timeout
        while time.time() < deadline:
            shares = client.listShares()
            if len(shares) >= expectedCount:
                return shares

            time.sleep(0.3)

        raise AssertionError(f"Timed out waiting for {expectedCount} daemon-managed shares")

    def _waitForDaemonDownload(self, downloadId, timeout=120):
        deadline = time.time() + timeout
        client = DaemonClient()
        while time.time() < deadline:
            download = client.getDownload(downloadId)
            if download is None:
                raise AssertionError(f"Daemon download disappeared: {downloadId}")

            if download['status'] == 'completed':
                return download
            if download['status'] == 'failed':
                raise AssertionError(f"Daemon download failed: {download['error']}")

            time.sleep(0.3)

        raise AssertionError(f"Timed out waiting for daemon download {downloadId}")

    def _readLatestOutputText(self):
        if self._procLogFile:
            self._procLogFile.flush()

        with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as logFile:
            return logFile.read()

    def _waitForCoreProcessExit(self, timeout=120):
        self.assertIsNotNone(self.coreProcess, "Core process should have been started")
        self.coreProcess.wait(timeout=timeout)
        return self.coreProcess.returncode

    @contextlib.contextmanager
    def _usingTestFile(self, filePath, jsonPath=None):
        """Temporarily point self.testFilePath/jsonOutputPath/originalFileHash/
        originalFileSize at filePath for the duration of the `with` block,
        restoring the previous values afterward (even on exception). Lets a
        test start an additional daemon share -- and, while still inside the
        block, verify its download against the right hash/size -- without
        losing track of whichever file self.testFilePath pointed at before."""
        originalFilePath = self.testFilePath
        originalJsonPath = self.jsonOutputPath
        originalFileHash = self.originalFileHash
        originalFileSize = self.originalFileSize

        self.testFilePath = filePath
        self.jsonOutputPath = jsonPath or os.path.join(
            self.tempDir, f'{os.path.splitext(os.path.basename(filePath))[0]}_share_info.json'
        )
        self.originalFileHash = self.getFileHash(filePath)
        self.originalFileSize = os.path.getsize(filePath)
        try:
            yield
        finally:
            self.testFilePath = originalFilePath
            self.jsonOutputPath = originalJsonPath
            self.originalFileHash = originalFileHash
            self.originalFileSize = originalFileSize


class DaemonTest(DaemonLifecycleMixin, FastFileLinkTestBase):
    """Functional tests for the background daemon and multi-session share management."""

    def _waitForDaemonDownloadMatching(self, downloadId, predicate, timeout=30):
        client = DaemonClient()
        deadline = time.time() + timeout
        while time.time() < deadline:
            download = client.getDownload(downloadId)
            if download is None:
                raise AssertionError(f"Daemon download disappeared: {downloadId}")
            if download['status'] == 'failed':
                raise AssertionError(f"Daemon download failed: {download['error']}")
            if predicate(download):
                return download
            time.sleep(0.05)
        raise AssertionError(f"Timed out waiting for daemon download {downloadId} to match state")

    def _testDaemonDownloadPauseResumeCycles(self, forceHTTPFallback=False):
        """Exercise real daemon pause/resume repeatedly, then hash-verify output."""
        if forceHTTPFallback:
            self._stopDaemon()
            self._daemonEnvOverrides = {
                'DISABLE_P2P': 'True',
                'WEBRTC_CLI_SIMULATE_ICE_FAILURE': 'True',
            }
            self._startDaemon()

        sourcePath = os.path.join(self.tempDir, 'pause-resume-source.bin')
        self.generateRandomFile(sourcePath, 32 * 1024 * 1024)
        destinationPath = os.path.join(self.tempDir, 'pause-resume-download')
        os.makedirs(destinationPath)

        with self._usingTestFile(sourcePath):
            shareLink = self._startFastFileLink(p2p=True, timeout=120)
            client = DaemonClient()
            download = client.createDownload(shareLink, destinationPath)

            for cycle in range(3):
                activeDownload = self._waitForDaemonDownloadMatching(
                    download['id'],
                    lambda item: item['status'] == 'downloading' and item['pauseSupported'] and item['transferred'] > 0,
                )
                self.assertGreater(activeDownload['transferred'], 0)
                self.assertTrue(client.pauseDownload(download['id']), f'Pause failed in cycle {cycle + 1}')
                pausedDownload = self._waitForDaemonDownloadMatching(
                    download['id'], lambda item: item['status'] == 'paused',
                )
                self.assertGreater(pausedDownload['transferred'], 0)
                self.assertTrue(client.resumeDownload(download['id']), f'Resume failed in cycle {cycle + 1}')

            completedDownload = self._waitForDaemonDownload(download['id'], timeout=180)
            self.assertEqual(completedDownload['status'], 'completed')
            self._verifyDownloadedFile(completedDownload['outputPath'])

    def testDaemonDownloadPauseResumeCyclesOverWebRTC(self):
        """A FastFileLink WebRTC download survives three pause/resume cycles."""
        self._testDaemonDownloadPauseResumeCycles()

    def testDaemonDownloadPauseResumeCyclesOverHTTPFallback(self):
        """The same pause/resume contract works after FastFileLink falls back to HTTP."""
        self._testDaemonDownloadPauseResumeCycles(forceHTTPFallback=True)

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

    def testDaemonStartForwardsShareEventsToHook(self):
        """Both daemon hosts configure the hook supplied to start()."""
        self._stopDaemon()
        hookPath = os.path.join(self.tempDir, 'daemon-events.jsonl')
        self._daemonManager.start(hookPath)
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])

        deadline = time.time() + 20
        while time.time() < deadline:
            if os.path.exists(hookPath):
                with open(hookPath, 'r', encoding='utf-8') as hookFile:
                    events = [json.loads(line) for line in hookFile if line.strip()]
                if any(
                    event['event'] == FFLEvent.shareLinkCreate.key and event['data']['link'] == shareLink
                    for event in events
                ):
                    return

            time.sleep(0.5)

        self.fail('Daemon did not forward the share link event to its configured hook')

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

    def testDaemonDownloadUsesP2PForFastFileLinkURL(self):
        """A daemon-owned receiver download uses the normal FFL WebRTC path end to end."""
        shareLink = self._startFastFileLink(p2p=True)
        destinationPath = os.path.join(self.tempDir, 'daemon-download')
        os.makedirs(destinationPath)

        download = DaemonClient().createDownload(shareLink, destinationPath)
        completedDownload = self._waitForDaemonDownload(download['id'])

        self.assertEqual(completedDownload['status'], 'completed')
        self.assertTrue(completedDownload['outputPath'])
        self.assertTrue(os.path.isfile(completedDownload['outputPath']))
        self.assertGreater(completedDownload['transferred'], 0)
        self._verifyDownloadedFile(completedDownload['outputPath'])

    def testDaemonDownloadSupportsGenericHTTPURL(self):
        """A non-FFL URL stays on the downloader's direct HTTP transport."""
        sourcePath = os.path.join(self.tempDir, 'generic-daemon-source.bin')
        self.generateRandomFile(sourcePath, 256 * 1024)
        sourceHash = self.getFileHash(sourcePath)
        httpServer = ThreadingHTTPServer(
            ('127.0.0.1', 0),
            partial(SimpleHTTPRequestHandler, directory=self.tempDir),
        )
        serverThread = threading.Thread(target=httpServer.serve_forever, daemon=True)
        serverThread.start()
        destinationPath = os.path.join(self.tempDir, 'generic-daemon-download')
        os.makedirs(destinationPath)

        try:
            url = f'http://127.0.0.1:{httpServer.server_address[1]}/{os.path.basename(sourcePath)}'
            download = DaemonClient().createDownload(url, destinationPath)
            completedDownload = self._waitForDaemonDownload(download['id'])

            self.assertEqual(completedDownload['status'], 'completed')
            self.assertEqual(self.getFileHash(completedDownload['outputPath']), sourceHash)
        finally:
            httpServer.shutdown()
            serverThread.join(timeout=5)
            httpServer.server_close()

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

    def testDaemonUploadShareByPull(self):
        """Test daemon-managed background upload works when UPLOAD_METHOD=Pull."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer()
        self._testServerProcesses.append(testServerProcess)
        self._daemonEnvOverrides = {
            'FILESHARE_TEST': LOCAL_TEST_SERVER_URL,
            'UPLOAD_METHOD': 'Pull',
        }
        self._startDaemon()

        shareLink = self._startFastFileLink(p2p=False, extraArgs=['--background'])
        print(f"[Test] Daemon pull upload link: {shareLink}")

        with open(self.jsonOutputPath, 'r', encoding='utf-8') as fileHandle:
            shareInfo = json.load(fileHandle)
        self.assertEqual(shareInfo.get('upload_mode'), 'server', f"Expected server upload JSON output: {shareInfo}")

        downloadedFilePath = self._getDownloadedFilePath('daemon_pull_upload_share_test.bin')
        self.downloadFileWithRequests(shareLink, downloadedFilePath)
        self._verifyDownloadedFile(downloadedFilePath)

    def testDaemonMultiShareReusesTunnelAndPort(self):
        """Test daemon P2P shares reuse the same tunnel base URL and local server port."""
        firstLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()

        secondFilePath = os.path.join(self.tempDir, 'second_testfile.bin')
        self.generateRandomFile(secondFilePath, 512 * 1024)
        with self._usingTestFile(secondFilePath):
            secondLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])

        shares = self._waitForManagedShareCount(2)
        shareByLink = {share['link']: share for share in shares}
        firstShare = shareByLink[firstLink]
        secondShare = shareByLink[secondLink]

        self.assertNotEqual(firstShare['id'], secondShare['id'])
        self.assertEqual(firstShare['port'], secondShare['port'])
        self.assertEqual(firstLink.rsplit('/', 1)[0], secondLink.rsplit('/', 1)[0])

    def testDaemonSequentialSharesPlainThenE2EE(self):
        """Test a plain share followed by an E2EE share on the same daemon-shared
        server: each ServerSession must serve only its own file, with no size or
        content mixed in from another session sharing the same server/tunnel."""
        firstLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()

        firstDownloadPath = self._getDownloadedFilePath('daemon_sequential_first.bin')
        self.downloadFileWithRequests(firstLink, firstDownloadPath)
        self._verifyDownloadedFile(firstDownloadPath, shareLink=firstLink)

        secondFilePath = os.path.join(self.tempDir, 'second_e2ee_testfile.bin')
        self.generateRandomFile(secondFilePath, 512 * 1024)
        with self._usingTestFile(secondFilePath):
            secondLink = self._startFastFileLink(p2p=True, extraArgs=['--background', '--e2ee'])

        secondDownloadPath = self._getDownloadedFilePath('daemon_sequential_second_e2ee.bin')
        transferChecksum = self.downloadFileWithRequests(secondLink, secondDownloadPath)
        # verifyOriginalContent=False: a plain requests download of an E2EE share
        # receives ciphertext, not plaintext, so it won't hash-match the source
        # file -- but it still cross-checks downloaded size/checksum against the
        # /checksum endpoint, which is enough to catch a size-mismatch regression.
        self._verifyDownloadedFile(
            secondDownloadPath,
            shareLink=secondLink,
            transferChecksum=transferChecksum,
            verifyOriginalContent=False,
        )

    def testDaemonUploadShareStop(self):
        """Test stopping an in-flight daemon upload cancels it and removes it from active shares."""
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        testServerProcess = self._startTestServer(
            extraEnvVars={'TEST_UPLOAD_CHUNK_DELAY_MS': '1000'},
            captureOutput=False,
        )
        self._testServerProcesses.append(testServerProcess)
        self._daemonEnvOverrides = {
            'FILESHARE_TEST': LOCAL_TEST_SERVER_URL,
            'UPLOAD_METHOD': 'Push',
            'UPLOAD_CHUNK_SIZE': str(8 * 1024 * 1024),
            'UPLOAD_CONCURRENCY': '1',
            'UPLOAD_NO_RETRY': 'True',
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
        self._waitForUploadTransferStart(testServerProcess, shareId)
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

        self._startFastFileLink(
            p2p=False,
            extraEnvVars={'FILESHARE_TEST': LOCAL_TEST_SERVER_URL},
            extraArgs=['--background'],
            inputData='yes\n',
            autoConfirmUpload=False,
        )
        self._assertDaemonRunning()

        returnCode = self._waitForCoreProcessExit()
        output = self._readLatestOutputText()

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

        self._startFastFileLink(
            p2p=False,
            extraEnvVars={'FILESHARE_TEST': LOCAL_TEST_SERVER_URL},
            inputData='yes\n',
            autoConfirmUpload=False,
        )
        self._assertDaemonRunning()

        returnCode = self._waitForCoreProcessExit()
        output = self._readLatestOutputText()

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

        shareId = self._getFirstManagedShareId()
        shareData = DaemonClient().getShare(shareId)
        self.assertEqual(shareData['shareRequest']['recipientAuth'], 'pickup')
        self.assertEqual(shareData['shareRequest']['pickupCode'], pickupCode)

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


class DaemonBrowserTest(DaemonLifecycleMixin, BrowserTestBase):
    """Real-browser tests against the daemon-shared server (multiple ServerSessions
    behind one origin), to catch bugs that only show up in the browser's own
    download/decryption path -- not reproducible with a plain requests.get()."""

    def testDaemonSequentialSharesPlainThenE2EEBrowserDownload(self):
        """Share a plain file, download+verify it in a browser, then -- in that
        SAME browser session/tab -- share a second file with --e2ee and
        download+verify it too. Both shares live on the same daemon-shared
        origin (one server, one tunnel, two UIDs), so any state the page/Service
        Worker/DownloadManager keeps that isn't properly scoped per-UID would
        leak from the first download into the second."""
        firstLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()

        downloadDir = self._getBrowserDownloadDir('chrome', 0)
        driver = self._setupChromeDriver(downloadDir)

        firstDownloadedFile = self._downloadWithBrowser(
            driver, firstLink, downloadDir, 'testfile.bin', disableFallback=False
        )
        self._verifyDownloadedFile(firstDownloadedFile)
        print("[Test] First (plain) share downloaded and verified via browser")

        secondFilePath = os.path.join(self.tempDir, 'second_e2ee_testfile.bin')
        self.generateRandomFile(secondFilePath, 512 * 1024)
        # _verifyDownloadedFile compares against self.originalFileHash/originalFileSize,
        # so it must run inside this block, before _usingTestFile restores them.
        with self._usingTestFile(secondFilePath):
            secondLink = self._startFastFileLink(p2p=True, extraArgs=['--background', '--e2ee'])

            secondDownloadedFile = self._downloadWithBrowser(
                driver, secondLink, downloadDir, 'second_e2ee_testfile.bin', disableFallback=False
            )
            self._verifyDownloadedFile(secondDownloadedFile)
            print("[Test] Second (E2EE) share downloaded and verified via browser")


class InProcessDaemonTest(DaemonTest):
    """Run the daemon functional suite against a daemon hosted by this test process."""

    daemonManagerClass = InProcessDaemonManager


class InProcessDaemonBrowserTest(DaemonBrowserTest):
    """Run the browser daemon suite against a daemon hosted by this test process."""

    daemonManagerClass = InProcessDaemonManager


if PreviewBrowserE2EETest is not None:

    class DaemonPreviewBrowserTest(DaemonLifecycleMixin, PreviewBrowserE2EETest):
        """Real-browser ZIP-preview test against the daemon-shared server. Reuses
        PreviewBrowserE2EETest's folder fixture and preview helpers, but shares it
        as the daemon's SECOND session (after a first, unrelated plain share) to
        reproduce bugs that only show up once a share is not the sole/most-recent
        session on the shared origin -- e.g. root-relative API calls that resolve
        via getDefaultSession() instead of the request's own UID."""

        @unittest.skipIf(SKIP_GUI_TEST, "Preview browser tests disabled because no GUI")
        def testDaemonSecondShareE2EEFolderPreview(self):
            """Second share on a daemon-shared origin: an E2EE folder share whose
            ZIP preview modal must load real (decrypted) manifest entries, not get
            stuck on 'Establishing connection...'."""
            firstFilePath = os.path.join(self.tempDir, 'daemon_preview_first.bin')
            self.generateRandomFile(firstFilePath, 64 * 1024)
            with self._usingTestFile(firstFilePath):
                self._startFastFileLink(p2p=True, extraArgs=['--background'])
                self._terminateProcess()
            print("[Test] First (plain) share started on daemon")

            # _usingTestFile above restored self.testFilePath/jsonOutputPath to the
            # E2EE folder fixture PreviewBrowserE2EETest.setUp() already set up.
            shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background', '--e2ee'])
            print(f"[Test] Second (folder, E2EE) share link: {shareLink}")

            downloadDir = self._getBrowserDownloadDir('chrome', 0)
            driver = self._setupChromeDriver(downloadDir)

            previewUrl = self._withQueryParams(shareLink, {'preview': 'true', 'debug': '1'})
            print(f"[Test] Preview URL: {previewUrl}")
            driver.get(previewUrl)

            self._waitForPreviewMetadataReady(driver)

            fileResult, expectedPath = self._fetchPreviewEntryBlob(driver)

            isPreviewableZip = driver.execute_script(
                "return window.previewUI ? window.previewUI.isPreviewableZip : null;"
            )
            metadataInitError = driver.execute_script(
                "return window.previewUI && window.previewUI.extractor "
                "? window.previewUI.extractor.__testMetaInitError : null;"
            )
            entryCount = driver.execute_script(
                "return window.previewUI && window.previewUI.extractor && window.previewUI.extractor.meta "
                "? (window.previewUI.extractor.meta.entries || []).length : 0;"
            )

            self.assertEqual(
                isPreviewableZip, True,
                f"Expected daemon second-share E2EE ZIP to be recognized as previewable, got {isPreviewableZip}"
            )
            self.assertIsNone(
                metadataInitError,
                f"Extractor metadata init failed on daemon-shared server: {metadataInitError}"
            )
            self.assertGreater(
                entryCount, 0,
                f"Expected decrypted manifest entries > 0, got {entryCount}; metadataInitError={metadataInitError}"
            )

            self._assertPreviewEntryMatchesSource(fileResult, expectedPath)


    class InProcessDaemonPreviewBrowserTest(DaemonPreviewBrowserTest):
        """Run the preview daemon suite against a daemon hosted by this test process."""

        daemonManagerClass = InProcessDaemonManager


if __name__ == '__main__':
    unittest.main()
