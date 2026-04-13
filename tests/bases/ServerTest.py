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

import json
import os
import threading
import time
import unittest
from urllib.parse import urlparse

import requests

from bases.Server import LogicalDownloadRequestStore

from ..BrowserTestBase import BrowserTestBase
from ..CoreTestBase import FastFileLinkTestBase


class LogicalDownloadRequestStoreTest(unittest.TestCase):
    """Unit tests for same-dl overlap tracking independent of HTTP plumbing."""

    def testOverlappingNewRequestSupersedesOlderOne(self):
        store = LogicalDownloadRequestStore()

        superseded = store.register('same-dl', 'req-1', 0, 1023)
        self.assertEqual(superseded, [])
        self.assertFalse(store.isSuperseded('same-dl', 'req-1'))

        superseded = store.register('same-dl', 'req-2', 512, 2047)
        self.assertEqual(superseded, ['req-1'])
        self.assertTrue(store.isSuperseded('same-dl', 'req-1'))
        self.assertFalse(store.isSuperseded('same-dl', 'req-2'))

    def testNonOverlappingRangesDoNotSupersede(self):
        store = LogicalDownloadRequestStore()

        store.register('same-dl', 'req-1', 0, 1023)
        superseded = store.register('same-dl', 'req-2', 2048, 4095)

        self.assertEqual(superseded, [])
        self.assertFalse(store.isSuperseded('same-dl', 'req-1'))
        self.assertFalse(store.isSuperseded('same-dl', 'req-2'))

    def testDifferentLogicalDlDoNotInterfere(self):
        store = LogicalDownloadRequestStore()

        store.register('dl-a', 'req-1', 0, None)
        superseded = store.register('dl-b', 'req-2', 0, None)

        self.assertEqual(superseded, [])
        self.assertFalse(store.isSuperseded('dl-a', 'req-1'))
        self.assertFalse(store.isSuperseded('dl-b', 'req-2'))

    def testUnboundedRangeOverlapsAndLatestWins(self):
        store = LogicalDownloadRequestStore()

        store.register('same-dl', 'req-1', 0, None)
        superseded = store.register('same-dl', 'req-2', 1024, None)

        self.assertEqual(superseded, ['req-1'])
        self.assertTrue(store.isSuperseded('same-dl', 'req-1'))
        self.assertFalse(store.isSuperseded('same-dl', 'req-2'))

    def testUnregisterRemovesTracking(self):
        store = LogicalDownloadRequestStore()

        store.register('same-dl', 'req-1', 0, 1023)
        store.unregister('same-dl', 'req-1')

        self.assertFalse(store.isSuperseded('same-dl', 'req-1'))


class DiagnosisEndpointTest(FastFileLinkTestBase):
    """Functional tests for the /diagnosis stall-report endpoint and server-side stall detection.

    Tests cover three layers:
    1. /diagnosis endpoint — accepts SW stall reports, returns 200 ok.
    2. Stall injection — ?stall-after=N blocks the HTTP download at N bytes.
    3. /status-based stall detection — server detects a stalled download and
       calls /diagnosis via the public tunnel URL on its own.

    Run with:
        STALL_DETECTION_SECONDS=3 python -m unittest tests.bases.ServerTest.DiagnosisEndpointTest
    """

    def _parseShareLink(self, shareLink):
        """Return (baseUrl, uid) from a share link like http://host:port/uid."""
        parsed = urlparse(shareLink.rstrip('/'))
        baseUrl = f'{parsed.scheme}://{parsed.netloc}'
        uid = parsed.path.lstrip('/')
        return baseUrl, uid

    def _diagnosisParams(self, **overrides):
        """Return a baseline set of query params for /diagnosis."""
        base = {
            'type': 'http',
            'phase': 'mid-stream',
            'delivered': '1024',
            'total': str(self.originalFileSize),
            'stall_ms': '5000',
            'percent': '0.10',
            'probe_status': '206',
            'range_ok': 'true',
            'has_auth': 'false',
            'browser': 'chrome',
            'ff_pass': 'false',
            'e2ee': 'false',
            'resume': 'false',
            'dl': 'test-dl-id-1234',
        }
        base.update(overrides)
        return base

    # -------------------------------------------------------------------------
    # /diagnosis endpoint tests
    # -------------------------------------------------------------------------

    def testDiagnosisEndpointAcceptsStallReport(self):
        """GET /diagnosis should accept a stall report and return 200 ok."""
        shareLink = self._startFastFileLink(p2p=True)

        baseUrl, uid = self._parseShareLink(shareLink)
        response = requests.get(
            f'{baseUrl}/{uid}/diagnosis',
            params=self._diagnosisParams(),
            timeout=10,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'ok')

    def testDiagnosisEndpointAcceptsDifferentPhases(self):
        """GET /diagnosis should work for all stall phases."""
        shareLink = self._startFastFileLink(p2p=True)

        baseUrl, uid = self._parseShareLink(shareLink)
        diagnosisUrl = f'{baseUrl}/{uid}/diagnosis'

        for phase in ('first-byte', 'mid-stream', 'tail'):
            with self.subTest(phase=phase):
                delivered = '0' if phase == 'first-byte' else '999000'
                percent   = '0.00' if phase == 'first-byte' else '99.90'
                response  = requests.get(
                    diagnosisUrl,
                    params=self._diagnosisParams(
                        phase=phase,
                        delivered=delivered,
                        percent=percent,
                    ),
                    timeout=10,
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, b'ok')

    # -------------------------------------------------------------------------
    # Stall injection + /diagnosis (SW simulation)
    # -------------------------------------------------------------------------

    def testStallInjectionBlocksDownloadMidStream(self):
        """?stall-after=N blocks the HTTP download at N bytes.

        End-to-end flow:
        1. Background thread starts a streaming download with ?stall-after=512.
        2. Server writes 512 bytes then sleeps indefinitely — simulating a stall.
        3. We verify the thread is still alive (blocked).
        4. We call /diagnosis to simulate the SW stall report — must return 200 ok.
        """
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, captureOutputIn=outputCapture)

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl  = f'{baseUrl}/{uid}/download'
        diagnosisUrl = f'{baseUrl}/{uid}/diagnosis'

        stallAfterBytes  = 512
        downloadError    = []
        downloadFinished = threading.Event()

        def stallDownload():
            try:
                with requests.get(
                    downloadUrl,
                    params={'stall-after': str(stallAfterBytes)},
                    stream=True,
                    timeout=None,
                ) as resp:
                    for chunk in resp.iter_content(chunk_size=256):
                        pass  # blocks indefinitely once server stalls
            except Exception as exc:
                downloadError.append(exc)
            finally:
                downloadFinished.set()

        threading.Thread(target=stallDownload, daemon=True).start()

        # Poll for the flushPrint stall-injection marker (up to 12 s)
        stallLogged = False
        for _i in range(60):
            time.sleep(0.2)
            if '[Test] Stall injection' in self._updateCapturedOutput(outputCapture):
                stallLogged = True
                break

        if not stallLogged:
            # Fallback: thread must still be alive (blocked by sleep 9999)
            self.assertFalse(
                downloadFinished.wait(timeout=0),
                'Download finished before stall confirmed. Errors: ' + str(downloadError),
            )

        # Simulate what the SW would send to /diagnosis while the download is stalled
        diagResponse = requests.get(
            diagnosisUrl,
            params=self._diagnosisParams(
                phase='mid-stream',
                delivered=str(stallAfterBytes),
                percent=f'{stallAfterBytes / self.originalFileSize * 100:.2f}',
                stall_ms='3000',
                dl='stall-test-dl-id',
            ),
            timeout=10,
        )
        self.assertEqual(diagResponse.status_code, 200)
        self.assertEqual(diagResponse.content, b'ok')

    # -------------------------------------------------------------------------
    # /status-based server-side stall detection
    # -------------------------------------------------------------------------

    def testStatusEndpointDetectsStallAndCallsDiagnosis(self):
        """Server detects a stalled download via /status and fires /diagnosis itself.

        The stall threshold is controlled by STALL_DETECTION_SECONDS (default 60 s).
        Set it to 3 s before running so the test completes quickly.

        Flow:
        1. Download stalls at 512 bytes via ?stall-after=512.
        2. We wait past the threshold so the stall is detectable.
        3. We call GET /status — this triggers stall detection.
        4. The server fires /diagnosis asynchronously via the public URL.
        5. We verify /status returns 200 with the expected JSON structure.
        6. We verify FFL_DIAGNOSIS_LOG contains the server-side stall report
           with the correct phase, delivered bytes, and source=server.
        """
        outputCapture = {}
        diagLogPath = os.path.join(self.tempDir, 'diagnosis.log')
        shareLink = self._startFastFileLink(
            p2p=True,
            captureOutputIn=outputCapture,
            extraEnvVars={'FFL_DIAGNOSIS_LOG': diagLogPath},
        )

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl = f'{baseUrl}/{uid}/download'
        statusUrl   = f'{baseUrl}/{uid}/status'

        stallAfterBytes  = 512
        downloadFinished = threading.Event()

        def stallDownload():
            try:
                with requests.get(
                    downloadUrl,
                    params={'stall-after': str(stallAfterBytes)},
                    stream=True,
                    timeout=None,
                ) as resp:
                    for chunk in resp.iter_content(chunk_size=256):
                        pass
            except Exception as exc:
                print(f'[Test] Stall download thread ended with: {exc}')
            finally:
                downloadFinished.set()

        threading.Thread(target=stallDownload, daemon=True).start()

        stallConfirmed = False
        for _i in range(60):
            time.sleep(0.2)
            if '[Test] Stall injection' in self._updateCapturedOutput(outputCapture):
                stallConfirmed = True
                break

        if not stallConfirmed:
            self.assertFalse(
                downloadFinished.wait(timeout=0),
                'Download finished before stall injection confirmed',
            )

        # Wait past the stall threshold (STALL_DETECTION_SECONDS + 1 s margin)
        stallThreshold = int(os.getenv('STALL_DETECTION_SECONDS', '60'))
        time.sleep(stallThreshold + 1)

        # Trigger /status — server detects the stall and fires /diagnosis
        statusResponse = requests.get(statusUrl, timeout=10)
        self.assertEqual(statusResponse.status_code, 200)
        self.assertIn('error', statusResponse.json())

        # Give the async /diagnosis thread time to write to the log
        time.sleep(2)

        # Verify the server actually called /diagnosis with correct parameters
        self.assertTrue(os.path.exists(diagLogPath), 'FFL_DIAGNOSIS_LOG was not created — /diagnosis was never called')
        with open(diagLogPath, 'r', encoding='utf-8') as f:
            entries = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(entries), 1, f'Expected 1 diagnosis entry, got {len(entries)}: {entries}')
        entry = entries[0]
        self.assertEqual(entry['source'], 'server', 'Expected source=server for server-side stall detection')
        self.assertEqual(entry['phase'], 'mid-stream', f'Expected phase=mid-stream, got {entry["phase"]}')
        self.assertEqual(entry['delivered'], str(stallAfterBytes), f'Expected delivered={stallAfterBytes}, got {entry["delivered"]}')

    def testStatusDetectsMultipleSimultaneousStalls(self):
        """DownloadProgressStore tracks each download independently.

        Two downloads stall at different byte offsets while one completes normally.
        /status must detect only the two stalled downloads and fire /diagnosis for
        each — not for the completed one.  Verified by:
        - Both stalled threads remain blocked throughout.
        - The active download completes before the stall threshold.
        - FFL_DIAGNOSIS_LOG contains exactly 2 entries (one per stalled download).
        - Neither entry corresponds to the completed download.
        - A second /status poll fires no duplicates (stallReported guard).
        """
        outputCapture = {}
        diagLogPath = os.path.join(self.tempDir, 'diagnosis.log')
        shareLink = self._startFastFileLink(
            p2p=True,
            captureOutputIn=outputCapture,
            extraEnvVars={'FFL_DIAGNOSIS_LOG': diagLogPath},
        )

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl = f'{baseUrl}/{uid}/download'
        statusUrl   = f'{baseUrl}/{uid}/status'

        stallPoints   = [256, 512]
        finishedFlags = [threading.Event(), threading.Event()]

        def makeStallDownload(stallAfter, finishedFlag):
            def run():
                try:
                    with requests.get(
                        downloadUrl,
                        params={'stall-after': str(stallAfter)},
                        stream=True,
                        timeout=None,
                    ) as resp:
                        for chunk in resp.iter_content(chunk_size=128):
                            pass
                except Exception as exc:
                    print(f'[Test] Stall download thread (stall-after={stallAfter}) ended with: {exc}')
                finally:
                    finishedFlag.set()
            return run

        for sp, ff in zip(stallPoints, finishedFlags):
            threading.Thread(target=makeStallDownload(sp, ff), daemon=True).start()

        # Start one active (non-stalled) download — it should complete quickly and
        # must NOT appear in the diagnosis log after /status fires stall reports.
        activeDownloadDone = threading.Event()

        def activeDownload():
            try:
                with requests.get(downloadUrl, stream=True, timeout=30) as resp:
                    for chunk in resp.iter_content(chunk_size=65536):
                        pass
            except Exception as exc:
                print(f'[Test] Active download thread ended with: {exc}')
            finally:
                activeDownloadDone.set()

        threading.Thread(target=activeDownload, daemon=True).start()

        # Wait until both stall-injection log lines appear (up to 15 s)
        stallCount = 0
        for _i in range(75):
            time.sleep(0.2)
            stallCount = self._updateCapturedOutput(outputCapture).count('[Test] Stall injection')
            if stallCount >= 2:
                break

        if stallCount < 2:
            for idx, (ff, sp) in enumerate(zip(finishedFlags, stallPoints)):
                self.assertFalse(
                    ff.wait(timeout=0),
                    f'Download {idx} (stall-after={sp}) finished unexpectedly',
                )

        # The active download must complete well before the stall threshold
        self.assertTrue(
            activeDownloadDone.wait(timeout=10),
            'Active download did not complete within 10 s — it should not have stalled',
        )

        stallThreshold = int(os.getenv('STALL_DETECTION_SECONDS', '60'))
        time.sleep(stallThreshold + 1)

        # First /status poll — detects and reports both stalls (not the completed download)
        statusResponse = requests.get(statusUrl, timeout=10)
        self.assertEqual(statusResponse.status_code, 200)
        self.assertIn('error', statusResponse.json())

        # Second /status poll — stallReported=True for both, no duplicates fired
        self.assertEqual(requests.get(statusUrl, timeout=10).status_code, 200)

        # Both stalled threads must still be blocked
        for idx, (ff, sp) in enumerate(zip(finishedFlags, stallPoints)):
            self.assertFalse(
                ff.wait(timeout=0),
                f'Download {idx} (stall-after={sp}) should still be blocked',
            )

        # Give the async /diagnosis threads time to write to the log
        time.sleep(2)

        # Verify the log: exactly 2 entries, both server-sourced, none from the active download
        self.assertTrue(os.path.exists(diagLogPath), 'FFL_DIAGNOSIS_LOG was not created — /diagnosis was never called')
        with open(diagLogPath, 'r', encoding='utf-8') as f:
            entries = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(entries), 2, f'Expected 2 diagnosis entries (one per stall), got {len(entries)}: {entries}')

        for entry in entries:
            self.assertEqual(entry['source'], 'server', f'Expected source=server, got: {entry}')

        deliveredValues = {int(entry['delivered']) for entry in entries}
        self.assertEqual(
            deliveredValues, {256, 512},
            f'Expected delivered bytes {{256, 512}}, got {deliveredValues}',
        )


class OverlappingDownloadReproTest(FastFileLinkTestBase):
    """Regression tests for same-dl HTTP relay overlap handling."""

    def __init__(self, methodName='runTest', fileSizeBytes=4 * 1024 * 1024):
        super().__init__(methodName, fileSizeBytes)

    def _parseShareLink(self, shareLink):
        parsed = urlparse(shareLink.rstrip('/'))
        baseUrl = f'{parsed.scheme}://{parsed.netloc}'
        uid = parsed.path.lstrip('/')
        return baseUrl, uid

    def _waitForStallInjection(self, outputCapture, timeoutSeconds=12):
        deadline = time.time() + timeoutSeconds
        while time.time() < deadline:
            output = self._updateCapturedOutput(outputCapture) or ""
            if '[Test] Stall injection' in output:
                return True
            time.sleep(0.2)
        return False

    def testSameDlOverlappingRangeSupersedesOlderRequest(self):
        """A newer overlapping same-dl request should supersede the older one.

        Before the fix, this scenario allowed both requests to stay active and
        duplicate sender traffic. The older stalled request now exits promptly
        once a newer overlapping request arrives under the same logical dl.
        """
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, captureOutputIn=outputCapture)

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl = f'{baseUrl}/{uid}/download'
        logicalDl = 'same-dl-overlap-repro'
        stallAfterBytes = 1024 * 1024
        rangeStart = stallAfterBytes // 2

        firstRequestStatus = []
        firstRequestError = []
        firstRequestFinished = threading.Event()

        def blockedDownload():
            try:
                with requests.get(
                    downloadUrl,
                    params={'dl': logicalDl, 'stall-after': str(stallAfterBytes)},
                    stream=True,
                    timeout=None,
                ) as response:
                    firstRequestStatus.append(response.status_code)
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
            except Exception as exc:
                firstRequestError.append(exc)
            finally:
                firstRequestFinished.set()

        threading.Thread(target=blockedDownload, daemon=True).start()

        stalled = self._waitForStallInjection(outputCapture)
        if not stalled:
            self.assertFalse(
                firstRequestFinished.wait(timeout=0),
                f"First request finished before stall injection was confirmed: {firstRequestError}",
            )

        self.assertEqual(firstRequestStatus, [200], f"Expected initial full download to return 200, got {firstRequestStatus}")
        self.assertFalse(firstRequestFinished.is_set(), "First same-dl request should still be blocked at stall point")

        with requests.get(
            downloadUrl,
            params={'dl': logicalDl},
            headers={'Range': f'bytes={rangeStart}-'},
            stream=True,
            timeout=30,
        ) as overlapResponse:
            self.assertEqual(
                overlapResponse.status_code, 206,
                f"Expected same-dl overlap request to resume with 206, got {overlapResponse.status_code}"
            )
            self.assertIn('Content-Range', overlapResponse.headers)

            overlappedBytes = 0
            for chunk in overlapResponse.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                overlappedBytes += len(chunk)
                if overlappedBytes >= 65536:
                    break

        self.assertGreater(overlappedBytes, 0, "Expected newer same-dl range request to receive bytes")
        supersededLogged = False
        deadline = time.time() + 5
        while time.time() < deadline:
            output = self._updateCapturedOutput(outputCapture) or ""
            if 'Connection disconnected, wait retrying.' in output:
                supersededLogged = True
                break
            time.sleep(0.2)

        self.assertTrue(
            supersededLogged,
            "Expected server to log that the older overlapping same-dl request was disconnected"
        )

    def testDifferentDlStillAllowsIndependentOverlappingRequests(self):
        """Different logical dl values should not interfere with each other."""
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, captureOutputIn=outputCapture)

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl = f'{baseUrl}/{uid}/download'
        stallAfterBytes = 1024 * 1024

        firstRequestStatus = []
        firstRequestError = []
        firstRequestFinished = threading.Event()

        def blockedDownload():
            try:
                with requests.get(
                    downloadUrl,
                    params={'dl': 'logical-dl-a', 'stall-after': str(stallAfterBytes)},
                    stream=True,
                    timeout=None,
                ) as response:
                    firstRequestStatus.append(response.status_code)
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
            except Exception as exc:
                firstRequestError.append(exc)
            finally:
                firstRequestFinished.set()

        threading.Thread(target=blockedDownload, daemon=True).start()

        stalled = self._waitForStallInjection(outputCapture)
        if not stalled:
            self.assertFalse(
                firstRequestFinished.wait(timeout=0),
                f"First request finished before stall injection was confirmed: {firstRequestError}",
            )

        self.assertEqual(firstRequestStatus, [200], f"Expected initial full download to return 200, got {firstRequestStatus}")
        self.assertFalse(firstRequestFinished.is_set(), "First request should still be stalled")

        with requests.get(
            downloadUrl,
            params={'dl': 'logical-dl-b'},
            headers={'Range': f'bytes={stallAfterBytes // 2}-'},
            stream=True,
            timeout=30,
        ) as overlapResponse:
            self.assertEqual(overlapResponse.status_code, 206)
            overlappedBytes = 0
            for chunk in overlapResponse.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                overlappedBytes += len(chunk)
                if overlappedBytes >= 65536:
                    break

        self.assertGreater(overlappedBytes, 0, "Expected independent different-dl request to receive bytes")
        self.assertFalse(
            firstRequestFinished.wait(timeout=1),
            "Expected stalled request with different dl to remain active"
        )

    def testSameDlNonOverlappingRangesCanCoexist(self):
        """Same logical dl should only supersede truly overlapping byte ranges."""
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, captureOutputIn=outputCapture)

        baseUrl, uid = self._parseShareLink(shareLink)
        downloadUrl = f'{baseUrl}/{uid}/download'
        logicalDl = 'same-dl-non-overlap'

        firstRequestStatus = []
        firstRequestError = []
        firstRequestFinished = threading.Event()

        def blockedRangeDownload():
            try:
                with requests.get(
                    downloadUrl,
                    params={'dl': logicalDl, 'stall-after': '524288'},
                    headers={'Range': 'bytes=0-1048575'},
                    stream=True,
                    timeout=None,
                ) as response:
                    firstRequestStatus.append(response.status_code)
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
            except Exception as exc:
                firstRequestError.append(exc)
            finally:
                firstRequestFinished.set()

        threading.Thread(target=blockedRangeDownload, daemon=True).start()

        stalled = self._waitForStallInjection(outputCapture)
        if not stalled:
            self.assertFalse(
                firstRequestFinished.wait(timeout=0),
                f"First request finished before stall injection was confirmed: {firstRequestError}",
            )

        self.assertEqual(firstRequestStatus, [206], f"Expected initial range download to return 206, got {firstRequestStatus}")
        self.assertFalse(firstRequestFinished.is_set(), "First non-overlapping range request should still be stalled")

        with requests.get(
            downloadUrl,
            params={'dl': logicalDl},
            headers={'Range': 'bytes=2097152-3145727'},
            stream=True,
            timeout=30,
        ) as secondRangeResponse:
            self.assertEqual(secondRangeResponse.status_code, 206)
            secondRangeBytes = 0
            for chunk in secondRangeResponse.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                secondRangeBytes += len(chunk)
                if secondRangeBytes >= 65536:
                    break

        self.assertGreater(secondRangeBytes, 0, "Expected non-overlapping same-dl range request to receive bytes")
        self.assertFalse(
            firstRequestFinished.wait(timeout=1),
            "Expected non-overlapping same-dl stalled request to remain active"
        )


class BrowserOverlapDownloadReproTest(BrowserTestBase):
    """Browser-assisted repro closer to the real user path.

    The first HTTP /download is started by the actual share page in Chrome
    (native browser download path with Service Worker enabled). While that
    native download is active, the test issues a second same-dl Range fetch
    from the same browser session and verifies the server serves it too.
    """

    def __init__(self, methodName='runTest', fileSizeBytes=64 * 1024 * 1024):
        super().__init__(methodName, fileSizeBytes=fileSizeBytes)

    def _parseShareLink(self, shareLink):
        parsed = urlparse(shareLink.rstrip('/'))
        baseUrl = f'{parsed.scheme}://{parsed.netloc}'
        uid = parsed.path.lstrip('/')
        return baseUrl, uid

    def _findLargestPartial(self, downloadDir):
        largestPath = None
        largestSize = 0
        if not os.path.isdir(downloadDir):
            return None, 0

        for filename in os.listdir(downloadDir):
            if not (filename.endswith('.crdownload') or filename.endswith('.part') or filename.endswith('.tmp')):
                continue

            filePath = os.path.join(downloadDir, filename)
            try:
                size = os.path.getsize(filePath)
            except OSError:
                continue

            if size > largestSize:
                largestPath = filePath
                largestSize = size

        return largestPath, largestSize

    def _waitForBrowserNativeDownloadStart(self, driver, downloadDir, minPartialBytes=256 * 1024, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            activeDlId = driver.execute_script(
                """
                return window.webrtcManager?.fallbackManager?.downloadManager?.activeDlId || null;
                """
            )
            partialPath, partialSize = self._findLargestPartial(downloadDir)
            if activeDlId and partialSize >= minPartialBytes:
                return {
                    'dl': activeDlId,
                    'partialPath': partialPath,
                    'partialSize': partialSize,
                }
            time.sleep(0.5)

        activeDlId = driver.execute_script(
            """
            return window.webrtcManager?.fallbackManager?.downloadManager?.activeDlId || null;
            """
        )
        partialPath, partialSize = self._findLargestPartial(downloadDir)
        raise AssertionError(
            f"Browser native download did not reach active state in time: dl={activeDlId}, partial={partialPath}, size={partialSize}"
        )

    def _loadJsonLines(self, path):
        if not os.path.exists(path):
            return []

        entries = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entries.append(json.loads(line))
        return entries

    def testBrowserPageAllowsOverlappingSameDlRangeFetchRepro(self):
        """Reproduce same-dl overlap with a real Chrome-started native download.

        This is intentionally closer to the user path than the pure requests-based
        repro: the first /download comes from the actual share page and browser
        download manager, not from a synthetic requests client.
        """
        shareLink = self._startFastFileLink(p2p=True)
        baseUrl, uid = self._parseShareLink(shareLink)

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self._attachConsoleMirror(driver)

        shareUrl = f"{shareLink}?webrtc=0&debug=1"
        print(f"[Test] Navigating browser to: {shareUrl}")
        driver.get(shareUrl)

        browserDownload = self._waitForBrowserNativeDownloadStart(driver, self.chromeDownloadDir)
        logicalDl = browserDownload['dl']
        print(
            f"[Test] Browser-native download started with dl={logicalDl}, "
            f"partial={browserDownload['partialSize']} bytes"
        )

        overlapResult = driver.execute_async_script(
            """
            const uid = arguments[0];
            const dl = arguments[1];
            const offset = arguments[2];
            const done = arguments[arguments.length - 1];

            (async () => {
                const url = new URL(`/${uid}/download`, window.location.origin);
                url.searchParams.set('dl', dl);

                const response = await fetch(url.toString(), {
                    headers: { 'Range': `bytes=${offset}-` },
                    cache: 'no-cache'
                });

                const contentRange = response.headers.get('Content-Range');
                let bytesRead = 0;
                if (response.body) {
                    const reader = response.body.getReader();
                    const first = await reader.read();
                    if (!first.done && first.value) {
                        bytesRead = first.value.byteLength;
                    }
                    try { await reader.cancel(); } catch (_e) {}
                }

                done({
                    status: response.status,
                    contentRange,
                    bytesRead
                });
            })().catch(error => {
                done({ error: String(error) });
            });
            """,
            uid,
            logicalDl,
            1024 * 1024,
        )

        print(f"[Test] Overlap fetch result: {overlapResult}")
        self.assertNotIn('error', overlapResult, f"Unexpected browser overlap error: {overlapResult}")
        self.assertEqual(
            overlapResult.get('status'), 206,
            f"Expected browser overlap request to get 206, got {overlapResult}"
        )
        self.assertTrue(
            overlapResult.get('contentRange'),
            f"Expected Content-Range header on overlapping browser fetch, got {overlapResult}"
        )
        self.assertGreater(
            overlapResult.get('bytesRead', 0), 0,
            f"Expected overlapping browser fetch to receive bytes, got {overlapResult}"
        )

    @unittest.skip("Exploratory repro: Chrome did not autonomously retry same-dl after forced disconnect in local automation yet")
    def testChromeAutomaticallyRetriesSameDlAfterForcedDisconnectRepro(self):
        """Reproduce browser-driven same-dl retries after a real mid-stream disconnect.

        Unlike the manual overlap repro, this test does not create the second
        request itself. The first /download is started by the real share page,
        the server force-closes that response mid-stream, and we assert that
        Chrome itself later emits additional /download requests carrying the
        same logical dl value.
        """
        outputCapture = {}
        downloadRequestLogPath = os.path.join(self.tempDir, 'download_requests.log')
        shareLink = self._startFastFileLink(
            p2p=True,
            captureOutputIn=outputCapture,
            extraEnvVars={'FFL_DOWNLOAD_REQUEST_LOG': downloadRequestLogPath},
        )
        _baseUrl, uid = self._parseShareLink(shareLink)

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self._attachConsoleMirror(driver)

        disconnectAfterBytes = 1024 * 1024
        shareUrl = f"{shareLink}?webrtc=0&debug=1"
        print(f"[Test] Navigating browser to: {shareUrl}")
        driver.get(shareUrl)

        driver.execute_script(
            """
            const uid = arguments[0];
            const disconnectAfter = arguments[1];
            const link = document.getElementById('download-link');
            if (!link) {
                throw new Error('download-link not found');
            }
            link.setAttribute('href', `/${uid}/download?disconnect-after=${disconnectAfter}`);
            """,
            uid,
            disconnectAfterBytes,
        )

        browserDownload = self._waitForBrowserNativeDownloadStart(driver, self.chromeDownloadDir)
        logicalDl = browserDownload['dl']
        print(
            f"[Test] Browser-native disconnect test started with dl={logicalDl}, "
            f"partial={browserDownload['partialSize']} bytes"
        )

        disconnectObserved = False
        repeatedDownloadRequests = []
        deadline = time.time() + 45

        while time.time() < deadline:
            output = self._updateCapturedOutput(outputCapture) or ""
            if '[Test] Disconnect injection:' in output:
                disconnectObserved = True

            repeatedDownloadRequests = [
                item for item in self._loadJsonLines(downloadRequestLogPath)
                if item.get('logicalDl') == logicalDl
            ]
            if disconnectObserved and len(repeatedDownloadRequests) >= 2:
                break

            time.sleep(1)

        print(f"[Test] Disconnect observed: {disconnectObserved}")
        print(f"[Test] Same-dl browser requests observed: {repeatedDownloadRequests}")

        self.assertTrue(
            disconnectObserved,
            "Expected server-side disconnect-after injection to trigger during browser-native download"
        )

        self.assertGreaterEqual(
            len(repeatedDownloadRequests), 2,
            f"Expected Chrome to emit at least two same-dl /download requests after forced disconnect, got {repeatedDownloadRequests}"
        )

    @unittest.skip("Exploratory repro: Chrome did not autonomously retry same-dl after long stall in local automation yet")
    def testChromeAutomaticallyRetriesSameDlAfterLongStallRepro(self):
        """Reproduce browser-driven same-dl retries after a long mid-stream stall.

        This is closer to the real user report than forced disconnect:
        the first /download stays open and stops making progress, and we
        observe whether Chrome itself later opens additional same-dl
        requests while the original request is still alive.
        """
        outputCapture = {}
        downloadRequestLogPath = os.path.join(self.tempDir, 'stall_download_requests.log')
        shareLink = self._startFastFileLink(
            p2p=True,
            captureOutputIn=outputCapture,
            extraEnvVars={'FFL_DOWNLOAD_REQUEST_LOG': downloadRequestLogPath},
        )
        _baseUrl, uid = self._parseShareLink(shareLink)

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self._attachConsoleMirror(driver)

        stallAfterBytes = 1024 * 1024
        shareUrl = f"{shareLink}?webrtc=0&debug=1&stallMs=5000"
        print(f"[Test] Navigating browser to: {shareUrl}")
        driver.get(shareUrl)

        driver.execute_script(
            """
            const uid = arguments[0];
            const stallAfter = arguments[1];
            const link = document.getElementById('download-link');
            if (!link) {
                throw new Error('download-link not found');
            }
            link.setAttribute('href', `/${uid}/download?stall-after=${stallAfter}`);
            """,
            uid,
            stallAfterBytes,
        )

        browserDownload = self._waitForBrowserNativeDownloadStart(driver, self.chromeDownloadDir)
        logicalDl = browserDownload['dl']
        print(
            f"[Test] Browser-native stall test started with dl={logicalDl}, "
            f"partial={browserDownload['partialSize']} bytes"
        )

        stallObserved = False
        repeatedDownloadRequests = []
        deadline = time.time() + 90

        while time.time() < deadline:
            output = self._updateCapturedOutput(outputCapture) or ""
            if '[Test] Stall injection:' in output:
                stallObserved = True

            repeatedDownloadRequests = [
                item for item in self._loadJsonLines(downloadRequestLogPath)
                if item.get('logicalDl') == logicalDl
            ]
            if stallObserved and len(repeatedDownloadRequests) >= 2:
                break

            time.sleep(1)

        print(f"[Test] Stall observed: {stallObserved}")
        print(f"[Test] Same-dl browser requests after stall: {repeatedDownloadRequests}")

        self.assertTrue(
            stallObserved,
            "Expected server-side stall-after injection to trigger during browser-native download"
        )

        self.assertGreaterEqual(
            len(repeatedDownloadRequests), 2,
            f"Expected Chrome to emit at least two same-dl /download requests after long stall, got {repeatedDownloadRequests}"
        )


if __name__ == '__main__':
    unittest.main()
