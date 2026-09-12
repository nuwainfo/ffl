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

import asyncio
import os
import queue
import socket
import subprocess
import tempfile
import time
import unittest

from unittest import mock

import requests

from bases.tunnels import resolveTunnelCandidate, resolveTunnelDomainFromEnv # isort:skip
from bases.tunnels.Loopback import LoopbackTunnelCandidate, LoopbackTunnelClient # isort:skip
from bases.Tunnel import AsyncTunnelThread, TunnelRunner # isort:skip
from tests.CoreTestBase import FastFileLinkTestBase


class LoopbackTunnelClientLifecycleTest(unittest.TestCase):
    """Exercises LoopbackTunnelClient's async contract directly (no local
    server, no thread) -- the same connect/listen/stop/shutdown shape
    AsyncTunnelThread relies on for BoreClient/WebTunnelClient."""

    def testConnectReportsLoopbackURL(self):
        async def run():
            client = LoopbackTunnelClient(54321)
            self.assertIsNone(client.getTunnelURL(), "No URL should be available before connect()")

            connected = await client.connect()
            self.assertTrue(connected)
            self.assertEqual(client.remotePort, 54321)
            self.assertEqual(client.getTunnelURL(), "http://127.0.0.1:54321/")

        asyncio.run(run())

    def testListenBlocksUntilShutdown(self):
        async def run():
            client = LoopbackTunnelClient(54321)
            await client.connect()

            listenTask = asyncio.create_task(client.listen())
            await asyncio.sleep(0.05)
            self.assertTrue(client.running, "listen() should mark the client running")
            self.assertFalse(listenTask.done(), "listen() should block until shutdown()")

            await client.shutdown()
            await asyncio.wait_for(listenTask, timeout=2)
            self.assertFalse(client.running)

        asyncio.run(run())


class LoopbackTunnelClientIntegrationTest(unittest.TestCase):
    """Drives LoopbackTunnelClient through the real AsyncTunnelThread harness
    against a plain `python -m http.server` local target. This isolates the
    tunnel-client machinery itself (connect/listen/getTunnelURL through the
    same thread BoreClient/WebTunnelClient use) from the rest of the FFL CLI.

    This is NOT the full end-to-end test -- it never runs FFL.py itself, so
    it can't catch a regression in how FFL.py wires TunnelRunner up to its
    own HTTP server. See LoopbackFastFileLinkE2ETest below for that.
    """

    def setUp(self):
        self._tempDirObj = tempfile.TemporaryDirectory()
        self.tempDir = self._tempDirObj.name

        with socket.socket() as s:
            s.bind(('', 0))
            self.testPort = s.getsockname()[1]

        self.indexPath = os.path.join(self.tempDir, "index.html")
        self.dataPath = os.path.join(self.tempDir, "data.bin")

        with open(self.indexPath, 'w', encoding='utf-8') as fileHandle:
            fileHandle.write("<html><body>Hello Loopback!</body></html>")
        FastFileLinkTestBase.generateRandomFile(self.dataPath, 1024 * 1024) # 1MB

        self.httpProcess = subprocess.Popen(
            ["python", "-m", "http.server", str(self.testPort)],
            cwd=self.tempDir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)

    def tearDown(self):
        self.httpProcess.terminate()
        self.httpProcess.wait()
        self._tempDirObj.cleanup()

    def testUseLoopbackTunnel(self):
        client = LoopbackTunnelClient(self.testPort)

        resultQueue = queue.Queue()
        tunnelThread = AsyncTunnelThread(resultQueue, client)
        print("[Test] Starting loopback tunnel client...")
        tunnelThread.start()

        try:
            ok, tunnelUrl = resultQueue.get(timeout=10)
            self.assertTrue(ok, f"Loopback tunnel did not connect: {tunnelThread.e}")
            self.assertEqual(tunnelUrl, f"http://127.0.0.1:{self.testPort}/")
            print(f"[Test] Tunnel URL: {tunnelUrl}")

            indexResp = requests.get(tunnelUrl, timeout=5)
            self.assertEqual(indexResp.status_code, 200)
            with open(self.indexPath, 'r', encoding='utf-8') as f:
                self.assertEqual(indexResp.text.strip(), f.read().strip())

            dataResp = requests.get(f"{tunnelUrl}data.bin", timeout=10)
            with open(self.dataPath, 'rb') as f:
                self.assertEqual(dataResp.content, f.read())

            print("[Test] Loopback tunnel content validated.")
        finally:
            tunnelThread.kill()
            tunnelThread.join(timeout=5)

        self.assertFalse(tunnelThread.is_alive(), "Tunnel thread should stop promptly after kill()")


class LoopbackFastFileLinkE2ETest(FastFileLinkTestBase):
    """The real end-to-end test: launches the actual FFL CLI process (the
    same one users run -- see tests/FFLTest.py's CoreCliTest, which this
    mirrors) with FFL_TUNNEL_DOMAIN=localhost, then downloads the resulting
    share link and verifies the file round-trips byte-for-byte. This is the
    scenario the loopback type exists for: a sandbox with no real internet
    access can still exercise FFL's full send/receive path end-to-end,
    because the "tunnel" never leaves 127.0.0.1.
    """

    def testSendAndDownloadOverLoopbackTunnel(self):
        try:
            shareLink = self._startFastFileLink(p2p=True, extraEnvVars={'FFL_TUNNEL_DOMAIN': 'localhost'})
            self.assertTrue(shareLink.startswith('http://127.0.0.1:'), f"Expected a loopback share link, got: {shareLink}")

            downloadedFilePath = self._getDownloadedFilePath()
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)
        finally:
            self._terminateProcess()


class TunnelDomainFromEnvTest(unittest.TestCase):
    """Unit tests for resolveTunnelDomainFromEnv() -- the single place that
    knows what FFL_TUNNEL_DOMAIN means, shared by resolveTunnelCandidate()
    (below) and addons/Features.py's server-based resolveTunnel()."""

    def setUp(self):
        self._originalValue = os.environ.pop('FFL_TUNNEL_DOMAIN', None)

    def tearDown(self):
        if self._originalValue is None:
            os.environ.pop('FFL_TUNNEL_DOMAIN', None)
        else:
            os.environ['FFL_TUNNEL_DOMAIN'] = self._originalValue

    def testUnsetReturnsNone(self):
        self.assertIsNone(resolveTunnelDomainFromEnv())

    def testUnrecognizedDomainReturnsNone(self):
        os.environ['FFL_TUNNEL_DOMAIN'] = 'example.com'
        self.assertIsNone(resolveTunnelDomainFromEnv(), "A domain that is neither a loopback alias nor fastfilelink.com must be ignored")

    def testRealDomainResolvesWithNoSecretYet(self):
        os.environ['FFL_TUNNEL_DOMAIN'] = '1.10.fastfilelink.com'
        candidate = resolveTunnelDomainFromEnv()
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.domain, '1.10.fastfilelink.com')
        self.assertIsNone(candidate.secret, "Caller is responsible for fetching/attaching the token")

    def testLocalhostAliasResolvesToLoopback(self):
        for alias in ('localhost', '127.0.0.1', 'LocalHost', ' localhost '):
            with self.subTest(alias=alias):
                os.environ['FFL_TUNNEL_DOMAIN'] = alias
                candidate = resolveTunnelDomainFromEnv()
                self.assertIsNotNone(candidate)
                self.assertEqual(candidate.domain, '127.0.0.1')
                self.assertIsInstance(candidate, LoopbackTunnelCandidate)
                self.assertIsNotNone(candidate.secret, "Secret must not be None or a token fetch will be attempted")

    def testResolveTunnelCandidateHonorsLoopbackOverride(self):
        """resolveTunnelCandidate() -- the base (no Features addon)
        resolveTunnel() implementation -- must apply the override itself,
        with no separate step required from its callers."""
        os.environ['FFL_TUNNEL_DOMAIN'] = 'localhost'
        candidate = resolveTunnelCandidate()
        self.assertIsInstance(candidate, LoopbackTunnelCandidate)


class TunnelRunnerLoopbackTest(unittest.TestCase):
    """Confirms TunnelRunner routes FFL_TUNNEL_DOMAIN=localhost to a fully
    offline loopback tunnel -- no reachability probe, no token fetch -- and
    that the resulting link actually serves the local file."""

    def setUp(self):
        self._originalValue = os.environ.get('FFL_TUNNEL_DOMAIN')
        os.environ['FFL_TUNNEL_DOMAIN'] = 'localhost'

        self._tempDirObj = tempfile.TemporaryDirectory()
        self.tempDir = self._tempDirObj.name
        with socket.socket() as s:
            s.bind(('', 0))
            self.testPort = s.getsockname()[1]

        with open(os.path.join(self.tempDir, "index.html"), 'w', encoding='utf-8') as fileHandle:
            fileHandle.write("hello from TunnelRunner")

        self.httpProcess = subprocess.Popen(
            ["python", "-m", "http.server", str(self.testPort)],
            cwd=self.tempDir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)
        self.runner = None

    def tearDown(self):
        if self.runner is not None:
            self.runner.stop()

        self.httpProcess.terminate()
        self.httpProcess.wait()
        self._tempDirObj.cleanup()

        if self._originalValue is None:
            os.environ.pop('FFL_TUNNEL_DOMAIN', None)
        else:
            os.environ['FFL_TUNNEL_DOMAIN'] = self._originalValue

    def testStartNeverTouchesNetwork(self):
        with mock.patch('bases.Tunnel.requests.get', side_effect=AssertionError('requests.get should not be called for a loopback tunnel')):
            with mock.patch('bases.Tunnel.fetchTunnelToken', side_effect=AssertionError('fetchTunnelToken should not be called for a loopback tunnel')):
                self.runner = TunnelRunner(fileSize=0)
                domain, link = self.runner.start(self.testPort)

        self.assertEqual(link, f"http://127.0.0.1:{self.testPort}/")
        self.assertIn('127.0.0.1', domain)

        response = requests.get(link, timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "hello from TunnelRunner")


if __name__ == '__main__':
    unittest.main()
