#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import asyncio
import logging
import os
import subprocess
import tempfile
import threading
import time
import unittest

import requests

from bases.Bore import BoreClient # isort:skip
from bases.Tunnel import fetchTunnelToken # isort:skip

# ---------------------------
# Silence noisy logs
# ---------------------------
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)


# ---------------------------
# File I/O helpers
# ---------------------------
def generateRandomFile(path, sizeBytes):
    with open(path, 'wb') as f:
        f.write(os.urandom(sizeBytes))


def writeFile(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


# ---------------------------
# Bore client runner in thread
# ---------------------------
class BoreClientThread:

    def __init__(self, boreClient):
        self.client = boreClient
        self.thread = None
        self.loop = None
        self.readyEvent = threading.Event()

    def start(self):

        def target():
            asyncio.run(self._main())

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        self.readyEvent.wait(timeout=10)

    async def _main(self):
        self.loop = asyncio.get_event_loop()
        connected = await self.client.connect()
        if connected:
            self.readyEvent.set()
            await self.client.listen()

    def stop(self):
        if self.loop and self.client:
            asyncio.run_coroutine_threadsafe(self.client.shutdown(), self.loop)
        if self.thread:
            self.thread.join(timeout=5)


# ---------------------------
# Main test case
# ---------------------------
class BoreHttpsTest(unittest.TestCase):

    def __init__(
        self,
        methodName='testUseHttpsTunnel',
        remoteHost="33.fastfilelink.com",
        secret=None,  # Will be fetched dynamically
        tempDir=None,
        port=8000
    ):
        super().__init__(methodName)
        self.remoteHost = remoteHost
        self.secret = secret
        self.testPort = port

        if tempDir is None:
            self._ownsTempDir = True
            self._tempDirObj = tempfile.TemporaryDirectory()
            self.tempDir = self._tempDirObj.name
        else:
            self._ownsTempDir = False
            self.tempDir = tempDir

    def setUp(self):
        assert isinstance(self.tempDir, str), "tempDir must be a path string"

        self.indexPath = os.path.join(self.tempDir, "index.html")
        self.dataPath = os.path.join(self.tempDir, "data.bin")

        writeFile(self.indexPath, "<html><body>Hello Bore!</body></html>")
        generateRandomFile(self.dataPath, 1024 * 1024) # 1MB

        self.httpProcess = subprocess.Popen(["python", "-m", "http.server",
                                             str(self.testPort)],
                                            cwd=self.tempDir,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)

        time.sleep(1)

    def tearDown(self):
        self.httpProcess.terminate()
        self.httpProcess.wait()

        # 如果自己建的，就負責清掉
        if self._ownsTempDir:
            self._tempDirObj.cleanup()

    def testUseHttpsTunnel(self):
        self.assertIsNotNone(self.remoteHost)
        
        # Fetch tunnel token dynamically
        if self.secret is None:
            print("[Test] Fetching tunnel token...")
            self.secret = fetchTunnelToken()
        
        self.assertIsNotNone(self.secret)

        client = BoreClient(
            localhost="localhost",
            localPort=self.testPort,
            remoteHost=self.remoteHost,
            secret=self.secret,
            useHttps=True,
            debug=False
        )

        # Wrap BoreClient in background thread
        tunnelRunner = BoreClientThread(client)
        print("[Test] Starting tunnel client...")
        tunnelRunner.start()

        self.assertIsNotNone(client.remotePort, "Tunnel did not return a valid remotePort")
        tunnelUrl = f"https://{client.remotePort}.{self.remoteHost}/"
        print(f"[Test] Tunnel URL: {tunnelUrl}")

        # Wait until tunnel actually accepts a request
        for attempt in range(15):
            try:
                print(f"[Test] Attempt {attempt + 1} to fetch index.html")
                r = requests.get(tunnelUrl, timeout=5)
                if r.status_code == 200:
                    print("[Test] index.html is served.")
                    break
            except Exception as e:
                print(f"[Test] attempt {attempt + 1} failed: {e}")
            time.sleep(1)
        else:
            self.fail("Tunnel never responded with valid HTTP response")

        # Validate index.html
        indexResp = requests.get(tunnelUrl, timeout=5)
        with open(self.indexPath, 'r', encoding='utf-8') as f:
            self.assertEqual(indexResp.text.strip(), f.read().strip())

        # Validate data.bin
        dataResp = requests.get(f"{tunnelUrl}data.bin", timeout=10)
        with open(self.dataPath, 'rb') as f:
            self.assertEqual(dataResp.content, f.read())

        print("[Test] Tunnel content validated.")
        tunnelRunner.stop()


if __name__ == '__main__':
    unittest.main()
