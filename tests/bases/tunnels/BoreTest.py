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
import logging
import os
import queue
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from functools import partial

import requests

from bases.tunnels.Bore import BoreClient # isort:skip
from bases.Tunnel import AsyncTunnelThread, fetchTunnelToken # isort:skip
from tests.CoreTestBase import FastFileLinkTestBase

# ---------------------------
# Silence noisy logs
# ---------------------------
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

STALE_TEST_TUNNEL_DOMAIN = os.getenv("BORE_STALE_TEST_DOMAIN", "33.fastfilelink.com")
STALE_PUBLIC_GET_TIMEOUT = float(os.getenv("BORE_STALE_PUBLIC_GET_TIMEOUT", "8"))
STALE_RECOVERY_DEADLINE = float(os.getenv("BORE_STALE_RECOVERY_DEADLINE", "30"))
STALE_CONTROL_IDLE_TIMEOUT = float(os.getenv("BORE_STALE_CONTROL_IDLE_TIMEOUT", "5"))


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


class _ProbeHandler(socketserver.StreamRequestHandler):
    responseBody = b"stale-link-probe-ok"

    def handle(self):
        _ = self.rfile.readline()
        while True:
            line = self.rfile.readline()
            if not line or line in (b"\r\n", b"\n"):
                break

        self.wfile.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(self.responseBody)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n" + self.responseBody
        )


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TcpPipe(threading.Thread):
    def __init__(self, source, target, stopEvent, dropReads=False):
        super().__init__(daemon=True)
        self.source = source
        self.target = target
        self.stopEvent = stopEvent
        self.dropReads = dropReads

    def run(self):
        try:
            while not self.stopEvent.is_set():
                data = self.source.recv(8192)
                if not data:
                    break
                if self.dropReads:
                    continue
                self.target.sendall(data)
        except OSError:
            pass
        finally:
            self.stopEvent.set()


class _ProxySession:
    def __init__(self, clientSock, upstreamSock, isControl):
        self.clientSock = clientSock
        self.upstreamSock = upstreamSock
        self.isControl = isControl
        self.stopEvent = threading.Event()
        self.clientToUpstream = _TcpPipe(clientSock, upstreamSock, self.stopEvent)
        self.upstreamToClient = _TcpPipe(upstreamSock, clientSock, self.stopEvent)
        self.frozen = False

    def start(self):
        self.clientToUpstream.start()
        self.upstreamToClient.start()

    def freezeAsHalfOpen(self):
        if self.frozen:
            return
        self.frozen = True
        try:
            self.upstreamSock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.upstreamSock.close()
        except OSError:
            pass
        self.upstreamToClient.dropReads = True
        self.clientToUpstream.dropReads = True

    def close(self):
        self.stopEvent.set()
        for sock in (self.clientSock, self.upstreamSock):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class FaultInjectingSocks5Proxy:
    """
    Minimal SOCKS5 proxy used to freeze the first long-lived control connection.

    We intentionally keep the client-side socket open while closing the upstream
    socket so the client sees a half-dead control channel and can exercise its
    reconnect logic.
    """

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self.port = port
        self.serverSock = None
        self.acceptThread = None
        self.stopEvent = threading.Event()
        self.sessions = []
        self.lock = threading.Lock()
        self.controlSession = None
        self._connectCount = 0

    def start(self):
        self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSock.bind((self.host, self.port))
        self.serverSock.listen(16)
        self.port = self.serverSock.getsockname()[1]
        self.acceptThread = threading.Thread(target=self._acceptLoop, daemon=True)
        self.acceptThread.start()

    def _acceptLoop(self):
        while not self.stopEvent.is_set():
            try:
                clientSock, _ = self.serverSock.accept()
            except OSError:
                break
            threading.Thread(target=self._handleClient, args=(clientSock,), daemon=True).start()

    def _recvExact(self, sock, size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise OSError("socket closed while reading exact bytes")
            data.extend(chunk)
        return bytes(data)

    def _handleClient(self, clientSock):
        upstreamSock = None
        try:
            header = self._recvExact(clientSock, 2)
            ver, methods = header[0], header[1]
            if ver != 5:
                raise OSError("invalid SOCKS version")
            _ = self._recvExact(clientSock, methods)
            clientSock.sendall(b"\x05\x00")

            req = self._recvExact(clientSock, 4)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 1:
                raise OSError("unsupported SOCKS request")

            if atyp == 1:
                destHost = socket.inet_ntoa(self._recvExact(clientSock, 4))
            elif atyp == 3:
                hostLen = self._recvExact(clientSock, 1)[0]
                destHost = self._recvExact(clientSock, hostLen).decode("idna")
            elif atyp == 4:
                destHost = socket.inet_ntop(socket.AF_INET6, self._recvExact(clientSock, 16))
            else:
                raise OSError("unsupported SOCKS address type")

            destPort = int.from_bytes(self._recvExact(clientSock, 2), "big")
            upstreamSock = socket.create_connection((destHost, destPort), timeout=15)
            upstreamSock.settimeout(None)
            clientSock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            with self.lock:
                self._connectCount += 1
                isControl = self._connectCount == 1
                session = _ProxySession(clientSock, upstreamSock, isControl=isControl)
                self.sessions.append(session)
                if isControl and self.controlSession is None:
                    self.controlSession = session

            session.start()
            while not session.stopEvent.wait(0.2):
                pass
        except OSError:
            try:
                clientSock.close()
            except OSError:
                pass
            if upstreamSock is not None:
                try:
                    upstreamSock.close()
                except OSError:
                    pass

    def freezeControlConnection(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            with self.lock:
                session = self.controlSession
            if session is not None:
                session.freezeAsHalfOpen()
                return
            time.sleep(0.1)
        raise RuntimeError("Control connection was never established")

    def stop(self):
        self.stopEvent.set()
        if self.serverSock is not None:
            try:
                self.serverSock.close()
            except OSError:
                pass
        with self.lock:
            sessions = list(self.sessions)
        for session in sessions:
            session.close()
        if self.acceptThread is not None:
            self.acceptThread.join(timeout=2)


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
        port=None
    ):
        super().__init__(methodName)
        self.remoteHost = remoteHost
        self.secret = secret
        if port is None:
            with socket.socket() as s:
                s.bind(('', 0))
                port = s.getsockname()[1]
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

        with open(self.indexPath, 'w', encoding='utf-8') as fileHandle:
            fileHandle.write("<html><body>Hello Bore!</body></html>")
        FastFileLinkTestBase.generateRandomFile(self.dataPath, 1024 * 1024) # 1MB

        self.httpProcess = subprocess.Popen(["python", "-m", "http.server",
                                             str(self.testPort)],
                                            cwd=self.tempDir,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)

        time.sleep(1)

    def tearDown(self):
        self.httpProcess.terminate()
        self.httpProcess.wait()

        if self._ownsTempDir:
            self._tempDirObj.cleanup()

    def testUseHttpsTunnel(self):
        self.assertIsNotNone(self.remoteHost)
        
        # Fetch tunnel token dynamically
        if self.secret is None:
            print("[Test] Fetching tunnel token...")
            self.secret = fetchTunnelToken(domain=self.remoteHost)
        
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


class BoreStaleLinkTest(unittest.TestCase):

    def setUp(self):
        self.httpServer = _ThreadingTCPServer(("127.0.0.1", 0), _ProbeHandler)
        self.httpThread = threading.Thread(target=self.httpServer.serve_forever, daemon=True)
        self.httpThread.start()
        self.localPort = self.httpServer.server_address[1]

        self.proxy = FaultInjectingSocks5Proxy()
        self.proxy.start()
        self.tunnelThread = None

    def tearDown(self):
        if self.tunnelThread is not None:
            self.tunnelThread.kill()
            self.tunnelThread.join(timeout=10)

        self.proxy.stop()
        self.httpServer.shutdown()
        self.httpServer.server_close()
        self.httpThread.join(timeout=2)

    def _startTunnel(self):
        resultQueue = queue.Queue()
        client = BoreClient(
            localhost="127.0.0.1",
            localPort=self.localPort,
            remoteHost=STALE_TEST_TUNNEL_DOMAIN,
            remotePort=0,
            tokenProvider=partial(fetchTunnelToken, domain=STALE_TEST_TUNNEL_DOMAIN),
            proxyConfig={
                "type": "socks5",
                "protocol": "socks5h",
                "host": "127.0.0.1",
                "port": self.proxy.port,
            },
        )
        client.controlIdleTimeout = STALE_CONTROL_IDLE_TIMEOUT
        self.tunnelThread = AsyncTunnelThread(resultQueue, client)
        self.tunnelThread.start()
        ok, tunnelUrl = resultQueue.get(timeout=30)
        self.assertTrue(ok, "Tunnel should connect successfully before the fault is injected")
        self.assertTrue(tunnelUrl.startswith("https://"), tunnelUrl)
        return tunnelUrl

    def _waitForHealthy(self, url, deadlineSeconds=20):
        deadline = time.time() + deadlineSeconds
        while time.time() < deadline:
            try:
                response = requests.get(url, timeout=STALE_PUBLIC_GET_TIMEOUT)
                if response.status_code == 200 and response.content == _ProbeHandler.responseBody:
                    return
            except requests.RequestException:
                pass
            time.sleep(1)
        self.fail(f"Tunnel {url} never became healthy")

    def _waitForRecovery(self, url, deadlineSeconds=STALE_RECOVERY_DEADLINE):
        deadline = time.time() + deadlineSeconds
        lastError = "no successful response observed"
        while time.time() < deadline:
            try:
                response = requests.get(url, timeout=STALE_PUBLIC_GET_TIMEOUT)
                if response.status_code == 200 and response.content == _ProbeHandler.responseBody:
                    return
                lastError = f"status={response.status_code} body={response.text[:120]!r}"
            except requests.RequestException as e:
                lastError = repr(e)
            time.sleep(1)
        self.fail(f"Tunnel did not recover before deadline: {lastError}")

    def testControlChannelHalfOpenRecoversSameLink(self):
        tunnelUrl = self._startTunnel()
        self._waitForHealthy(tunnelUrl)

        self.proxy.freezeControlConnection()

        self._waitForRecovery(tunnelUrl)

    def testKillStopsHalfOpenControlPromptly(self):
        tunnelUrl = self._startTunnel()
        self._waitForHealthy(tunnelUrl)

        self.proxy.freezeControlConnection()
        time.sleep(1)

        killStart = time.time()
        self.tunnelThread.kill()
        self.tunnelThread.join(timeout=2)
        elapsed = time.time() - killStart

        self.assertFalse(
            self.tunnelThread.is_alive(),
            f"Tunnel thread should stop promptly after kill(); elapsed={elapsed:.2f}s",
        )


if __name__ == '__main__':
    unittest.main()
