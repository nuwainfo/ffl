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

import base64
import json
import os
import threading
import unittest

from unittest import mock

from bases.Tunnel import TunnelRunner
from bases.tunnels import TunnelCandidate
from bases.tunnels.Web import (
    WebTunnelClient, WebTunnelConfigurationError, _RawHTTPResponse,
)
from addons.Features import FeatureLevel, FeatureManager # isort:skip

from tests.BrowserTestBase import BrowserTestBase # isort:skip


class _FakeConnection:
    def __init__(self):
        self.closed = False
        self.connected = False
        self.auto_open = 1

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True


class _FakeSocket:
    def __init__(self, data):
        self.data = bytearray(data)

    def recv(self, size):
        data, self.data = self.data[:size], self.data[size:]
        return bytes(data)


class _FakeHTTPResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self._headers = headers
        self._body = body
        self._offset = 0

    def getheaders(self):
        return self._headers

    def getheader(self, name, default=None):
        for headerName, headerValue in self._headers:
            if headerName.lower() == name.lower():
                return headerValue
        return default

    def read(self, size=-1):
        if size < 0:
            size = len(self._body) - self._offset
        data = self._body[self._offset:self._offset + size]
        self._offset += len(data)
        return data

    def read1(self, size=-1):
        # Independent of read() (not just delegating to it), so a test can
        # replace one without affecting the other -- matching how the two are
        # genuinely different methods on a real HTTPResponse.
        if size < 0:
            size = len(self._body) - self._offset
        data = self._body[self._offset:self._offset + size]
        self._offset += len(data)
        return data


class WebTunnelConfigurationTest(unittest.TestCase):
    """The server decides bore vs. web (via TunnelRunner.resolveTunnel()); there is
    no client-side transport setting.  Agent/public URL default to the resolved
    domain and can be overridden by FFL_WEB_TUNNEL_AGENT_URL/PUBLIC_URL for local
    development against a relay that isn't registered on the server."""

    def _makeResolvedWeb(self):
        # A fresh instance every call: createClient()/prefetch mutate `secret`/
        # `preSock` on the resolved candidate in place, so a single shared
        # instance would leak state between test methods.
        return TunnelCandidate(domain='10.fastfilelink.com', type='web')

    def testWebTypeCreatesClientWithoutBore(self):
        with mock.patch.object(TunnelRunner, 'resolveTunnel', return_value=self._makeResolvedWeb()), \
             mock.patch('bases.Tunnel.fetchTunnelToken') as fetchToken:
            fetchToken.return_value = 'short-lived-token'
            client = TunnelRunner(1024).createClient(8080, uid='share-id')

        self.assertIsInstance(client, WebTunnelClient)
        self.assertEqual(8080, client.localPort)
        self.assertEqual('https://10.fastfilelink.com/', client.getTunnelURL())
        self.assertEqual('share-id', client.shareUID)
        # Every tunnel server (bore or web relay) self-serves /api/tunnel/token,
        # so the resolved domain is passed through uniformly for both transports.
        fetchToken.assert_called_once_with(domain='10.fastfilelink.com')
        self.assertEqual('short-lived-token', client.secret)
        self.assertTrue(callable(client.tokenProvider))

    def testWebTypeDefaultsWhenResolverOmitsType(self):
        """A resolver result with no `type` key must fall back to bore."""
        with mock.patch.object(TunnelRunner, 'resolveTunnel', return_value=TunnelCandidate(domain='33.fastfilelink.com')), \
             mock.patch('bases.Tunnel.requests.get'), \
             mock.patch('bases.Tunnel.fetchTunnelToken', return_value='token'):
            runner = TunnelRunner(1024)
            self.assertEqual('default', runner.getTunnelType())
            self.assertTrue(runner.reusableAcrossShares)

    def testWebTypeUsesEnvOverrideForAgentAndPublicURL(self):
        environment = {
            'FFL_WEB_TUNNEL_AGENT_URL': 'https://custom-agent.example.com/',
            'FFL_WEB_TUNNEL_PUBLIC_URL': 'https://custom-public.example.com/',
        }
        with mock.patch.object(TunnelRunner, 'resolveTunnel', return_value=self._makeResolvedWeb()), \
             mock.patch.dict(os.environ, environment, clear=False), \
             mock.patch('bases.Tunnel.fetchTunnelToken', return_value='token'):
            client = TunnelRunner(1024).createClient(8080, uid='share-id')

        self.assertEqual('https://custom-public.example.com/', client.getTunnelURL())
        self.assertEqual('https://custom-agent.example.com/', client.agentURL)

    def testFeatureResolveTunnelHonorsWebTypeFromServer(self):
        """Features' resolveTunnel() override must pass a server-selected web
        candidate through unchanged, rather than assuming bore."""
        fakeFeatureManager = mock.Mock()
        fakeFeatureManager.user.level = FeatureLevel.STANDARD
        fakeFeatureManager.allowFileSize.return_value = True
        fakeFeatureManager.consumeTunnelPrefetch.return_value = None

        with mock.patch('addons.Features.getLowLatencyTunnel', return_value=self._makeResolvedWeb()), \
             mock.patch('bases.Tunnel.fetchTunnelToken', return_value='token'):
            EnhancedTunnelRunner = FeatureManager.getTunnelRunnerClass(fakeFeatureManager, TunnelRunner)
            client = EnhancedTunnelRunner(1024).createClient(8000, uid='share-id')

        self.assertIsInstance(client, WebTunnelClient)

    def testFeaturePrefetchFetchesTokenForWebType(self):
        """The prefetch's non-reusable (web) branch fetches a token for the
        resolved candidate's own domain, same as every other transport."""
        fakeFeatureManager = mock.Mock()
        fakeFeatureManager.getTunnelToken.return_value = 'token'

        with mock.patch('addons.Features._tunnelPrefetchCache') as fakeCache, \
             mock.patch('addons.Features.getLowLatencyTunnel', return_value=self._makeResolvedWeb()):
            fakeCache.load.return_value = None
            fakeCache.isDomainFresh.return_value = False
            FeatureManager._fetchTunnelAndToken(fakeFeatureManager, 1024, None)

        fakeFeatureManager.getTunnelToken.assert_called_once_with(domain='10.fastfilelink.com')

    def testWebTypeRetainsSocksProxyConfiguration(self):
        proxyConfig = {
            'type': 'socks5',
            'host': '127.0.0.1',
            'port': 9150,
            'protocol': 'socks5h',
        }
        with mock.patch.object(TunnelRunner, 'resolveTunnel', return_value=self._makeResolvedWeb()), \
             mock.patch('bases.Tunnel.fetchTunnelToken', return_value='token'):
            client = TunnelRunner(1024, proxyConfig=proxyConfig).createClient(8080, uid='share-id')

        self.assertEqual(proxyConfig, client.proxyConfig)
        self.assertEqual(('127.0.0.1', 9150), client._getSocks5Proxy())

    def testWebTypeUsesSocksEnvironmentFallback(self):
        with mock.patch.dict(os.environ, {
            'FFL_TUNNEL_SOCKS5': '127.0.0.1:9050',
        }, clear=False):
            client = WebTunnelClient(
                8080,
                'https://10.fastfilelink.com/',
                'https://10.fastfilelink.com/',
                'test-token',
                'share-id',
            )
            self.assertEqual(('127.0.0.1', 9050), client._getSocks5Proxy())

    def testRequestHeaderFilteringRemovesHopByHopAndContentLength(self):
        client = WebTunnelClient(
            8080,
            'https://10.fastfilelink.com/',
            'https://10.fastfilelink.com/',
            'test-token',
            'share-id',
        )
        headers = client._filterRequestHeaders([
            ['Connection', 'keep-alive'],
            ['Transfer-Encoding', 'chunked'],
            ['Content-Length', '42'],
            ['Accept-Encoding', 'gzip'],
            ['host', 'relay.example.com'],
            ['Range', 'bytes=10-'],
            ['X-FFL-Test', 'value'],
        ])

        self.assertEqual({'Range': 'bytes=10-', 'X-FFL-Test': 'value'}, headers)


class WebTunnelRelayTest(unittest.TestCase):
    def testRawResponseDecodesChunkedTransferCoding(self):
        response = _RawHTTPResponse(_FakeSocket(
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Test: value\r\n\r\n'
            b'3\r\nabc\r\n2;extension=value\r\nde\r\n0\r\nX-Trailer: ignored\r\n\r\n'
        ))

        self.assertEqual(200, response.status)
        self.assertEqual(b'ab', response.read(2))
        self.assertEqual(b'cde', response.read(10))
        self.assertEqual(b'', response.read(10))

    def testRawResponseFillsPlainReadsAcrossSocketPackets(self):
        class FragmentedSocket(_FakeSocket):
            def recv(self, size):
                return super().recv(min(size, 2))

        response = _RawHTTPResponse(FragmentedSocket(
            b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde'
        ))

        self.assertEqual(b'abcde', response.read(5))
        self.assertEqual(b'', response.read(5))

    def testMissingAgentURLRaisesConfigurationError(self):
        with self.assertRaises(WebTunnelConfigurationError):
            WebTunnelClient(8080, None, 'https://10.fastfilelink.com/', 'token', 'share-id')

    def testWebSocketUpgradeAcceptsNormalHTTPHeaderWhitespace(self):
        client = WebTunnelClient(
            8080, 'https://relay.example.com/', 'https://0.10.fastfilelink.com/',
            'test-secret', 'share-id',
        )
        key = base64.b64encode(b'0' * 16).decode('ascii')
        import hashlib
        accept = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')
        ).digest()).decode('ascii')
        rawSocket = mock.Mock()
        with mock.patch.object(client, '_connectSocket', return_value=rawSocket), \
             mock.patch('bases.tunnels.Web.secrets.token_bytes', return_value=b'0' * 16), \
             mock.patch.object(client, '_receiveHTTPHeaders', return_value=(
                 f'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}'
             ).encode('ascii')):
            client._connectWebSocket()

        self.assertTrue(client.running)
        rawSocket.sendall.assert_called_once()
        client.stop()

    def testWebTunnelRefreshesTokenOnlyAfterInitialConnection(self):
        tokenProvider = mock.Mock(return_value='refreshed-token')
        client = WebTunnelClient(
            8080, 'https://relay.example.com/', 'https://0.10.fastfilelink.com/',
            'initial-token', 'share-id', tokenProvider=tokenProvider,
        )

        client._refreshSecret()
        self.assertEqual('initial-token', client.secret)
        tokenProvider.assert_not_called()

        client._refreshSecret()
        self.assertEqual('refreshed-token', client.secret)
        tokenProvider.assert_called_once_with()


    def testRelayRequestSendsBinaryFramesOrderedChunksAndEnd(self):
        client = WebTunnelClient(
            8080,
            'https://relay.example.com/',
            'https://0.10.fastfilelink.com/',
            'test-secret',
            'share-id',
            chunkSize=3,
        )
        localConnection = _FakeConnection()
        localResponse = _FakeHTTPResponse(
            206,
            [
                ('Content-Type', 'application/octet-stream'),
                ('Content-Range', 'bytes 3-7/8'),
                ('Transfer-Encoding', 'chunked'),
            ],
            b'34567',
        )
        frames = []
        client.running = True
        client.connected = True
        generation = client._connectionGeneration
        client._sendWindows[(generation, 7)] = client._INITIAL_WINDOW

        with mock.patch('bases.tunnels.Web.http.client.HTTPConnection', return_value=localConnection), \
             mock.patch.object(client, '_requestLocalServer', return_value=localResponse) as requestLocal, \
             mock.patch.object(client, '_sendFrame', side_effect=lambda *args, **kwargs: frames.append(args)):
            client._relayRequest(generation, 7, {
                'method': 'POST',
                'path': '/share/download',
                'host': 'relay.example.com',
                'headers': [['Content-Type', 'application/json']],
                'hasBody': True,
            }, b'input-body')

        requestLocal.assert_called_once()
        self.assertIs(localConnection, requestLocal.call_args.args[0])
        self.assertEqual(b'input-body', requestLocal.call_args.args[2])
        self.assertTrue(localConnection.closed)
        self.assertNotIn((generation, 7), client._activeConnections)
        self.assertEqual([
            client._RESPONSE, client._DATA, client._DATA, client._END,
        ], [frame[0] for frame in frames])
        self.assertEqual([7, 7, 7, 7], [frame[1] for frame in frames])
        metadata = json.loads(frames[0][2].decode('utf-8'))
        self.assertEqual(206, metadata['status'])
        self.assertNotIn(['Transfer-Encoding', 'chunked'], metadata['headers'])
        self.assertEqual(b'345', frames[1][2])
        self.assertEqual(b'67', frames[2][2])

    def testRelayRequestSkipsBodyStreamingForNullBodyStatuses(self):
        """204/205/304 must not be streamed, matching TunnelRelay's own
        _responseHasBody() on the Worker side -- otherwise the agent tries to
        read a body the DO already decided this stream doesn't have."""
        for status in (204, 205, 304):
            with self.subTest(status=status):
                client = WebTunnelClient(
                    8080, 'https://relay.example.com/', 'https://0.10.fastfilelink.com/', 'test-secret', 'share-id',
                )
                localConnection = _FakeConnection()
                localResponse = _FakeHTTPResponse(status, [], b'')
                localResponse.read = mock.Mock(side_effect=AssertionError(f'{status} response must not be read as a body'))
                frames = []
                client.running = True
                client.connected = True
                generation = client._connectionGeneration
                client._sendWindows[(generation, 13)] = client._INITIAL_WINDOW

                with mock.patch('bases.tunnels.Web.http.client.HTTPConnection', return_value=localConnection), \
                     mock.patch.object(client, '_requestLocalServer', return_value=localResponse), \
                     mock.patch.object(client, '_sendFrame', side_effect=lambda *args, **kwargs: frames.append(args)):
                    client._relayRequest(generation, 13, {
                        'method': 'GET',
                        'path': '/share/asset.js',
                        'host': 'relay.example.com',
                        'headers': [['If-None-Match', '"etag"']],
                        'hasBody': False,
                    }, None)

                self.assertEqual([client._RESPONSE, client._END], [frame[0] for frame in frames])

    def testStreamResponseUsesRead1ForEventStreamContentType(self):
        """text/event-stream must use read1() (returns whatever's already
        arrived) rather than read() (blocks accumulating up to chunkSize or
        EOF) -- otherwise an SSE event can sit unsent for as long as the next
        one takes to show up."""
        client = WebTunnelClient(
            8080, 'https://relay.example.com/', 'https://0.10.fastfilelink.com/', 'test-secret', 'share-id',
        )
        client.running = True
        client.connected = True
        generation = client._connectionGeneration
        client._sendWindows[(generation, 9)] = client._INITIAL_WINDOW

        response = _FakeHTTPResponse(200, [('Content-Type', 'text/event-stream; charset=utf-8')], b'data: hello\n\n')
        response.read = mock.Mock(side_effect=AssertionError('read() must not be used for text/event-stream'))

        frames = []
        with mock.patch.object(client, '_sendFrame', side_effect=lambda *args, **kwargs: frames.append(args)):
            client._streamResponse(generation, 9, response)

        self.assertEqual([client._DATA], [frame[0] for frame in frames])
        self.assertEqual(b'data: hello\n\n', frames[0][2])

    def testStreamResponseExitsPromptlyWhenCancelledMidWait(self):
        """_cancelRequest() pops the (generation, streamID) window entry
        entirely rather than setting it to 0; a stale `.get(key, 0) < 1`
        check can't tell that apart from "window legitimately exhausted,
        more credit still coming" and would loop in wait(timeout=5) forever
        instead of ever reaching the raise below it."""
        client = WebTunnelClient(
            8080, 'https://relay.example.com/', 'https://0.10.fastfilelink.com/', 'test-secret', 'share-id',
        )
        client.running = True
        client.connected = True
        generation = client._connectionGeneration
        key = (generation, 11)
        client._sendWindows[key] = 0 # start exhausted so the thread waits immediately

        response = _FakeHTTPResponse(200, [('Content-Type', 'application/octet-stream')], b'irrelevant')
        raised = {}
        finished = threading.Event()

        def worker():
            try:
                client._streamResponse(generation, 11, response)
            except Exception as e:
                raised['error'] = e
            finished.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            with client._windowChanged:
                client._sendWindows.pop(key, None) # simulate _cancelRequest()
                client._windowChanged.notify_all()

            self.assertTrue(finished.wait(timeout=2), "stream thread did not exit after cancellation")
            self.assertIsInstance(raised.get('error'), ConnectionError)
        finally:
            thread.join(timeout=2)


class WebTunnelFunctionalTest(BrowserTestBase):
    """Functional test: a real P2P + E2EE share forced onto the web tunnel via
    FFL_TUNNEL_DOMAIN, downloaded end-to-end through a real browser (WebRTC +
    in-browser E2EE decryption)."""

    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testP2PWithE2EEOverWebTunnel(self):
        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=['--e2ee'],
            extraEnvVars={'FFL_TUNNEL_DOMAIN': '10.fastfilelink.com'},
        )

        self.assertIn('10.fastfilelink.com', shareLink, "Share link should use the web tunnel domain")
        print(f"[Test] Share link on web tunnel: {shareLink}")

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        try:
            expectedFilename = os.path.basename(self.testFilePath)
            downloadedPath = self._downloadWithBrowser(
                driver, shareLink, self.chromeDownloadDir, expectedFilename, disableFallback=True
            )
            self._verifyDownloadedFile(downloadedPath)
            print("[OK] Browser WebRTC + E2EE download over the web tunnel verified")
        finally:
            driver.quit()


if __name__ == '__main__':
    unittest.main()
