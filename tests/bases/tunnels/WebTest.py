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
import base64
import contextlib
import hashlib
import json
import os
import socket
import ssl
import struct
import threading
import unittest
import urllib.parse
from unittest import mock

from bases.Tunnel import TunnelRunner
from bases.tunnels import TunnelCandidate
from bases.tunnels.Web import (
    WebTunnelClient, WebTunnelConfigurationError,
    _HeartbeatedSocket, _LaneRequestState, _TunnelLane, _WebSocketConnection,
)
from addons.Features import FeatureLevel, FeatureManager # isort:skip

from tests.BrowserTestBase import BrowserTestBase # isort:skip


class _FakeSSLContext:
    """Plain attributes (not a Mock) so a test can assert the TLS-version
    workaround left minimum_version/maximum_version untouched -- a Mock's
    attributes auto-vivify on read, making "never assigned" indistinguishable
    from "assigned a Mock"."""
    def __init__(self):
        self.minimum_version = None
        self.maximum_version = None
        self.wrap_socket = mock.Mock(return_value=mock.Mock())


class _FakeConnection:
    def __init__(self):
        self.closed = False
        self.connected = False
        self.auto_open = 1

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True


class _FakeHTTPResponse:
    def __init__(self, status, headers, body, contentLength=None):
        self.status = status
        self._headers = headers
        self._body = body
        self._offset = 0
        # Mirrors http.client.HTTPResponse.length: None when no Content-Length
        # was declared (chunked/close-terminated), else the remaining
        # undelivered byte count, decremented as reads are consumed. Left as
        # None by default so existing tests (which never declare a length)
        # keep modelling the "unknown length" case unchanged.
        self.length = contentLength
        # Read by the lane's terminal END diagnostics log only -- not by any
        # correctness path -- so a fixed, uninteresting default is fine here.
        self.chunked = False
        self.will_close = False

    def getheaders(self):
        return self._headers

    def getheader(self, name, default=None):
        for headerName, headerValue in self._headers:
            if headerName.lower() == name.lower():
                return headerValue
        return default

    def _consume(self, data):
        if self.length is not None:
            self.length -= len(data)
        return data

    def read(self, size=-1):
        if size < 0:
            size = len(self._body) - self._offset
        data = self._body[self._offset:self._offset + size]
        self._offset += len(data)
        return self._consume(data)

    def read1(self, size=-1):
        # Independent of read() (not just delegating to it), so a test can
        # replace one without affecting the other -- matching how the two are
        # genuinely different methods on a real HTTPResponse.
        if size < 0:
            size = len(self._body) - self._offset
        data = self._body[self._offset:self._offset + size]
        self._offset += len(data)
        return self._consume(data)


def _newClient(**overrides):
    kwargs = dict(
        localPort=8080,
        agentURL='https://relay.example.com/',
        publicURL='https://0.10.fastfilelink.com/',
        secret='test-secret',
        tunnelID='share-id',
    )
    kwargs.update(overrides)
    return WebTunnelClient(**kwargs)


def _newHeartbeatOwner(webSocket):
    """A minimal _HeartbeatedSocket standing in for whatever real subclass
    (_TunnelLane or WebTunnelClient) would normally own the heartbeat --
    lets _runHeartbeat/_runReceiveLoop be tested directly, independent of
    either subclass's own connect/listen machinery."""
    owner = _HeartbeatedSocket()
    owner.running = True
    owner._webSocket = webSocket
    return owner


@contextlib.contextmanager
def _mockedWebSocketUpgradeHandshake(client):
    """Patches `client` to fake a successful RFC 6455 upgrade handshake
    with a fixed Sec-WebSocket-Key, yielding the mocked raw socket so a
    test can inspect what was actually sent."""
    key = base64.b64encode(b'0' * 16).decode('ascii')
    accept = base64.b64encode(hashlib.sha1(
        (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')
    ).digest()).decode('ascii')
    rawSocket = mock.Mock()
    with mock.patch.object(client, '_connectSocket', return_value=rawSocket), \
         mock.patch('bases.tunnels.Web.secrets.token_bytes', return_value=b'0' * 16), \
         mock.patch.object(client, '_receiveHTTPHeaders', return_value=(
             f'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}'
         ).encode('ascii')):
        yield rawSocket


class WebTunnelConfigurationTest(unittest.TestCase):
    """The server decides bore vs. web (via TunnelRunner.resolveTunnel()); there is
    no client-side transport setting.  Agent/public URL default to the resolved
    domain and can be overridden by FFL_WEB_TUNNEL_AGENT_URL/PUBLIC_URL for local
    development against a relay that isn't registered on the server."""

    def _makeResolvedWeb(self):
        # A fresh instance every call: createClient()/prefetch mutate `secret`/
        # `preSock` on the resolved candidate in place, so a single shared
        # instance would leak state between test methods.
        return TunnelCandidate(domain='1.10.fastfilelink.com', type='web')

    def testWebTypeCreatesClientWithoutBore(self):
        with mock.patch.object(TunnelRunner, 'resolveTunnel', return_value=self._makeResolvedWeb()), \
             mock.patch('bases.Tunnel.fetchTunnelToken') as fetchToken:
            fetchToken.return_value = 'short-lived-token'
            client = TunnelRunner(1024).createClient(8080, uid='share-id')

        self.assertIsInstance(client, WebTunnelClient)
        self.assertEqual(8080, client.localPort)
        self.assertEqual('https://1.10.fastfilelink.com/', client.getTunnelURL())
        self.assertEqual('share-id', client.tunnelID)
        # Every tunnel server (bore or web relay) self-serves /api/tunnel/token,
        # so the resolved domain is passed through uniformly for both transports.
        fetchToken.assert_called_once_with(domain='1.10.fastfilelink.com')
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

        fakeFeatureManager.getTunnelToken.assert_called_once_with(domain='1.10.fastfilelink.com')

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
            client = _newClient()
            self.assertEqual(('127.0.0.1', 9050), client._getSocks5Proxy())

    def testRequestHeaderFilteringRemovesHopByHopAndContentLength(self):
        client = _newClient()
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
    def testMissingAgentURLRaisesConfigurationError(self):
        with self.assertRaises(WebTunnelConfigurationError):
            WebTunnelClient(8080, None, 'https://1.10.fastfilelink.com/', 'token', 'share-id')

    def testLaneCountCapMatchesRelayMaxLanes(self):
        # Must not exceed the relay's own maximum lane count -- a larger
        # configured pool here would just mean the excess lanes permanently
        # fail to connect (429).
        _newClient(laneCount=16)
        with self.assertRaises(WebTunnelConfigurationError):
            _newClient(laneCount=17)

    def testLaneCountAboveEightWarnsAboutMemoryHeadroom(self):
        """16 lanes is the relay's hard ceiling, not a production
        recommendation -- each additional lane adds real per-request memory
        pressure on the relay side against its 128MB isolate budget.
        Allowed (controlled load testing is a legitimate use), but worth a
        loud warning rather than a silent config change."""
        with mock.patch('bases.tunnels.Web.logger') as fakeLogger:
            _newClient(laneCount=9)

        fakeLogger.warning.assert_called_once()
        self.assertIn('exceeds the recommended production value', fakeLogger.warning.call_args.args[0])
        self.assertEqual((9, WebTunnelClient._RECOMMENDED_MAX_LANE_COUNT), fakeLogger.warning.call_args.args[1:])

    def testLaneCountAtOrBelowEightDoesNotWarn(self):
        with mock.patch('bases.tunnels.Web.logger') as fakeLogger:
            _newClient(laneCount=8)

        fakeLogger.warning.assert_not_called()

    def testChunkSizeAcceptsTwoMiBDataFrameLimit(self):
        client = _newClient(chunkSize=WebTunnelClient._MAX_FRAME_DATA)

        self.assertEqual(2 * 1024 * 1024, client.chunkSize)

    def testSendFramePoisonsSocketOnFirstWriteFailure(self):
        """A write failure on a lane's WebSocket must latch the connection
        closed immediately, instead of letting a later write raise its own
        unrelated-looking error against an already-broken socket (observed
        live: a real SSLEOFError followed moments later by an unrelated
        write getting "[SSL: BAD_LENGTH] bad length" from the same dead
        SSLObject). The dedicated I/O thread needs a real, selector-capable
        socket -- a bare Mock has no real fileno() -- so this closes one
        side of a real socketpair before the connection ever touches it,
        forcing the very first write to fail.
        """
        localSocket, peerSocket = socket.socketpair()
        self.addCleanup(peerSocket.close)
        localSocket.close()
        webSocket = _WebSocketConnection(localSocket, WebTunnelClient._MAX_WS_OUTSTANDING_BYTES)

        with self.assertRaises(ConnectionError):
            webSocket.sendBinary(b'first')

        # A second send on the same (now-poisoned) connection must fail
        # cleanly too, without ever attempting another socket operation.
        with self.assertRaises(ConnectionError):
            webSocket.sendBinary(b'second')

    def testConnectSocketForcesTLS12OnPython312Workaround(self):
        """Same workaround bases.Utils.StallResilientAdapter applies to the
        requests-based upload/download path: Python 3.12 + OpenSSL 3.x has a
        documented SSLEOFError/stall issue specific to TLS 1.3. This
        connection is held open and read from for as long as a lane lives,
        exactly the kind of long-lived TLS connection that issue affects."""
        client = _newClient()
        rawSocket = mock.Mock()
        fakeContext = _FakeSSLContext()
        parsedURL = urllib.parse.urlsplit(client.agentURL)

        with mock.patch('bases.tunnels.Web.socket.create_connection', return_value=rawSocket), \
             mock.patch('bases.tunnels.Web.ssl.create_default_context', return_value=fakeContext), \
             mock.patch('bases.tunnels.Web.sys.version_info', (3, 12, 0)), \
             mock.patch('bases.tunnels.Web.ENABLE_PY312_WORKAROUND', True):
            client._connectSocket(parsedURL, 5)

        self.assertEqual(ssl.TLSVersion.TLSv1_2, fakeContext.minimum_version)
        self.assertEqual(ssl.TLSVersion.TLSv1_2, fakeContext.maximum_version)
        fakeContext.wrap_socket.assert_called_once_with(rawSocket, server_hostname=parsedURL.hostname)

    def testConnectSocketSkipsTLSForceWhenWorkaroundDisabled(self):
        client = _newClient()
        rawSocket = mock.Mock()
        fakeContext = _FakeSSLContext()
        parsedURL = urllib.parse.urlsplit(client.agentURL)

        with mock.patch('bases.tunnels.Web.socket.create_connection', return_value=rawSocket), \
             mock.patch('bases.tunnels.Web.ssl.create_default_context', return_value=fakeContext), \
             mock.patch('bases.tunnels.Web.sys.version_info', (3, 12, 0)), \
             mock.patch('bases.tunnels.Web.ENABLE_PY312_WORKAROUND', False):
            client._connectSocket(parsedURL, 5)

        self.assertIsNone(fakeContext.minimum_version)
        self.assertIsNone(fakeContext.maximum_version)

    def testWebSocketUpgradePerformsHandshakeAndReturnsConnection(self):
        client = _newClient()
        with _mockedWebSocketUpgradeHandshake(client) as rawSocket:
            connection = client._performWebSocketUpgrade('_tunnel/agent/lane')

        self.assertIsInstance(connection, _WebSocketConnection)
        rawSocket.sendall.assert_called_once()
        sentRequest = rawSocket.sendall.call_args.args[0].decode('ascii')
        self.assertIn('GET /_tunnel/agent/lane HTTP/1.1', sentRequest)
        self.assertIn('X-Tunnel-Context: share-id', sentRequest)
        self.assertIn(f'X-Tunnel-Agent-ID: {client.agentInstanceID}', sentRequest)
        self.assertEqual(client._MAX_WS_OUTSTANDING_BYTES, connection._maxOutstandingBytes)

    def testWebSocketUpgradeIncludesExtraHeadersForLaneIdentity(self):
        client = _newClient()
        with _mockedWebSocketUpgradeHandshake(client) as rawSocket:
            client._performWebSocketUpgrade('_tunnel/agent/lane', extraHeaders={'X-Tunnel-Lane-ID': '3'})

        sentRequest = rawSocket.sendall.call_args.args[0].decode('ascii')
        self.assertIn('X-Tunnel-Lane-ID: 3', sentRequest)

    def testWebTunnelRefreshesTokenOnlyAfterInitialConnection(self):
        tokenProvider = mock.Mock(return_value='refreshed-token')
        client = _newClient(tokenProvider=tokenProvider)

        client._refreshSecret()
        self.assertEqual('test-secret', client.secret)
        tokenProvider.assert_not_called()

        # Advance past the refresh throttle (see
        # testRefreshSecretThrottlesRepeatedCallsWithinMinInterval) so this
        # second call is treated as a genuine later refresh, not part of the
        # same startup burst.
        client._lastSecretRefreshAt -= client._MIN_SECRET_REFRESH_INTERVAL
        client._refreshSecret()
        self.assertEqual('refreshed-token', client.secret)
        tokenProvider.assert_called_once_with()

    def testRefreshSecretThrottlesRepeatedCallsWithinMinInterval(self):
        """Every lane's own connect() calls _refreshSecret() too (see
        _TunnelLane._connect), so a freshly-started pool of N lanes must not
        turn into N+1 tokenProvider() calls in a startup burst."""
        tokenProvider = mock.Mock(return_value='refreshed-token')
        client = _newClient(tokenProvider=tokenProvider)
        client._skipInitialRefresh = False # pretend the initial connect already happened

        for _ in range(9):
            client._refreshSecret()

        tokenProvider.assert_called_once_with()

    def testStopStopsEveryLane(self):
        client = _newClient()
        client.running = True
        fakeLanes = [mock.Mock(), mock.Mock()]
        client._lanes = fakeLanes

        client.stop()

        self.assertFalse(client.running)
        for lane in fakeLanes:
            lane.stop.assert_called_once()

    def testLanePoolStartsExactlyOnceAcrossMultipleControlReconnects(self):
        client = _newClient(laneCount=2)
        with mock.patch('bases.tunnels.Web._TunnelLane') as fakeLaneClass:
            fakeLaneClass.side_effect = lambda c, i: mock.Mock()
            client._startLanePoolOnce()
            # A later control reconnect calling connect() again must not
            # spin up a second pool alongside the first.
            client._startLanePoolOnce()

        self.assertEqual(2, fakeLaneClass.call_count)

    def testRunHeartbeatCallsOnFailureWhenPingFails(self):
        fakeWebSocket = mock.Mock()
        fakeWebSocket.sendPing.side_effect = ConnectionError('simulated ping failure')
        stopEvent = mock.Mock()
        stopEvent.wait.return_value = False # fires immediately; the failure returns before a 2nd iteration
        onFailure = mock.Mock()

        _newHeartbeatOwner(fakeWebSocket)._runHeartbeat(stopEvent, onFailure, 'test')

        onFailure.assert_called_once_with(fakeWebSocket)

    def testRunHeartbeatCallsOnTickAfterEachSuccessfulPing(self):
        fakeWebSocket = mock.Mock()
        stopEvent = mock.Mock()
        # False for the first iteration, True to end the loop afterwards --
        # unlike the failure tests below, nothing here raises to break the
        # loop on its own, so it must be told to stop after one tick.
        stopEvent.wait.side_effect = [False, True]
        onFailure = mock.Mock()
        onTick = mock.Mock()

        _newHeartbeatOwner(fakeWebSocket)._runHeartbeat(stopEvent, onFailure, 'test', onTick=onTick)

        onTick.assert_called_once_with()
        onFailure.assert_not_called()

    def testRunHeartbeatTreatsOnTickFailureLikeAFailedPing(self):
        """A raw ping succeeding but the application-level PING failing must
        still be treated as a dead transport -- otherwise a partially-broken
        connection (accepts raw WS control frames but can't carry
        application frames) would never be noticed."""
        fakeWebSocket = mock.Mock()
        stopEvent = mock.Mock()
        stopEvent.wait.return_value = False
        onFailure = mock.Mock()
        onTick = mock.Mock(side_effect=ConnectionError('simulated application ping failure'))

        _newHeartbeatOwner(fakeWebSocket)._runHeartbeat(stopEvent, onFailure, 'test', onTick=onTick)

        onFailure.assert_called_once_with(fakeWebSocket)

    def testRunHeartbeatSkipsRawPingOnTicksNotMatchingTheRatioButStillCallsOnTick(self):
        """The raw WebSocket-level ping is a pure transport-liveness probe
        -- auto-handled by the relay platform's runtime, never reaching the
        relay's frame handler -- so it has nothing to do with keeping the
        connection alive and doesn't need `interval`'s own fast cadence.
        onTick's own condition
        (see _TunnelLane._sendApplicationPing) still needs checking every
        tick regardless."""
        fakeWebSocket = mock.Mock()
        stopEvent = mock.Mock()
        stopEvent.wait.side_effect = [False, False, False, True]
        onFailure = mock.Mock()
        onTick = mock.Mock()

        _newHeartbeatOwner(fakeWebSocket)._runHeartbeat(
            stopEvent, onFailure, 'test', onTick=onTick, rawPingEveryNTicks=3,
        )

        self.assertEqual(3, onTick.call_count) # every tick
        fakeWebSocket.sendPing.assert_called_once() # only the 3rd
        onFailure.assert_not_called()

    def testControlHeartbeatFailureClosesSocketAndMarksDisconnected(self):
        client = _newClient()
        fakeWebSocket = mock.Mock()
        client._webSocket = fakeWebSocket
        client.connected = True

        client._onHeartbeatFailure(fakeWebSocket)

        self.assertIsNone(client._webSocket)
        self.assertFalse(client.connected)
        fakeWebSocket.close.assert_called_once_with(graceful=False)

    def testControlListenBackoffGrowsOnRepeatedImmediateFailureAndResetsAfterGenuineUptime(self):
        """AsyncTunnelThread's outer loop reconnects the instant listen()
        returns, with no delay of its own for this path -- listen() must
        throttle itself when the control connection keeps dying within
        moments of connecting, and only reset once a cycle genuinely stays
        up."""
        client = _newClient()
        client.running = True

        async def runCycle(elapsed):
            with mock.patch.object(client, '_listenControlSocket', return_value=False), \
                 mock.patch.object(client, '_closeWebSocket'), \
                 mock.patch('bases.tunnels.Web.time.monotonic', side_effect=[0.0, elapsed]), \
                 mock.patch('bases.tunnels.Web.random.uniform', return_value=0.01):
                await client.listen()

        asyncio.run(runCycle(0.1))
        self.assertEqual(2, client._backoff)

        asyncio.run(runCycle(0.2))
        self.assertEqual(4, client._backoff)

        asyncio.run(runCycle(client._MIN_HEALTHY_CONNECTION_DURATION + 1))
        self.assertEqual(1, client._backoff)


class TunnelLaneTest(unittest.TestCase):
    """Frame-level and lifecycle tests for a single _TunnelLane -- the unit
    that carries at most one HTTP request at a time (see the module
    docstring for the overall control-connection + lane-pool design)."""

    @staticmethod
    def _captureSends(frames):
        return lambda frameType, epoch, payload=b'', buffered=False: frames.append((frameType, epoch, payload))

    def testLaneAcceptsRequestStreamsOrderedChunksAndEnd(self):
        client = _newClient(chunkSize=3)
        lane = _TunnelLane(client, 0)
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
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state

        with mock.patch('bases.tunnels.Web.http.client.HTTPConnection', return_value=localConnection), \
             mock.patch.object(client, '_requestLocalServer', return_value=localResponse) as requestLocal, \
             mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
            lane._runRequest(state, {
                'method': 'POST', 'path': '/share/download', 'host': 'relay.example.com',
                'headers': [['Content-Type', 'application/json']], 'hasBody': True,
            }, b'input-body')

        requestLocal.assert_called_once()
        self.assertIs(localConnection, requestLocal.call_args.args[0])
        self.assertEqual(b'input-body', requestLocal.call_args.args[2])
        self.assertTrue(localConnection.closed)
        self.assertIsNone(lane._current)
        self.assertEqual([client._RESPONSE, client._DATA, client._DATA, client._END], [frame[0] for frame in frames])
        self.assertEqual([1, 1, 1, 1], [frame[1] for frame in frames])
        metadata = json.loads(frames[0][2].decode('utf-8'))
        self.assertEqual(206, metadata['status'])
        self.assertNotIn(['Transfer-Encoding', 'chunked'], metadata['headers'])
        self.assertEqual(b'345', frames[1][2])
        self.assertEqual(b'67', frames[2][2])
        self.assertEqual(b'', frames[3][2])

    def testLaneUsesBoundedRead1OnlyForFirstOrdinaryDataFrame(self):
        """First-byte latency policy must affect exactly one ordinary DATA
        frame; bulk frames still use the configured large read() size."""
        client = _newClient(chunkSize=20, firstDataSize=10)
        lane = _TunnelLane(client, 0)
        response = _FakeHTTPResponse(
            200, [('Content-Type', 'application/octet-stream')], b'0123456789' * 5, contentLength=50,
        )
        response.read1 = mock.Mock(wraps=response.read1)
        response.read = mock.Mock(wraps=response.read)
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state
        frames = []

        with mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
            lane._streamResponse(state, response)

        self.assertEqual([10], [call.args[0] for call in response.read1.call_args_list])
        self.assertEqual([20, 20], [call.args[0] for call in response.read.call_args_list])
        self.assertEqual(
            [b'0123456789', b'01234567890123456789', b'01234567890123456789'],
            [frame[2] for frame in frames],
        )

    def testLaneTreatsPrematureLocalEOFAsFailureNotCleanEnd(self):
        """http.client.HTTPResponse.read(n) -- the sized-read path used
        here -- does not raise on a premature local connection close when a
        Content-Length was declared: it silently returns fewer bytes than
        asked, leaves response.length non-zero, then returns b'' on the
        next call with no exception at all. Forwarding that as a clean END
        would hand the browser a truncated body under a 200 status with no
        error anywhere in the pipeline."""
        client = _newClient(chunkSize=1024)
        lane = _TunnelLane(client, 0)
        localConnection = _FakeConnection()
        body = b'x' * 40
        localResponse = _FakeHTTPResponse(
            200, [('Content-Type', 'application/octet-stream')], body, contentLength=len(body) + 60,
        )
        frames = []
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state

        with mock.patch('bases.tunnels.Web.http.client.HTTPConnection', return_value=localConnection), \
             mock.patch.object(client, '_requestLocalServer', return_value=localResponse), \
             mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
            lane._runRequest(state, {
                'method': 'GET', 'path': '/share/download', 'host': 'relay.example.com',
                'headers': [], 'hasBody': False,
            }, None)

        self.assertEqual([client._RESPONSE, client._DATA, client._CANCEL], [frame[0] for frame in frames])
        self.assertIn(b'ended early', frames[2][2])

    def testStreamResponseSkipsCreditWaitOnceContentLengthFullyRead(self):
        """END carries no payload and needs no send credit -- once
        response.length hits 0 (set by the read that delivered the last
        declared byte), the loop must return immediately instead of calling
        _waitForSendRoom() one more time just to make a now-pointless empty
        read() call and learn what response.length already knows for free.
        Without this, a lane whose origin body finished exactly as its
        credit ran out would sit blocked waiting on a WINDOW_UPDATE that
        only arrives once the browser pulls again."""
        client = _newClient(chunkSize=1024)
        lane = _TunnelLane(client, 0)
        body = b'x' * 40
        response = _FakeHTTPResponse(
            200, [('Content-Type', 'application/octet-stream')], body, contentLength=len(body),
        )
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state

        frames = []
        waitCalls = [0]
        originalWait = lane._waitForSendRoom

        def countingWait(s):
            waitCalls[0] += 1
            return originalWait(s)

        with mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)), \
             mock.patch.object(lane, '_waitForSendRoom', side_effect=countingWait):
            lane._streamResponse(state, response)

        self.assertEqual([client._DATA], [frame[0] for frame in frames])
        self.assertEqual(body, frames[0][2])
        self.assertEqual(1, waitCalls[0]) # exactly one wait -- not a second one just to discover EOF

    def testAcceptRequestRejectsSecondRequestWhileLaneIsBusy(self):
        """A lane must never be handed two live requests at once -- that
        invariant is the whole reason a lane exists. A relay-side bug that
        violates it should close the lane loudly, not silently guess which
        request is the real one."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        lane._current = _LaneRequestState(1, client._INITIAL_WINDOW)

        metadata = {'method': 'GET', 'path': '/x', 'host': 'relay.example.com', 'headers': [], 'hasBody': False}
        metadataBytes = json.dumps(metadata).encode('utf-8')
        payload = struct.pack('!I', len(metadataBytes)) + metadataBytes

        with self.assertRaises(ConnectionError):
            lane._acceptRequest(2, payload)

        self.assertEqual(1, lane._current.epoch) # the original request is untouched

    def testLaneAcceptsNextRequestImmediatelyAfterCancelWithoutWaitingForOldWorkerCleanup(self):
        """The relay releases a lane back to its idle pool -- and may
        dispatch a new REQUEST -- the instant it sends CANCEL, without
        waiting for the agent to confirm the old request's local cleanup
        finished. _current must already be clear the moment CANCEL is
        processed, not only once the old worker thread's own (possibly
        slow, e.g. blocked for its full 30s timeout on Windows) cleanup
        reaches its finally block."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        # No localConnection set on this state -- simulates the old worker
        # thread not having even gotten that far yet, the tightest version
        # of the race.
        lane._current = _LaneRequestState(1, client._INITIAL_WINDOW)

        lane._cancelCurrent(1)
        self.assertIsNone(lane._current)

        metadata = {'method': 'GET', 'path': '/x', 'host': 'relay.example.com', 'headers': [], 'hasBody': False}
        metadataBytes = json.dumps(metadata).encode('utf-8')
        payload = struct.pack('!I', len(metadataBytes)) + metadataBytes

        with mock.patch('bases.tunnels.Web.threading.Thread'):
            lane._acceptRequest(2, payload) # must not raise "still busy"

        self.assertEqual(2, lane._current.epoch)

    def testBufferedDataKeepsLaneBusyUntilTerminalFrameFlushes(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state
        sentFrames = []
        terminalStarted = threading.Event()
        releaseTerminal = threading.Event()

        def sendRaw(frameType, epoch, payload=b'', buffered=False):
            sentFrames.append((frameType, epoch, payload, buffered))
            if frameType == client._END:
                terminalStarted.set()
                releaseTerminal.wait(timeout=1)

        with mock.patch.object(lane, '_sendRaw', side_effect=sendRaw):
            lane._sendFrame(state, client._DATA, b'queued-data', buffered=True)
            terminalThread = threading.Thread(
                target=lane._sendFrame, args=(state, client._END, b''), kwargs={'final': True},
            )
            terminalThread.start()
            self.assertTrue(terminalStarted.wait(timeout=1))

            # END is a synchronous flush barrier. The old request remains
            # current until its terminal frame has crossed that barrier, so
            # no new request can append data after it in the writer FIFO.
            self.assertIs(state, lane._current)

            releaseTerminal.set()
            terminalThread.join(timeout=1)
            self.assertFalse(terminalThread.is_alive())

        self.assertIsNone(lane._current)
        self.assertEqual(
            [(client._DATA, True), (client._END, False)],
            [(frameType, buffered) for frameType, _, _, buffered in sentFrames],
        )
        # A second attempt to send on behalf of the same, now-detached state
        # must be refused, not silently accepted again.
        with self.assertRaises(ConnectionError):
            lane._sendFrame(state, client._END, b'', final=True)

    def testLaneSilentlyAcceptsPongWithoutWarningLog(self):
        """PONG is the relay's expected reply to this lane's own
        _sendApplicationPing -- it must not fall through to the "unsupported
        frame type" branch and log a warning on every heartbeat round-trip."""
        client = _newClient()
        lane = _TunnelLane(client, 0)

        with mock.patch('bases.tunnels.Web.logger') as logger:
            lane._handleFrame(client._PONG, 0, b'')

        logger.warning.assert_not_called()

    def testSendApplicationPingSkipsIdleLane(self):
        """Unlike the raw WebSocket-level ping (auto-handled by the relay
        platform's runtime, never itself keeping the connection alive on the
        relay side), any application-level message -- including this PING --
        does. An idle lane has nothing for the relay's stall diagnostics to
        observe, so it must not send one and keep the connection alive for
        no reason."""
        client = _newClient()
        lane = _TunnelLane(client, 0)

        with mock.patch.object(lane, '_sendRaw') as sendRaw:
            lane._sendApplicationPing()

        sendRaw.assert_not_called()

    def testSendApplicationPingSkipsRequestThatJustSentAFrame(self):
        """A lane streaming DATA continuously is already, by itself, all
        the liveness signal a relay instance needs (the relay platform keeps
        an instance active for as long as its request/response stream is in flight) --
        pinging on top of that would just be redundant PING/PONG traffic on
        every healthy download. lastFrameSentAt starts at "now" the moment
        a request is accepted, so this covers both a request that just
        began and one that just sent a RESPONSE/DATA/END/CANCEL."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        lane._current = _LaneRequestState(1, client._INITIAL_WINDOW) # lastFrameSentAt = now

        with mock.patch.object(lane, '_sendRaw') as sendRaw:
            lane._sendApplicationPing()

        sendRaw.assert_not_called()

    def testSendApplicationPingFiresOnceRequestHasGoneQuietForAFullInterval(self):
        """The one case this exists to surface: a live, uncancelled request
        that hasn't produced a RESPONSE/DATA/END/CANCEL of its own in a
        full heartbeat interval -- long enough that losing the connection in
        that gap would otherwise get treated as an abnormal restart (see
        busy-lane recovery). Independent of send credit -- a request can go
        quiet for reasons that have nothing to do with flow control
        (browser not pulling, local disk stall, upstream server pausing)."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, client._INITIAL_WINDOW) # credit available, but idle
        state.lastFrameSentAt -= client._LANE_HEARTBEAT_INTERVAL
        lane._current = state
        frames = []

        with mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
            lane._sendApplicationPing()

        self.assertEqual([(client._PING, 1, b'')], frames)

    def testSendFrameResetsTheIdleClockSendApplicationPingChecks(self):
        """A frame actually sent for this request must push the next
        eligible ping out by a full interval again -- otherwise a lane
        that's genuinely streaming DATA on a cadence close to the
        heartbeat's own would still get spurious PINGs in the gaps."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        state.lastFrameSentAt -= client._LANE_HEARTBEAT_INTERVAL
        lane._current = state

        with mock.patch.object(lane, '_sendRaw') as sendRaw:
            lane._sendFrame(state, client._DATA, b'x') # a real frame, resets the clock
            sendRawCallsAfterData = sendRaw.call_count
            lane._sendApplicationPing()

            # Only the DATA send itself, no PING on top of it.
            self.assertEqual(sendRawCallsAfterData, sendRaw.call_count)

    def testSendApplicationPingSkipsCancelledRequest(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, 0)
        state.cancelled = True
        state.lastFrameSentAt -= client._LANE_HEARTBEAT_INTERVAL
        lane._current = state

        with mock.patch.object(lane, '_sendRaw') as sendRaw:
            lane._sendApplicationPing()

        sendRaw.assert_not_called()

    def testStartHeartbeatWiresLaneApplicationPingAsOnTick(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        lane._webSocket = mock.Mock()

        with mock.patch('bases.tunnels.Web.threading.Thread') as fakeThread:
            lane._startHeartbeat()

        kwargs = fakeThread.call_args.kwargs['kwargs']
        self.assertEqual(lane._sendApplicationPing, kwargs['onTick'])
        # Comfortably under the window the relay would otherwise treat this
        # connection as idle enough to drop -- see WebTunnelClient._LANE_HEARTBEAT_INTERVAL.
        self.assertEqual(client._LANE_HEARTBEAT_INTERVAL, kwargs['interval'])
        self.assertLess(client._LANE_HEARTBEAT_INTERVAL, 10)
        # The raw transport ping has nothing to do with keeping the
        # connection alive and doesn't need the fast interval -- only every Nth tick.
        self.assertEqual(
            max(1, client._LANE_RAW_PING_INTERVAL // client._LANE_HEARTBEAT_INTERVAL),
            kwargs['rawPingEveryNTicks'],
        )

    def testStartHeartbeatNeverPassesZeroRawPingEveryNTicks(self):
        """A heartbeat interval raised above the raw-ping interval would
        floor-divide to 0 -- _runHeartbeat's own `tick % rawPingEveryNTicks`
        would then raise ZeroDivisionError on its very first tick, silently
        retiring an otherwise-healthy lane as a dead transport instead of
        surfacing the actual misconfiguration."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        lane._webSocket = mock.Mock()

        with mock.patch.object(WebTunnelClient, '_LANE_HEARTBEAT_INTERVAL', 25), \
             mock.patch('bases.tunnels.Web.threading.Thread') as fakeThread:
            lane._startHeartbeat()

        kwargs = fakeThread.call_args.kwargs['kwargs']
        self.assertEqual(1, kwargs['rawPingEveryNTicks'])

    def testSendRawFailureNullsLaneWebSocketImmediately(self):
        """Unlike the low-level _WebSocketConnection (which poisons its own
        internal socket reference on a write failure), _TunnelLane holds a
        separate reference to that same object -- a work thread's failed
        send must clear it too, or the lane's own receive loop (blocked on a
        read, possibly on a different thread) has nothing telling it the
        transport just died until the relay's side eventually notices."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        fakeWebSocket = mock.Mock()
        fakeWebSocket.sendBinary.side_effect = ConnectionError('simulated write failure')
        lane._webSocket = fakeWebSocket

        with self.assertRaises(ConnectionError):
            lane._sendRaw(client._PING, 0)

        self.assertIsNone(lane._webSocket)
        fakeWebSocket.close.assert_called_once_with(graceful=False)

    def testLaneSkipsBodyStreamingForNullBodyStatuses(self):
        """204/205/304 must not be streamed, matching the relay's own
        null-body handling -- otherwise the agent tries to read a body the
        relay already decided this request doesn't have."""
        for status in (204, 205, 304):
            with self.subTest(status=status):
                client = _newClient()
                lane = _TunnelLane(client, 0)
                localConnection = _FakeConnection()
                localResponse = _FakeHTTPResponse(status, [], b'')
                localResponse.read = mock.Mock(side_effect=AssertionError(f'{status} response must not be read as a body'))
                frames = []
                state = _LaneRequestState(1, client._INITIAL_WINDOW)
                lane._current = state

                with mock.patch('bases.tunnels.Web.http.client.HTTPConnection', return_value=localConnection), \
                     mock.patch.object(client, '_requestLocalServer', return_value=localResponse), \
                     mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
                    lane._runRequest(state, {
                        'method': 'GET', 'path': '/share/asset.js', 'host': 'relay.example.com',
                        'headers': [['If-None-Match', '"etag"']], 'hasBody': False,
                    }, None)

                self.assertEqual([client._RESPONSE, client._END], [frame[0] for frame in frames])

    def testLaneStreamResponseUsesRead1ForEventStreamContentType(self):
        """text/event-stream must use read1() (returns whatever's already
        arrived) rather than read() (blocks accumulating up to chunkSize or
        EOF) -- otherwise an SSE event can sit unsent for as long as the
        next one takes to show up."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        response = _FakeHTTPResponse(200, [('Content-Type', 'text/event-stream; charset=utf-8')], b'data: hello\n\n')
        response.read = mock.Mock(side_effect=AssertionError('read() must not be used for text/event-stream'))
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        lane._current = state

        frames = []
        with mock.patch.object(lane, '_sendRaw', side_effect=self._captureSends(frames)):
            lane._streamResponse(state, response)

        self.assertEqual([client._DATA], [frame[0] for frame in frames])
        self.assertEqual(b'data: hello\n\n', frames[0][2])

    def testLaneExitsPromptlyWhenCancelledMidWait(self):
        """Cancelling a request while its worker is blocked waiting for send
        credit must wake it immediately via _stateChanged.notify_all(), not
        leave it parked in wait(timeout=5) until the next poll."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        response = _FakeHTTPResponse(200, [('Content-Type', 'application/octet-stream')], b'irrelevant')
        state = _LaneRequestState(1, 0) # start exhausted so the thread waits immediately
        lane._current = state

        raised = {}
        finished = threading.Event()

        def worker():
            try:
                lane._streamResponse(state, response)
            except Exception as e:
                raised['error'] = e
            finished.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            with lane._stateChanged:
                state.cancelled = True
                lane._stateChanged.notify_all()

            self.assertTrue(finished.wait(timeout=2), "lane request thread did not exit after cancellation")
            self.assertIsInstance(raised.get('error'), ConnectionError)
        finally:
            thread.join(timeout=2)

    def testWaitForSendRoomLogsStallDiagnosticsAfterThreshold(self):
        """A stall waiting for send credit must be observable -- previously
        this loop woke up every 5s to silently recheck the condition, with
        nothing distinguishing an indefinite silent stall from ordinary
        legitimate backpressure."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, 0) # starts exhausted -- waits immediately
        state.bytesSent = 12345
        lane._current = state

        waitCallCount = [0]

        def fakeWait(timeout=None):
            waitCallCount[0] += 1
            if waitCallCount[0] >= 2:
                state.sendCredit = 100 # let the loop exit after logging once

        with mock.patch.object(lane._stateChanged, 'wait', side_effect=fakeWait), \
             mock.patch('bases.tunnels.Web.time.monotonic', side_effect=[0.0, 10.0]), \
             mock.patch('bases.tunnels.Web.logger') as fakeLogger:
            readSize = lane._waitForSendRoom(state)

        self.assertEqual(100, readSize)
        fakeLogger.warning.assert_called_once()
        self.assertIn('stalled waiting for send credit', fakeLogger.warning.call_args.args[0])

    def testWaitForSendRoomRaisesPastTheFailLoudDeadline(self):
        """The relay's own equivalent stall deadline only ever starts
        counting once *its* bookkeeping (remainingWindow)
        says the window is exhausted -- a credit-accounting divergence
        (the relay believes it already sent a WINDOW_UPDATE this lane never
        applied) leaves the relay's own view of remainingWindow > 0
        indefinitely, so its deadline never fires at all. Without an
        independent bound on this side, that divergence would wait forever
        behind nothing but a periodic warning log."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, 0) # starts exhausted -- waits immediately
        lane._current = state

        with mock.patch.object(lane._stateChanged, 'wait'), \
             mock.patch('bases.tunnels.Web.time.monotonic', side_effect=[0.0, 700.0]), \
             mock.patch('bases.tunnels.Web.logger'):
            with self.assertRaises(ConnectionError) as raised:
                lane._waitForSendRoom(state)

        self.assertIn('fail-loud deadline', str(raised.exception))

    def testCreditCurrentLogsAcceptedAndIgnoredWindowUpdates(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(3, 100)
        lane._current = state

        with mock.patch('bases.tunnels.Web.logger') as fakeLogger:
            lane._creditCurrent(3, struct.pack('!I', 50)) # matching epoch -- accepted
            lane._creditCurrent(2, struct.pack('!I', 50)) # stale epoch -- ignored

        fakeLogger.debug.assert_called_once()
        self.assertIn('accepted WINDOW_UPDATE', fakeLogger.debug.call_args.args[0])
        fakeLogger.info.assert_called_once()
        self.assertIn('ignored WINDOW_UPDATE', fakeLogger.info.call_args.args[0])

    def testLaneSendFrameRefusesStaleEpoch(self):
        """A work thread whose request has been superseded by a newer one on
        the same lane must not be able to write a frame for it -- this is
        what keeps a late/slow old request from corrupting the new one now
        sharing the same underlying socket."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        oldState = _LaneRequestState(1, client._INITIAL_WINDOW)
        newState = _LaneRequestState(2, client._INITIAL_WINDOW)
        lane._current = newState # the lane has already moved on

        with self.assertRaises(ConnectionError):
            lane._sendFrame(oldState, client._DATA, b'stale')

    def testLaneCancelFrameForceClosesLocalConnectionForMatchingEpoch(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(5, client._INITIAL_WINDOW)
        connection = _FakeConnection()
        connection.sock = None
        state.localConnection = connection
        lane._current = state

        lane._cancelCurrent(5)

        self.assertTrue(state.cancelled)
        self.assertTrue(connection.closed)

    def testLaneCancelIgnoresStaleEpoch(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(5, client._INITIAL_WINDOW)
        lane._current = state

        lane._cancelCurrent(4) # a CANCEL for an epoch this lane already moved past

        self.assertFalse(state.cancelled)

    def testLaneWindowUpdateCreditsCurrentRequest(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(3, 100)
        lane._current = state

        lane._creditCurrent(3, struct.pack('!I', 50))

        self.assertEqual(150, state.sendCredit)

    def testLaneWindowUpdateIgnoresStaleEpoch(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(3, 100)
        lane._current = state

        lane._creditCurrent(2, struct.pack('!I', 50))

        self.assertEqual(100, state.sendCredit)

    def testLaneHeartbeatFailureClosesWebSocket(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)
        fakeWebSocket = mock.Mock()
        lane._webSocket = fakeWebSocket

        lane._onTransportFailure(fakeWebSocket)

        self.assertIsNone(lane._webSocket)
        fakeWebSocket.close.assert_called_once_with(graceful=False)

    def testLaneBackoffGrowsOnRepeatedImmediateFailureAndResetsAfterGenuineUptime(self):
        client = _newClient()
        lane = _TunnelLane(client, 0)

        def runCycle(elapsed):
            with mock.patch.object(lane, '_connect'), \
                 mock.patch.object(lane, '_listen', return_value=False), \
                 mock.patch.object(lane, '_closeWebSocket'), \
                 mock.patch.object(lane, '_cleanupAfterDisconnect'), \
                 mock.patch('bases.tunnels.Web.time.monotonic', side_effect=[0.0, elapsed]), \
                 mock.patch('bases.tunnels.Web.random.uniform', return_value=0.01):
                lane._runOneCycle()

        runCycle(0.1)
        self.assertEqual(2, lane._backoff)

        runCycle(0.2)
        self.assertEqual(4, lane._backoff)

        runCycle(client._MIN_HEALTHY_CONNECTION_DURATION + 1)
        self.assertEqual(1, lane._backoff)

    def testLaneDisconnectCancelsOnlyItsOwnHeldRequest(self):
        """_cleanupAfterDisconnect fails whatever request this lane was
        holding when its transport died -- no resume, matching the plain
        Bore tunnel's own failure semantics. This is what keeps one lane's
        failure from ever being able to affect another lane's request."""
        client = _newClient()
        lane = _TunnelLane(client, 0)
        state = _LaneRequestState(1, client._INITIAL_WINDOW)
        connection = _FakeConnection()
        connection.sock = None
        state.localConnection = connection
        lane._current = state

        lane._cleanupAfterDisconnect()

        self.assertIsNone(lane._current)
        self.assertTrue(connection.closed)


class WebTunnelFunctionalTest(BrowserTestBase):
    """Functional test: a real P2P + E2EE share forced onto the web tunnel via
    FFL_TUNNEL_DOMAIN, downloaded end-to-end through a real browser (WebRTC +
    in-browser E2EE decryption)."""

    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testP2PWithE2EEOverWebTunnel(self):
        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=['--e2ee'],
            extraEnvVars={'FFL_TUNNEL_DOMAIN': '1.10.fastfilelink.com'},
        )

        self.assertIn('1.10.fastfilelink.com', shareLink, "Share link should use the web tunnel domain")
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
