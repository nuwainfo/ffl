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

import concurrent.futures
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest

from unittest import mock

from bases.Tunnel import TunnelRunner, fetchTunnelToken # isort:skip
from bases.tunnels import ( # isort:skip
    SUPPORTED_TUNNEL_TYPES, TunnelCandidate, TunnelDialer, TunnelRace, TunnelSSLContext, getLowLatencyTunnel
)
from bases.tunnels.Bore import BoreClient, BoreTunnelCandidate # isort:skip
from addons.Features import FeatureManager # isort:skip
from bases.Utils import parseProxyString # isort:skip
from tests.CoreTestBase import FastFileLinkTestBase
from tests.ProxyTestServer import LocalTunnelProxy


def _buildTunnelTypeTestClasses():
    """Map each transport type to the live integration TestCase that exercises
    it, built lazily so importing this module doesn't drag in every tunnel
    test module's own dependencies.

    /api/tunnels decides transport per-domain via its `type` field (see
    bases/tunnels/__init__.py) -- getBuiltinTunnels() asks for every type this
    client supports (bases.tunnels.SUPPORTED_TUNNEL_TYPES), so both 'bore' and
    'web' candidates can appear here. Dispatching on `type` instead of
    assuming 'bore' means each candidate is tested with the client code that
    will actually handle it in production, not silently exercised through the
    wrong transport (which would just fail with a confusing low-level
    protocol error instead of a clear "no test for this type" message); a
    type this test suite has no live coverage for yet fails loudly instead of
    being skipped unnoticed.
    """
    from tests.bases.tunnels.BoreTest import BoreHTTPSTest # isort:skip
    from tests.bases.tunnels.WebTest import WebHTTPSTest # isort:skip

    return {
        'bore': lambda host, secret, tempDir, port: BoreHTTPSTest(
            methodName='testUseHTTPSTunnel', remoteHost=host, secret=secret, tempDir=tempDir, port=port
        ),
        'web': lambda host, secret, tempDir, port: WebHTTPSTest(
            methodName='testUseHTTPSTunnel', remoteHost=host, secret=secret, tempDir=tempDir, port=port
        ),
    }


class TunnelsIntegrationTest(unittest.TestCase):

    def testAllTunnelServers(self):
        servers = FastFileLinkTestBase.getBuiltinTunnels()
        typeTestClasses = _buildTunnelTypeTestClasses()

        typeCounts = {}
        for tunnel in servers:
            tunnelType = tunnel.get('type')
            typeCounts[tunnelType] = typeCounts.get(tunnelType, 0) + 1
        typeBreakdown = ', '.join(f'{t}={n}' for t, n in sorted(typeCounts.items(), key=lambda kv: str(kv[0])))

        print(f"\n[Test] Total servers to test: {len(servers)} ({typeBreakdown})\n")

        results = []
        lock = threading.Lock()

        def runOne(i, tunnel):
            host = tunnel["domain"]
            tunnelType = tunnel.get("type")
            tempDir = tempfile.mkdtemp()
            port = 9000 + i

            try:
                if tunnelType not in SUPPORTED_TUNNEL_TYPES:
                    with lock:
                        print(f"[❌ FAIL] {host} - Unknown tunnel type {tunnelType!r} from /api/tunnels")
                        results.append((host, False))
                    return

                buildTestCase = typeTestClasses.get(tunnelType)
                if buildTestCase is None:
                    with lock:
                        print(
                            f"[❌ FAIL] {host} - No live integration test registered for tunnel "
                            f"type {tunnelType!r} (add one under tests/bases/tunnels/ and wire it "
                            f"into _buildTunnelTypeTestClasses)"
                        )
                        results.append((host, False))
                    return

                # Fetch token dynamically for each test
                print(f"[Test] Fetching token for {host}...")
                try:
                    secret = fetchTunnelToken(domain=host)
                except Exception as e:
                    isJenkins = 'JENKINS_HOME' in os.environ
                    isRateLimited = '429' in str(e)
                    if isJenkins and isRateLimited:
                        print(
                            f"[⚠️  WARN] {host} - Token fetch returned 429 on Jenkins "
                            f"(Jenkins itself may be on this server). "
                            f"Falling back to fastfilelink.com token."
                        )
                        try:
                            secret = fetchTunnelToken(domain='fastfilelink.com')
                        except Exception as fallbackE:
                            with lock:
                                print(f"[❌ FAIL] {host} - Fallback token fetch also failed: {fallbackE}")
                                results.append((host, False))
                            return
                    else:
                        with lock:
                            print(f"[❌ FAIL] {host} - Token fetch failed: {e}")
                            results.append((host, False))
                        return

                testCase = buildTestCase(host, secret, tempDir, port)
                result = unittest.TestResult()
                testCase.run(result)

                with lock:
                    if result.failures or result.errors:
                        print(f"[❌ FAIL] {host}")

                        for test_case, traceback_str in result.failures + result.errors:
                            print(f"\n[TestCase] {test_case.id()}")
                            print("[Traceback]")
                            print(traceback_str)

                        results.append((host, False))
                    else:
                        print(f"[✅ OK] {host} ({tunnelType})")
                        results.append((host, True))

            finally:
                shutil.rmtree(tempDir, ignore_errors=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(runOne, i, tunnel) for i, tunnel in enumerate(servers)]
            concurrent.futures.wait(futures)

        failed = [host for host, ok in results if not ok]
        if failed:
            self.fail(f"{len(failed)} tunnel server(s) failed: {failed}")

        self.assertTrue(len(failed) == 0)


class TunnelProxyTestBase(unittest.TestCase):
    """A real proxy (tests/ProxyTestServer.py) that redirects every tunnel to
    a local listener. Destinations use the reserved `.invalid` TLD, which never
    resolves, so only a connection that really went through the proxy can
    succeed.
    """

    RELAY_DOMAIN = 'relay.proxy-only.invalid'
    PROBE_HOST = f'0.{RELAY_DOMAIN}'

    def setUp(self):
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.acceptThread = threading.Thread(target=self._acceptForever, daemon=True)
        self.acceptThread.start()
        self.proxies = []

    def tearDown(self):
        for proxy in self.proxies:
            proxy.stop()
        self.listener.close()

    def _acceptForever(self):
        while True:
            try:
                conn, _address = self.listener.accept()
            except OSError:
                return # listener closed by tearDown
            conn.close()

    def _startProxy(self, username=None, password=None):
        proxy = LocalTunnelProxy(username=username, password=password, redirectTo=self.listener.getsockname())
        self.proxies.append(proxy.start())
        return proxy

    def _raceThrough(self, proxyURL):
        candidates = [TunnelCandidate.fromDomain(self.RELAY_DOMAIN)]
        with mock.patch.dict(os.environ, {'FFL_TUNNEL_SOCKS5': ''}):
            return getLowLatencyTunnel(candidates, proxyConfig=parseProxyString(proxyURL))


class TunnelProxyTest(TunnelProxyTestBase):
    """Tunnel probing and dialing must honour --proxy, whether it is SOCKS5 or HTTP CONNECT."""

    def testLowLatencyRaceProbesThroughHTTPProxy(self):
        proxy = self._startProxy()

        winner = self._raceThrough(proxy.httpURL)

        self.assertEqual(self.RELAY_DOMAIN, winner.domain)
        self.assertIsNotNone(winner.latency)
        self.assertIn((self.PROBE_HOST, 443), proxy.targets)

    def testLowLatencyRaceProbesThroughSocks5Proxy(self):
        proxy = self._startProxy()

        winner = self._raceThrough(proxy.socks5URL)

        self.assertEqual(self.RELAY_DOMAIN, winner.domain)
        self.assertIn((self.PROBE_HOST, 443), proxy.targets)

    def testLowLatencyRaceFailsWhenProxyRejectsCredentials(self):
        proxy = self._startProxy(username='alice', password='secret')

        with self.assertRaises(ConnectionError):
            self._raceThrough(f"http://alice:wrong@127.0.0.1:{proxy.httpPort}")

        self.assertEqual([], proxy.targets)
        self.assertGreater(proxy.rejectedAuthentications, 0)

    def testBorePreConnectUsesHTTPProxyWithBasicAuth(self):
        proxy = self._startProxy(username='alice', password='s3cret')

        sock = BoreClient.openTcpConnectionBlocking(self.PROBE_HOST, 443, proxyConfig=parseProxyString(proxy.httpURL))

        self.assertIsNotNone(sock)
        sock.close()
        self.assertEqual([(self.PROBE_HOST, 443)], proxy.targets)
        self.assertEqual(0, proxy.rejectedAuthentications)

    def testBorePreConnectUsesSocks5UsernamePasswordAuth(self):
        proxy = self._startProxy(username='alice', password='secret')

        sock = BoreClient.openTcpConnectionBlocking(self.PROBE_HOST, 443, proxyConfig=parseProxyString(proxy.socks5URL))

        self.assertIsNotNone(sock)
        sock.close()
        self.assertEqual([(self.PROBE_HOST, 443)], proxy.targets)
        self.assertEqual(0, proxy.rejectedAuthentications)

    def testTunnelRunnerReportsHTTPProxyWithoutPassword(self):
        runner = TunnelRunner(1024, proxyConfig=parseProxyString('http://alice:secret@127.0.0.1:3128'))

        self.assertEqual('http://alice@127.0.0.1:3128', runner.getProxyInfo())


class TunnelPreferenceTest(unittest.TestCase):
    """The web tunnel is preferred. Directly or through SOCKS5, relays are
    ranked by latency weighted by tunnel type, bore weighing 2: bore wins only
    when web is more than twice as slow. Behind an HTTP proxy web always wins
    while one is reachable: HTTP proxies -- especially TLS-intercepting ones --
    reliably carry only HTTP(S), which the web tunnel (WebSocket over HTTPS)
    is and bore's own protocol is not. Probe latencies are simulated (in real
    time, since the race decides on elapsed time), so the outcome does not
    depend on the network."""

    BORE_DOMAIN = 'bore.proxy-only.invalid'
    WEB_DOMAIN = 'web.proxy-only.invalid'
    HTTP_PROXY_URL = 'http://127.0.0.1:3128'
    SOCKS5_PROXY_URL = 'socks5://127.0.0.1:1080'

    def _race(self, latencies, proxyURL=None, unreachableAfter=0):
        """Race a bore and a web relay whose probes take `latencies[type]` ms
        (None: unreachable, failing after `unreachableAfter` ms)."""
        candidates = [
            TunnelCandidate.fromDict({'domain': self.BORE_DOMAIN, 'type': 'bore'}),
            TunnelCandidate.fromDict({'domain': self.WEB_DOMAIN, 'type': 'web'}),
        ]
        latencyByHost = {candidate.probeHost: latencies[candidate.type] for candidate in candidates}

        def measureLatency(dialer, host, port=443, timeout=5):
            latency = latencyByHost[host]
            time.sleep((latency if latency is not None else unreachableAfter) / 1000)
            return latency

        proxyConfig = parseProxyString(proxyURL) if proxyURL else None
        with mock.patch.dict(os.environ, {'FFL_TUNNEL_SOCKS5': ''}), \
             mock.patch.object(TunnelDialer, 'measureLatency', measureLatency):
            return getLowLatencyTunnel(candidates, proxyConfig=proxyConfig)

    def testDirectPicksWebUnlessItIsMoreThanTwiceAsSlow(self):
        winner = self._race({'bore': 200, 'web': 300})

        self.assertEqual('web', winner.type)

    def testDirectPicksBoreWhenWebIsMoreThanTwiceAsSlow(self):
        winner = self._race({'bore': 200, 'web': 500})

        self.assertEqual('bore', winner.type)

    def testSocks5ProxyWeighsLikeDirect(self):
        self.assertEqual('web', self._race({'bore': 200, 'web': 300}, self.SOCKS5_PROXY_URL).type)
        self.assertEqual('bore', self._race({'bore': 200, 'web': 500}, self.SOCKS5_PROXY_URL).type)

    def testHTTPProxyPicksWebEvenWhenMuchSlower(self):
        winner = self._race({'bore': 50, 'web': 500}, self.HTTP_PROXY_URL)

        self.assertEqual('web', winner.type)

    def testHTTPProxyFallsBackToBoreWhenNoWebRelayIsReachable(self):
        winner = self._race({'bore': 5, 'web': None}, self.HTTP_PROXY_URL)

        self.assertEqual('bore', winner.type)

    def testWinnerDoesNotWaitForProbesThatCanNoLongerBeatIt(self):
        startTime = time.monotonic()
        winner = self._race({'bore': 50, 'web': 3000})

        self.assertEqual('bore', winner.type)
        self.assertLess(time.monotonic() - startTime, 1.5)

    def testHTTPProxyDoesNotWaitForFallbackProbes(self):
        startTime = time.monotonic()
        winner = self._race({'bore': 3000, 'web': 50}, self.HTTP_PROXY_URL)

        self.assertEqual('web', winner.type)
        self.assertLess(time.monotonic() - startTime, 1.5)

    def testHTTPProxyProbesFallbacksAlongsideWeb(self):
        # The bore probe runs while web times out, so falling back costs no extra probe round.
        startTime = time.monotonic()
        winner = self._race({'bore': 500, 'web': None}, self.HTTP_PROXY_URL, unreachableAfter=1000)

        self.assertEqual('bore', winner.type)
        self.assertLess(time.monotonic() - startTime, 1.3)

    def testCandidatesThatCanWinAreProbedFirst(self):
        # With a single probe slot, web must not wait queued behind the bore probe it would beat anyway.
        startTime = time.monotonic()
        with mock.patch.object(TunnelRace, 'MAX_PARALLEL_PROBES', 1):
            winner = self._race({'bore': 1000, 'web': 50}, self.HTTP_PROXY_URL)

        self.assertEqual('web', winner.type)
        self.assertLess(time.monotonic() - startTime, 0.8)

    def testDirectReusesCachedBoreRelayInPrefetch(self):
        cachedBore = {'domain': self.BORE_DOMAIN, 'type': 'bore', 'domainSelectedAt': time.time()}

        with mock.patch.dict(os.environ, {'FFL_TUNNEL_SOCKS5': ''}), \
             mock.patch('addons.Features._tunnelPrefetchCache') as fakeCache, \
             mock.patch('addons.Features.getLowLatencyTunnel') as race, \
             mock.patch.object(BoreTunnelCandidate, 'tryReuseCached', return_value=True):
            fakeCache.load.return_value = cachedBore
            fakeCache.isDomainFresh.return_value = True
            candidate = FeatureManager._fetchTunnelAndToken(mock.Mock(), 1024, None)

        race.assert_not_called()
        self.assertEqual(self.BORE_DOMAIN, candidate.domain)

    def testHTTPProxySkipsCachedBoreRelayInPrefetch(self):
        cachedBore = {'domain': self.BORE_DOMAIN, 'type': 'bore', 'domainSelectedAt': time.time()}
        webWinner = TunnelCandidate.fromDict({'domain': self.WEB_DOMAIN, 'type': 'web'})
        fakeFeatureManager = mock.Mock()

        with mock.patch('addons.Features._tunnelPrefetchCache') as fakeCache, \
             mock.patch('addons.Features.getLowLatencyTunnel', return_value=webWinner) as race, \
             mock.patch.object(BoreTunnelCandidate, 'tryReuseCached') as reuseCached:
            fakeCache.load.return_value = cachedBore
            fakeCache.isDomainFresh.return_value = True
            candidate = FeatureManager._fetchTunnelAndToken(
                fakeFeatureManager, 1024, parseProxyString('http://127.0.0.1:3128')
            )

        reuseCached.assert_not_called()
        race.assert_called_once()
        self.assertIs(webWinner, candidate)


class TunnelSSLContextTest(unittest.TestCase):
    """Tunnel TLS must trust the CA bundles the environment names -- the same
    REQUESTS_CA_BUNDLE `requests` trusts for FFL's API calls, or SSL_CERT_FILE --
    so it works behind a TLS-intercepting proxy, and must still reject an
    interceptor nobody trusts."""

    CA_BUNDLE_ENV_VARS = ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')
    RELAY_HOST = 'fastfilelink.com'

    def setUp(self):
        self.proxy = LocalTunnelProxy(interceptTLS=True).start()

    def tearDown(self):
        self.proxy.stop()

    def _handshakeThroughInterceptingProxy(self, **caBundleEnvironment):
        dialer = TunnelDialer.fromProxyConfig(parseProxyString(self.proxy.httpURL))
        with mock.patch.dict(os.environ):
            for name in self.CA_BUNDLE_ENV_VARS:
                os.environ.pop(name, None)
            os.environ.update(caBundleEnvironment)

            context = TunnelSSLContext.create()

        with context.wrap_socket(dialer.dial(self.RELAY_HOST, 443, 15), server_hostname=self.RELAY_HOST) as tlsSocket:
            return tlsSocket.getpeercert()

    def testTrustsRequestsCABundle(self):
        certificate = self._handshakeThroughInterceptingProxy(REQUESTS_CA_BUNDLE=self.proxy.caCertPath)

        self.assertIsNotNone(certificate)

    def testTrustsSSLCertFile(self):
        certificate = self._handshakeThroughInterceptingProxy(SSL_CERT_FILE=self.proxy.caCertPath)

        self.assertIsNotNone(certificate)

    def testRejectsUntrustedInterceptor(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._handshakeThroughInterceptingProxy()


class TunnelSSLContextSharingTest(unittest.TestCase):
    """shared() builds one context per process for each TLS-version pin, so a
    pinned variant never alters the unpinned context other tunnels use."""

    def setUp(self):
        sharedPatch = mock.patch.object(TunnelSSLContext, '_shared', {})
        sharedPatch.start()
        self.addCleanup(sharedPatch.stop)

    def testReturnsTheSameContextEveryTime(self):
        self.assertIs(TunnelSSLContext.shared(), TunnelSSLContext.shared())

    def testPinnedVariantIsSeparateAndPinned(self):
        unpinned = TunnelSSLContext.shared()
        pinned = TunnelSSLContext.shared(ssl.TLSVersion.TLSv1_2)

        self.assertIsNot(unpinned, pinned)
        self.assertIs(pinned, TunnelSSLContext.shared(ssl.TLSVersion.TLSv1_2))
        self.assertEqual(ssl.TLSVersion.TLSv1_2, pinned.minimum_version)
        self.assertEqual(ssl.TLSVersion.TLSv1_2, pinned.maximum_version)
        self.assertNotEqual(ssl.TLSVersion.TLSv1_2, unpinned.maximum_version)


if __name__ == '__main__':
    unittest.main()
