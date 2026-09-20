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

"""Tests for the 'lan' tunnel type (FFL_TUNNEL_DOMAIN=lan).

Purpose of LAN: share a file with a receiver on the same local network with no
relay and no internet dependency. The share link points straight at the
sender's LAN IPv4 address, and while it is active FFL must not depend on
external STUN servers or NAT port mapping.

The runtime network policy that expresses this (SettingsGetter
.overrideNetworkPolicy) is context-local, because one process (the daemon) can
serve LAN shares while it concurrently downloads from other kinds of URLs.
"""

import asyncio
import json
import os
import socket
import tempfile
import threading
import unittest

from unittest import mock
from urllib.parse import urlparse

import requests

from bases.Daemon import DaemonClient, DaemonSharedRuntime # isort:skip
from bases.Kernel import StorageLocator # isort:skip
from bases.Settings import NetworkPolicy, SettingsGetter # isort:skip
from bases.Tunnel import TunnelRunner # isort:skip
from bases.tunnels import SUPPORTED_TUNNEL_TYPES, TunnelCandidate, resolveTunnelCandidate, resolveTunnelDomainFromEnv # isort:skip
from bases.tunnels.LAN import LANTunnelCandidate, LANTunnelClient, LANTunnelConfigurationError # isort:skip
from bases.tunnels.Loopback import LoopbackTunnelCandidate # isort:skip
from bases.Utils import NetworkEndpoint # isort:skip
from addons.Tunnels import TunnelRunnerProvider # isort:skip
from tests.CoreTestBase import FastFileLinkTestBase
from tests.bases.DaemonTest import DaemonLifecycleMixin


def detectLANHost():
    """The sender's own LAN IPv4, or None when this machine has no LAN interface."""
    try:
        return LANTunnelClient.resolveLANHost()
    except LANTunnelConfigurationError:
        return None


LAN_HOST = detectLANHost()
requiresLAN = unittest.skipIf(LAN_HOST is None, 'No non-loopback IPv4 interface available')


def getFreePort():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def getLinkTunnelType(shareLink):
    """The type of tunnel a share link was served through, read from its host."""
    host = urlparse(shareLink).hostname
    return 'lan' if host == LAN_HOST else TunnelCandidate.resolveType(host)


def assertOfferAdvertisesLANHost(testCase, shareLink):
    """The share's P2P offer must point the peer at the LAN address, not at 127.0.0.1."""
    response = requests.get(f'{shareLink}/p2p/offer', timeout=15)
    testCase.assertEqual(response.status_code, 200, response.text)
    endpoints = json.loads(response.text)['tcpEndpoints']

    testCase.assertTrue(endpoints, 'Offer must advertise at least one TCP endpoint')
    testCase.assertTrue(any(LAN_HOST in endpoint for endpoint in endpoints), endpoints)
    testCase.assertFalse(any('127.0.0.1' in endpoint for endpoint in endpoints), endpoints)


class PreservedTunnelPreference:
    """--preferred-tunnel persists into the user's tunnels.json; put it back after each test."""

    def setUp(self):
        configPath = StorageLocator.getInstance().findConfig('tunnels.json', prefer=StorageLocator.Location.CURRENT)
        originalContent = None
        if os.path.exists(configPath):
            with open(configPath, 'rb') as configFile:
                originalContent = configFile.read()

        self.addCleanup(self._restoreTunnelConfig, configPath, originalContent)
        super().setUp()

    @staticmethod
    def _restoreTunnelConfig(configPath, originalContent):
        if originalContent is None:
            if os.path.exists(configPath):
                os.remove(configPath)

            return

        with open(configPath, 'wb') as configFile:
            configFile.write(originalContent)


class EnvironmentTestCase(unittest.TestCase):
    """Restores FFL_TUNNEL_DOMAIN / FFL_LAN_HOST around each test."""

    ENV_NAMES = ('FFL_TUNNEL_DOMAIN', 'FFL_LAN_HOST')

    def setUp(self):
        self._savedEnv = {name: os.environ.pop(name, None) for name in self.ENV_NAMES}

    def tearDown(self):
        for name, value in self._savedEnv.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class LANTunnelResolutionTest(EnvironmentTestCase):
    """FFL_TUNNEL_DOMAIN=lan resolves to a LAN candidate that needs no network."""

    def testLANIsARegisteredTunnelType(self):
        self.assertIn('lan', SUPPORTED_TUNNEL_TYPES)

    def testEnvSelectsLANCandidate(self):
        for alias in ('lan', 'LAN', ' lan '):
            with self.subTest(alias=alias):
                os.environ['FFL_TUNNEL_DOMAIN'] = alias
                candidate = resolveTunnelDomainFromEnv()
                self.assertIsInstance(candidate, LANTunnelCandidate)

    def testBaselineResolverHonorsLANOverride(self):
        os.environ['FFL_TUNNEL_DOMAIN'] = 'lan'
        self.assertIsInstance(resolveTunnelCandidate(), LANTunnelCandidate)

    def testCandidateFromDictResolvesByType(self):
        candidate = TunnelCandidate.fromDict({'domain': 'anything', 'type': 'lan'})
        self.assertIsInstance(candidate, LANTunnelCandidate)

    @requiresLAN
    def testTunnelRunnerNeverTouchesTheInternet(self):
        os.environ['FFL_TUNNEL_DOMAIN'] = 'lan'
        with mock.patch('bases.Tunnel.requests.get', side_effect=AssertionError('no reachability probe for LAN')):
            with mock.patch('bases.Tunnel.fetchTunnelToken', side_effect=AssertionError('no token for LAN')):
                with TunnelRunner(fileSize=0) as runner:
                    port = getFreePort()
                    _domain, link = runner.start(port)

                    self.assertEqual(link, f'http://{LAN_HOST}:{port}/')


class PreferredTunnelTypeTest(EnvironmentTestCase):
    """`--preferred-tunnel default:<type>` forces one type of the built-in tunnels, no env var needed."""

    def _createRunner(self, preferredTunnel):
        with tempfile.TemporaryDirectory() as configDir:
            configPath = os.path.join(configDir, 'tunnels.json')
            with open(configPath, 'w', encoding='utf-8') as configFile:
                json.dump({'tunnels': {}, 'settings': {'preferred_tunnel': preferredTunnel}}, configFile)

            provider = TunnelRunnerProvider(configPath=configPath)
            return provider, provider.getTunnelRunnerClass(TunnelRunner)(0)

    def testCLIOffersEverySupportedTypeByItsPublicName(self):
        """bore is an implementation, so users see it as tcp."""
        provider, _runner = self._createRunner('default')
        choices = provider.getAvailableTunnels(includeDefault=True)
        self.assertIn('default', choices)
        for publicName in ('tcp', 'web', 'lan', 'loopback'):
            self.assertIn(f'default:{publicName}', choices)

        self.assertNotIn('default:bore', choices)

    def testForcedTypeSelectsThatTunnel(self):
        for preferredTunnel, expectedType in (
            ('default:tcp', 'bore'), ('default:web', 'web'), ('default:lan', 'lan'), ('default:loopback', 'loopback')
        ):
            with self.subTest(preferredTunnel=preferredTunnel):
                _provider, runner = self._createRunner(preferredTunnel)
                self.assertEqual(runner.resolvedType, expectedType)

    def testTCPIsAnotherNameForBore(self):
        for preferredTunnel in ('default:tcp', 'default:bore'):
            with self.subTest(preferredTunnel=preferredTunnel):
                self.assertEqual(TunnelRunnerProvider.parseForcedTunnelType(preferredTunnel), 'bore')

    def testPlainDefaultForcesNothing(self):
        _provider, runner = self._createRunner('default')
        self.assertIsNone(runner.forcedTunnelType)

    def testForcedTypeWinsOverEnvironment(self):
        os.environ['FFL_TUNNEL_DOMAIN'] = 'localhost'
        _provider, runner = self._createRunner('default:lan')
        self.assertEqual(runner.resolvedType, 'lan')

    def testUnknownForcedTypeFailsFast(self):
        for preferredTunnel in ('default:nope', 'default:', 'default:localhost'):
            with self.subTest(preferredTunnel=preferredTunnel):
                with self.assertRaises(ValueError):
                    self._createRunner(preferredTunnel)


class LANHostSelectionTest(EnvironmentTestCase):
    """Which local address LAN advertises, and what is rejected."""

    def testEnvOverridesAutoDetection(self):
        os.environ['FFL_LAN_HOST'] = '10.20.30.40'
        self.assertEqual(LANTunnelClient.resolveLANHost(), '10.20.30.40')

    def testRejectsAddressesTheReceiverCannotReach(self):
        for badHost in ('127.0.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', 'not-an-ip', 'example.com'):
            with self.subTest(host=badHost):
                os.environ['FFL_LAN_HOST'] = badHost
                with self.assertRaises(LANTunnelConfigurationError):
                    LANTunnelClient.resolveLANHost()

    def testNoUsableAddressFailsFastWithHint(self):
        with mock.patch.object(LANTunnelClient, '_selectHostByRoute', return_value=None), \
                mock.patch.object(LANTunnelClient, '_selectHostByHostname', return_value=None):
            with self.assertRaisesRegex(LANTunnelConfigurationError, 'FFL_LAN_HOST'):
                LANTunnelClient.resolveLANHost()


class LANTunnelClientTest(EnvironmentTestCase):
    """Client lifecycle and byte relay, driven directly on an event loop."""

    @requiresLAN
    def testListenBlocksUntilShutdownThenClosesTheRelay(self):
        async def run():
            client = LANTunnelClient(getFreePort(), lanHost=LAN_HOST)
            client.requestedPort = 0
            self.assertTrue(await client.connect())

            listenTask = asyncio.create_task(client.listen())
            await asyncio.sleep(0.05)
            self.assertTrue(client.running)
            self.assertFalse(listenTask.done())

            await client.shutdown()
            await asyncio.wait_for(listenTask, 2)
            self.assertFalse(client.running)
            with self.assertRaises(OSError):
                await asyncio.wait_for(asyncio.open_connection(LAN_HOST, client.remotePort), 2)

        asyncio.run(run())

    def testNetworkPolicyIsDirectOnlyAndNamesTheLANHost(self):
        client = LANTunnelClient(1234, lanHost='192.168.1.50')
        self.assertEqual(client.networkPolicy, NetworkPolicy.createDirect(directConnectionHosts=['192.168.1.50']))

    @requiresLAN
    def testConnectDoesNotLeakAmbientSettings(self):
        """The policy belongs to the share (client.networkPolicy), so starting a
        tunnel must not change what unrelated code in this process resolves."""

        async def run():
            client = LANTunnelClient(getFreePort(), lanHost=LAN_HOST)
            client.requestedPort = 0
            self.assertTrue(await client.connect())
            try:
                settings = SettingsGetter.getInstance()
                self.assertTrue(settings.portMappingEnabled)
                self.assertIsNone(settings.directConnectionHosts)
            finally:
                await client.shutdown()

        asyncio.run(run())


class NetworkEndpointTest(unittest.TestCase):
    """A receiver classifies its target URL to decide whether NAT traversal is needed."""

    def testPrivateAndLoopbackAddressesAreDirect(self):
        for url in (
            'http://192.168.0.5:8000/x', 'http://10.1.2.3/x', 'http://172.16.9.9/x', 'http://100.64.1.1/x',
            'http://169.254.1.1/x', 'http://127.0.0.1:1/x', 'http://localhost:1/x', 'http://[::1]:1/x',
            'http://[fd00::1]:1/x'
        ):
            with self.subTest(url=url):
                endpoint = NetworkEndpoint.fromURL(url)
                self.assertFalse(endpoint.requiresNATTraversal)
                self.assertEqual(endpoint.networkPolicy, NetworkPolicy.createDirect())

    def testPublicAndNamedHostsNeedTraversal(self):
        for url in ('https://8.8.8.8/x', 'https://fastfilelink.com/x', 'https://33.fastfilelink.com/x', '/relative'):
            with self.subTest(url=url):
                endpoint = NetworkEndpoint.fromURL(url)
                self.assertTrue(endpoint.requiresNATTraversal)
                self.assertEqual(endpoint.networkPolicy, NetworkPolicy())


class RuntimeNetworkPolicyContextTest(unittest.TestCase):
    """SettingsGetter's runtime overrides are scoped to the calling context, so
    a daemon serving a LAN share and concurrently downloading from the internet
    cannot leak one policy into the other."""

    DIRECT = NetworkPolicy.createDirect(directConnectionHosts=['192.168.1.50'])

    def setUp(self):
        self.settings = SettingsGetter.getInstance()

    def testOverrideAppliesAndRestores(self):
        with self.settings.overrideNetworkPolicy(self.DIRECT):
            self.assertFalse(self.settings.portMappingEnabled)
            self.assertEqual(self.settings.directConnectionHosts, ['192.168.1.50'])
            self.assertEqual(self.settings.getICEServerEntries(), [])
            self.assertEqual(self.settings.getSTUNServerURLs(), [])

        self.assertTrue(self.settings.portMappingEnabled)
        self.assertIsNone(self.settings.directConnectionHosts)
        self.assertTrue(self.settings.getICEServerEntries())

    def testNestedOverridesLastWinsAndUnwind(self):
        with self.settings.overrideNetworkPolicy(self.DIRECT):
            with self.settings.overrideNetworkPolicy(NetworkPolicy.createDirect(['10.0.0.9'])):
                self.assertEqual(self.settings.directConnectionHosts, ['10.0.0.9'])

            self.assertEqual(self.settings.directConnectionHosts, ['192.168.1.50'])

        self.assertIsNone(self.settings.directConnectionHosts)

    def testInvalidPolicyIsRejected(self):
        with self.assertRaises(TypeError):
            self.settings.overrideNetworkPolicy({'portMappingEnabled': False})

        with self.assertRaises(TypeError):
            self.settings.overrideNetworkPolicy(NetworkPolicy(portMappingEnabled='no'))

    def testRestoreTwiceFails(self):
        override = self.settings.overrideNetworkPolicy(self.DIRECT)
        override.restore()
        with self.assertRaises(RuntimeError):
            override.restore()

    def testThreadsDoNotSeeEachOthersOverrides(self):
        """A LAN download in one thread and an internet download in another."""
        lanActive = threading.Event()
        internetChecked = threading.Event()
        seen = {}

        def lanDownload():
            with self.settings.overrideNetworkPolicy(self.DIRECT):
                lanActive.set()
                self.assertTrue(internetChecked.wait(5))
                seen['lan'] = (self.settings.portMappingEnabled, self.settings.directConnectionHosts)

            seen['lanAfter'] = self.settings.portMappingEnabled

        def internetDownload():
            self.assertTrue(lanActive.wait(5))
            with self.settings.overrideNetworkPolicy(NetworkEndpoint.fromURL('https://fastfilelink.com/x').networkPolicy):
                seen['internet'] = (
                    self.settings.portMappingEnabled, self.settings.directConnectionHosts,
                    bool(self.settings.getICEServerEntries())
                )

            internetChecked.set()

        threads = [threading.Thread(target=lanDownload), threading.Thread(target=internetDownload)]
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(10)

        self.assertEqual(seen['lan'], (False, ['192.168.1.50']))
        self.assertEqual(seen['internet'], (True, None, True), 'Internet download must keep STUN + port mapping')
        self.assertTrue(seen['lanAfter'])
        self.assertTrue(self.settings.portMappingEnabled, 'Main thread must be untouched')

    def testAsyncTasksAreIsolated(self):
        async def run():
            async def lanTask(started, proceed):
                with self.settings.overrideNetworkPolicy(self.DIRECT):
                    started.set()
                    await proceed.wait()
                    return self.settings.portMappingEnabled

            async def plainTask(started, proceed):
                await started.wait()
                value = self.settings.portMappingEnabled
                proceed.set()
                return value

            started, proceed = asyncio.Event(), asyncio.Event()
            return await asyncio.gather(lanTask(started, proceed), plainTask(started, proceed))

        self.assertEqual(asyncio.run(run()), [False, True])

    def testOverrideCannotBeRestoredFromAnotherContext(self):
        """Fail fast instead of silently corrupting another context's stack."""
        override = self.settings.overrideNetworkPolicy(self.DIRECT)
        errors = []

        def restore():
            try:
                override.restore()
            except RuntimeError as error:
                errors.append(error)

        thread = threading.Thread(target=restore)
        thread.start()
        thread.join(5)

        self.assertEqual(len(errors), 1)
        self.assertFalse(self.settings.portMappingEnabled, 'Owning context is unaffected')
        override.restore()
        self.assertTrue(self.settings.portMappingEnabled)


class ReceiverPolicyScopeTest(unittest.TestCase):
    """FFLDownloader runs each download under its own endpoint's policy."""

    def _observePolicyDuring(self, url):
        from bases.Download import FFLDownloader # isort:skip
        from bases.P2P import P2PDownloadMixin # isort:skip

        seen = {}

        def fakeDownload(downloader, url, *args, **kwargs):
            settings = SettingsGetter.getInstance()
            seen['portMapping'] = settings.portMappingEnabled
            seen['stun'] = bool(settings.getSTUNServerURLs())
            return 'done'

        with mock.patch.object(P2PDownloadMixin, 'downloadFile', fakeDownload):
            self.assertEqual(FFLDownloader.__new__(FFLDownloader).downloadFile(url), 'done')

        self.assertTrue(SettingsGetter.getInstance().portMappingEnabled, 'Policy must be restored after the download')
        return seen

    def testLANURLIsDownloadedDirectly(self):
        self.assertEqual(self._observePolicyDuring('http://192.168.0.5:8000/abc'), {'portMapping': False, 'stun': False})

    def testInternetURLKeepsTraversal(self):
        self.assertEqual(self._observePolicyDuring('https://33.fastfilelink.com/abc'), {'portMapping': True, 'stun': True})

class SessionNetworkPolicyScopeTest(unittest.TestCase):
    """Requests with no resolved session get no policy (the with-session case is proven
    end to end by testP2POfferAdvertisesLANHostNotLoopback)."""

    def _applyPolicyOf(self, session):
        from bases.Server import DownloadHandler # isort:skip

        handler = DownloadHandler.__new__(DownloadHandler)
        handler.session = session
        return handler._applySessionNetworkPolicy()

    def testNoSessionMeansNoPolicy(self):
        with self._applyPolicyOf(None):
            self.assertTrue(SettingsGetter.getInstance().portMappingEnabled)


@requiresLAN
class LANFastFileLinkE2ETest(PreservedTunnelPreference, FastFileLinkTestBase):
    """Real `FFL.py share` process with FFL_TUNNEL_DOMAIN=lan, downloaded by a receiver."""

    LAN_ENV = {'FFL_TUNNEL_DOMAIN': 'lan'}

    def _startLANShare(self, **kwargs):
        extraEnvVars = dict(self.LAN_ENV)
        extraEnvVars.update(kwargs.pop('extraEnvVars', {}))
        shareLink = self._startFastFileLink(p2p=True, extraEnvVars=extraEnvVars, **kwargs)
        self.assertRegex(shareLink, rf'^http://{LAN_HOST}:\d+/', f'Expected a LAN share link, got: {shareLink}')
        return shareLink

    def testShareLinkPointsAtLANAddressAndDownloads(self):
        try:
            shareLink = self._startLANShare()

            downloadedFilePath = self._getDownloadedFilePath()
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)
        finally:
            self._terminateProcess()

    def testPreferredTunnelDefaultLANSharesOnTheLAN(self):
        """`--preferred-tunnel default:lan` is enough: no FFL_TUNNEL_DOMAIN."""
        try:
            shareLink = self._startFastFileLink(p2p=True, preferredTunnel='default:lan')
            self.assertRegex(shareLink, rf'^http://{LAN_HOST}:\d+/', f'Expected a LAN share link, got: {shareLink}')

            downloadedFilePath = self._getDownloadedFilePath()
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)
        finally:
            self._terminateProcess()

    def testPreferredTunnelForcesTheRelayType(self):
        for tunnelType, preferredTunnel in (('bore', 'default:tcp'), ('web', 'default:web')):
            with self.subTest(preferredTunnel=preferredTunnel):
                try:
                    shareLink = self._startFastFileLink(p2p=True, preferredTunnel=preferredTunnel)
                    self.assertEqual(getLinkTunnelType(shareLink), tunnelType, shareLink)

                    downloadedFilePath = self._getDownloadedFilePath(f'{tunnelType}.bin')
                    self.downloadFileWithRequests(shareLink, downloadedFilePath)
                    self._verifyDownloadedFile(downloadedFilePath)
                finally:
                    self._terminateProcess()
                    os.remove(self.jsonOutputPath) # else the next share's harness would read this share's link

    def testReceiverCoreDownloadOverLAN(self):
        """The FFL CLI receiver (FFLDownloader) downloads a LAN link, with no STUN/port mapping."""
        try:
            shareLink = self._startLANShare()

            downloadedFilePath = self._downloadWithCore(shareLink, self._getDownloadedFilePath('core.bin'))
            self._verifyDownloadedFile(downloadedFilePath)
        finally:
            self._terminateProcess()

    def testE2EEShareOverLAN(self):
        try:
            shareLink = self._startLANShare(extraArgs=['--e2ee'])

            downloadedFilePath = self._downloadWithCore(shareLink, self._getDownloadedFilePath('e2ee.bin'))
            self._verifyDownloadedFile(downloadedFilePath)
        finally:
            self._terminateProcess()

    def testP2POfferAdvertisesLANHostNotLoopback(self):
        """The server applies the share's own direct-only policy while building its P2P offer,
        so the peer is told to connect to the LAN address rather than 127.0.0.1."""
        try:
            shareLink = self._startLANShare()

            assertOfferAdvertisesLANHost(self, shareLink)
        finally:
            self._terminateProcess()

    def testInvalidLANHostFailsTheShareClearly(self):
        with self.assertRaises(AssertionError):
            self._startFastFileLink(
                p2p=True,
                timeout=20,
                extraEnvVars={
                    'FFL_TUNNEL_DOMAIN': 'lan',
                    'FFL_LAN_HOST': '127.0.0.1'
                },
            )

        self._terminateProcess()
        self._procLogFile.flush()
        with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as logFile:
            self.assertIn('FFL_LAN_HOST', logFile.read())


@requiresLAN
class LANDaemonTestBase(DaemonLifecycleMixin, FastFileLinkTestBase):
    """A daemon whose shared tunnel is the LAN tunnel."""

    DOWNLOAD_TIMEOUT_MULTIPLIER = 1

    def setUp(self):
        super().setUp()
        self._stopDaemon()
        self._daemonEnvOverrides = {'FFL_TUNNEL_DOMAIN': 'lan'}
        self._startDaemon()


class LANDaemonE2ETest(LANDaemonTestBase):
    """One daemon process, LAN tunnel, several shares plus a daemon-owned download."""

    def testMultipleSharesShareOneLANRelay(self):
        firstLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self._terminateProcess()

        secondPath = os.path.join(self.tempDir, 'second_lan.bin')
        self.generateRandomFile(secondPath, 512 * 1024)
        with self._usingTestFile(secondPath):
            secondLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])

        for link in (firstLink, secondLink):
            self.assertRegex(link, rf'^http://{LAN_HOST}:\d+/')

        self.assertEqual(firstLink.rsplit('/', 1)[0], secondLink.rsplit('/', 1)[0], 'LAN relay is reusable across shares')

        secondDownload = self._getDownloadedFilePath('second_downloaded.bin')
        self.downloadFileWithRequests(secondLink, secondDownload)
        self.assertEqual(self.getFileHash(secondDownload), self.getFileHash(secondPath))

    def testDaemonDownloadsFromLANShare(self):
        shareLink = self._startFastFileLink(p2p=True)
        destinationPath = os.path.join(self.tempDir, 'daemon-lan-download')
        os.makedirs(destinationPath)

        download = DaemonClient().createDownload(shareLink, destinationPath)
        completed = self._waitForDaemonDownload(download['id'])

        self.assertEqual(completed['status'], 'completed')
        self._verifyDownloadedFile(completed['outputPath'])


@requiresLAN
class LANAndInternetDaemonDownloadE2ETest(DaemonLifecycleMixin, FastFileLinkTestBase):
    """One normal daemon (real fastfilelink.com tunnel) downloading, at the same
    time, from a real fastfilelink.com share and from a real LAN share.

    The internet share is hosted by the daemon itself. The LAN share is a
    separate foreground CLI process started with FFL_TUNNEL_DOMAIN=lan (a
    daemon has a single tunnel, so a LAN share and an internet share can only
    coexist across processes). Both downloads run in the daemon's worker
    threads, each under its own endpoint's network policy.
    """

    DOWNLOAD_TIMEOUT_MULTIPLIER = 1

    def testDaemonDownloadsInternetAndLANSharesConcurrently(self):
        internetLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        self.assertRegex(internetLink, r'^https://[^/]*fastfilelink\.com/', f'Expected a real relay link, got: {internetLink}')
        self._terminateProcess()

        lanSourcePath = os.path.join(self.tempDir, 'lan_source.bin')
        self.generateRandomFile(lanSourcePath, 4 * 1024 * 1024)
        with self._usingTestFile(lanSourcePath):
            lanLink = self._startFastFileLink(
                p2p=True, extraArgs=['--foreground'], extraEnvVars={'FFL_TUNNEL_DOMAIN': 'lan'}
            )
            self.assertRegex(lanLink, rf'^http://{LAN_HOST}:\d+/', f'Expected a LAN link, got: {lanLink}')

            client = DaemonClient()
            destinations = {}
            downloads = {}
            for name, link in (('internet', internetLink), ('lan', lanLink)):
                destinations[name] = os.path.join(self.tempDir, f'daemon-{name}-download')
                os.makedirs(destinations[name])
                downloads[name] = client.createDownload(link, destinations[name])

            completed = {name: self._waitForDaemonDownload(download['id']) for name, download in downloads.items()}

            for name, download in completed.items():
                self.assertEqual(download['status'], 'completed', f'{name} download: {download}')
                self.assertGreater(download['transferred'], 0, name)

            self.assertEqual(self.getFileHash(completed['lan']['outputPath']), self.originalFileHash)

        self.assertEqual(self.getFileHash(completed['internet']['outputPath']), self.originalFileHash)


@requiresLAN
class DaemonTunnelTypeE2ETest(PreservedTunnelPreference, DaemonLifecycleMixin, FastFileLinkTestBase):
    """A daemon serves all its shares through one tunnel: once a share exists, a
    later share must use the same type of tunnel, chosen with --preferred-tunnel."""

    DOWNLOAD_TIMEOUT_MULTIPLIER = 1

    def _startBackgroundShare(self, preferredTunnel):
        shareLink = self._startFastFileLink(p2p=True, preferredTunnel=preferredTunnel, extraArgs=['--background'])
        self._terminateProcess()
        os.remove(self.jsonOutputPath) # else the next share's harness would read this share's link
        return shareLink

    def assertBackgroundShareDenied(self, preferredTunnel, requestedType, currentType):
        with self.assertRaises(AssertionError):
            self._startFastFileLink(
                p2p=True, timeout=30, preferredTunnel=preferredTunnel, extraArgs=['--background']
            )

        self._terminateProcess()
        self._procLogFile.flush()
        with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as logFile:
            self.assertIn(f'{requestedType} tunnel while existing shares use a {currentType} tunnel', logFile.read())

        self.assertEqual(len(DaemonClient().listShares()), 1, 'Only the first share exists; the denied one must not be created')

    def testLANShareAfterInternetShareIsDenied(self):
        self._startBackgroundShare('default:tcp')
        self.assertBackgroundShareDenied('default:lan', requestedType='lan', currentType='bore')

    def testWebShareAfterBoreShareIsDenied(self):
        self._startBackgroundShare('default:tcp')
        self.assertBackgroundShareDenied('default:web', requestedType='web', currentType='bore')

    def testBoreShareAfterWebShareIsDenied(self):
        self._startBackgroundShare('default:web')
        self.assertBackgroundShareDenied('default:tcp', requestedType='bore', currentType='web')

    def testInternetShareAfterLANShareIsDenied(self):
        self.assertRegex(self._startBackgroundShare('default:lan'), rf'^http://{LAN_HOST}:\d+/')
        self.assertBackgroundShareDenied('default:web', requestedType='web', currentType='lan')

    def assertSecondShareAccepted(self, tunnelType, preferredTunnel):
        firstLink = self._startBackgroundShare(preferredTunnel)
        secondLink = self._startBackgroundShare(preferredTunnel)

        self.assertEqual(getLinkTunnelType(secondLink), tunnelType)
        self.assertEqual(firstLink.rsplit('/', 1)[0], secondLink.rsplit('/', 1)[0], 'One tunnel serves both shares')

    def testPlainShareJoinsTheExistingTunnel(self):
        """A share that forces no type is not compared: it uses the daemon's tunnel."""
        firstLink = self._startBackgroundShare('default:lan')
        secondLink = self._startBackgroundShare('default')

        self.assertEqual(getLinkTunnelType(secondLink), 'lan')
        self.assertEqual(firstLink.rsplit('/', 1)[0], secondLink.rsplit('/', 1)[0], 'One tunnel serves both shares')

    def testSecondLANShareIsAccepted(self):
        self.assertSecondShareAccepted('lan', 'default:lan')

    def testSecondBoreShareIsAccepted(self):
        self.assertSecondShareAccepted('bore', 'default:tcp')


class FixedTunnelRunner(TunnelRunner):
    """A TunnelRunner that resolves to a given candidate (no network involved)."""

    def __init__(self, candidate, forcedTunnelType=None):
        super().__init__(0)
        self._candidate = candidate
        self.forcedTunnelType = forcedTunnelType

    def resolveTunnel(self):
        return self._candidate


class DaemonTunnelTypeTest(unittest.TestCase):
    """A share that forces a tunnel type must match the type of the daemon's existing tunnel;
    a share that forces none simply uses the existing tunnel."""

    LAN = LANTunnelCandidate()
    BORE = TunnelCandidate.fromDomain('33.fastfilelink.com')
    WEB = TunnelCandidate.fromDomain('1.10.fastfilelink.com')

    def requireSameTunnelType(self, existing, forcedTunnelType):
        class Runtime(DaemonSharedRuntime):

            def createTunnel(self, size, context):
                return FixedTunnelRunner(TunnelCandidate.fromType('lan'), forcedTunnelType=forcedTunnelType)

        runtime = Runtime()
        runtime._tunnelRunner = FixedTunnelRunner(existing)
        runtime.requireSameTunnelType(0, None)

    def testTypeIsResolvedFromTheDomain(self):
        self.assertEqual(TunnelCandidate.resolveType('33.fastfilelink.com'), 'bore')
        self.assertEqual(TunnelCandidate.resolveType('1.10.fastfilelink.com'), 'web')
        self.assertEqual(TunnelCandidate.resolveType('anything', type='lan'), 'lan')
        self.assertEqual(FixedTunnelRunner(self.BORE).resolvedType, 'bore')
        self.assertEqual(FixedTunnelRunner(self.LAN).resolvedType, 'lan')

    def testForcedTypeMatchingTheExistingTunnelIsAccepted(self):
        self.requireSameTunnelType(self.LAN, 'lan')
        self.requireSameTunnelType(self.BORE, 'bore')
        self.requireSameTunnelType(self.WEB, 'web')

    def testForcedTypeDifferentFromTheExistingTunnelIsRefused(self):
        for existing, forcedTunnelType, currentType in (
            (self.BORE, 'lan', 'bore'),
            (self.LAN, 'bore', 'lan'),
            (self.BORE, 'web', 'bore'),
            (self.WEB, 'bore', 'web'),
        ):
            with self.subTest(current=currentType, forced=forcedTunnelType):
                with self.assertRaisesRegex(RuntimeError, f'{forcedTunnelType} tunnel.*{currentType} tunnel'):
                    self.requireSameTunnelType(existing, forcedTunnelType)

    def testUnforcedShareUsesTheExistingTunnelWhateverItsType(self):
        """The share's own resolution (a LAN candidate here) is never consulted."""
        for existing in (self.LAN, self.BORE, self.WEB):
            with self.subTest(existing=existing.domain):
                self.requireSameTunnelType(existing, None)


if __name__ == '__main__':
    unittest.main()
