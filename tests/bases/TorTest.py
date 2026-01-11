#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
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

import os
import shutil
import subprocess
import time
import unittest

from unittest.mock import patch, MagicMock

from bases.Tor import (
    isPortOpen,
    isTorPort,
    detectTorProxy,
    checkViaCheckPage,
    getExitIp,
    checkIpInExitList,
    checkViaOnionoo,
    makeRequestsProxies,
    TOR_BROWSER_PORT,
    TOR_SERVICE_PORT,
)
from bases.Utils import ProxyConfig, parseProxyString

class TestIsPortOpen(unittest.TestCase):
    """Test cases for isPortOpen function."""

    @patch('bases.Tor.socket.create_connection')
    def testPortOpen(self, mockSocket):
        """Test when port is open and accepting connections."""
        mockSocket.return_value.__enter__ = MagicMock()
        mockSocket.return_value.__exit__ = MagicMock()

        result = isPortOpen('127.0.0.1', 9150)
        self.assertTrue(result)
        mockSocket.assert_called_once_with(('127.0.0.1', 9150), timeout=0.8)
        print("[OK] Port open detection works")

    @patch('bases.Tor.socket.create_connection')
    def testPortClosed(self, mockSocket):
        """Test when port is closed or unreachable."""
        mockSocket.side_effect = OSError("Connection refused")

        result = isPortOpen('127.0.0.1', 9999)
        self.assertFalse(result)
        print("[OK] Port closed detection works")


class TestIsTorPort(unittest.TestCase):
    """Test cases for isTorPort function."""

    def testTorBrowserPort(self):
        """Test detection of Tor Browser default port."""
        config: ProxyConfig = {
            'type': 'socks5',
            'url': 'socks5h://127.0.0.1:9150',
            'host': '127.0.0.1',
            'port': 9150,
            'protocol': 'socks5h',
            'username': None,
            'password': None,
        }

        result = isTorPort(config)
        self.assertTrue(result)
        print("[OK] Tor Browser port (9150) detected")

    def testTorServicePort(self):
        """Test detection of Tor service default port."""
        config: ProxyConfig = {
            'type': 'socks5',
            'url': 'socks5h://localhost:9050',
            'host': 'localhost',
            'port': 9050,
            'protocol': 'socks5h',
            'username': None,
            'password': None,
        }

        result = isTorPort(config)
        self.assertTrue(result)
        print("[OK] Tor service port (9050) detected")

    def testNonTorPort(self):
        """Test rejection of non-Tor SOCKS5 port."""
        config: ProxyConfig = {
            'type': 'socks5',
            'url': 'socks5h://127.0.0.1:1080',
            'host': '127.0.0.1',
            'port': 1080,
            'protocol': 'socks5h',
            'username': None,
            'password': None,
        }

        result = isTorPort(config)
        self.assertFalse(result)
        print("[OK] Non-Tor port (1080) rejected")

    def testRemoteHost(self):
        """Test rejection of remote SOCKS5 proxy."""
        config: ProxyConfig = {
            'type': 'socks5',
            'url': 'socks5h://proxy.example.com:9050',
            'host': 'proxy.example.com',
            'port': 9050,
            'protocol': 'socks5h',
            'username': None,
            'password': None,
        }

        result = isTorPort(config)
        self.assertFalse(result)
        print("[OK] Remote host rejected (not localhost)")

    def testHttpProxy(self):
        """Test rejection of HTTP proxy."""
        config: ProxyConfig = {
            'type': 'http',
            'url': 'http://127.0.0.1:8080',
            'host': '127.0.0.1',
            'port': 8080,
            'protocol': 'http',
            'username': None,
            'password': None,
        }

        result = isTorPort(config)
        self.assertFalse(result)
        print("[OK] HTTP proxy rejected (not SOCKS5)")


class TestDetectTorProxy(unittest.TestCase):
    """Test cases for detectTorProxy function."""

    @patch('bases.Tor.isPortOpen')
    def testTorBrowserDetected(self, mockIsPortOpen):
        """Test detection when Tor Browser is running."""
        mockIsPortOpen.side_effect = lambda host, port: port == TOR_BROWSER_PORT

        result = detectTorProxy()
        self.assertIsNotNone(result)
        self.assertEqual(result, f"socks5://127.0.0.1:{TOR_BROWSER_PORT}")
        print(f"[OK] Tor Browser detected: {result}")

    @patch('bases.Tor.isPortOpen')
    def testTorServiceDetected(self, mockIsPortOpen):
        """Test detection when Tor service is running."""
        mockIsPortOpen.side_effect = lambda host, port: port == TOR_SERVICE_PORT

        result = detectTorProxy()
        self.assertIsNotNone(result)
        self.assertEqual(result, f"socks5://127.0.0.1:{TOR_SERVICE_PORT}")
        print(f"[OK] Tor service detected: {result}")

    @patch('bases.Tor.isPortOpen')
    def testNoTorDetected(self, mockIsPortOpen):
        """Test when no Tor is running."""
        mockIsPortOpen.return_value = False

        result = detectTorProxy()
        self.assertIsNone(result)
        print("[OK] No Tor detected (all ports closed)")

    @patch('bases.Tor.isPortOpen')
    def testCustomPorts(self, mockIsPortOpen):
        """Test detection with custom port list."""
        mockIsPortOpen.side_effect = lambda host, port: port == 8888

        result = detectTorProxy(checkPorts=[8888, 9999])
        self.assertIsNotNone(result)
        self.assertEqual(result, "socks5://127.0.0.1:8888")
        print("[OK] Custom port detection works")


class TestCheckViaCheckPage(unittest.TestCase):
    """Test cases for checkViaCheckPage function."""

    @patch('bases.Tor.fetchText')
    def testTorDetected(self, mockFetchText):
        """Test when check.torproject.org confirms Tor."""
        mockFetchText.return_value = """
            <html>
                <h1>Congratulations. This browser is configured to use Tor.</h1>
            </html>
        """

        result = checkViaCheckPage({})
        self.assertTrue(result)
        print("[OK] check.torproject.org Tor confirmation parsed")

    @patch('bases.Tor.fetchText')
    def testTorNotDetected(self, mockFetchText):
        """Test when check.torproject.org indicates NOT Tor."""
        mockFetchText.return_value = """
            <html>
                <h1>Sorry. You are not using Tor.</h1>
            </html>
        """

        result = checkViaCheckPage({})
        self.assertFalse(result)
        print("[OK] check.torproject.org NOT Tor parsed")

    @patch('bases.Tor.fetchText')
    def testPageUnreachable(self, mockFetchText):
        """Test when check.torproject.org is unreachable."""
        mockFetchText.return_value = None

        result = checkViaCheckPage({})
        self.assertIsNone(result)
        print("[OK] Unreachable page returns None")

    @patch('bases.Tor.fetchText')
    def testUnrecognizedContent(self, mockFetchText):
        """Test when page content is unrecognized."""
        mockFetchText.return_value = "<html>Some random content</html>"

        result = checkViaCheckPage({})
        self.assertIsNone(result)
        print("[OK] Unrecognized page content returns None")


class TestGetExitIp(unittest.TestCase):
    """Test cases for getExitIp function."""

    @patch('bases.Tor.fetchJson')
    def testSuccessfulFetch(self, mockFetchJson):
        """Test successful exit IP fetch."""
        mockFetchJson.return_value = {"ip": "185.220.101.1"}

        result = getExitIp({})
        self.assertEqual(result, "185.220.101.1")
        print("[OK] Exit IP fetched successfully")

    @patch('bases.Tor.fetchJson')
    def testFailedFetch(self, mockFetchJson):
        """Test failed exit IP fetch."""
        mockFetchJson.return_value = None

        result = getExitIp({})
        self.assertIsNone(result)
        print("[OK] Failed fetch returns None")

    @patch('bases.Tor.fetchJson')
    def testInvalidResponse(self, mockFetchJson):
        """Test invalid JSON response."""
        mockFetchJson.return_value = {"error": "invalid"}

        result = getExitIp({})
        self.assertIsNone(result)
        print("[OK] Invalid response returns None")


class TestCheckIpInExitList(unittest.TestCase):
    """Test cases for checkIpInExitList function."""

    @patch('bases.Tor.requests.get')
    def testIpInExitList(self, mockGet):
        """Test when IP is in Tor exit list."""
        mockResponse = MagicMock()
        mockResponse.text = (
            "ExitAddress 185.220.101.1 2026-01-10 12:00:00\n"
            "ExitAddress 185.220.101.2 2026-01-10 12:00:00\n"
        )
        mockResponse.raise_for_status = MagicMock()
        mockGet.return_value = mockResponse

        result = checkIpInExitList("185.220.101.1")
        self.assertTrue(result)
        print("[OK] IP found in exit list")

    @patch('bases.Tor.requests.get')
    def testIpNotInExitList(self, mockGet):
        """Test when IP is NOT in Tor exit list."""
        mockResponse = MagicMock()
        mockResponse.text = "ExitAddress 185.220.101.1 2026-01-10 12:00:00\n"
        mockResponse.raise_for_status = MagicMock()
        mockGet.return_value = mockResponse

        result = checkIpInExitList("1.2.3.4")
        self.assertFalse(result)
        print("[OK] IP not found in exit list")

    @patch('bases.Tor.requests.get')
    def testFetchFailure(self, mockGet):
        """Test when exit list fetch fails."""
        mockGet.side_effect = Exception("Network error")

        result = checkIpInExitList("185.220.101.1")
        self.assertIsNone(result)
        print("[OK] Fetch failure returns None")


class TestCheckViaOnionoo(unittest.TestCase):
    """Test cases for checkViaOnionoo function."""

    @patch('bases.Tor.fetchJson')
    def testIpFoundInOnionoo(self, mockFetchJson):
        """Test when IP is found in Onionoo database."""
        mockFetchJson.return_value = {
            "relays": [{"nickname": "TorRelay1", "fingerprint": "ABC123"}]
        }

        result = checkViaOnionoo("185.220.101.1")
        self.assertTrue(result)
        print("[OK] IP found in Onionoo database")

    @patch('bases.Tor.fetchJson')
    def testIpNotFoundInOnionoo(self, mockFetchJson):
        """Test when IP is NOT found in Onionoo database."""
        mockFetchJson.return_value = {"relays": []}

        result = checkViaOnionoo("1.2.3.4")
        self.assertFalse(result)
        print("[OK] IP not found in Onionoo database")

    @patch('bases.Tor.fetchJson')
    def testOnionooFetchFailure(self, mockFetchJson):
        """Test when Onionoo API fetch fails."""
        mockFetchJson.return_value = None

        result = checkViaOnionoo("185.220.101.1")
        self.assertIsNone(result)
        print("[OK] Onionoo fetch failure returns None")


class TestTorIntegration(unittest.TestCase):
    """Integration tests requiring actual Tor binary (tor or Tor Browser)

    These tests require:
    - Tor binary ('tor') in PATH, OR
    - Tor Browser installed and running on port 9150

    Skip with: SKIP_INTEGRATION_TESTS=1 python -m unittest tests.bases.TorTest
    """

    def setUp(self):
        """Set up test environment"""
        self.torProcess = None
        self.torDataDir = None

    def tearDown(self):
        """Clean up Tor process if started"""
        if self.torProcess:
            try:
                self.torProcess.terminate()
                self.torProcess.wait(timeout=5)
            except Exception as e:
                print(f"Warning: Error stopping Tor process: {e}")

    def _startTorService(self, port=9050):
        """
        Start Tor daemon on specified port for testing.

        Returns:
            subprocess.Popen: Tor process, or None if failed to start
        """
        import tempfile

        # Check if tor binary is available
        torBinary = shutil.which('tor')
        if not torBinary:
            self.skipTest("tor binary not found in PATH")

        # Create temporary data directory
        self.torDataDir = tempfile.mkdtemp(prefix='tor_test_')

        # Start Tor with minimal config
        try:
            proc = subprocess.Popen(
                [torBinary, '--SocksPort', str(port), '--DataDirectory', self.torDataDir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait for Tor to bootstrap (check for "Bootstrapped 100%")
            print(f"Starting Tor daemon on port {port}...")
            maxWait = 60  # seconds
            startTime = time.time()

            while time.time() - startTime < maxWait:
                # Check if process died
                if proc.poll() is not None:
                    stdout, stderr = proc.communicate()
                    raise RuntimeError(f"Tor process died: {stderr}")

                # Check if port is open (Tor is ready)
                if isPortOpen('127.0.0.1', port):
                    print(f"✓ Tor daemon ready on port {port}")
                    return proc

                time.sleep(0.5)

            # Timeout
            proc.terminate()
            raise RuntimeError(f"Tor daemon did not start within {maxWait} seconds")

        except Exception as e:
            print(f"Failed to start Tor daemon: {e}")
            return None

    @unittest.skipUnless(
        shutil.which('tor') or isPortOpen('127.0.0.1', 9150) or isPortOpen('127.0.0.1', 9050),
        "tor binary not found and Tor Browser not running"
    )
    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testRealTorDetection(self):
        """Test detection of real Tor service"""
        # Check if Tor Browser is already running
        torProxy = detectTorProxy()

        if torProxy:
            print(f"✓ Tor detected (already running): {torProxy}")
        else:
            # Try to start Tor daemon
            print("Tor not running - attempting to start tor daemon...")
            self.torProcess = self._startTorService(port=9050)
            if not self.torProcess:
                self.skipTest("Could not start tor daemon")

            torProxy = detectTorProxy()
            self.assertIsNotNone(torProxy, "Should detect started Tor daemon")
            print(f"✓ Tor detected (started by test): {torProxy}")

    @unittest.skipUnless(
        shutil.which('tor') or isPortOpen('127.0.0.1', 9150) or isPortOpen('127.0.0.1', 9050),
        "tor binary not found and Tor Browser not running"
    )
    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testRealTorVerification(self):
        """Test verification of real Tor proxy using multiple methods"""
        from bases.Utils import parseProxyString

        # Check if Tor is already running
        torProxy = detectTorProxy()

        if not torProxy:
            # Try to start Tor daemon
            print("Tor not running - attempting to start tor daemon...")
            self.torProcess = self._startTorService(port=9050)
            if not self.torProcess:
                self.skipTest("Could not start tor daemon")

            torProxy = detectTorProxy()

        self.assertIsNotNone(torProxy, "Tor should be detected")
        print(f"✓ Testing Tor verification for: {torProxy}")

        # Parse proxy config
        proxyConfig = parseProxyString(torProxy)
        self.assertIsNotNone(proxyConfig, "Should parse Tor proxy string")

        # Test heuristic check
        self.assertTrue(isTorPort(proxyConfig), "Should identify as Tor port")
        print("✓ Heuristic check passed")

        # Test robust verification (this will actually contact Tor network)
        print("Running robust Tor verification (checking against Tor network)...")
        print("  - This may take 10-30 seconds...")

        from bases.Tor import verifyTorProxy

        isVerified = verifyTorProxy(proxyConfig, skipExitListCheck=True)
        self.assertTrue(isVerified, "Should verify as real Tor proxy")
        print("✓ Robust verification passed")

    @unittest.skipUnless(
        shutil.which('tor') or isPortOpen('127.0.0.1', 9150) or isPortOpen('127.0.0.1', 9050),
        "tor binary not found and Tor Browser not running"
    )
    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testTorCheckPage(self):
        """Test check.torproject.org verification with real Tor"""

        # Check if Tor is already running
        torProxy = detectTorProxy()

        if not torProxy:
            # Try to start Tor daemon
            print("Tor not running - attempting to start tor daemon...")
            self.torProcess = self._startTorService(port=9050)
            if not self.torProcess:
                self.skipTest("Could not start tor daemon")

            torProxy = detectTorProxy()

        self.assertIsNotNone(torProxy, "Tor should be detected")
        print(f"✓ Testing check.torproject.org with: {torProxy}")

        # Parse proxy config
        proxyConfig = parseProxyString(torProxy)
        proxies = makeRequestsProxies(proxyConfig['url'])

        # Check via official Tor check page
        print("Checking via check.torproject.org...")
        result = checkViaCheckPage(proxies)

        # Should return True if Tor is working correctly
        self.assertTrue(result, "check.torproject.org should confirm Tor usage")
        print("✓ check.torproject.org confirmed Tor usage")


if __name__ == '__main__':
    unittest.main()
