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

import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
import time
import unittest
import requests

from addons.Tunnels import TunnelRunnerProvider, StaticURLTunnelClient # isort:skip
from bases.Tunnel import TunnelRunner # isort:skip


def createTestConfig(preferredTunnel='default', enableCloudflare=False, enableNgrok=False, enableStaticUrl=False):
    """DRY factory for test configurations"""
    config = {
        "tunnels": {
            "cloudflare": {
                "name": "Cloudflare Tunnel",
                "binary": "cloudflared",
                "args": ["tunnel", "--url", "http://127.0.0.1:{port}"],
                "url_pattern": "https://[^\\s]+\\.trycloudflare\\.com",
                "timeout": 45,
                "enabled": enableCloudflare
            },
            "ngrok": {
                "name": "ngrok",
                "binary": "ngrok",
                "args": ["http", "{port}"],
                "url_pattern": "https://[^\\s]+\\.ngrok\\.io",
                "timeout": 30,
                "enabled": enableNgrok
            }
        },
        "settings": {
            "preferred_tunnel": preferredTunnel,
            "fallback_order": ["ngrok", "cloudflare", "default"]
        }
    }

    # Add static URL tunnels if enabled
    if enableStaticUrl:
        config["tunnels"]["static-fixed"] = {
            "name": "Static Fixed URL",
            "url": "https://test-fixed.example.com",
            "enabled": True
        }
        config["tunnels"]["static-with-port"] = {
            "name": "Static URL with Port",
            "url": "https://test-port.example.com:{port}",
            "enabled": True
        }
        config["settings"]["fallback_order"] = ["static-fixed", "static-with-port"] + config["settings"]["fallback_order"]

    return config


class SimpleHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Simple HTTP handler for testing file serving"""

    def __init__(self, *args, testFile=None, **kwargs):
        self.testFile = testFile
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/test':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Hello from tunnel test!')
        elif self.path == '/file' and self.testFile and os.path.exists(self.testFile):
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            with open(self.testFile, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)


class TestTunnelIntegration(unittest.TestCase):
    """Integration test for tunnel functionality with real HTTP server"""

    def setUp(self):
        """Set up test environment"""
        self.tempDir = tempfile.mkdtemp()
        self.configPath = os.path.join(self.tempDir, 'tunnels.json')
        self.testFile = os.path.join(self.tempDir, 'test_file.txt')
        self.httpServer = None
        self.httpThread = None

        # Create test file
        with open(self.testFile, 'w') as f:
            f.write('This is a test file for tunnel serving!')

        # Find available port for HTTP server
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            self.httpPort = s.getsockname()[1]
        
        # Include current directory in PATH to find tunnels executable.
        self.oldPath = os.environ['PATH']
        os.environ['PATH'] = f'{os.environ['PATH']}:{os.getcwd()}'

    def tearDown(self):
        """Clean up test environment"""
        if self.httpServer:
            self.httpServer.shutdown()
        if self.httpThread:
            self.httpThread.join(timeout=2)
        if os.path.exists(self.tempDir):
            shutil.rmtree(self.tempDir)
        
        # Restore PATH for preventing side-effect.
        os.environ['PATH'] = self.oldPath

    def startHttpServer(self):
        """Start simple HTTP server for testing"""
        handler = lambda *args, **kwargs: SimpleHTTPHandler(*args, testFile=self.testFile, **kwargs)
        self.httpServer = socketserver.TCPServer(('127.0.0.1', self.httpPort), handler)
        self.httpThread = threading.Thread(target=self.httpServer.serve_forever)
        self.httpThread.daemon = True
        self.httpThread.start()
        time.sleep(0.1) # Give server time to start

    def _waitForTunnelAvailable(self, tunnelLink, maxRetries=12, initialDelay=2):
        """Wait for tunnel to become available with exponential backoff"""
        delay = initialDelay
        for attempt in range(maxRetries):
            try:
                print(f"Attempt {attempt + 1}: Testing tunnel availability...")
                response = requests.get(f'{tunnelLink}test', timeout=5)
                if response.status_code == 200:
                    print(f"✅ Tunnel available after {attempt + 1} attempts")
                    return
                else:
                    print(f"Tunnel responded with status {response.status_code}")
            except (
                requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.RequestException
            ) as e:
                print(f"Tunnel not yet available (attempt {attempt + 1}): {type(e).__name__}")
            except Exception as e:
                print(f"Unexpected error testing tunnel: {e}")

            if attempt < maxRetries - 1: # Don't sleep on last attempt
                print(f"Waiting {delay} seconds before retry...")
                time.sleep(delay)
                delay = min(delay * 1.5, 10) # Exponential backoff, max 10s

        self.fail(f"Tunnel {tunnelLink} did not become available after {maxRetries} attempts")

    def testDefaultTunnelBehavior(self):
        """Test that default tunnel preference works (basic functionality)"""
        # Create config with default preference
        config = createTestConfig(preferredTunnel='default')
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        provider = TunnelRunnerProvider(self.configPath)
        EnhancedTunnelRunner = provider.getTunnelRunnerClass(TunnelRunner)
        runner = EnhancedTunnelRunner(1024)

        # Should prefer None (default tunnel = builtin Bore)
        self.assertIsNone(runner.preferredTunnel)

    @unittest.skipUnless(shutil.which('cloudflared'), "cloudflared binary not found in PATH")
    @unittest.skipIf(os.getenv('SKIP_INTEGRATION_TESTS'), "Integration tests disabled")
    def testTunnelWithRealHttpServer(self):
        """Integration test: Run actual tunnel with HTTP server and verify file serving"""
        # Create config with cloudflare enabled
        config = createTestConfig(preferredTunnel='cloudflare', enableCloudflare=True)
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        # Start HTTP server
        self.startHttpServer()

        # Verify HTTP server works locally first
        response = requests.get(f'http://127.0.0.1:{self.httpPort}/test', timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, 'Hello from tunnel test!')

        # Test file serving locally
        response = requests.get(f'http://127.0.0.1:{self.httpPort}/file', timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, 'This is a test file for tunnel serving!')

        # Now test with tunnel
        provider = TunnelRunnerProvider(self.configPath)
        EnhancedTunnelRunner = provider.getTunnelRunnerClass(TunnelRunner)

        with EnhancedTunnelRunner(1024) as tunnelRunner:
            # Start tunnel
            print(f"Starting tunnel for HTTP server on port {self.httpPort}")
            try:
                domain, tunnelLink = tunnelRunner.start(self.httpPort)
                self.assertIsNotNone(domain, "Tunnel should provide a domain")
                self.assertIsNotNone(tunnelLink, "Tunnel should provide a link")
            except Exception as e:
                print(f"Tunnel start failed: {e}")
                # Let's try to get more debug info
                if hasattr(tunnelRunner, 'tunnelThread') and tunnelRunner.tunnelThread:
                    if hasattr(tunnelRunner.tunnelThread, 'e') and tunnelRunner.tunnelThread.e:
                        print(f"Tunnel thread error: {tunnelRunner.tunnelThread.e}")
                raise
            self.assertTrue(tunnelLink.startswith('https://'), "Tunnel link should be HTTPS")

            print(f"Tunnel created: {tunnelLink}")

            # Wait for tunnel to become available with retries
            self._waitForTunnelAvailable(tunnelLink)

            # Test basic endpoint through tunnel
            response = requests.get(f'{tunnelLink}test', timeout=10)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, 'Hello from tunnel test!')
            print("✅ Basic tunnel connectivity test passed")

            # Test file serving through tunnel
            response = requests.get(f'{tunnelLink}file', timeout=10)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, 'This is a test file for tunnel serving!')
            print("✅ File serving through tunnel test passed")

    def testTunnelRunnerProvider(self):
        """Test TunnelRunnerProvider basic functionality"""
        # Create a test config file first
        config = createTestConfig(preferredTunnel='cloudflare', enableCloudflare=True)
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        # Test config loading
        provider = TunnelRunnerProvider(self.configPath)
        self.assertTrue(os.path.exists(self.configPath))

        # Test config parsing
        with open(self.configPath, 'r') as f:
            config = json.load(f)

        self.assertIn('tunnels', config)
        self.assertIn('settings', config)
        self.assertEqual(config['settings']['preferred_tunnel'], 'cloudflare')

    def testBinaryAvailabilityFiltering(self):
        """Test that tunnels without available binaries are filtered out"""
        # Create config with ngrok as preferred (but ngrok binary doesn't exist)
        # and cloudflare enabled (cloudflared binary exists)
        config = createTestConfig(preferredTunnel='ngrok', enableCloudflare=True, enableNgrok=True)
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        provider = TunnelRunnerProvider(self.configPath)
        availableTunnels = provider.getAvailableTunnels()

        # Should have cloudflare (binary exists) but not ngrok (binary doesn't exist)
        self.assertIn('cloudflare', availableTunnels)
        self.assertNotIn('ngrok', availableTunnels)

        # Test tunnel runner creation - should fallback to cloudflare despite ngrok being preferred
        EnhancedTunnelRunner = provider.getTunnelRunnerClass(TunnelRunner)
        runner = EnhancedTunnelRunner(1024)

        # Since ngrok binary doesn't exist, should fallback to cloudflare
        self.assertEqual(runner.preferredTunnel, 'cloudflare')

    def testStaticURLTunnelIntegration(self):
        """Test static URL tunnel functionality and preference setting"""
        # Create config with static URL tunnels
        config = createTestConfig(preferredTunnel='static-fixed', enableStaticUrl=True)
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        provider = TunnelRunnerProvider(self.configPath)

        # Test that static URL tunnels are detected as available
        availableTunnels = provider.getAvailableTunnels()
        self.assertIn('static-fixed', availableTunnels)
        self.assertIn('static-with-port', availableTunnels)

        # Test tunnel runner creation with static URL preference
        EnhancedTunnelRunner = provider.getTunnelRunnerClass(TunnelRunner)
        runner = EnhancedTunnelRunner(1024)

        # Should prefer static-fixed tunnel
        self.assertEqual(runner.preferredTunnel, 'static-fixed')
        self.assertEqual(runner.getTunnelType(), 'Static Fixed URL')

        # Test client creation
        client = runner._createExternalClient(8080)
        self.assertIsInstance(client, StaticURLTunnelClient)
        self.assertEqual(client.getTunnelURL(), 'https://test-fixed.example.com')

        # Test that client can connect (URL validation)
        self.assertTrue(client.connect())
        self.assertTrue(client.running)
        client.shutdown()
        self.assertFalse(client.running)

    def testSetPreferredTunnelMethod(self):
        """Test _setPreferredTunnel method functionality"""
        # Create initial config
        config = createTestConfig(preferredTunnel='default')
        with open(self.configPath, 'w') as f:
            json.dump(config, f)

        provider = TunnelRunnerProvider(self.configPath)

        # Test setting preferred tunnel
        provider._setPreferredTunnel('cloudflare')

        # Verify the change was saved
        with open(self.configPath, 'r') as f:
            updatedConfig = json.load(f)

        self.assertEqual(updatedConfig['settings']['preferred_tunnel'], 'cloudflare')

        # Test that provider reflects the change
        settings = provider._getSettings()
        self.assertEqual(settings['preferred_tunnel'], 'cloudflare')


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
