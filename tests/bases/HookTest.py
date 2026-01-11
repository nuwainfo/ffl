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

import time
import unittest

from bases.Hook import HookServer, HookClient, HookError, HookAuthError


class HookTest(unittest.TestCase):
    """Test HTTP webhook mechanism"""

    def testBasicServerClient(self):
        """Test basic server-client communication"""
        receivedEvents = []

        # Create server without auth
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()

        # Event handler
        def onEvent(eventName, eventData):
            receivedEvents.append((eventName, eventData))

        server.onEvent = onEvent

        # Create client
        hookUrl = server.getHookURL()
        client = HookClient(hookUrl)

        # Send events
        client.sendEvent('/test/event1', {'key': 'value1'})
        client.sendEvent('/test/event2', {'key': 'value2', 'number': 123})

        # Wait for events to be received (server processes them in separate iterations)
        time.sleep(1.5)

        # Verify events
        self.assertEqual(len(receivedEvents), 2)
        self.assertEqual(receivedEvents[0][0], '/test/event1')
        self.assertEqual(receivedEvents[0][1]['key'], 'value1')
        self.assertEqual(receivedEvents[1][0], '/test/event2')
        self.assertEqual(receivedEvents[1][1]['key'], 'value2')
        self.assertEqual(receivedEvents[1][1]['number'], 123)

        # Cleanup
        server.stop()

    def testAuthSuccess(self):
        """Test successful authentication"""
        receivedEvents = []

        # Create server with auth
        server = HookServer(host='127.0.0.1', port=0, path='/events', username='app', password='secret123')
        server.start()

        def onEvent(eventName, eventData):
            receivedEvents.append((eventName, eventData))

        server.onEvent = onEvent

        # Create client with correct credentials
        hookUrl = server.getHookURL()
        client = HookClient(hookUrl)

        # Send event
        client.sendEvent('/test/auth', {'authenticated': True})

        # Wait for event
        time.sleep(1.0)

        # Verify event received
        self.assertEqual(len(receivedEvents), 1)
        self.assertEqual(receivedEvents[0][0], '/test/auth')

        # Cleanup
        server.stop()

    def testAuthFailure(self):
        """Test authentication failure"""
        receivedEvents = []

        # Create server with auth
        server = HookServer(host='127.0.0.1', port=0, path='/events', username='app', password='secret123')
        server.start()

        def onEvent(eventName, eventData):
            receivedEvents.append((eventName, eventData))

        server.onEvent = onEvent

        # Create client with wrong credentials
        wrongUrl = f"http://app:wrongpass@127.0.0.1:{server.port}/events"
        client = HookClient(wrongUrl)

        # Send event - should fail
        with self.assertRaises(HookAuthError):
            client.sendEvent('/test/event', {'key': 'value'})

        # Wait for server to finish processing the 401 response
        time.sleep(0.2)

        # Verify no events were received
        self.assertEqual(len(receivedEvents), 0)

        # Cleanup
        server.stop()

    def testParseHookURL(self):
        """Test webhook URL parsing"""
        # Test with auth
        config = HookClient.parseHookURL('http://app:token@127.0.0.1:12345/events')
        self.assertEqual(config['scheme'], 'http')
        self.assertEqual(config['host'], '127.0.0.1')
        self.assertEqual(config['port'], 12345)
        self.assertEqual(config['path'], '/events')
        self.assertEqual(config['username'], 'app')
        self.assertEqual(config['password'], 'token')

        # Test without auth
        config = HookClient.parseHookURL('http://127.0.0.1:8080/webhook')
        self.assertEqual(config['username'], None)
        self.assertEqual(config['password'], None)

        # Test with default port
        config = HookClient.parseHookURL('http://example.com/events')
        self.assertEqual(config['port'], 80)

        config = HookClient.parseHookURL('https://example.com/events')
        self.assertEqual(config['port'], 443)

        # Test invalid formats
        with self.assertRaises(ValueError):
            HookClient.parseHookURL('invalid')

        with self.assertRaises(ValueError):
            HookClient.parseHookURL('ftp://example.com/events') # Wrong scheme

    def testCustomPath(self):
        """Test custom webhook path"""
        receivedEvents = []

        # Create server with custom path
        server = HookServer(host='127.0.0.1', port=0, path='/custom/webhook')
        server.start()

        def onEvent(eventName, eventData):
            receivedEvents.append((eventName, eventData))

        server.onEvent = onEvent

        # Send to correct path
        hookUrl = server.getHookURL()
        client = HookClient(hookUrl)
        client.sendEvent('/test/custom', {'path': 'correct'})

        time.sleep(0.2)
        self.assertEqual(len(receivedEvents), 1)

        # Send to wrong path - should fail (404)
        wrongUrl = f"http://127.0.0.1:{server.port}/wrong/path"
        wrongClient = HookClient(wrongUrl)
        with self.assertRaises(HookError):
            wrongClient.sendEvent('/test/wrong', {'path': 'wrong'})

        # Still only 1 event received
        self.assertEqual(len(receivedEvents), 1)

        # Cleanup
        server.stop()

    def testLargeMessage(self):
        """Test sending large messages"""
        receivedEvents = []

        # Create server
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()

        def onEvent(eventName, eventData):
            receivedEvents.append((eventName, eventData))

        server.onEvent = onEvent

        # Create client
        hookUrl = server.getHookURL()
        client = HookClient(hookUrl)

        # Send large message
        largeData = {'data': 'x' * 100000} # 100KB of data
        client.sendEvent('/test/large', largeData)

        # Wait for event
        time.sleep(0.2)

        # Verify event received
        self.assertEqual(len(receivedEvents), 1)
        self.assertEqual(receivedEvents[0][0], '/test/large')
        self.assertEqual(len(receivedEvents[0][1]['data']), 100000)

        # Cleanup
        server.stop()


if __name__ == '__main__':
    unittest.main()
