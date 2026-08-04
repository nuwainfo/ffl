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

import json
import time
import unittest
import threading
import base64
import os
import hashlib
import mimetypes
import zipfile

import requests

from types import SimpleNamespace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote
from io import BytesIO

from functools import partial

from bases.Hook import HookServer, HookClient, HookError, HookAuthError, HookEventSerializer, HookEndpointRouter
from bases.crypto import CryptoInterface
from bases.E2EE import StreamDecryptor
from ..CoreTestBase import FastFileLinkTestBase

try:
    import wx
    SKIP_GUI_TEST = False
except ImportError:
    SKIP_GUI_TEST = True


class _JSONHookEventHandlerMixin:
    """Shared request/response helpers for BaseHTTPRequestHandler subclasses that
    simulate a local hook server in these tests: JSON {"event", "data"} POST
    bodies, JSON/binary responses, and optional Basic auth.

    Subclasses may set the class attribute AUTH_HEADER to the expected
    'Authorization' header value to require Basic auth on every request; leave
    it None (the default) to skip auth checks entirely. AUTH_REALM controls the
    WWW-Authenticate realm sent on a failed challenge.
    """
    AUTH_HEADER = None
    AUTH_REALM = 'Hook Test'

    def log_message(self, format, *args):
        return

    def _checkAuth(self):
        return self.AUTH_HEADER is None or self.headers.get('Authorization') == self.AUTH_HEADER

    def _sendAuthChallenge(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', f'Basic realm="{self.AUTH_REALM}"')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _requireAuth(self):
        """Returns True if authorized; otherwise sends a 401 challenge and returns False."""
        if self._checkAuth():
            return True
        self._sendAuthChallenge()
        return False

    def _sendEmptyStatus(self, status):
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _sendBytes(self, body, contentType, status=HTTPStatus.OK):
        self.send_response(status)
        self.send_header('Content-Type', contentType)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sendJSON(self, payload, status=HTTPStatus.OK):
        self._sendBytes(json.dumps(payload).encode('utf-8'), 'application/json', status)

    def _readEventPayload(self):
        """Parse a POST body of the form {"event": ..., "data": ...}."""
        contentLength = int(self.headers.get('Content-Length', 0))
        requestData = json.loads(self.rfile.read(contentLength)) if contentLength else {}
        return requestData.get('event'), requestData.get('data', {})


class HookTest(unittest.TestCase):
    """Test HTTP webhook mechanism"""

    class _FakeMultiShareServer:
        def __init__(self, serverAddress, sessions):
            self.server_address = serverAddress
            self._sessions = sessions
            self._sessionsLock = threading.Lock()

        def getSessionCount(self):
            return len(self._sessions)

    @staticmethod
    def _makeHookSession(uid, domain, fileName, fileSize):
        return SimpleNamespace(
            uid=uid,
            domain=domain,
            config=SimpleNamespace(
                authPassword='secret',
                defaultWebRTC=True,
                e2eeEnabled=False,
                torEnabled=False,
            ),
            reader=SimpleNamespace(contentName=fileName, size=fileSize),
            e2eeManager=None,
        )

    @staticmethod
    def _makeExpectedRegisterContext(session, port, sessionCount):
        return {
            'uid': session.uid,
            'domain': session.domain,
            'fileName': session.reader.contentName,
            'fileSize': session.reader.size,
            'authEnabled': True,
            'defaultWebRTC': True,
            'e2eeEnabled': False,
            'torEnabled': False,
            'port': port,
            'sessionCount': sessionCount,
        }

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

    def testSendEventWithResponse(self):
        """Test request/response webhook calls"""
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()

        def onEvent(eventName, eventData):
            if eventName == '/test/response':
                return {'status': 201, 'content-type': 'text/plain; charset=utf-8', 'body': 'ok'}
            return {'status': 200}

        server.onEvent = onEvent
        client = HookClient(server.getHookURL())

        response = client.sendEvent('/test/response', {'hello': 'world'}, expectResponse=True)
        self.assertEqual(response['status'], 201)
        self.assertEqual(response['body'], 'ok')

        server.stop()

    def testEndpointRegisterAndRequest(self):
        """Test endpoint registration and request dispatch payloads"""
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()

        def onEvent(eventName, eventData):
            if eventName == '/hook/server/endpoints/register':
                return {
                    'routes': [
                        {'method': 'GET', 'path': '/hello'},
                        {'method': 'POST', 'path': '/echo'},
                    ]
                }
            if eventName == '/hook/server/request':
                if eventData.get('path') == '/hello':
                    return {'status': 200, 'content-type': 'text/html', 'body': '<html>Hello</html>'}
                return {'status': 200, 'body': {'echo': eventData.get('body', {})}}
            return {'status': 200}

        server.onEvent = onEvent
        client = HookClient(server.getHookURL())

        routes = client.registerServerEndpoints({'uid': 'abc123'})
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0]['method'], 'GET')
        self.assertEqual(routes[0]['path'], '/hello')

        response = client.dispatchServerRequest({'method': 'GET', 'path': '/hello', 'query': {'k': ['v']}})
        self.assertEqual(response['status'], 200)
        self.assertIn('Hello', response['body'])

        response = client.dispatchServerRequest({'method': 'POST', 'path': '/echo', 'body': {'name': 'naga'}})
        self.assertEqual(response['status'], 200)
        self.assertEqual(response['body']['echo']['name'], 'naga')

        server.stop()

    def testEndpointRegisterInvalidRoutes(self):
        """Test endpoint registration response validation"""
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()

        def onEvent(eventName, eventData):
            if eventName == '/hook/server/endpoints/register':
                return {'routes': {'method': 'GET', 'path': '/invalid'}}
            return {'status': 200}

        server.onEvent = onEvent
        client = HookClient(server.getHookURL())

        with self.assertRaises(HookError):
            client.registerServerEndpoints({'uid': 'abc123'})

        server.stop()

    def testFetchRoutesSupportsMultiShareSession(self):
        """Hook endpoint registration should use the active session context."""
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()
        session = self._makeHookSession('abc123', 'https://example.com/', 'demo.txt', 12)
        multiShareServer = self._FakeMultiShareServer(('127.0.0.1', 8080), {'abc123': session, 'def456': session})
        expectedContext = self._makeExpectedRegisterContext(session, 8080, 2)

        def onEvent(eventName, eventData):
            if eventName == '/hook/server/endpoints/register':
                self.assertEqual(eventData, expectedContext)
                return {'routes': [{'method': 'GET', 'path': '/manifest'}]}
            return {'status': 200}

        server.onEvent = onEvent
        client = HookClient(server.getHookURL())

        routes = HookEndpointRouter._fetchRoutes(multiShareServer, session, client)
        self.assertEqual(routes, [{'method': 'GET', 'path': '/manifest', 'encryptResponse': False}])

        server.stop()

    def testFetchRoutesSupportsMultipleSessions(self):
        """Hook endpoint registration should cache one route set per session."""
        server = HookServer(host='127.0.0.1', port=0, path='/events')
        server.start()
        session1 = self._makeHookSession('abc123', 'https://example.com/a', 'a.txt', 12)
        session2 = self._makeHookSession('def456', 'https://example.com/b', 'b.txt', 34)
        multiShareServer = self._FakeMultiShareServer(
            ('127.0.0.1', 8080),
            {'abc123': session1, 'def456': session2}
        )

        seenContexts = []

        def onEvent(eventName, eventData):
            if eventName == '/hook/server/endpoints/register':
                seenContexts.append(dict(eventData))
                return {'routes': [{'method': 'GET', 'path': '/manifest'}]}
            return {'status': 200}

        server.onEvent = onEvent
        client = HookClient(server.getHookURL())

        routes1 = HookEndpointRouter._getRoutesForSession(multiShareServer, session1, client)
        routes2 = HookEndpointRouter._getRoutesForSession(multiShareServer, session2, client)
        routes3 = HookEndpointRouter._getRoutesForSession(multiShareServer, session1, client)

        self.assertEqual(routes1, [{'method': 'GET', 'path': '/manifest', 'encryptResponse': False}])
        self.assertEqual(routes2, [{'method': 'GET', 'path': '/manifest', 'encryptResponse': False}])
        self.assertEqual(routes3, [{'method': 'GET', 'path': '/manifest', 'encryptResponse': False}])
        self.assertEqual(seenContexts, [
            self._makeExpectedRegisterContext(session1, 8080, 2),
            self._makeExpectedRegisterContext(session2, 8080, 2),
        ])

        server.stop()

    def testRegisterForHandlerSupportsMultipleSessions(self):
        """Hook routes should register per session and forward the active session identity."""
        state = {'registerContexts': [], 'requestUids': []}
        authUser = 'ffl'
        authPassword = 'test-hook-token'
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"

        class HookEndpointHandler(_JSONHookEventHandlerMixin, BaseHTTPRequestHandler):
            AUTH_HEADER = authHeader

            def do_GET(self):
                if not self._requireAuth():
                    return

                state['requestUids'].append(self.headers.get('X-FFL-UID'))
                self._sendBytes(b'ok', 'text/plain; charset=utf-8')

            def do_POST(self):
                if not self._requireAuth():
                    return

                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                    return

                eventName, eventData = self._readEventPayload()
                if eventName == '/hook/server/endpoints/register':
                    state['registerContexts'].append(dict(eventData))
                    self._sendJSON({'routes': [{'method': 'GET', 'path': '/hello'}]})
                else:
                    self._sendJSON({'status': 'ok'})

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), HookEndpointHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()

        try:
            client = HookClient(f'http://{authUser}:{authPassword}@127.0.0.1:{hookServer.server_address[1]}/events')

            session1 = self._makeHookSession('abc123', 'https://example.com/a', 'a.txt', 12)
            session2 = self._makeHookSession('def456', 'https://example.com/b', 'b.txt', 34)
            multiShareServer = self._FakeMultiShareServer(
                ('127.0.0.1', hookServer.server_address[1]),
                {'abc123': session1, 'def456': session2}
            )

            class FakeHeaders(dict):
                def get(self, key, default=None):
                    return super().get(key, default)

            class FakeHandler:
                def __init__(self, server, session):
                    self.server = server
                    self.session = session
                    self.headers = FakeHeaders()
                    self.sentHeaders = []
                    self.status = None
                    self.wfile = BytesIO()

                def send_response(self, status):
                    self.status = status

                def send_header(self, key, value):
                    self.sentHeaders.append((key, value))

                def end_headers(self):
                    return

                def send_error(self, code, message):
                    raise AssertionError(f"Unexpected proxy error {code}: {message}")

            for session in (session1, session2):
                fakeHandler = FakeHandler(multiShareServer, session)
                getPathMap = {}
                postPathMap = {}
                headPathMap = {}

                HookEndpointRouter.registerForHandler(
                    handler=fakeHandler,
                    server=multiShareServer,
                    session=session,
                    hookClient=client,
                    getPathMap=getPathMap,
                    postPathMap=postPathMap,
                    headPathMap=headPathMap
                )

                self.assertIn('/hello', getPathMap)
                getPathMap['/hello']({})
                self.assertEqual(fakeHandler.status, 200)
                self.assertEqual(fakeHandler.wfile.getvalue(), b'ok')

            self.assertEqual(state['registerContexts'], [
                self._makeExpectedRegisterContext(session1, hookServer.server_address[1], 2),
                self._makeExpectedRegisterContext(session2, hookServer.server_address[1], 2),
            ])
            self.assertEqual(state['requestUids'], ['abc123', 'def456'])

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)


class HookEventSerializerTest(unittest.TestCase):
    """Tests for HookEventSerializer utilities and extractor registration."""

    def setUp(self):
        # Save and restore EXTRACTOR_PREFIXES so tests are isolated
        self._originalPrefixes = dict(HookEventSerializer.EXTRACTOR_PREFIXES)

    def tearDown(self):
        HookEventSerializer.EXTRACTOR_PREFIXES.clear()
        HookEventSerializer.EXTRACTOR_PREFIXES.update(self._originalPrefixes)

    # ------------------------------------------------------------------
    # extractTypeValues
    # ------------------------------------------------------------------

    def testExtractTypeValuesConvertsTypeToName(self):
        """Type objects are replaced with their __name__ string."""
        class Foo:
            pass

        result = HookEventSerializer.extractTypeValues({'context': {'cls': Foo}}, key='context')
        self.assertEqual(result, {'context': {'cls': 'Foo'}})

    def testExtractTypeValuesConvertsListOfTypes(self):
        """Lists of type objects are each replaced with __name__."""
        class A:
            pass

        class B:
            pass

        result = HookEventSerializer.extractTypeValues({'context': {'classes': [A, B]}}, key='context')
        self.assertEqual(result, {'context': {'classes': ['A', 'B']}})

    def testExtractTypeValuesKeepsScalars(self):
        """Scalar values (str, int, float, bool, None) are kept as-is."""
        data = {'context': {'name': 'hello', 'count': 42, 'ratio': 3.14, 'flag': True, 'empty': None}}
        result = HookEventSerializer.extractTypeValues(data, key='context')
        self.assertEqual(result, {'context': data['context']})

    def testExtractTypeValuesDropsNonSerializableObjects(self):
        """Non-serializable objects that are not types are silently dropped."""

        class Manager:
            pass

        result = HookEventSerializer.extractTypeValues(
            {'context': {'mgr': Manager(), 'name': 'kept'}}, key='context'
        )
        self.assertNotIn('mgr', result['context'])
        self.assertEqual(result['context']['name'], 'kept')

    def testExtractTypeValuesMissingKey(self):
        """Missing key returns an empty mapping under that key."""
        result = HookEventSerializer.extractTypeValues({}, key='context')
        self.assertEqual(result, {'context': {}})

    def testExtractTypeValuesCustomKey(self):
        """The key parameter controls which dict key is extracted and returned."""
        result = HookEventSerializer.extractTypeValues({'payload': {'cls': int}}, key='payload')
        self.assertEqual(result, {'payload': {'cls': 'int'}})

    # ------------------------------------------------------------------
    # registerExtractorPrefix + partial binding
    # ------------------------------------------------------------------

    def testRegisterExtractorPrefixWithPartial(self):
        """Prefix registered via partial is applied during serialize()."""

        class MyClass:
            pass

        HookEventSerializer.registerExtractorPrefix(
            '/test/class/', partial(HookEventSerializer.extractTypeValues, key='context')
        )

        result = HookEventSerializer.serialize(
            '/test/class/create', {'context': {'cls': MyClass}, 'manager': object()}
        )
        self.assertEqual(result['data']['context']['cls'], 'MyClass')
        # The 'manager' key from the raw event data is stripped by the extractor
        self.assertNotIn('manager', result['data'])

    def testRegisterExtractorPrefixLongerPrefixTakesPrecedence(self):
        """When two prefixes match, the first registered wins (dict insertion order)."""

        HookEventSerializer.registerExtractorPrefix('/foo/', lambda e: {'from': 'foo'})
        HookEventSerializer.registerExtractorPrefix('/foo/bar/', lambda e: {'from': 'foobar'})

        result = HookEventSerializer.serialize('/foo/baz/event', {})
        self.assertEqual(result['data']['from'], 'foo')

        result2 = HookEventSerializer.serialize('/foo/bar/event', {})
        self.assertEqual(result2['data']['from'], 'foo')

    def testRegisterExtractorPrefixDoesNotAffectExactMatch(self):
        """An exact EXTRACTORS entry takes priority over any prefix match."""
        from bases.Kernel import FFLEvent

        HookEventSerializer.registerExtractorPrefix(
            FFLEvent.shareLinkCreate.key[:5],  # just the leading '/'
            lambda e: {'overridden': True}
        )

        # shareLinkCreate has an exact extractor — prefix must not override it
        result = HookEventSerializer.serialize(FFLEvent.shareLinkCreate.key, {'filePath': '/tmp/f'})
        self.assertNotIn('overridden', result['data'])
        self.assertIn('filePath', result['data'])

    def testUnregisteredPrefixFallsBackToMakeJSONSafe(self):
        """Events with no matching extractor still serialize via makeJSONSafe."""
        result = HookEventSerializer.serialize('/unknown/event', {'value': 42})
        self.assertEqual(result['data']['value'], 42)


class HookFunctionalTest(FastFileLinkTestBase):
    """Functional tests for hook endpoint integration with real Core process."""

    def _startHelloHookServer(self, registerEvents, endpointRequests, authUser='ffl', authPassword='test-hook-token'):
        """Local hook server that registers a single GET /hello route and records
        every request's query args and headers. Shared by tests that only need a
        minimal registered endpoint to probe proxying behavior (basic dispatch,
        non-ASCII file names, ...).

        Returns (hookServer, hookThread, hookUrl).
        """
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"

        class LocalHookServerHandler(_JSONHookEventHandlerMixin, BaseHTTPRequestHandler):
            AUTH_HEADER = authHeader

            def do_POST(self):
                if not self._requireAuth():
                    return

                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                    return

                eventName, eventData = self._readEventPayload()
                if eventName == '/hook/server/endpoints/register':
                    registerEvents.append(eventData)
                    self._sendJSON({'routes': [{'method': 'GET', 'path': '/hello'}]})
                else:
                    self._sendJSON({'status': 'ok'})

            def do_GET(self):
                if not self._requireAuth():
                    return

                parsed = urlparse(self.path)
                if parsed.path == '/hello':
                    endpointRequests.append({
                        'path': parsed.path,
                        'query': parse_qs(parsed.query),
                        'fileNameHeader': self.headers.get('X-FFL-FileName'),
                    })
                    self._sendBytes(b'hello from hook server', 'text/plain; charset=utf-8')
                    return

                self._sendEmptyStatus(HTTPStatus.NOT_FOUND)

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), LocalHookServerHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()
        hookUrl = f"http://{authUser}:{authPassword}@127.0.0.1:{hookServer.server_address[1]}/events"
        return hookServer, hookThread, hookUrl

    def testHookRegisteredEndpointHello(self):
        """Verify hook-registered /hello endpoint is served at [share link]/hello."""
        registerEvents = []
        endpointRequests = []
        outputCapture = {}

        hookServer, hookThread, hookUrl = self._startHelloHookServer(registerEvents, endpointRequests)

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraArgs=["--hook", hookUrl, "--timeout", "30", "--log-level", "DEBUG"]
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)

            shareLink = shareInfo["link"]
            helloUrl = f"{shareLink.rstrip('/')}/hello?source=test"

            response = None
            lastError = None
            for _ in range(5):
                try:
                    response = requests.get(helloUrl, timeout=30)
                    if response.status_code == 200:
                        break
                except Exception as e:
                    lastError = e
                time.sleep(1)

            if response is None:
                raise AssertionError(f"Failed to request {helloUrl}: {lastError}")

            if response.status_code != 200:
                processOutput = self._updateCapturedOutput(outputCapture)
                self.fail(
                    f"Expected 200 for {helloUrl}, got {response.status_code}\n"
                    f"registerEvents={registerEvents}\n"
                    f"endpointRequests={endpointRequests}\n"
                    f"processOutput={processOutput}"
                )

            self.assertEqual(response.status_code, 200, f"Expected 200 for {helloUrl}, got {response.status_code}")
            self.assertEqual(response.text, "hello from hook server")
            self.assertIn("text/plain", response.headers.get("Content-Type", ""))

            self.assertGreaterEqual(len(registerEvents), 1, "Hook server should receive endpoint registration event")
            self.assertGreaterEqual(len(endpointRequests), 1, "Hook server should receive proxied /hello request")
            self.assertEqual(endpointRequests[-1].get('path'), '/hello')
            self.assertEqual(endpointRequests[-1].get('query', {}).get('source'), ['test'])

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)

    def testHookProxyWithChineseFileName(self):
        """Verify hook-proxied endpoints (e.g. /hello) work when the shared file name
        contains non-ASCII characters.

        Regression test: X-FFL-FileName is forwarded on every hook-proxied request
        (bases/Hook.py _addSessionForwardHeaders). HTTP header values are latin-1
        encoded by the underlying `requests` library, so a raw Chinese file name
        raises UnicodeEncodeError before the request is even sent, and the proxy
        falls back to a bare 502 for every hook endpoint (not just /manifest, /thumb).
        """
        registerEvents = []
        endpointRequests = []
        outputCapture = {}

        hookServer, hookThread, hookUrl = self._startHelloHookServer(registerEvents, endpointRequests)

        originalTestFilePath = self.testFilePath
        originalFileSize = self.originalFileSize
        chineseFileName = "中文檔名測試.txt"
        chineseFilePath = os.path.join(self.tempDir, chineseFileName)
        with open(chineseFilePath, "wb") as fileHandle:
            fileHandle.write(b"hello from chinese filename test\n")
        self.testFilePath = chineseFilePath
        self.originalFileSize = os.path.getsize(chineseFilePath)

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraArgs=["--hook", hookUrl, "--timeout", "30", "--log-level", "DEBUG"]
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)

            shareLink = shareInfo["link"]
            helloUrl = f"{shareLink.rstrip('/')}/hello"

            response = None
            lastError = None
            for _ in range(5):
                try:
                    response = requests.get(helloUrl, timeout=30)
                    break
                except Exception as e:
                    lastError = e
                time.sleep(1)

            if response is None:
                raise AssertionError(f"Failed to request {helloUrl}: {lastError}")

            if response.status_code != 200:
                processOutput = self._updateCapturedOutput(outputCapture)
                self.fail(
                    f"Expected 200 for {helloUrl} when the shared file name contains "
                    f"non-ASCII characters, got {response.status_code}. This reproduces the "
                    f"X-FFL-FileName header UnicodeEncodeError bug in bases/Hook.py.\n"
                    f"registerEvents={registerEvents}\n"
                    f"endpointRequests={endpointRequests}\n"
                    f"processOutput={processOutput}"
                )

            self.assertEqual(response.text, "hello from hook server")
            self.assertGreaterEqual(len(registerEvents), 1, "Hook server should receive endpoint registration event")
            self.assertGreaterEqual(len(endpointRequests), 1, "Hook server should receive proxied /hello request")

            fileNameHeader = endpointRequests[-1].get('fileNameHeader')
            self.assertIsNotNone(fileNameHeader, "X-FFL-FileName header should be forwarded")
            fileNameHeader.encode('ascii') # header value itself must be ASCII-safe on the wire
            self.assertEqual(
                unquote(fileNameHeader),
                chineseFileName,
                "X-FFL-FileName should be percent-encoded so the hook server can unquote() the original name",
            )

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)
            self.testFilePath = originalTestFilePath
            self.originalFileSize = originalFileSize

    def _startPreviewHookServer(self, state, encryptResponse=False, includeFileEndpoint=False):
        """Create and start a local HTTP server for preview-style hook endpoint tests.

        Handles POST /events for hook registration and share-link events, and GET
        endpoints for /manifest, /thumb, and optionally /file.

        Args:
            state: Mutable dict populated as events arrive. Required keys:
                   'registerEvents' (list), 'endpointRequests' (list),
                   'shareManifest' (list), 'shareLink' (str),
                   'sharedRoot' (str|None), 'fakeThumbBytes' (bytes)
            encryptResponse: Set encryptResponse flag on all registered GET routes.
            includeFileEndpoint: Also register and serve the /file endpoint.

        Returns:
            (hookServer, hookThread, hookUrl)
        """
        authUser = 'ffl'
        authPassword = 'test-hook-token'
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"
        fakeThumbBytes = state['fakeThumbBytes']

        routePaths = ['/manifest', '/thumb']
        if includeFileEndpoint:
            routePaths.append('/file')
        routes = [{'method': 'GET', 'path': p, 'encryptResponse': encryptResponse} for p in routePaths]

        class LocalHookServerHandler(_JSONHookEventHandlerMixin, BaseHTTPRequestHandler):
            AUTH_HEADER = authHeader

            def do_POST(self):
                if not self._requireAuth():
                    return

                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                    return

                eventName, eventData = self._readEventPayload()

                if eventName == '/hook/server/endpoints/register':
                    state['registerEvents'].append(eventData)
                    self._sendJSON({'routes': routes})
                else:
                    if eventName == '/share/link/create':
                        state['shareManifest'] = eventData.get('manifest', [])
                        state['shareLink'] = eventData.get('link', '')
                        state['sharedRoot'] = eventData.get('filePath')
                    self._sendJSON({'status': 'ok'})

            def do_GET(self):
                if not self._requireAuth():
                    return

                parsed = urlparse(self.path)
                args = parse_qs(parsed.query)
                shareManifest = state['shareManifest']
                sharedRoot = state['sharedRoot']
                shareLink = state['shareLink']

                uid = urlparse(shareLink).path.strip('/').split('/')[0] if shareLink else ''
                previewEntries = []
                fileIndex = 0
                for item in shareManifest:
                    if item.get('isDir', False):
                        continue
                    arcname = item.get('arcname', '')
                    mimeType, _encoding = mimetypes.guess_type(arcname)
                    if not mimeType:
                        mimeType = 'application/octet-stream'
                    previewEntries.append({
                        'index': fileIndex,
                        'segmentIndex': item.get('index', 0),
                        'name': arcname,
                        'hash': hashlib.blake2b(arcname.encode('utf-8'), digest_size=32).hexdigest(),
                        'size': item.get('size', 0),
                        'mtime': item.get('mtime', 0),
                        'mime': mimeType,
                        'dataOffset': item.get('data_offset', 0),
                    })
                    fileIndex += 1

                previewManifest = {
                    'uid': uid,
                    'zipName': os.path.basename(os.path.normpath(sharedRoot)) + '.zip' if sharedRoot else 'shared.zip',
                    'zipSize': 0,
                    'count': len(previewEntries),
                    'entries': previewEntries,
                }

                if parsed.path == '/manifest':
                    state['endpointRequests'].append({'path': '/manifest'})
                    body = json.dumps(previewManifest).encode('utf-8')
                    self._sendBytes(body, 'application/json; charset=utf-8')
                    return

                if parsed.path == '/thumb':
                    state['endpointRequests'].append({'path': '/thumb', 'args': args})
                    self._sendBytes(fakeThumbBytes, 'image/png')
                    return

                if includeFileEndpoint and parsed.path == '/file':
                    state['endpointRequests'].append({'path': '/file', 'args': args})
                    hashValue = args.get('hash', [None])[0]
                    if not hashValue:
                        self._sendEmptyStatus(HTTPStatus.BAD_REQUEST)
                        return

                    selectedEntry = next((e for e in previewManifest['entries'] if e.get('hash') == hashValue), None)
                    if not selectedEntry or not sharedRoot:
                        self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                        return

                    relativeName = selectedEntry['name']
                    sharedRootName = os.path.basename(os.path.normpath(sharedRoot))
                    if relativeName.startswith(f"{sharedRootName}/"):
                        relativeName = relativeName[len(sharedRootName) + 1:]
                    filePath = os.path.join(sharedRoot, relativeName.replace('/', os.sep))
                    if not os.path.exists(filePath):
                        self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                        return

                    with open(filePath, 'rb') as fileHandle:
                        fileBody = fileHandle.read()
                    self._sendBytes(fileBody, selectedEntry.get('mime', 'application/octet-stream'))
                    return

                self._sendEmptyStatus(HTTPStatus.NOT_FOUND)

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), LocalHookServerHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()
        hookUrl = f"http://{authUser}:{authPassword}@127.0.0.1:{hookServer.server_address[1]}/events"
        return hookServer, hookThread, hookUrl

    def testHookPreviewStyleEndpointsFromShareManifest(self):
        """Verify hook-based /manifest, /file, /thumb endpoints work with hash parameters."""
        state = {
            'registerEvents': [],
            'endpointRequests': [],
            'shareManifest': [],
            'shareLink': '',
            'sharedRoot': None,
            'fakeThumbBytes': b"\x89PNG\r\n\x1a\nHOOK-THUMB",
        }
        outputCapture = {}

        sharedFolder = os.path.join(self.tempDir, "hook_preview_folder")
        os.makedirs(sharedFolder, exist_ok=True)
        nestedFolder = os.path.join(sharedFolder, "nested")
        os.makedirs(nestedFolder, exist_ok=True)
        with open(os.path.join(sharedFolder, "hello.txt"), "wb") as fileHandle:
            fileHandle.write(b"hello from hook preview test\n")
        with open(os.path.join(nestedFolder, "info.json"), "wb") as fileHandle:
            fileHandle.write(b'{"name":"hook","ok":true}\n')

        originalTestFile = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = sharedFolder
        self.originalFileSize = -1

        hookServer, hookThread, hookUrl = self._startPreviewHookServer(
            state, encryptResponse=False, includeFileEndpoint=True
        )

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraEnvVars={"DISABLE_ADDONS": "Preview"},
                extraArgs=["--hook", hookUrl, "--timeout", "30", "--log-level", "DEBUG"]
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)

            shareLink = shareInfo["link"].rstrip('/')

            manifestReady = False
            for retryIndex in range(10):
                if state['shareManifest']:
                    manifestReady = True
                    break
                time.sleep(0.5)
            self.assertTrue(manifestReady, "shareLinkCreate hook payload should include raw manifest entries")

            manifestResponse = requests.get(f"{shareLink}/manifest", timeout=30)
            self.assertEqual(manifestResponse.status_code, 200)
            manifestData = manifestResponse.json()
            self.assertGreater(manifestData.get('count', 0), 0)
            self.assertGreater(len(manifestData.get('entries', [])), 0)

            fileEntry = manifestData['entries'][0]
            fileHash = fileEntry['hash']
            fileResponse = requests.get(f"{shareLink}/file?hash={fileHash}", timeout=30)
            self.assertEqual(fileResponse.status_code, 200)

            expectedRelativeName = fileEntry['name']
            sharedFolderName = os.path.basename(os.path.normpath(sharedFolder))
            if expectedRelativeName.startswith(f"{sharedFolderName}/"):
                expectedRelativeName = expectedRelativeName[len(sharedFolderName) + 1:]
            expectedPath = os.path.join(sharedFolder, expectedRelativeName.replace('/', os.sep))
            with open(expectedPath, 'rb') as fileHandle:
                expectedBytes = fileHandle.read()
            self.assertEqual(fileResponse.content, expectedBytes)

            thumbResponse = requests.get(f"{shareLink}/thumb?hash={fileHash}", timeout=30)
            self.assertEqual(thumbResponse.status_code, 200)
            self.assertEqual(thumbResponse.content, state['fakeThumbBytes'])
            self.assertIn('image/png', thumbResponse.headers.get('Content-Type', ''))

            self.assertGreaterEqual(len(state['registerEvents']), 1)
            pathRequests = [entry.get('path') for entry in state['endpointRequests']]
            self.assertIn('/manifest', pathRequests)
            self.assertIn('/file', pathRequests)
            self.assertIn('/thumb', pathRequests)

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)
            self.testFilePath = originalTestFile
            self.originalFileSize = originalFileSize

    def testHookPreviewStyleEndpointsWithE2EE(self):
        """Verify hook-based /manifest and /thumb endpoints with encryptResponse:true are E2EE-encrypted."""
        state = {
            'registerEvents': [],
            'endpointRequests': [],
            'shareManifest': [],
            'shareLink': '',
            'sharedRoot': None,
            'fakeThumbBytes': b"\x89PNG\r\n\x1a\nHOOK-THUMB",
        }
        outputCapture = {}

        sharedFolder = os.path.join(self.tempDir, "hook_e2ee_folder")
        os.makedirs(sharedFolder, exist_ok=True)
        with open(os.path.join(sharedFolder, "hello.txt"), "wb") as fileHandle:
            fileHandle.write(b"hello from e2ee hook test\n")

        originalTestFile = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = sharedFolder
        self.originalFileSize = -1

        hookServer, hookThread, hookUrl = self._startPreviewHookServer(
            state, encryptResponse=True, includeFileEndpoint=False
        )

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraEnvVars={"DISABLE_ADDONS": "Preview"},
                extraArgs=["--e2ee", "--hook", hookUrl, "--timeout", "30", "--log-level", "DEBUG"]
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)

            shareLink = shareInfo["link"].rstrip('/')

            manifestReady = False
            for retryIndex in range(10):
                if state['shareManifest']:
                    manifestReady = True
                    break
                time.sleep(0.5)
            self.assertTrue(manifestReady, "shareLinkCreate hook payload should include raw manifest entries")

            # E2EE key exchange
            crypto = CryptoInterface()
            privKey, pubKey = crypto.generateRSAKeyPair()
            pubKeyPem = crypto.serializeRSAPublicKey(pubKey)

            e2eeManifestResponse = requests.get(f"{shareLink}/e2ee/manifest", timeout=30)
            self.assertEqual(e2eeManifestResponse.status_code, 200)
            chunkSize = e2eeManifestResponse.json().get('chunkSize', 0)
            self.assertGreater(chunkSize, 0)

            initResponse = requests.post(f"{shareLink}/e2ee/init", json={"publicKey": pubKeyPem}, timeout=30)
            self.assertEqual(initResponse.status_code, 200)
            initData = initResponse.json()
            contentKey = crypto.decryptRSAOAEP(privKey, base64.b64decode(initData['wrappedContentKey']))
            nonceBase = crypto.decryptRSAOAEP(privKey, base64.b64decode(initData['nonceBase']))

            # Decrypt /manifest
            encManifestBytes = requests.get(f"{shareLink}/manifest", timeout=30).content
            with self.assertRaises(Exception):
                json.loads(encManifestBytes)
            manifestData = self._decryptE2EEResponse(encManifestBytes, "manifest", contentKey, nonceBase, chunkSize)
            self.assertGreater(manifestData.get('count', 0), 0)

            # Decrypt /thumb
            fileHash = manifestData['entries'][0]['hash']
            encThumbBytes = requests.get(f"{shareLink}/thumb?hash={fileHash}", timeout=30).content
            self.assertNotEqual(encThumbBytes[:4], b'\x89PNG')
            thumbStreamId = f"thumb/{fileHash}"
            decryptedThumb = self._decryptE2EEResponse(encThumbBytes, thumbStreamId, contentKey, nonceBase, chunkSize)
            self.assertEqual(decryptedThumb, state['fakeThumbBytes'])

            self.assertGreaterEqual(len(state['registerEvents']), 1)

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)
            self.testFilePath = originalTestFile
            self.originalFileSize = originalFileSize

    def _decryptE2EEResponse(self, encryptedBytes, streamId, contentKey, nonceBase, chunkSize):
        """Fetch tags from the running FFL server and decrypt an encrypted hook response.

        Args:
            encryptedBytes: Raw ciphertext returned by the hook endpoint.
            streamId: Stream identifier used when encrypting (e.g. "manifest", "thumb/<hash>").
            contentKey: AES-256 content key (decrypted from RSA-OAEP wrapping).
            nonceBase: GCM nonce base (decrypted from RSA-OAEP wrapping).
            chunkSize: Encryption chunk size from /e2ee/manifest.

        Returns:
            Decrypted payload — bytes for binary content, parsed dict/list for JSON.
        """
        numChunks = max(1, (len(encryptedBytes) + chunkSize - 1) // chunkSize)
        with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
            shareLink = json.load(jsonFile)['link'].rstrip('/')
        tagsResponse = requests.get(
            f"{shareLink}/e2ee/tags",
            params={"streamId": streamId, "start": "0", "count": str(numChunks)},
            timeout=30,
        )
        self.assertEqual(tagsResponse.status_code, 200)
        tags = tagsResponse.json()['tags']
        self.assertEqual(len(tags), numChunks)

        decryptor = StreamDecryptor(contentKey, nonceBase, streamId, len(encryptedBytes))
        plaintext = b''.join(
            decryptor.decryptChunk(i, encryptedBytes[i * chunkSize:(i + 1) * chunkSize], base64.b64decode(tags[i]['tag']))
            for i in range(numChunks)
        )
        try:
            return json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return plaintext


    # ------------------------------------------------------------------
    # Sidecar upload helpers (shared by testHookSidecarProducer variants)
    # ------------------------------------------------------------------

    def _buildSidecarFolder(self):
        """Create test folder with a real JPEG and a text file.

        Initialises wx.App in the main thread via ThumbnailGenerator, then
        writes a real 100×100 JPEG — simulating a photo on Android.

        Returns a dict: sharedFolder, photoPath, readmePath, photoArcname,
        readmeArcname, photoHash, readmeHash, photoFileSize, readmeFileSize.
        """
        from addons.Preview import ThumbnailGenerator as ThumbGen, _hashArcname

        folderName = 'hook_sidecar_folder'
        sharedFolder = os.path.join(self.tempDir, folderName)
        os.makedirs(sharedFolder, exist_ok=True)

        photoPath = os.path.join(sharedFolder, 'photo.jpg')
        readmePath = os.path.join(sharedFolder, 'readme.txt')

        ThumbGen.getInstance()  # must be called in main thread to init wx.App
        wxImg = wx.Image(100, 100)
        wxImg.SetData(bytes([200, 120, 60] * 100 * 100))  # warm-orange 100×100 px
        wxImg.SaveFile(photoPath, wx.BITMAP_TYPE_JPEG)

        with open(readmePath, 'wb') as fh:
            fh.write(b'hello from hook sidecar test\n')

        photoArcname = f'{folderName}/photo.jpg'
        readmeArcname = f'{folderName}/readme.txt'
        return {
            'sharedFolder': sharedFolder,
            'photoPath': photoPath,
            'readmePath': readmePath,
            'photoArcname': photoArcname,
            'readmeArcname': readmeArcname,
            'photoHash': _hashArcname(photoArcname),
            'readmeHash': _hashArcname(readmeArcname),
            'photoFileSize': os.path.getsize(photoPath),
            'readmeFileSize': os.path.getsize(readmePath),
        }

    def _startAndroidHookServer(self, folderInfo):
        """Start the simulated Android hook server for sidecar upload tests.

        On /upload/tell: respond with a size estimate and kick off async wx
        thumbnail generation (simulating what the Android app does natively).
        On /upload/sidecar/fetch: wait for generation, then return the sidecar
        binary (inner manifest JSON + thumbnail bytes) and its outer manifest.

        Returns (server, thread, hookUrl, tellEvents, fetchEvents).
        """
        from addons.Preview import ThumbnailGenerator as ThumbGen

        tellEvents = []
        fetchEvents = []
        generationComplete = threading.Event()
        thumbState = []  # list of (fileHash, thumbBytes) built by generateAsync

        authUser = 'ffl'
        authPassword = 'test-hook-sidecar'
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"

        photoPath = folderInfo['photoPath']
        readmePath = folderInfo['readmePath']
        photoArcname = folderInfo['photoArcname']
        readmeArcname = folderInfo['readmeArcname']
        photoHash = folderInfo['photoHash']
        readmeHash = folderInfo['readmeHash']
        photoFileSize = folderInfo['photoFileSize']
        readmeFileSize = folderInfo['readmeFileSize']

        class AndroidHookHandler(_JSONHookEventHandlerMixin, BaseHTTPRequestHandler):
            AUTH_HEADER = authHeader
            AUTH_REALM = 'Android Sim'

            def _buildInnerManifest(self, uid):
                manifest = {
                    'uid': uid,
                    'zipName': 'hook_sidecar_folder.zip',
                    'zipSize': 0,
                    'count': 2,
                    'entries': [
                        {
                            'index': 0, 'segmentIndex': 0,
                            'name': photoArcname, 'hash': photoHash,
                            'size': photoFileSize, 'mtime': 0,
                            'mime': 'image/jpeg', 'dataOffset': 0,
                        },
                        {
                            'index': 1, 'segmentIndex': 1,
                            'name': readmeArcname, 'hash': readmeHash,
                            'size': readmeFileSize, 'mtime': 0,
                            'mime': 'text/plain', 'dataOffset': 0,
                        },
                    ],
                }
                return json.dumps(manifest, separators=(',', ':')).encode('utf-8')

            def do_POST(self):
                if not self._requireAuth():
                    return

                eventName, eventData = self._readEventPayload()

                if eventName == '/upload/tell':
                    tellEvents.append(eventData)

                    def generateAsync():
                        try:
                            gen = ThumbGen.getInstance()
                            for filePath, arcname, fileHash, mimeType in [
                                (photoPath, photoArcname, photoHash, 'image/jpeg'),
                                (readmePath, readmeArcname, readmeHash, 'text/plain'),
                            ]:
                                result = gen.generateThumbnailData(
                                    filePath, arcname, mimeType, allowFallback=True
                                )
                                if result:
                                    thumbBytes, _i = result
                                    thumbState.append((fileHash, thumbBytes))
                        except Exception:
                            pass
                        finally:
                            generationComplete.set()

                    threading.Thread(target=generateAsync, daemon=True).start()

                    uid = eventData.get('uid', '')
                    innerManifest = self._buildInnerManifest(uid)
                    estimatedSize = len(innerManifest) + 2 * 20 * 1024
                    self._sendJSON({'sidecar': {'size': estimatedSize}})

                elif eventName == '/upload/sidecar/fetch':
                    fetchEvents.append(eventData)
                    generationComplete.wait(timeout=30)

                    uid = eventData.get('uid') or (tellEvents[0].get('uid', '') if tellEvents else '')
                    innerManifest = self._buildInnerManifest(uid)

                    sidecarData = innerManifest
                    offset = len(innerManifest)
                    thumbHashMap = {}
                    for fileHash, thumbBytes in thumbState:
                        thumbHashMap[fileHash] = [offset, offset + len(thumbBytes)]
                        sidecarData += thumbBytes
                        offset += len(thumbBytes)

                    self._sendJSON({
                        'data': base64.b64encode(sidecarData).decode('ascii'),
                        'manifest': {
                            'manifest': [0, len(innerManifest)],
                            'thumb': {'hash': thumbHashMap},
                        },
                    })

                else:
                    self._sendJSON({'status': 'ok'})

        server = ThreadingHTTPServer(('127.0.0.1', 0), AndroidHookHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        hookUrl = f"http://{authUser}:{authPassword}@127.0.0.1:{server.server_address[1]}/events"
        return server, thread, hookUrl, tellEvents, fetchEvents

    def _assertSidecarUpload(self, shareLink, tellEvents, fetchEvents, processOutput, *, verifyZip=True):
        """Assert hook events, optional ZIP download, preview page, manifest, and thumbnail."""
        self.assertGreater(
            len(tellEvents), 0,
            f"Hook server should receive /upload/tell event.\n{processOutput}"
        )
        self.assertGreater(
            len(fetchEvents), 0,
            f"Hook server should receive /upload/sidecar/fetch event.\n{processOutput}"
        )
        self.assertIn('uid', fetchEvents[0], "/upload/sidecar/fetch payload should contain upload uid")

        if verifyZip:
            downloadedZipPath = self._getDownloadedFilePath("hook_sidecar_folder.zip")
            self.downloadFileWithRequests(shareLink, downloadedZipPath)
            self.assertTrue(zipfile.is_zipfile(downloadedZipPath), "Downloaded file should be a valid ZIP archive")
            with zipfile.ZipFile(downloadedZipPath, 'r') as zf:
                namelist = zf.namelist()
            self.assertTrue(any('photo.jpg' in n for n in namelist), f"ZIP should contain photo.jpg; got: {namelist}")
            self.assertTrue(any('readme.txt' in n for n in namelist), f"ZIP should contain readme.txt; got: {namelist}")

        previewResponse = requests.get(
            shareLink,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"},
            timeout=30,
        )
        self.assertEqual(previewResponse.status_code, 200, f"Preview page should return HTTP 200; got {previewResponse.status_code}")
        self.assertIn('text/html', previewResponse.headers.get('Content-Type', ''), "Preview page should return HTML")

        parsed = urlparse(shareLink)
        serverUrl = f"{parsed.scheme}://{parsed.netloc}"
        uid = parsed.path.lstrip('/')

        manifestResponse = requests.get(f"{serverUrl}/{uid}/manifest", timeout=30)
        self.assertEqual(manifestResponse.status_code, 200, f"Manifest endpoint should return 200; got {manifestResponse.status_code}")
        self.assertGreater(len(manifestResponse.content), 0, "Manifest response should be non-empty (sidecar was uploaded)")

        if 'application/json' in manifestResponse.headers.get('Content-Type', ''):
            # Plain upload: manifest is unencrypted JSON — verify entries and thumbnail.
            entries = manifestResponse.json().get('entries', [])
            self.assertEqual(len(entries), 2, f"Manifest should contain 2 entries; got {entries}")

            photoEntry = next((e for e in entries if 'photo.jpg' in e['name']), None)
            self.assertIsNotNone(photoEntry, "Manifest should contain photo.jpg entry")

            thumbResponse = requests.get(f"{serverUrl}/{uid}/thumb?hash={photoEntry['hash']}", timeout=30)
            self.assertEqual(thumbResponse.status_code, 200, f"Thumbnail endpoint should return 200 for photo.jpg; got {thumbResponse.status_code}")
            thumbBytes = thumbResponse.content
            self.assertGreater(len(thumbBytes), 0, "Thumbnail response should be non-empty")
            self.assertTrue(
                thumbBytes[:3] == b'\xff\xd8\xff',
                f"Thumbnail should be JPEG (FF D8 FF); got {thumbBytes[:3].hex()}"
            )
            print(f"[Test] photo.jpg thumbnail: {len(thumbBytes)} bytes (valid JPEG)")
        else:
            # E2EE upload: sidecar is encrypted — verify it was stored (non-empty binary).
            print(f"[Test] Sidecar stored encrypted: {len(manifestResponse.content)} bytes")

    def _runSidecarUploadTest(self, extraUploadArgs=None):
        """Upload a folder with Android-simulated hook sidecar, then assert results.

        extraUploadArgs: additional FFL args (e.g. ['--e2ee']).
        ZIP-content verification is skipped for e2ee uploads since the downloaded
        file is encrypted and cannot be opened as a plain ZIP.
        """
        folderInfo = self._buildSidecarFolder()
        server, thread, hookUrl, tellEvents, fetchEvents = self._startAndroidHookServer(folderInfo)

        originalTestFile = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = folderInfo['sharedFolder']
        self.originalFileSize = -1
        outputCapture = {}

        try:
            shareLink = self._startFastFileLink(
                p2p=False,
                captureOutputIn=outputCapture,
                extraEnvVars={"DISABLE_ADDONS": "Preview"},
                extraArgs=["--hook", hookUrl, "--log-level", "DEBUG"] + (extraUploadArgs or []),
            )

            processOutput = self._updateCapturedOutput(outputCapture)
            e2eeKey = next(
                (line.split("Encryption Key:", 1)[1].strip() for line in processOutput.splitlines() if "Encryption Key:" in line),
                None,
            )

            print(f"\n{'=' * 60}")
            print(f"[Test] UPLOAD SHARE URL (open in browser to verify preview):")
            print(f"[Test] {shareLink}")
            if e2eeKey:
                print(f"[Test] Encryption Key: {e2eeKey}")
            print(f"{'=' * 60}\n")

            verifyZip = '--e2ee' not in (extraUploadArgs or [])
            self._assertSidecarUpload(shareLink, tellEvents, fetchEvents, processOutput, verifyZip=verifyZip)

        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.testFilePath = originalTestFile
            self.originalFileSize = originalFileSize

    @unittest.skipIf(SKIP_GUI_TEST, "Preview tests disabled because no GUI")
    def testHookSidecarProducer(self):
        """Simulate Android app providing sidecar during folder upload via hook."""
        self._runSidecarUploadTest()

    @unittest.skipIf(SKIP_GUI_TEST, "Preview tests disabled because no GUI")
    def testHookSidecarProducerWithE2EE(self):
        """Same as testHookSidecarProducer but with end-to-end encryption (--e2ee).

        The main ZIP download is skipped (it is encrypted), but the sidecar
        manifest and thumbnail endpoints are verified — sidecar data is not
        affected by the e2ee flag.
        """
        self._runSidecarUploadTest(extraUploadArgs=['--e2ee'])

    def _startEventControlledHookServer(self, state, failStatusFor):
        """Local hook server for HookEventForwarder failure-handling tests.

        POST /hook/server/endpoints/register is answered per failStatusFor like
        any other event (it is not special-cased here); the test itself decides
        when registration should succeed. On success it mounts a single GET
        /hello route so registration health is independently observable from
        HTTP requests, on top of the raw per-event counts below.

        failStatusFor(eventName, occurrence) -> Optional[int]: called for every
        posted event with a 1-based per-eventName occurrence count; return an
        HTTP status to answer with (e.g. 401, 500), or None for a normal 200.

        state['eventCounts']: {eventName: occurrence count}, updated for every
        posted event, including ones the forwarder itself never sends (so a
        count that stops advancing is proof forwarding was skipped, not just
        that this test didn't check).

        Returns (hookServer, hookThread, hookUrl).
        """
        state.setdefault('eventCounts', {})

        class LocalHookServerHandler(_JSONHookEventHandlerMixin, BaseHTTPRequestHandler):
            def do_POST(self):
                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self._sendEmptyStatus(HTTPStatus.NOT_FOUND)
                    return

                eventName, _eventData = self._readEventPayload()

                occurrence = state['eventCounts'].get(eventName, 0) + 1
                state['eventCounts'][eventName] = occurrence
                failStatus = failStatusFor(eventName, occurrence)

                if failStatus:
                    self._sendEmptyStatus(failStatus)
                    return

                if eventName == '/hook/server/endpoints/register':
                    self._sendJSON({'routes': [{'method': 'GET', 'path': '/hello'}]})
                else:
                    self._sendJSON({'status': 'ok'})

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == '/hello':
                    self._sendBytes(b'hello from hook server', 'text/plain; charset=utf-8')
                    return

                self._sendEmptyStatus(HTTPStatus.NOT_FOUND)

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), LocalHookServerHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()
        hookUrl = f"http://127.0.0.1:{hookServer.server_address[1]}/events"
        return hookServer, hookThread, hookUrl

    def testHookForwarderCooldownSkipsFailingEventButKeepsRetryingRegistration(self):
        """A burst of consecutive failures on an unrelated event (downloadStarted)
        must not disable hook endpoint registration for this session.

        Reproduces the FFL core regression: pre-fix, HookEventForwarder called
        self.clear() on the very first HookError from ANY forwarded event --
        since it is subscribed to the wildcard FFLEvent.all, an unrelated event
        failure (e.g. a progress notification) permanently killed the sender,
        and _mergeAdditionalEndpointMaps()'s serverEndpointsRegister trigger is
        the *only* channel that mounts hook-registered routes like /manifest,
        /thumb (or here, /hello) per request. Once cleared, no future request on
        that connection -- or any later connection -- could register endpoints
        again without an app restart, and the *old* route cache stored a failed
        [] lookup as if it were a real (empty) success, keeping it 404 even
        after the hook server recovered.

        This test drives the real fix in bases/Hook.py:
          - 3 consecutive downloadStarted failures enter cooldown (short window,
            overridden via HOOK_FORWARDER_COOLDOWN_SECONDS for the test) -- during
            which further downloadStarted attempts are skipped outright (proven
            by the hook server's per-event occurrence count going flat).
          - serverEndpointsRegister is exempt from that skip and keeps being
            retried on every request regardless of cooldown state.
          - A failed registration attempt is no longer cached (bases/Hook.py
            HookEndpointRouter._fetchRoutes/_getRoutesForSession), so once the
            hook server starts answering it successfully again, the very next
            request mounts /hello -- no restart, no reconfigure needed.
        """
        # A Range download turns out to fire more than one non-registration
        # event per request (downloadStarted, downloadProgress, ...), and
        # _consecutiveFailures is a single counter shared across ALL forwarded
        # event names -- a success on any one of them (there is no per-name
        # bucketing) resets it. So rather than assume a fixed "N requests == 3
        # failures" mapping, fail every non-registration event unconditionally
        # via state['failNonReg'] and detect the threshold being crossed by
        # watching state['nonRegAttempts'] (count of non-registration events
        # that actually reached the hook server) stop advancing.
        state = {'nonRegAttempts': 0, 'failNonReg': True, 'failReg': True}

        def failStatusFor(eventName, occurrence):
            if eventName == '/hook/server/endpoints/register':
                return HTTPStatus.INTERNAL_SERVER_ERROR if state['failReg'] else None
            state['nonRegAttempts'] += 1
            return HTTPStatus.INTERNAL_SERVER_ERROR if state['failNonReg'] else None

        hookServer, hookThread, hookUrl = self._startEventControlledHookServer(state, failStatusFor)
        outputCapture = {}
        cooldownSeconds = 3

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraArgs=["--hook", hookUrl, "--timeout", "60", "--log-level", "DEBUG"],
                extraEnvVars={"HOOK_FORWARDER_COOLDOWN_SECONDS": str(cooldownSeconds)},
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)
            shareLink = shareInfo["link"]
            downloadUrl = shareLink.rstrip('/') + '/download'
            helloUrl = shareLink.rstrip('/') + '/hello'

            # Bounded Range requests are cheap, don't count toward maxDownloads,
            # and don't mark a single-use reader consumed -- each one still
            # independently triggers downloadStarted/downloadProgress (bases/
            # Server.py _handleStartDownloadActions), which is exactly what we
            # need: a controllable, repeatable, non-registration event to fail.
            def hitDownload():
                response = requests.get(downloadUrl, headers={'Range': 'bytes=0-0'}, timeout=15)
                self.assertIn(
                    response.status_code, (200, 206),
                    f"Range download request should succeed regardless of hook forwarding failures; "
                    f"got {response.status_code}"
                )

            # Keep hitting /download until a whole request goes by without
            # state['nonRegAttempts'] advancing at all -- proof that cooldown
            # is now suppressing every non-registration event outright, not
            # just that this particular event happened to succeed.
            registeredEndpointPath = '/hook/server/endpoints/register'
            cooldownObserved = False
            for _ in range(10):
                before = state['nonRegAttempts']
                hitDownload()
                if state['nonRegAttempts'] == before:
                    cooldownObserved = True
                    break
            self.assertTrue(
                cooldownObserved,
                f"Cooldown never appeared to engage after repeated failures (nonRegAttempts={state['nonRegAttempts']})"
            )
            self.assertGreater(
                state['eventCounts'].get(registeredEndpointPath, 0), 0,
                "Registration must have kept being retried throughout, exempt from the cooldown skip"
            )

            helloDuringCooldown = requests.get(helloUrl, timeout=15)
            self.assertEqual(
                helloDuringCooldown.status_code, HTTPStatus.NOT_FOUND,
                "Registration is still failing by design at this point, so /hello legitimately isn't mounted yet "
                "-- but critically the process is still alive and retrying, not permanently disabled"
            )

            registrationAttemptsSoFar = state['eventCounts'].get(registeredEndpointPath, 0)

            # One more request while still (probably) in cooldown: registration
            # -- exempt from the skip -- must still be attempted for real.
            hitDownload()
            self.assertGreater(
                state['eventCounts'].get(registeredEndpointPath, 0), registrationAttemptsSoFar,
                "Registration must keep being retried on every request regardless of cooldown state"
            )

            # Let both the hook server and the cooldown window recover, then
            # make one more request: registration should now succeed and mount
            # /hello, and downloadStarted/downloadProgress should reach the
            # hook server again (cooldown expired) instead of being skipped.
            state['failReg'] = False
            state['failNonReg'] = False
            time.sleep(cooldownSeconds + 1.5)

            nonRegAttemptsBeforeRecovery = state['nonRegAttempts']
            hitDownload()
            self.assertGreater(
                state['nonRegAttempts'], nonRegAttemptsBeforeRecovery,
                "downloadStarted/downloadProgress should be forwarded again now that cooldown has elapsed"
            )

            helloAfterRecovery = requests.get(helloUrl, timeout=15)
            self.assertEqual(
                helloAfterRecovery.status_code, HTTPStatus.OK,
                "/hello must be mounted automatically once registration succeeds again -- no app restart needed"
            )
            self.assertEqual(helloAfterRecovery.text, "hello from hook server")

        finally:
            processOutput = self._updateCapturedOutput(outputCapture)
            print(f"[Test] eventCounts={state.get('eventCounts')}\nprocessOutput={processOutput}")
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)

    def testHookForwarderAuthFailureDisablesWithoutRetry(self):
        """A single HookAuthError (401) must disable forwarding immediately and
        permanently -- unlike a plain HookError, it must NOT wait for
        FAILURE_THRESHOLD consecutive failures, and must NOT auto-resume after
        COOLDOWN_SECONDS.

        Rationale: the credentials embedded in a hookURL are fixed for the life
        of a share session (only a fresh HookEventForwarder.configure() call --
        i.e. a new session -- ever changes them), so a 401 is deterministic: it
        will fail exactly the same way on every retry. Treating it like a
        transient network error and retrying it on a cooldown timer would just
        repeat the same doomed request forever. A plain HookError (timeout,
        connection refused, 5xx) has no such guarantee and IS expected to
        recover on its own, which is why only HookAuthError takes this path --
        see testHookForwarderCooldownSkipsFailingEventButKeepsRetryingRegistration
        for the contrasting (auto-recovering) behavior.

        Route registration is merged into each TCP connection's own handler
        instance (bases/Server.py _mergeAdditionalEndpointMaps), so every new
        connection needs the forwarder to be live *at the moment it connects* --
        an earlier connection's successful /hello mount does not carry over to
        a later one. That makes "the forwarder is now disabled" directly
        observable as later connections 404 on /hello even though an earlier
        connection, before the 401, mounted it successfully -- this is the
        literal recipient-facing symptom (new page loads 404 on /manifest,
        /thumb after the app hiccups) the fix addresses.
        """
        state = {}

        def failStatusFor(eventName, occurrence):
            if eventName == '/download/create':
                return HTTPStatus.UNAUTHORIZED
            return None

        hookServer, hookThread, hookUrl = self._startEventControlledHookServer(state, failStatusFor)
        outputCapture = {}
        # Short cooldown so that, if the fix wrongly treated this as a plain
        # HookError, waiting past it would (incorrectly) look like recovery.
        cooldownSeconds = 2

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraArgs=["--hook", hookUrl, "--timeout", "60", "--log-level", "DEBUG"],
                extraEnvVars={"HOOK_FORWARDER_COOLDOWN_SECONDS": str(cooldownSeconds)},
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)
            shareLink = shareInfo["link"]
            downloadUrl = shareLink.rstrip('/') + '/download'
            helloUrl = shareLink.rstrip('/') + '/hello'

            def hitDownload():
                response = requests.get(downloadUrl, headers={'Range': 'bytes=0-0'}, timeout=15)
                self.assertIn(response.status_code, (200, 206))

            # Connection 1: registration succeeds and mounts /hello for *this*
            # connection -- proving the session was healthy beforehand -- while
            # downloadStarted gets a 401 on its first and only occurrence,
            # disabling the forwarder immediately (before this connection closes).
            hitDownload()
            self.assertEqual(state['eventCounts'].get('/download/create'), 1)

            # Connection 2 (brand new TCP connection, opened after the 401):
            # its own registration attempt is skipped outright because the
            # forwarder is already disabled, so /hello 404s here even though it
            # was reachable one connection ago. This is the actual recipient
            # symptom: a fresh page load hitting a 404 right after the app hiccups.
            self.assertEqual(
                requests.get(helloUrl, timeout=15).status_code, HTTPStatus.NOT_FOUND,
                "A new connection after the 401 must not be able to mount /hello -- the forwarder is disabled"
            )

            # Connections 3 and 4, issued immediately: with a plain HookError
            # this would still be well within FAILURE_THRESHOLD (no cooldown
            # yet), so if the fix mishandled HookAuthError as a plain HookError,
            # these would still reach the hook server. They must not.
            hitDownload()
            hitDownload()
            self.assertEqual(
                state['eventCounts'].get('/download/create'), 1,
                "No further downloadStarted attempts should reach the hook server after the 401 -- "
                "the forwarder must be disabled outright, not merely counting toward a threshold"
            )

            # Wait past what would be the cooldown window for a plain HookError,
            # then try again: a cooldown-based disable would auto-resume here;
            # an auth-triggered clear() must not.
            time.sleep(cooldownSeconds + 1.5)
            hitDownload()
            self.assertEqual(
                state['eventCounts'].get('/download/create'), 1,
                "The 401 disable must be permanent (until a fresh configure()), not time-limited like cooldown"
            )
            self.assertEqual(
                requests.get(helloUrl, timeout=15).status_code, HTTPStatus.NOT_FOUND,
                "/hello must still be unreachable on a new connection -- no auto-resume, unlike cooldown"
            )

        finally:
            processOutput = self._updateCapturedOutput(outputCapture)
            print(f"[Test] eventCounts={state.get('eventCounts')}\nprocessOutput={processOutput}")
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
