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

import requests

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from bases.Hook import HookServer, HookClient, HookError, HookAuthError
from ..CoreTestBase import FastFileLinkTestBase


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


class HookFunctionalTest(FastFileLinkTestBase):
    """Functional tests for hook endpoint integration with real Core process."""

    def testHookRegisteredEndpointHello(self):
        """Verify hook-registered /hello endpoint is served at [share link]/hello."""
        registerEvents = []
        endpointRequests = []
        outputCapture = {}

        authUser = 'ffl'
        authPassword = 'test-hook-token'
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"

        class LocalHookServerHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _checkAuth(self):
                return self.headers.get('Authorization') == authHeader

            def _sendAuthChallenge(self):
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header('WWW-Authenticate', 'Basic realm="Hook Test"')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_POST(self):
                if not self._checkAuth():
                    self._sendAuthChallenge()
                    return

                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self.send_response(HTTPStatus.NOT_FOUND)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return

                contentLength = int(self.headers.get('Content-Length', 0))
                requestData = json.loads(self.rfile.read(contentLength)) if contentLength else {}

                eventName = requestData.get('event')
                eventData = requestData.get('data', {})

                if eventName == '/hook/server/endpoints/register':
                    registerEvents.append(eventData)
                    responseData = {'routes': [{'method': 'GET', 'path': '/hello'}]}
                else:
                    responseData = {'status': 'ok'}

                responseBody = json.dumps(responseData).encode('utf-8')
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(responseBody)))
                self.end_headers()
                self.wfile.write(responseBody)

            def do_GET(self):
                if not self._checkAuth():
                    self._sendAuthChallenge()
                    return

                parsed = urlparse(self.path)
                if parsed.path == '/hello':
                    endpointRequests.append({
                        'path': parsed.path,
                        'query': parse_qs(parsed.query),
                    })
                    responseBody = b'hello from hook server'
                    self.send_response(HTTPStatus.OK)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.send_header('Content-Length', str(len(responseBody)))
                    self.end_headers()
                    self.wfile.write(responseBody)
                    return

                self.send_response(HTTPStatus.NOT_FOUND)
                self.send_header('Content-Length', '0')
                self.end_headers()

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), LocalHookServerHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()
        hookUrl = f"http://{authUser}:{authPassword}@127.0.0.1:{hookServer.server_address[1]}/events"

        try:
            self._startFastFileLink(
                p2p=True,
                captureOutputIn=outputCapture,
                extraArgs=["--hook", hookUrl, "--timeout", "30", "--log-level", "DEBUG"]
            )

            with open(self.jsonOutputPath, 'r', encoding='utf-8') as jsonFile:
                shareInfo = json.load(jsonFile)

            shareLink = shareInfo["link"]
            uid = urlparse(shareLink).path.strip('/').split('/')[0]
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

    def testHookPreviewStyleEndpointsFromShareManifest(self):
        """Verify hook-based /manifest, /file, /thumb endpoints work with hash parameters."""
        registerEvents = []
        endpointRequests = []
        outputCapture = {}

        sharedFolder = os.path.join(self.tempDir, "hook_preview_folder")
        os.makedirs(sharedFolder, exist_ok=True)
        nestedFolder = os.path.join(sharedFolder, "nested")
        os.makedirs(nestedFolder, exist_ok=True)

        file1Path = os.path.join(sharedFolder, "hello.txt")
        file2Path = os.path.join(nestedFolder, "info.json")
        file1Content = b"hello from hook preview test\n"
        file2Content = b'{"name":"hook","ok":true}\n'

        with open(file1Path, "wb") as fileHandle:
            fileHandle.write(file1Content)
        with open(file2Path, "wb") as fileHandle:
            fileHandle.write(file2Content)

        originalTestFile = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = sharedFolder
        self.originalFileSize = -1

        authUser = 'ffl'
        authPassword = 'test-hook-token'
        authHeader = f"Basic {base64.b64encode(f'{authUser}:{authPassword}'.encode()).decode()}"

        fakeThumbBytes = b"\x89PNG\r\n\x1a\nHOOK-THUMB"
        shareManifest = []
        shareLink = ''
        sharedRoot = None

        class LocalHookServerHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _checkAuth(self):
                return self.headers.get('Authorization') == authHeader

            def _sendAuthChallenge(self):
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header('WWW-Authenticate', 'Basic realm="Hook Test"')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_POST(self):
                nonlocal shareManifest
                nonlocal shareLink
                nonlocal sharedRoot

                if not self._checkAuth():
                    self._sendAuthChallenge()
                    return

                parsed = urlparse(self.path)
                if parsed.path != '/events':
                    self.send_response(HTTPStatus.NOT_FOUND)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return

                contentLength = int(self.headers.get('Content-Length', 0))
                requestData = json.loads(self.rfile.read(contentLength)) if contentLength else {}

                eventName = requestData.get('event')
                eventData = requestData.get('data', {})

                if eventName == '/hook/server/endpoints/register':
                    registerEvents.append(eventData)
                    responseData = {
                        'routes': [
                            {'method': 'GET', 'path': '/manifest'},
                            {'method': 'GET', 'path': '/file'},
                            {'method': 'GET', 'path': '/thumb'},
                        ]
                    }
                else:
                    if eventName == '/share/link/create':
                        shareManifest = eventData.get('manifest', [])
                        shareLink = eventData.get('link', '')
                        sharedRoot = eventData.get('filePath')
                    responseData = {'status': 'ok'}

                responseBody = json.dumps(responseData).encode('utf-8')
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(responseBody)))
                self.end_headers()
                self.wfile.write(responseBody)

            def do_GET(self):
                if not self._checkAuth():
                    self._sendAuthChallenge()
                    return

                parsed = urlparse(self.path)
                args = parse_qs(parsed.query)

                uid = ''
                if shareLink:
                    uid = urlparse(shareLink).path.strip('/').split('/')[0]

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
                    endpointRequests.append({'path': '/manifest'})
                    body = json.dumps(previewManifest).encode('utf-8')
                    self.send_response(HTTPStatus.OK)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if parsed.path == '/file':
                    endpointRequests.append({'path': '/file', 'args': args})
                    hashValue = args.get('hash', [None])[0]
                    if not hashValue:
                        self.send_response(HTTPStatus.BAD_REQUEST)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return

                    entries = previewManifest.get('entries', [])
                    selectedEntry = None
                    for item in entries:
                        if item.get('hash') == hashValue:
                            selectedEntry = item
                            break

                    if not selectedEntry or not sharedRoot:
                        self.send_response(HTTPStatus.NOT_FOUND)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return

                    relativeName = selectedEntry.get('name', '')
                    sharedRootName = os.path.basename(os.path.normpath(sharedRoot))
                    if relativeName.startswith(f"{sharedRootName}/"):
                        relativeName = relativeName[len(sharedRootName) + 1:]
                    relativeName = relativeName.replace('/', os.sep)
                    filePath = os.path.join(sharedRoot, relativeName)
                    if not os.path.exists(filePath):
                        self.send_response(HTTPStatus.NOT_FOUND)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return

                    with open(filePath, 'rb') as fileHandle:
                        fileBody = fileHandle.read()

                    self.send_response(HTTPStatus.OK)
                    self.send_header('Content-Type', selectedEntry.get('mime', 'application/octet-stream'))
                    self.send_header('Content-Length', str(len(fileBody)))
                    self.end_headers()
                    self.wfile.write(fileBody)
                    return

                if parsed.path == '/thumb':
                    endpointRequests.append({'path': '/thumb', 'args': args})
                    self.send_response(HTTPStatus.OK)
                    self.send_header('Content-Type', 'image/png')
                    self.send_header('Content-Length', str(len(fakeThumbBytes)))
                    self.end_headers()
                    self.wfile.write(fakeThumbBytes)
                    return

                self.send_response(HTTPStatus.NOT_FOUND)
                self.send_header('Content-Length', '0')
                self.end_headers()

        hookServer = ThreadingHTTPServer(('127.0.0.1', 0), LocalHookServerHandler)
        hookThread = threading.Thread(target=hookServer.serve_forever, daemon=True)
        hookThread.start()
        hookUrl = f"http://{authUser}:{authPassword}@127.0.0.1:{hookServer.server_address[1]}/events"

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
                if shareManifest:
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
            self.assertEqual(thumbResponse.content, fakeThumbBytes)
            self.assertIn('image/png', thumbResponse.headers.get('Content-Type', ''))

            self.assertGreaterEqual(len(registerEvents), 1)
            pathRequests = [entry.get('path') for entry in endpointRequests]
            self.assertIn('/manifest', pathRequests)
            self.assertIn('/file', pathRequests)
            self.assertIn('/thumb', pathRequests)

        finally:
            hookServer.shutdown()
            hookServer.server_close()
            hookThread.join(timeout=5)
            self.testFilePath = originalTestFile
            self.originalFileSize = originalFileSize


if __name__ == '__main__':
    unittest.main()
