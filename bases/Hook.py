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
"""
Hook IPC mechanism for forwarding events between processes using HTTP webhooks.

This module provides a simple HTTP-based webhook mechanism for forwarding EventService
events from CLI subprocess to GUI parent process (or any external webhook receiver).

Protocol:
    - HTTP POST requests with JSON payload
    - HTTP Basic Auth for authentication (optional)
    - Event format: {"event": "event_name", "data": {...}}

Usage (Server side - GUI):
    server = HookServer(host='127.0.0.1', port=0, path='/events', username='app', password='token')
    server.start()

    def onEvent(eventName, eventData):
        print(f"Received event: {eventName}, data: {eventData}")

    server.onEvent = onEvent
    hookURL = server.getHookURL()  # e.g., http://app:token@127.0.0.1:12345/events
    # ... later ...
    server.stop()

Usage (Client side - CLI):
    client = HookClient('http://app:token@127.0.0.1:12345/events')
    client.sendEvent('/server/ready', {'url': 'http://...'})
"""

import base64
import json
import secrets
import threading

from dataclasses import is_dataclass, asdict
from datetime import datetime, date
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from urllib.parse import urlparse, urlunparse, urlencode
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import requests

from http import HTTPStatus

from bases.Kernel import getLogger, FFLEvent, Event
from bases.Server import AuthMixin, HTTPAuth

logger = getLogger(__name__)


_CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class HookError(Exception):
    """Base exception for Hook-related errors."""
    pass


class HookAuthError(HookError):
    """Authentication error."""
    pass


class HookRequestHandler(AuthMixin, BaseHTTPRequestHandler):
    """HTTP request handler for webhook server."""

    REALM = 'Hook Server'

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"Hook request: {format % args}")

    @property
    def auth(self) -> HTTPAuth:
        """Return HTTPAuth from server for AuthMixin."""
        return HTTPAuth(user=self.server.username, password=self.server.password)

    def _sendJsonResponse(self, statusCode: int, payload: dict):
        responseBody = json.dumps(HookEventSerializer.makeJsonSafe(payload)).encode('utf-8')

        try:
            self.send_response(statusCode)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(responseBody)))
            self.end_headers()
            self.wfile.write(responseBody)
        except _CLIENT_DISCONNECT_ERRORS as e:
            logger.info(
                "Hook client disconnected before response could be sent for %s from %s: %s",
                getattr(self, 'path', ''), self.client_address[0], e
            )

    def do_POST(self):
        """Handle POST request with event data."""
        # Check authentication using AuthMixin
        if not self.handleAuthentication():
            return

        # Check path
        if self.server.path and self.path != self.server.path:
            self.send_response(404)
            self.end_headers()
            logger.warning(f"Invalid path {self.path} from {self.client_address[0]}")
            return

        # Read request body
        contentLength = int(self.headers.get('Content-Length', 0))
        if contentLength == 0:
            self._sendJsonResponse(400, {'error': "Empty request body"})
            return

        try:
            requestBody = self.rfile.read(contentLength)
            data = json.loads(requestBody.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._sendJsonResponse(400, {'error': f'Invalid JSON: {e}'})
            logger.warning(f"Invalid JSON from {self.client_address[0]}: {e}")
            return

        # Extract event name and data
        eventName = data.get('event')
        eventData = data.get('data', {})

        if not eventName:
            self._sendJsonResponse(400, {'error': "Missing event field"})
            logger.warning(f"Missing event field from {self.client_address[0]}")
            return

        responsePayload = None

        # Call event handler
        if self.server.onEvent:
            try:
                responsePayload = self.server.onEvent(eventName, eventData)
            except Exception as e:
                logger.error(f"Error in event handler for {eventName}: {e}")
                self._sendJsonResponse(500, {'error': f'Handler error: {e}'})
                return

        # Send success response
        if responsePayload is None:
            responsePayload = {'status': 'ok'}

        self._sendJsonResponse(200, responsePayload)


class HookServer(ThreadingHTTPServer):
    """
    HTTP webhook server for receiving events.

    Example:
        server = HookServer(host='127.0.0.1', port=0, path='/events',
                           username='app', password='token')
        server.start()
        print(f"Webhook URL: {server.getHookURL()}")

        def onEvent(eventName, eventData):
            print(f"Event: {eventName}, data: {eventData}")

        server.onEvent = onEvent
    """

    daemon_threads = True

    @staticmethod
    def generateToken() -> str:
        """
        Generate a secure random token for hook authentication.

        Returns:
            str: 32-character hex token
        """
        return secrets.token_hex(16)

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 0,
        path: str = '/events',
        username: Optional[str] = 'ffl',
        password: Optional[str] = None,
        onEventCallable=None,
    ):
        super().__init__((host, port), HookRequestHandler)

        self.host = host
        self.port = self.server_address[1] # Get actual port (if 0 was passed)
        self.path = path
        self.username = username
        self.password = password if password else HookServer.generateToken()
        self.onEvent: Optional[Callable[[str, dict], None]] = onEventCallable

        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """
        Start webhook server in background thread.

        Raises:
            HookError: If server is already running
        """
        if self._running:
            raise HookError("Server already running")

        self._running = True
        self._thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': 0.5}, daemon=True)
        self._thread.start()

        logger.debug(f"Hook server started on {self.host}:{self.port}{self.path}")

    def stop(self):
        """Stop webhook server."""
        if not self._running:
            return

        self._running = False
        self.shutdown()

        if self._thread:
            self._thread.join(timeout=5.0)

        self.server_close()

        logger.debug("Hook server stopped")

    def getHookURL(self) -> str:
        """
        Get webhook URL (including auth credentials if configured).

        Returns:
            str: Full webhook URL (e.g., http://app:token@127.0.0.1:12345/events)
        """
        if self.username and self.password:
            netloc = f"{self.username}:{self.password}@{self.host}:{self.port}"
        else:
            netloc = f"{self.host}:{self.port}"

        return urlunparse(('http', netloc, self.path, '', '', ''))


class HookEventSerializer:
    """
    Serializes events into JSON-safe payloads for Hook IPC.

    Handles:
    - Extracting/filtering non-serializable objects via EXTRACTORS (exact) and
      EXTRACTOR_PREFIXES (prefix-based, for event families)
    - Converting values to JSON-safe format via makeJsonSafe
    """

    @staticmethod
    def extractShareLinkCreateEvent(eventData: dict) -> dict:
        extracted = {key: value for key, value in eventData.items() if key not in ('args', 'reader')}

        reader = eventData.get('reader')
        if not reader or not reader.supportManifest:
            return extracted

        extracted['manifest'] = reader.manifest
        return extracted

    @staticmethod
    def extractTypeValues(eventData: dict, key: str) -> dict:
        """Strip non-serializable objects from a named mapping, converting type objects to their name.

        Generic utility for events that carry a mapping (under `key`) where values may be
        class objects (types), lists of types, or plain scalars.  Non-serializable values
        that are not types are silently dropped.

        Use functools.partial to bind `key` when registering as an extractor:
            partial(HookEventSerializer.extractTypeValues, key='context')
        """
        mapping = eventData.get(key, {})
        safeMapping = {}
        for k, v in mapping.items():
            if isinstance(v, type):
                safeMapping[k] = v.__name__
            elif isinstance(v, list):
                safeMapping[k] = [item.__name__ if isinstance(item, type) else str(item) for item in v]
            elif isinstance(v, (str, int, float, bool, type(None))):
                safeMapping[k] = v
                
        return {key: safeMapping}

    @staticmethod
    def extractCliArgumentsEvent(eventData: dict) -> dict:
        """Strip ArgumentParser, Namespace, and function objects from /cli/arguments/* events."""
        result = {}
        for k, v in eventData.items():
            if k in ('parser', 'args'):
                continue
                
            if k == 'commandRegistry' and isinstance(v, dict):
                result[k] = {
                    name: {ck: cv for ck, cv in cmd.items() if ck != 'setupFunction'}
                    for name, cmd in v.items()
                    if isinstance(cmd, dict)
                }
            else:
                result[k] = v
                
        return result

    EXTRACTORS = {
        # Exact-match extractors keyed by Event instance
        FFLEvent.shareLinkCreate:
            lambda eventData: HookEventSerializer.extractShareLinkCreateEvent(eventData),
        FFLEvent.downloadStarted:
            lambda e: {k: v for k, v in e.items() if k not in ('request', 'handler', 'server')},
        FFLEvent.downloadProgress:
            lambda e: {k: v for k, v in e.items() if k not in ('progressObj', 'handler')},
        FFLEvent.downloadCompleted:
            lambda e: {k: v for k, v in e.items() if k not in ('handler', 'server')},
        FFLEvent.downloadFailed:
            lambda e: {k: v for k, v in e.items() if k not in ('exception', 'handler')},
        FFLEvent.webrtcConnected:
            lambda e: {k: v for k, v in e.items() if k not in ('peerConnection', 'dataChannel')},
        FFLEvent.webrtcTransferProgress:
            lambda e: {k: v for k, v in e.items() if k not in ('progressObj', 'dataChannel')},
        FFLEvent.webrtcTransferCompleted:
            lambda e: {k: v for k, v in e.items() if k not in ('peerConnection', 'dataChannel')},
        FFLEvent.errorOccurred:
            lambda e: {k: v for k, v in e.items() if k not in ('exception', 'stack')},
    }

    # Prefix-based extractors applied when no exact match is found.
    # Covers entire event families (e.g. all /cli/arguments/* events).
    # Addons can extend this via registerExtractorPrefix().
    EXTRACTOR_PREFIXES = {
        '/cli/arguments/': staticmethod(lambda e: HookEventSerializer.extractCliArgumentsEvent(e)),
    }

    @classmethod
    def registerExtractor(cls, event, extractor):
        """Register an extractor for an event type.

        Allows addons to register their own event extractors without modifying
        the base EXTRACTORS dict.

        Args:
            event:     Event instance (e.g., UploadEvent.uploadStarted)
            extractor: Callable(eventData: dict) -> dict
        """
        cls.EXTRACTORS[event] = extractor

    @classmethod
    def registerExtractorPrefix(cls, prefix: str, extractor):
        """Register a prefix-based extractor for an event family.

        Allows addons to handle entire event families without modifying Hook.py.

        Args:
            prefix:    Event name prefix (e.g., '/feature/class/')
            extractor: Callable(eventData: dict) -> dict
        """
        cls.EXTRACTOR_PREFIXES[prefix] = extractor

    @staticmethod
    def makeJsonSafe(value, keyPath: str = ''):
        """Convert value into JSON serializable data.

        Containers (dict/list/tuple/set) are handled structurally so that only
        the actual non-serializable leaf values produce a log message, including
        the full key path for easy identification.

        Args:
            value:   Value to make JSON-safe.
            keyPath: Dot-notation path used in log messages (e.g. '[/event].field.sub').
        """
        # Handle known container types structurally — no json.dumps probe needed.
        if isinstance(value, dict):
            return {
                str(k): HookEventSerializer.makeJsonSafe(v, f'{keyPath}.{k}' if keyPath else str(k))
                for k, v in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                HookEventSerializer.makeJsonSafe(v, f'{keyPath}[{i}]')
                for i, v in enumerate(value)
            ]

        if is_dataclass(value):
            return HookEventSerializer.makeJsonSafe(asdict(value), keyPath)

        if isinstance(value, Enum):
            return HookEventSerializer.makeJsonSafe(value.value, keyPath)

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return base64.b64encode(value).decode('ascii')

        # Scalar: attempt direct serialization, fall back to repr with location context.
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            location = f" at '{keyPath}'" if keyPath else ''
            logger.debug(
                "Non-serializable value%s: %s — falling back to repr()",
                location, type(value).__name__
            )
            return repr(value)

    @staticmethod
    def serialize(eventName: str, eventData: dict = None) -> dict:
        """Serialize event into JSON-safe payload.

        Args:
            eventName: Event name (e.g., '/server/ready')
            eventData: Event data dictionary

        Returns:
            dict: {'event': eventName, 'timestamp': ISO8601, 'data': {...}}
        """
        eventData = eventData or {}

        # Exact-match extractor first, then prefix-based fallback.
        extractor = HookEventSerializer.EXTRACTORS.get(Event(eventName))
        if extractor is None:
            for prefix, prefixExtractor in HookEventSerializer.EXTRACTOR_PREFIXES.items():
                if eventName.startswith(prefix):
                    extractor = prefixExtractor
                    break

        if extractor:
            extracted = extractor(eventData)
            eventData = extracted if extracted is not None else {}

        safeData = HookEventSerializer.makeJsonSafe(eventData, keyPath=f'[{eventName}]')

        logger.debug("Sent event: %s", eventName)

        return {
            'event': eventName,
            'timestamp': datetime.now().isoformat(),
            'data': safeData
        }


class HookFileWriter:
    """
    Writes Hook events to a JSONL file.

    Example:
        writer = HookFileWriter('/path/to/events.jsonl')
        writer.sendEvent('/server/ready', {'url': 'http://...'})
        writer.close()
    """

    def __init__(self, filePath: str):
        """
        Initialize file writer.

        Args:
            filePath: Path to JSONL output file
        """
        self.filePath = filePath
        self._file = open(filePath, 'a', encoding='utf-8')
        self._lock = threading.Lock()

    def sendEvent(self, eventName: str, eventData: dict = None):
        """
        Write event to JSONL file.

        Args:
            eventName: Event name (e.g., '/server/ready')
            eventData: Event data dictionary
        """
        payload = HookEventSerializer.serialize(eventName, eventData)

        with self._lock:
            if self._file is None:
                return

            self._file.write(json.dumps(payload) + '\n')
            self._file.flush()

        logger.debug(f"Wrote event to file: {eventName}")

    def close(self):
        """Close the file."""
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class HookClient:
    """
    HTTP webhook client for sending events.

    Example:
        with HookClient('http://app:token@127.0.0.1:12345/events') as client:
            client.sendEvent('/server/ready', {'url': 'http://...'})
    """

    EVENT_ENDPOINTS_REGISTER = '/hook/server/endpoints/register'
    EVENT_ENDPOINT_REQUEST = '/hook/server/request'

    @staticmethod
    def parseHookURL(hookURL: str) -> dict:
        """
        Parse webhook URL.

        Format: http://[username:password@]host:port/path
                https://[username:password@]host:port/path

        Args:
            hookURL: Webhook URL string

        Returns:
            dict: {
                'url': str,           # Full URL with auth
                'scheme': str,        # http or https
                'host': str,          # hostname
                'port': int,          # port number
                'path': str,          # URL path
                'username': str|None, # username for auth (optional)
                'password': str|None  # password for auth (optional)
            }

        Raises:
            ValueError: If URL format is invalid
        """
        if not hookURL:
            raise ValueError("Hook URL cannot be empty")

        parsed = urlparse(hookURL)

        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid scheme '{parsed.scheme}' (expected http or https): {hookURL}")

        if not parsed.hostname:
            raise ValueError(f"Missing hostname in URL: {hookURL}")

        # Extract port (use default if not specified)
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == 'https' else 80

        # Extract path (default to '/')
        path = parsed.path if parsed.path else '/'

        return {
            'url': hookURL,
            'scheme': parsed.scheme,
            'host': parsed.hostname,
            'port': port,
            'path': path,
            'username': parsed.username,
            'password': parsed.password
        }

    def __init__(self, hookURL: str):
        """
        Initialize webhook client.

        Args:
            hookURL: Webhook URL (format: http://[user:pass@]host:port/path)
        """
        self.config = HookClient.parseHookURL(hookURL)
        self.hookURL = hookURL

    def _getAuth(self):
        if self.config['username'] and self.config['password']:
            return (self.config['username'], self.config['password'])
        return None

    def _postPayload(self, payload: dict, timeout: float = 10.0):
        try:
            response = requests.post(self.hookURL, json=payload, auth=self._getAuth(), timeout=timeout)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send hook payload: {e}")
            raise HookError(f"Request failed: {e}")

        if response.status_code == 401:
            raise HookAuthError("Authentication failed")
        if response.status_code != 200:
            raise HookError(f"Server returned status {response.status_code}: {response.text}")

        return response

    def sendEvent(self, eventName: str, eventData: dict = None, timeout: float = 10.0, expectResponse: bool = False):
        """
        Send event to webhook server.

        Args:
            eventName: Event name (e.g., '/server/ready')
            eventData: Event data dictionary
            timeout: Request timeout in seconds
            expectResponse: Parse and return JSON response payload when True

        Raises:
            HookError: If request fails
        """
        payload = HookEventSerializer.serialize(eventName, eventData)
        response = self._postPayload(payload, timeout=timeout)

        if not expectResponse:
            return None

        try:
            responsePayload = response.json()
        except json.JSONDecodeError as e:
            raise HookError(f"Hook response is not valid JSON: {e}")

        if not isinstance(responsePayload, dict):
            raise HookError("Hook response must be a JSON object")

        logger.debug("Received response for event: %s", eventName)
        return responsePayload

    def registerServerEndpoints(self, serverContext: dict, timeout: float = 5.0) -> list:
        response = self.sendEvent(
            HookClient.EVENT_ENDPOINTS_REGISTER, serverContext, timeout=timeout, expectResponse=True
        )

        routes = response.get('routes')
        if routes is None:
            data = response.get('data')
            if isinstance(data, dict):
                routes = data.get('routes')

        if routes is None:
            return []

        if not isinstance(routes, list):
            raise HookError("Hook endpoint registration response requires 'routes' as a list")

        return routes

    def dispatchServerRequest(self, requestData: dict, timeout: float = 10.0) -> dict:
        return self.sendEvent(HookClient.EVENT_ENDPOINT_REQUEST, requestData, timeout=timeout, expectResponse=True)


class HookEndpointRouter:
    ALLOWED_METHODS = {'GET', 'POST', 'HEAD'}
    BLOCKED_RESPONSE_HEADERS = {
        'content-length', 'content-encoding', 'connection', 'transfer-encoding', 'server', 'date'
    }

    @classmethod
    def _normalizeRoute(cls, route: dict) -> Optional[dict]:
        if not isinstance(route, dict):
            return None

        method = route.get('method')
        path = route.get('path')

        if not isinstance(method, str) or not isinstance(path, str):
            return None

        method = method.strip().upper()
        path = path.strip()

        if method not in cls.ALLOWED_METHODS:
            return None

        if not path.startswith('/') or '?' in path or '*' in path:
            return None

        return {'method': method, 'path': path, 'encryptResponse': bool(route.get('encryptResponse', False))}

    @classmethod
    def _fetchRoutes(cls, server, hookClient: HookClient) -> list:
        context = {
            'uid': server.uid,
            'domain': server.domain,
            'port': server.server_address[1],
            'authEnabled': bool(server.config.authPassword),
            'defaultWebRTC': bool(server.config.defaultWebRTC),
            'e2eeEnabled': bool(server.config.e2eeEnabled),
            'torEnabled': bool(server.config.torEnabled),
            'fileName': server.reader.contentName,
            'fileSize': server.reader.size,
        }

        routes = []
        try:
            registered = hookClient.registerServerEndpoints(context)
            for route in registered:
                normalized = cls._normalizeRoute(route)
                if normalized:
                    routes.append(normalized)
                else:
                    logger.warning(f"Ignored invalid hook endpoint route: {route}")
        except Exception as e:
            logger.warning(f"Hook endpoint registration failed: {e}")

        return routes

    @staticmethod
    def _computeStreamId(path: str, args) -> str:
        """Derive a stable stream ID from a hook endpoint path and its query args.

        If a 'hash' query parameter is present it is appended so that different
        resources served from the same path get distinct tag namespaces.

        Examples:
            /thumb?hash=abc  → "thumb/abc"
            /file?hash=abc   → "file/abc"
            /manifest        → "manifest"
        """
        pathSegment = path.lstrip('/')
        hashValue = None
        if args:
            hashList = args.get('hash')
            if hashList:
                hashValue = hashList[0] if isinstance(hashList, list) else hashList
        if hashValue:
            return f"{pathSegment}/{hashValue}"
        return pathSegment

    @classmethod
    def _encryptAndSendHookResponse(cls, handler, data: bytes, streamId: str, contentType: str):
        """Encrypt hook response data with the server's E2EE manager and send to client."""
        originalSize = len(data)
        e2eeManager = handler.server.e2eeManager
        encryptor = e2eeManager.createEncryptor(
            filename=streamId,
            filesize=originalSize,
            startChunkIndex=0,
            saveTags=True,
            streamId=streamId,
        )
        chunkSize = e2eeManager.chunkSize
        encryptedChunks = []
        offset = 0
        while offset < originalSize:
            chunk = data[offset:offset + chunkSize]
            encryptedChunks.append(encryptor.encryptChunk(chunk))
            offset += chunkSize
        encryptedData = b''.join(encryptedChunks)

        handler.send_response(HTTPStatus.OK)
        handler.send_header('Content-Type', contentType)
        handler.send_header('Content-Length', str(len(encryptedData)))
        handler.send_header('Cache-Control', 'no-cache')
        handler.end_headers()
        handler.wfile.write(encryptedData)

    @staticmethod
    def _buildProxyURL(hookClient: HookClient, path: str, args=None) -> str:
        scheme = hookClient.config['scheme']
        host = hookClient.config['host']
        port = hookClient.config['port']
        defaultPort = 443 if scheme == 'https' else 80
        netloc = f'{host}:{port}' if port != defaultPort else host
        query = urlencode(args or {}, doseq=True)
        return urlunparse((scheme, netloc, path, '', query, ''))

    @staticmethod
    def _buildForwardHeaders(handler):
        blockedRequestHeaders = {'host', 'content-length', 'connection', 'transfer-encoding'}
        headers = {}
        for key in handler.headers:
            if key.lower() in blockedRequestHeaders:
                continue
            headers[key] = handler.headers.get(key)

        # Keep upstream response body/headers consistent by disabling compression.
        headers['Accept-Encoding'] = 'identity'
        return headers

    @classmethod
    def _sendProxyResponse(cls, handler, method: str, response: requests.Response):
        status = response.status_code
        body = b'' if method == 'HEAD' else response.content

        if status in (204, 304):
            body = b''

        handler.send_response(status)

        for key, value in response.headers.items():
            lower = key.lower()
            if lower in cls.BLOCKED_RESPONSE_HEADERS:
                continue

            strValue = str(value)
            if '\r' in key or '\n' in key or '\r' in strValue or '\n' in strValue:
                continue

            handler.send_header(key, strValue)

        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()

        if method != 'HEAD' and body:
            handler.wfile.write(body)

    @classmethod
    def _proxyRequest(
        cls,
        handler,
        hookClient: HookClient,
        method: str,
        path: str,
        args=None,
        body=None,
        encryptResponse: bool = False
    ):
        try:
            url = cls._buildProxyURL(hookClient, path, args=args)
            requestHeaders = cls._buildForwardHeaders(handler)

            requestArgs = {
                'url': url,
                'headers': requestHeaders,
                'auth': hookClient._getAuth(),
                'timeout': 10.0,
                'allow_redirects': False,
            }

            if method == 'POST':
                requestArgs['json'] = HookEventSerializer.makeJsonSafe(body if body is not None else {})

            response = requests.request(method, **requestArgs)

            serverObj = getattr(handler, 'server', None)
            e2eeManager = getattr(serverObj, 'e2eeManager', None)
            e2eeEnabled = getattr(getattr(serverObj, 'config', None), 'e2eeEnabled', False)

            if (
                encryptResponse and method != 'HEAD' and response.status_code == 200 and e2eeManager is not None and
                e2eeEnabled
            ):
                streamId = cls._computeStreamId(path, args)
                contentType = response.headers.get('Content-Type', 'application/octet-stream')
                cls._encryptAndSendHookResponse(handler, response.content, streamId, contentType)
            else:
                cls._sendProxyResponse(handler, method, response)
        except requests.exceptions.RequestException as e:
            handler.send_error(502, f'Hook endpoint request failed: {e}')
        except Exception as e:
            logger.exception(f"Unexpected hook proxy error: {e}")
            handler.send_error(502, "Hook endpoint request failed")

    @classmethod
    def registerForHandler(cls, handler, server, hookClient: HookClient, getPathMap, postPathMap, headPathMap):
        routes = cls._fetchRoutes(server, hookClient)
        for route in routes:
            method = route['method']
            path = route['path']
            encryptResp = route.get('encryptResponse', False)

            if method == 'GET':
                getPathMap[path] = (
                    lambda args, _path=path, _enc=encryptResp: cls.
                    _proxyRequest(handler, hookClient, 'GET', _path, args=args, encryptResponse=_enc)
                )
                headPathMap[path] = (lambda _path=path: cls._proxyRequest(handler, hookClient, 'HEAD', _path, args={}))
            elif method == 'POST':
                postPathMap[path] = (
                    lambda data, _path=path, _enc=encryptResp: cls.
                    _proxyRequest(handler, hookClient, 'POST', _path, body=data, encryptResponse=_enc)
                )
            elif method == 'HEAD':
                headPathMap[path] = (lambda _path=path: cls._proxyRequest(handler, hookClient, 'HEAD', _path))


def registerHookEndpointsForHandler(handler, server, hookClient: HookClient, getPathMap, postPathMap, headPathMap):
    HookEndpointRouter.registerForHandler(
        handler=handler,
        server=server,
        hookClient=hookClient,
        getPathMap=getPathMap,
        postPathMap=postPathMap,
        headPathMap=headPathMap
    )


_hookResponseHandlers: dict = {}


def registerHookResponseHandler(eventName: str, handler, timeout: float = 10.0) -> None:
    """Register a response handler for a specific event forwarded via hook.

    When a HookClient forwards an event that has a registered handler, the event
    is sent with expectResponse=True and the handler is called with the response.
    For HookFileWriter senders the event is always fire-and-forget regardless.

    Handler signature: handler(hookSender: HookClient, eventData: dict, response: dict) -> None

    Args:
        eventName: Event name key (e.g. UploadEvent.uploadTell.key)
        handler:   Callable invoked with (hookSender, eventData, response)
        timeout:   Response wait timeout in seconds for HookClient request/response mode
    """
    _hookResponseHandlers[eventName] = {'handler': handler, 'timeout': timeout}


def forwardEventToHook(hookSender, eventName, **eventData):
    if eventName == FFLEvent.serverEndpointsRegister.key:
        if isinstance(hookSender, HookClient):
            registerHookEndpointsForHandler(
                handler=eventData['handler'],
                server=eventData['server'],
                hookClient=hookSender,
                getPathMap=eventData['getPathMap'],
                postPathMap=eventData['postPathMap'],
                headPathMap=eventData['headPathMap']
            )
        return

    responseHandlerSpec = _hookResponseHandlers.get(eventName)
    if responseHandlerSpec and isinstance(hookSender, HookClient):
        response = hookSender.sendEvent(
            eventName, eventData, expectResponse=True, timeout=responseHandlerSpec.get('timeout', 10.0)
        )
        responseHandlerSpec['handler'](hookSender, eventData, response or {})
    else:
        hookSender.sendEvent(eventName, eventData)
