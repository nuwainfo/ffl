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

import json
import secrets
import threading

from dataclasses import is_dataclass, asdict
from datetime import datetime, date
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from urllib.parse import urlparse, urlunparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import requests

from bases.Kernel import getLogger, FFLEvent, Event
from bases.Server import AuthMixin, HTTPAuth

logger = getLogger(__name__)


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
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Empty request body"}')
            return

        try:
            requestBody = self.rfile.read(contentLength)
            data = json.loads(requestBody.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'Invalid JSON: {e}'}).encode('utf-8'))
            logger.warning(f"Invalid JSON from {self.client_address[0]}: {e}")
            return

        # Extract event name and data
        eventName = data.get('event')
        eventData = data.get('data', {})

        if not eventName:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Missing event field"}')
            logger.warning(f"Missing event field from {self.client_address[0]}")
            return

        # Call event handler
        if self.server.onEvent:
            try:
                self.server.onEvent(eventName, eventData)
            except Exception as e:
                logger.error(f"Error in event handler for {eventName}: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({'error': f'Handler error: {e}'}).encode('utf-8'))
                return

        # Send success response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')


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
    - Extracting/filtering non-serializable objects via HOOK_EXTRACTORS
    - Converting values to JSON-safe format via makeJsonSafe
    """

    EXTRACTORS = {
        # Remove non-serializable objects from events
        FFLEvent.shareLinkCreate:
            lambda e: {
                k: v for k, v in e.items() if k not in ('args', 'reader')
            },
        FFLEvent.downloadStarted:
            lambda e: {
                k: v for k, v in e.items() if k not in ('request', 'handler', 'server')
            },
        FFLEvent.downloadProgress:
            lambda e: {
                k: v for k, v in e.items() if k not in ('progressObj', 'handler')
            },
        FFLEvent.downloadCompleted:
            lambda e: {
                k: v for k, v in e.items() if k not in ('handler', 'server')
            },
        FFLEvent.downloadFailed:
            lambda e: {
                k: v for k, v in e.items() if k not in ('exception', 'handler')
            },
        FFLEvent.uploadStarting:
            lambda e: {
                k: v for k, v in e.items() if k not in ('reader', 'uploadMethod')
            },
        FFLEvent.uploadStarted:
            lambda e: {
                k: v for k, v in e.items() if k not in ('reader', 'uploadMethod')
            },
        FFLEvent.uploadProgress:
            lambda e: {
                k: v for k, v in e.items() if k not in ('progressObj', 'uploadMethod', 'reader')
            },
        FFLEvent.uploadCompleted:
            lambda e: {
                k: v for k, v in e.items() if k not in ('uploadMethod', 'reader', 'response')
            },
        FFLEvent.uploadFailed:
            lambda e: {
                k: v for k, v in e.items() if k not in ('exception', 'uploadMethod')
            },
        FFLEvent.webrtcConnected:
            lambda e: {
                k: v for k, v in e.items() if k not in ('peerConnection', 'dataChannel')
            },
        FFLEvent.webrtcTransferProgress:
            lambda e: {
                k: v for k, v in e.items() if k not in ('progressObj', 'dataChannel')
            },
        FFLEvent.webrtcTransferCompleted:
            lambda e: {
                k: v for k, v in e.items() if k not in ('peerConnection', 'dataChannel')
            },
        FFLEvent.errorOccurred:
            lambda e: {
                k: v for k, v in e.items() if k not in ('exception', 'stack')
            },
    }

    @staticmethod
    def makeJsonSafe(value):
        """
        Convert value into JSON serializable data.
        Any non-serializable value will be converted to repr().
        """
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError) as e:
            logger.debug(f"Value not directly JSON-serializable, converting: {type(value).__name__} - {e}")

        if is_dataclass(value):
            return HookEventSerializer.makeJsonSafe(asdict(value))

        if isinstance(value, Enum):
            return HookEventSerializer.makeJsonSafe(value.value)

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, dict):
            return {str(k): HookEventSerializer.makeJsonSafe(v) for k, v in value.items()}

        if isinstance(value, (list, tuple, set)):
            return [HookEventSerializer.makeJsonSafe(v) for v in value]

        return repr(value)

    @staticmethod
    def serialize(eventName: str, eventData: dict = None) -> dict:
        """
        Serialize event into JSON-safe payload.

        Args:
            eventName: Event name (e.g., '/server/ready')
            eventData: Event data dictionary

        Returns:
            dict: {'event': eventName, 'timestamp': ISO8601, 'data': {...}}
        """
        eventData = eventData or {}

        extractor = HookEventSerializer.EXTRACTORS.get(Event(eventName))
        if extractor:
            extracted = extractor(eventData)
            if extracted is not None:
                eventData = extracted
            else:
                eventData = {}

        return {
            'event': eventName,
            'timestamp': datetime.now().isoformat(),
            'data': HookEventSerializer.makeJsonSafe(eventData)
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

    def sendEvent(self, eventName: str, eventData: dict = None):
        """
        Send event to webhook server.

        Args:
            eventName: Event name (e.g., '/server/ready')
            eventData: Event data dictionary

        Raises:
            HookError: If request fails
        """
        payload = HookEventSerializer.serialize(eventName, eventData)

        try:
            # Prepare auth if credentials provided
            auth = None
            if self.config['username'] and self.config['password']:
                auth = (self.config['username'], self.config['password'])

            # Send POST request
            response = requests.post(self.hookURL, json=payload, auth=auth, timeout=10.0)

            # Check response
            if response.status_code == 401:
                raise HookAuthError("Authentication failed")
            elif response.status_code != 200:
                raise HookError(f"Server returned status {response.status_code}: {response.text}")

            logger.debug(f"Sent event: {eventName}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send event {eventName}: {e}")
            raise HookError(f"Request failed: {e}")
