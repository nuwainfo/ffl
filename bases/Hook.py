#!/usr/bin/env python
# -*- coding: utf-8 -*-
# $Id$
#
# Copyright (c) 2026 Nuwa Information Co., Ltd, All Rights Reserved.
#
# Licensed under the Proprietary License,
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at our web site.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Author: Bear $
# $Date: 2026-01-10 23:42:45 +0800 (週六, 10 一月 2026) $
# $Revision: 18427 $
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

from urllib.parse import urlparse, urlunparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import requests

from bases.Kernel import getLogger, FFLEvent, Event

logger = getLogger(__name__)


class HookError(Exception):
    """Base exception for Hook-related errors."""
    pass


class HookAuthError(HookError):
    """Authentication error."""
    pass


class HookRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for webhook server."""

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"Hook request: {format % args}")

    def do_POST(self):
        """Handle POST request with event data."""
        # Check if authentication is required
        if self.server.username and self.server.password:
            # Verify HTTP Basic Auth
            authHeader = self.headers.get('Authorization')
            if not authHeader or not self._checkAuth(authHeader):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Hook Server"')
                self.end_headers()
                logger.warning(f"Unauthorized hook request from {self.client_address[0]}")
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

    def _checkAuth(self, authHeader: str) -> bool:
        """
        Check HTTP Basic Auth header.

        Args:
            authHeader: Authorization header value

        Returns:
            bool: True if authentication is valid
        """
        if not authHeader.startswith('Basic '):
            return False

        try:
            # Decode base64 credentials
            encodedCredentials = authHeader[6:] # Remove 'Basic '
            decodedCredentials = base64.b64decode(encodedCredentials).decode('utf-8')
            username, password = decodedCredentials.split(':', 1)

            return (username == self.server.username and password == self.server.password)
        except Exception as e:
            logger.debug(f'_checkAuth error: {str(e)}')
            return False


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


HOOK_EXTRACTORS = {
    FFLEvent.shareLinkCreate: lambda e: {
        k: v for k, v in e.items() if k not in ('args', 'reader')
    },
}


class HookClient:
    """
    HTTP webhook client for sending events.

    Example:
        client = HookClient('http://app:token@127.0.0.1:12345/events')
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

    @staticmethod
    def makeJsonSafe(value):
        """
        Convert value into JSON serializable data.
        Any non-serializable value will be converted to repr().
        """
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            logger.debug('Unable to json.dumps {value=} skip')

        if is_dataclass(value):
            return HookClient.makeJsonSafe(asdict(value))

        if isinstance(value, Enum):
            return HookClient.makeJsonSafe(value.value)

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, dict):
            return {str(k): HookClient.makeJsonSafe(v) for k, v in value.items()}

        if isinstance(value, (list, tuple, set)):
            return [HookClient.makeJsonSafe(v) for v in value]

        return repr(value)

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
        eventData = eventData or {}

        extractor = HOOK_EXTRACTORS.get(Event(eventName))
        if extractor:
            extracted = extractor(eventData)
            if extracted is not None:
                eventData = extracted
            else:
                eventData = {}

        payload = {'event': eventName, 'data': HookClient.makeJsonSafe(eventData)}

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
