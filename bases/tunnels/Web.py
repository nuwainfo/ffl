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

"""WebSocket client for the HTTPS-only Web tunnel.

The public side remains ordinary HTTPS.  This module implements only the
agent-to-relay connection and deliberately keeps the implementation
stdlib-only so this transport does not add another runtime dependency.
"""

import asyncio
import base64
import http.client
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import urllib.parse


from bases.Kernel import getLogger

from . import _receiveExactly, Socks5ProxySupport


logger = getLogger(__name__)

class WebTunnelConfigurationError(ValueError):
    """Raised when the Web tunnel environment is incomplete or invalid."""


class _RawHTTPResponse:
    """HTTP response metadata plus a decoded HTTP entity-body reader.

    The tunnel deliberately has no knowledge of the application protocol above
    HTTP.  It does, however, have to decode HTTP transfer codings because the
    relay receives an entity body, not the origin's chunk framing.
    """

    def __init__(self, sock):
        self._sock = sock
        packet = bytearray()
        while b'\r\n\r\n' not in packet:
            packet.extend(sock.recv(4096))
            if len(packet) > 64 * 1024:
                raise ConnectionError('Local HTTP response headers are too large')
                
        rawHeaders, self._pendingBody = bytes(packet).split(b'\r\n\r\n', 1)
        statusLine, *headerLines = rawHeaders.decode('iso-8859-1').split('\r\n')
        parts = statusLine.split(' ', 2)
        if len(parts) < 2 or not parts[0].startswith('HTTP/'):
            raise ConnectionError(f'Invalid local HTTP response: {statusLine}')
            
        self.status = int(parts[1])
        self._headers = [tuple(line.split(':', 1)) for line in headerLines if ':' in line]
        
        transferEncoding = ','.join(
            value for name, value in self._headers if name.strip().lower() == 'transfer-encoding'
        ).lower()        
        self._chunked = 'chunked' in transferEncoding
        self._chunkRemaining = 0
        self._chunkComplete = False

    def getheaders(self):
        return [(name.strip(), value.strip()) for name, value in self._headers]

    def read(self, size):
        if self._chunked:
            return self._readChunked(size)
            
        return self._readPlain(size)

    def _readPlain(self, size):
        """Match ``HTTPResponse.read(size)``: fill the requested read or EOF."""
        data = bytearray()
        if self._pendingBody:
            data.extend(self._pendingBody[:size])
            self._pendingBody = self._pendingBody[len(data):]
            
        while len(data) < size:
            packet = self._sock.recv(size - len(data))
            if not packet:
                break
                
            data.extend(packet)
            
        return bytes(data)

    def _receive(self, size):
        while len(self._pendingBody) < size:
            data = self._sock.recv(max(4096, size - len(self._pendingBody)))
            if not data:
                raise ConnectionError('Local HTTP response ended inside chunked transfer encoding')
                
            self._pendingBody += data
            
        data, self._pendingBody = self._pendingBody[:size], self._pendingBody[size:]
        
        return data

    def _readChunkLine(self):
        while b'\r\n' not in self._pendingBody:
            data = self._sock.recv(4096)
            if not data:
                raise ConnectionError('Local HTTP response ended inside chunked transfer encoding')
                
            self._pendingBody += data
            
        line, self._pendingBody = self._pendingBody.split(b'\r\n', 1)
        
        return line

    def _readChunked(self, size):
        if self._chunkComplete:
            return b''
            
        data = bytearray()
        while len(data) < size:
            if self._chunkRemaining == 0:
                chunkLine = self._readChunkLine().split(b';', 1)[0].strip()
                
                try:
                    self._chunkRemaining = int(chunkLine, 16)
                except ValueError as e:
                    raise ConnectionError('Local HTTP response has an invalid chunk size') from e
                    
                if self._chunkRemaining == 0:
                    while self._readChunkLine():
                        pass
                        
                    self._chunkComplete = True
                    return bytes(data)
                    
            readSize = min(size - len(data), self._chunkRemaining)
            data.extend(self._receive(readSize))
            self._chunkRemaining -= readSize
            
            if self._chunkRemaining == 0 and self._receive(2) != b'\r\n':
                raise ConnectionError('Local HTTP response has an invalid chunk terminator')
                
        return bytes(data)


class _WebSocketConnection:
    """Minimal RFC 6455 binary client used by :class:`WebTunnelClient`."""

    # Precomputed per-byte XOR tables, one per possible mask-byte value. Masking a
    # payload one Python-level `value ^ mask[i % 4]` at a time is the dominant cost
    # on large DATA frames; bytes.translate() runs the substitution in C instead.
    _XOR_TABLES = tuple(bytes(value ^ key for value in range(256)) for key in range(256))

    def __init__(self, sock):
        self.sock = sock
        self._sendLock = threading.Lock()

    @classmethod
    def _maskPayload(cls, payload, mask):
        """XOR `payload` against the 4-byte `mask`, repeating per RFC 6455 §5.3."""
        result = bytearray(payload)
        for offset, key in enumerate(mask):
            result[offset::4] = result[offset::4].translate(cls._XOR_TABLES[key])
            
        return bytes(result)

    def sendBinary(self, data):
        self._sendFrame(0x2, data)

    def sendPong(self, data=b''):
        self._sendFrame(0xA, data)

    def sendPing(self, data=b''):
        self._sendFrame(0x9, data)

    def close(self, graceful=True):
        """Args:
            graceful: Send a WebSocket close frame first. Skip this when
                reacting to a receive error or network drop -- the socket is
                already broken, so sendall() for the close frame has nothing
                to do but wait out its own timeout before cleanup/reconnect
                can proceed.
        """
        sock = self.sock
        if not sock:
            return

        if graceful:
            try:
                self._sendFrame(0x8, b'')
            except Exception as e:
                logger.debug('Failed to send Web tunnel close frame (socket likely already broken): %s', e)

        self.sock = None

        try:
            sock.close()
        except OSError as e:
            logger.debug('Failed to close Web tunnel socket (likely already closed): %s', e)

    def _sendFrame(self, opcode, data):
        if not self.sock:
            raise ConnectionError('Web tunnel WebSocket is closed')
            
        payload = bytes(data)
        payloadLength = len(payload)
        header = bytearray((0x80 | opcode, 0x80))
        if payloadLength < 126:
            header[1] |= payloadLength
        elif payloadLength <= 0xffff:
            header[1] |= 126
            header.extend(struct.pack('!H', payloadLength))
        else:
            header[1] |= 127
            header.extend(struct.pack('!Q', payloadLength))
            
        mask = secrets.token_bytes(4)
        maskedPayload = self._maskPayload(payload, mask)
        with self._sendLock:
            # Two writes instead of one concatenated buffer: WebSocket framing
            # doesn't require a frame to land in a single TCP segment, and this
            # avoids one more full-payload copy on large DATA frames.
            self.sock.sendall(bytes(header) + mask)
            self.sock.sendall(maskedPayload)

    def receive(self):
        """Return ``(opcode, payload)``. Server messages must be unfragmented."""
        first, second = _receiveExactly(self.sock, 2)
        if not first & 0x80:
            raise ConnectionError('Fragmented Web tunnel WebSocket messages are unsupported')
            
        opcode = first & 0x0f
        masked = bool(second & 0x80)
        length = second & 0x7f
        if length == 126:
            length = struct.unpack('!H', _receiveExactly(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack('!Q', _receiveExactly(self.sock, 8))[0]
            
        if length > 32 * 1024 * 1024:
            raise ConnectionError('Web tunnel WebSocket frame is too large')
            
        mask = _receiveExactly(self.sock, 4) if masked else None
        payload = _receiveExactly(self.sock, length)
        if mask:
            payload = self._maskPayload(payload, mask)

        return opcode, payload


class WebTunnelClient(Socks5ProxySupport):
    """Relays a localhost HTTP server through one multiplexed WebSocket."""

    _PROTOCOL_VERSION = 1
    _OPEN = 1
    _RESPONSE = 2
    _DATA = 3
    _END = 4
    _RESET = 5
    _WINDOW_UPDATE = 6
    _PING = 7
    _PONG = 8
    _FRAME_HEADER = struct.Struct('!BBII')
    # Must match the relay's own initial window -- a hardcoded protocol
    # constant assumed identically by both sides, not negotiated at connect time.
    _INITIAL_WINDOW = 4 * 1024 * 1024
    _MAX_FRAME_DATA = 1024 * 1024
    
    _HOP_BY_HOP_HEADERS = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade',
    })

    def __init__(self, localPort, agentURL, publicURL, secret, tunnelID, chunkSize=None, proxyConfig=None, tokenProvider=None):
        self.localPort = localPort
        self.agentURL = self._normalizeBaseURL(agentURL)
        self.publicURL = self._normalizeBaseURL(publicURL)
        self.secret = secret
        self.tokenProvider = tokenProvider
        self._skipInitialRefresh = self.secret is not None
        
        # This is an opaque routing key.  The transport neither creates nor
        # interprets it; applications may use a UID, a URL-encoded alias, or
        # any other header-safe identifier.
        self.shareUID = tunnelID
        self.chunkSize = min(chunkSize or self._getChunkSize(), self._MAX_FRAME_DATA)
        self.proxyConfig = proxyConfig
        self.remoteHost = urllib.parse.urlparse(self.agentURL).hostname or 'Web'
        self.lastConnectError = None
        self.running = False # should this client keep trying to connect/reconnect
        self.connected = False # is the current WebSocket actually live right now
        
        self._webSocket = None
        self._webSocketLock = threading.Lock()
        self._heartbeatStop = threading.Event()
        self._heartbeatThread = None
        self._activeConnections = {}
        self._sendWindows = {}
        self._connectionsLock = threading.Lock()
        self._windowChanged = threading.Condition(self._connectionsLock)

        # Incremented on every successful connect(). A fast disconnect/reconnect
        # can leave a _relayRequest thread from the old WebSocket still running
        # (blocked in local I/O) after a new OPEN for the same streamID has
        # already been dispatched under the new connection; every request
        # thread captures the generation active when it started and checks it
        # before touching shared per-stream state, so a stale thread can't
        # clobber or cancel a newer one.
        self._connectionGeneration = 0

        self._validateConfiguration()

    @staticmethod
    def _normalizeBaseURL(url):
        if not url:
            return url
            
        return url if url.endswith('/') else f'{url}/'

    @classmethod
    def _getChunkSize(cls):
        value = os.getenv('FFL_WEB_TUNNEL_CHUNK_SIZE', str(1024 * 1024))
        try:
            chunkSize = int(value)
        except ValueError as e:
            raise WebTunnelConfigurationError('FFL_WEB_TUNNEL_CHUNK_SIZE must be an integer') from e
            
        if chunkSize < 1 or chunkSize > cls._MAX_FRAME_DATA:
            raise WebTunnelConfigurationError(
                'FFL_WEB_TUNNEL_CHUNK_SIZE must be between 1 and 1048576 bytes'
            )
        
        return chunkSize

    def _validateConfiguration(self):
        missingNames = []
        
        if not self.agentURL:
            missingNames.append('FFL_WEB_TUNNEL_AGENT_URL')
            
        if not self.publicURL:
            missingNames.append('FFL_WEB_TUNNEL_PUBLIC_URL')
            
        if not self.secret:
            missingNames.append('tunnel token')
            
        if not self.shareUID:
            missingNames.append('tunnel ID')
            
        if missingNames:
            raise WebTunnelConfigurationError(
                f"Missing Web tunnel environment variable(s): {', '.join(missingNames)}"
            )
        
        for name, url in (('FFL_WEB_TUNNEL_AGENT_URL', self.agentURL),
                          ('FFL_WEB_TUNNEL_PUBLIC_URL', self.publicURL)):
            parts = urllib.parse.urlparse(url)
            if parts.scheme != 'https' or not parts.netloc:
                raise WebTunnelConfigurationError(f'{name} must be an HTTPS URL')
                
        if not self._isValidTunnelID(self.shareUID):
            raise WebTunnelConfigurationError('tunnel ID must be a visible ASCII header value')

    @staticmethod
    def _isValidTunnelID(tunnelID):
        return bool(tunnelID) and len(tunnelID) <= 1024 and all(
            0x21 <= ord(character) <= 0x7e for character in tunnelID
        )

    def getTunnelURL(self):
        return self.publicURL

    async def connect(self):
        try:
            await asyncio.to_thread(self._refreshSecret)
            await asyncio.to_thread(self._connectWebSocket)
            return True
        except Exception as e:
            self.lastConnectError = e
            return False

    def _refreshSecret(self):
        if not callable(self.tokenProvider):
            return

        if self._skipInitialRefresh:
            self._skipInitialRefresh = False
            return

        newSecret = self.tokenProvider()
        if not newSecret:
            logger.warning('Token provider returned empty token; keeping existing token')
            return

        if newSecret != self.secret:
            logger.info('Web tunnel token refreshed')
            
        self.secret = newSecret

    def _connectWebSocket(self):
        # graceful=False: whatever the previous self._webSocket was is being
        # torn down specifically because we're about to replace it -- most
        # likely because it's already stale/broken, same reasoning as
        # listen()'s finally block below.
        self._closeWebSocket(graceful=False)


        parsedURL = urllib.parse.urlparse(urllib.parse.urljoin(self.agentURL, '_tunnel/agent/connect'))
        rawSocket = self._connectSocket(parsedURL, timeout=30)
        try:
            key = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            path = parsedURL.path or '/'
            if parsedURL.query:
                path = f'{path}?{parsedURL.query}'
                
            host = parsedURL.netloc
            request = (
                f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n'
                'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Key: {key}\r\nAuthorization: Bearer {self.secret}\r\n'
                f'X-FFL-Share-UID: {self.shareUID}\r\n\r\n'
            )
        
            rawSocket.sendall(request.encode('ascii'))
            responseHead = self._receiveHTTPHeaders(rawSocket)
            statusLine, *headerLines = responseHead.decode('iso-8859-1').split('\r\n')
            
            if not statusLine.startswith('HTTP/') or ' 101 ' not in f' {statusLine} ':
                raise ConnectionError(f'Web tunnel WebSocket upgrade failed: {statusLine}')
                
            headers = {
                name.strip().lower(): value.strip()
                for line in headerLines if ':' in line
                for name, value in [line.split(':', 1)]
            }
        
            expectedAccept = base64.b64encode(
                __import__('hashlib').sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()
            ).decode('ascii')
            
            if headers.get('sec-websocket-accept') != expectedAccept:
                raise ConnectionError('Web tunnel WebSocket upgrade returned an invalid accept key')
                
            with self._webSocketLock:
                self._webSocket = _WebSocketConnection(rawSocket)
                self._connectionGeneration += 1

            self.running = True
            self.connected = True
            self._startHeartbeat()
            
            logger.info('Web tunnel agent connected: %s%s', self.getTunnelURL(), self.shareUID)
        except Exception:
            rawSocket.close()
            raise

    @staticmethod
    def _receiveHTTPHeaders(sock):
        data = bytearray()
        while b'\r\n\r\n' not in data:
            if len(data) > 64 * 1024:
                raise ConnectionError('Web tunnel WebSocket upgrade response headers are too large')
                
            data.extend(_receiveExactly(sock, 1))
            
        return bytes(data[:-4])

    def _connectSocket(self, parsedURL, timeout):
        port = parsedURL.port or http.client.HTTPS_PORT
        proxy = self._getSocks5Proxy()
        rawSocket = self._connectSocks5(*proxy, parsedURL.hostname, port, timeout) if proxy else socket.create_connection(
            (parsedURL.hostname, port), timeout=timeout
        )
        context = ssl.create_default_context()
        return context.wrap_socket(rawSocket, server_hostname=parsedURL.hostname)

    async def listen(self):
        peerClosed = False
        try:
            peerClosed = await asyncio.to_thread(self._listenWebSocket)
        except ConnectionError as e:
            if self.running:
                logger.warning('Web tunnel WebSocket ended: %s', e)
        finally:
            # graceful=True only for a clean peer-initiated close (opcode
            # 0x8): we still owe that peer our own close frame as a courtesy.
            # Any other exit (broken read, receive() raising, self.running
            # flipped False elsewhere) means the connection isn't healthy
            # enough for a graceful close to be worth attempting -- see
            # _WebSocketConnection.close().
            self._closeWebSocket(graceful=peerClosed)
            # A natural disconnect (as opposed to stop()) leaves self.running
            # True so AsyncTunnelThread's outer loop reconnects; without this,
            # _streamResponse() waiters below would poll self.running/window
            # forever since nothing else ever wakes or invalidates them.
            self._cleanupAfterDisconnect()

    def _listenWebSocket(self):
        """Returns True if the peer closed cleanly (WebSocket close frame),
        False for every other exit (no socket, receive() raising, or
        self.running flipped False elsewhere) -- see listen()'s use of this
        to decide whether a graceful close is owed back.
        """
        # Captured once per connect()/listen() cycle: every frame processed by
        # this loop iteration -- and every request thread it spawns -- belongs
        # to this one generation. See _connectionGeneration in __init__.
        generation = self._connectionGeneration

        while self.running:
            webSocket = self._getWebSocket()
            if not webSocket:
                return False

            opcode, payload = webSocket.receive()
            if opcode == 0x8:
                return True

            if opcode == 0x9:
                webSocket.sendPong(payload)
                continue

            if opcode != 0x2:
                continue

            frameType, streamID, data = self._decodeFrame(payload)
            self._handleFrame(frameType, streamID, data, generation)

        return False

    def _handleFrame(self, frameType, streamID, payload, generation):
        if frameType == self._OPEN:
            metadata, body = self._decodeOpen(payload)
            with self._windowChanged:
                self._sendWindows[(generation, streamID)] = self._INITIAL_WINDOW

            threading.Thread(
                target=self._relayRequest,
                args=(generation, streamID, metadata, body),
                daemon=True,
                name=f'web-tunnel-{generation}-{streamID}',
            ).start()
        elif frameType == self._RESET:
            self._cancelRequest(generation, streamID)
        elif frameType == self._WINDOW_UPDATE:
            if len(payload) != 4:
                raise ConnectionError('Invalid Web tunnel WINDOW_UPDATE frame')

            with self._windowChanged:
                key = (generation, streamID)
                if key in self._sendWindows:
                    self._sendWindows[key] += struct.unpack('!I', payload)[0]
                    self._windowChanged.notify_all()
        elif frameType == self._PING:
            self._sendFrame(self._PONG, streamID)
        else:
            logger.warning('Ignoring unsupported Web tunnel frame type: %s', frameType)

    def _relayRequest(self, generation, streamID, requestData, body):
        localConnection = http.client.HTTPConnection('127.0.0.1', self.localPort, timeout=30)
        try:
            # Connect explicitly (near-instant for localhost) and disable
            # auto-reconnect *before* registering: request()'s default
            # auto_open=1 would otherwise silently reopen and send the
            # request even if a cancellation closes this connection in the
            # gap between registration and this point (verified: close()
            # before request() does not stop request() from opening a fresh
            # connection and succeeding as if nothing happened).
            localConnection.connect()
            localConnection.auto_open = 0

            # Registered before the local request is even sent (not after
            # getresponse() returns headers): a slow local handler otherwise
            # leaves this connection unreachable to _cancelRequest()/
            # _cleanupAfterDisconnect() for as long as it takes to respond,
            # since neither would find it in _activeConnections yet.
            if not self._registerConnection(generation, streamID, localConnection):
                return

            response = self._requestLocalServer(localConnection, requestData, body)
            self._sendResponse(streamID, response, generation)

            if self._responseHasBody(requestData['method'], response.status):
                self._streamResponse(generation, streamID, response)

            self._sendFrame(self._END, streamID, generation=generation)
        except Exception as e:
            logger.warning('Web tunnel request %s failed: %s', streamID, e)
            self._sendReset(streamID, str(e), generation)
        finally:
            self._removeConnection(generation, streamID)
            localConnection.close()

    def _requestLocalServer(self, connection, requestData, body):
        headers = self._filterRequestHeaders(requestData['headers'])
        headers['Accept-Encoding'] = 'identity'
        # Direct assignment, not setdefault(): _filterRequestHeaders() already
        # strips any forwarded 'host'/'Host', so there's nothing to defer to
        # here. Using setdefault() on a dict keyed by the original (often
        # already-lowercase) header name let a forwarded 'host' and this
        # 'Host' coexist as two distinct keys -- verified sending both to a
        # real local server.
        headers['Host'] = requestData['host']

        connection.request(requestData['method'], requestData['path'], body=body, headers=headers)

        return connection.getresponse()

    def _filterRequestHeaders(self, headerItems):
        headers = {}
        for headerName, headerValue in headerItems:
            normalizedName = headerName.lower()

            if normalizedName not in self._HOP_BY_HOP_HEADERS and normalizedName not in ('accept-encoding', 'content-length', 'host'):
                headers[headerName] = headerValue

        return headers

    def _sendResponse(self, streamID, response, generation):
        headers = [[name, value] for name, value in response.getheaders() if name.lower() not in self._HOP_BY_HOP_HEADERS]
        self._sendFrame(
            self._RESPONSE, streamID, json.dumps({'status': response.status, 'headers': headers}).encode('utf-8'),
            generation=generation,
        )

    # Content types that must not be buffered up to a full chunk before
    # forwarding -- e.g. SSE, where the browser needs each small event as it
    # arrives, not once ~chunkSize bytes have accumulated.
    _LOW_LATENCY_CONTENT_TYPES = frozenset({'text/event-stream'})
    _LOW_LATENCY_READ_SIZE = 64 * 1024

    @classmethod
    def _isLowLatencyResponse(cls, response):
        contentType = response.getheader('Content-Type', '').split(';', 1)[0].strip().lower()
        return contentType in cls._LOW_LATENCY_CONTENT_TYPES

    # Must match the relay's own null-body handling for 204/205/304 -- the
    # agent must never try to stream a body for one, or the two sides
    # disagree about whether an END frame with no preceding DATA frames is
    # expected.
    _NULL_BODY_STATUSES = frozenset({204, 205, 304})

    @classmethod
    def _responseHasBody(cls, method, status):
        return method != 'HEAD' and status not in cls._NULL_BODY_STATUSES

    def _streamResponse(self, generation, streamID, response):
        key = (generation, streamID)
        # http.client.HTTPResponse.read(n) keeps pulling from the socket
        # until it accumulates n bytes (or EOF) -- fine for a large file, but
        # it delays an already-arrived low-latency event behind whatever the
        # next read needs to fill (verified: 2s to relay a write that arrived
        # instantly, with a 2s gap before the next write). read1() does at
        # most one underlying read and returns whatever's available
        # immediately, which is what _LOW_LATENCY_CONTENT_TYPES needs;
        # regular transfers keep using read() so a large file isn't split
        # into far more, far smaller WebSocket messages than necessary.
        lowLatency = self._isLowLatencyResponse(response)

        while True:
            with self._windowChanged:
                # `key in self._sendWindows` is load-bearing, not redundant
                # with the `available < 1` check below: _cancelRequest() pops
                # the key entirely rather than setting it to 0, and
                # .get(key, 0) can't tell "cancelled" apart from "window
                # legitimately exhausted, more credit incoming" -- both read
                # as 0. Without this, a cancelled-but-still-connected stream
                # loops in wait(timeout=5) forever: the outer `available < 1`
                # raise is never reached because the inner while never exits.
                while (
                    self.running and self.connected
                    and key in self._sendWindows and self._sendWindows[key] < 1
                ):
                    self._windowChanged.wait(timeout=5)

                available = self._sendWindows.get(key)
                if not self.running or not self.connected or available is None or available < 1:
                    raise ConnectionError('Web tunnel stream was cancelled')

                readSize = min(self.chunkSize, available)

            if lowLatency:
                data = response.read1(min(readSize, self._LOW_LATENCY_READ_SIZE))
            else:
                data = response.read(readSize)

            if not data:
                return

            with self._windowChanged:
                if key not in self._sendWindows:
                    raise ConnectionError('Web tunnel stream was cancelled')

                self._sendWindows[key] -= len(data)

            self._sendFrame(self._DATA, streamID, data, generation=generation)

    def _sendReset(self, streamID, message, generation=None):
        try:
            self._sendFrame(self._RESET, streamID, message.encode('utf-8')[:1024], generation=generation)
        except Exception as e:
            logger.debug('Could not send Web tunnel reset: %s', e)

    def _sendFrame(self, frameType, streamID, payload=b'', generation=None):
        packet = self._FRAME_HEADER.pack(self._PROTOCOL_VERSION, frameType, streamID, len(payload)) + payload
        with self._webSocketLock:
            # Per-request frames (RESPONSE/DATA/END/RESET) pass their
            # generation; a stale generation (from a request thread that
            # outlived a reconnect) must never write onto whatever connection
            # -- old or new -- happens to be current now. Connection-scoped
            # traffic (PONG) has no generation and always targets whichever
            # WebSocket is current.
            if generation is not None and generation != self._connectionGeneration:
                raise ConnectionError('Web tunnel connection was replaced')

            webSocket = self._webSocket

        if not webSocket:
            raise ConnectionError('Web tunnel WebSocket is not connected')

        webSocket.sendBinary(packet)

    def _decodeFrame(self, packet):
        if len(packet) < self._FRAME_HEADER.size:
            raise ConnectionError('Web tunnel frame is truncated')
            
        version, frameType, streamID, payloadLength = self._FRAME_HEADER.unpack(packet[:self._FRAME_HEADER.size])
        payload = packet[self._FRAME_HEADER.size:]
        if version != self._PROTOCOL_VERSION or payloadLength != len(payload):
            raise ConnectionError('Web tunnel frame is invalid')
            
        return frameType, streamID, payload

    @staticmethod
    def _decodeOpen(payload):
        if len(payload) < 4:
            raise ConnectionError('Web tunnel OPEN frame is truncated')
            
        metadataLength = struct.unpack('!I', payload[:4])[0]
        if metadataLength > len(payload) - 4:
            raise ConnectionError('Web tunnel OPEN frame has invalid metadata')
            
        metadata = json.loads(payload[4:4 + metadataLength].decode('utf-8'))
        return metadata, payload[4 + metadataLength:] if metadata['hasBody'] else None

    def _getWebSocket(self):
        with self._webSocketLock:
            return self._webSocket

    def _startHeartbeat(self):
        self._heartbeatStop.set()
        stopEvent = threading.Event()
        
        self._heartbeatStop = stopEvent
        self._heartbeatThread = threading.Thread(
            target=self._heartbeatLoop,
            args=(stopEvent,),
            daemon=True,
            name='web-tunnel-heartbeat',
        )
        self._heartbeatThread.start()

    def _heartbeatLoop(self, stopEvent):
        # Keep the agent <-> relay WebSocket alive while the share is idle.
        # This uses the existing binary tunnel PING/PONG protocol rather
        # than application-specific traffic.
        while not stopEvent.wait(20):
            if not self.running:
                return
                
            try:
                webSocket = self._getWebSocket()
                if not webSocket:
                    return
                    
                webSocket.sendPing()
            except Exception:
                return

    def _registerConnection(self, generation, streamID, connection):
        """Register a just-created local connection, unless this request was
        already cancelled/cleaned up before it got the chance (checked
        atomically against the same lock _cancelRequest()/
        _cleanupAfterDisconnect() use, via the window entry _handleFrame()'s
        OPEN case creates up front). Returns False if the caller should just
        close the connection and stop instead of proceeding.
        """
        key = (generation, streamID)
        with self._windowChanged:
            if key not in self._sendWindows or generation != self._connectionGeneration or not self.connected:
                return False

            self._activeConnections[key] = connection
            return True

    def _removeConnection(self, generation, streamID):
        with self._windowChanged:
            self._activeConnections.pop((generation, streamID), None)
            self._sendWindows.pop((generation, streamID), None)
            self._windowChanged.notify_all()

    def _cancelRequest(self, generation, streamID):
        with self._windowChanged:
            connection = self._activeConnections.get((generation, streamID))
            self._sendWindows.pop((generation, streamID), None)
            self._windowChanged.notify_all()

        if connection:
            logger.info('Web tunnel request %s was cancelled by the browser', streamID)
            self._forceCloseLocalConnection(connection)

    @staticmethod
    def _forceCloseLocalConnection(connection):
        """Best-effort abort of a local HTTPConnection from a thread other
        than the one that may be blocked inside its request()/getresponse()/
        read(). shutdown() before close() is the standard way to unblock a
        concurrent recv() on POSIX; on Windows it does not reliably do so
        (verified empirically -- the blocked thread stayed blocked past both
        close() alone and shutdown()+close() from another thread). This still
        closes the socket so the request can't proceed once the local
        handler responds, but the requesting thread may only actually unblock
        once the local server itself responds or its own 30s timeout fires.
        """
        try:
            if connection.sock:
                connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logger.debug('Local connection shutdown() failed (may already be closed): %s', e)

        connection.close()

    def _closeWebSocket(self, graceful=True):
        self._heartbeatStop.set()
        with self._webSocketLock:
            webSocket, self._webSocket = self._webSocket, None

        if webSocket:
            webSocket.close(graceful=graceful)

    def _cleanupAfterDisconnect(self):
        """Fail every in-flight stream and drop local connections once the
        agent WebSocket is no longer usable (explicit stop(), or listen()
        exiting on its own after a drop). Without this, _streamResponse()
        waiters block on window credit that will never arrive, leaking their
        thread and local HTTP connection for as long as the process runs.
        """
        self.connected = False
        with self._windowChanged:
            connections = list(self._activeConnections.values())
            self._activeConnections.clear()
            self._sendWindows.clear()
            self._windowChanged.notify_all()

        for connection in connections:
            try:
                self._forceCloseLocalConnection(connection)
            except Exception as e:
                logger.debug('Failed to close local connection during Web tunnel cleanup: %s', e)

    def stop(self):
        self.running = False
        self._closeWebSocket()
        self._cleanupAfterDisconnect()

    async def shutdown(self):
        await asyncio.to_thread(self.stop)
