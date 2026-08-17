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

The public side remains ordinary HTTPS. This module implements only the
agent-to-relay connection and deliberately keeps the implementation
stdlib-only so this transport does not add another runtime dependency.

Modeled on an HTTP/1.1 connection pool, just reversed: a small number of
persistent WebSocket "lanes" are held open to the relay, each carrying at
most one HTTP request at a time, plus one separate control connection that
carries no request traffic and exists only so the relay can tell "is this
agent online at all" apart from "are all its lanes currently busy". A
lane's own connection failure only fails the one request it happens to be
holding -- every other lane (and the control connection) is unaffected,
and there is no resume across a reconnect: a request whose lane drops
mid-flight just fails (matching the plain Bore tunnel's own failure
semantics), and the lane rejoins the pool ready for a fresh request once
reconnected.
"""

import asyncio
import base64
import hashlib
import http.client
import json
import os
import queue
import random
import selectors
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse


from bases.Kernel import getLogger
from bases.Utils import ENABLE_PY312_WORKAROUND

from . import _receiveExactly, Socks5ProxySupport


logger = getLogger(__name__)

class WebTunnelConfigurationError(ValueError):
    """Raised when the Web tunnel environment is incomplete or invalid."""


class _WebSocketConnection:
    """Minimal RFC 6455 binary client used by :class:`WebTunnelClient`.

    One dedicated I/O thread owns the underlying SSLSocket for its entire
    lifetime -- OpenSSL SSL connection objects are not safe for simultaneous
    use from multiple threads.

    `sendBinaryAsync()` is deliberately limited to response DATA frames: it
    queues a frame without waiting for its TLS write to finish, but applies a
    bounded payload budget. Every other send remains a flush barrier, so FIFO
    order makes a terminal END/CANCEL proof that all preceding DATA reached the
    socket before its lane can be reused.

    Why not the `websockets` package instead of this hand-rolled RFC 6455
    subset: its high-level `send()`/`recv()` API has no equivalent of the
    bounded-async-DATA-vs-synchronous-terminal-barrier split this class
    depends on, nor a knob forcing `_MAX_TLS_WRITE_SIZE`-sized SSL writes.

    Future maintenance option: replace the RFC 6455 codec/handshake only
    with `websockets`' Sans-I/O layer, while retaining this class's own
    custom socket/TLS/I/O scheduling.
    """

    class _PendingWrite:
        __slots__ = ('segments', 'payloadSize', 'done', 'error', 'finished')

        def __init__(self, segments, payloadSize):
            self.segments = segments
            self.payloadSize = payloadSize
            self.done = threading.Event()
            self.error = None
            self.finished = False

    _MAX_FRAME_SIZE = 32 * 1024 * 1024
    _MAX_TLS_WRITE_SIZE = 64 * 1024

    # Precomputed per-byte XOR tables, one per possible mask-byte value. Masking a
    # payload one Python-level `value ^ mask[i % 4]` at a time is the dominant cost
    # on large DATA frames; bytes.translate() runs the substitution in C instead.
    _XOR_TABLES = tuple(bytes(value ^ key for value in range(256)) for key in range(256))

    def __init__(self, sock, maxOutstandingBytes):
        self.sock = sock
        self._stateLock = threading.Lock()
        self._outboundRoom = threading.Condition(self._stateLock)
        self._outbound = queue.Queue()
        self._outboundPayloadBytes = 0
        self._maxOutstandingBytes = maxOutstandingBytes
        self._inbound = queue.Queue()
        self._closed = False
        self._transportError = None
        self._receiveBuffer = bytearray()
        self._wakeReader, self._wakeWriter = socket.socketpair()
        self._wakeReader.setblocking(False)
        self._wakeWriter.setblocking(False)
        self._ioThread = threading.Thread(
            target=self._runIO,
            daemon=True,
            name='web-tunnel-websocket-io',
        )
        self._ioThread.start()

    @staticmethod
    def _bestEffortCloseSocket(sock, label):
        try:
            sock.close()
        except OSError as e:
            logger.debug('Failed to close %s (likely already closed): %s', label, e)

    @staticmethod
    def _formatTransportError(operation, sock, error):
        """Keep the original socket/SSL failure visible through ConnectionError."""
        try:
            socketTimeout = sock.gettimeout()
        except Exception:
            # Best-effort diagnostic only -- `sock` may not even be a real
            # socket here (e.g. a transport that never finished connecting),
            # and this helper must never itself raise: every caller reaches
            # it from inside an already-failing path, and a second failure
            # here would skip _failTransport() entirely, leaving every
            # blocked receive()/pending write hanging forever instead of
            # getting a clean ConnectionError.
            socketTimeout = 'unavailable'

        details = [
            '{}: {}'.format(type(error).__name__, error),
            'socketTimeout={!r}'.format(socketTimeout),
        ]
        errorNumber = getattr(error, 'errno', None)
        if errorNumber is not None:
            details.append('errno={!r}'.format(errorNumber))
            
        winError = getattr(error, 'winerror', None)
        if winError is not None:
            details.append('winerror={!r}'.format(winError))

        return 'Web tunnel WebSocket {} failed ({})'.format(operation, ', '.join(details))

    @classmethod
    def _maskPayload(cls, payload, mask):
        """XOR `payload` against the 4-byte `mask`, repeating per RFC 6455 §5.3."""
        result = bytearray(payload)
        for offset, key in enumerate(mask):
            result[offset::4] = result[offset::4].translate(cls._XOR_TABLES[key])

        return bytes(result)

    def sendBinary(self, data):
        self._sendFrame(0x2, data)

    def sendBinaryAsync(self, data):
        """Queue binary DATA while keeping unsent payload memory bounded."""
        self._sendFrame(0x2, data, waitForCompletion=False)

    def sendPong(self, data=b''):
        self._sendFrame(0xA, data)

    def sendPing(self, data=b''):
        self._sendFrame(0x9, data)

    def close(self, graceful=True):
        """Close this WebSocket without letting another thread touch SSLSocket.

        `graceful=True` first sends a WebSocket close frame through the same I/O
        owner thread.  A broken transport skips that write and only requests
        teardown, avoiding re-entering OpenSSL from the caller thread.
        """
        if graceful:
            try:
                self._sendFrame(0x8, b'')
            except Exception as e:
                logger.debug('Failed to send Web tunnel close frame (socket likely already broken): %s', e)

        with self._outboundRoom:
            alreadyClosed = self._closed
            self._closed = True
            transportError = self._transportError
            self._outboundRoom.notify_all()

        if not alreadyClosed and transportError is None:
            self._inbound.put(ConnectionError('Web tunnel WebSocket is closed'))
            
        self._wakeIO()
        
        if not alreadyClosed and threading.current_thread() is not self._ioThread:
            self._ioThread.join(timeout=2)

    def _completeWrite(self, write, error=None):
        with self._outboundRoom:
            if write.finished:
                return

            write.finished = True
            write.error = error
            self._outboundPayloadBytes -= write.payloadSize
            self._outboundRoom.notify_all()
                        
        write.done.set()

    def _enqueueWrite(self, write):
        with self._outboundRoom:
            # A single legal frame may be larger than the normal budget
            # (e.g. a request body on the control connection). It can start
            # from an empty queue, but must never sit behind buffered DATA and
            # make the producer wait forever for room it can never obtain.
            while (
                not self._closed and self._outboundPayloadBytes > 0
                and self._outboundPayloadBytes + write.payloadSize > self._maxOutstandingBytes
            ):
                self._outboundRoom.wait()

            if self._closed:
                if self._transportError:
                    raise self._transportError
                    
                raise ConnectionError('Web tunnel WebSocket is closed')

            self._outboundPayloadBytes += write.payloadSize
            self._outbound.put(write)

    def _sendFrame(self, opcode, data, waitForCompletion=True):
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
        write = self._PendingWrite(
            (bytes(header) + mask, self._maskPayload(payload, mask)), payloadLength,
        )
        self._enqueueWrite(write)

        self._wakeIO()
        if not waitForCompletion:
            return

        write.done.wait()
        if write.error:
            raise write.error

    def receive(self):
        """Return ``(opcode, payload)``. Server messages must be unfragmented."""
        item = self._inbound.get()
        if isinstance(item, BaseException):
            raise item
            
        return item

    def _wakeIO(self):
        try:
            self._wakeWriter.send(b'\0')
        except (BlockingIOError, OSError):
            # The wake socket is only an edge trigger.  If its tiny buffer is
            # already full, the I/O thread is guaranteed to observe readability.
            pass

    def _drainWakeSocket(self):
        while True:
            try:
                if not self._wakeReader.recv(4096):
                    return
            except BlockingIOError:
                return

    def _runIO(self):
        sock = self.sock
        selector = selectors.DefaultSelector()
        currentWrite = None
        segmentIndex = 0
        segmentOffset = 0
        writeNeedsRead = False
        readNeedsWrite = False

        try:
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ)
            selector.register(self._wakeReader, selectors.EVENT_READ)

            while True:
                with self._stateLock:
                    shouldClose = self._closed

                if currentWrite is None:
                    try:
                        currentWrite = self._outbound.get_nowait()
                        segmentIndex = 0
                        segmentOffset = 0
                        writeNeedsRead = False
                    except queue.Empty:
                        currentWrite = None

                if shouldClose and currentWrite is None:
                    return

                socketEvents = selectors.EVENT_READ
                if currentWrite is not None and not writeNeedsRead:
                    socketEvents |= selectors.EVENT_WRITE
                    
                if readNeedsWrite:
                    socketEvents |= selectors.EVENT_WRITE
                    
                selector.modify(sock, socketEvents)

                for key, mask in selector.select():
                    if key.fileobj is self._wakeReader:
                        self._drainWakeSocket()
                        continue

                    if mask & selectors.EVENT_READ:
                        if currentWrite is not None and writeNeedsRead:
                            writeNeedsRead = False
                            
                        try:
                            self._readAvailable(sock)
                            readNeedsWrite = False
                        except ssl.SSLWantReadError:
                            # Not an error: nothing decryptable yet. The next
                            # EVENT_READ readiness re-triggers this read.
                            pass
                        except ssl.SSLWantWriteError:
                            readNeedsWrite = True
                        except (OSError, ssl.SSLError, ConnectionError) as e:
                            raise ConnectionError(self._formatTransportError('read', sock, e)) from e

                    if mask & selectors.EVENT_WRITE:
                        if readNeedsWrite:
                            try:
                                self._readAvailable(sock)
                                readNeedsWrite = False
                            except ssl.SSLWantReadError:
                                readNeedsWrite = False
                            except ssl.SSLWantWriteError:
                                # Not an error: this opportunistic read still
                                # needs a write first, and the socket isn't
                                # writable this iteration either --
                                # readNeedsWrite stays set until it is.
                                pass
                            except (OSError, ssl.SSLError, ConnectionError) as e:
                                raise ConnectionError(self._formatTransportError('read', sock, e)) from e

                        if currentWrite is not None and not writeNeedsRead:
                            try:
                                while segmentIndex < len(currentWrite.segments):
                                    segment = currentWrite.segments[segmentIndex]
                                    if segmentOffset == len(segment):
                                        # Zero-length WebSocket payloads are valid for control
                                        # frames such as PING/PONG/CLOSE.  Do not call
                                        # SSLSocket.send(b''): it legitimately returns 0,
                                        # which means "nothing to send", not "peer closed".
                                        segmentIndex += 1
                                        segmentOffset = 0
                                        continue

                                    sent = sock.send(memoryview(segment)[segmentOffset:segmentOffset + self._MAX_TLS_WRITE_SIZE])
                                    if sent <= 0:
                                        raise ConnectionError('Peer closed the connection unexpectedly')
                                        
                                    segmentOffset += sent

                                self._completeWrite(currentWrite)
                                currentWrite = None
                            except (ssl.SSLWantWriteError, BlockingIOError):
                                # Not an error: the socket buffer is full.
                                # segmentIndex/segmentOffset are untouched, so
                                # the next EVENT_WRITE readiness resumes this
                                # same send() from exactly where it left off.
                                pass
                            except ssl.SSLWantReadError:
                                writeNeedsRead = True
                            except (OSError, ssl.SSLError, ConnectionError) as e:
                                error = ConnectionError(self._formatTransportError('write', sock, e))
                                self._completeWrite(currentWrite, error)
                                currentWrite = None
                                raise error from e
                                
        except BaseException as e:
            # _failTransport() below is what unblocks every blocked
            # receive()/pending write on this connection -- it must run no
            # matter what, even if formatting this error somehow itself
            # raises, or those callers would hang forever instead of seeing
            # a clean ConnectionError.
            try:
                error = e if isinstance(e, ConnectionError) else ConnectionError(
                    self._formatTransportError('transport', sock, e)
                )
            except Exception:
                error = e if isinstance(e, ConnectionError) else ConnectionError(
                    'Web tunnel WebSocket transport failed: {}: {}'.format(type(e).__name__, e)
                )
            self._failTransport(error, currentWrite)
        finally:
            try:
                selector.close()
            except Exception as e:
                logger.debug('Failed to close Web tunnel I/O selector (likely already closed): %s', e)
                
            self._bestEffortCloseSocket(sock, 'Web tunnel socket')
            self.sock = None
            
            for wakeSocket in (self._wakeReader, self._wakeWriter):
                self._bestEffortCloseSocket(wakeSocket, 'Web tunnel wake socket')

    def _readAvailable(self, sock):
        """Drain currently-decryptable TLS bytes and emit every complete frame."""
        madeProgress = False
        while True:
            try:
                data = sock.recv(64 * 1024)
            except (ssl.SSLWantReadError, BlockingIOError):
                if madeProgress:
                    return
                    
                raise

            if not data:
                raise ConnectionError('Peer closed the connection unexpectedly')

            madeProgress = True
            self._receiveBuffer.extend(data)
            self._emitBufferedFrames()

            if sock.pending() <= 0:
                return

    def _emitBufferedFrames(self):
        buffer = self._receiveBuffer
        while True:
            if len(buffer) < 2:
                return

            first = buffer[0]
            second = buffer[1]
            if not first & 0x80:
                raise ConnectionError('Fragmented Web tunnel WebSocket messages are unsupported')

            length = second & 0x7f
            headerLength = 2
            if length == 126:
                if len(buffer) < 4:
                    return
                    
                length = struct.unpack('!H', buffer[2:4])[0]
                headerLength = 4
            elif length == 127:
                if len(buffer) < 10:
                    return
                    
                length = struct.unpack('!Q', buffer[2:10])[0]
                headerLength = 10
            else:
                pass

            if length > self._MAX_FRAME_SIZE:
                raise ConnectionError('Web tunnel WebSocket frame is too large')

            masked = bool(second & 0x80)
            maskLength = 4 if masked else 0
            frameLength = headerLength + maskLength + length
            if len(buffer) < frameLength:
                return

            mask = bytes(buffer[headerLength:headerLength + 4]) if masked else None
            payloadStart = headerLength + maskLength
            payload = bytes(buffer[payloadStart:frameLength])
            del buffer[:frameLength]

            if mask:
                payload = self._maskPayload(payload, mask)
                
            self._inbound.put((first & 0x0f, payload))

    def _failTransport(self, error, currentWrite):
        with self._outboundRoom:
            if self._transportError is None:
                self._transportError = error
                
            self._closed = True
            self._outboundRoom.notify_all()

        if currentWrite is not None:
            self._completeWrite(currentWrite, error)

        while True:
            try:
                write = self._outbound.get_nowait()
            except queue.Empty:
                break
            self._completeWrite(write, error)

        # One terminal error is enough to unblock the receive loop.  Any later
        # receive() call gets the same connection failure rather than hanging.
        self._inbound.put(error)


class _HeartbeatedSocket:
    """Owns one WebSocket reference kept alive by a background heartbeat
    thread. Shared base for the control connection and every data lane --
    they differ only in what a dead transport should do about it (see
    `_startHeartbeatThread`'s `onFailure`) and what else, if anything, needs
    checking on every tick (see `_runHeartbeat`'s own `onTick`).

    Subclasses must set `self.running` (before starting a heartbeat or
    receive loop) to say whether they should keep trying at all -- both
    `_runHeartbeat` and `_runReceiveLoop` read it directly.
    """

    def __init__(self):
        self._webSocket = None
        self._webSocketLock = threading.Lock()
        self._heartbeatStop = threading.Event()

    def _getWebSocket(self):
        with self._webSocketLock:
            return self._webSocket

    def _closeWebSocket(self, graceful=True):
        self._heartbeatStop.set()
        with self._webSocketLock:
            webSocket, self._webSocket = self._webSocket, None

        if webSocket:
            webSocket.close(graceful=graceful)

    def _poisonWebSocket(self, failedWebSocket):
        """Null out `failedWebSocket` if it's still the current one, then
        close it. Called from whatever thread first discovers a dead
        transport (the heartbeat, or -- for a lane -- a work thread's own
        write failure) -- proactive, since nothing else would otherwise wake
        a concurrent blocked receive() on this same connection."""
        with self._webSocketLock:
            if self._webSocket is failedWebSocket:
                self._webSocket = None
                
        failedWebSocket.close(graceful=False)

    def _startHeartbeatThread(self, onFailure, label, threadName, **heartbeatKwargs):
        self._heartbeatStop.set()
        stopEvent = threading.Event()
        self._heartbeatStop = stopEvent
        
        threading.Thread(
            target=self._runHeartbeat,
            args=(stopEvent, onFailure, label),
            kwargs=heartbeatKwargs,
            daemon=True,
            name=threadName,
        ).start()

    def _runHeartbeat(self, stopEvent, onFailure, label, onTick=None, interval=20, rawPingEveryNTicks=1):
        """Keeps this WebSocket alive while otherwise idle, using a raw
        WebSocket-level ping (opcode 0x9). Shared by the control connection
        and every data lane -- they differ only in `onFailure` (what "the
        transport just died" should do about it) and, for a lane, `onTick`.

        `onTick`, if given, runs on every tick regardless of whether the raw
        ping itself fired this tick -- used by lanes to also check whether an
        application-level PING is warranted (see
        _TunnelLane._sendApplicationPing). A raw ping failure is treated
        exactly like an onTick failure: both mean the transport is dead.

        `interval` lets a lane tick faster than the control connection needs
        to: a lane whose active request has gone quiet must still notice and
        emit *some* application-level frame comfortably inside whatever gap
        would make the relay treat this connection as idle enough to drop,
        since losing the connection while a request is still genuinely in
        flight is exactly what the relay's own lane-recovery logic has to
        treat as an abnormal restart -- but the relay platform's runtime
        auto-handles the raw ping itself and never surfaces it to the relay's
        frame handler at all, so its own cadence has nothing to do with
        keeping the connection alive and doesn't need to track
        `interval`. `rawPingEveryNTicks`
        decouples the two: 1 (default) raw-pings every tick, matching
        `interval` exactly (the control connection's own case); a lane passes
        a larger value to keep `interval` fast for onTick's own check while
        only actually raw-pinging -- a pure transport-liveness probe -- every
        Nth tick.
        """
        tick = 0
        while not stopEvent.wait(interval):
            if not self.running:
                return

            webSocket = self._getWebSocket()
            if not webSocket:
                return

            tick += 1
            try:
                if tick % rawPingEveryNTicks == 0:
                    webSocket.sendPing()
                if onTick:
                    onTick()
            except Exception as e:
                # A silent return here would leave the connection looking alive
                # until its own blocked read happens to notice -- which isn't
                # guaranteed to happen promptly from a cross-thread close on
                # Windows. Propagate the failure immediately instead.
                logger.warning('Web tunnel %s heartbeat detected a failed transport: %s', label, e)
                onFailure(webSocket)
                return

    def _runReceiveLoop(self, onBinaryPayload=None):
        """Reads frames off this WebSocket until told to stop or the peer
        closes cleanly. Shared by the control connection and every data lane
        -- they differ only in whether an incoming binary (opcode 0x2)
        application frame means anything: a lane passes `onBinaryPayload` to
        decode and dispatch it; the control connection carries no
        application frames at all, so passing nothing there leaves one (like
        any other unrecognized opcode) silently ignored rather than treated
        as a protocol error. Ping is always answered automatically; a clean
        WebSocket close frame is the only thing that ends the loop on its own.

        Returns True if the peer closed cleanly (WebSocket close frame).
        """
        while self.running:
            webSocket = self._getWebSocket()
            if not webSocket:
                return False

            opcode, payload = webSocket.receive()
            if opcode == 0x8:
                return True

            if opcode == 0x9:
                webSocket.sendPong(payload)
            elif opcode == 0x2 and onBinaryPayload:
                onBinaryPayload(payload)
            else:
                pass

        return False


class _LaneRequestState:
    """Everything about the one request a _TunnelLane is currently holding.

    Replaced wholesale (never mutated across requests) each time the lane
    accepts a new REQUEST -- the work thread handling a request captures
    its own state object at spawn and checks object identity (`state is
    self._current`) before every send, so a thread whose request has since
    been cancelled or superseded by a newer one on the same lane can never
    act on, or write a stale frame into, whatever request now actually owns
    the lane.
    """

    __slots__ = (
        'epoch', 'localConnection', 'sendCredit', 'cancelled', 'terminalizing',
        'bytesSent', 'lastCreditAt', 'lastFrameSentAt',
    )

    def __init__(self, epoch, initialWindow):
        self.epoch = epoch
        self.localConnection = None
        self.sendCredit = initialWindow
        self.cancelled = False
        self.terminalizing = False
        
        # For stall diagnostics only (_waitForSendRoom/_creditCurrent) --
        # not used by any correctness path.
        self.bytesSent = 0
        self.lastCreditAt = time.monotonic()
        
        # Set here (request accepted, nothing sent yet) and refreshed by
        # every successful RESPONSE/DATA/END/CANCEL send (see
        # _TunnelLane._sendFrame) -- read by _sendApplicationPing to tell
        # "this request is actively producing frames of its own, which
        # already proves liveness" apart from "genuinely gone quiet".
        self.lastFrameSentAt = time.monotonic()


class _TunnelLane(_HeartbeatedSocket):
    """One persistent WebSocket carrying at most one HTTP request at a time.

    Mirrors an HTTP/1.1 keep-alive connection: reused across requests, but
    never carries more than one in flight. Runs its own independent
    connect/listen/reconnect cycle in a dedicated thread for the lifetime of
    the tunnel, entirely decoupled from the control connection's own
    lifecycle -- see WebTunnelClient.connect()/listen(), which only manage
    the control connection and start this pool once, the first time it
    succeeds.
    """

    def __init__(self, client, laneIndex):
        self.client = client
        self.laneIndex = laneIndex
        self.running = True
        super().__init__()

        # All per-request state lives here. None while idle; replaced (not
        # mutated) by _acceptRequest for each new REQUEST this lane accepts.
        self._stateLock = threading.Lock()
        self._stateChanged = threading.Condition(self._stateLock)
        self._current = None

        self._backoff = 1
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f'web-tunnel-lane-{laneIndex}',
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self.running = False
        self._closeWebSocket(graceful=False)
        self._cleanupAfterDisconnect()

    def _run(self):
        while self.running:
            self._runOneCycle()

    def _runOneCycle(self):
        cycleStartedAt = time.monotonic()
        peerClosed = False
        try:
            self._connect()
            peerClosed = self._listen()
        except ConnectionError as e:
            if self.running:
                logger.warning(
                    'Web tunnel lane %s ended after %.1fs: %s',
                    self.laneIndex, time.monotonic() - cycleStartedAt, e,
                )
        except Exception as e:
            if self.running:
                logger.warning(
                    'Web tunnel lane %s failed after %.1fs: %s',
                    self.laneIndex, time.monotonic() - cycleStartedAt, e,
                )
        finally:
            self._closeWebSocket(graceful=peerClosed)
            self._cleanupAfterDisconnect()

        if not self.running:
            return

        if time.monotonic() - cycleStartedAt >= self.client._MIN_HEALTHY_CONNECTION_DURATION:
            self._backoff = 1
            return

        self._sleepBackoff()

    def _sleepBackoff(self):
        # Each lane jitters and backs off independently: if every lane in
        # the pool drops at once (a genuine network blip), reconnecting them
        # all on the exact same schedule would just reproduce a synchronized
        # thundering herd against the relay instead of spreading it out.
        delay = self._backoff
        jittered = random.uniform(delay / 2, delay) if delay > 0 else 0
        remaining = jittered
        while remaining > 0 and self.running:
            step = min(0.5, remaining)
            time.sleep(step)
            remaining -= step
            
        self._backoff = min(delay * 2, self.client._MAX_RECONNECT_BACKOFF)

    def _connect(self):
        self.client._refreshSecret()
        webSocket = self.client._performWebSocketUpgrade(
            '_tunnel/agent/lane', extraHeaders={'X-Tunnel-Lane-ID': str(self.laneIndex)},
        )
        
        with self._webSocketLock:
            self._webSocket = webSocket
            
        self._startHeartbeat()

    def _startHeartbeat(self):
        self._startHeartbeatThread(
            self._onTransportFailure, f'lane-{self.laneIndex}', f'web-tunnel-lane-{self.laneIndex}-heartbeat',
            onTick=self._sendApplicationPing,
            interval=self.client._LANE_HEARTBEAT_INTERVAL,
            # max(1, ...): a future _LANE_HEARTBEAT_INTERVAL raised above
            # _LANE_RAW_PING_INTERVAL would otherwise floor-divide to 0, and
            # _runHeartbeat's own `tick % rawPingEveryNTicks` would raise
            # ZeroDivisionError on the very first tick -- caught by its own
            # try/except and treated as a dead transport, silently retiring
            # an otherwise-healthy lane instead of surfacing the actual
            # configuration mistake.
            rawPingEveryNTicks=max(1, self.client._LANE_RAW_PING_INTERVAL // self.client._LANE_HEARTBEAT_INTERVAL),
        )

    def _sendApplicationPing(self):
        # Keeps the connection alive on the relay side (unlike the raw
        # WebSocket-level ping above, auto-handled by the relay platform's
        # runtime and never reaching webSocketMessage()), so this only fires
        # for a lane holding a request that has gone quiet -- not for an idle
        # lane, and not for one still actively streaming: the relay already
        # treats an in-flight request/response stream as enough activity on
        # its own, so DATA itself is already sufficient liveness signal.
        # "Quiet" means no RESPONSE/DATA/END/CANCEL sent for a full
        # heartbeat interval (see _sendFrame, which stamps
        # lastFrameSentAt).
        #
        # The state check and the send must stay atomic with respect to
        # _sendFrame's own final=True transition (END/CANCEL clearing
        # _current) -- otherwise this could carry a now-stale epoch, read
        # by the relay as an orphaned lane. _sendRaw only touches the
        # separate _webSocketLock, so holding this lock across the send is
        # safe.
        with self._stateChanged:
            state = self._current
            if state is None or state.cancelled or state.terminalizing:
                return
                
            if time.monotonic() - state.lastFrameSentAt < self.client._LANE_HEARTBEAT_INTERVAL:
                return
                
            self._sendRaw(self.client._PING, state.epoch)

    def _onTransportFailure(self, failedWebSocket):
        """Called whenever this lane's WebSocket is discovered dead --
        either the heartbeat's own ping failing, or (see _sendRaw) a work
        thread's write failing. Both can happen on a thread other than this
        lane's own receive loop, so both must proactively null/close the
        connection here rather than count on that loop noticing on its own:
        a write failure on one thread doesn't otherwise wake a concurrent
        blocked read() on another.
        """
        self._poisonWebSocket(failedWebSocket)

    def _listen(self):
        """Returns True if the peer closed cleanly (WebSocket close frame)."""
        def onBinaryPayload(payload):
            frameType, epoch, data = self.client._decodeFrame(payload)
            self._handleFrame(frameType, epoch, data)

        return self._runReceiveLoop(onBinaryPayload)

    def _handleFrame(self, frameType, epoch, payload):
        if frameType == self.client._REQUEST:
            self._acceptRequest(epoch, payload)
        elif frameType == self.client._CANCEL:
            self._cancelCurrent(epoch)
        elif frameType == self.client._WINDOW_UPDATE:
            self._creditCurrent(epoch, payload)
        elif frameType == self.client._PING:
            self._sendRaw(self.client._PONG, epoch)
        elif frameType == self.client._PONG:
            # The relay's reply to this lane's own _sendApplicationPing --
            # nothing to do with it beyond having received it (the point was
            # only to give the relay a periodic tick to observe, see
            # _sendApplicationPing), but it must be recognized here or every
            # heartbeat round-trip logs a spurious "unsupported frame type"
            # warning.
            pass
        else:
            logger.warning('Ignoring unsupported Web tunnel frame type: %s', frameType)

    def _acceptRequest(self, epoch, payload):
        requestData, body = self.client._decodeRequest(payload)
        with self._stateChanged:
            if self._current is not None:
                # The relay must never hand this lane a second request
                # before the first one has finished -- that's the whole
                # protocol invariant a lane exists to provide. A relay-side bug
                # that violates it is something to surface loudly by
                # closing the lane, not silently guess which request is the
                # real one.
                raise ConnectionError(
                    f'Web tunnel lane {self.laneIndex} received REQUEST for epoch {epoch} '
                    f'while still busy with epoch {self._current.epoch}'
                )

            state = _LaneRequestState(epoch, self.client._INITIAL_WINDOW)
            self._current = state
            self._stateChanged.notify_all()

        threading.Thread(
            target=self._runRequest,
            args=(state, requestData, body),
            daemon=True,
            name=f'web-tunnel-lane-{self.laneIndex}-{epoch}',
        ).start()

    def _cancelCurrent(self, epoch):
        with self._stateChanged:
            state = self._current
            if not state or state.epoch != epoch:
                return

            state.cancelled = True
            # Detach immediately, not once the old worker thread eventually
            # notices and unwinds: the relay releases this lane back to its
            # idle pool the instant CANCEL goes out and may dispatch a new
            # REQUEST right behind it, but the old worker's own local
            # cleanup (closing localConnection) can block for its own 30s
            # timeout on Windows (see _forceCloseLocalConnection) -- until
            # this line, the lane's own busy-lane check would still see the
            # cancelled request as "current" and reject the new one.
            self._current = None
            connection = state.localConnection
            self._stateChanged.notify_all()

        if connection:
            self.client._forceCloseLocalConnection(connection)

    def _creditCurrent(self, epoch, payload):
        if len(payload) != 4:
            raise ConnectionError('Invalid Web tunnel WINDOW_UPDATE frame')

        credit = struct.unpack('!I', payload)[0]
        with self._stateChanged:
            state = self._current
            if state and state.epoch == epoch:
                state.sendCredit += credit
                state.lastCreditAt = time.monotonic()
                self._stateChanged.notify_all()
                logger.debug(
                    'Web tunnel lane %s accepted WINDOW_UPDATE: epoch=%s +%s credit -> %s',
                    self.laneIndex, epoch, credit, state.sendCredit,
                )
            else:
                # Logged (not silently dropped) so a stalled-transfer
                # diagnosis can tell this apart from the frame never having
                # arrived at all. A stale/mismatched epoch here is expected
                # once a request finishes (a late credit grant for it can
                # still be in flight), so this is info, not a warning.
                logger.info(
                    'Web tunnel lane %s ignored WINDOW_UPDATE for stale epoch: incoming=%s current=%s',
                    self.laneIndex, epoch, state.epoch if state else None,
                )

    def _runRequest(self, state, requestData, body):
        requestStartedAt = time.monotonic()
        localConnection = http.client.HTTPConnection('127.0.0.1', self.client.localPort, timeout=30)
        try:
            # Connect explicitly (near-instant for localhost) and disable
            # auto-reconnect *before* registering: request()'s default
            # auto_open=1 would otherwise silently reopen and send the
            # request even if a CANCEL closes this connection in the gap
            # between here and registration.
            localConnection.connect()
            localConnection.auto_open = 0

            # The 30s constructor timeout above is generous for what should
            # be a near-instant localhost connect, but http.client applies
            # that same socket timeout to every subsequent read too -- and a
            # local origin can legitimately go quiet far longer than 30s
            # without being dead (slow backend work, or the local server's
            # own stall-detection/diagnosis feature deliberately holding a
            # response open). Widen it once connected, to the same
            # stuck-but-not-dead ceiling _waitForSendRoom already uses for
            # the outbound side, so a merely slow-but-alive origin isn't
            # killed by this transport's own impatience. A genuinely dead
            # origin is still promptly caught the same way it already is if
            # the browser cancels mid-wait: _cancelCurrent's
            # _forceCloseLocalConnection() unblocks this read via a
            # cross-thread socket shutdown regardless of its timeout value.
            localConnection.sock.settimeout(self._STALL_DEADLINE)

            with self._stateChanged:
                if state is not self._current or state.cancelled:
                    return

                state.localConnection = localConnection
                self._stateChanged.notify_all()

            response = self.client._requestLocalServer(localConnection, requestData, body)
            
            # Terminal diagnostics for the *normal* completion path (the
            # stall/failure paths already log on their own) -- lets the log
            # alone distinguish e.g. a genuinely truncated large file from a
            # smaller, complete Range response.
            logger.info(
                'Web tunnel lane %s response: epoch=%s method=%s path=%s range=%s status=%s '
                'contentLength=%s contentRange=%s transferEncoding=%s',
                self.laneIndex, state.epoch, requestData['method'], requestData['path'],
                self.client._requestHeaderValue(requestData, 'Range'), response.status,
                response.getheader('Content-Length'), response.getheader('Content-Range'),
                response.getheader('Transfer-Encoding'),
            )
            self._sendResponse(state, response)

            if self.client._responseHasBody(requestData['method'], response.status):
                self._streamResponse(state, response)

            # Split into a before/after pair around the actual send: a log
            # line alone never proved the frame left this process -- if the
            # WebSocket write itself failed or the process died mid-call,
            # "end" would still have been logged despite END never reaching
            # the relay. Seeing only "preparing END" for a request means the
            # write itself is where to look; seeing "END sent" with no
            # corresponding relay-side completion log means the frame left
            # the agent but the relay never processed it.
            logger.info(
                'Web tunnel lane %s preparing END: epoch=%s bytesSent=%s expectedLength=%s chunked=%s willClose=%s',
                self.laneIndex, state.epoch, state.bytesSent, response.getheader('Content-Length'),
                response.chunked, response.will_close,
            )
            
            self._sendFrame(state, self.client._END, b'', final=True)
            
            logger.info(
                'Web tunnel lane %s END sent: epoch=%s bytesSent=%s',
                self.laneIndex, state.epoch, state.bytesSent,
            )
        except Exception as e:
            with self._stateChanged:
                currentState = self._current
                sendCredit = state.sendCredit
                lastCreditAgo = time.monotonic() - state.lastCreditAt
                
            logger.warning(
                'Web tunnel lane %s request failed: epoch=%s bytesSent=%s sendCredit=%s '
                'requestSeconds=%.1f lastCreditAgoSeconds=%.1f stillCurrent=%s error=%s',
                self.laneIndex, state.epoch, state.bytesSent, sendCredit,
                time.monotonic() - requestStartedAt, lastCreditAgo, currentState is state, e,
            )
            
            self._sendCancel(state, str(e))
        finally:
            localConnection.close()
            
            with self._stateChanged:
                if self._current is state:
                    self._current = None
                    
                self._stateChanged.notify_all()

    def _sendResponse(self, state, response):
        headers = [
            [name, value] for name, value in response.getheaders()
            if name.lower() not in self.client._HOP_BY_HOP_HEADERS
        ]
        payload = json.dumps({'status': response.status, 'headers': headers}).encode('utf-8')
        self._sendFrame(state, self.client._RESPONSE, payload)

    def _streamResponse(self, state, response):
        # http.client.HTTPResponse.read(n) keeps pulling from the socket
        # until it accumulates n bytes (or EOF) -- fine for a large file, but
        # it delays an already-arrived low-latency event behind whatever the
        # next read needs to fill. read1() does at most one underlying read
        # and returns whatever's available immediately, which is what
        # _LOW_LATENCY_CONTENT_TYPES needs; regular transfers keep using
        # read() so a large file isn't split into far more, far smaller
        # WebSocket messages than necessary.
        lowLatency = self.client._isLowLatencyResponse(response)

        while True:
            # response.length hits 0 the instant the last declared byte is
            # actually read -- checked here, before waiting for send credit,
            # because END carries no payload and so needs none: without this,
            # a lane whose origin body finished exactly as its credit ran out
            # would sit in _waitForSendRoom() waiting on a WINDOW_UPDATE that
            # only arrives once the browser pulls again, to learn something
            # response.length already knows for free.
            if response.length == 0:
                return

            readSize = self._waitForSendRoom(state)

            firstData = state.bytesSent == 0
            if firstData:
                # Startup policy: one bounded single underlying read gets a
                # first body byte onto the already-open lane without waiting
                # for the normal (usually 2 MiB) steady-state read to fill.
                # Every later read deliberately stays on the large read()
                # path, so bulk transfers do not turn into many small WS
                # messages.
                data = response.read1(min(readSize, self.client.firstDataSize))
            elif lowLatency:
                data = response.read1(min(readSize, self.client._LOW_LATENCY_READ_SIZE))
            else:
                data = response.read(readSize)

            if not data:
                # http.client.HTTPResponse.read(n) -- the SIZED read path
                # used here -- does NOT raise on a premature connection
                # close when a Content-Length was declared: it just returns
                # fewer bytes than asked and leaves response.length
                # non-zero, then returns b'' on the next call with no
                # exception at all. Only the *unsized* read() path raises
                # IncompleteRead. So an empty read here is ambiguous on its
                # own -- it means either "declared length fully delivered"
                # (response.length is None, having no declared length, or
                # already drained to 0) or "local server hung up early"
                # (response.length is a nonzero remainder). Treating the
                # latter as success would forward a truncated body to the
                # browser as if it were complete.
                if response.length not in (None, 0):
                    raise ConnectionError(
                        'Local HTTP response ended early: {} byte(s) still expected'.format(response.length)
                    )
                return

            with self._stateChanged:
                if state is not self._current or state.cancelled:
                    raise ConnectionError('Web tunnel lane request was cancelled')

                state.sendCredit -= len(data)
                state.bytesSent += len(data) # stall diagnostics only

            self._sendFrame(state, self.client._DATA, data, buffered=True)

    # First stall diagnostic once a single wait has run this long...
    _STALL_LOG_AFTER = 5
    
    # ...then repeated at this interval for as long as it keeps stalling,
    # not on every 5s wait() wake-up -- this can legitimately run for a
    # long time under real (if unusual) downstream backpressure, and
    # shouldn't flood the log while it does.    
    _STALL_LOG_INTERVAL = 30
    
    # Bounds how long this side will wait for credit at all -- independent
    # of the relay's own equivalent stall deadline, since a credit-accounting
    # divergence between the two sides (e.g. a WINDOW_UPDATE lost in transit)
    # can leave the relay's own bookkeeping seeing remainingWindow > 0 -- its
    # deadline never starts counting -- while this side alone sees sendCredit
    # stuck at 0.
    _STALL_DEADLINE = 600

    def _waitForSendRoom(self, state):
        waitStartedAt = time.monotonic()
        nextLogAt = waitStartedAt + self._STALL_LOG_AFTER

        with self._stateChanged:
            while (
                state is self._current and not state.cancelled
                and state.sendCredit < 1
            ):
                self._stateChanged.wait(timeout=5)

                if state is not self._current or state.cancelled or state.sendCredit >= 1:
                    break

                now = time.monotonic()
                if now < nextLogAt:
                    continue

                nextLogAt = now + self._STALL_LOG_INTERVAL
                waitedSeconds = now - waitStartedAt
                logger.warning(
                    'Web tunnel lane %s stalled waiting for send credit: epoch=%s bytesSent=%s '
                    'sendCredit=%s waitedSeconds=%.1f lastCreditAgoSeconds=%.1f transportConnected=%s',
                    self.laneIndex, state.epoch, state.bytesSent, state.sendCredit,
                    waitedSeconds, now - state.lastCreditAt, self._getWebSocket() is not None,
                )

                if waitedSeconds > self._STALL_DEADLINE:
                    raise ConnectionError(
                        'Web tunnel lane {} stalled waiting for send credit past the fail-loud '
                        'deadline ({:.0f}s)'.format(self.laneIndex, waitedSeconds)
                    )

            if state is not self._current or state.cancelled:
                raise ConnectionError('Web tunnel lane request was cancelled')

            return min(self.client.chunkSize, state.sendCredit)

    def _sendCancel(self, state, message):
        try:
            self._sendFrame(state, self.client._CANCEL, message.encode('utf-8')[:1024], final=True)
        except ConnectionError as e:
            logger.debug('Could not send Web tunnel lane cancel: %s', e)

    def _sendFrame(self, state, frameType, payload, final=False, buffered=False):
        """Send one frame for `state`'s request -- refuses if this lane has
        since moved on to a different request (or none), so a thread whose
        request was already cancelled/superseded can never write a stale
        frame into whatever now actually owns this lane's socket. Mirrors
        the single-writer-per-connection invariant _WebSocketConnection
        itself relies on (its own internal send lock only keeps individual
        frames from interleaving, not out-of-order ones from stale threads).

        `buffered=True` is reserved for response DATA. It may return once
        the WebSocket writer has accepted the frame into its bounded FIFO,
        allowing the local HTTP reader to stay ahead of TLS without allowing
        unbounded memory growth. Terminal frames are always synchronous
        barriers: their FIFO position proves all preceding DATA has been
        written before this lane becomes reusable.
        """
        if final:
            with self._stateChanged:
                if state is not self._current:
                    raise ConnectionError('Web tunnel lane request was superseded')

                # Suppress the old request's heartbeat while its terminal
                # frame waits behind buffered DATA. The lock must not span
                # I/O: a peer CANCEL still needs to detach this request
                # promptly on the listener thread.
                state.terminalizing = True
                epoch = state.epoch

            self._sendRaw(frameType, epoch, payload)
            state.lastFrameSentAt = time.monotonic()

            with self._stateChanged:
                if self._current is state:
                    self._current = None
                    self._stateChanged.notify_all()
                    
            return

        with self._stateChanged:
            if state is not self._current:
                raise ConnectionError('Web tunnel lane request was superseded')

            epoch = state.epoch
            
        self._sendRaw(frameType, epoch, payload, buffered=buffered)
        state.lastFrameSentAt = time.monotonic()

    def _sendRaw(self, frameType, epoch, payload=b'', buffered=False):
        packet = self.client._FRAME_HEADER.pack(self.client._PROTOCOL_VERSION, frameType, epoch, len(payload)) + payload
        webSocket = self._getWebSocket()
        if not webSocket:
            raise ConnectionError('Web tunnel lane is not connected')

        try:
            if buffered:
                webSocket.sendBinaryAsync(packet)
            else:
                webSocket.sendBinary(packet)
        except ConnectionError:
            # This runs on a work thread, not this lane's own receive loop
            # -- without proactively tearing the connection down here, the
            # receive loop's blocked read() has nothing to wake it up until
            # the relay itself eventually notices and closes its end.
            self._onTransportFailure(webSocket)
            raise

    def _cleanupAfterDisconnect(self):
        """Fails whatever request this lane was holding when its transport
        died. No resume -- this is Bore-equivalent semantics: only the one
        request this lane happened to be carrying is lost, and the lane
        rejoins the pool ready for a fresh request once reconnected."""
        with self._stateChanged:
            state = self._current
            self._current = None
            self._stateChanged.notify_all()

        if state and state.localConnection:
            try:
                self.client._forceCloseLocalConnection(state.localConnection)
            except Exception as e:
                logger.debug('Failed to close local connection during Web tunnel lane cleanup: %s', e)


class WebTunnelClient(_HeartbeatedSocket, Socks5ProxySupport):
    """Owns the control connection and the pool of data lanes relaying a
    localhost HTTP server through the Web tunnel relay.

    AsyncTunnelThread only ever drives connect()/listen() -- both of those
    manage the control connection alone. The lane pool is self-managed: it
    starts once, the first time connect() succeeds, and from then on every
    lane runs its own independent connect/listen/reconnect loop for the
    life of the tunnel (see _TunnelLane), regardless of what happens to the
    control connection afterwards.
    """

    _PROTOCOL_VERSION = 3
    _REQUEST = 1
    _RESPONSE = 2
    _DATA = 3
    _END = 4
    _CANCEL = 5
    _WINDOW_UPDATE = 6
    _PING = 7
    _PONG = 8
    _FRAME_HEADER = struct.Struct('!BBII')
    
    # Must match the relay's own initial window -- a hardcoded protocol
    # constant assumed identically by both sides, not negotiated at connect time.
    _INITIAL_WINDOW = 4 * 1024 * 1024
    
    # Local transport buffering policy. This deliberately remains separate
    # from _INITIAL_WINDOW: the former bounds Python's queued WebSocket
    # payloads, while the latter is a wire-protocol credit contract with the
    # relay. They currently share a 4 MiB value because that was the measured
    # pipeline depth, not because either mechanism depends on the other.
    _MAX_WS_OUTSTANDING_BYTES = 4 * 1024 * 1024
    
    # The relay accepts these 2 MiB WebSocket DATA messages. Keeping this
    # comfortably below the WebSocket's 32 MiB hard frame limit bounds per-
    # lane memory while halving per-message runtime dispatch versus 1 MiB.
    _MAX_FRAME_DATA = 2 * 1024 * 1024

    # A connection cycle running at least this long is treated as having
    # been genuinely up, resetting the reconnect backoff below -- otherwise
    # a single old blip would keep inflating the delay for the rest of the
    # tunnel's life. Deliberately not "a handful of seconds": a transport
    # that cycles every 6-10s would otherwise be judged healthy every time
    # and never actually back off.
    _MIN_HEALTHY_CONNECTION_DURATION = 60
    _MAX_RECONNECT_BACKOFF = 30
    
    # See _refreshSecret: bounds how often the control connection and every
    # lane's own reconnect can each trigger a real tokenProvider() call.
    _MIN_SECRET_REFRESH_INTERVAL = 30
    
    # How often a lane's heartbeat tick re-checks whether its active
    # request has gone quiet long enough to warrant an application-level
    # PING (see _TunnelLane._sendApplicationPing) -- deliberately well
    # under the window the relay would otherwise treat this connection as
    # idle enough to drop, since a continuously-streaming lane never
    # actually needs the PING itself (see _sendApplicationPing) but a lane
    # that's gone idle mid-request must still be noticed and pinged within
    # this window, or losing the connection in that gap gets treated as an
    # abnormal restart.
    _LANE_HEARTBEAT_INTERVAL = 5

    # The raw WebSocket-level ping (auto-handled by the relay platform's
    # runtime, never reaching the relay's frame handler) has nothing to do
    # with keeping the connection alive and exists purely to detect a dead
    # transport -- it doesn't need _LANE_HEARTBEAT_INTERVAL's own faster
    # cadence. Matches the control connection's own interval (see
    # WebTunnelClient's own _startHeartbeat, which uses _runHeartbeat's
    # default).
    _LANE_RAW_PING_INTERVAL = 20

    # Must match the relay's own maximum lane count -- see _getLaneCount.
    _MAX_LANE_COUNT = 16
    
    # Not a hard cap -- see _getLaneCount's warning when exceeded.
    _RECOMMENDED_MAX_LANE_COUNT = 8

    _HOP_BY_HOP_HEADERS = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade',
    })

    def __init__(self, localPort, agentURL, publicURL, secret, tunnelID, chunkSize=None, proxyConfig=None, 
                 tokenProvider=None, laneCount=None, localPathPrefix=None, firstDataSize=None):
        self.localPort = localPort
        self.agentURL = self._normalizeBaseURL(agentURL)
        self.publicURL = self._normalizeBaseURL(publicURL)
        self.secret = secret
        self.tokenProvider = tokenProvider
        self._skipInitialRefresh = self.secret is not None
        self._secretLock = threading.Lock()
        
        # Far enough in the past that the very first real refresh attempt
        # (once _skipInitialRefresh is used up) is never itself throttled --
        # there's nothing to throttle against yet at construction time.
        self._lastSecretRefreshAt = time.monotonic() - self._MIN_SECRET_REFRESH_INTERVAL

        # This is an opaque routing key.  The transport neither creates nor
        # interprets it; applications may use an opaque ID, a URL-encoded alias, or
        # any other header-safe identifier.
        self.tunnelID = tunnelID
        self.localPathPrefix = self._normalizeLocalPathPrefix(localPathPrefix)
        self.chunkSize = min(chunkSize or self._getChunkSize(), self._MAX_FRAME_DATA)
        self.firstDataSize = self._getFirstDataSize(firstDataSize)
        self.proxyConfig = proxyConfig
        self.remoteHost = urllib.parse.urlparse(self.agentURL).hostname or 'Web'
        self.laneCount = self._getLaneCount(laneCount)
        
        # Identifies this agent process to the relay across every connection
        # it opens (control and every lane) -- see _performWebSocketUpgrade.
        # Lets the relay recognize and retire a previous process's lanes
        # when this one takes over the same tunnel, instead of pooling both
        # processes' lanes together indistinguishably.
        self.agentInstanceID = secrets.token_urlsafe(24)
        self.lastConnectError = None
        self.running = False # should this client keep trying to connect/reconnect
        self.connected = False # is the control connection actually live right now

        super().__init__()
        self._backoff = 1

        self._lanes = []
        self._lanesStarted = False
        self._lanesLock = threading.Lock()

        self._validateConfiguration()

    # ---- Static and class helpers -------------------------------------------

    @staticmethod
    def _normalizeBaseURL(url):
        if not url:
            return url

        return url if url.endswith('/') else f'{url}/'

    @staticmethod
    def _isValidTunnelID(tunnelID):
        return bool(tunnelID) and len(tunnelID) <= 1024 and all(
            0x21 <= ord(character) <= 0x7e for character in tunnelID
        )

    @staticmethod
    def _normalizeLocalPathPrefix(localPathPrefix):
        if localPathPrefix is None:
            return None
            
        if not localPathPrefix.startswith('/'):
            raise WebTunnelConfigurationError('local path prefix must start with /')
            
        if localPathPrefix != '/':
            localPathPrefix = localPathPrefix.rstrip('/') or '/'
            
        return localPathPrefix

    @staticmethod
    def _receiveHTTPHeaders(sock):
        data = bytearray()
        while b'\r\n\r\n' not in data:
            if len(data) > 64 * 1024:
                raise ConnectionError('Web tunnel WebSocket upgrade response headers are too large')

            data.extend(_receiveExactly(sock, 1))

        return bytes(data[:-4])

    @staticmethod
    def _requestHeaderValue(requestData, name):
        normalizedName = name.lower()
        for headerName, headerValue in requestData['headers']:
            if headerName.lower() == normalizedName:
                return headerValue
                
        return None

    @staticmethod
    def _forceCloseLocalConnection(connection):
        """Best-effort abort of a local HTTPConnection from a thread other
        than the one that may be blocked inside its request()/getresponse()/
        read(). shutdown() before close() is the standard way to unblock a
        concurrent recv() on POSIX; on Windows it does not reliably do so.
        This still closes the socket so the request can't proceed once the local
        handler responds, but the requesting thread may only actually unblock
        once the local server itself responds or its own 30s timeout fires.
        """
        try:
            if connection.sock:
                connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logger.debug('Local connection shutdown() failed (may already be closed): %s', e)

        connection.close()

    @staticmethod
    def _decodeRequest(payload):
        if len(payload) < 4:
            raise ConnectionError('Web tunnel REQUEST frame is truncated')

        metadataLength = struct.unpack('!I', payload[:4])[0]
        if metadataLength > len(payload) - 4:
            raise ConnectionError('Web tunnel REQUEST frame has invalid metadata')

        metadata = json.loads(payload[4:4 + metadataLength].decode('utf-8'))
        return metadata, payload[4 + metadataLength:] if metadata['hasBody'] else None

    @classmethod
    def _getBoundedFrameDataSize(cls, explicitValue, environmentName, defaultValue):
        if explicitValue is not None:
            frameDataSize = explicitValue
        else:
            value = os.getenv(environmentName, str(defaultValue))
            try:
                frameDataSize = int(value)
            except ValueError as e:
                raise WebTunnelConfigurationError(f'{environmentName} must be an integer') from e

        if frameDataSize < 1 or frameDataSize > cls._MAX_FRAME_DATA:
            raise WebTunnelConfigurationError(
                f'{environmentName} must be between 1 and {cls._MAX_FRAME_DATA} bytes'
            )
            
        return frameDataSize

    @classmethod
    def _getChunkSize(cls):
        return cls._getBoundedFrameDataSize(None, 'FFL_WEB_TUNNEL_CHUNK_SIZE', 1024 * 1024)

    @classmethod
    def _getFirstDataSize(cls, explicitValue=None):
        """Return the bounded first-DATA size, independent of bulk chunks."""
        return cls._getBoundedFrameDataSize(
            explicitValue, 'FFL_WEB_TUNNEL_FIRST_DATA_SIZE', 64 * 1024,
        )

    @classmethod
    def _getLaneCount(cls, explicitValue=None):
        if explicitValue is not None:
            laneCount = explicitValue
        else:
            value = os.getenv('FFL_WEB_TUNNEL_LANE_COUNT', str(cls._RECOMMENDED_MAX_LANE_COUNT))
            try:
                laneCount = int(value)
            except ValueError as e:
                raise WebTunnelConfigurationError('FFL_WEB_TUNNEL_LANE_COUNT must be an integer') from e

        # Must not exceed the relay's own maximum lane count -- a larger pool
        # here would just mean the excess lanes permanently fail to connect
        # (429) and sit retrying forever.
        # Applies whether the count came from the environment or was passed
        # explicitly to the constructor -- both are equally capable of
        # exceeding what the relay will actually accept.
        if laneCount < 1 or laneCount > cls._MAX_LANE_COUNT:
            raise WebTunnelConfigurationError(
                f'FFL_WEB_TUNNEL_LANE_COUNT must be between 1 and {cls._MAX_LANE_COUNT}'
            )

        # _MAX_LANE_COUNT is the relay's hard ceiling, not a production
        # recommendation -- every active lane can hold up to roughly
        # INITIAL_WINDOW + RESPONSE_STREAM_HIGH_WATER_MARK (~4.5MB) of
        # in-flight response data on the relay side, on top of a shared,
        # separately-capped buffered-request-body budget
        # (MAX_BUFFERED_REQUEST_BODY_BYTES). At the full 16 lanes that's
        # comfortably enough to threaten the relay's own ~128MB per-instance
        # memory limit once its own runtime overhead and other concurrent
        # requests sharing that instance are accounted for; _RECOMMENDED_MAX_LANE_COUNT
        # leaves much more headroom and is what production should actually
        # run. Not enforced as a hard cap here -- the full range is
        # legitimate for controlled load testing -- but anything above the
        # recommendation is worth a second look, not a silent config change.
        if laneCount > cls._RECOMMENDED_MAX_LANE_COUNT:
            logger.warning(
                'Web tunnel lane count %s exceeds the recommended production value of %s -- '
                'each additional lane adds meaningful per-request memory pressure on the '
                'relay side; intended for controlled load testing, not routine production use.',
                laneCount, cls._RECOMMENDED_MAX_LANE_COUNT,
            )

        return laneCount

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

    # ---- Instance methods -----------------------------------------------------

    def _validateConfiguration(self):
        missingNames = []

        if not self.agentURL:
            missingNames.append('FFL_WEB_TUNNEL_AGENT_URL')

        if not self.publicURL:
            missingNames.append('FFL_WEB_TUNNEL_PUBLIC_URL')

        if not self.secret:
            missingNames.append('tunnel token')

        if not self.tunnelID:
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

        if not self._isValidTunnelID(self.tunnelID):
            raise WebTunnelConfigurationError('tunnel ID must be a visible ASCII header value')

    def getTunnelURL(self):
        return self.publicURL

    # ---- Control connection (drives AsyncTunnelThread's connect()/listen()) --

    async def connect(self):
        try:
            await asyncio.to_thread(self._refreshSecret)
            await asyncio.to_thread(self._connectControlSocket)
            self._startLanePoolOnce()
            return True
        except Exception as e:
            self.lastConnectError = e
            return False

    def _startLanePoolOnce(self):
        """Starts the lane pool exactly once, the first time the control
        connection ever succeeds. From then on each lane manages its own
        lifecycle independently -- later control reconnects never touch it."""
        with self._lanesLock:
            if self._lanesStarted:
                return

            self._lanesStarted = True
            for laneIndex in range(self.laneCount):
                lane = _TunnelLane(self, laneIndex)
                self._lanes.append(lane)
                lane.start()

    def _refreshSecret(self):
        if not callable(self.tokenProvider):
            return

        with self._secretLock:
            if self._skipInitialRefresh:
                self._skipInitialRefresh = False
                self._lastSecretRefreshAt = time.monotonic()
                return

            # Every lane's own connect() calls this too (see
            # _TunnelLane._connect), so a freshly-started pool of N lanes
            # would otherwise call tokenProvider() N+1 times in a burst.
            # Skip if a refresh already happened recently enough that its
            # token is still current -- what actually needs refreshing is
            # the token's own (multi-minute) TTL, not connect-time
            # coincidence between the control connection and every lane.
            if time.monotonic() - self._lastSecretRefreshAt < self._MIN_SECRET_REFRESH_INTERVAL:
                return

            newSecret = self.tokenProvider()
            if not newSecret:
                logger.warning('Token provider returned empty token; keeping existing token')
                return

            if newSecret != self.secret:
                logger.info('Web tunnel token refreshed')

            self.secret = newSecret
            self._lastSecretRefreshAt = time.monotonic()

    def _connectControlSocket(self):
        # graceful=False: whatever the previous self._webSocket was is being
        # torn down specifically because we're about to replace it -- most
        # likely because it's already stale/broken, same reasoning as
        # listen()'s finally block below.
        self._closeWebSocket(graceful=False)

        webSocket = self._performWebSocketUpgrade('_tunnel/agent/connect')
        with self._webSocketLock:
            self._webSocket = webSocket

        self.running = True
        self.connected = True
        self._startHeartbeat()

        logger.info('Web tunnel agent connected: %s%s', self.getTunnelURL(), self.tunnelID)

    def _performWebSocketUpgrade(self, path, extraHeaders=None):
        """Connects a fresh raw socket and performs the RFC6455 HTTP
        upgrade handshake against `path`. Shared by the control connection
        and every data lane -- they differ only in which endpoint they hit
        and, for a lane, its own X-Tunnel-Lane-ID (see `extraHeaders`).

        Every upgrade carries X-Tunnel-Agent-ID so the relay can tell which
        lanes belong to which agent process -- without it, a lane from an
        agent process that's since been replaced (e.g. the CLI restarted)
        could sit in the relay's pool indistinguishable from the current
        one's, and a request handed to it would just fail against a process
        that's already gone.
        """
        parsedURL = urllib.parse.urlparse(urllib.parse.urljoin(self.agentURL, path))
        rawSocket = self._connectSocket(parsedURL, timeout=30)
        try:
            key = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            requestPath = parsedURL.path or '/'
            if parsedURL.query:
                requestPath = f'{requestPath}?{parsedURL.query}'

            host = parsedURL.netloc
            extraHeaderLines = ''.join(f'{name}: {value}\r\n' for name, value in (extraHeaders or {}).items())
            request = (
                f'GET {requestPath} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n'
                'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Key: {key}\r\nAuthorization: Bearer {self.secret}\r\n'
                f'X-Tunnel-Context: {self.tunnelID}\r\nX-Tunnel-Agent-ID: {self.agentInstanceID}\r\n'
                f'{extraHeaderLines}\r\n'
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
                hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()
            ).decode('ascii')

            if headers.get('sec-websocket-accept') != expectedAccept:
                raise ConnectionError('Web tunnel WebSocket upgrade returned an invalid accept key')

            return _WebSocketConnection(rawSocket, self._MAX_WS_OUTSTANDING_BYTES)
        except Exception:
            rawSocket.close()
            raise

    def _connectSocket(self, parsedURL, timeout):
        port = parsedURL.port or http.client.HTTPS_PORT
        proxy = self._getSocks5Proxy()
        rawSocket = self._connectSocks5(*proxy, parsedURL.hostname, port, timeout) if proxy else socket.create_connection(
            (parsedURL.hostname, port), timeout=timeout
        )
        context = ssl.create_default_context()
        if sys.version_info >= (3, 12) and ENABLE_PY312_WORKAROUND:
            # Same workaround bases.Utils.StallResilientAdapter applies to
            # the requests-based upload/download path: Python 3.12 +
            # OpenSSL 3.x has a documented SSLEOFError/stall issue specific
            # to TLS 1.3, and this connection -- one per lane, held open and
            # read from for as long as the lane lives -- is exactly the kind
            # of long-lived TLS connection that issue affects. Forcing TLS
            # 1.2 avoids it entirely; this control/lane WebSocket has no
            # other reason to require 1.3.
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        return context.wrap_socket(rawSocket, server_hostname=parsedURL.hostname)

    async def listen(self):
        cycleStartedAt = time.monotonic()
        peerClosed = False
        try:
            peerClosed = await asyncio.to_thread(self._listenControlSocket)
        except ConnectionError as e:
            if self.running:
                logger.warning('Web tunnel control connection ended: %s', e)
        finally:
            self._closeWebSocket(graceful=peerClosed)
            self.connected = False

        if not self.running:
            return

        # Deliberately uptime-only, not "or peerClosed": a peer that sends a
        # clean close every few seconds is just as much a storm as a broken
        # transport failing outright.
        if time.monotonic() - cycleStartedAt >= self._MIN_HEALTHY_CONNECTION_DURATION:
            self._backoff = 1
            return

        # AsyncTunnelThread's outer loop reconnects the instant this
        # coroutine returns, with no delay of its own for this path -- so
        # without this, a control connection that keeps failing immediately
        # after each reconnect gets hammered in a zero-delay retry storm.
        delay = self._backoff
        jittered = random.uniform(delay / 2, delay) if delay > 0 else 0
        
        logger.warning('Web tunnel control connection keeps failing immediately after reconnect; waiting %.1fs before retrying', jittered)
        
        # stop() flips self.running from another thread with nothing to
        # cancel this coroutine's sleep, so wait in short slices rather than
        # one long asyncio.sleep.
        remaining = jittered
        while remaining > 0 and self.running:
            step = min(0.5, remaining)
            await asyncio.sleep(step)
            remaining -= step
            
        self._backoff = min(delay * 2, self._MAX_RECONNECT_BACKOFF)

    def _listenControlSocket(self):
        """Returns True if the peer closed cleanly (WebSocket close frame).
        The control connection carries no application frames -- only raw
        ping/pong keeps it alive -- so anything else received is simply
        ignored rather than treated as a protocol error."""
        return self._runReceiveLoop()

    def _startHeartbeat(self):
        self._startHeartbeatThread(self._onHeartbeatFailure, 'control', 'web-tunnel-control-heartbeat')

    def _onHeartbeatFailure(self, failedWebSocket):
        self._poisonWebSocket(failedWebSocket)
        self.connected = False

    # ---- HTTP relay helpers shared by every lane -----------------------

    def _getLocalRequestPath(self, requestPath):
        if self.localPathPrefix is None:
            return requestPath

        path, separator, query = requestPath.partition('?')
        encodedTunnelID = urllib.parse.quote(self.tunnelID, safe='%._~-')        
        tunnelPathPrefix = f'/{encodedTunnelID}'
        if path == tunnelPathPrefix:
            relativePath = '/'
        elif path.startswith(f'{tunnelPathPrefix}/'):
            relativePath = path[len(tunnelPathPrefix):]
        else:
            return requestPath

        if self.localPathPrefix == '/':
            localPath = relativePath
        elif relativePath == '/':
            localPath = f'{self.localPathPrefix}/'
        else:
            localPath = f'{self.localPathPrefix}{relativePath}'

        return f'{localPath}?{query}' if separator else localPath

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

        connection.request(requestData['method'], self._getLocalRequestPath(requestData['path']), body=body, headers=headers)

        return connection.getresponse()

    def _filterRequestHeaders(self, headerItems):
        headers = {}
        for headerName, headerValue in headerItems:
            normalizedName = headerName.lower()

            if normalizedName not in self._HOP_BY_HOP_HEADERS and normalizedName not in ('accept-encoding', 'content-length', 'host'):
                headers[headerName] = headerValue

        return headers

    # ---- Frame encoding shared by control and every lane -----------------

    def _decodeFrame(self, packet):
        if len(packet) < self._FRAME_HEADER.size:
            raise ConnectionError('Web tunnel frame is truncated')

        version, frameType, epoch, payloadLength = self._FRAME_HEADER.unpack(packet[:self._FRAME_HEADER.size])
        payload = packet[self._FRAME_HEADER.size:]
        if version != self._PROTOCOL_VERSION or payloadLength != len(payload):
            raise ConnectionError('Web tunnel frame is invalid')

        return frameType, epoch, payload

    # ---- Shutdown ----------------------------------------------------------

    def stop(self):
        self.running = False
        self._closeWebSocket()

        with self._lanesLock:
            lanes = list(self._lanes)

        for lane in lanes:
            lane.stop()

    async def shutdown(self):
        await asyncio.to_thread(self.stop)
