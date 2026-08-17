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
Python implementation of secure bore client that connects via HTTPS only.
Windows and Unix compatible with concurrent connection handling.
For security, all connections are forced to use HTTPS/TLS encryption.
"""

import asyncio
import json
import os
import socket
import ssl
import threading
import traceback
import uuid

from hashlib import sha256
from hmac import HMAC

from bases.Kernel import getLogger

from . import Socks5ProxySupport

# Configure logging
logger = getLogger(__name__)

# Constants from the original Rust implementation
HTTPS_PORT = 443 # Port used when in HTTPS mode
MAX_FRAME_LENGTH = 256
NETWORK_TIMEOUT = 60 # seconds
LOCAL_CONNECT_RETRY_TIMEOUT = 5.0 # seconds
LOCAL_CONNECT_RETRY_INTERVAL = 0.1 # seconds
DEFAULT_CONTROL_IDLE_TIMEOUT = int(os.getenv("BORE_CONTROL_IDLE_TIMEOUT", "90"))

BORE_DEBUG = os.getenv('BORE_DEBUG', False)
BORE_VERBOSE = os.getenv('BORE_VERBOSE', False)

class _SSLContextCache:
    # ssl.create_default_context() loads the system trust store on first call.
    # Cost varies by platform (~200ms Windows cert store, ~50ms Linux/macOS CA bundle).
    # Caching it here means the cost is paid once per process, and warmSSLContext()
    # can pay it early from a background thread.
    _ctx = None
    _lock = threading.Lock()

    @classmethod
    def get(cls):
        if cls._ctx is None:
            with cls._lock:
                if cls._ctx is None:
                    cls._ctx = ssl.create_default_context()
        return cls._ctx

    @classmethod
    def warm(cls):
        cls.get()


def warmSSLContext():
    """Pre-create the shared SSL context. Call from a background thread to pay the cost early."""
    _SSLContextCache.warm()




class Authenticator:
    """Authentication wrapper similar to the Rust implementation."""

    def __init__(self, secret):
        # Hash the secret first like in the original implementation
        hashedSecret = sha256(secret.encode()).digest()
        self.hmac = HMAC(key=hashedSecret, digestmod=sha256)
        logger.debug("Authenticator initialized with hashed secret")

    def answer(self, challengeUuid):
        """Generate a reply message for a challenge."""
        hmacCopy = self.hmac.copy()
        hmacCopy.update(challengeUuid.bytes)
        return hmacCopy.hexdigest()


class DelimitedStream:
    """Class for handling null-delimited JSON messages."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.readBuffer = bytearray()
        self._lock = asyncio.Lock() # Add a lock to prevent concurrent reads

    async def send(self, message):
        """Send a message as JSON with null terminator."""
        try:
            jsonData = json.dumps(message)
            data = jsonData.encode() + b'\0'
            logger.debug("Sending: %s", jsonData)
            self.writer.write(data)
            await self.writer.drain()
        except Exception as e:
            logger.error("Error sending message: %s", e)
            raise

    async def _readFrame(self):
        """Read a null-delimited frame."""
        try:
            # Use a lock to prevent concurrent reads on the same reader
            async with self._lock:
                while b'\0' not in self.readBuffer:
                    # logger.debug("Waiting for data...")
                    chunk = await self.reader.read(1024)
                    if not chunk:
                        logger.debug("End of stream reached")
                        return None
                    # logger.debug(f"Received chunk of {len(chunk)} bytes")
                    self.readBuffer.extend(chunk)

                # Extract the frame
                idx = self.readBuffer.find(b'\0')
                if idx > MAX_FRAME_LENGTH:
                    logger.error("Frame too large: %s bytes", idx)
                    raise ValueError(f"Frame exceeded MAX_FRAME_LENGTH: {idx}")

                frame = bytes(self.readBuffer[:idx])
                self.readBuffer = self.readBuffer[idx + 1:]
                # logger.debug(f"Extracted frame of {len(frame)} bytes")
                return frame
        except Exception as e:
            logger.error("Error reading frame: %s", e)
            raise

    async def recv(self):
        """Receive and parse a JSON message."""
        try:
            frame = await self._readFrame()
            if frame is None:
                logger.debug("No frame received")
                return None

            # logger.debug(f"Raw received frame: {frame}")

            try:
                parsed = json.loads(frame)
                # logger.debug(f"Parsed message: {parsed}")
                return parsed
            except json.JSONDecodeError as e:
                logger.error("JSON decode error: %s", e)
                logger.error("Raw frame: %s", frame)
                raise

        except Exception as e:
            logger.error("Error receiving message: %s", e)
            logger.error(traceback.format_exc())
            raise

    async def recvWithTimeout(self, timeout=NETWORK_TIMEOUT):
        """Receive a message with timeout."""
        try:
            return await asyncio.wait_for(self.recv(), timeout)
        except asyncio.TimeoutError:
            logger.error("Timeout after %s seconds waiting for response", timeout)
            raise TimeoutError(f"Timed out waiting for response after {timeout} seconds")


class ControlConnectionStaleError(ConnectionError):
    """Raised when the control channel stops delivering frames for too long."""


class BoreClient(Socks5ProxySupport):
    """Python implementation of the bore client."""

    def __init__(
        self,
        localhost,
        localPort,
        remoteHost,
        remotePort=0,
        secret=None,
        tokenProvider=None,
        bufferSize=65536,
        verbose=False,
        debug=True,
        useHttps=False, # Ignored - always uses HTTPS for security
        proxyConfig=None, # Optional proxy configuration dict from parseProxyString()
    ):
        self.localhost = localhost
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.requestedPort = remotePort
        self.remotePort = None # Will be assigned by server
        self.authenticator = None
        self.controlConnection = None
        self.running = False
        # Last exception (or synthesized one) that caused connect() to return False.
        # connect() logs-and-swallows every failure so its retry loop stays simple;
        # this lets callers that need to raise (e.g. AsyncTunnelThread) report the
        # real cause instead of a bare "failed" boolean.
        self.lastConnectError = None
        self.bufferSize = bufferSize
        self.connectionLock = asyncio.Lock() # Add a lock for connection handling
        self.runningTasks = set() # Task management per instance
        self.proxyConfig = proxyConfig # Store proxy configuration
        self.tokenProvider = tokenProvider
        self.controlIdleTimeout = max(0, DEFAULT_CONTROL_IDLE_TIMEOUT)

        # Force HTTPS mode for security (ignores useHttps parameter)
        self.useHttps = True # Always True for security

        # Setup secure control host and port (always HTTPS)
        self.controlHost = f"0.{remoteHost}"
        self.controlPort = HTTPS_PORT

        # Use environment variable for secret if not provided
        secret = secret or os.environ.get("BORE_SECRET")
        self._setSecret(secret)

        # Skip the first _refreshSecret() call when a fresh secret was supplied at
        # construction time — avoids an unnecessary extra token round-trip on the
        # initial connect().  Subsequent reconnects will refresh normally.
        self._skipInitialRefresh = self.secret is not None

        # Use the shared SSL context (created once; Windows cert store load ~200ms).
        self._sslCtx = _SSLContextCache.get()

        # Pre-connected TCP socket injected by the prefetch path to skip the TCP
        # RTT inside connect().  Consumed once; reconnects do a fresh TCP connect.
        self._preTcpSocket = None

        if not self.secret:
            logger.warning("No secret provided and BORE_SECRET environment variable not set")

    async def _recvControlMessage(self):
        """
        Receive one control message, with an idle timeout if enabled.

        When the control channel silently wedges, we prefer to break out to the
        reconnect loop instead of waiting forever on recv().
        """
        if self.controlIdleTimeout > 0:
            try:
                return await asyncio.wait_for(self.controlConnection.recv(), self.controlIdleTimeout)
            except asyncio.TimeoutError as e:
                raise ControlConnectionStaleError(
                    f"Control connection idle for {self.controlIdleTimeout} seconds"
                ) from e

        return await self.controlConnection.recv()

    async def _closeControlConnection(self, forceAbort=False):
        if not self.controlConnection or not hasattr(self.controlConnection, 'writer'):
            return

        writer = self.controlConnection.writer
        transport = getattr(writer, "transport", None)

        try:
            if forceAbort and transport is not None and hasattr(transport, "abort"):
                transport.abort()
                return

            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5)
        except Exception as e:
            logger.debug("Error closing control connection: %s", e)

    def _setSecret(self, secret):
        self.secret = secret
        self.authenticator = Authenticator(secret) if secret else None

    def _refreshSecret(self):
        if not callable(self.tokenProvider):
            return

        if self._skipInitialRefresh:
            self._skipInitialRefresh = False
            return

        newSecret = self.tokenProvider()
        if not newSecret:
            logger.warning("Token provider returned empty token; keeping existing token")
            return

        if newSecret != self.secret:
            logger.info("Tunnel token refreshed")

        self._setSecret(newSecret)

    def addRunningTask(self, task):
        """Add a task to the running tasks set with proper cleanup callback."""
        self.runningTasks.add(task)
        task.add_done_callback(self.removeRunningTask)

    @staticmethod
    def _isLocalConnectRetryable(error):
        """Return True when local loopback connection failure is transient."""
        if isinstance(error, ConnectionRefusedError):
            return True

        if isinstance(error, OSError):
            # Linux/macOS: 111/61, Windows: 10061
            return error.errno in (111, 61, 10061)

        return False

    async def _connectLocalService(self):
        """
        Connect to local service with short retries.
        This absorbs startup races where the tunnel receives traffic before
        the local HTTP server starts listening.
        """
        deadline = asyncio.get_running_loop().time() + LOCAL_CONNECT_RETRY_TIMEOUT
        lastError = None

        while True:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(self.localhost, self.localPort),
                    NETWORK_TIMEOUT,
                )
            except Exception as e:
                lastError = e
                if not self._isLocalConnectRetryable(e):
                    raise

                if asyncio.get_running_loop().time() >= deadline:
                    raise lastError

                await asyncio.sleep(LOCAL_CONNECT_RETRY_INTERVAL)

    def removeRunningTask(self, task):
        """Safely remove a task from running tasks set."""
        try:
            self.runningTasks.remove(task)
        except KeyError as e:
            # Task was already removed or set was cleared during shutdown
            logger.debug("Task already removed from running tasks: %s", e)

    @classmethod
    def openTcpConnectionBlocking(cls, host, port, proxyConfig=None, timeout=NETWORK_TIMEOUT):
        """Establish a TCP connection (optionally via SOCKS5 proxy) in blocking mode.

        Returns a socket ready for asyncio adoption via open_connection(sock=..., ssl=...).
        Returns None on failure so callers can fall back to a normal connect().
        """
        try:
            proxy = cls.resolveSocks5Proxy(proxyConfig)
            if proxy:
                return cls._connectViaSocks5Blocking(*proxy, host, port, timeout)

            return socket.create_connection((host, port), timeout=timeout)
        except Exception as e:
            logger.debug(f"TCP pre-connect to {host}:{port} failed: {e}")
            return None

    def injectPreTcpSocket(self, sock):
        """Inject a pre-connected TCP socket to skip the TCP RTT in connect()."""
        self._preTcpSocket = sock

    @classmethod
    def _connectViaSocks5Blocking(cls, proxyHost, proxyPort, destHost, destPort, timeout):
        """
        Establish connection to destHost:destPort via SOCKS5 proxy using blocking I/O.
        This function runs in a thread executor to avoid blocking the event loop.

        Args:
            proxyHost: SOCKS5 proxy host
            proxyPort: SOCKS5 proxy port
            destHost: Destination host to connect to
            destPort: Destination port to connect to
            timeout: Connection timeout in seconds

        Returns a non-blocking socket connected to destHost:destPort.
        Raises ConnectionError (an OSError subclass) if the SOCKS5 handshake fails.
        """
        logger.info(f"Connecting to {destHost}:{destPort} via SOCKS5 proxy {proxyHost}:{proxyPort}")
        sock = cls._connectSocks5(proxyHost, proxyPort, destHost, destPort, timeout, nonBlocking=True)
        logger.debug("SOCKS5 connection established to %s:%s", destHost, destPort)
        return sock

    async def _openTlsConnection(self, host, port, sslCtx, serverHostname=None, timeout=None):
        """
        Establish TLS connection to host:port, optionally via SOCKS5 proxy.

        Priority order for proxy configuration:
        1. self.proxyConfig (from --proxy CLI argument)
        2. FFL_TUNNEL_SOCKS5 environment variable
        3. No proxy (direct connection)

        Returns (reader, writer) tuple compatible with asyncio streams.
        """
        proxy = self._getSocks5Proxy()
        proxyHost, proxyPort = proxy if proxy else (None, None)
        if proxy:
            logger.debug("Using SOCKS5 proxy: %s:%s", proxyHost, proxyPort)

        if not proxyHost:
            # No proxy configured - use standard asyncio connection
            return await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=sslCtx,
                    server_hostname=serverHostname,
                ),
                timeout,
            )

        # SOCKS5 proxy configured - establish connection via proxy
        loop = asyncio.get_running_loop()

        # Run blocking SOCKS5 handshake in thread pool to avoid blocking event loop
        sock = await loop.run_in_executor(
            None,
            self._connectViaSocks5Blocking,
            proxyHost,
            proxyPort,
            host,
            port,
            timeout,
        )

        # Wrap existing socket with TLS and create asyncio streams
        return await asyncio.wait_for(
            asyncio.open_connection(
                sock=sock,
                ssl=sslCtx,
                server_hostname=serverHostname,
            ),
            timeout,
        )

    async def connect(self):
        """
        Establish secure control channel via TLS to 0.<domain>:443
        For security, all connections use HTTPS/TLS encryption.
        Optionally uses SOCKS5 proxy if FFL_TUNNEL_SOCKS5 is configured.
        """
        self.lastConnectError = None
        try:
            try:
                self._refreshSecret()
            except Exception as e:
                if not self.secret:
                    logger.error(f"Failed to refresh tunnel token before connect: {e}")
                    logger.error(traceback.format_exc())
                    self.lastConnectError = e
                    return False

                logger.warning(f"Failed to refresh tunnel token, reusing existing token: {e}")

            logger.info(f"Connecting to {self.controlHost}:{self.controlPort}...")

            # 1. Establish secure TLS connection (always HTTPS, optionally via SOCKS5).
            #    When a pre-connected TCP socket was injected by the prefetch path,
            #    adopt it directly (skipping the TCP RTT) and only do the TLS handshake.
            try:
                preSock = self._preTcpSocket
                self._preTcpSocket = None  # consume once; reconnects start fresh
                if preSock is not None:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            sock=preSock,
                            ssl=self._sslCtx,
                            server_hostname=self.controlHost,
                        ),
                        NETWORK_TIMEOUT,
                    )
                    logger.debug("Using pre-connected TCP socket (TCP RTT already paid)")
                else:
                    reader, writer = await self._openTlsConnection(
                        self.controlHost,
                        self.controlPort,
                        self._sslCtx,
                        serverHostname=self.controlHost,
                        timeout=NETWORK_TIMEOUT,
                    )
            except asyncio.TimeoutError as e:
                logger.error(f"Connect timed-out after {NETWORK_TIMEOUT}s")
                self.lastConnectError = e
                return False
            except Exception as e:
                logger.error(f"Failed to establish control TLS connection: {type(e).__name__}: {e}")
                logger.error(traceback.format_exc())
                self.lastConnectError = e
                return False

            # 2. Wrap as DelimitedStream
            self.controlConnection = DelimitedStream(reader, writer)

            # 3. Authenticate (if secret is configured)
            if self.authenticator:
                await self._authenticate(self.controlConnection)

            # 4. Send Hello message
            hello = {"Hello": self.requestedPort}
            await self.controlConnection.send(hello)

            # 5. Wait for server to assign public port
            while True:
                resp = await self.controlConnection.recvWithTimeout()
                if not resp:
                    logger.error("Server closed connection unexpectedly")
                    self.lastConnectError = ConnectionError("Server closed connection unexpectedly")
                    return False

                if "Hello" in resp:
                    self.remotePort = resp["Hello"]
                    url = self.getTunnelURL()
                    logger.info(f"Tunnel ready => {url}")
                    return True

                if "Error" in resp:
                    logger.error(f"Server error: {resp['Error']}")
                    self.lastConnectError = ConnectionError(f"Server error: {resp['Error']}")
                    return False

        except Exception as e:
            logger.error(f"connect() fatal error: {e}")
            logger.error(traceback.format_exc())
            self.lastConnectError = e
            return False

    async def _authenticate(self, stream, role="ctrl", port=None):
        """Handle the authentication challenge-response protocol."""
        try:
            # Wait for the challenge
            logger.debug("Waiting for authentication challenge...")
            response = await stream.recvWithTimeout()
            logger.debug("Received response for auth: %s", response)

            if not response:
                logger.error("No response received when expecting challenge")
                raise ConnectionError("Expected authentication challenge, but no response received")

            if "Challenge" not in response:
                logger.error(f"Unexpected response during authentication: {response}")
                raise ConnectionError(f"Expected authentication challenge, but received: {response}")

            # Get the challenge UUID
            challengeUuidStr = response["Challenge"]
            logger.debug("Received challenge UUID: %s", challengeUuidStr)

            try:
                challengeUuid = uuid.UUID(challengeUuidStr)
            except ValueError as e:
                logger.error("Invalid UUID format: %s", challengeUuidStr)
                raise ConnectionError(f"Invalid UUID format in challenge: {e}")

            # Calculate the response
            authResponse = self.authenticator.answer(challengeUuid)
            logger.debug("Generated authentication response (length %s)", len(authResponse))

            # Build authentication message with token
            authMessage = {"Authenticate": authResponse, "token": self.secret, "role": role}

            # Add port for data connections
            if role == "data" and port is not None:
                authMessage["port"] = str(port)

            # Send the authentication response
            logger.debug("Sending authentication response...")
            await stream.send(authMessage)
            logger.debug("Authentication response sent")
        except Exception as e:
            logger.error(f"Authentication error: {type(e).__name__}: {e}")
            logger.error(traceback.format_exc())
            raise

    def _getConnectionHost(self, connectionId: str | None = None) -> str:
        """
        Get the host name for secure HTTPS connections to the bore server.        
        """
        # All control and data channels connect to 0.<domain> (HTTPS only)
        return self.controlHost # equivalent to f"0.{self.remoteHost}"

    def _getConnectionPort(self):
        """Get the port for secure HTTPS connections (always 443)."""
        # Always use HTTPS port for security
        return HTTPS_PORT

    async def _handleConnection(self, connectionId):
        """Handle one incoming stream (identified by UUID) from the server."""
        try:
            host = self._getConnectionHost(connectionId)
            port = self._getConnectionPort()
            logger.info(f"Data-channel {connectionId}: connecting to {host}:{port}")

            # 1. Establish secure data channel connection (always HTTPS, optionally via SOCKS5)
            try:
                remoteReader, remoteWriter = await self._openTlsConnection(
                    host,
                    port,
                    self._sslCtx,
                    serverHostname=host,
                    timeout=NETWORK_TIMEOUT,
                )
            except TimeoutError as e:
                logger.warning(f"Failed to open data channel {connectionId}: timed out connecting to {host}:{port}")
                return
            except Exception as e:
                logger.error(f"Failed to open data channel {connectionId}: {type(e).__name__}: {e}")
                logger.error(traceback.format_exc())
                return

            remoteConn = DelimitedStream(remoteReader, remoteWriter)

            # 2. Authenticate (if secret is provided)
            if self.authenticator:
                await self._authenticate(remoteConn, role="data", port=self.remotePort)

            # 3. Tell bore-server "I accept this connection"
            await remoteConn.send({"Accept": connectionId})
            logger.info(f"Sent Accept for {connectionId}")

            # 4. Connect to local service
            try:
                localReader, localWriter = await self._connectLocalService()
                logger.info(f"Local service connected at {self.localhost}:{self.localPort}")
            except Exception as e:
                logger.error(f"Local connect error: {e}")
                remoteWriter.close()
                await remoteWriter.wait_closed()
                return

            # 5. Bidirectional proxy
            await self._proxyConnection(remoteReader, remoteWriter, localReader, localWriter, connectionId)

        except Exception as e:
            logger.error(f"Error handling connection {connectionId}: {e}")
            logger.error(traceback.format_exc())

    async def _proxyConnection(self, remoteReader, remoteWriter, localReader, localWriter, connectionId):
        """Proxy data between the local service and the remote connection."""

        async def pipe(reader, writer, name):
            try:
                totalBytes = 0
                while True:
                    data = await reader.read(self.bufferSize)
                    if not data:
                        logger.debug("%s pipe closed by peer", name)
                        break
                    totalBytes += len(data)
                    writer.write(data)
                    await writer.drain()
                logger.debug("%s pipe closed after transferring %s bytes", name, totalBytes)
            except Exception as e:
                logger.debug("%s pipe error: %s: %s", name, type(e).__name__, e)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug("Exception during connection cleanup: %s", e)

        # Start two tasks for bidirectional proxying
        logger.debug("Starting bidirectional proxy for connection %s", connectionId)
        remoteToLocal = asyncio.create_task(pipe(remoteReader, localWriter, f"remote→local-{connectionId}"))
        localToRemote = asyncio.create_task(pipe(localReader, remoteWriter, f"local→remote-{connectionId}"))

        self.addRunningTask(remoteToLocal)
        self.addRunningTask(localToRemote)

        try:
            await asyncio.gather(remoteToLocal, localToRemote)
        except Exception as e:
            logger.debug("Proxy error for connection %s: %s: %s", connectionId, type(e).__name__, e)

        logger.debug("Connection %s closed", connectionId)

    async def listen(self):
        """Start listening for connections from the server."""
        self.running = True
        forceAbortControlConnection = False
        try:
            logger.info("Starting to listen for incoming connections")
            while self.running:
                try:
                    message = await self._recvControlMessage()
                    if not message:
                        logger.info("Control connection closed by server")
                        break

                    # logger.debug(f"Received control message: {message}")

                    if "Heartbeat" in message:
                        # Just a heartbeat, no action needed
                        # logger.debug("Received heartbeat")
                        pass
                    elif "Connection" in message:
                        # New connection request
                        connectionId = message["Connection"]
                        logger.info(f"New connection request: {connectionId}")
                        # Handle the connection in a separate task
                        h = asyncio.create_task(self._handleConnection(connectionId))
                        self.addRunningTask(h)

                    elif "Error" in message:
                        logger.error(f"Server error: {message['Error']}")
                    else:
                        logger.warning(f"Unexpected message: {message}")

                except asyncio.CancelledError:
                    logger.info("Listen task cancelled")
                    break
                except ControlConnectionStaleError as e:
                    logger.warning("%s; forcing reconnect", e)
                    forceAbortControlConnection = True
                    break
                except Exception as e:
                    logger.error(f"Error in listen loop: {type(e).__name__}: {e}")
                    logger.error(traceback.format_exc())
                    if isinstance(e, ConnectionError):
                        logger.error("Connection error, breaking listen loop")
                        break
                    # Sleep a bit to avoid tight loop in case of repeated errors
                    await asyncio.sleep(1)

        finally:
            self.running = False
            await self._closeControlConnection(forceAbort=forceAbortControlConnection)
            logger.debug("Client stopped")

    def stop(self):
        """Stop the client."""
        self.running = False

    async def shutdown(self):
        """
        Gracefully shut down the client.
        This method cancels all running background tasks and waits for them to complete.
        """
        self.stop() # Set self.running = False to stop the main listen() loop

        # If the control channel is wedged in recv(), actively abort it so listen()
        # can unwind immediately instead of waiting for an idle timeout or EOF.
        await self._closeControlConnection(forceAbort=True)

        # 1. Get all running tasks to be cancelled.
        # Create a list from the set to avoid issues with changing size during iteration.
        tasksToCancel = list(self.runningTasks)
        if not tasksToCancel:
            return

        # 2. Cancel all running tasks.
        logger.debug("Cancelling %s running tasks...", len(tasksToCancel))
        for task in tasksToCancel:
            task.cancel()

        # 3. Wait for all tasks to finish their cancellation.
        # Using return_exceptions=True prevents one task's exception
        # from stopping the entire gather operation.
        await asyncio.gather(*tasksToCancel, return_exceptions=True)

        logger.debug("All tasks have been cancelled and cleaned up.")

    def getTunnelURL(self):
        """Get the secure tunnel URL (always HTTPS)"""
        if not self.remotePort:
            return None

        # Always return HTTPS URL for security
        return f"https://{self.remotePort}.{self.remoteHost}/"
