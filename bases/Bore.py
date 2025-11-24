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
"""
Python implementation of secure bore client that connects via HTTPS only.
Windows and Unix compatible with concurrent connection handling.
For security, all connections are forced to use HTTPS/TLS encryption.
"""

import asyncio
import json
import os
import ssl
import traceback
import uuid

from hashlib import sha256
from hmac import HMAC

from bases.Kernel import getLogger

# Configure logging
logger = getLogger(__name__)

# Constants from the original Rust implementation
HTTPS_PORT = 443 # Port used when in HTTPS mode
MAX_FRAME_LENGTH = 256
NETWORK_TIMEOUT = 60 # seconds

BORE_DEBUG = os.getenv('BORE_DEBUG', False)
BORE_VERBOSE = os.getenv('BORE_VERBOSE', False)


class Authenticator:
    """Authentication wrapper similar to the Rust implementation."""

    def __init__(self, secret):
        # Hash the secret first like in the original implementation
        hashedSecret = sha256(secret.encode()).digest()
        self.hmac = HMAC(key=hashedSecret, digestmod=sha256)
        logger.debug("Authenticator initialized with hashed secret")

    def answer(self, challenge_uuid):
        """Generate a reply message for a challenge."""
        hmacCopy = self.hmac.copy()
        hmacCopy.update(challenge_uuid.bytes)
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
            logger.debug(f"Sending: {jsonData}")
            self.writer.write(data)
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error sending message: {e}")
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
                    logger.error(f"Frame too large: {idx} bytes")
                    raise ValueError(f"Frame exceeded MAX_FRAME_LENGTH: {idx}")

                frame = bytes(self.readBuffer[:idx])
                self.readBuffer = self.readBuffer[idx + 1:]
                # logger.debug(f"Extracted frame of {len(frame)} bytes")
                return frame
        except Exception as e:
            logger.error(f"Error reading frame: {e}")
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
                logger.error(f"JSON decode error: {e}")
                logger.error(f"Raw frame: {frame}")
                raise

        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            logger.error(traceback.format_exc())
            raise

    async def recvWithTimeout(self, timeout=NETWORK_TIMEOUT):
        """Receive a message with timeout."""
        try:
            return await asyncio.wait_for(self.recv(), timeout)
        except asyncio.TimeoutError:
            logger.error(f"Timeout after {timeout} seconds waiting for response")
            raise TimeoutError(f"Timed out waiting for response after {timeout} seconds")


class BoreClient:
    """Python implementation of the bore client."""

    def __init__(
        self,
        localhost,
        localPort,
        remoteHost,
        remotePort=0,
        secret=None,
        bufferSize=8192,
        verbose=False,
        debug=True,
        useHttps=False, # Ignored - always uses HTTPS for security
    ):
        self.localhost = localhost
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.requestedPort = remotePort
        self.remotePort = None # Will be assigned by server
        self.authenticator = Authenticator(secret) if secret else None
        self.controlConnection = None
        self.running = False
        self.bufferSize = bufferSize
        self.connectionLock = asyncio.Lock() # Add a lock for connection handling
        self.runningTasks = set() # Task management per instance

        # Force HTTPS mode for security (ignores useHttps parameter)
        self.useHttps = True # Always True for security

        # Setup secure control host and port (always HTTPS)
        self.controlHost = f"0.{remoteHost}"
        self.controlPort = HTTPS_PORT

        # Use environment variable for secret if not provided
        secret = secret or os.environ.get("BORE_SECRET")
        self.secret = secret
        if not self.secret:
            logger.warning("No secret provided and BORE_SECRET environment variable not set")

    def addRunningTask(self, task):
        """Add a task to the running tasks set with proper cleanup callback."""
        self.runningTasks.add(task)
        task.add_done_callback(self.removeRunningTask)

    def removeRunningTask(self, task):
        """Safely remove a task from running tasks set."""
        try:
            self.runningTasks.remove(task)
        except KeyError as e:
            # Task was already removed or set was cleared during shutdown
            logger.debug(f"Task already removed from running tasks: {e}")

    async def connect(self):
        """
        Establish secure control channel via TLS to 0.<domain>:443
        For security, all connections use HTTPS/TLS encryption.
        """
        try:
            logger.info(f"Connecting to {self.controlHost}:{self.controlPort}...")

            # 1. Establish secure TLS connection (always HTTPS for security)
            try:
                sslCtx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.controlHost,
                        self.controlPort,
                        ssl=sslCtx,
                        server_hostname=self.controlHost,
                    ),
                    NETWORK_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.error(f"Connect timed-out after {NETWORK_TIMEOUT}s")
                return False
            except Exception as e:
                logger.error(f"TCP connect failed: {type(e).__name__}: {e}")
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
                    return False

                if "Hello" in resp:
                    self.remotePort = resp["Hello"]
                    url = self.getTunnelURL()
                    logger.info(f"Tunnel ready => {url}")
                    return True

                if "Error" in resp:
                    logger.error(f"Server error: {resp['Error']}")
                    return False

        except Exception as e:
            logger.error(f"connect() fatal error: {e}")
            logger.error(traceback.format_exc())
            return False

    async def _authenticate(self, stream, role="ctrl", port=None):
        """Handle the authentication challenge-response protocol."""
        try:
            # Wait for the challenge
            logger.debug("Waiting for authentication challenge...")
            response = await stream.recvWithTimeout()
            logger.debug(f"Received response for auth: {response}")

            if not response:
                logger.error("No response received when expecting challenge")
                raise ConnectionError("Expected authentication challenge, but no response received")

            if "Challenge" not in response:
                logger.error(f"Unexpected response during authentication: {response}")
                raise ConnectionError(f"Expected authentication challenge, but received: {response}")

            # Get the challenge UUID
            challengeUuidStr = response["Challenge"]
            logger.debug(f"Received challenge UUID: {challengeUuidStr}")

            try:
                challenge_uuid = uuid.UUID(challengeUuidStr)
            except ValueError as e:
                logger.error(f"Invalid UUID format: {challengeUuidStr}")
                raise ConnectionError(f"Invalid UUID format in challenge: {e}")

            # Calculate the response
            authResponse = self.authenticator.answer(challenge_uuid)
            logger.debug(f"Generated authentication response (length {len(authResponse)})")

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

            # 1. Establish secure data channel connection (always HTTPS)
            try:
                sslCtx = ssl.create_default_context()
                remoteReader, remoteWriter = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=sslCtx, server_hostname=host),
                    NETWORK_TIMEOUT,
                )
            except Exception as e:
                logger.error(f"Failed to open data channel {connectionId}: {e}")
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
                localReader, localWriter = await asyncio.wait_for(
                    asyncio.open_connection(self.localhost, self.localPort),
                    NETWORK_TIMEOUT,
                )
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
                        logger.debug(f"{name} pipe closed by peer")
                        break
                    totalBytes += len(data)
                    writer.write(data)
                    await writer.drain()
                logger.debug(f"{name} pipe closed after transferring {totalBytes} bytes")
            except Exception as e:
                logger.debug(f"{name} pipe error: {type(e).__name__}: {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Exception during connection cleanup: {e}")

        # Start two tasks for bidirectional proxying
        logger.debug(f"Starting bidirectional proxy for connection {connectionId}")
        remoteToLocal = asyncio.create_task(pipe(remoteReader, localWriter, f"remote→local-{connectionId}"))
        localToRemote = asyncio.create_task(pipe(localReader, remoteWriter, f"local→remote-{connectionId}"))

        self.addRunningTask(remoteToLocal)
        self.addRunningTask(localToRemote)

        try:
            await asyncio.gather(remoteToLocal, localToRemote)
        except Exception as e:
            logger.debug(f"Proxy error for connection {connectionId}: {type(e).__name__}: {e}")

        logger.debug(f"Connection {connectionId} closed")

    async def listen(self):
        """Start listening for connections from the server."""
        self.running = True
        try:
            logger.info("Starting to listen for incoming connections")
            while self.running:
                try:
                    message = await self.controlConnection.recv()
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
            if self.controlConnection and hasattr(self.controlConnection, 'writer'):
                try:
                    self.controlConnection.writer.close()
                    await self.controlConnection.writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing control connection: {e}")
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

        # 1. Get all running tasks to be cancelled.
        # Create a list from the set to avoid issues with changing size during iteration.
        tasksToCancel = list(self.runningTasks)
        if not tasksToCancel:
            return

        # 2. Cancel all running tasks.
        logger.debug(f"Cancelling {len(tasksToCancel)} running tasks...")
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
