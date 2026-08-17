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

import asyncio
import json
import sys
import threading
import uuid
import concurrent.futures
import os
import time

from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Callable

import requests

from aiortc import (RTCConfiguration, RTCDataChannel, RTCIceServer, RTCPeerConnection, RTCSessionDescription)
from aiortc.sdp import candidate_from_sdp

try:
    from aiortc_native_sctp import install_native_sctp
    install_native_sctp()
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.debug('Unable to use aiortc_native_sctp: {e}')

from bases.Checksum import DEFAULT_CHECKSUM_ALGORITHM
from bases.Kernel import getLogger, FFLEvent, StorageLocator, Throttler
from bases.Utils import ONE_MB, formatSize, getEnv
from bases.Progress import Progress
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.Readers import FolderChangedException, StdinHandoffTakenOver
from bases.I18n import _

# Setup logging
logger = getLogger(__name__)

# Custom exception for WebRTC connection timeout
class WebRTCConnectionTimeout(Exception):
    """Raised when WebRTC connection establishment times out"""
    pass


class WebRTCDataChannelTimeout(WebRTCConnectionTimeout):
    """Raised when a connected WebRTC peer does not open its data channel."""
    pass


class WebRTCFallbackError(RuntimeError):
    """Carries the output offset when WebRTC hands a download to HTTP."""

    def __init__(self, error: Exception, resumePosition: int):
        super().__init__(str(error))
        self.resumePosition = resumePosition


# Custom exception for WebRTC disabled by server policy
class WebRTCDisabledError(Exception):
    """Raised when WebRTC is disabled by server policy (e.g., --force-relay for licensed users)"""

    def __init__(self, reason="WebRTC connections are disabled by server policy"):
        self.reason = reason
        super().__init__(reason)


# Chrome/Edge local connection sleep delay (seconds) - "3 ticks trick" to avoid buffer issues
# https://github.com/aiortc/aioice/issues/58
CHROME_EDGE_LOCAL_SLEEP_DELAY = getEnv('WEBRTC_CHROME_EDGE_LOCAL_SLEEP_DELAY', 0.047)
# Sleep once every N bytes to avoid excessive sleeping (default: TRANSFER_CHUNK_SIZE for original behavior)
CHROME_EDGE_LOCAL_SLEEP_INTERVAL = getEnv('WEBRTC_CHROME_EDGE_LOCAL_SLEEP_INTERVAL', TRANSFER_CHUNK_SIZE)

# WebRTC connection idle timeout configuration (seconds)
# Heartbeat idle timeout: How long to wait without heartbeat before considering connection stale
# Max wait for START: Hard upper limit to prevent infinite waiting for START signal
# 5 minutes - generous for background tab throttling
HEARTBEAT_IDLE_TIMEOUT = getEnv('WEBRTC_HEARTBEAT_IDLE_TIMEOUT', 5 * 60)
# 2 hours - optional hard limit to prevent infinite waiting
MAX_WAIT_FOR_START = getEnv('WEBRTC_MAX_WAIT_FOR_START', 2 * 60 * 60)
# Send-buffer drain timeout: how long to wait for bufferedamountlow before
# treating an active WebRTC transfer as stalled. This prevents indefinite hangs
# when the data channel stays open but stops draining.
WEBRTC_SEND_BUFFER_DRAIN_TIMEOUT = getEnv('WEBRTC_SEND_BUFFER_DRAIN_TIMEOUT', 60)

# Without winloop, Edge will fail to use WebRTC, it will cause consent query timeout after few seconds.
# It speeds up a lot on Firefox, but slow down a little on Chrome/Edge.
if sys.platform == "win32":
    # Please "import winloop._noop" rather than "import winloop" here,
    # or it will raise "No module named winloop" error.
    # https://github.com/Vizonex/Winloop/issues/9
    import winloop._noop # pylint: disable=import-error
    winloop.install()
    assert isinstance(asyncio.get_event_loop_policy(), winloop.EventLoopPolicy)

class DummyWebRTCManager:
    """
    Lightweight WebRTC Manager that blocks all WebRTC operations.

    Used when WebRTC should be completely disabled (e.g., Tor privacy mode,
    server policy enforcement). Does not inherit from WebRTCManager to avoid
    unnecessary event loop and WebRTC infrastructure overhead.
    """

    def __init__(self, reason=None, *args, **kwargs):
        """
        Initialize DummyWebRTCManager.

        Args:
            reason: Custom error message (optional)
            *args, **kwargs: Ignored (for compatibility with WebRTCManager signature)
        """
        self.reason = reason or _("WebRTC connections are disabled by server policy")

    async def createOffer(self, *args, **kwargs):
        """Block WebRTC offer creation"""
        raise WebRTCDisabledError(self.reason)

    async def setAnswer(self, *args, **kwargs):
        """Block WebRTC answer handling"""
        raise WebRTCDisabledError(self.reason)

    async def addCandidate(self, *args, **kwargs):
        """Block ICE candidate handling"""
        raise WebRTCDisabledError(self.reason)

    async def notifyDownloadComplete(self, *args, **kwargs):
        """Block download completion notification"""
        raise WebRTCDisabledError(self.reason)

    async def sendFile(self, *args, **kwargs):
        """Block file sending"""
        raise WebRTCDisabledError(self.reason)

    async def shutdownWebRTC(self):
        """No-op shutdown (nothing to clean up)"""
        pass

    def close(self):
        """No-op close (no resources to cleanup)"""
        pass


class AsyncLoopExceptionMixin:
    """Mixin to handle unhandled exceptions in asyncio event loop tasks"""

    def _handleLoopException(self, loop, context):
        """Handle exceptions in asyncio event loop tasks

        This method logs unhandled exceptions from asyncio tasks instead of
        printing them to stderr, providing better control over error handling.

        Args:
            loop: The asyncio event loop
            context: Exception context dict with 'exception' and 'message' keys
        """
        # Extract exception and message from context
        exception = context.get('exception')
        message = context.get('message', 'Unhandled exception in async task')

        # Log the exception instead of printing to stderr
        if exception:
            logger.debug(f"{message}: {exception}")
        else:
            logger.debug(f"{message}: {context}")


@dataclass
class ClientInfo:
    browser: str
    domain: str
    protocol: str
    userAgent: str
    isLocalConnection: bool = False
    detectedIp: Optional[str] = None


class ICEServerConfigProvider:
    """Resolves the RTCIceServer list used for WebRTC ICE negotiation.

    Reads `webrtc.json` (StorageLocator search order, current dir first, same
    as tunnels.json) if the user has created one with their own STUN/TURN
    servers. Never writes to disk - if the file is absent, unreadable, or has
    no usable entries, this silently falls back to FFL's built-in public STUN
    servers rather than breaking WebRTC connectivity.
    """

    CONFIG_FILENAME = 'webrtc.json'

    _DEFAULT_ICE_SERVER_ENTRIES = [
        {"urls": "stun:stun.l.google.com:19302"},
        {"urls": "stun:stun.cloudflare.com:3478"},
        {"urls": "stun:stun.nextcloud.com:443"},
        {"urls": "stun:openrelayproject.org:443"},
    ]

    @staticmethod
    def _buildICEServer(entry: Dict[str, Any]) -> RTCIceServer:
        return RTCIceServer(
            urls=entry['urls'],
            username=entry.get('username'),
            credential=entry.get('credential'),
            credentialType=entry.get('credential_type', 'password'),
        )

    def __init__(self, configPath: Optional[str] = None):
        self.configPath = configPath or self._getDefaultConfigPath()
        self.iceServers = self._loadICEServers()

    def _getDefaultConfigPath(self) -> str:
        storageLocator = StorageLocator.getInstance()
        return storageLocator.findConfig(self.CONFIG_FILENAME, prefer=StorageLocator.Location.CURRENT)

    def _loadICEServers(self) -> List[RTCIceServer]:
        if not os.path.exists(self.configPath):
            return self._buildICEServers(self._DEFAULT_ICE_SERVER_ENTRIES)

        try:
            with open(self.configPath, 'r') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to load WebRTC config from {self.configPath}, using built-in defaults: {e}")
            return self._buildICEServers(self._DEFAULT_ICE_SERVER_ENTRIES)

        iceServers = self._buildICEServers(data.get('ice_servers') or [])
        if not iceServers:
            logger.warning(f"No usable ice_servers in {self.configPath}, using built-in defaults")
            return self._buildICEServers(self._DEFAULT_ICE_SERVER_ENTRIES)

        return iceServers

    def _buildICEServers(self, entries: List[Dict[str, Any]]) -> List[RTCIceServer]:
        iceServers = []
        for entry in entries:
            try:
                iceServers.append(self._buildICEServer(entry))
            except (KeyError, TypeError) as e:
                logger.warning(f"Skipping invalid ICE server entry {entry} in {self.configPath}: {e}")

        return iceServers


class WebRTCManager(AsyncLoopExceptionMixin):
    # Transfer chunk size - shared across WebRTC and HTTP downloads
    CHUNK_SIZE = TRANSFER_CHUNK_SIZE

    def __init__(
        self,
        loggerCallback=print,
        downloadCallback=None,
        exceptionCallback=None,
        checksumStore=None,
        shareId=None,
        iceServers: Optional[List[RTCIceServer]] = None,
    ):
        # WebRTC state
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._runLoop, daemon=True)
        self.thread.start()
        self.pcs: Set[RTCPeerConnection] = set()
        self.peers: Dict[str, Tuple[RTCPeerConnection, Optional[ClientInfo], deque]] = {}
        self.loggerCallback = loggerCallback
        self.downloadCallback = downloadCallback
        self.exceptionCallback = exceptionCallback
        self.checksumStore = checksumStore
        self.shareId = shareId

        # Download completion events for each peer
        self.downloadCompleteEvents: Dict[str, threading.Event] = {}

        # Track sendFile tasks for proper cleanup
        self.sendFileTasks: Dict[str, asyncio.Task] = {}

        # Track peer statistics (file size, reported bytes, etc.) for diagnostics
        self.peerStats: Dict[str, Dict[str, Any]] = {}

        # ICE servers configuration - defaults to the user's webrtc.json (or FFL's
        # built-in STUN servers if absent/invalid); pass explicitly to override.
        self.iceServers = iceServers if iceServers is not None else ICEServerConfigProvider().iceServers

    def _runLoop(self):
        """Run asyncio event loop with exception handler"""
        asyncio.set_event_loop(self.loop)
        # Set exception handler from Mixin to catch unhandled exceptions in tasks
        self.loop.set_exception_handler(self._handleLoopException)
        self.loop.run_forever()

    def _handleStartDownloadActions(self, size):
        return

    def _handlePostDownloadActions(self, size):
        if self.downloadCallback:
            self.downloadCallback()

    def runAsync(self, coro, *, wait: bool = True, timeout: float = 15, name: str = "task"):
        """
         Execute coroutine in a synchronous environment and return the result

        - wait=True: block until coroutine finishes, return its result (old behavior)
        - wait=False: schedule coroutine on WebRTC loop, return "OK" immediately
        """
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)

        if not wait:

            def _done(f):
                try:
                    f.result()
                except Exception as e:
                    logger.exception("runAsync(wait=False) task failed (%s): %s", name, e)
                    cb = getattr(self, "exceptionCallback", None)
                    if cb:
                        try:
                            cb(e)
                        except Exception as cbE:
                            logger.exception("exceptionCallback failed: %s", cbE)

            fut.add_done_callback(_done)
            return fut

        try:
            return fut.result(timeout=timeout)
        except Exception as e:
            logger.exception(f"Error in runAsync: {e}")
            raise

    async def createOffer(self, reader, fileSize, getSizeFunc=None, browserHint=None, offset=0, e2eeManager=None):
        # Generate a unique peer ID
        peerId = uuid.uuid4().hex

        config = RTCConfiguration(iceServers=self.iceServers)
        pc = RTCPeerConnection(configuration=config)
        q = deque() # ICE candidate queue
        self.pcs.add(pc)
        # Store peer connection with its ID (initially no client info) and candidate queue
        self.peers[peerId] = (pc, None, q)
        self.peerStats[peerId] = {
            "fileSize": fileSize,
            "offset": offset,
        }

        # Initialize download completion event for this peer
        self.downloadCompleteEvents[peerId] = threading.Event()

        @pc.on("icecandidate")
        async def _onICECandidate(evt):
            # evt.candidate might be None
            cand = evt.candidate
            if cand is None:
                q.append({"candidate": "end-of-candidates"})
            else:
                # Use built-in to_sdp() for consistent serialization
                q.append({
                    "candidate": cand.to_sdp(),
                    "sdpMid": cand.sdpMid,
                    "sdpMLineIndex": cand.sdpMLineIndex,
                })

        # Create data channel and set browser hint immediately
        dc = pc.createDataChannel("filetransfer", ordered=True)

        # Set browser hint right after data channel creation (perfect timing)
        if browserHint and hasattr(pc, 'sctp') and pc.sctp and hasattr(pc.sctp, 'transport'):
            pc.sctp.transport._browser_hint = browserHint
        elif browserHint:
            logger.warning(f"Browser hint '{browserHint}' provided but SCTP transport not available for peer {peerId}")

        # Track sendFile task for proper cleanup
        task = asyncio.create_task(
            self.sendFile(dc, peerId, reader, fileSize, getSizeFunc, offset=offset, e2eeManager=e2eeManager)
        )
        self.sendFileTasks[peerId] = task

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)

        return {"type": pc.localDescription.type, "sdp": pc.localDescription.sdp, "peerId": peerId}

    async def setAnswer(self, data: Dict[str, Any]):
        if "peerId" not in data:
            logger.debug("Missing peerId in answer data")
            return "skip"

        peerId = data.get("peerId")
        peerEntry = self.peers.get(peerId)

        if peerEntry is None:
            logger.debug(f"setAnswer: Unknown peerId: {peerId}")
            return "skip"

        pc, _, q = peerEntry

        # Extract and store client info
        clientInfoData = data.get("clientInfo", {})
        clientInfo = ClientInfo(
            browser=clientInfoData.get("browser", "unknown"),
            domain=clientInfoData.get("domain", "unknown"),
            protocol=clientInfoData.get("protocol", "unknown"),
            userAgent=clientInfoData.get("userAgent", "unknown"),
            isLocalConnection=clientInfoData.get("isLocalConnection", False),
            detectedIp=clientInfoData.get("detectedIp", None)
        )

        # Update peers dict with client info
        self.peers[peerId] = (pc, clientInfo, q)
        
        # isLocalConnection here is the client's pre-connection heuristic, which
        # is now always False (see WebRTC.js detectRTCConnectionType) - the real
        # value only arrives later via the "LOCAL:" data channel message once
        # getStats() resolves (_applyClientLocalConnectionCorrection updates
        # clientInfo.isLocalConnection in place). This log line and the
        # webrtcConnected event below therefore always report "Remote" at
        # answer time; consumers that need the corrected value (e.g. sendFile's
        # Chrome/Edge local-pacing check) read clientInfo.isLocalConnection
        # directly rather than this event's snapshot.
        connectionType = "Local" if clientInfo.isLocalConnection else "Remote"
        logger.info(f"Client info for peer {peerId}: {clientInfo.browser} on {clientInfo.domain} ({connectionType})")

        # Trigger webrtcConnected event
        FFLEvent.webrtcConnected.trigger(
            peerId=peerId,
            connectionType=connectionType.lower(),
            clientInfo={
                'browser': clientInfo.browser,
                'domain': clientInfo.domain,
                'platform': clientInfo.userAgent
            }
        )

        desc = RTCSessionDescription(sdp=data["sdp"], type=data["type"])
        await pc.setRemoteDescription(desc)

        return "OK"

    async def addCandidate(self, data: Dict[str, Any]):
        if "peerId" not in data:
            logger.debug("Missing peerId in candidate data")
            return "skip"

        peerId = data.get("peerId")
        peerEntry = self.peers.get(peerId)

        if peerEntry is None:
            logger.warning(f"addCandidate: Unknown peerId: {peerId}")
            return "skip"

        pc, clientInfo, q = peerEntry

        if pc.connectionState in ("closed", "failed"):
            return "skip"

        candLine = data.get("candidate", "")
        if not candLine or candLine.strip() == "end-of-candidates":
            return "skip"

        ice = candidate_from_sdp(candLine)
        ice.sdpMid = data.get("sdpMid")
        ice.sdpMLineIndex = data.get("sdpMLineIndex")
        try:
            await pc.addIceCandidate(ice)
        except AttributeError as e:
            if 'media' in str(e):
                logger.warning("self.__remoteDescription().media, 'NoneType' object has no attribute 'media' => pass")

        return "OK"

    async def notifyDownloadComplete(self, data: Dict[str, Any]):
        """Handle browser notification that download is complete"""
        if "peerId" not in data:
            logger.debug("Missing peerId in download complete notification")
            return "skip"

        peerId = data.get("peerId")
        peerEntry = self.peers.get(peerId)

        if peerEntry is None:
            logger.debug(f"notifyDownloadComplete: Unknown peerId: {peerId}")
            return "skip"

        # Track reported byte count for diagnostics
        receivedBytesRaw = data.get("receivedBytes")
        if receivedBytesRaw is not None:
            try:
                receivedBytes = int(receivedBytesRaw)
            except (TypeError, ValueError):
                logger.warning(f"Invalid receivedBytes value from peer {peerId}: {receivedBytesRaw}")
            else:
                stats = self.peerStats.setdefault(peerId, {})
                stats["receivedBytes"] = receivedBytes
                expectedSize = stats.get("fileSize")
                if expectedSize is not None:
                    if receivedBytes < expectedSize:
                        deficit = expectedSize - receivedBytes
                        logger.warning(
                            "Peer %s reported %s received (%s missing)",
                            peerId,
                            formatSize(receivedBytes),
                            formatSize(deficit),
                        )
                    else:
                        logger.info(
                            "Peer %s reported %s received (expected %s)",
                            peerId,
                            formatSize(receivedBytes),
                            formatSize(expectedSize),
                        )
                else:
                    logger.info("Peer %s reported %s received", peerId, formatSize(receivedBytes))

        # Signal that download is complete for this peer
        if peerId in self.downloadCompleteEvents:
            self.downloadCompleteEvents[peerId].set()

        return "OK"

    def getCandidates(self, peerId: str):
        peerEntry = self.peers.get(peerId)
        if not peerEntry:
            raise ValueError(f"Unknown peerId: {peerId}")

        pc, clientInfo, q = peerEntry
        if q:
            return q.popleft() # Return and remove the first candidate
        else:
            return None # No candidates available

    async def _cleanupPeer(self, peerId: str):
        """Unified cleanup of peer connection and associated resources"""
        # Remove peer connection and close it
        peerEntry = self.peers.pop(peerId, None)
        if peerEntry:
            pc, clientInfo, q = peerEntry
            await pc.close()
            self.pcs.discard(pc)

        # Clean up completion event and task tracking
        self.downloadCompleteEvents.pop(peerId, None)
        self.sendFileTasks.pop(peerId, None)
        self.peerStats.pop(peerId, None)

    async def _failPeerWithErrorCode(self, dc: RTCDataChannel, peerId: str, errorMsg: str, errorCode: str):
        """
        Unified helper for reporting a fatal peer error and aborting the transfer

        Args:
            dc: Data channel to send error message
            peerId: Peer identifier
            errorMsg: Error message to log and raise
            errorCode: Error code to send to client (e.g., "ERROR:STALE", "ERROR:TIMEOUT",
                "ERROR:E2EE_UNALIGNED_RESUME")
        """
        logger.info(errorMsg)

        try:
            dc.send(errorCode)
        except Exception as e:
            logger.debug(f'Unable to send {errorCode} ({e}) for peer {peerId}')

        await self._cleanupPeer(peerId)
        raise RuntimeError(errorMsg)

    def _applyClientLocalConnectionCorrection(self, peerId: str, message: str):
        """
        Apply the browser's post-connection getStats() local/remote determination.

        The client's pre-connection heuristic (sent in the /answer clientInfo)
        only inspects a throwaway, unconnected RTCPeerConnection's candidates,
        which is unreliable: browsers mask host candidates behind mDNS `.local`
        names by default, so two machines on entirely different networks can
        still produce a `.local` host candidate. Once the real peer connection
        is established, the browser inspects the actual selected candidate pair
        via getStats() and sends the authoritative result here as "LOCAL:true"
        or "LOCAL:false", so the Chrome/Edge local-connection send pacing
        workaround (see sendFile()) reflects the real connection type.
        """
        isLocal = message.split(":", 1)[1].strip().lower() == "true"

        peerEntry = self.peers.get(peerId)
        if not peerEntry:
            logger.debug(f"LOCAL correction for unknown peer {peerId}, ignoring")
            return

        pc, clientInfo, q = peerEntry
        if not clientInfo:
            logger.debug(f"LOCAL correction for peer {peerId} arrived before clientInfo was set, ignoring")
            return

        if clientInfo.isLocalConnection != isLocal:
            logger.info(
                f"Correcting isLocalConnection for peer {peerId}: "
                f"{clientInfo.isLocalConnection} -> {isLocal} (from getStats selected candidate pair)"
            )
            clientInfo.isLocalConnection = isLocal

    async def _waitForSendBufferDrain(self, bufferFlushed, peerId, sentBytes, phase):
        try:
            await asyncio.wait_for(bufferFlushed.wait(), timeout=WEBRTC_SEND_BUFFER_DRAIN_TIMEOUT)
        except asyncio.TimeoutError as e:
            raise RuntimeError(
                f"WebRTC send buffer stalled during {phase} after sending {sentBytes} bytes "
                f"for peer {peerId} (waited {WEBRTC_SEND_BUFFER_DRAIN_TIMEOUT}s)"
            ) from e

    async def sendFile(
        self,
        dc: RTCDataChannel,
        peerId: str,
        reader,
        fileSize: Optional[int],
        getSizeFunc=None,
        offset=0,
        e2eeManager=None
    ):
        startReceived = asyncio.Event()
        lastHeartbeat = time.monotonic()
        checksumSession = None
        shouldCommitChecksum = False

        def onMessage(message):
            nonlocal lastHeartbeat
            # Any message counts as keepalive signal
            lastHeartbeat = time.monotonic()

            if isinstance(message, str):
                if message == "START":
                    logger.debug(f"Received START signal from client for peer {peerId}")
                    startReceived.set()
                elif message == "PING":
                    # Respond to heartbeat
                    try:
                        dc.send("PONG")
                    except Exception as e:
                        logger.debug(f"PONG error {e} for peer {peerId}")
                elif message == "CANCEL":
                    # Optional: support explicit cancellation
                    logger.info(f"Client cancelled preview for peer {peerId}")
                    startReceived.set() # Exit wait loop
                elif message.startswith("LOCAL:"):
                    self._applyClientLocalConnectionCorrection(peerId, message)
                else:
                    logger.debug(f"Unrecognized {message} for peer {peerId}")

        # Set up message handler FIRST (before waiting for open)
        dc.on("message", onMessage)

        # Now wait for channel to open
        while dc.readyState != "open":
            await asyncio.sleep(0.05)

        logger.debug(f"Waiting for START signal (heartbeat mode) for peer {peerId}")
        waitStartBegin = time.monotonic()

        # Wait for START with heartbeat validation
        while not startReceived.is_set():
            now = time.monotonic()

            # Check if client heartbeat is lost (page closed, network disconnected, etc.)
            if now - lastHeartbeat > HEARTBEAT_IDLE_TIMEOUT:
                errorMsg = f"Client heartbeat lost (>{HEARTBEAT_IDLE_TIMEOUT}s) before START for peer {peerId}"
                await self._failPeerWithErrorCode(dc, peerId, errorMsg, "ERROR:STALE")

            # Optional: hard upper limit to prevent server resource exhaustion
            if now - waitStartBegin > MAX_WAIT_FOR_START:
                errorMsg = f"Client never started within {MAX_WAIT_FOR_START}s for peer {peerId}"
                await self._failPeerWithErrorCode(dc, peerId, errorMsg, "ERROR:TIMEOUT")

            await asyncio.sleep(1.0)

        logger.info(f"Client ready to receive file for peer {peerId}")

        pc = None
        clientInfo = None

        # Get client info from peers dict
        peerEntry = self.peers.get(peerId)
        if peerEntry:
            pc, clientInfo, q = peerEntry
            if clientInfo:
                if offset > 0:
                    logger.info(
                        f"Resuming file transfer from offset {offset} for "
                        f"{clientInfo.browser} browser on {clientInfo.domain}"
                    )
                else:
                    logger.info(f"Starting file transfer for {clientInfo.browser} browser on {clientInfo.domain}")
            else:
                if offset > 0:
                    logger.info(f"Resuming file transfer from offset {offset} (client info not yet available)")
                else:
                    logger.info("Starting file transfer (client info not yet available)")
        else:
            raise RuntimeError(f'Invalid peer: {peerId}')

        # Trigger webrtcTransferStarted event
        FFLEvent.webrtcTransferStarted.trigger(
            shareId=self.shareId,
            peerId=peerId,
            fileName=reader.contentName,
            fileSize=fileSize,
            resumeOffset=offset,
            e2eeEnabled=e2eeManager is not None
        )

        try:
            self._handleStartDownloadActions(fileSize)
        except PermissionError as e:
            # File size or other validation error from enhanced handler
            logger.error(f"File transfer validation failed: {e}")
            raise

        # Initialize E2EE stream encryptor if enabled
        streamEncryptor = None
        if e2eeManager:
            # AES-GCM nonces are derived from a chunk index (buildNonce), so a
            # chunk index must always encrypt the same plaintext window -- the
            # session's (contentKey, nonceBase) is generated once and reused
            # across reconnects, so restarting the encryptor's chunk index at
            # 0 on every resume would re-encrypt the offset's plaintext under
            # a chunk index already used for different plaintext earlier (the
            # same nonce-reuse hazard fixed for HTTP Range via
            # CryptoHelper.alignChunkStart/alignChunkEnd). A WebRTC chunk is
            # only ever written to disk after its ciphertext+tag fully
            # decrypts, so a genuine resume offset should always land exactly
            # on a chunkSize boundary; if it doesn't, some other invariant is
            # broken, so fail closed here rather than silently reusing a
            # chunk index for different plaintext. The client already treats
            # any "ERROR:" message as fatal and falls back to HTTP resume.
            if offset > 0 and offset % e2eeManager.chunkSize != 0:
                await self._failPeerWithErrorCode(
                    dc, peerId,
                    f"WebRTC E2EE resume offset {offset} is not aligned to chunkSize "
                    f"{e2eeManager.chunkSize} for peer {peerId}",
                    "ERROR:E2EE_UNALIGNED_RESUME"
                )

            startChunkIndex = offset // e2eeManager.chunkSize
            streamEncryptor = e2eeManager.createWebRTCEncryptor(
                reader.contentName, fileSize, startChunkIndex=startChunkIndex
            )

        if self.checksumStore:
            checksumSession = self.checksumStore.begin(transport='webrtc', e2ee=bool(streamEncryptor))
            shouldCommitChecksum = offset == 0

        bufferFlushed = asyncio.Event()
        bufferFlushed.set()

        def setFlushed():
            bufferFlushed.set()

        dc.on("bufferedamountlow", setFlushed)

        sent = offset # Start counting from offset

        settingsGetter = SettingsGetter.getInstance()
        progress = Progress(
            fileSize,
            sizeFormatter=getSizeFunc,
            loggerCallback=self.loggerCallback,
            useBar=settingsGetter.isCLIMode(),
        )

        # Initialize progress to offset if resuming
        if offset > 0:
            progress.update(offset)

        # Track bytes sent since last sleep for Chrome/Edge optimization
        bytesSinceLastSleep = 0
        progressThrottler = Throttler(interval=1.0)
        transferStartTime = time.time()

        # Avoid blocking event loop
        loop = asyncio.get_running_loop()
        # When E2EE is enabled, the plaintext read size must match
        # e2eeManager.chunkSize -- that's what the encryptor's chunkIndex is
        # computed against (both currently derive from TRANSFER_CHUNK_SIZE,
        # but reading via e2eeManager.chunkSize here removes the assumption
        # that they'll always be kept in sync).
        sendChunkSize = e2eeManager.chunkSize if e2eeManager else self.CHUNK_SIZE
        chunkIter = iter(reader.iterChunks(sendChunkSize, start=offset))

        def _iterNextChunk(it):
            return next(it, None)

        try:
            while True:
                chunk = await loop.run_in_executor(None, _iterNextChunk, chunkIter)
                if chunk is None:
                    break

                # Wait until buffer is acceptable for next packet
                await self._waitForSendBufferDrain(bufferFlushed, peerId, sent, "chunk send")

                # Track plaintext size before encryption
                plaintextSize = len(chunk)

                # Encrypt chunk if E2EE is enabled
                if streamEncryptor:
                    chunk = streamEncryptor.processChunk(chunk)

                if checksumSession:
                    checksumSession.update(chunk)

                dc.send(chunk)
                sent += plaintextSize # Count plaintext bytes, not encrypted bytes
                bufferFlushed.clear()

                if sent == plaintextSize and os.environ.get("WEBRTC_SIMULATE_DELAY_AFTER_FIRST_CHUNK") == "True":
                    await asyncio.sleep(1)

                if clientInfo and clientInfo.browser in ('edge', 'chrome'):
                    # Use isLocalConnection instead of domain check
                    if clientInfo.isLocalConnection:
                        bytesSinceLastSleep += plaintextSize
                        # Apply Chrome/Edge strategy for local connections, 3 ticks trick.
                        # Sleep once every N bytes to avoid excessive sleeping
                        if bytesSinceLastSleep >= CHROME_EDGE_LOCAL_SLEEP_INTERVAL:
                            await asyncio.sleep(CHROME_EDGE_LOCAL_SLEEP_DELAY)
                            bytesSinceLastSleep = 0

                # Progress logging every 5MB or every 2 seconds
                progress.update(sent, extraText=_("P2P direct"))

                # Trigger webrtcTransferProgress event (throttled)
                if progressThrottler.shouldTrigger():
                    currentTime = time.time()
                    percentage = (sent * 100.0 / fileSize) if fileSize and fileSize > 0 else 0
                    duration = currentTime - transferStartTime
                    speed = int(sent / duration) if duration > 0 else 0

                    FFLEvent.webrtcTransferProgress.trigger(
                        shareId=self.shareId,
                        peerId=peerId,
                        bytesTransferred=sent,
                        totalBytes=fileSize,
                        percentage=percentage,
                        speed=speed,
                    )

            # Wait for buffer to drain before sending EOF to prevent race condition
            # where EOF arrives before final chunk on receiver side
            await self._waitForSendBufferDrain(bufferFlushed, peerId, sent, "EOF send")

            if checksumSession and shouldCommitChecksum:
                checksumSession.commit()

            # Send EOF marker
            dc.send("EOF")

            # Final progress update
            progress.update(sent, forceLog=True, extraText=_("P2P direct"), forceFinish=fileSize is None)

            # Trigger webrtcTransferCompleted event
            duration = time.time() - transferStartTime
            averageSpeed = int(sent / duration) if duration > 0 else 0
            FFLEvent.webrtcTransferCompleted.trigger(
                shareId=self.shareId,
                peerId=peerId,
                bytesTransferred=sent,
                duration=duration,
                averageSpeed=averageSpeed
            )

            # Calculate final statistics
            sizeDisplay = getSizeFunc(sent) if getSizeFunc else f"{sent / (ONE_MB):.2f} MB"
            self.loggerCallback(_(
                'Finish transfer {sizeDisplay} for [#{peerId}], '
                'please wait for the recipient to finish downloading before you close the application..\n'
            ).format(sizeDisplay=sizeDisplay, peerId=peerId[:5]))

            # Wait for browser to signal completion or timeout after 30 seconds
            completionEvent = self.downloadCompleteEvents.get(peerId)
            if completionEvent:
                # Wait in a thread to avoid blocking the asyncio loop
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(completionEvent.wait, 30) # 30 second timeout
                    completed = await asyncio.get_event_loop().run_in_executor(None, future.result)

                if not completed:
                    logger.warning(
                        f"Timeout waiting for browser completion signal for peer {peerId}, proceeding with cleanup"
                    )
            else:
                logger.error(f"No completion event found for peer {peerId}, falling back to 5 second delay")
                await asyncio.sleep(5)

            # Clean up peer connection and resources
            await self._cleanupPeer(peerId)
            # Trigger post event (includes tracking and callback)
            self._handlePostDownloadActions(sent)

        except StdinHandoffTakenOver:
            logger.info("WebRTC stdin stream handed off to HTTP fallback")
            await self._cleanupPeer(peerId)
        except Exception as e:
            # Handle all exceptions generically
            logger.exception(f"Error sending file: {e}")

            # Use exception callback to handle the error (calls _handleDownloadExceptionActions)
            if self.exceptionCallback:
                self.exceptionCallback(e)

            # Send ERROR to datachannel
            try:
                dc.send("ERROR")
            except Exception as ee:
                logger.debug(f"Failed to send ERROR message to data channel: {ee}")

            # Clean up peer connection and resources
            await self._cleanupPeer(peerId)
        finally:
            if checksumSession and not checksumSession.isClosed:
                checksumSession.abort()

    async def shutdownWebRTC(self):
        # Cancel all sendFile tasks
        for task in self.sendFileTasks.values():
            if not task.done():
                task.cancel()

        # Wait for all tasks to be cancelled
        if self.sendFileTasks:
            await asyncio.gather(*self.sendFileTasks.values(), return_exceptions=True)

        # Close all peer connections
        pcsToClose = [pc for pc, _, _ in self.peers.values()]
        await asyncio.gather(*[pc.close() for pc in pcsToClose], return_exceptions=True)

        # Clear all tracking dictionaries
        self.pcs.clear()
        self.peers.clear()
        self.downloadCompleteEvents.clear()
        self.sendFileTasks.clear()

    def closeWebRTC(self):
        try:
            self.runAsync(self.shutdownWebRTC(), timeout=5)
        except Exception as e:
            logger.exception(f"Error closing WebRTC connections: {e}")


class WebRTCDownloadMixin(AsyncLoopExceptionMixin):
    """
    Adds WebRTC (aiortc/P2P) as a download transport on top of a Downloader.

    This class deals only with WebRTC concerns and must never import from
    bases.Download — it reaches HTTP/generic functionality purely through
    duck-typed `self.x` calls resolved via MRO once composed into a concrete
    class. A class composing this mixin must also provide (typically by also
    inheriting bases.Download.HTTPDownloader):
      - self._resolveDownloadContext(url, credentials, recipientPrivateKey)
      - self._downloadViaHTTP(...) / self._dispatchHTTPDownload(...)
      - self.loggerCallback, self._currentProgress, self._finishProgress(...)
      - the other Downloader-level helpers (_buildURL, _sendHTTPRequest, etc.)

    Mixin contract for future transports (e.g. IrohDownloadMixin):
      - __init__ cooperatively calls super().__init__(*args, **kwargs) FIRST,
        then sets up its own transport-specific state.
      - downloadFile() calls self._resolveDownloadContext(...) exactly once,
        attempts its own transport, and on failure/unsupported falls back to
        self._dispatchHTTPDownload(...) (NOT super().downloadFile(), which
        would re-run _resolveDownloadContext and duplicate HEAD requests /
        E2EE key prompts).
    """

    # WebRTC-only class constants
    _MAX_ICE_RETRIES = 5
    _ICE_RETRY_DELAYS = (0.2, 0.4, 0.8, 1.6, 2.0)
    _ICE_IDLE_SLEEP = 0.2 # Sleep interval when no ICE candidates are available

    _STATUS_SETUP_WEBRTC = _("Setting up WebRTC")
    _STATUS_ESTABLISHING = _("Establishing connection")
    _STATUS_NEGOTIATING = _("Negotiating connection")
    _STATUS_WAITING_CHANNEL = _("Waiting for data channel")
    _STATUS_CONNECTION_COUNTDOWN = _("Establishing WebRTC ({seconds}s)")
    _STATUS_CHANNEL_COUNTDOWN = _("Waiting for data channel ({seconds}s)")
    _STATUS_TRANSFER_COUNTDOWN = _("Waiting for transfer ({seconds}s)")

    # Default connection timeout for WebRTC establishment (seconds)
    # Web uses 30s, CLI uses 60s for more tolerance on slower connections
    CONNECTION_TIMEOUT_DEFAULT = 60
    DATA_CHANNEL_TIMEOUT_DEFAULT = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loop = None
        self.thread = None

        # Debug simulation settings from environment variables
        self.debugSimulateStall = os.environ.get("WEBRTC_CLI_SIMULATE_STALL") == "True"
        self.debugStallAfterBytes = int(os.environ.get("WEBRTC_CLI_STALL_AFTER_BYTES", "50000")) # Default 50KB
        self.debugSimulateDropBeforeFirstPayload = os.environ.get(
            "WEBRTC_CLI_SIMULATE_DROP_BEFORE_FIRST_PAYLOAD"
        ) == "True"
        self.debugSimulateIceFailure = os.environ.get("WEBRTC_CLI_SIMULATE_ICE_FAILURE") == "True"
        self.debugSimulateConnectionHang = os.environ.get("WEBRTC_CLI_SIMULATE_CONNECTION_HANG") == "True"
        self.disableHTTPFallback = os.environ.get("DISABLE_HTTP_FALLBACK") == "True"

        # Connection timeout can be overridden via WEBRTC_CLI_CONNECTION_TIMEOUT environment variable
        self.connectionTimeout = int(
            os.environ.get('WEBRTC_CLI_CONNECTION_TIMEOUT', str(self.CONNECTION_TIMEOUT_DEFAULT))
        )
        self.dataChannelTimeout = int(
            os.environ.get('WEBRTC_CLI_DATA_CHANNEL_TIMEOUT', str(self.DATA_CHANNEL_TIMEOUT_DEFAULT))
        )

        # Always log the timeout value during initialization for debugging
        envTimeout = os.environ.get('WEBRTC_CLI_CONNECTION_TIMEOUT', 'not set')
        logger.debug(
            f"Downloader initialized with connectionTimeout={self.connectionTimeout}s "
            f"(env var: {envTimeout}), dataChannelTimeout={self.dataChannelTimeout}s"
        )

        debugEnabled = (
            self.debugSimulateStall or self.debugSimulateDropBeforeFirstPayload or self.debugSimulateIceFailure or self.debugSimulateConnectionHang or
            self.disableHTTPFallback
        )
        if debugEnabled:
            logger.debug(
                f"Debug mode enabled: stall={self.debugSimulateStall} "
                f"(after {self.debugStallAfterBytes} bytes), "
                f"drop-before-first-payload={self.debugSimulateDropBeforeFirstPayload}, "
                f"ice-failure={self.debugSimulateIceFailure}, "
                f"connection-hang={self.debugSimulateConnectionHang}, "
                f"disable-http-fallback={self.disableHTTPFallback}, timeout={self.connectionTimeout}s, "
                f"data-channel-timeout={self.dataChannelTimeout}s"
            )

        self._setupEventLoop()

    def _setupEventLoop(self):
        """Setup dedicated event loop for WebRTC operations"""
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._runLoop, daemon=True)
        self.thread.start()

    def _updateFallbackCountdown(self, progress, statusTemplate, deadline, context):
        """Show the remaining WebRTC wait before the HTTP fallback starts."""
        remainingSeconds = max(0, int(deadline - time.time() + 0.999))
        countdown = (statusTemplate, remainingSeconds)
        if context['lastCountdown'] == countdown:
            return

        context['lastCountdown'] = countdown
        self._updateProgressStatus(progress, statusTemplate.format(seconds=remainingSeconds))

    def _runLoop(self):
        """Run asyncio event loop with exception handler"""
        asyncio.set_event_loop(self.loop)
        # Set exception handler from Mixin to catch unhandled exceptions in tasks
        self.loop.set_exception_handler(self._handleLoopException)
        self.loop.run_forever()

    def _failDownload(self, context: dict, error: Exception, errorEvent: asyncio.Event):
        """Unified helper to handle download failure: close file and set error"""
        context['error'] = error

        if context.get('outputFile') and context['outputFile'] is not sys.stdout.buffer:
            try:
                context['outputFile'].close()
                context['outputFile'] = None
            except Exception as e:
                logger.debug(f"Error closing file during download failure: {e}")

        errorEvent.set()

    def _waitFutureInterruptibly(self, future: concurrent.futures.Future, pollInterval: float = 0.5):
        """Wait for future result with interruptible polling to allow Ctrl+C

        Args:
            future: The future to wait for
            pollInterval: Polling interval in seconds (default 0.5s)

        Returns:
            The future's result

        Raises:
            Any exception raised by the future
        """
        while True:
            try:
                return future.result(timeout=pollInterval)
            except concurrent.futures.TimeoutError as e:
                # Just a poll timeout, continue waiting (allows KeyboardInterrupt to be caught)
                logger.debug(f"Future polling timeout after {pollInterval}s, continuing: {e}")
                continue

    async def _pumpLocalIceCandidates(self, pc: RTCPeerConnection, baseURL: str, peerId: str, authHeaders: dict):
        """Handle local ICE candidates and send them to server"""

        @pc.on("icecandidate")
        async def onIceCandidate(event):
            candidate = event.candidate

            if candidate is None:
                payload = {"peerId": peerId, "candidate": "end-of-candidates"}
            else:
                payload = {
                    "peerId": peerId,
                    "candidate": candidate.to_sdp(),
                    "sdpMid": candidate.sdpMid,
                    "sdpMLineIndex": candidate.sdpMLineIndex,
                }

            try:
                await asyncio.to_thread(
                    self._sendHTTPRequest, self._buildURL(baseURL, "candidate"), "POST", payload, authHeaders
                )
            except Exception as e:
                logger.warning(f"Failed to send ICE candidate: {e}")

    async def _pollRemoteIceCandidates(self, pc: RTCPeerConnection, baseURL: str, peerId: str, authHeaders: dict):
        """Poll server for remote ICE candidates with exponential backoff retry"""
        candidateURL = self._buildURL(baseURL, "candidate", peer=peerId)

        # Retry configuration using module-level constants
        consecutiveFailures = 0

        while True:
            try:
                candidateData, status = await asyncio.to_thread(
                    self._sendHTTPRequest, candidateURL, "GET", None, authHeaders, 10
                )

                # Reset failure counter on successful request
                consecutiveFailures = 0

                if status == 204: # No candidates available yet
                    await asyncio.sleep(self._ICE_IDLE_SLEEP)
                    continue
                elif status == 404: # Peer closed/not found - terminal error
                    logger.debug("Peer not found (404), stopping ICE polling")
                    break

                if candidateData and candidateData.get("candidate") == "end-of-candidates":
                    logger.debug("Received end-of-candidates from server")
                    break

                if candidateData:
                    await pc.addIceCandidate(candidateData)

            except Exception as e:
                consecutiveFailures += 1

                # Retry with exponential backoff for recoverable errors (5xx, network glitch)
                if consecutiveFailures >= self._MAX_ICE_RETRIES:
                    logger.warning(f"Max retries ({self._MAX_ICE_RETRIES}) reached for ICE polling, stopping: {e}")
                    break

                retryDelay = self._ICE_RETRY_DELAYS[consecutiveFailures - 1]
                logger.debug(
                    f"ICE polling failed (attempt {consecutiveFailures}/{self._MAX_ICE_RETRIES}), "
                    f"retrying in {retryDelay}s: {e}"
                )
                await asyncio.sleep(retryDelay)

    async def _setupDataChannelHandling(
        self,
        pc: RTCPeerConnection,
        outputPath: str,
        fileSize: int,
        baseURL: str,
        peerId: str,
        authHeaders: dict,
        progress,
        resumePosition: int = 0,
        e2eeContext: Optional[dict] = None,
        statusErrorQueue: Optional[deque] = None,
        verifyChecksum: bool = False,
        checksumAlgorithm: str = DEFAULT_CHECKSUM_ALGORITHM
    ):
        """Setup data channel for file reception

        Args:
            resumePosition: Byte offset to resume from (0 for new download)
            e2eeContext: E2EE encryption context (contentKey, nonceBase, filename, filesize, chunkSize)
            statusErrorQueue: Optional deque to check for server-reported errors before raising generic errors
        """
        downloadComplete = asyncio.Event()
        errorEvent = asyncio.Event()

        # Initialize E2EE stream decryptor if encryption is enabled
        streamDecryptor = None
        if e2eeContext:
            streamDecryptor = self.e2eeClient.createWebRTCDecryptor(e2eeContext)

        # Use context dict instead of multiple nonlocal variables
        # Initialize bytesReceived with resume position
        context = {
            'bytesReceived': resumePosition,
            'outputFile': None,
            'stallSimulated': False,
            'dropBeforeFirstPayloadSimulated': False,
            'error': None,
            'downloadStarted': False,
            'statusUpdated': False,
            'connectedAt': None,
            'dataChannelOpen': False,
            'lastCountdown': None,
            'streamDecryptor': streamDecryptor,
            'checksumState': self._createTransferChecksumState(verifyChecksum, checksumAlgorithm)
        }

        # Monitor connection state for early failure detection
        @pc.on("connectionstatechange")
        async def onConnectionStateChange():
            state = pc.connectionState
            logger.debug(f"WebRTC connection state changed to: {state}")

            if state == "connected" and context['connectedAt'] is None:
                context['connectedAt'] = time.time()

            # If connection fails/closes before download completes, trigger error
            if state in ("failed", "closed", "disconnected") and not downloadComplete.is_set():
                # Check if server reported a specific error (e.g., FolderChangedException)
                # before raising a generic connection error
                if statusErrorQueue and statusErrorQueue:
                    serverError = statusErrorQueue[0]
                    logger.debug(f"[WebRTC] Connection {state}, using server error: {serverError}")
                    self._failDownload(context, serverError, errorEvent)
                else:
                    errorMsg = f"WebRTC connection {state} before download completed"
                    logger.warning(errorMsg)
                    self._failDownload(context, RuntimeError(errorMsg), errorEvent)

        @pc.on("datachannel")
        def onDataChannel(channel):
            logger.debug(f"Data channel received, simulateHang={self.debugSimulateConnectionHang}")
            # Debug: Simulate connection hang by ignoring data channel
            if self.debugSimulateConnectionHang:
                logger.debug("Simulating connection hang - ignoring data channel")
                return
            logger.debug("Data channel accepted - setting up file transfer")
            # Open file when data channel is established (append mode if resuming), or use stdout
            mode = 'ab' if resumePosition > 0 else 'wb'
            context['outputFile'] = sys.stdout.buffer if outputPath == "-" else open(outputPath, mode)

            # Send START signal when channel opens
            def sendStartSignal():
                try:
                    logger.debug(f"Data channel ready, sending START signal")
                    channel.send("START")
                except Exception as e:
                    logger.warning(f"Failed to send START signal: {e}")

            def markDataChannelOpen():
                context['dataChannelOpen'] = True
                sendStartSignal()

            @channel.on("open")
            def onChannelOpen():
                markDataChannelOpen()

            # If channel is already open, send START immediately
            if channel.readyState == "open":
                logger.debug(f"Data channel already open, sending START immediately")
                markDataChannelOpen()

            @channel.on("message")
            def onMessage(data):
                try:
                    if isinstance(data, str):
                        if data == "EOF":
                            # Use progress.write() for completion message so it doesn't interfere with progress bar
                            progress.write("File transfer completed")
                            if context['outputFile']:
                                # Flush any remaining encrypted frames from the decryptor buffer
                                if context['streamDecryptor']:
                                    finalData = context['streamDecryptor'].flush()
                                    if finalData:
                                        context['outputFile'].write(finalData)
                                        context['bytesReceived'] += len(finalData)
                                        logger.debug(f"Wrote {len(finalData)} bytes from streamDecryptor.flush()")

                                context['outputFile'].flush()

                                if context['outputFile'] is not sys.stdout.buffer:
                                    context['outputFile'].close()

                            self._finalizeTransferChecksumState(context['checksumState'])

                            # Final progress update
                            progress.update(context['bytesReceived'], forceLog=True, extraText="WebRTC P2P")

                            # Notify server of completion (best effort - peer may already be cleaned up)
                            context['completionTask'] = asyncio.create_task(
                                self._notifyCompletionSafely(baseURL, peerId, authHeaders)
                            )
                            downloadComplete.set()
                        elif data == "ERROR":
                            progress.write("Server reported error during transfer")
                            if context['outputFile'] and context['outputFile'] is not sys.stdout.buffer:
                                context['outputFile'].close()

                            downloadComplete.set()
                        elif data.startswith("ERROR:"):
                            # Handle specific error codes from server (ERROR:STALE, ERROR:TIMEOUT)
                            errorType = data.split(":", 1)[1] if ":" in data else "UNKNOWN"
                            progress.write(f"Server connection error: {errorType}")

                            if context['outputFile'] and context['outputFile'] is not sys.stdout.buffer:
                                context['outputFile'].close()

                            self._failDownload(context, RuntimeError(f"Server error: {errorType}"), errorEvent)
                        elif data == "PONG":
                            # Heartbeat response from server (no action needed)
                            logger.debug("Received PONG from server")
                    else:
                        # Binary data
                        if context['outputFile']:
                            if context['error']:
                                return

                            if (
                                self.debugSimulateDropBeforeFirstPayload and
                                not context['dropBeforeFirstPayloadSimulated']
                            ):
                                context['dropBeforeFirstPayloadSimulated'] = True
                                channel.close()
                                self._failDownload(
                                    context,
                                    RuntimeError("Debug: Simulated drop before first payload write"),
                                    errorEvent
                                )
                                return

                            self._updateTransferChecksumState(context['checksumState'], data)

                            # Process chunk (decrypt if E2EE enabled, otherwise passthrough)
                            processedData = context['streamDecryptor'].processChunk(
                                data
                            ) if context['streamDecryptor'] else data

                            # Write processed data
                            context['outputFile'].write(processedData)
                            context['bytesReceived'] += len(processedData)

                            # Mark that download has started
                            if not context['downloadStarted']:
                                context['downloadStarted'] = True

                            # Debug: Simulate stall after specified bytes
                            if (
                                self.debugSimulateStall and not context['stallSimulated'] and
                                context['bytesReceived'] >= self.debugStallAfterBytes
                            ):

                                logger.debug(
                                    f"Simulating network stall - closing data channel after "
                                    f"{context['bytesReceived']} bytes"
                                )
                                context['stallSimulated'] = True

                                # Close immediately to ensure stall before file completes
                                try:
                                    channel.close()
                                    logger.debug("Data channel closed to simulate network failure")
                                except Exception as e:
                                    logger.debug(f"Error closing data channel: {e}")

                                # Raise error to stop download
                                raise RuntimeError(
                                    f"Debug: Simulated network stall at {context['bytesReceived']} bytes"
                                )

                            # Update progress bar
                            progress.update(context['bytesReceived'], extraText="WebRTC P2P")

                            # Legacy progress callback
                            if self.progressCallback:
                                self.progressCallback(context['bytesReceived'], fileSize)
                except Exception as e:
                    # Capture exception in context and signal error
                    logger.error(f"Error in onMessage callback: {e}")
                    self._failDownload(context, e, errorEvent)

        return downloadComplete, errorEvent, context

    async def _cancelTasks(self, tasks):
        """Cancel and await a list of tasks, ignoring cancellation errors

        Args:
            tasks: List of tasks (None values are automatically filtered out)
        """
        # Filter out None values
        validTasks = [t for t in tasks if t is not None]

        for task in validTasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    logger.debug(
                        f"Task cancelled successfully: {task.get_name() if hasattr(task, 'get_name') else 'unnamed'}"
                    )
                except Exception as e:
                    logger.debug(f"Error during task cleanup: {e}")

    async def _notifyCompletionSafely(self, baseURL: str, peerId: str, authHeaders: dict):
        """Safely notify server of completion, ignoring 404 errors (peer already cleaned up)"""
        try:
            await asyncio.to_thread(
                self._sendHTTPRequest, self._buildURL(baseURL, "complete"), "POST", {"peerId": peerId}, authHeaders
            )
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                # Peer already cleaned up - this is normal and harmless
                logger.debug(f"Peer {peerId} already cleaned up (404) - this is expected")
            else:
                # Other HTTP errors should still be logged
                statusCode = e.response.status_code if e.response else 'unknown'
                logger.warning(f"Failed to notify completion: HTTP {statusCode}")
        except Exception as e:
            # Network or other errors - log but don't fail
            logger.warning(f"Failed to notify completion: {e}")

    async def _downloadViaWebRTC(
        self,
        url: str,
        outputPath: Optional[str] = None,
        credentials: Optional[Tuple[str, str]] = None,
        resume: bool = False,
        e2eeContext: Optional[dict] = None,
        urlInfo=None,
        checksumAlgorithm: str = DEFAULT_CHECKSUM_ALGORITHM,
        pickupCode: Optional[str] = None,
        proof: Optional[str] = None
    ) -> str:
        """Core WebRTC download implementation

        Args:
            urlInfo: Optional pre-parsed URL info to avoid redundant parsing
        """
        if urlInfo is None:
            urlInfo = self._extractURLInfo(url)

        authHeaders = self._createAuthHeaders(credentials)

        # If WebRTC is not supported, raise exception to trigger HTTP fallback
        if not urlInfo.supportsWebRTC or urlInfo.isGenericURL:
            raise RuntimeError("WebRTC not supported for this URL")

        # Get file metadata first using helper
        fileSize, fileName, __ = await asyncio.to_thread(self._getRemoteMetadata, urlInfo.baseURL, authHeaders)

        # Resolve output path using helper
        finalOutputPath = self._resolveOutputPath(outputPath, fileName)

        # Display file info
        fileSizeDisplay = f"{fileSize:,} bytes" if self._isKnownSize(fileSize) else "unknown bytes"
        self.loggerCallback(_("Downloading {filename} ({fileSize})").format(
            filename=fileName, fileSize=fileSizeDisplay))

        # Handle resume logic
        resumePosition = self._handleResumeLogic(finalOutputPath, fileSize, resume)
        verifyChecksum = self._shouldVerifyChecksum(urlInfo, resumePosition)

        # File already complete (skip check for unknown size)
        if self._isKnownSize(fileSize) and resumePosition >= fileSize:
            return self._finishAlreadyComplete(fileSize, resumePosition, finalOutputPath)

        if resumePosition > 0 and self._isPositiveSize(fileSize):
            self.loggerCallback(_("Resuming WebRTC download from {resumePos} / {totalSize}").format(
                resumePos=formatSize(resumePosition), totalSize=formatSize(fileSize)
            ))

        # Initialize progress bar early with connection status using helper
        # Store as instance variable so it can be reused for HTTP fallback if WebRTC fails
        self._currentProgress = self._ensureProgress(fileSize, self._STATUS_CONNECTING, resumePosition)
        progress = self._currentProgress

        # Get offer from server
        self._updateProgressStatus(progress, self._STATUS_REQUESTING)

        # Build offer URL with resume offset and debug parameters using helper
        offerURL = self._buildURL(
            urlInfo.baseURL,
            "offer",
            offset=resumePosition if resumePosition > 0 else None,
            **({
                'simulate-ice-failure': 'true'
            } if self.debugSimulateIceFailure else {}),
            **({
                'simulate-stall': 'true',
                'stall-after': self.debugStallAfterBytes
            } if self.debugSimulateStall else {})
        )
        if pickupCode:
            authHeaders['X-FFL-Pickup'] = pickupCode
        if proof:
            authHeaders['X-FFL-Proof'] = proof

        if resumePosition > 0 or self.debugSimulateIceFailure or self.debugSimulateStall:
            logger.debug(f"Using offer URL: {offerURL}")

        try:
            offerData, __ = await asyncio.to_thread(self._sendHTTPRequest, offerURL, "GET", None, authHeaders)
            peerId = offerData["peerId"]
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                # /offer endpoint not found - WebRTC not supported
                raise RuntimeError("WebRTC not supported (/offer endpoint returned 404)")
            raise

        # Setup WebRTC peer connection
        self._updateProgressStatus(progress, self._STATUS_SETUP_WEBRTC)

        iceServers = ICEServerConfigProvider().iceServers

        # Debug: Simulate ICE failure by using invalid STUN servers
        if self.debugSimulateIceFailure:
            logger.debug("Simulating ICE failure with invalid STUN servers")
            iceServers = [RTCIceServer(urls="stun:invalid.example.com:19302")] # Invalid server to force failure

        config = RTCConfiguration(iceServers=iceServers)
        pc = RTCPeerConnection(configuration=config)

        # Initialize variables for finally block cleanup
        context = None
        completionTask = None

        # Create status error queue early so it can be passed to data channel handler
        # This allows connection state changes to check for specific server errors
        statusErrorQueue = deque()

        try:
            # Setup data channel handling (pass statusErrorQueue for error prioritization)
            downloadComplete, errorEvent, context = await self._setupDataChannelHandling(
                pc, finalOutputPath, fileSize, urlInfo.baseURL, peerId, authHeaders, progress, resumePosition,
                e2eeContext, statusErrorQueue, verifyChecksum, checksumAlgorithm
            )

            # Setup ICE candidate handling
            await self._pumpLocalIceCandidates(pc, urlInfo.baseURL, peerId, authHeaders)

            # Set remote description and create answer
            self._updateProgressStatus(progress, self._STATUS_ESTABLISHING)

            await pc.setRemoteDescription(RTCSessionDescription(offerData["sdp"], offerData["type"]))
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Send answer to server
            self._updateProgressStatus(progress, self._STATUS_NEGOTIATING)

            await asyncio.to_thread(
                self._sendHTTPRequest,
                self._buildURL(urlInfo.baseURL, "answer"),
                "POST",
                {
                    "peerId": peerId,
                    "type": pc.localDescription.type,
                    "sdp": pc.localDescription.sdp,
                    "clientInfo": {
                        "browser": "cli",
                        "domain": "cli",
                        "protocol": "webrtc",
                        "userAgent": "fastfilelink-cli"
                        # isLocalConnection removed - let server detect based on IP
                    }
                },
                authHeaders
            )

            # Start ICE candidate polling and wait for completion
            self._updateProgressStatus(progress, self._STATUS_WAITING_CHANNEL)

            # Start background thread for status polling
            statusStopEvent = threading.Event()
            self._startStatusPollingThread(urlInfo.baseURL, authHeaders, statusStopEvent, statusErrorQueue)

            # Debug: Simulate connection hang by creating a task that never completes
            if self.debugSimulateConnectionHang:

                async def hangForever():
                    await asyncio.sleep(float('inf'))

                pollingTask = asyncio.create_task(hangForever())
            else:
                # Start polling task in background
                pollingTask = asyncio.create_task(
                    self._pollRemoteIceCandidates(pc, urlInfo.baseURL, peerId, authHeaders)
                )

            # Wait for download to complete or error (polling continues in background)
            completionTask = None
            errorTask = None
            try:
                # Create tasks for waiting on events (only once)
                completionTask = asyncio.create_task(downloadComplete.wait())
                errorTask = asyncio.create_task(errorEvent.wait())

                connectionDeadline = time.time() + self.connectionTimeout

                # Monitor context and update status when download starts
                while True:
                    # Update status to "Downloading" when first data arrives
                    if context['downloadStarted'] and not context['statusUpdated']:
                        self._updateProgressStatus(progress, self._STATUS_DOWNLOADING)
                        context['statusUpdated'] = True

                    # Check status error queue (lock-free, no performance impact)
                    if statusErrorQueue:
                        serverError = statusErrorQueue[0]
                        logger.debug(f"[WebRTC] Error found in queue: {serverError}")
                        statusStopEvent.set()
                        await self._cancelTasks([pollingTask, completionTask, errorTask])
                        raise serverError

                    if not context['downloadStarted']:
                        connectedAt = context['connectedAt']
                        
                        if connectedAt is None:
                            timeoutDeadline = connectionDeadline
                            timeoutError = WebRTCConnectionTimeout(
                                f"WebRTC connection timeout after {self.connectionTimeout} seconds"
                            )
                            statusTemplate = self._STATUS_CONNECTION_COUNTDOWN
                        elif not context['dataChannelOpen']:
                            dataChannelDeadline = connectedAt + self.dataChannelTimeout
                            timeoutDeadline = min(connectionDeadline, dataChannelDeadline)
                            timeoutError = WebRTCDataChannelTimeout(
                                f"WebRTC data channel did not open after {self.dataChannelTimeout} seconds"
                            )
                            statusTemplate = self._STATUS_CHANNEL_COUNTDOWN
                        else:
                            timeoutDeadline = connectionDeadline
                            timeoutError = WebRTCConnectionTimeout(
                                f"WebRTC transfer did not start after {self.connectionTimeout} seconds"
                            )
                            statusTemplate = self._STATUS_TRANSFER_COUNTDOWN

                        self._updateFallbackCountdown(progress, statusTemplate, timeoutDeadline, context)
                        
                        if time.time() >= timeoutDeadline:
                            statusStopEvent.set()
                            await self._cancelTasks([pollingTask, completionTask, errorTask])
                            raise timeoutError

                    # Wait for either completion or error with timeout
                    done, pending = await asyncio.wait([completionTask, errorTask],
                                                       timeout=0.1,
                                                       return_when=asyncio.FIRST_COMPLETED)

                    if done:
                        # One of the events fired
                        if completionTask in done:
                            winner = downloadComplete
                        else:
                            winner = errorEvent
                        break
                    # Otherwise continue monitoring

                # Check if error occurred
                if winner is errorEvent:
                    error = context.get('error')
                    statusStopEvent.set()
                    await self._cancelTasks([pollingTask, completionTask, errorTask])
                    raise error if error else RuntimeError("Download failed due to error in data channel")

                # Download completed successfully, cancel polling and monitoring tasks
                statusStopEvent.set()
                await self._cancelTasks([pollingTask, completionTask, errorTask])
            except asyncio.CancelledError:
                # Task cancelled (e.g., timeout in downloadFile) - clean up and close file
                logger.debug("WebRTC download cancelled, cleaning up...")
                statusStopEvent.set()
                await self._cancelTasks([pollingTask, completionTask, errorTask])

                if context.get('outputFile') and context['outputFile'] is not sys.stdout.buffer:
                    context['outputFile'].close()
                    context['outputFile'] = None

                raise
            except Exception:
                # On error, cancel polling and monitoring tasks
                statusStopEvent.set()
                await self._cancelTasks([pollingTask, completionTask, errorTask])
                raise
            finally:
                statusStopEvent.set()

            # Finish progress bar on successful completion
            self._finishProgress()

            if verifyChecksum:
                await asyncio.to_thread(
                    self._verifyTransferChecksum, urlInfo.baseURL, authHeaders, context.get('checksumState'), 'webrtc'
                )

            return finalOutputPath

        except Exception as error:
            if context is not None:
                raise WebRTCFallbackError(error, context['bytesReceived']) from error
                
            raise
        finally:
            # Clean up any completion notification task (but NOT progress bar - might be reused for HTTP fallback)
            if context and 'completionTask' in context:
                try:
                    await asyncio.wait_for(self._cancelTasks([context['completionTask']]), timeout=2.0)
                except asyncio.TimeoutError:
                    logger.debug("Timeout while cancelling completion task during cleanup")
                except Exception as e:
                    logger.debug(f"Error cancelling completion task during cleanup: {e}")

            # Close peer connection with timeout to prevent hanging
            try:
                await asyncio.wait_for(pc.close(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.debug("Timeout while closing peer connection during cleanup")
            except Exception as e:
                logger.debug(f"Error closing peer connection during cleanup: {e}")

    def _fallbackToHTTP(
        self,
        url: str,
        outputPath: Optional[str],
        credentials: Optional[Tuple[str, str]],
        resume: bool,
        webrtcError: Exception,
        e2eeContext: Optional[dict] = None,
        urlInfo=None,
        checksumAlgorithm: str = DEFAULT_CHECKSUM_ALGORITHM,
        pickupCode: Optional[str] = None,
        proof: Optional[str] = None,
        fallbackResumePosition: int = 0
    ) -> str:
        """Common HTTP fallback logic for both timeout and exception cases

        Args:
            urlInfo: Optional pre-parsed URL info to avoid redundant parsing
        """
        if self.disableHTTPFallback:
            logger.debug("HTTP fallback disabled via DISABLE_HTTP_FALLBACK - re-raising WebRTC error")
            if self._currentProgress:
                try:
                    self._finishProgress(complete=False)
                except Exception as progressError:
                    logger.debug(f"Error finishing progress bar after disabling fallback: {progressError}")
            raise webrtcError

        # Reuse existing progress bar from WebRTC attempt for seamless transition
        sharedProgress = self._currentProgress

        if sharedProgress:
            # Reuse the existing progress bar - just update its description
            self._updateProgressStatus(sharedProgress, self._STATUS_HTTP_FALLBACK)
        else:
            # Fallback: create new progress bar if somehow we don't have one
            if urlInfo is None:
                urlInfo = self._extractURLInfo(url)

            authHeaders = self._createAuthHeaders(credentials)
            fileSize, __, __ = self._getRemoteMetadata(urlInfo.baseURL, authHeaders)
            sharedProgress = self._ensureProgress(fileSize, self._STATUS_HTTP_FALLBACK, 0)

        try:
            # Force resume when falling back from WebRTC to continue from where WebRTC left off
            result = self._downloadViaHTTP(
                url,
                outputPath,
                credentials,
                sharedProgress,
                resume,
                forceResume=True,
                e2eeContext=e2eeContext,
                urlInfo=urlInfo,
                pickupCode=pickupCode,
                proof=proof,
                checksumAlgorithm=checksumAlgorithm,
                fallbackResumePosition=fallbackResumePosition
            )
            self._finishProgress()
            return result
        except FolderChangedException as folderError:
            # Clean up progress bar on failure without completing to 100%
            self._finishProgress(complete=False)
            # Folder changed error - re-raise with clear message
            raise FolderChangedException(str(folderError)) from folderError
        except Exception as httpError:
            # Clean up progress bar on failure without completing to 100%
            self._finishProgress(complete=False)
            # If both methods fail, raise the original WebRTC error with fallback context
            raise RuntimeError(
                f"Both WebRTC and HTTP downloads failed. WebRTC: {webrtcError}. HTTP: {httpError}"
            ) from webrtcError

    def downloadFile(self, url, outputPath=None, credentials=None, resume=False,
                      pickupCode=None, recipientPrivateKey=None) -> str:
        """Try WebRTC first (if supported/enabled), fall back to HTTP."""
        self._validateOutputPath(outputPath)
        ctx = self._resolveDownloadContext(url, credentials, recipientPrivateKey)
        urlInfo = ctx['urlInfo']

        if urlInfo.isGenericURL:
            return self._dispatchHTTPDownload(url, outputPath, credentials, resume, ctx, pickupCode)

        webrtcDisabled = os.getenv('DISABLE_WEBRTC', None) == 'True'
        useWebRTC = urlInfo.supportsWebRTC and not webrtcDisabled

        if not useWebRTC:
            self.loggerCallback(_("WebRTC not supported, using HTTP download..."))
            return self._dispatchHTTPDownload(url, outputPath, credentials, resume, ctx, pickupCode)

        future = None
        try:
            # Try WebRTC first
            self.loggerCallback(_("Attempting WebRTC download..."))
            future = asyncio.run_coroutine_threadsafe(
                self._downloadViaWebRTC(
                    url, outputPath, credentials, resume,
                    ctx['e2eeContext'], urlInfo, ctx['checksumAlgorithm'], pickupCode, ctx['proof']
                ),
                self.loop
            )

            # Wait for result with interruptible polling to allow Ctrl+C
            return self._waitFutureInterruptibly(future)
        except KeyboardInterrupt:
            # User pressed Ctrl+C - cancel the download and cleanup
            logger.debug("Download interrupted by user (Ctrl+C)")
            if future:
                future.cancel()
                try:
                    future.result(timeout=2)
                except concurrent.futures.CancelledError:
                    logger.debug("Future cancelled successfully after Ctrl+C")
                except concurrent.futures.TimeoutError:
                    logger.debug("Future cancellation timed out after Ctrl+C")
                except Exception as e:
                    logger.debug(f"Error while cancelling future after Ctrl+C: {e}")
            # Finish progress bar cleanly before raising
            if self._currentProgress:
                try:
                    self._finishProgress(complete=False)
                except Exception as e:
                    logger.debug(f"Error finishing progress bar after Ctrl+C: {e}")
            raise
        except WebRTCFallbackError as webrtcError:
            return self._fallbackToHTTP(
                url, outputPath, credentials, resume, webrtcError,
                ctx['e2eeContext'], urlInfo, ctx['checksumAlgorithm'], pickupCode, ctx['proof'],
                webrtcError.resumePosition
            )
        except WebRTCConnectionTimeout as timeoutError:
            # Connection establishment timed out, fall back to HTTP
            return self._fallbackToHTTP(
                url, outputPath, credentials, resume, timeoutError,
                ctx['e2eeContext'], urlInfo, ctx['checksumAlgorithm'], pickupCode, ctx['proof']
            )
        except Exception as webrtcError:
            # Log WebRTC failure and fall back to HTTP
            logger.debug(f"WebRTC download failed: {webrtcError}")
            return self._fallbackToHTTP(
                url, outputPath, credentials, resume, webrtcError,
                ctx['e2eeContext'], urlInfo, ctx['checksumAlgorithm'], pickupCode, ctx['proof']
            )

    def close(self):
        """Stop the WebRTC event-loop thread; cooperatively closes further mixins/base via MRO."""
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
            
        super().close()
