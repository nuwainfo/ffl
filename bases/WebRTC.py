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
import sys
import threading
import uuid
import concurrent.futures
import re
import urllib.parse
import base64
import os
import time

from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple, Callable
from urllib.parse import urlparse, unquote

import requests

from aiortc import (RTCConfiguration, RTCDataChannel, RTCIceServer, RTCPeerConnection, RTCSessionDescription)
from aiortc.sdp import candidate_from_sdp

from bases.Kernel import getLogger
from bases.Utils import ONE_MB, formatSize, getEnv, StallResilientAdapter
from bases.Progress import Progress
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE
from bases.E2EE import E2EEClient
from bases.Reader import FolderChangedException
from bases.I18n import _


# Custom exception for WebRTC connection timeout
class WebRTCConnectionTimeout(Exception):
    """Raised when WebRTC connection establishment times out"""
    pass


# Custom exception for WebRTC disabled by server policy
class WebRTCDisabledError(Exception):
    """Raised when WebRTC is disabled by server policy (e.g., --force-relay for licensed users)"""

    def __init__(self, reason="WebRTC connections are disabled by server policy"):
        self.reason = reason
        super().__init__(reason)


@dataclass
class URLInfo:
    """Information extracted from a download URL"""
    baseURL: str # Base URL with trailing slash
    uid: str # UID (empty for custom tunnels or generic URLs)
    supportsWebRTC: bool # Whether WebRTC is supported
    isGenericURL: bool # Whether this is a generic HTTP URL (not FastFileLink)
    e2eeEnabled: bool = False # Whether E2EE encryption is enabled
    isUploadMode: bool = False # Whether this is an uploaded file (not P2P)
    urlFragment: str = "" # URL fragment (e.g., #key for E2EE upload mode)


# Default ICE servers for WebRTC connections
DEFAULT_ICE_SERVERS = [
    RTCIceServer(urls="stun:stun.l.google.com:19302"),
    RTCIceServer(urls="stun:stun.cloudflare.com:3478"),
    RTCIceServer(urls="stun:stun.nextcloud.com:443"),
    RTCIceServer(urls="stun:openrelayproject.org:80"),
    RTCIceServer(urls="stun:openrelayproject.org:443"),
]

# Chrome/Edge local connection sleep delay (seconds) - "3 ticks trick" to avoid buffer issues
# https://github.com/aiortc/aioice/issues/58
CHROME_EDGE_LOCAL_SLEEP_DELAY = getEnv('WEBRTC_CHROME_EDGE_LOCAL_SLEEP_DELAY', 0.047)
# Sleep once every N bytes to avoid excessive sleeping (default: TRANSFER_CHUNK_SIZE for original behavior)
CHROME_EDGE_LOCAL_SLEEP_INTERVAL = getEnv('WEBRTC_CHROME_EDGE_LOCAL_SLEEP_INTERVAL', TRANSFER_CHUNK_SIZE)

# HTTP download timeout configuration (seconds)
# Connect timeout: How long to wait for initial connection
# Read timeout: How long to wait between chunks (increased from 30s to handle stalls)
HTTP_CONNECT_TIMEOUT = getEnv('HTTP_CONNECT_TIMEOUT', 10)
HTTP_READ_TIMEOUT = getEnv('HTTP_READ_TIMEOUT', 600)  # 10 minutes to handle large file stalls

# Without winloop, Edge will fail to use WebRTC, it will cause consent query timeout after few seconds.
# It speeds up a lot on Firefox, but slow down a little on Chrome/Edge.
if sys.platform == "win32":
    # Please "import winloop._noop" rather than "import winloop" here,
    # or it will raise "No module named winloop" error.
    # https://github.com/Vizonex/Winloop/issues/9
    import winloop._noop # pylint: disable=import-error
    winloop.install()
    assert isinstance(asyncio.get_event_loop_policy(), winloop.EventLoopPolicy)

# Setup logging
logger = getLogger(__name__)


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


class WebRTCManager(AsyncLoopExceptionMixin):
    # Transfer chunk size - shared across WebRTC and HTTP downloads
    CHUNK_SIZE = TRANSFER_CHUNK_SIZE

    def __init__(self, loggerCallback=print, downloadCallback=None, exceptionCallback=None):
        # WebRTC state
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._runLoop, daemon=True)
        self.thread.start()
        self.pcs: Set[RTCPeerConnection] = set()
        self.peers: Dict[str, Tuple[RTCPeerConnection, Optional[ClientInfo], deque]] = {}
        self.loggerCallback = loggerCallback
        self.downloadCallback = downloadCallback
        self.exceptionCallback = exceptionCallback

        # Download completion events for each peer
        self.downloadCompleteEvents: Dict[str, threading.Event] = {}

        # Track sendFile tasks for proper cleanup
        self.sendFileTasks: Dict[str, asyncio.Task] = {}

        # Track peer statistics (file size, reported bytes, etc.) for diagnostics
        self.peerStats: Dict[str, Dict[str, Any]] = {}

        # ICE servers configuration
        self.iceServers = DEFAULT_ICE_SERVERS

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

    def runAsync(self, coro, timeout=15):
        # Execute coroutine in a synchronous environment and return the result (blocking)
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
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
        connectionType = "Local" if clientInfo.isLocalConnection else "Remote"
        logger.info(f"Client info for peer {peerId}: {clientInfo.browser} on {clientInfo.domain} ({connectionType})")

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
        while dc.readyState != "open":
            await asyncio.sleep(0.05)

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

        try:
            self._handleStartDownloadActions(fileSize)
        except PermissionError as e:
            # File size or other validation error from enhanced handler
            logger.error(f"File transfer validation failed: {e}")
            raise

        # Initialize E2EE stream encryptor if enabled
        streamEncryptor = None
        if e2eeManager:
            streamEncryptor = e2eeManager.createWebRTCEncryptor(reader.contentName, fileSize)

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

        try:
            # Use reader.iterChunks() instead of open()
            for chunk in reader.iterChunks(self.CHUNK_SIZE, start=offset):
                # Wait until buffer is acceptable for next packet
                await bufferFlushed.wait()

                # Track plaintext size before encryption
                plaintextSize = len(chunk)

                # Encrypt chunk if E2EE is enabled
                if streamEncryptor:
                    chunk = streamEncryptor.processChunk(chunk)

                dc.send(chunk)
                sent += plaintextSize # Count plaintext bytes, not encrypted bytes
                bufferFlushed.clear()

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

            # Wait for buffer to drain before sending EOF to prevent race condition
            # where EOF arrives before final chunk on receiver side
            await bufferFlushed.wait()

            # Send EOF marker
            dc.send("EOF")

            # Final progress update
            progress.update(sent, forceLog=True, extraText=_("P2P direct"), forceFinish=fileSize is None)

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


class WebRTCDownloader(AsyncLoopExceptionMixin):
    """WebRTC-based file downloader that connects to FastFileLink servers"""

    # Class-level constants for progress bar and retry configuration
    _PROGRESS_BAR_FORMAT = '{desc} {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]{postfix}'
    _MAX_ICE_RETRIES = 5
    _ICE_RETRY_DELAYS = (0.2, 0.4, 0.8, 1.6, 2.0)
    _ICE_IDLE_SLEEP = 0.2 # Sleep interval when no ICE candidates are available

    # Progress status messages
    _STATUS_CONNECTING = _("Connecting to server")
    _STATUS_REQUESTING = _("Requesting connection")
    _STATUS_SETUP_WEBRTC = _("Setting up WebRTC")
    _STATUS_ESTABLISHING = _("Establishing connection")
    _STATUS_NEGOTIATING = _("Negotiating connection")
    _STATUS_WAITING_CHANNEL = _("Waiting for data channel")
    _STATUS_DOWNLOADING = _("Downloading")
    _STATUS_HTTP_DOWNLOAD = _("HTTP download")
    _STATUS_HTTP_FALLBACK = _("HTTP fallback")
    _STATUS_FILE_COMPLETE = _("File already downloaded")
    _STATUS_METADATA = _("Getting file metadata")

    # Default connection timeout for WebRTC establishment (seconds)
    # Web uses 30s, CLI uses 60s for more tolerance on slower connections
    CONNECTION_TIMEOUT_DEFAULT = 60

    @staticmethod
    def _isKnownSize(fileSize: int) -> bool:
        """Check if file size is known (not None or negative)"""
        return fileSize is not None and fileSize >= 0

    @staticmethod
    def _isPositiveSize(fileSize: int) -> bool:
        """Check if file size is known and positive (> 0)"""
        return fileSize is not None and fileSize > 0

    def __init__(self, loggerCallback: Callable = print, progressCallback: Optional[Callable] = None):
        self.loggerCallback = loggerCallback
        self.progressCallback = progressCallback
        self.loop = None
        self.thread = None
        self._currentProgress = None
        self._e2eeClient = None

        # Debug simulation settings from environment variables
        self.debugSimulateStall = os.environ.get("WEBRTC_CLI_SIMULATE_STALL") == "True"
        self.debugStallAfterBytes = int(os.environ.get("WEBRTC_CLI_STALL_AFTER_BYTES", "50000")) # Default 50KB
        self.debugSimulateIceFailure = os.environ.get("WEBRTC_CLI_SIMULATE_ICE_FAILURE") == "True"
        self.debugSimulateConnectionHang = os.environ.get("WEBRTC_CLI_SIMULATE_CONNECTION_HANG") == "True"
        self.disableHTTPFallback = os.environ.get("DISABLE_HTTP_FALLBACK") == "True"

        # Connection timeout can be overridden via WEBRTC_CLI_CONNECTION_TIMEOUT environment variable
        self.connectionTimeout = int(
            os.environ.get('WEBRTC_CLI_CONNECTION_TIMEOUT', str(self.CONNECTION_TIMEOUT_DEFAULT))
        )

        # Always log the timeout value during initialization for debugging
        envTimeout = os.environ.get('WEBRTC_CLI_CONNECTION_TIMEOUT', 'not set')
        logger.debug(
            f"Downloader initialized with connectionTimeout={self.connectionTimeout}s "
            f"(env var: {envTimeout})"
        )

        debugEnabled = (
            self.debugSimulateStall or self.debugSimulateIceFailure
            or self.debugSimulateConnectionHang or self.disableHTTPFallback
        )
        if debugEnabled:
            logger.debug(
                f"Debug mode enabled: stall={self.debugSimulateStall} "
                f"(after {self.debugStallAfterBytes} bytes), "
                f"ice-failure={self.debugSimulateIceFailure}, "
                f"connection-hang={self.debugSimulateConnectionHang}, "
                f"disable-http-fallback={self.disableHTTPFallback}, timeout={self.connectionTimeout}s"
            )

        self._setupEventLoop()

    def _updateProgressStatus(self, progress, description):
        """Update progress bar description and refresh display"""
        progress.setDescription(description)
        if progress.useBar and progress.pbar:
            progress.pbar.refresh()

    def _ensureProgress(self, fileSize: int, desc: str, resumePosition: int = 0) -> Progress:
        """Ensure progress bar exists and is configured correctly - reuse if exists, create if needed"""
        if self._currentProgress:
            self._updateProgressStatus(self._currentProgress, desc)
            # Update to resume position if provided and greater than current
            if resumePosition > self._currentProgress.transferred:
                self._currentProgress.update(resumePosition)
            return self._currentProgress

        # Create new progress bar
        # For unknown sizes, use None to let Progress class choose appropriate format
        settingsGetter = SettingsGetter.getInstance()
        barFormat = None if not self._isKnownSize(fileSize) else self._PROGRESS_BAR_FORMAT

        self._currentProgress = Progress(
            fileSize,
            sizeFormatter=formatSize,
            loggerCallback=self.loggerCallback,
            useBar=settingsGetter.isCLIMode(),
            barFormat=barFormat
        )
        self._currentProgress.setDescription(desc)
        if resumePosition > 0:
            self._currentProgress.update(resumePosition)
        return self._currentProgress

    def _finishProgress(self, complete: bool = True):
        """Finish and clean up progress bar"""
        if self._currentProgress:
            self._currentProgress.finishBar(complete=complete)
            self._currentProgress = None

    def _finishAlreadyComplete(self, fileSize: int, resumePosition: int, finalOutputPath: str, sharedProgress=None):
        """Unified helper for file already complete scenario

        Args:
            fileSize: Total file size
            resumePosition: Current file position (should equal fileSize)
            finalOutputPath: Path to the complete file
            sharedProgress: Optional shared progress bar from WebRTC download
        """
        if sharedProgress:
            self._updateProgressStatus(sharedProgress, self._STATUS_FILE_COMPLETE)
            sharedProgress.update(fileSize, forceLog=True, extraText="HTTP fallback")
        else:
            progress = self._ensureProgress(fileSize, self._STATUS_FILE_COMPLETE, resumePosition)
            progress.update(fileSize, forceLog=True, extraText="HTTP fallback")
        self._finishProgress()
        logger.debug(f"File already downloaded: {finalOutputPath}")
        return finalOutputPath

    def _setupEventLoop(self):
        """Setup dedicated event loop for WebRTC operations"""
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._runLoop, daemon=True)
        self.thread.start()

    def _runLoop(self):
        """Run asyncio event loop with exception handler"""
        asyncio.set_event_loop(self.loop)
        # Set exception handler from Mixin to catch unhandled exceptions in tasks
        self.loop.set_exception_handler(self._handleLoopException)
        self.loop.run_forever()

    def _createAuthHeaders(self, credentials: Optional[Tuple[str, str]]) -> dict:
        """Create HTTP Basic Auth headers if credentials provided"""
        if not credentials:
            return {}

        username, password = credentials
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _makeHeaders(
        self, credentials: Optional[Tuple[str, str]], extra: Optional[dict] = None, userAgent: bool = True
    ) -> dict:
        """Create headers with auth and optional extra headers

        Args:
            credentials: Optional (username, password) tuple for Basic Auth
            extra: Optional additional headers
            userAgent: If True, add User-Agent header (default: True for better compatibility)
        """
        headers = self._createAuthHeaders(credentials)

        # Add User-Agent to mimic browser for better website compatibility
        if userAgent:
            headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )

        if extra:
            headers.update(extra)
        return headers

    def _buildURL(self, base: str, path: str, excludeUID: bool = False, **params) -> str:
        """Build URL with optional query parameters

        Args:
            base: Base URL (may include UID like https://domain.com/uid/)
            path: Path to append (e.g., "/download", "/e2ee/manifest")
            excludeUID: If True, strip UID from base before appending path
            **params: Query parameters

        Returns:
            Complete URL
        """
        # Filter out None values
        queryParams = {k: str(v) for k, v in params.items() if v is not None}

        # Strip UID from base if requested (for E2EE endpoints)
        if excludeUID:
            # Extract domain without UID: https://domain.com/uid/ -> https://domain.com
            match = re.match(r'(https://[^/]+)/[^/]+/?$', base)
            if match:
                base = match.group(1)

        # Ensure we don't create double slashes
        base = base.rstrip('/')
        path = '/' + path.lstrip('/')

        url = base + path
        if queryParams:
            url += "?" + urllib.parse.urlencode(queryParams)
        return url

    @property
    def e2eeClient(self):
        """Lazy initialization of E2EEClient to ensure methods are available"""
        if self._e2eeClient is None:
            self._e2eeClient = E2EEClient(self._buildURL, self._makeHeaders)
        return self._e2eeClient

    def _getUploadModeEncryptionKey(self, urlFragment: str) -> bytes:
        """Get encryption key for upload mode - from URL fragment or user prompt

        Args:
            urlFragment: URL fragment that may contain the encryption key

        Returns:
            Raw encryption key bytes (32 bytes for AES-256)

        Raises:
            ValueError: If key is invalid or user doesn't provide one
        """
        # First check URL fragment for key
        if urlFragment:
            keyBase64 = urlFragment.strip()
            try:
                key = base64.b64decode(keyBase64)
                if len(key) == 32: # AES-256 requires 32 bytes
                    logger.debug("Using encryption key from URL fragment")
                    return key
                else:
                    logger.warning(f"Key from URL fragment has invalid length: {len(key)} bytes (expected 32)")
            except Exception as e:
                logger.warning(f"Failed to decode key from URL fragment: {e}")

        # Prompt user for key
        self.loggerCallback(_("\n⚠️  This file is encrypted. Please enter the encryption key:"))
        self.loggerCallback(_("(The key should be provided by the person who shared this file)\n"))

        try:
            keyInput = input(_("Encryption key: ")).strip()
            if not keyInput:
                raise ValueError(_("Encryption key is required to download this file"))

            # Decode base64 key
            key = base64.b64decode(keyInput)
            if len(key) != 32:
                raise ValueError(_("Invalid key length: {keyLength} bytes (expected 32 bytes for AES-256)").format(
                    keyLength=len(key)))

            return key
        except KeyboardInterrupt:
            raise RuntimeError(_("Download cancelled by user"))
        except Exception as e:
            raise ValueError(_("Invalid encryption key: {error}").format(error=e))

    def _getRemoteMetadata(self, url: str, headers: dict, isGenericURL: bool = False) -> Tuple[int, str]:
        """Get file size and name from remote server using HEAD request

        Args:
            url: For generic URLs, this is the full URL; for FastFileLink URLs, this is the base URL
            headers: HTTP headers to include
            isGenericURL: If True, use URL directly; if False, append /download endpoint
        """
        # For generic URLs, use URL directly; for FastFileLink, append /download
        headURL = url if isGenericURL else self._buildURL(url, "download")
        head = self._sendHTTPHead(headURL, headers)
        fileSize = int(head.get("Content-Length", "0") or 0)
        if fileSize == 0: # Well, in Caddy case, it always return 0.
            fileSize = int(head.get("FFL-FileSize", "0") or 0)

        # For generic URLs, extract filename from URL if no Content-Disposition header
        if isGenericURL and "Content-Disposition" not in head:
            # Extract filename from URL path
            parsedURL = urlparse(url)
            fileName = unquote(parsedURL.path.split('/')[-1]) or 'index.html'
        else:
            fileName = self._parseFileInfo(head.get("Content-Disposition", 'attachment; filename=download.bin'))

        return fileSize, fileName

    def _resolveOutputPath(self, outputPath: Optional[str], fileName: str) -> str:
        """Resolve output path handling directory vs file path cases"""
        if outputPath:
            return os.path.join(outputPath, fileName) if os.path.isdir(outputPath) else outputPath
        return fileName

    def _sendHTTPRequest(
        self,
        url: str,
        method: str = "GET",
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: int = 30
    ) -> Tuple[any, int]:
        """Make HTTP request using requests library"""
        requestHeaders = headers or {}

        try:
            if method == "GET":
                response = requests.get(url, headers=requestHeaders, timeout=timeout)
            elif method == "POST":
                requestHeaders["Content-Type"] = "application/json"
                response = requests.post(url, json=data, headers=requestHeaders, timeout=timeout)
            else:
                # Generic method support
                response = requests.request(
                    method, url, json=data if data else None, headers=requestHeaders, timeout=timeout
                )

            # Handle expected status codes for candidate polling
            if response.status_code in (204, 404):
                return None, response.status_code

            # Raise for other error status codes
            response.raise_for_status()

            # Try to parse JSON response
            if requestHeaders.get("Content-Type") == "application/json" or method == "GET":
                try:
                    return response.json(), response.status_code
                except ValueError:
                    return response.text, response.status_code
            else:
                return response.text, response.status_code

        except requests.exceptions.HTTPError as e:
            # Re-raise with status code if needed
            if e.response and e.response.status_code in (204, 404):
                return None, e.response.status_code
            raise

    def _sendHTTPHead(self, url: str, headers: Optional[dict] = None) -> dict:
        """Make HTTP HEAD request to get headers using requests library

        Automatically handles Caddy quirk where HEAD returns Content-Length: 0
        by retrying with GET when detected.
        """
        response = requests.head(url, headers=headers or {}, timeout=10)
        response.raise_for_status()
        head = response.headers

        # Check if Caddy returns Content-Length: 0 (Caddy quirk with HEAD requests)
        serverHeader = head.get('Server', '')
        contentLength = head.get('Content-Length', '')
        isCaddyWithZeroLength = ('Caddy' in serverHeader and contentLength == '0')

        # If Caddy returns Content-Length: 0, retry with GET to get proper headers
        if isCaddyWithZeroLength:
            logger.debug("Caddy returned Content-Length: 0 for HEAD, retrying with GET")
            response = requests.get(url, headers=headers or {}, timeout=10, stream=True)
            head = response.headers
            response.close() # Close immediately after getting headers

        return head # Return CaseInsensitiveDict for case-insensitive header access

    def _parseFileInfo(self, contentDisposition: str) -> str:
        """Parse filename from Content-Disposition header"""
        # Try RFC 5987 encoded filename first (handles UTF-8 properly)
        match = re.search(r"filename\*=UTF-8''([^;]+)", contentDisposition)
        if match:
            return urllib.parse.unquote(match.group(1))

        # Try standard filename parameter
        match = re.search(r'filename="?([^";]+)"?', contentDisposition)
        if match:
            # URL decode in case it's percent-encoded
            return urllib.parse.unquote(match.group(1))

        return "download.bin"

    def _handleResumeLogic(self, filePath: str, fileSize: int, allowResume: bool) -> int:
        """
        Handle resume logic for downloads

        Args:
            filePath: Path to output file
            fileSize: Total size of file to download (None or -1 for unknown)
            allowResume: Whether to resume (True) or overwrite (False)

        Returns:
            Resume position in bytes (0 for new download)
        """
        if not os.path.exists(filePath):
            return 0

        currentSize = os.path.getsize(filePath)

        # Handle unknown file size (None or -1) - cannot determine completion, always overwrite
        if not self._isKnownSize(fileSize):
            if currentSize > 0:
                logger.info(f"Unknown size file - overwriting existing {formatSize(currentSize)} file: {filePath}")
            os.remove(filePath)
            return 0

        # Known file size - handle resume or overwrite
        if not allowResume:
            # Overwrite existing file
            logger.debug(f"Overwriting existing file: {filePath}")
            os.remove(filePath)
            return 0

        # Resume mode - check if already complete
        if currentSize >= fileSize:
            return currentSize

        # Resume from current position
        if currentSize > 0:
            logger.debug(f"Resuming from {formatSize(currentSize)} / {formatSize(fileSize)}")
        return currentSize

    def _failDownload(self, context: dict, error: Exception, errorEvent: asyncio.Event):
        """Unified helper to handle download failure: close file and set error"""
        context['error'] = error
        if context.get('outputFile'):
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

    def _extractURLInfo(self, url: str) -> URLInfo:
        """Extract base URL and UID from FastFileLink URL, validate it's downloadable

        This method handles three scenarios:
        1. fastfilelink.com domain - format: https://domain.fastfilelink.com/UID
        2. Custom tunnel domains - validate by checking Server header
        3. Generic HTTP URLs - treat as direct download URLs (like wget)

        Special case: Local test server uses format http://127.0.0.1:5000/port/UID
        where 'port' is a numeric port identifier and 'UID' is the actual share ID.

        Returns:
            URLInfo: Object containing URL information and validation results

        Raises:
            ValueError: If URL is not accessible or invalid
        """
        # Extract domain and URL fragment from URL
        parsedURL = urllib.parse.urlparse(url)
        domain = parsedURL.netloc
        urlFragment = parsedURL.fragment # Extract #key for E2EE upload mode

        # Try to extract UID from URL
        uid = ""
        baseURL = ""
        supportsWebRTC = True # Assume WebRTC is supported by default

        # Strip query and fragment for pattern matching
        urlForMatching = url.split('?')[0].split('#')[0]

        # Check if original URL ended with / (before query/fragment)
        endsWithSlash = urlForMatching.endswith('/')

        # Match the entire path and extract UID
        match = re.search(r'(https?://[^/]+)(/.+?)/?$', urlForMatching)
        if match:
            domainPart = match.group(1)
            pathPart = match.group(2)
            # Extract path segments
            pathSegments = [seg for seg in pathPart.split('/') if seg]

            if pathSegments:
                # Special case: Local test server (127.0.0.1) with /port/UID format
                # Pattern: http://127.0.0.1:5000/4444/DPnpNKWs
                # Here '4444' is a port identifier (numeric) and 'DPnpNKWs' is the UID
                isLocalTestServer = '127.0.0.1' in domain or 'localhost' in domain

                if isLocalTestServer and len(pathSegments) >= 2 and pathSegments[0].isdigit():
                    # Test server format: /port/UID
                    # Use last segment as UID, keep full path in baseURL
                    uid = pathSegments[-1]
                    baseURL = domainPart + pathPart.rstrip('/')
                else:
                    # Standard format: /UID or custom tunnel
                    # Last segment is the UID
                    uid = pathSegments[-1]
                    baseURL = domainPart + pathPart.rstrip('/')
            else:
                # No path segments
                baseURL = urlForMatching.rstrip('/')
                uid = ""
        else:
            # Custom tunnel without UID (e.g., https://custom.domain.com/)
            # Use the URL without query/fragment as base, will validate via HEAD request
            baseURL = urlForMatching.rstrip('/')

        # Only append / if original URL ended with /
        if endsWithSlash and not baseURL.endswith('/'):
            baseURL += '/'

        try:
            # Try HEAD request to base URL first (Caddy quirk handled automatically)
            head = self._sendHTTPHead(baseURL.rstrip('/'), self._makeHeaders(None))

            # Check if this is a FastFileLink server
            isFastFileLinkDomain = 'fastfilelink.com' in domain
            serverHeader = head.get('Server', '')
            fflServerHeader = head.get('FFL-Server', '')
            fflMode = head.get('FFL-Mode', '')
            isFastFileLinkServer = serverHeader.startswith('FFL Server/') or bool(fflServerHeader)

            if not isFastFileLinkDomain and not isFastFileLinkServer and not fflMode:
                # Not a FastFileLink server? TRY /download:
                head = self._sendHTTPHead(f"{baseURL.rstrip('/')}/download", self._makeHeaders(None))
                fflMode = head.get('FFL-Mode', '')
                if not fflMode:
                    #  fall through to generic URL handling
                    raise requests.exceptions.RequestException("Not a FastFileLink server")

            # For fastfilelink.com, check if UID starts with "0." (upload mode, WebRTC not supported)
            if isFastFileLinkDomain and uid.startswith("0."):
                logger.info(f"UID {uid} is upload mode (starts with '0.'), WebRTC not supported")
                supportsWebRTC = False

            # Check FFL-Mode header for E2EE, WebRTC support, and upload mode
            e2eeEnabled = '+E2EE' in fflMode
            isUploadMode = '+Upload' in fflMode
            if 'HTTP' in fflMode and 'P2P' not in fflMode:
                supportsWebRTC = False

            return URLInfo(
                baseURL,
                uid,
                supportsWebRTC,
                isGenericURL=False,
                e2eeEnabled=e2eeEnabled,
                isUploadMode=isUploadMode,
                urlFragment=urlFragment
            )

        except requests.exceptions.RequestException as e:
            logger.debug(
                f"No /download endpoint found (network error or endpoint doesn't exist), "
                f"treating as generic HTTP URL: {e}"
            )

            # Verify the URL itself is accessible (use consistent headers for better compatibility)
            head = self._sendHTTPHead(url, self._makeHeaders(None))
            # This is a valid generic HTTP URL
            return URLInfo(
                baseURL=url, # Use original URL as-is
                uid="",
                supportsWebRTC=False,
                isGenericURL=True
            )

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

    def _startStatusPollingThread(self, baseURL: str, authHeaders: dict, stopEvent: threading.Event, errorQueue: deque):
        """
        Start background thread to poll server status for errors (unified for WebRTC and HTTP)

        Args:
            baseURL: Base URL for the download
            authHeaders: Authentication headers
            stopEvent: Threading event to signal when to stop polling
            errorQueue: Deque to store detected errors (thread-safe, lock-free reads)
        """

        def pollingWorker():
            statusURL = self._buildURL(baseURL, "status", excludeUID=False)
            pollInterval = 0.5 # Poll every 0.5 seconds for faster error detection

            logger.debug(f"[STATUS_POLL] Background thread started, URL: {statusURL}")

            while not stopEvent.is_set():
                try:
                    # Poll status endpoint
                    logger.debug(f"[STATUS_POLL] Polling status endpoint...")
                    statusData, status = self._sendHTTPRequest(statusURL, "GET", None, authHeaders, 5)

                    logger.debug(
                        f"[STATUS_POLL] Status response: {status}, has error: {statusData.get('error') 
                                                                               if statusData else None}"
                    )

                    if status == 200 and statusData:
                        error = statusData.get('error')
                        if error:
                            errorType = error.get('type', 'unknown')
                            errorDetail = error.get('detail', 'Server reported an error')
                            exceptionClass = error.get('exceptionClass', '')

                            logger.debug(f"[STATUS_POLL] Server error detected: {errorType}")

                            # Create appropriate exception based on server error class
                            if exceptionClass == FolderChangedException.__name__:
                                exception = FolderChangedException(errorDetail)
                            else:
                                exception = RuntimeError(errorDetail)

                            # Add to error queue (thread-safe append, no lock needed)
                            errorQueue.append(exception)
                            logger.debug("[STATUS_POLL] Error added to queue, stopping polling")
                            return

                    # Wait before next poll (check stopEvent periodically)
                    stopEvent.wait(pollInterval)

                except Exception as e:
                    # Log but don't fail - status polling is best-effort
                    logger.debug(f"[STATUS_POLL] Polling error (non-fatal): {e}")
                    if not stopEvent.is_set():
                        stopEvent.wait(pollInterval)

            logger.debug("[STATUS_POLL] Background thread stopped")

        # Start background daemon thread
        thread = threading.Thread(target=pollingWorker, daemon=True, name="StatusPolling")
        thread.start()
        return thread

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
        statusErrorQueue: Optional[deque] = None
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
            'error': None,
            'downloadStarted': False,
            'statusUpdated': False,
            'streamDecryptor': streamDecryptor
        }

        # Monitor connection state for early failure detection
        @pc.on("connectionstatechange")
        async def onConnectionStateChange():
            state = pc.connectionState
            logger.debug(f"WebRTC connection state changed to: {state}")

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
            # Open file when data channel is established (append mode if resuming)
            mode = 'ab' if resumePosition > 0 else 'wb'
            context['outputFile'] = open(outputPath, mode)

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
                                context['outputFile'].close()

                            # Final progress update
                            progress.update(context['bytesReceived'], forceLog=True, extraText="WebRTC P2P")

                            # Notify server of completion (best effort - peer may already be cleaned up)
                            context['completionTask'] = asyncio.create_task(
                                self._notifyCompletionSafely(baseURL, peerId, authHeaders)
                            )
                            downloadComplete.set()
                        elif data == "ERROR":
                            progress.write("Server reported error during transfer")
                            if context['outputFile']:
                                context['outputFile'].close()
                            downloadComplete.set()
                    else:
                        # Binary data
                        if context['outputFile']:
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
        urlInfo: Optional[URLInfo] = None
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
        fileSize, filename = await asyncio.to_thread(self._getRemoteMetadata, urlInfo.baseURL, authHeaders)

        # Resolve output path using helper
        finalOutputPath = self._resolveOutputPath(outputPath, filename)

        # Display file info
        fileSizeDisplay = f"{fileSize:,} bytes" if self._isKnownSize(fileSize) else "unknown bytes"
        self.loggerCallback(_("Downloading {filename} ({fileSize})").format(
            filename=filename, fileSize=fileSizeDisplay))

        # Handle resume logic
        resumePosition = self._handleResumeLogic(finalOutputPath, fileSize, resume)

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

        iceServers = DEFAULT_ICE_SERVERS

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
                e2eeContext, statusErrorQueue
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

                # Connection establishment timeout (cleared when download starts)
                connectionTimeout = self.connectionTimeout
                connectionStart = time.time()

                # Monitor context and update status when download starts
                while True:
                    # Update status to "Downloading" when first data arrives
                    if context['downloadStarted'] and not context['statusUpdated']:
                        self._updateProgressStatus(progress, self._STATUS_DOWNLOADING)
                        context['statusUpdated'] = True
                        # Clear connection timeout once download starts
                        connectionTimeout = None

                    # Check status error queue (lock-free, no performance impact)
                    if statusErrorQueue:
                        serverError = statusErrorQueue[0]
                        logger.debug(f"[WebRTC] Error found in queue: {serverError}")
                        statusStopEvent.set()
                        await self._cancelTasks([pollingTask, completionTask, errorTask])
                        raise serverError

                    # Check connection timeout (only before download starts)
                    if connectionTimeout:
                        elapsed = time.time() - connectionStart
                        if elapsed > connectionTimeout:
                            statusStopEvent.set()
                            await self._cancelTasks([pollingTask, completionTask, errorTask])
                            raise WebRTCConnectionTimeout(
                                f"WebRTC connection timeout after {connectionTimeout} seconds"
                            )

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
                if context.get('outputFile'):
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

            return finalOutputPath

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

    def _downloadViaHTTP(
        self,
        url: str,
        outputPath: Optional[str] = None,
        credentials: Optional[Tuple[str, str]] = None,
        sharedProgress=None,
        resume: bool = False,
        forceResume: bool = False,
        e2eeContext: Optional[dict] = None,
        urlInfo: Optional[URLInfo] = None
    ) -> str:
        """
        Download file via HTTP with resume capability as fallback

        Args:
            resume: If True, resume incomplete download; if False, overwrite existing file
            forceResume: If True, always resume from existing file (used for WebRTC fallback)
            urlInfo: Optional pre-parsed URL info to avoid redundant parsing
        """

        # Parse the original URL to get base URL and construct download endpoint
        # Follow same pattern as DownloadManager.js: /{uid}/download
        if urlInfo is None:
            urlInfo = self._extractURLInfo(url)

        # For generic URLs, use the URL directly; otherwise construct /download endpoint
        if urlInfo.isGenericURL:
            downloadURL = urlInfo.baseURL # Use original URL as-is for generic downloads
        else:
            # Construct the download URL (same as web interface)
            downloadURL = self._buildURL(urlInfo.baseURL, "download")

        # Get file metadata using HEAD request - always respect Content-Disposition from server
        if sharedProgress:
            self._updateProgressStatus(sharedProgress, self._STATUS_METADATA)
        try:
            headers = self._makeHeaders(credentials)
            # For generic URLs, use the actual URL directly; for FastFileLink URLs, use baseURL
            metadataURL = url if urlInfo.isGenericURL else urlInfo.baseURL
            fileSize, fileName = self._getRemoteMetadata(metadataURL, headers, isGenericURL=urlInfo.isGenericURL)
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                raise RuntimeError("File not found or expired")
            raise RuntimeError(f"Failed to get file metadata: HTTP {e.response.status_code if e.response else 'error'}")
        except Exception as e:
            raise RuntimeError(f"Failed to get file metadata: {e}")

        # Resolve output path using helper
        finalOutputPath = self._resolveOutputPath(outputPath, fileName)

        # Handle resume logic (forceResume takes precedence for WebRTC fallback)
        resumePosition = self._handleResumeLogic(finalOutputPath, fileSize, forceResume or resume)

        # File already complete - early return (skip check for unknown/unreliable sizes)
        if (self._isPositiveSize(fileSize) and resumePosition >= fileSize and
            not (urlInfo.isGenericURL and fileSize == 0)):
            return self._finishAlreadyComplete(fileSize, resumePosition, finalOutputPath, sharedProgress)

        # Show resume message if resuming (only when not using shared progress and size is known)
        if resumePosition > 0 and not sharedProgress and self._isPositiveSize(fileSize):
            self.loggerCallback(_("Resuming download from {resumePos} / {totalSize}").format(
                resumePos=formatSize(resumePosition), totalSize=formatSize(fileSize)
            ))

        # Use shared progress or create new one
        if sharedProgress:
            progress = sharedProgress
            self._updateProgressStatus(progress, self._STATUS_HTTP_DOWNLOAD)
            # Update progress to current resume position if needed
            if resumePosition > 0 and resumePosition > progress.transferred:
                progress.update(resumePosition)
        else:
            progress = self._ensureProgress(fileSize, self._STATUS_HTTP_DOWNLOAD, resumePosition)

        # Set range header for resume using helper
        rangeHeader = {'Range': f'bytes={resumePosition}-'} if resumePosition > 0 else None
        downloadHeaders = self._makeHeaders(credentials, rangeHeader)

        # Initialize E2EE stream decryptor if enabled (tags fetched on-demand)
        streamDecryptor = None
        if e2eeContext:
            streamDecryptor = self.e2eeClient.createHTTPDecryptor(e2eeContext, resumePosition)

        # Start download without extra logging if using shared progress

        # Create session with StallResilientAdapter for Python 3.12 workarounds and better stall handling
        session = requests.Session()
        adapter = StallResilientAdapter(
            chunkSize=TRANSFER_CHUNK_SIZE,
            allowedMethods={'GET'}  # Download method only
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Start background thread for status polling
        statusStopEvent = threading.Event()
        statusErrorQueue = deque()
        self._startStatusPollingThread(urlInfo.baseURL, downloadHeaders, statusStopEvent, statusErrorQueue)

        try:
            # Use tuple timeout: (connect_timeout, read_timeout) with increased read timeout
            # to handle large file stalls (especially on Python 3.12 + TLS 1.3)
            with session.get(downloadURL, headers=downloadHeaders, stream=True, 
                             timeout=(HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT)) as response:
                # Check status codes
                if response.status_code not in (200, 206): # 206 is partial content for resume
                    raise RuntimeError(f"HTTP download failed: {response.status_code}")

                # Verify content range for resume
                if resumePosition > 0 and response.status_code != 206:
                    raise RuntimeError("Server does not support resume")

                # For unknown size (generic URLs or stdin), try to get actual Content-Length from GET response
                if not self._isKnownSize(fileSize):
                    actualContentLength = response.headers.get('Content-Length')
                    if actualContentLength:
                        actualSize = int(actualContentLength)
                        if actualSize > 0:
                            fileSize = actualSize
                            # Recreate progress bar with actual size
                            if not sharedProgress:
                                self._finishProgress(complete=False)
                                progress = self._ensureProgress(fileSize, self._STATUS_HTTP_DOWNLOAD, resumePosition)

                # Open file for writing (append mode if resuming)
                mode = 'ab' if resumePosition > 0 else 'wb'
                totalDownloaded = resumePosition # Start from resume position

                with open(finalOutputPath, mode) as f:
                    for chunk in response.iter_content(chunk_size=TRANSFER_CHUNK_SIZE):
                        # Check status error queue (lock-free, very fast - no performance impact)
                        if statusErrorQueue:
                            serverError = statusErrorQueue[0]
                            logger.debug(f"[HTTP] Error found in queue: {serverError}")
                            statusStopEvent.set()
                            raise serverError

                        if chunk: # Filter out keep-alive chunks
                            # Process chunk (decrypt if E2EE enabled, otherwise passthrough)
                            processedData = streamDecryptor.processChunk(chunk) if streamDecryptor else chunk

                            f.write(processedData)
                            totalDownloaded += len(processedData)
                            progress.update(totalDownloaded, extraText="HTTP fallback")

                    # Flush any remaining buffered data
                    if streamDecryptor:
                        finalData = streamDecryptor.flush()
                        if finalData:
                            f.write(finalData)
                            totalDownloaded += len(finalData)
                            progress.update(totalDownloaded, extraText="HTTP fallback")

        except requests.exceptions.RequestException as e:
            # Don't update progress to 100% on failure
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise RuntimeError(f"Network error during HTTP download: {e}")
        except KeyboardInterrupt:
            # User cancelled - clean up progress bar
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise
        except FolderChangedException:
            # Re-raise folder change exceptions as-is (don't wrap in RuntimeError)
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise
        except Exception as e:
            # Don't update progress to 100% on any failure
            statusStopEvent.set()
            if not sharedProgress:
                self._finishProgress(complete=False)
            raise RuntimeError(f"HTTP download failed: {e}")
        finally:
            statusStopEvent.set()
            session.close()  # Clean up session resources

        # Verify final file size (skip for generic URLs and unknown sizes)
        finalSize = os.path.getsize(finalOutputPath)
        if not urlInfo.isGenericURL and self._isPositiveSize(fileSize) and finalSize != fileSize:
            raise RuntimeError(f"Download incomplete: {finalSize} != {fileSize} bytes")

        # Final progress update on success
        progress.update(finalSize, forceLog=True, extraText="HTTP fallback")
        if not sharedProgress: # Only finish bar if we created it
            self._finishProgress()
        # Only log to logger, not loggerCallback to avoid extra line after progress bar
        logger.debug(f"HTTP download completed: {finalOutputPath}")
        return finalOutputPath

    def _fallbackToHTTP(
        self,
        url: str,
        outputPath: Optional[str],
        credentials: Optional[Tuple[str, str]],
        resume: bool,
        webrtcError: Exception,
        e2eeContext: Optional[dict] = None,
        urlInfo: Optional[URLInfo] = None
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
            fileSize, __ = self._getRemoteMetadata(urlInfo.baseURL, authHeaders)
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
                urlInfo=urlInfo
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

    def downloadFile(
        self,
        url: str,
        outputPath: Optional[str] = None,
        credentials: Optional[Tuple[str, str]] = None,
        resume: bool = False
    ) -> str:
        """Download file via WebRTC with HTTP fallback"""
        # Validate URL and check if WebRTC is supported
        try:
            urlInfo = self._extractURLInfo(url)
        except (ValueError, requests.exceptions.RequestException) as e:
            raise RuntimeError(f"Invalid download URL: {e}")

        # If this is a generic HTTP URL (not FastFileLink), show warning and download directly
        if urlInfo.isGenericURL:
            self.loggerCallback(_("⚠️  This is not a FastFileLink URL, downloading directly via HTTP (like wget)..."))
            return self._downloadViaHTTP(url, outputPath, credentials, None, resume, e2eeContext=None, urlInfo=urlInfo)

        # Check for E2EE encryption using FFL-Mode header
        e2eeContext = None
        if urlInfo.e2eeEnabled:
            self.loggerCallback(_("🔒 End-to-end encryption detected"))

            # Get encryption key for upload mode (from URL fragment or user input)
            contentKey = self._getUploadModeEncryptionKey(urlInfo.urlFragment) if urlInfo.isUploadMode else None

            # Build E2EE context (handles both upload and P2P modes)
            # Returns None if E2EE is not actually enabled (e.g., manifest endpoint returns 404)
            e2eeContext = self.e2eeClient.buildE2EEContext(urlInfo.baseURL, urlInfo.isUploadMode, contentKey)

            if e2eeContext and urlInfo.isUploadMode:
                self.loggerCallback(_("✓ Encryption key verified successfully"))

        webrtcDisabled = os.getenv('DISABLE_WEBRTC', None) == 'True'

        # If WebRTC is not supported (upload mode), use HTTP download directly
        useWebRTC = urlInfo.supportsWebRTC and not webrtcDisabled

        if not useWebRTC:
            self.loggerCallback(_("WebRTC not supported, using HTTP download..."))
            return self._downloadViaHTTP(
                url, outputPath, credentials, None, resume, e2eeContext=e2eeContext, urlInfo=urlInfo
            )

        future = None
        try:
            # Try WebRTC first
            self.loggerCallback(_("Attempting WebRTC download..."))
            future = asyncio.run_coroutine_threadsafe(
                self._downloadViaWebRTC(url, outputPath, credentials, resume, e2eeContext, urlInfo), self.loop
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
        except WebRTCConnectionTimeout as timeoutError:
            # Connection establishment timed out, fall back to HTTP
            return self._fallbackToHTTP(url, outputPath, credentials, resume, timeoutError, e2eeContext, urlInfo)
        except Exception as webrtcError:
            # Log WebRTC failure and fall back to HTTP
            logger.debug(f"WebRTC download failed: {webrtcError}")
            return self._fallbackToHTTP(url, outputPath, credentials, resume, webrtcError, e2eeContext, urlInfo)

    def close(self):
        """Cleanup resources"""
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)

