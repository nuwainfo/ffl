#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import asyncio
import sys
import threading
import uuid
import concurrent.futures

from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple

from aiortc import (RTCConfiguration, RTCDataChannel, RTCIceServer, RTCPeerConnection, RTCSessionDescription)
from aiortc.sdp import candidate_from_sdp

from bases.Kernel import getLogger
from bases.Utils import ONE_MB, ONE_KB, ONE_GB, sendException
from bases.Progress import Progress
from bases.Settings import SettingsGetter

# Without winloop, Edge will fail to use WebRTC, it will cause consent query timeout after few seconds.
# It speeds up a lot on Firefox, but slow down a little on Chrome/Edge.
if sys.platform == "win32":
    # Please "import winloop._noop" rather than "import winloop" here,
    # or it will raise "No module named winloop" error.
    # https://github.com/Vizonex/Winloop/issues/9
    import winloop._noop  # pylint: disable=import-error
    winloop.install()
    assert isinstance(asyncio.get_event_loop_policy(), winloop.EventLoopPolicy)

# Setup logging
logger = getLogger(__name__)


@dataclass
class ClientInfo:
    browser: str
    domain: str
    protocol: str
    userAgent: str
    isLocalConnection: bool = False
    detectedIp: Optional[str] = None


class WebRTCManager:

    def __init__(self, loggerCallback=print, downloadCallback=None):
        # WebRTC state
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._runLoop, daemon=True)
        self.thread.start()
        self.pcs: Set[RTCPeerConnection] = set()
        self.peers: Dict[str, Tuple[RTCPeerConnection, Optional[ClientInfo], deque]] = {}
        self.loggerCallback = loggerCallback
        self.downloadCallback = downloadCallback

        # Download completion events for each peer
        self.downloadCompleteEvents: Dict[str, threading.Event] = {}

        # ICE servers configuration
        self.iceServers = [
            RTCIceServer(urls="stun:stun.l.google.com:19302"),
            RTCIceServer(urls="stun:stun.cloudflare.com:3478"),
            RTCIceServer(urls="stun:stun.nextcloud.com:443"),
            RTCIceServer(urls="stun:openrelayproject.org:80"),
            RTCIceServer(urls="stun:openrelayproject.org:443"),
        ]

    def _runLoop(self):
        # Run asyncio event loop"""
        asyncio.set_event_loop(self.loop)
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

    async def createOffer(self, filePath, fileSize, getSizeFunc=None, browserHint=None):
        # Generate a unique peer ID
        peerId = uuid.uuid4().hex

        config = RTCConfiguration(iceServers=self.iceServers)
        pc = RTCPeerConnection(configuration=config)
        q = deque() # ICE candidate queue
        self.pcs.add(pc)
        # Store peer connection with its ID (initially no client info) and candidate queue
        self.peers[peerId] = (pc, None, q)

        # Initialize download completion event for this peer
        self.downloadCompleteEvents[peerId] = threading.Event()

        def candidateToSdp(candidate):
            # Convert RTCIceCandidate to SDP string format
            return (
                f"candidate:{candidate.foundation} {candidate.component} {candidate.protocol} {candidate.priority} "
                f"{candidate.ip} {candidate.port} typ {candidate.type}"
            )

        @pc.on("icecandidate")
        async def _onICECandidate(evt):
            # evt.candidate might be None
            cand = evt.candidate
            if cand is None:
                q.append({"candidate": "end-of-candidates"})
            else:
                q.append({
                    "candidate": candidateToSdp(cand),
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

        asyncio.create_task(self.sendFile(dc, peerId, filePath, fileSize, getSizeFunc))

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

        # Signal that download is complete for this peer
        if peerId in self.downloadCompleteEvents:
            self.downloadCompleteEvents[peerId].set()

        return "OK"

    def getCandidates(self, peerId: str):
        peerEntry = self.peers.get(peerId)
        if not peerEntry:
            raise ValueError("Unknown peer")

        pc, clientInfo, q = peerEntry
        if q:
            return q.popleft() # Return and remove the first candidate
        else:
            return None # No candidates available

    async def sendFile(self, dc: RTCDataChannel, peerId: str, filePath: str, fileSize: int, getSizeFunc=None):
        CHUNK_SIZE = 256 * ONE_KB # 256 KB

        while dc.readyState != "open":
            await asyncio.sleep(0.05)

        pc = None
        clientInfo = None

        # Get client info from peers dict
        peerEntry = self.peers.get(peerId)
        if peerEntry:
            pc, clientInfo, q = peerEntry
            if clientInfo:
                logger.info(f"Starting file transfer for {clientInfo.browser} browser on {clientInfo.domain}")
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

        bufferFlushed = asyncio.Event()
        bufferFlushed.set()

        def setFlushed():
            bufferFlushed.set()

        dc.on("bufferedamountlow", setFlushed)

        sent = 0

        settingsGetter = SettingsGetter.getInstance()
        progress = Progress(
            fileSize,
            sizeFormatter=getSizeFunc,
            loggerCallback=self.loggerCallback,
            useBar=settingsGetter.isCLIMode(),
        )

        try:
            with open(filePath, "rb") as fp:
                while True:
                    chunk = fp.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Wait until buffer is acceptable for next packet
                    await bufferFlushed.wait()

                    dc.send(chunk)
                    sent += len(chunk)
                    bufferFlushed.clear()

                    if clientInfo and clientInfo.browser in ('edge', 'chrome'):
                        # Use isLocalConnection instead of domain check
                        if clientInfo.isLocalConnection:
                            # https://github.com/aiortc/aioice/issues/58
                            await asyncio.sleep(
                                0.047
                            ) # Apply Chrome/Edge strategy for local connections, 3 ticks trick.

                    # Progress logging every 5MB or every 2 seconds
                    progress.update(sent, extraText="P2P direct")

            # Send EOF marker
            dc.send("EOF")

            # Final progress update
            progress.update(sent, forceLog=True, extraText="P2P direct")

            # Calculate final statistics
            totalTime = progress.getElapsedTime()
            sizeDisplay = getSizeFunc(sent) if getSizeFunc else f"{sent / (ONE_MB):.2f} MB"
            self.loggerCallback(
                f'Finish transfer {sizeDisplay} for [#{peerId[:5]}], '
                'please wait for the recipient to finish downloading before you close the application..\n'
            )

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

            # Remove the peer connection from peers dictionary
            peerEntry = self.peers.pop(peerId, None)
            if peerEntry:
                pc, clientInfo, q = peerEntry
                await pc.close()
                self.pcs.discard(pc)

            # Clean up the completion event
            self.downloadCompleteEvents.pop(peerId, None)

            # Trigger post event (includes tracking and callback)
            self._handlePostDownloadActions(sent)

        except Exception as e:
            logger.exception(f"Error sending file: {e}")
            try:
                dc.send("ERROR")
            except Exception as ee:
                logger.debug(str(ee))
                pass

            # Clean up the connection on error
            peerEntry = self.peers.pop(peerId, None)
            if peerEntry:
                pc, clientInfo, q = peerEntry
                await pc.close()
                self.pcs.discard(pc)

            # Clean up the completion event on error
            self.downloadCompleteEvents.pop(peerId, None)

    async def shutdownWebRTC(self):
        pcsToClose = [pc for pc, _, _ in self.peers.values()]
        await asyncio.gather(*[pc.close() for pc in pcsToClose], return_exceptions=True)
        self.pcs.clear()
        self.peers.clear()
        self.downloadCompleteEvents.clear()

    def closeWebRTC(self):
        try:
            self.runAsync(self.shutdownWebRTC(), timeout=5)
        except Exception as e:
            logger.exception(f"Error closing WebRTC connections: {e}")
