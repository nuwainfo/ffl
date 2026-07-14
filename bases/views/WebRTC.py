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

import datetime
import os

from http import HTTPStatus

from bases.Kernel import getLogger, FFLEvent
from bases.Utils import formatSize
from bases.WebRTC import WebRTCDisabledError
from bases.views import BaseController, BaseView, HTTPResult

logger = getLogger(__name__)


class WebRTCController(BaseController):
    """WebRTC signaling (offer/answer/candidate) decisions for one ShareSession."""

    def getTemplateContext(self, webrtcOverride=None, webrtcOverrideRequested=False) -> dict:
        """WebRTC-disable flag for the /static/index.html template context.

        webrtcOverride: True/False/None — the parsed ?webrtc= query param (None
        if absent or unrecognized). webrtcOverrideRequested: whether ?webrtc=
        was present at all, regardless of whether it parsed cleanly.
        """
        webrtcDisabled = os.getenv('DISABLE_WEBRTC', None) == 'True'

        if webrtcOverride is False:
            webrtcDisabled = True
        elif webrtcOverride is True:
            webrtcDisabled = False
        else:
            pass

        if not webrtcOverrideRequested and not self.session.config.defaultWebRTC:
            webrtcDisabled = True

        return {'disableWebRTC': webrtcDisabled}

    def createOffer(self, reader, size, browserHint, offset) -> HTTPResult:
        e2eeManager = self.session.e2eeManager if self.session.config.e2eeEnabled else None

        try:
            offer = self.session.webRTC.runAsync(
                self.session.webRTC.createOffer(
                    reader, size, formatSize, browserHint=browserHint, offset=offset, e2eeManager=e2eeManager
                )
            )
        except WebRTCDisabledError as e:
            # Handle WebRTC policy enforcement - use 403 Forbidden
            logger.info(f"WebRTC offer rejected by policy: {e.reason}")
            return HTTPResult(status=HTTPStatus.FORBIDDEN, body=e.reason.encode())

        # Trigger webrtcOfferReceived event
        FFLEvent.webrtcOfferReceived.trigger(
            peerId=offer.get('peerId'),
            sessionId=offer.get('sessionId'),
            timestamp=datetime.datetime.now().isoformat()
        )
        return self._buildJSONResult(offer)

    def getCandidate(self, args) -> HTTPResult:
        # Get peerId from query parameters
        peerId = args.get("peer", [""])[0] if "peer" in args else ""
        if not peerId:
            return self._buildNotFoundResult("Missing peer parameter")

        # Get candidate from WebRTC manager
        try:
            candidate = self.session.webRTC.getCandidates(peerId)
        except ValueError:
            return self._buildNotFoundResult("Unknown peer")

        if candidate:
            return self._buildJSONResult(candidate)

        # No candidates available
        return self._buildNoContentResult()

    def submitAnswer(self, data) -> HTTPResult:
        result = self.session.webRTC.runAsync(self.session.webRTC.setAnswer(data))
        return HTTPResult(status=HTTPStatus.OK, body=result.encode())

    def submitCandidate(self, data) -> HTTPResult:
        self.session.webRTC.runAsync(self.session.webRTC.addCandidate(data), wait=False, name="addCandidate")
        return HTTPResult(status=HTTPStatus.OK, body=b"OK")


class WebRTCView(BaseView):
    """Mounts GET /offer, GET /candidate, POST /answer, POST /candidate."""

    controller = WebRTCController

    @staticmethod
    def _detectBrowser(userAgent: str) -> str:
        """Detect browser type from User-Agent header for DTLS strategy selection"""
        userAgent = userAgent.lower()

        if 'firefox' in userAgent:
            return 'firefox'
        elif 'chrome' in userAgent:
            return 'chrome'
        elif 'edge' in userAgent:
            return 'edge'
        elif 'safari' in userAgent and 'chrome' not in userAgent:
            return 'safari'
        else:
            return 'unknown'

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        # These paths require a /{uid}/... prefix in multi-session mode and are
        # additionally forbidden for HEAD — GET/POST only.
        mapHEADRoute('/offer', self._handleForbiddenHead)
        mapHEADRoute('/answer', self._handleForbiddenHead)
        mapHEADRoute('/candidate', self._handleForbiddenHead)

        self._registerRoute(mapGETRoute, '/offer', self.handleOffer)
        self._registerRoute(mapGETRoute, '/candidate', self.handleCandidatePolling)
        self._registerRoute(mapPOSTRoute, '/answer', self.handleAnswer)
        self._registerRoute(mapPOSTRoute, '/candidate', self.handleCandidate)

    def _getWebRTCDebugOptions(self, args):
        """Collect WebRTC-specific debug/test options from URL params."""
        return {
            'simulateIceFailure': bool(args) and self.parseURLBooleanParam(args.get('simulate-ice-failure', [None])[0]),
            'simulateStall': bool(args) and self.parseURLBooleanParam(args.get('simulate-stall', [None])[0]),
            'stallAfterBytes': self._parsePositiveDebugIntArg(args, 'stall-after', default=50000),
        }

    def handleOffer(self, args, *, controller):
        if not self._checkViewAccess(self.path, args):
            return

        # Check for debug simulation parameters
        debugOptions = self._getWebRTCDebugOptions(args)
        if debugOptions['simulateIceFailure']:
            logger.warning("Debug: Simulating ICE failure - returning 500 error")
            self.send_error(500, "Simulated ICE connection failure for testing")
            return

        if debugOptions['simulateStall']:
            stallAfter = debugOptions['stallAfterBytes']
            logger.warning(f"Debug: Simulating stall after {stallAfter} bytes - WebRTC will work initially")

        # Handle resume offset parameter
        offset = self._parseIntArg(args, 'offset', default=0)
        if offset:
            logger.info(f"Resume requested from offset: {offset}")

        _path, _name, size, _ctype, reader = self._getFileInfo()

        # Detect browser for DTLS strategy selection
        userAgent = self.headers.get('User-Agent', '')
        browserHint = self._detectBrowser(userAgent)
        logger.info(f"Detected browser: {browserHint} from User-Agent: {userAgent[:100]}...")

        result = controller.createOffer(reader, size, browserHint, offset)
        self.sendHTTPResult(result)

    def handleCandidatePolling(self, args, *, controller):
        result = controller.getCandidate(args)
        self.sendHTTPResult(result)

    def handleAnswer(self, data, *, controller):
        result = controller.submitAnswer(data)
        self.sendHTTPResult(result)

    def handleCandidate(self, data, *, controller):
        result = controller.submitCandidate(data)
        self.sendHTTPResult(result)

    def contributeTemplateContext(self, args) -> dict:
        webrtcParam = args.get('webrtc', [None])[0] if args else None
        webrtcOverride = self.parseURLBooleanParam(webrtcParam) if webrtcParam else None

        return self._makeController().getTemplateContext(
            webrtcOverride=webrtcOverride,
            webrtcOverrideRequested=bool(webrtcParam),
        )
