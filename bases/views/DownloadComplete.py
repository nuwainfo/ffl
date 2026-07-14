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

from http import HTTPStatus
from typing import Optional

from bases.Kernel import getLogger, FFLEvent
from bases.views import BaseController, BaseView, HTTPResult

logger = getLogger(__name__)


class DownloadCompleteController(BaseController):
    """Download-completion notification/ACK decisions for one ShareSession.

    Handles two cases sharing the /complete endpoint:
    - WebRTC P2P: payload contains peerId, unblocks sendFile()'s completion wait
    - HTTP relay:  payload contains downloadId, unblocks _waitForHTTPDownloadComplete()
    """

    def notifyWebRTCIfPresent(self, data: dict, clientInfo: dict) -> Optional[str]:
        """If data contains peerId, notify the WebRTC manager and fire its receipt event.

        Returns 'webrtc' as the connection type, or None if this wasn't a WebRTC completion.
        """
        if 'peerId' not in data:
            return None

        self.session.webRTC.runAsync(
            self.session.webRTC.notifyDownloadComplete(data), wait=False, name="notifyDownloadComplete"
        )
        FFLEvent.receiptCreated.trigger(downloadId=data['peerId'], connectionType='webrtc', clientInfo=clientInfo)
        return 'webrtc'

    def acknowledgeHttpCompletion(self, downloadId: str, clientInfo: dict):
        """Acknowledge an HTTP relay completion. Must be called AFTER the /complete
        response has been sent — acknowledging may unblock a file-serving thread
        that shuts the connection down, which must never race the response write.
        """
        ackStatus = self.session.httpDownloadCompletionStore.acknowledge(downloadId)
        if ackStatus == 'accepted':
            logger.debug(f"HTTP download complete ACK received for {downloadId[:8]}")
            FFLEvent.receiptCreated.trigger(downloadId=downloadId, connectionType='http', clientInfo=clientInfo)
        elif ackStatus == 'duplicate':
            logger.debug(f"HTTP download complete ACK duplicate ignored for {downloadId[:8]}")
        else:
            logger.debug(f"HTTP download complete ACK: unknown downloadId {downloadId[:8]}")


class DownloadCompleteView(BaseView):
    """Mounts POST /complete.

    _buildDownloadCompleteResponse() stays on DownloadHandler (not the controller):
    addons/Features.py dynamically subclasses DownloadHandler and overrides it to
    inject licensing-driven receipt-confirmation payloads, so it must remain a
    normal overridable method on the handler class, not move into a fresh
    per-request controller instance.
    """

    controller = DownloadCompleteController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        # /complete is GET/POST only. Pre-existing quirk, preserved as-is: this
        # also gets gated by --force-relay, same as the WebRTC signaling paths.
        mapHEADRoute('/complete', self._handleForbiddenHead)
        self._registerRoute(mapPOSTRoute, '/complete', self.handleComplete)

    def handleComplete(self, data, *, controller):
        clientInfo = {
            'userAgent': self.headers.get('User-Agent', 'Unknown'),
            'domain': self.headers.get('Host', 'Unknown'),
        }

        connectionType = controller.notifyWebRTCIfPresent(data, clientInfo)

        downloadId = data.get('downloadId')
        if downloadId:
            connectionType = 'relay'

        payload, contentType = self._buildDownloadCompleteResponse(data)
        headers = {'FFL-CompleteType': connectionType} if connectionType else {}
        self.sendHTTPResult(HTTPResult(status=HTTPStatus.OK, body=payload, contentType=contentType, headers=headers))

        # Acknowledge AFTER sending the response so the file-serving thread (which may call
        # _forceShutdown) cannot race the response delivery and close the connection first.
        if downloadId:
            controller.acknowledgeHttpCompletion(downloadId, clientInfo)
