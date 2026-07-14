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

import os

from bases.Utils import flushPrint
from bases.views import BaseController, BaseView, HTTPResult


class DebugController(BaseController):
    """Client-side debug log ingestion and debug-flag decisions for one ShareSession."""

    def getTemplateContext(self, serverDebugRequested=False, debugRequested=False) -> dict:
        """Client debug page flags for the /static/index.html template context."""
        return {
            'debug': debugRequested or os.getenv('JS_DEBUG', None) == 'True',
            'serverDebug': serverDebugRequested or os.getenv('JS_LOG_TO_SERVER_DEBUG', None) == 'True',
        }

    def recordDebugLog(self, data: dict, userAgent: str) -> HTTPResult:
        """POST /debug/log — client-side debug log messages for mobile debugging.

        Usage (follows same pattern as DEBUG and DISABLE_WEBRTC):
        1. Set environment variable: JS_LOG_TO_SERVER_DEBUG="True"
        2. Access URL with parameter: ?debug=server
        3. Server replaces 'const SERVER_DEBUG = false;' with 'const SERVER_DEBUG = true;'
        4. Client logs are forwarded to server stdout via flushPrint()

        This is useful for debugging on mobile devices where console access is limited.
        """
        category = data.get('category', 'CLIENT')
        message = data.get('message', '')
        timestamp = data.get('timestamp', '')
        sessionId = data.get('sessionId', 'unknown')

        # Format and print the debug message to server stdout
        logPrefix = f"[{timestamp}] [CLIENT-DEBUG] [{category}] [Session:{sessionId[:8]}]"
        flushPrint(f"{logPrefix} {message}")

        # Log user agent for context (only once per session)
        if sessionId not in self.session._debugUserAgentSessions:
            flushPrint(f"[CLIENT-DEBUG] [INFO] [Session:{sessionId[:8]}] User-Agent: {userAgent}")
            self.session._debugUserAgentSessions.add(sessionId)

        return self._buildJSONResult({"status": "success"})


class DebugView(BaseView):
    """Mounts POST /debug/log (only when JS_LOG_TO_SERVER_DEBUG is enabled) and
    contributes debug page flags to the /static/index.html template context."""

    controller = DebugController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        if os.getenv('JS_LOG_TO_SERVER_DEBUG') == 'True':
            self._registerRoute(mapPOSTRoute, '/debug/log', self.handleDebugLog)

    def handleDebugLog(self, data, *, controller):
        userAgent = self.headers.get('User-Agent', 'Unknown')
        result = controller.recordDebugLog(data, userAgent)
        self.sendHTTPResult(result)

    def contributeTemplateContext(self, args) -> dict:
        debugParam = args.get('debug', [None])[0] if args else None
        serverDebugRequested = bool(debugParam) and debugParam.lower() == 'server'
        debugRequested = (
            bool(debugParam) and not serverDebugRequested and self.parseURLBooleanParam(debugParam) is True
        )

        return self._makeController().getTemplateContext(
            serverDebugRequested=serverDebugRequested,
            debugRequested=debugRequested,
        )
