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
from typing import Mapping, Optional

from bases.E2EE import CryptoHelper, E2EE_PROTOCOL_VERSION
from bases.Kernel import getLogger
from bases.views import BaseController, BaseView, HTTPResult

logger = getLogger(__name__)


class E2EEController(BaseController):
    """E2EE manifest/tags/init decisions for one ShareSession."""

    def getManifest(self, fileName: str, fileSize: int) -> HTTPResult:
        """GET /e2ee/manifest — E2E encryption metadata."""
        logger.debug(f"[E2EE] Manifest request - e2eeEnabled={self.session.config.e2eeEnabled}")
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            return self._buildNotFoundResult("[E2EE] E2EE not enabled, returning silent 404 for /e2ee/manifest")

        manifest = {
            'e2eeEnabled': True,
            'version': E2EE_PROTOCOL_VERSION,
            'fileName': fileName,
            'fileSize': CryptoHelper.normalizeFileSize(fileSize),
            'chunkSize': self.session.e2eeManager.chunkSize,
        }
        return self._buildJSONResult(manifest)

    def getTags(self, args: Mapping) -> HTTPResult:
        """GET /e2ee/tags — tags for a chunk range.

        Query parameters:
            start: Starting chunk index
            count: Number of tags to return
            streamId: Stream identifier (optional, default: "global")
        """
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            return self._buildNotFoundResult("[E2EE] E2EE not enabled, returning silent 404 for /e2ee/tags")

        try:
            startChunk = int(args.get('start', ['0'])[0])
            count = int(args.get('count', ['0'])[0])
        except (ValueError, TypeError):
            return HTTPResult(status=HTTPStatus.BAD_REQUEST, body=b"Invalid start/count parameter")

        streamId = args.get('streamId', ['global'])[0] # Default to "global" for backwards compatibility

        logger.debug(f"[E2EE] Tags request: streamId={streamId}, start={startChunk}, count={count}")

        if count <= 0:
            logger.warning(f"[E2EE] Invalid count parameter: {count}")
            return HTTPResult(status=HTTPStatus.BAD_REQUEST, body=f"Invalid count parameter: {count}".encode())

        # Load all tags from E2EEManager for specified stream
        allTags = self.session.e2eeManager.getTags(streamId)
        logger.debug(f"[E2EE] Total tags available for stream '{streamId}': {len(allTags)}")

        # Filter tags by range
        endChunk = startChunk + count
        requestedTags = [tag for tag in allTags if startChunk <= tag['chunkIndex'] < endChunk]

        logger.debug(f"[E2EE] Returning {len(requestedTags)} tags for range [{startChunk}, {endChunk})")

        return self._buildJSONResult({'tags': requestedTags})

    def handleInit(self, publicKeyPem: Optional[str], fileName: str, fileSize: int) -> HTTPResult:
        """POST /e2ee/init — RSA key exchange for E2E encryption."""
        if not self.session.config.e2eeEnabled:
            # Return silent 404 if E2EE not enabled
            return self._buildNotFoundResult("[E2EE] E2EE not enabled, returning silent 404 for /e2ee/init")

        if not publicKeyPem:
            return HTTPResult(status=HTTPStatus.BAD_REQUEST, body=b"Missing publicKey")

        # Delegate to E2EEManager -- a malformed/non-PEM publicKey is realistic,
        # untrusted client input (not an internal invariant violation), so it's
        # reported as a clean 400 rather than surfacing as a 500.
        try:
            responseData = self.session.e2eeManager.handleInit(publicKeyPem, fileName, fileSize)
        except ValueError as e:
            logger.warning(f"[E2EE] Invalid publicKey in /e2ee/init: {e}")
            return HTTPResult(status=HTTPStatus.BAD_REQUEST, body=b"Invalid publicKey")

        return self._buildJSONResult(responseData)


class E2EEView(BaseView):
    """Mounts GET /e2ee/manifest, GET /e2ee/tags, POST /e2ee/init, GET /static/js/E2EE.js."""

    controller = E2EEController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        self._registerRoute(mapGETRoute, '/e2ee/manifest', self.handleManifest)
        self._registerRoute(mapGETRoute, '/e2ee/tags', self.handleTags)
        self._registerRoute(mapPOSTRoute, '/e2ee/init', self.handleInit)
        # Not via _registerRoute: no controller is needed, and _handleStaticScript
        # already has its own complete exception handling.
        mapGETRoute('/static/js/E2EE.js', self.handleE2EEScript)

    def handleManifest(self, args, *, controller):
        _path, name, size, _ctype, _reader = self._getFileInfo(quoteName=False)
        result = controller.getManifest(fileName=name, fileSize=size)
        self.sendHTTPResult(result)

    def handleTags(self, args, *, controller):
        result = controller.getTags(args)
        self.sendHTTPResult(result)

    def handleInit(self, data, *, controller):
        _path, name, size, _ctype, _reader = self._getFileInfo(quoteName=False)
        result = controller.handleInit(data.get('publicKey'), fileName=name, fileSize=size)
        self.sendHTTPResult(result)

    def handleE2EEScript(self, args):
        """Serve E2EE.js - proxy from remote or serve locally."""
        self._handleStaticScript("/static/js/E2EE.js")
