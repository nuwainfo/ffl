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

import base64

from bases.views import BaseController, BaseView, HTTPResult


class ChecksumController(BaseController):
    """Checksum-polling decisions for one ShareSession."""

    def getChecksumStatus(self) -> HTTPResult:
        """GET /checksum — download integrity verification polling endpoint."""
        responseData = self.session.checksumStore.getResponseData()
        recipientAuth = self.session.config.recipientAuth
        if recipientAuth and recipientAuth.requiresPubkey():
            # Expose the RSA-OAEP challenge for CLI clients downloading via P2P.
            # The browser gets these challenges baked into index.html as PUBKEY_CHALLENGES
            # at serve time; CLI clients (ffl download <url>) cannot render HTML, so they
            # fetch /checksum to retrieve it dynamically and decrypt it with their private key.
            encryptedChallenges = [
                base64.b64encode(challengeCiphertext).decode()
                for challengeCiphertext in recipientAuth.getChallengeCiphertexts()
            ]
            responseData['encryptedChallenges'] = encryptedChallenges

        return self._buildJSONResult(responseData, headers={'Cache-Control': 'no-cache'})


class ChecksumView(BaseView):
    """Mounts GET /checksum, GET /static/js/Checksum.js."""

    controller = ChecksumController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        self._registerRoute(mapGETRoute, '/checksum', self.handleChecksum)
        # Not via _registerRoute: no controller is needed, and _handleStaticScript
        # already has its own complete exception handling.
        mapGETRoute('/static/js/Checksum.js', self.handleChecksumScript)

    def handleChecksum(self, args, *, controller):
        result = controller.getChecksumStatus()
        self.sendHTTPResult(result)

    def handleChecksumScript(self, args):
        """Serve Checksum.js - proxy from remote or serve locally.
        Required for same-origin importScripts() in ProgressServiceWorker.js."""
        self._handleStaticScript("/static/js/Checksum.js")
