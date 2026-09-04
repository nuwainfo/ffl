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

from dataclasses import replace

from bases.Kernel import getLogger
from bases.Utils import getEnv

logger = getLogger(__name__)

try:
    from ffl_p2p.P2P import P2PAnswer, P2PConnector, P2PPublisher
except ImportError:
    P2PAnswer = None
    P2PConnector = None
    P2PPublisher = None


def isP2PAvailable():
    return P2PConnector is not None and not getEnv('DISABLE_P2P', False)


class P2PDownloadMixin:
    """Try direct P2P TCP once, then delegate to WebRTC and HTTP fallback."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.p2pTimeout = 1.5

    def downloadFile(self, url, outputPath=None, resume=False, downloadAuth=None):
        self._validateOutputPath(outputPath)
        credentials, pickupCode, recipientPrivateKey, encryptionKey = self._getDownloadAuthValues(downloadAuth)
        ctx = self._resolveDownloadContext(url, credentials, recipientPrivateKey, encryptionKey)
        urlInfo = ctx['urlInfo']

        webRTCDebugEnabled = (
            self.debugSimulateIceFailure or self.debugSimulateStall or
            self.debugSimulateDropBeforeFirstPayload or self.debugSimulateConnectionHang
        )
    
        canUseP2P = (
            isP2PAvailable() and not webRTCDebugEnabled and
            not urlInfo.isGenericURL and urlInfo.supportsWebRTC
        )
    
        if canUseP2P:
            headers = self._createAuthHeaders(credentials)
            if pickupCode:
                headers['X-FFL-Pickup'] = pickupCode
                
            if ctx['proof']:
                headers['X-FFL-Proof'] = ctx['proof']

            connection = None
            try:
                self.loggerCallback(self._STATUS_CONNECTING)
                self.loggerCallback('Attempting P2P download...')
                connection = P2PConnector().connect(urlInfo.baseURL, timeout=self.p2pTimeout, headers=headers)
                if connection and connection.transportName == 'tcp':
                    directURL = connection.transport.baseURL
                    directURLInfo = replace(urlInfo, baseURL=directURL)
                    
                    self.loggerCallback('Using P2P TCP download...')
                    
                    return self._downloadViaHTTP(
                        directURL, outputPath, credentials, None, resume,
                        e2eeContext=ctx['e2eeContext'], urlInfo=directURLInfo,
                        pickupCode=pickupCode, proof=ctx['proof'], checksumAlgorithm=ctx['checksumAlgorithm'],
                    )
            except InterruptedError:
                raise
            except Exception as error:
                logger.debug(f'P2P download unavailable: {error}')
            finally:
                if connection:
                    connection.close()

        return self._downloadWithResolvedContext(
            url, outputPath, credentials, resume, pickupCode, ctx
        )
