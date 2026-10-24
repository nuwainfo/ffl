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

from dataclasses import asdict, replace
from http import HTTPStatus

from bases.P2P import (
    QUICFileSender,
    P2PAnswer,
    P2PConfiguration,
    P2PPublisher,
    isP2PAvailable,
)
from bases.Settings import SettingsGetter
from bases.views import BaseController, BaseView, HTTPResult


class P2PController(BaseController):
    def _resolveTCPEndpoints(self, port, host, portMappingEnabled, useTLS):
        localHosts = SettingsGetter.getInstance().directConnectionHosts
        if localHosts is None:
            localHosts = [host] if host not in {'', '0.0.0.0', '::'} else None

        return self.session.p2pPublications.tcpEndpoints.resolve(
            port, localHosts, f'/{self.session.uid}', portMappingEnabled, useTLS
        )

    def createOffer(self, port, host, directTLSIdentity, server=None):
        if not isP2PAvailable() or not self.session.config.defaultWebRTC:
            return None

        # Downloaders probe direct endpoints with their auth headers, so the
        # endpoints are TLS, pinned by the fingerprint this (HTTPS) offer carries.
        tcpCertificateFingerprint = directTLSIdentity.sha256Fingerprint if directTLSIdentity else None
        portMappingEnabled = SettingsGetter.getInstance().portMappingEnabled
        # Per-downloader publishers carry only ICE/QUIC; the share owns its TCP endpoints.
        publisher = P2PPublisher(
            port,
            configuration=P2PConfiguration.createICEConfiguration(),
            useUDPPortMapping=portMappingEnabled,
            useTCPPortMapping=False,
            tcpLocalHosts=[],
        )
        offer = self.session.p2pPublications.open(publisher, QUICFileSender(self.session, server=server))
        offer = replace(
            offer,
            tcpEndpoints=self._resolveTCPEndpoints(
                port, host, portMappingEnabled, useTLS=tcpCertificateFingerprint is not None
            ),
            tcpCertificateFingerprint=tcpCertificateFingerprint,
        )

        return self._buildJSONResult(asdict(offer))

    def submitAnswer(self, data):
        answer = P2PAnswer.fromDict(data)
        publication = self.session.p2pPublications.get(answer.sessionId)
        if publication is None:
            return self._buildNotFoundResult('P2P offer was not created')

        publication.accept(answer)

        return self._buildJSONResult({'accepted': True})


class P2PView(BaseView):
    """Mount P2P signaling beside FFL's existing HTTP download routes."""

    controller = P2PController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        mapHEADRoute('/p2p/offer', self._handleForbiddenHead)
        mapHEADRoute('/p2p/answer', self._handleForbiddenHead)
        mapHEADRoute('/p2p/ping', self._handleForbiddenHead)
        
        self._registerRoute(mapGETRoute, '/p2p/offer', self.handleOffer)
        self._registerRoute(mapGETRoute, '/p2p/ping', self.handlePing)
        self._registerRoute(mapPOSTRoute, '/p2p/answer', self.handleAnswer)

    def handleOffer(self, args, *, controller):
        result = controller.createOffer(
            self.server.server_port, self.server.server_address[0], self.server.directTLSIdentity,
            server=self.server,
        )
        
        self.sendHTTPResult(result or controller._buildNotFoundResult())

    def handlePing(self, args, *, controller):
        if not isP2PAvailable() or not controller.session.config.defaultWebRTC:
            self.sendHTTPResult(controller._buildNotFoundResult())
            return
            
        self.sendHTTPResult(HTTPResult(status=HTTPStatus.OK, body=b'OK'))

    def handleAnswer(self, data, *, controller):
        self.sendHTTPResult(controller.submitAnswer(data))
