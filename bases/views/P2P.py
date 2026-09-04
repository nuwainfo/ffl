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

from bases.P2P import P2PAnswer, P2PPublisher, isP2PAvailable
from bases.views import BaseController, BaseView, HTTPResult


class P2PController(BaseController):
    def _newPublisher(self, port, host):
        if not isP2PAvailable() or not self.session.config.defaultWebRTC:
            return None

        localHosts = [host] if host not in {'', '0.0.0.0', '::'} else None
        return P2PPublisher(port, tcpPath=f'/{self.session.uid}', tcpLocalHosts=localHosts)

    def createOffer(self, port, host):
        publisher = self._newPublisher(port, host)
        if publisher is None:
            return None
            
        offer = publisher.createOffer()
        self.session.p2pPublishers[offer.sessionId] = publisher
        
        return self._buildJSONResult(offer.__dict__)

    def submitAnswer(self, data):
        answer = P2PAnswer.fromDict(data)
        publisher = self.session.p2pPublishers.get(answer.sessionId)
        if publisher is None:
            return self._buildNotFoundResult('P2P offer was not created')
            
        publisher.acceptAnswer(answer)
        
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
        result = controller.createOffer(self.server.server_port, self.server.server_address[0])
        self.sendHTTPResult(result or controller._buildNotFoundResult())

    def handlePing(self, args, *, controller):
        if not isP2PAvailable() or not controller.session.config.defaultWebRTC:
            self.sendHTTPResult(controller._buildNotFoundResult())
            return
            
        self.sendHTTPResult(HTTPResult(status=HTTPStatus.OK, body=b'OK'))

    def handleAnswer(self, data, *, controller):
        self.sendHTTPResult(controller.submitAnswer(data))
