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

"""The 'loopback' tunnel type (see resolveTunnelDomainFromEnv() in
bases/tunnels/__init__.py): LoopbackTunnelCandidate and its client do no
networking of their own. The local HTTP server FFL already runs on
`localPort` *is* the "tunnel", so this module only reports that address back
as the share URL instead of relaying traffic anywhere. Exists for local
testing in environments with no real internet access (e.g. a sandboxed LLM
agent exercising the CLI/server code path).
"""

import asyncio

from dataclasses import dataclass
from typing import Optional

from bases.Kernel import getLogger

from . import TunnelCandidate

logger = getLogger(__name__)

LOOPBACK_TYPE = 'loopback'
LOOPBACK_HOST = '127.0.0.1'


class LoopbackTunnelClient:
    """Implements the same async client contract as BoreClient/WebTunnelClient
    (connect/listen/stop/shutdown/getTunnelURL, plus remoteHost/remotePort/
    requestedPort/lastConnectError) so it plugs into AsyncTunnelThread and
    TunnelRunner unmodified, but every step is a no-op.
    """

    def __init__(self, localPort):
        self.localPort = localPort
        self.remoteHost = LOOPBACK_HOST
        self.requestedPort = localPort
        self.remotePort = None
        self.lastConnectError = None
        self.running = False
        self._stopEvent = asyncio.Event()

    async def connect(self):
        self.lastConnectError = None
        self.remotePort = self.requestedPort
        logger.info(f"Loopback tunnel ready => {self.getTunnelURL()}")
        return True

    async def listen(self):
        # Nothing to relay -- just block until stop()/shutdown() wakes us, the
        # same shape Bore/Web use to keep AsyncTunnelThread's reconnect loop
        # from spinning. Clearing first guards a prior shutdown() from
        # causing an immediate return if main() ever calls listen() again.
        self._stopEvent.clear()
        self.running = True
        try:
            await self._stopEvent.wait()
        finally:
            self.running = False

    def getTunnelURL(self):
        if not self.remotePort:
            return None

        return f"http://{self.remoteHost}:{self.remotePort}/"

    def stop(self):
        self.running = False

    async def shutdown(self):
        self.stop()
        self._stopEvent.set()


@dataclass
class LoopbackTunnelCandidate(TunnelCandidate):
    """The candidate FFL_TUNNEL_DOMAIN=localhost/127.0.0.1 resolves to:
    always the loopback address, already carries a (dummy) secret so no
    token is ever fetched for it, and opts out of createClient()'s
    reachability probe via requiresNetworkSetup.
    """

    domain: str = LOOPBACK_HOST
    type: Optional[str] = LOOPBACK_TYPE
    secret: Optional[str] = ''

    @property
    def requiresNetworkSetup(self):
        return False

    def createClient(self, port, uid, tokenProvider, proxyConfig=None, **kwargs):
        return LoopbackTunnelClient(port)
