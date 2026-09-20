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

"""The ``lan`` tunnel type.

LAN exposes FFL's loopback HTTP server on one directly reachable local IPv4
address. The client reports the direct-network policy that address implies
(no external ICE servers, no NAT port mapping, the host it exposes) through
``networkPolicy``. It never installs that policy itself: the share that owns
the tunnel applies it to its own requests via SettingsGetter
.overrideNetworkPolicy(), so tunnel threads never change process-wide state.
"""

import asyncio
import ipaddress
import os
import socket

from dataclasses import dataclass
from typing import Optional

from bases.Kernel import getLogger
from bases.Settings import NetworkPolicy

from . import TunnelCandidate


logger = getLogger(__name__)


class LANTunnelConfigurationError(ValueError):
    """Raised when no usable local address can be selected for LAN sharing."""


class LANTunnelClient:
    """Expose FFL's loopback HTTP server on one directly reachable LAN address."""

    LOOPBACK_HOST = '127.0.0.1'
    LAN_HOST_ENV = 'FFL_LAN_HOST'
    _ROUTE_PROBES = (
        ('1.1.1.1', 80),
        ('8.8.8.8', 80),
    )
    _BACKEND_CONNECT_TIMEOUT = 5.0
    _BACKEND_CONNECT_RETRY_INTERVAL = 0.05
    _RELAY_BUFFER_SIZE = 64 * 1024

    @staticmethod
    def _isUsableLANAddress(address):
        return (
            address.version == 4 and
            not address.is_unspecified and
            not address.is_loopback and
            not address.is_multicast
        )

    @classmethod
    def _validateLANHost(cls, host):
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise LANTunnelConfigurationError(
                f'{cls.LAN_HOST_ENV} must be an IPv4 address, got {host!r}'
            ) from error

        if address.version != 4:
            raise LANTunnelConfigurationError(
                f'{cls.LAN_HOST_ENV} currently supports IPv4 addresses only, got {host!r}'
            )

        if not cls._isUsableLANAddress(address):
            raise LANTunnelConfigurationError(
                f'{cls.LAN_HOST_ENV} must identify a non-loopback local IPv4 address, got {host!r}'
            )

        return str(address)

    @classmethod
    def _selectHostByRoute(cls):
        for target in cls._ROUTE_PROBES:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(target)
                address = ipaddress.ip_address(sock.getsockname()[0])
                if cls._isUsableLANAddress(address):
                    return str(address)
            except OSError:
                continue
            finally:
                sock.close()

        return None

    @classmethod
    def _selectHostByHostname(cls):
        try:
            infos = socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
            )
        except OSError:
            return None

        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if cls._isUsableLANAddress(address):
                return str(address)

        return None

    @classmethod
    def resolveLANHost(cls):
        configured = os.getenv(cls.LAN_HOST_ENV, '').strip()
        if configured:
            return cls._validateLANHost(configured)

        host = cls._selectHostByRoute() or cls._selectHostByHostname()
        if host:
            return host

        raise LANTunnelConfigurationError(
            f'Cannot determine a LAN IPv4 address automatically; '
            f'set {cls.LAN_HOST_ENV}=<local-ip>'
        )

    def __init__(self, localPort, lanHost=None):
        self.localPort = localPort
        self.remoteHost = lanHost
        self.requestedPort = localPort
        self.remotePort = None
        self.lastConnectError = None
        self.running = False
        self._server = None
        self._stopEvent = asyncio.Event()
        self._connectionTasks = set()

    async def _connectBackend(self):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._BACKEND_CONNECT_TIMEOUT
        lastError = None

        while loop.time() < deadline:
            try:
                return await asyncio.open_connection(self.LOOPBACK_HOST, self.localPort)
            except OSError as error:
                lastError = error
                await asyncio.sleep(self._BACKEND_CONNECT_RETRY_INTERVAL)

        if lastError is not None:
            raise lastError

        raise ConnectionError(
            f'Cannot connect to local FFL server on {self.LOOPBACK_HOST}:{self.localPort}'
        )

    async def _pipe(self, reader, writer):
        while True:
            data = await reader.read(self._RELAY_BUFFER_SIZE)
            if not data:
                return

            writer.write(data)
            await writer.drain()

    async def _relayConnection(self, clientReader, clientWriter):
        backendWriter = None
        try:
            backendReader, backendWriter = await self._connectBackend()
            upstream = asyncio.create_task(self._pipe(clientReader, backendWriter))
            downstream = asyncio.create_task(self._pipe(backendReader, clientWriter))

            done, pending = await asyncio.wait(
                (upstream, downstream),
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            await asyncio.gather(*done, *pending, return_exceptions=True)
        except Exception as error:
            logger.debug('LAN relay connection ended with error: %s', error)
        finally:
            if backendWriter is not None:
                backendWriter.close()

            clientWriter.close()

    def _handleConnection(self, clientReader, clientWriter):
        task = asyncio.create_task(self._relayConnection(clientReader, clientWriter))
        self._connectionTasks.add(task)
        task.add_done_callback(self._connectionTasks.discard)

    @property
    def networkPolicy(self):
        if self.remoteHost is None:
            raise RuntimeError('LAN network policy requires a resolved LAN host; call connect() first')

        return NetworkPolicy.createDirect(directConnectionHosts=[self.remoteHost])

    async def _closeServer(self):
        if self._server is None:
            return

        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def connect(self):
        self.lastConnectError = None

        if self._server is not None:
            self.remotePort = self.requestedPort
            return True

        try:
            if self.remoteHost is None:
                self.remoteHost = self.resolveLANHost()

            self._server = await asyncio.start_server(
                self._handleConnection,
                host=self.remoteHost,
                port=self.requestedPort,
            )
            self.remotePort = self._server.sockets[0].getsockname()[1]
            logger.info('LAN tunnel ready => %s', self.getTunnelURL())
            return True
        except Exception as error:
            self.lastConnectError = error
            logger.error(
                'Failed to start LAN tunnel on %s:%s: %s',
                self.remoteHost,
                self.requestedPort,
                error,
            )
            await self._closeServer()
            return False

    async def listen(self):
        self._stopEvent.clear()
        self.running = True
        try:
            await self._stopEvent.wait()
        finally:
            self.running = False

    def getTunnelURL(self):
        if not self.remoteHost or not self.remotePort:
            return None

        return f'http://{self.remoteHost}:{self.remotePort}/'

    def stop(self):
        self.running = False

    async def shutdown(self):
        self.stop()
        self._stopEvent.set()
        await self._closeServer()

        tasks = tuple(self._connectionTasks)
        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._connectionTasks.clear()


@dataclass
class LANTunnelCandidate(TunnelCandidate):
    """Candidate selected by ``FFL_TUNNEL_DOMAIN=lan``."""

    TYPE = 'lan'

    domain: str = TYPE
    type: Optional[str] = TYPE
    secret: Optional[str] = ''

    @property
    def requiresNetworkSetup(self):
        return False

    def resolveNetworkPolicy(self, client):
        return client.networkPolicy

    def createClient(self, port, uid, tokenProvider, proxyConfig=None, **kwargs):
        return LANTunnelClient(port)
