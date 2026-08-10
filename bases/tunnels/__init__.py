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

"""Tunnel transport implementations (Bore, Web) and the default type/domain resolver.

Which transport a share uses is decided by the server (via the `type` field on
each candidate returned from `/api/tunnels`), never by a client-side setting.
When the Features addon isn't available to query that endpoint, this module's
resolveTunnelCandidate() races two well-known fallback domains through the same
selection logic instead.
"""

import concurrent.futures
import os
import socket
import threading

from dataclasses import dataclass
from time import monotonic
from typing import Optional

from bases.Kernel import getLogger
from bases.Utils import DataclassDictMixin


logger = getLogger(__name__)

# Transport types createTunnelClient() knows how to build. Callers that fetch
# candidates from the server (e.g. the Features addon) pass this to /api/tunnels
# so the server never returns a type this client version can't yet construct.
SUPPORTED_TUNNEL_TYPES = ('bore', 'web')

# Baseline (no Features addon) fallback candidates, as a single comma-separated
# list rather than one env var per transport. Order doesn't matter; each
# domain's type is inferred by name if not already known (see
# TunnelCandidate.resolveType below). 
BUILTIN_TUNNELS = os.getenv(
    'BUILTIN_TUNNELS',
    ','.join(['33.fastfilelink.com'] + [f'{i}.10.fastfilelink.com' for i in range(1, 10)]),
)


@dataclass
class TunnelCandidate(DataclassDictMixin):
    """One entry from /api/tunnels (or a hardcoded fallback with the same shape).

    Everything about what a tunnel "type" means lives on this class — no other
    module compares against the 'bore'/'web' strings directly.
    """

    domain: str
    type: Optional[str] = None
    latency: Optional[float] = None
    secret: Optional[str] = None
    preSock: Optional[object] = None

    # Domains known to speak the web relay protocol; every other domain
    # defaults to bore. Bare '10.fastfilelink.com' is deliberately absent --
    # it's kept alive only as a worker_tunnel deployment target, never
    # referenced from Python (an FFL_TUNNEL_DOMAIN override should point at
    # one of these slots instead, e.g. '1.10.fastfilelink.com'). Extend this
    # set if more are registered.
    _WEB_DOMAINS = frozenset({f'{i}.10.fastfilelink.com' for i in range(1, 10)})

    def resolveType(self):
        """Infer and cache `type` by domain name, unless already known (e.g.
        a candidate built from the server's /api/tunnels response, which
        already reports its own type)."""
        if self.type is None:
            self.type = 'web' if self.domain in self._WEB_DOMAINS else 'bore'
            
        return self.type

    @property
    def reusableAcrossShares(self):
        """Whether one connected client can serve more than one share.

        True for bore (one control connection multiplexes every share by URL
        path); False for web (each share is a separate relay endpoint, so a
        fresh client/connection is required per share).
        """
        return self.resolveType() != 'web'


def getLatency(host: str, port: int = 443, timeout: float = 5):
    # Calculate a latency point using sockets with proper resource cleanup.

    # Args:
    #     host: Target hostname or IP address
    #     port: Target port (default: 443 for HTTPS)
    #     timeout: Connection timeout in seconds (default: 5)

    # Returns:
    #     float: Latency in milliseconds, or None if connection failed

    # Start a timer
    startTime = monotonic()
    s = None

    try:
        # Try to Connect
        s = socket.create_connection((host, port), timeout=timeout)
        s.shutdown(socket.SHUT_RD)

        # Stop Timer
        runtimeMs = (monotonic() - startTime) * 1000
        return float(runtimeMs)

    except (socket.timeout, OSError) as e:
        # If something bad happens, the latency_point is None
        logger.debug(f"Failed to connect to {host}:{port} for latency check: {e}")
        return None

    finally:
        # Always close the socket to prevent resource leaks
        if s is not None:
            try:
                s.close()
            except Exception as e:
                logger.debug(f"Failed to close socket in getLatency: {e}")


def _receiveExactly(sock, size):
    """Read an exact socket fragment or raise a useful connection error."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('Peer closed the connection unexpectedly')
            
        data.extend(chunk)
        
    return bytes(data)


class Socks5ProxySupport:
    """SOCKS5 proxy resolution and handshake, shared by BoreClient and
    WebTunnelClient (both inherit it unconditionally -- it's required
    infrastructure, not an optional trait).

    Everything SOCKS5-protocol-specific — the env var name, config
    resolution, and the wire handshake — lives here, so it's defined once
    instead of duplicated across the two transports. (`_receiveExactly` stays
    a plain module function: besides the handshake here, Web.py also uses it
    for unrelated WebSocket/HTTP framing.)
    """

    SOCKS5_ENV_VAR = 'FFL_TUNNEL_SOCKS5'

    @classmethod
    def resolveSocks5Proxy(cls, proxyConfig):
        """Resolve the (host, port) SOCKS5 proxy to use, or None.

        Priority: an explicit `proxyConfig` (from --proxy) > the
        FFL_TUNNEL_SOCKS5 environment variable > no proxy. A classmethod so
        it can also be called where no instance exists yet (e.g. BoreClient's
        pre-connect helper, which runs before a BoreClient is constructed).
        """
        if proxyConfig and proxyConfig.get('type') == 'socks5':
            return proxyConfig['host'], proxyConfig['port']

        value = os.getenv(cls.SOCKS5_ENV_VAR, '').strip()
        if not value:
            return None

        host, separator, portValue = value.rpartition(':')
        if not separator:
            logger.warning('Ignoring invalid %s value: %r', cls.SOCKS5_ENV_VAR, value)
            return None

        try:
            return host, int(portValue)
        except ValueError:
            logger.warning('Ignoring invalid %s port in: %r', cls.SOCKS5_ENV_VAR, value)
            return None

    def _getSocks5Proxy(self):
        return self.resolveSocks5Proxy(self.proxyConfig)

    @staticmethod
    def _connectSocks5(proxyHost, proxyPort, destinationHost, destinationPort, timeout, nonBlocking=False):
        """Return a TCP socket to a destination through a no-auth SOCKS5 proxy.

        Shared by Bore (which additionally switches the result to non-blocking
        mode for asyncio adoption) and Web (which keeps it blocking for a
        synchronous HTTPS/WebSocket handshake). A staticmethod so it can be
        called via `cls`/`self` from either subclass without needing an
        instance-bound `proxyConfig`.
        """
        sock = socket.create_connection((proxyHost, proxyPort), timeout=timeout)
        sock.settimeout(timeout)
        
        try:
            sock.sendall(b'\x05\x01\x00')
            greeting = _receiveExactly(sock, 2)
            if greeting[0] != 5 or greeting[1] == 0xff:
                raise ConnectionError(f'SOCKS5 proxy rejected no-authentication: {greeting!r}')

            hostname = destinationHost.encode('idna')
            if len(hostname) > 255:
                raise ConnectionError('SOCKS5 destination hostname is too long')

            request = bytearray((5, 1, 0, 3, len(hostname)))
            request.extend(hostname)
            request.extend(destinationPort.to_bytes(2, 'big'))
            sock.sendall(request)

            response = _receiveExactly(sock, 4)
            if response[0] != 5 or response[1] != 0:
                raise ConnectionError(f'SOCKS5 CONNECT failed with reply code {response[1]}')

            addressType = response[3]
            if addressType == 1:
                addressSize = 4
            elif addressType == 3:
                addressSize = _receiveExactly(sock, 1)[0]
            elif addressType == 4:
                addressSize = 16
            else:
                raise ConnectionError(f'SOCKS5 proxy returned unknown address type {addressType}')

            _receiveExactly(sock, addressSize + 2)

            if nonBlocking:
                sock.settimeout(None)
                sock.setblocking(False)

            return sock
        except Exception:
            sock.close()
            raise


def getLowLatencyTunnel(candidates, latencyThreshold=60):
    """Race tunnel candidates with parallel latency testing and pick the best one.

    Args:
        candidates: Non-empty list of TunnelCandidate instances.  This is either
            the raw /api/tunnels response, converted by the caller (Features
            addon), or a hardcoded fallback list with the same shape (no
            Features addon).
        latencyThreshold: Maximum acceptable latency in milliseconds; the first
            candidate to answer within this threshold wins immediately.

    Returns:
        TunnelCandidate: The winning candidate, with `type` resolved.

    Raises:
        ConnectionError: When no candidates are given, or none are reachable.
    """
    if not candidates:
        raise ConnectionError('No tunnel candidates were provided.')

    # Parallel latency testing with early termination.
    # TCP connect on port 443 is sufficient proof of reachability — no extra HTTP GET needed.
    foundGood = threading.Event()
    best = {'result': None}

    def probe(candidate):
        if foundGood.is_set():
            return candidate

        candidate.latency = getLatency(f"0.{candidate.domain}")
        if candidate.latency is not None and candidate.latency <= latencyThreshold and not foundGood.is_set():
            best['result'] = candidate
            foundGood.set()

        return candidate

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(candidates))) as executor:
        futures = [executor.submit(probe, candidate) for candidate in candidates]

        for future in concurrent.futures.as_completed(futures):
            future.result()
            if foundGood.is_set():
                for f in futures:
                    if not f.done():
                        f.cancel()
                break

    if best['result']:
        best['result'].resolveType()
        return best['result']

    # Fallback: TCP latency probe already proved reachability; pick the lowest-latency result.
    reachable = [candidate for candidate in candidates if candidate.latency is not None]
    if not reachable:
        raise ConnectionError('Cannot connect to any FastFileLink server.')

    winner = min(reachable, key=lambda candidate: candidate.latency)
    winner.resolveType()
    return winner


def resolveTunnelCandidate(latencyThreshold=60):
    """Baseline (no Features addon) domain+type resolution.

    Races the domains in BUILTIN_TUNNELS through getLowLatencyTunnel() using
    the same selection logic the Features addon uses for the real server list.
    """
    domains = [domain.strip() for domain in BUILTIN_TUNNELS.split(',') if domain.strip()]
    candidates = [TunnelCandidate(domain=domain) for domain in domains]
    return getLowLatencyTunnel(candidates, latencyThreshold=latencyThreshold)


def createTunnelClient(resolved, port, uid, tokenProvider, proxyConfig=None, **kwargs):
    """Build the tunnel client for a resolved candidate.

    Args:
        resolved: TunnelCandidate from getLowLatencyTunnel()/resolveTunnelCandidate(),
            with `secret` already populated by the caller.
        port: Local port to tunnel.
        uid: Share uid, used by web as its opaque per-share routing key; bore
            routes by URL path instead and ignores it.
        tokenProvider: Callable returning a fresh token when the client needs
            to refresh it.
        proxyConfig: Optional proxy configuration.
        **kwargs: Forwarded to BoreClient only, unused for web.

    Returns:
        BoreClient or WebTunnelClient: Configured client instance.
    """
    domain = resolved.domain

    if resolved.resolveType() == 'web':
        from .Web import WebTunnelClient
        
        agentURL = os.getenv('FFL_WEB_TUNNEL_AGENT_URL') or f'https://{domain}/'
        publicURL = os.getenv('FFL_WEB_TUNNEL_PUBLIC_URL') or f'https://{domain}/'

        return WebTunnelClient(
            port, agentURL, publicURL, resolved.secret, uid,
            tokenProvider=tokenProvider,
            proxyConfig=proxyConfig,
        )

    from .Bore import BoreClient
    
    client = BoreClient(
        localhost='127.0.0.1',
        localPort=port,
        remoteHost=domain,
        remotePort=0,
        secret=resolved.secret,
        tokenProvider=tokenProvider,
        verbose=False,
        debug=False,
        useHttps=True,
        proxyConfig=proxyConfig,
        **kwargs
    )
    if resolved.preSock is not None:
        client.injectPreTcpSocket(resolved.preSock)

    return client
