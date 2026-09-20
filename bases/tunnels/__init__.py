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

from abc import ABC, abstractmethod
from dataclasses import dataclass
from time import monotonic
from typing import Optional

from bases.Kernel import getLogger
from bases.Settings import NetworkPolicy
from bases.Utils import DataclassDictMixin


logger = getLogger(__name__)

# Transport types createTunnelClient() knows how to build. Callers that fetch
# candidates from the server (e.g. the Features addon) pass this to /api/tunnels
# so the server never returns a type this client version can't yet construct.
# 'loopback' and 'lan' are local-only transports resolved by the explicit
# FFL_TUNNEL_DOMAIN override (resolveTunnelDomainFromEnv() below), not normal
# server-selected relay backends, but they live in the same registry so every
# bases/tunnels/*.py transport has one consistent type name.
SUPPORTED_TUNNEL_TYPES = ('bore', 'web', 'loopback', 'lan')

# FFL_TUNNEL_DOMAIN values that select a local-only transport instead of a domain.
LOCAL_TUNNEL_ALIASES = {
    'localhost': 'loopback',
    '127.0.0.1': 'loopback',
    'lan': 'lan',
}

# The local-only tunnel types those aliases select: built directly, with no
# tunnel server list to choose from.
LOCAL_TUNNEL_TYPES = tuple(dict.fromkeys(LOCAL_TUNNEL_ALIASES.values()))

# Baseline (no Features addon) fallback candidates, as a single comma-separated
# list rather than one env var per transport. Order doesn't matter; each
# domain's type is inferred by name if not already known (see
# TunnelCandidate._resolveClass below).
BUILTIN_TUNNELS = os.getenv(
    'BUILTIN_TUNNELS',
    ','.join(['33.fastfilelink.com'] + [f'{i}.10.fastfilelink.com' for i in range(1, 3)]),
)


@dataclass
class TunnelCandidate(DataclassDictMixin, ABC):
    """One entry from /api/tunnels (or a hardcoded fallback with the same shape)."""

    domain: str
    type: Optional[str] = None
    latency: Optional[float] = None
    secret: Optional[str] = None
    preSock: Optional[object] = None

    @classmethod
    def resolveType(cls, domain, type=None):
        """The tunnel type of `domain`: `type` when already known, otherwise
        inferred from the domain name -- only WebTunnelCandidate's known
        domains are web, every other domain is bore.
        """
        from .Web import WebTunnelCandidate

        return type or ('web' if domain in WebTunnelCandidate.WEB_DOMAINS else 'bore')

    @classmethod
    def _resolveClass(cls, domain, type=None):
        """Resolve the concrete subclass for `domain`. `type` selects it
        directly when already known; omit it to infer from the domain name
        instead (a bare BUILTIN_TUNNELS entry, an explicit
        FFL_TUNNEL_DOMAIN=<real domain> override, or a legacy /api/tunnels
        response with no `type` key) -- every domain outside
        WebTunnelCandidate's known set defaults to bore.
        """
        from .Bore import BoreTunnelCandidate
        from .LAN import LANTunnelCandidate
        from .Loopback import LoopbackTunnelCandidate
        from .Web import WebTunnelCandidate

        classesByType = {
            'bore': BoreTunnelCandidate,
            'web': WebTunnelCandidate,
            'loopback': LoopbackTunnelCandidate,
            'lan': LANTunnelCandidate,
        }
        return classesByType[cls.resolveType(domain, type=type)]

    @classmethod
    def fromType(cls, type):
        """Construct the candidate of a local-only tunnel `type` (see LOCAL_TUNNEL_TYPES)."""
        return cls._resolveClass(None, type=type)()

    @classmethod
    def fromDomain(cls, domain, type=None, **kwargs):
        """Construct the concrete subclass for a bare `domain` (see _resolveClass())."""
        return cls._resolveClass(domain, type=type)(domain=domain, **kwargs)

    @classmethod
    def fromDict(cls, data, **overrides):
        """TunnelCandidate.fromDict(data) is polymorphic: it resolves
        data['type'] (or, absent that, the domain-name convention) to a
        concrete subclass first, then that subclass's own inherited
        fromDict() does the actual field mapping. Called directly on an
        already-concrete subclass (e.g. WebTunnelCandidate.fromDict(data)),
        it skips re-resolving and just maps fields, like the generic
        DataclassDictMixin.fromDict() it falls through to.
        """
        if cls is TunnelCandidate:
            concreteClass = cls._resolveClass(data.get('domain'), type=data.get('type'))
            return concreteClass.fromDict(data, **overrides)

        return super().fromDict(data, **overrides)

    @property
    def probeHost(self):
        """Host to TCP-probe for reachability/latency racing (see
        getLowLatencyTunnel() below). Defaults to the bare domain;
        BoreTunnelCandidate overrides this to add its '0.'-prefixed
        dedicated probe/control host.
        """
        return self.domain

    @property
    def reusableAcrossShares(self):
        """Whether one connected client can serve more than one share.

        True for every transport except web, which overrides this to False
        (each share is a separate relay endpoint, so a fresh client/connection
        is required per share).
        """
        return True

    @property
    def requiresNetworkSetup(self):
        """Whether createClient() must probe the domain's reachability and
        fetch a token before building a client for this candidate.

        True for every real transport (bore/web), regardless of whether a
        secret already happens to be attached (e.g. from Features.py's
        prefetch path) -- the reachability probe and the secret answer
        different questions. LoopbackTunnelCandidate overrides this to
        False, since it needs neither (as does LANTunnelCandidate).
        """
        return True

    def resolveNetworkPolicy(self, client):
        """Runtime network policy that `client` (built by createClient())
        implies for the share it carries. Base: no constraint. LAN overrides
        this to require direct-only transports.
        """
        return NetworkPolicy()

    @abstractmethod
    def createClient(self, port, uid, tokenProvider, proxyConfig=None, **kwargs):
        """Build the tunnel client for this resolved candidate.

        Args:
            port: Local port to tunnel.
            uid: Share uid; web uses it as its opaque per-share routing key,
                bore/loopback ignore it (bore routes by URL path instead).
            tokenProvider: Callable returning a fresh token when the client
                needs to refresh it.
            proxyConfig: Optional proxy configuration.
            **kwargs: Forwarded to BoreClient only, unused elsewhere.
        """

    def attachToken(self, tokenGetter, proxyConfig):
        """Fetch and attach this candidate's auth token.
        Base: a plain token fetch. BoreTunnelCandidate overrides this
        to also warm its control TCP socket and the shared SSL context in
        parallel, since only bore's own connect() benefits from either.
        """
        self.secret = tokenGetter(domain=self.domain)

    def tryReuseCached(self, tokenGetter, proxyConfig):
        """Attempt to reuse this candidate without a full
        re-resolution. Returns True once `secret` (and, where applicable,
        `preSock`) are attached; False tells the caller to discard this
        candidate and fall back to a fresh getLowLatencyTunnel() call
        instead.

        Base: trusts the cache and just calls attachToken(). BoreTunnelCandidate
        overrides this to first prove the cached domain is still actually
        reachable via its own TCP pre-connect, since a live token alone
        doesn't guarantee that for bore's dedicated control connection.
        """
        self.attachToken(tokenGetter, proxyConfig)
        return True


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
        TunnelCandidate: The winning candidate.

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

        candidate.latency = getLatency(candidate.probeHost)
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
        return best['result']

    # Fallback: TCP latency probe already proved reachability; pick the lowest-latency result.
    reachable = [candidate for candidate in candidates if candidate.latency is not None]
    if not reachable:
        raise ConnectionError('Cannot connect to any FastFileLink server.')

    return min(reachable, key=lambda candidate: candidate.latency)


def resolveTunnelDomainFromEnv():
    """Resolve an explicit FFL_TUNNEL_DOMAIN override, or None if it's unset
    or not a domain this client recognizes -- the single place that knows
    what that env var means, shared by resolveTunnelCandidate() (below) and
    addons/Features.py's server-based resolveTunnel(), so neither has to
    special-case it on its own.

    Recognizes:
      - a local alias (see LOCAL_TUNNEL_ALIASES): 'localhost'/'127.0.0.1' ->
        LoopbackTunnelCandidate (bases/tunnels/Loopback.py), for exercising the
        CLI/server code path in a sandbox with no real internet access; 'lan'
        -> LANTunnelCandidate (bases/tunnels/LAN.py), which exposes the local
        HTTP server on a directly reachable LAN IPv4 address. Their secret is
        already set (not None) since neither needs a token -- callers that
        fetch a token only when `candidate.secret is None` skip that step for
        free.
      - an explicit fastfilelink.com (sub)domain -> a plain candidate with no
        secret yet; the caller is responsible for fetching/attaching one.
    """
    envTunnelDomain = os.getenv('FFL_TUNNEL_DOMAIN', '').strip()
    if not envTunnelDomain:
        return None

    localType = LOCAL_TUNNEL_ALIASES.get(envTunnelDomain.lower())
    if localType:
        return TunnelCandidate.fromType(localType)

    if envTunnelDomain.endswith('fastfilelink.com'):
        return TunnelCandidate.fromDomain(envTunnelDomain)

    return None


def resolveTunnelCandidate(latencyThreshold=60, tunnelType=None):
    """Baseline (no Features addon) domain+type resolution.

    `tunnelType` forces one type of tunnel (see SUPPORTED_TUNNEL_TYPES): a
    local-only type is built directly, a relay type restricts the race to
    candidates of that type. Otherwise an explicit FFL_TUNNEL_DOMAIN override
    is honored first (see resolveTunnelDomainFromEnv()), and then the domains
    in BUILTIN_TUNNELS are raced through getLowLatencyTunnel() using the same
    selection logic the Features addon uses for the real server list.
    """
    if tunnelType in LOCAL_TUNNEL_TYPES:
        return TunnelCandidate.fromType(tunnelType)

    if tunnelType is None:
        envCandidate = resolveTunnelDomainFromEnv()
        if envCandidate is not None:
            return envCandidate

    domains = [domain.strip() for domain in BUILTIN_TUNNELS.split(',') if domain.strip()]
    candidates = [TunnelCandidate.fromDomain(domain) for domain in domains]
    if tunnelType is not None:
        candidates = [
            candidate for candidate in candidates
            if TunnelCandidate.resolveType(candidate.domain, type=candidate.type) == tunnelType
        ]

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
        BoreClient, WebTunnelClient, LoopbackTunnelClient, or LANTunnelClient: Configured client instance.
    """
    return resolved.createClient(port, uid, tokenProvider, proxyConfig=proxyConfig, **kwargs)
