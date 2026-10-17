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

"""Tunnel transport implementations (Bore, Web), the default type/domain resolver,
and the dialers every transport opens its relay connections with.

Which transport a share uses is decided by the server (via the `type` field on
each candidate returned from `/api/tunnels`), never by a client-side setting.
When the Features addon isn't available to query that endpoint, this module's
resolveTunnelCandidate() races two well-known fallback domains through the same
selection logic instead.
"""

import asyncio
import base64
import concurrent.futures
import os
import socket
import ssl
import threading
import urllib.request

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
    def resolvedType(self):
        """This candidate's tunnel type, inferred from its domain when `type` is unset."""
        return self.resolveType(self.domain, type=self.type)

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


class TunnelSSLContext:
    """The TLS context tunnel connections verify their relay with: the platform
    trust store plus every CA bundle the environment names in SSL_CERT_FILE,
    REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE. The last two are what `requests`
    (FFL's API calls) trusts, so a TLS-intercepting proxy the environment
    trusts for API calls is trusted for tunnels too. Certificate verification
    is never disabled.

    Loading the trust store is slow (~200ms Windows cert store, ~50ms
    Linux/macOS CA bundle), so shared() builds one context per process for
    each TLS-version pin and warm() lets a background thread pay that cost
    early. A context is safe to share across threads and connections.
    """

    CA_BUNDLE_ENV_VARS = ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')

    _shared = {} # pinnedVersion -> context
    _lock = threading.Lock()

    @classmethod
    def create(cls):
        """A new, unshared context."""
        context = ssl.create_default_context()
        caBundles = dict.fromkeys(filter(None, (os.getenv(name) for name in cls.CA_BUNDLE_ENV_VARS)))
        for caBundle in caBundles:
            if os.path.isdir(caBundle):
                context.load_verify_locations(capath=caBundle)
            else:
                context.load_verify_locations(cafile=caBundle)

        return context

    @classmethod
    def shared(cls, pinnedVersion=None):
        """The process-wide context, with both its minimum and maximum TLS
        version pinned to `pinnedVersion` (an ssl.TLSVersion) when given."""
        context = cls._shared.get(pinnedVersion)
        if context is not None:
            return context

        with cls._lock:
            if pinnedVersion not in cls._shared:
                context = cls.create()
                if pinnedVersion is not None:
                    context.minimum_version = pinnedVersion
                    context.maximum_version = pinnedVersion

                cls._shared[pinnedVersion] = context

            return cls._shared[pinnedVersion]

    @classmethod
    def warm(cls):
        cls.shared()


class SocketReader:
    """Exact-size blocking reads from a raw socket, for handshakes that must
    not consume bytes past their own frame (SOCKS5, HTTP CONNECT, WebSocket upgrade)."""

    MAX_HTTP_HEAD_SIZE = 64 * 1024

    def __init__(self, sock):
        self.sock = sock

    def read(self, size):
        """Read exactly `size` bytes or raise a useful connection error."""
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError('Peer closed the connection unexpectedly')

            data.extend(chunk)

        return bytes(data)

    def readHTTPHead(self):
        """The HTTP response head, without its terminating blank line."""
        head = bytearray()
        while not head.endswith(b'\r\n\r\n'):
            if len(head) >= self.MAX_HTTP_HEAD_SIZE:
                raise ConnectionError('HTTP response head is too large')

            head.extend(self.read(1)) # byte-at-a-time: never consume past the head

        return bytes(head[:-4])


class TunnelDialer(ABC):
    """Opens TCP connections to tunnel relays: directly, or through a SOCKS5 or
    HTTP CONNECT proxy. Build one with fromProxyConfig().

    Tunnel transports (bore's control/data connections, the web tunnel's
    WebSockets) and the relay latency race use raw sockets rather than
    `requests`, so the HTTP(S)_PROXY environment that `requests` honours never
    reaches them; a TunnelDialer is what carries the proxy to those sockets.
    """

    SOCKS5_ENV_VAR = 'FFL_TUNNEL_SOCKS5'

    # Latency multiplier per tunnel type for relays reached through this
    # dialer: relays are ranked by latency * weight, so a type weighing 2 wins
    # only when every other type is more than twice as slow. Unlisted types
    # weigh 1. The web tunnel is preferred: bore's own protocol is the one
    # middleboxes are likelier to break.
    tunnelTypeWeights = {'bore': 2.0}

    # Tunnel types raced only when no relay of any other type is reachable.
    fallbackTunnelTypes = frozenset()

    @classmethod
    def fromProxyConfig(cls, proxyConfig):
        """The dialer for `proxyConfig` (a bases.Utils.ProxyConfig, from --proxy
        or the proxy environment), else for the FFL_TUNNEL_SOCKS5 environment
        variable, else a direct dialer."""
        if proxyConfig:
            return ProxyDialer.fromConfig(proxyConfig)

        return Socks5ProxyDialer.fromEnvironment(cls.SOCKS5_ENV_VAR) or DirectDialer()

    @property
    def displayURL(self):
        """The proxy URL without its password, for display; None when direct."""
        return None

    def latencyWeightOf(self, tunnelType):
        return self.tunnelTypeWeights.get(tunnelType, 1.0)

    def isFallbackType(self, tunnelType):
        return tunnelType in self.fallbackTunnelTypes

    @abstractmethod
    def dial(self, host, port, timeout):
        """Return a blocking TCP socket connected to host:port."""

    async def openStream(self, host, port, sslCtx, serverHostname=None, timeout=None):
        """Open an asyncio TLS stream (reader, writer) to host:port."""
        sock = await asyncio.get_running_loop().run_in_executor(None, self.dial, host, port, timeout)
        return await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=sslCtx, server_hostname=serverHostname),
            timeout,
        )

    def measureLatency(self, host, port=443, timeout=5):
        """Milliseconds to open a TCP connection to host:port, or None when unreachable."""
        startTime = monotonic()
        try:
            sock = self.dial(host, port, timeout)
        except OSError as e:
            logger.debug(f"Failed to connect to {host}:{port} for latency check: {e}")
            return None

        latency = (monotonic() - startTime) * 1000
        try:
            sock.shutdown(socket.SHUT_RD)
        except OSError as e:
            logger.debug(f"Failed to shut down latency probe socket to {host}:{port}: {e}")
        finally:
            sock.close()

        return float(latency)


class DirectDialer(TunnelDialer):
    """Connects straight to the relay."""

    def dial(self, host, port, timeout):
        return socket.create_connection((host, port), timeout=timeout)

    async def openStream(self, host, port, sslCtx, serverHostname=None, timeout=None):
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=sslCtx, server_hostname=serverHostname),
            timeout,
        )


class ProxyDialer(TunnelDialer):
    """Connects to the proxy, then asks it (_handshake) for a tunnel to the relay.

    Hosts matched by NO_PROXY (urllib.request.proxy_bypass) are dialed
    directly, as `requests` does for its own connections.
    """

    def __init__(self, host, port, scheme, username=None, password=None):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.username = username
        self.password = password

    @classmethod
    def fromConfig(cls, proxyConfig):
        if proxyConfig['protocol'] == 'https':
            raise ValueError(
                f"Tunnel connections cannot use an HTTPS (TLS-to-proxy) proxy "
                f"({proxyConfig['host']}:{proxyConfig['port']}); use an http:// or socks5:// proxy instead."
            )

        dialerClasses = {'socks5': Socks5ProxyDialer, 'http': HTTPConnectProxyDialer}
        return dialerClasses[proxyConfig['type']](
            proxyConfig['host'],
            proxyConfig['port'],
            proxyConfig['protocol'],
            username=proxyConfig.get('username'),
            password=proxyConfig.get('password'),
        )

    @property
    def displayURL(self):
        credentials = f"{self.username}@" if self.username else ''
        return f"{self.scheme}://{credentials}{self.host}:{self.port}"

    @abstractmethod
    def _handshake(self, sock, host, port):
        """Ask the proxy, over `sock`, to tunnel to host:port; raise ConnectionError on refusal."""

    def dial(self, host, port, timeout):
        if urllib.request.proxy_bypass(host):
            logger.debug(f"{host} is excluded by NO_PROXY, connecting directly")
            return DirectDialer().dial(host, port, timeout)

        logger.debug(f"Connecting to {host}:{port} via proxy {self.displayURL}")
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            self._handshake(sock, host, port)
        except Exception:
            sock.close()
            raise

        return sock


class Socks5ProxyDialer(ProxyDialer):
    """SOCKS5 (RFC 1928) with optional username/password auth (RFC 1929).
    The relay hostname is always resolved by the proxy (socks5h semantics)."""

    VERSION = 0x05
    NO_AUTHENTICATION = 0x00
    USERNAME_PASSWORD = 0x02
    USERNAME_PASSWORD_VERSION = 0x01
    CONNECT_COMMAND = 0x01
    ADDRESS_SIZES = {0x01: 4, 0x04: 16}
    DOMAIN_ADDRESS = 0x03

    @classmethod
    def fromEnvironment(cls, envVar):
        """The dialer for a host:port in `envVar`, or None when unset or invalid."""
        value = os.getenv(envVar, '').strip()
        if not value:
            return None

        host, separator, portValue = value.rpartition(':')
        if not separator or not portValue.isdigit():
            logger.warning('Ignoring invalid %s value: %r', envVar, value)
            return None

        return cls(host, int(portValue), 'socks5h')

    def _authenticate(self, sock, reader):
        username = self.username.encode('utf-8')
        password = (self.password or '').encode('utf-8')
        if len(username) > 255 or len(password) > 255:
            raise ConnectionError('SOCKS5 username and password must each be at most 255 bytes')

        sock.sendall(
            bytes((self.USERNAME_PASSWORD_VERSION, len(username))) + username + bytes((len(password),)) + password
        )
        _version, status = reader.read(2)
        if status != 0:
            raise ConnectionError('SOCKS5 proxy rejected the username/password')

    def _negotiateMethod(self, sock, reader):
        methods = (self.NO_AUTHENTICATION, self.USERNAME_PASSWORD) if self.username else (self.NO_AUTHENTICATION,)
        sock.sendall(bytes((self.VERSION, len(methods), *methods)))

        version, method = reader.read(2)
        if version != self.VERSION or method not in methods:
            raise ConnectionError(f'SOCKS5 proxy accepted none of the offered authentication methods {methods}')

        if method == self.USERNAME_PASSWORD:
            self._authenticate(sock, reader)

    def _handshake(self, sock, host, port):
        reader = SocketReader(sock)
        self._negotiateMethod(sock, reader)

        hostname = host.encode('idna')
        if len(hostname) > 255:
            raise ConnectionError('SOCKS5 destination hostname is too long')

        request = bytearray((self.VERSION, self.CONNECT_COMMAND, 0, self.DOMAIN_ADDRESS, len(hostname)))
        request.extend(hostname)
        request.extend(port.to_bytes(2, 'big'))
        sock.sendall(request)

        version, reply, _reserved, addressType = reader.read(4)
        if version != self.VERSION or reply != 0:
            raise ConnectionError(f'SOCKS5 CONNECT to {host}:{port} failed with reply code {reply}')

        if addressType == self.DOMAIN_ADDRESS:
            addressSize = reader.read(1)[0]
        elif addressType in self.ADDRESS_SIZES:
            addressSize = self.ADDRESS_SIZES[addressType]
        else:
            raise ConnectionError(f'SOCKS5 proxy returned unknown address type {addressType}')

        reader.read(addressSize + 2)


class HTTPConnectProxyDialer(ProxyDialer):
    """HTTP proxy, tunnelling TCP with the CONNECT method (RFC 9110 9.3.6)
    and optional Basic proxy authentication."""

    # HTTP proxies -- TLS-intercepting ones above all -- reliably carry only
    # HTTP(S); the web tunnel is WebSocket over HTTPS, bore is its own protocol.
    fallbackTunnelTypes = frozenset({'bore'})

    def _handshake(self, sock, host, port):
        authority = f"[{host}]:{port}" if ':' in host else f"{host}:{port}"
        requestLines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
        if self.username:
            credentials = base64.b64encode(f"{self.username}:{self.password or ''}".encode('utf-8')).decode('ascii')
            requestLines.append(f"Proxy-Authorization: Basic {credentials}")

        sock.sendall(('\r\n'.join(requestLines) + '\r\n\r\n').encode('latin-1'))

        statusLine = SocketReader(sock).readHTTPHead().split(b'\r\n', 1)[0].decode('latin-1')
        statusParts = statusLine.split(' ', 2)
        if len(statusParts) < 2 or statusParts[1] != '200':
            raise ConnectionError(f'HTTP proxy refused CONNECT {authority}: {statusLine}')


class TunnelRace:
    """Probes tunnel candidates in parallel through a dialer and picks the
    reachable one with the lowest weighted latency: latency * the dialer's
    weight for the candidate's tunnel type (see TunnelDialer.tunnelTypeWeights).
    A candidate of a fallback type (TunnelDialer.fallbackTunnelTypes) wins only
    when no other is reachable; it is probed alongside the others all the
    same, so falling back costs no extra round of probes.

    A probe still running after t ms will measure at least t ms, so it can no
    longer beat a finished candidate once t * its weight reaches that
    candidate's weighted latency; the race ends there without waiting for it.
    Candidates still queued behind MAX_PARALLEL_PROBES have no such bound, so
    they are waited for only while the best weighted latency so far exceeds
    `latencyThreshold`.
    """

    MAX_PARALLEL_PROBES = 8

    def __init__(self, candidates, dialer, latencyThreshold):
        self.candidates = candidates
        self.dialer = dialer
        self.latencyThreshold = latencyThreshold
        self._weights = [dialer.latencyWeightOf(candidate.resolvedType) for candidate in candidates]
        self._isFallback = [dialer.isFallbackType(candidate.resolvedType) for candidate in candidates]
        self._startedAt = [None] * len(candidates)
        self._finished = [False] * len(candidates)
        self._condition = threading.Condition()

    def run(self):
        """The winning candidate; raise ConnectionError when none is reachable."""
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(self.MAX_PARALLEL_PROBES, len(self.candidates)))
        try:
            # Candidates likelier to win are probed first, so none waits queued behind ones that cannot beat it.
            probeOrder = sorted(range(len(self.candidates)), key=lambda index: (self._isFallback[index], self._weights[index]))
            futures = [executor.submit(self._probe, index) for index in probeOrder]
            with self._condition:
                decided, bestIndex, waitSeconds = self._decide()
                while not decided:
                    self._condition.wait(waitSeconds)
                    decided, bestIndex, waitSeconds = self._decide()

            for future in futures:
                if future.done():
                    future.result() # surface a probe's unexpected error
        finally:
            # Probes that can no longer win finish in the background.
            executor.shutdown(wait=False, cancel_futures=True)

        if bestIndex is None:
            raise ConnectionError('Cannot connect to any FastFileLink server.')

        winner = self.candidates[bestIndex]
        logger.debug(
            f"Tunnel race winner: {winner.domain} ({winner.latency:.1f}ms, weighted {self._weightedLatency(bestIndex):.1f}ms)"
        )
        return winner

    def _probe(self, index):
        with self._condition:
            self._startedAt[index] = monotonic()
            self._condition.notify()

        latency = None
        try:
            latency = self.dialer.measureLatency(self.candidates[index].probeHost)
        finally:
            with self._condition:
                self.candidates[index].latency = latency
                self._finished[index] = True
                self._condition.notify()

    def _weightedLatency(self, index):
        return self.candidates[index].latency * self._weights[index]

    def _rank(self, index):
        return self._isFallback[index], self._weightedLatency(index)

    def _decide(self):
        """(decided, index of the best candidate so far, seconds until it may
        be decided by time alone); called with the condition held."""
        pending = [index for index, finished in enumerate(self._finished) if not finished]
        reachable = [
            index for index, finished in enumerate(self._finished)
            if finished and self.candidates[index].latency is not None
        ]
        bestIndex = min(reachable, key=self._rank, default=None)
        if not pending or bestIndex is None:
            return not pending, bestIndex, None

        if any(not self._isFallback[index] for index in pending) and self._isFallback[bestIndex]:
            return False, bestIndex, None # a non-fallback candidate may still be reachable

        # Only candidates in the best one's tier can still beat it.
        pending = [index for index in pending if self._isFallback[index] == self._isFallback[bestIndex]]
        bestLatency = self._weightedLatency(bestIndex)
        if bestLatency > self.latencyThreshold and any(self._startedAt[index] is None for index in pending):
            return False, bestIndex, None

        # When the last running probe that could still come in under bestLatency stops being able to.
        lastDeadline = max((
            self._startedAt[index] + bestLatency / self._weights[index] / 1000
            for index in pending if self._startedAt[index] is not None
        ), default=0.0)
        waitSeconds = lastDeadline - monotonic()
        
        return waitSeconds <= 0, bestIndex, max(waitSeconds, 0)


def getLowLatencyTunnel(candidates, latencyThreshold=60, proxyConfig=None):
    """Race tunnel candidates with parallel latency testing and pick the best
    one, ranked by latency weighted per tunnel type for the route; candidates
    of the route's fallback types win only when no other is reachable (see
    TunnelRace).

    Args:
        candidates: Non-empty list of TunnelCandidate instances.  This is either
            the raw /api/tunnels response, converted by the caller (Features
            addon), or a hardcoded fallback list with the same shape (no
            Features addon).
        latencyThreshold: Weighted latency in milliseconds that is good enough
            not to wait for candidates still queued behind the parallel probes.
        proxyConfig: Optional proxy configuration; candidates are probed
            through the same proxy their tunnel will later be dialed through.

    Returns:
        TunnelCandidate: The winning candidate.

    Raises:
        ConnectionError: When no candidates are given, or none are reachable.
    """
    if not candidates:
        raise ConnectionError('No tunnel candidates were provided.')

    # TCP connect on port 443 is sufficient proof of reachability — no extra HTTP GET needed.
    return TunnelRace(candidates, TunnelDialer.fromProxyConfig(proxyConfig), latencyThreshold).run()


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


def resolveTunnelCandidate(latencyThreshold=60, tunnelType=None, proxyConfig=None):
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
        candidates = [candidate for candidate in candidates if candidate.resolvedType == tunnelType]

    return getLowLatencyTunnel(candidates, latencyThreshold=latencyThreshold, proxyConfig=proxyConfig)


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
