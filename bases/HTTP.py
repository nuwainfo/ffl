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

import functools
import json
import re

from collections import OrderedDict
from dataclasses import dataclass
from http import HTTPMethod, HTTPStatus
from typing import Optional
from urllib.parse import parse_qs

import requests

from bases.Kernel import getLogger
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE

logger = getLogger(__name__)


@dataclass
class ByteRange:
    """A parsed Range request header (RFC 7233), before resolving against an
    actual resource size."""
    start: int
    end: Optional[int]  # None = open-ended (e.g. "bytes=500-")


@dataclass
class ResolvedRange:
    """A ByteRange resolved against an actual resource size."""
    start: int
    end: Optional[int]
    satisfiable: bool
    contentLength: Optional[int]  # None when the resource size is unknown, so no clamping was possible


class RangeResolver:
    """
    Pure Range-header parsing/resolution — no socket, no handler, no session.
    Every edge case (bytes=0-0, bytes=5-0, bytes=999999-, unknown size) is a
    plain function-in/value-out unit test, no HTTP server needed.
    """

    _PATTERN = re.compile(r'bytes=(\d+)-(\d+)?$')

    @staticmethod
    def parse(header: Optional[str]) -> Optional[ByteRange]:
        """Parse a Range request header. Returns None if absent, blank, or malformed."""
        if not header or not header.strip():
            return None

        match = RangeResolver._PATTERN.search(header)
        if not match:
            return None

        startText, endText = match.groups()
        start = int(startText)
        end = int(endText) if endText is not None else None

        # end may legitimately be 0 (e.g. "bytes=0-0" for a single byte), so this
        # must check "is not None" rather than truthiness, otherwise an invalid
        # range like "bytes=5-0" silently passes through as if end were unset.
        if end is not None and start > end:
            return None

        return ByteRange(start=start, end=end)

    @staticmethod
    def resolve(byteRange: Optional[ByteRange], size: Optional[int]) -> ResolvedRange:
        """Resolve a parsed ByteRange (or None, meaning no Range header was sent)
        against an actual resource size (or None, meaning unknown — e.g. a
        chunked-transfer source like stdin — in which case no clamping is
        possible and the range passes through unresolved, always satisfiable).
        """
        if byteRange is None:
            end = size - 1 if size is not None else None
            return ResolvedRange(start=0, end=end, satisfiable=True, contentLength=size)

        if size is None:
            return ResolvedRange(start=byteRange.start, end=byteRange.end, satisfiable=True, contentLength=None)

        if byteRange.start >= size or (byteRange.end is not None and byteRange.start > byteRange.end):
            return ResolvedRange(start=byteRange.start, end=byteRange.end, satisfiable=False, contentLength=None)

        clampedEnd = min(byteRange.end, size - 1) if byteRange.end is not None else size - 1
        contentLength = clampedEnd - byteRange.start + 1

        return ResolvedRange(start=byteRange.start, end=clampedEnd, satisfiable=True, contentLength=contentLength)


class HTTPRequestHandlerHelper:
    """
    Generic HTTP request-handler utilities: canned error/plain/JSON responses,
    chunked-transfer-encoding writes, and parsing URL/query parameters. Just
    raw request/response primitives (self.send_response/send_header/
    end_headers/self.wfile).
    """

    def _handleDefaultHead(self):
        super().do_HEAD()

    def _handleForbiddenHead(self, message='Disabled by server policy'):
        content = message.encode('utf-8')
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()

    def _handleForbidden(self, message='Disabled by server policy'):
        self._handleForbiddenHead(message)
        self.wfile.write(message.encode('utf-8'))

    def _handle404(self, message=None):
        if message:
            logger.debug(message)

        content = str(HTTPStatus.NOT_FOUND)
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/html")
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())

    def _sendConnectionHeader(self, keepAlive: Optional[bool]):
        """Send the Connection header for a hand-rolled keep-alive protocol"""
        if keepAlive is not None:
            self.send_header('Connection', 'keep-alive' if keepAlive else 'close')

    def _sendBytes(
        self,
        payload: bytes,
        ctype: str = "text/plain; charset=utf-8",
        extraHeaders: dict = None,
        status: HTTPStatus = HTTPStatus.OK,
    ):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        if extraHeaders:
            for key, value in extraHeaders.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(payload)

    def _sendJSON(self, status: int, data: dict, keepAlive: Optional[bool] = None):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self._sendConnectionHeader(keepAlive)
        self.end_headers()
        self.wfile.write(body)

    def _sendText(self, code: int, reason: str, msg: str, keepAlive: Optional[bool] = None):
        """Send a plain-text response with a custom status reason phrase."""
        data = msg.encode('utf-8')
        self.send_response(code, reason)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self._sendConnectionHeader(keepAlive)
        self.end_headers()
        self.wfile.write(data)

    def _readRequestBody(self) -> bytes:
        contentLength = int(self.headers.get('Content-Length', '0'))
        return self.rfile.read(contentLength) if contentLength > 0 else b''

    def _readJSONBody(self) -> dict:
        body = self._readRequestBody()
        return json.loads(body.decode('utf-8')) if body else {}

    def _readFormBody(self) -> dict:
        parsedForm = parse_qs(self._readRequestBody().decode('utf-8'), keep_blank_values=True)
        return {key: values[-1] if values else '' for key, values in parsedForm.items()}

    def _writeChunk(self, data: bytes):
        """
        Write a single chunk in HTTP/1.1 chunked transfer encoding format

        Args:
            data: Chunk data to write
        """
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    def _finishChunked(self):
        """Write the final chunk marker for HTTP/1.1 chunked transfer encoding"""
        self.wfile.write(b"0\r\n\r\n")

    def _streamFile(
        self,
        path: str,
        fileSize: Optional[int],
        rangeHeader: Optional[str] = None,
        ctype: str = 'application/octet-stream',
        keepAlive: Optional[bool] = None,
        chunkSize: int = TRANSFER_CHUNK_SIZE,
    ):
        """Stream a local file as the HTTP response, honoring an optional Range
        header via RangeResolver.

        fileSize=None means unknown length (can't be os.path.getsize()'d ahead
        of time) -- Range is not supported in that case (a Range header on an
        unknown-size resource is unsatisfiable, same as DownloadHandler's
        stdin/deflate-ZIP case), and the response uses Transfer-Encoding:
        chunked (see _writeChunk/_finishChunked) instead of Content-Length.

        A malformed/unparseable Range header is treated the same as no Range
        header at all (RangeResolver.parse returns None) -- the full resource
        is sent with 200, per RFC 7233's guidance to ignore invalid Range
        headers rather than reject them. Only a well-formed Range outside the
        resource's bounds gets 416.
        """
        byteRange = RangeResolver.parse(rangeHeader)

        if fileSize is None:
            if byteRange is not None:
                # Content-Length: 0 is required here, not optional -- on a kept-alive
                # connection, a response with no Content-Length/Transfer-Encoding and
                # no body leaves the client blocked reading a body that never arrives
                # while the server has already moved on to the next request.
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header('Content-Range', 'bytes */*')
                self.send_header('Content-Length', '0')
                self._sendConnectionHeader(keepAlive)
                self.end_headers()
                return

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', ctype)
            self.send_header('Transfer-Encoding', 'chunked')
            self._sendConnectionHeader(keepAlive)
            self.end_headers()

            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(chunkSize)
                    if not chunk:
                        break
                        
                    self._writeChunk(chunk)
                    
            self._finishChunked()
            return

        resolved = RangeResolver.resolve(byteRange, fileSize)
        if not resolved.satisfiable:
            # See the Content-Length: 0 comment in the fileSize=None branch above --
            # same hang risk applies here.
            self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Range', f'bytes */{fileSize}')
            self.send_header('Content-Length', '0')
            self._sendConnectionHeader(keepAlive)
            self.end_headers()
            return

        partial = byteRange is not None
        self.send_response(HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK)
        self.send_header('Content-Type', ctype)
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', str(resolved.contentLength))
        if partial:
            self.send_header('Content-Range', f'bytes {resolved.start}-{resolved.end}/{fileSize}')
            
        self._sendConnectionHeader(keepAlive)
        self.end_headers()

        try:
            with open(path, 'rb') as f:
                if resolved.start > 0:
                    f.seek(resolved.start)

                remaining = resolved.contentLength
                while remaining > 0:
                    chunk = f.read(min(chunkSize, remaining))
                    if not chunk:
                        break
                        
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except OSError as e:
            logger.error(f"Error streaming file {path}: {e}")

    @staticmethod
    def parseURLBooleanParam(value):
        """
        Parse a loosely-typed boolean: a real bool passes through, otherwise
        matches common string representations.

        True values: true, 1, on, yes (case-insensitive)
        False values: false, 0, off, no (case-insensitive)

        Returns True/False, or None if value is not a recognized boolean.
        """
        if isinstance(value, bool):
            return value
            
        if not value:
            return False

        lowerValue = value.lower()
        if lowerValue in ('true', '1', 'on', 'yes'):
            return True
        if lowerValue in ('false', '0', 'off', 'no'):
            return False

        return None

    @staticmethod
    def _parsePositiveDebugIntArg(args, argName, default=None):
        """Parse a positive integer debug query parameter."""
        if not args or argName not in args:
            return default

        rawValue = args[argName][0]
        if rawValue.isdecimal():
            return int(rawValue)

        logger.warning(f"[Test] Invalid {argName} value: {rawValue!r}, must be a positive integer")
        return default

    @staticmethod
    def _parseIntArg(args, argName, default=0):
        """Parse an integer query parameter, falling back to default on invalid input."""
        if not args or argName not in args:
            return default

        try:
            return int(args[argName][0])
        except (ValueError, IndexError, TypeError):
            return default


class StaticMixin:
    """
    Static asset/script serving, Requires the host class to be a 
    SimpleHTTPRequestHandler subclass
    (_serveLocalStaticScript uses super().do_GET() for local file serving),
    so this can only be mixed into the request handler itself — a View
    reaches it via self.handler, same as any other handler-owned method.
    """

    def _handleStatic(self, args=None, requestHeaders=None):
        """Serve a local static file through SimpleHTTPRequestHandler."""
        self._extraHeaders = requestHeaders or {}
        super().do_GET()

    def _serveLocalStaticScript(self, requestHeaders=None):
        """Serve script from local filesystem."""
        self._handleStatic(requestHeaders=requestHeaders)

    def _proxyStaticScript(self, scriptPath, requestHeaders=None, fallbackToLocal=False):
        """Generic method to proxy JavaScript files from static server

        Args:
            scriptPath: Relative path to script (e.g., "/static/js/E2EE.js")
            requestHeaders: Optional dict of additional headers to send with request
            fallbackToLocal: If True, fallback to local script when remote fetch fails
        """
        try:
            settingsGetter = SettingsGetter.getInstance()
            staticServer = settingsGetter.getStaticServer()
            remoteUrl = f"{staticServer}{scriptPath}"

            # Force identity encoding so the upstream returns plain bytes.
            # Copying remote Content-Encoding (zstd/gzip) while requests may have
            # already decoded the body causes Content-Length mismatches that break
            # HTTP/2 streams with INTERNAL_ERROR.
            headers = dict(requestHeaders or {})
            headers['Accept-Encoding'] = 'identity'

            response = requests.get(remoteUrl, headers=headers, timeout=10)
            response.raise_for_status()

            content = response.content
            contentType = response.headers.get('Content-Type', 'application/javascript')

            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', contentType)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        except requests.RequestException as e:
            if fallbackToLocal:
                logger.warning(
                    f"Failed to fetch {scriptPath} from {remoteUrl}, fallback to local script: {e}"
                )
                self._serveLocalStaticScript(requestHeaders=requestHeaders)
                return

            logger.error(f"Failed to fetch {scriptPath} from {remoteUrl}: {e}")
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Failed to fetch from remote server: {str(e)}")
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            logger.debug("Client disconnected while proxying static script")
        except Exception as e:
            logger.exception(e)
            self.send_error(500, str(e))

    def _handleStaticScript(self, scriptPath, requestHeaders=None, fallbackToLocal=False):
        """Handle static script - proxy from remote or serve locally

        Args:
            scriptPath: Path to the script file
            requestHeaders: Headers to send with remote request (proxy mode) or set in response (local mode)
            fallbackToLocal: If True, fallback to local script when remote fetch fails
        """
        settingsGetter = SettingsGetter.getInstance()
        staticServer = settingsGetter.getStaticServer()

        # If static server is remote (starts with http), proxy the file
        if staticServer.startswith('http'):
            self._proxyStaticScript(scriptPath, requestHeaders, fallbackToLocal=fallbackToLocal)
        else:
            # Static server is local - serve from local filesystem
            self._serveLocalStaticScript(requestHeaders=requestHeaders)


class PathResolverMixin:
    """
    Resolves an incoming request path against a host class's route tables,
    one per HTTPMethod. __new__ populates self.paths/self.reversePaths fresh
    per instance, so a host class never creates the mapping itself -- route
    registration should go through mapGETRoute()/mapHEADRoute()/
    mapPOSTRoute()/mapDELETERoute()/mapPUTRoute() rather than indexing
    self.paths directly.

    String keys match exactly; keys exposing `.match()` (e.g. compiled regex)
    are tried afterwards, in insertion order. Since `.match()` only anchors
    the start of the string, a pattern relying on exact-length matching must
    anchor its own trailing `$`, or trailing characters past a valid prefix
    are silently accepted. Named groups in a matched pattern are bound as
    keyword arguments on the returned handler, via functools.partial.

    Passing name=... records path (or, for a compiled re.Pattern, its own
    .pattern source, via getattr(path, 'pattern', path)) into
    self.reversePaths[name] -- the single source of truth a template can
    read back to build URLs, instead of a second, hand-maintained mapping.
    """

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.paths = {method: OrderedDict() for method in HTTPMethod}
        instance.reversePaths = {}
        return instance

    def mapGETRoute(self, path, handler, name=None):
        self._mapRoute(HTTPMethod.GET, path, handler, name=name)

    def mapHEADRoute(self, path, handler, name=None):
        self._mapRoute(HTTPMethod.HEAD, path, handler, name=name)

    def mapPOSTRoute(self, path, handler, name=None):
        self._mapRoute(HTTPMethod.POST, path, handler, name=name)

    def mapDELETERoute(self, path, handler, name=None):
        self._mapRoute(HTTPMethod.DELETE, path, handler, name=name)

    def mapPUTRoute(self, path, handler, name=None):
        self._mapRoute(HTTPMethod.PUT, path, handler, name=name)

    def _mapRoute(self, method, path, handler, name=None):
        routeMap = self.paths[method]
        if path in routeMap:
            raise RuntimeError(f"Route conflict: {path} is already mapped for {method.name}")

        routeMap[path] = handler

        if name is not None:
            self.reversePaths[name] = getattr(path, 'pattern', path)

    _ROUTE_GROUP_PATTERN = re.compile(r'\(\?P<(\w+)>[^()]*\)')

    @classmethod
    def buildRouteURL(cls, patternSource, **values):
        """Reverse a reversePaths[name] value back into an actual URL, e.g.
        '/api/gui/shares/(?P<shareId>[^/]+)$' + shareId='abc' ->
        '/api/gui/shares/abc'. A no-op for a plain-string value. A classmethod
        (no instance state) so it can be called directly."""
        url = cls._ROUTE_GROUP_PATTERN.sub(lambda match: str(values[match.group(1)]), patternSource)
        return url.rstrip('$')

    def _resolveHandler(self, routeMap, path):
        for routePath, handler in routeMap.items():
            if isinstance(routePath, str) and path == routePath:
                return handler

        for routePath, handler in routeMap.items():
            if hasattr(routePath, 'match'):
                match = routePath.match(path)
                if match:
                    namedGroups = match.groupdict()
                    return functools.partial(handler, **namedGroups) if namedGroups else handler

        return None

    def _resolveGETHandler(self, path):
        return self._resolveHandler(self.paths[HTTPMethod.GET], path)

    def _resolveHEADHandler(self, path):
        return self._resolveHandler(self.paths[HTTPMethod.HEAD], path)

    def _resolvePOSTHandler(self, path):
        return self._resolveHandler(self.paths[HTTPMethod.POST], path)

    def _resolveDELETEHandler(self, path):
        return self._resolveHandler(self.paths[HTTPMethod.DELETE], path)

    def _resolvePUTHandler(self, path):
        return self._resolveHandler(self.paths[HTTPMethod.PUT], path)
