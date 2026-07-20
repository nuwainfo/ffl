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

import io
import os
import re
import tempfile
import unittest

from dataclasses import dataclass, field
from functools import partial

from bases.HTTP import (
    ByteRange,
    FormDataMixin,
    HTTPRequestHandlerHelper,
    PathResolverMixin,
    RangeResolver,
    ResolvedRange,
)


class RangeResolverTest(unittest.TestCase):
    """Unit tests for RangeResolver.parse()/resolve() — pure Range-header
    parsing/resolution math, no HTTP server needed."""

    # --- parse() ---

    def testParseNoHeader(self):
        self.assertIsNone(RangeResolver.parse(None))

    def testParseBlankHeader(self):
        self.assertIsNone(RangeResolver.parse(''))
        self.assertIsNone(RangeResolver.parse('   '))

    def testParseMalformedHeader(self):
        self.assertIsNone(RangeResolver.parse('garbage'))
        self.assertIsNone(RangeResolver.parse('bytes='))
        self.assertIsNone(RangeResolver.parse('bytes=abc-def'))

    def testParseSingleByte(self):
        # bytes=0-0: a fully-specified single-byte range, not "unset".
        self.assertEqual(RangeResolver.parse('bytes=0-0'), ByteRange(start=0, end=0))

    def testParseInvalidStartAfterEnd(self):
        # bytes=5-0: start > end must be rejected outright, not silently
        # passed through as if end were unset.
        self.assertIsNone(RangeResolver.parse('bytes=5-0'))

    def testParseOpenEnded(self):
        self.assertEqual(RangeResolver.parse('bytes=500-'), ByteRange(start=500, end=None))

    def testParseBoundedRange(self):
        self.assertEqual(RangeResolver.parse('bytes=100-199'), ByteRange(start=100, end=199))

    # --- resolve() ---

    def testResolveNoRangeKnownSize(self):
        resolved = RangeResolver.resolve(None, 100)
        self.assertEqual(resolved, ResolvedRange(start=0, end=99, satisfiable=True, contentLength=100))

    def testResolveNoRangeUnknownSize(self):
        resolved = RangeResolver.resolve(None, None)
        self.assertEqual(resolved, ResolvedRange(start=0, end=None, satisfiable=True, contentLength=None))

    def testResolveSingleByteWithinBounds(self):
        resolved = RangeResolver.resolve(ByteRange(start=0, end=0), 100)
        self.assertEqual(resolved, ResolvedRange(start=0, end=0, satisfiable=True, contentLength=1))

    def testResolveOpenEndedClampsToSize(self):
        resolved = RangeResolver.resolve(ByteRange(start=50, end=None), 100)
        self.assertEqual(resolved, ResolvedRange(start=50, end=99, satisfiable=True, contentLength=50))

    def testResolveStartWayBeyondSizeUnsatisfiable(self):
        # bytes=999999- against a 100-byte resource.
        resolved = RangeResolver.resolve(ByteRange(start=999999, end=None), 100)
        self.assertFalse(resolved.satisfiable)

    def testResolveStartAtExactSizeUnsatisfiable(self):
        # start == size is out of bounds -- valid indices are 0..size-1.
        resolved = RangeResolver.resolve(ByteRange(start=100, end=None), 100)
        self.assertFalse(resolved.satisfiable)

    def testResolveEndBeyondSizeIsClampedNotRejected(self):
        # A too-large end is clamped to the last valid byte, not treated as unsatisfiable.
        resolved = RangeResolver.resolve(ByteRange(start=0, end=999999), 100)
        self.assertEqual(resolved, ResolvedRange(start=0, end=99, satisfiable=True, contentLength=100))

    def testResolveExactFullRange(self):
        resolved = RangeResolver.resolve(ByteRange(start=0, end=99), 100)
        self.assertEqual(resolved, ResolvedRange(start=0, end=99, satisfiable=True, contentLength=100))

    def testResolveUnknownSizePassesThroughUnvalidated(self):
        # Unknown size (e.g. stdin, deflate ZIP streaming) means there's nothing
        # to validate against, so the range passes through as-is and is always
        # reported satisfiable -- even one that would be rejected against a
        # known size.
        resolved = RangeResolver.resolve(ByteRange(start=100, end=None), None)
        self.assertEqual(resolved, ResolvedRange(start=100, end=None, satisfiable=True, contentLength=None))

        resolvedHuge = RangeResolver.resolve(ByteRange(start=999999999, end=None), None)
        self.assertTrue(resolvedHuge.satisfiable)


class _TestValueResolver(FormDataMixin.ValueResolver):
    pass


@dataclass
class _TestFormState(FormDataMixin):
    name: str = field(default='', metadata={'formStrip': True})
    nickname: str | None = field(default=None, metadata={'formStrip': True, 'formEmptyAsNone': True})
    enabled: bool = False
    count: int = field(default=0, metadata={
        'formParser': partial(_TestValueResolver.parseOptionalCount, fieldName='Count'),
    })
    aliases: str | None = field(default=None, metadata={
        'formKeys': ('aliases', 'alias'),
        'formParser': _TestValueResolver.buildSerializedDelimitedValue,
        'formEmptyAsNone': True,
    })
    upperName: str | None = field(default=None, metadata={
        'formValueFactory': lambda formData: str(formData['name']).strip().upper(),
    })


class ValueResolverTest(unittest.TestCase):

    def testParseOptionalCountAcceptsBlankAsZero(self):
        self.assertEqual(_TestValueResolver.parseOptionalCount('', 'Count'), 0)

    def testParseOptionalCountRejectsInvalidText(self):
        with self.assertRaisesRegex(ValueError, 'Count'):
            _TestValueResolver.parseOptionalCount('abc', 'Count')

    def testParseOptionalCountRejectsNegativeValue(self):
        with self.assertRaisesRegex(ValueError, 'Count'):
            _TestValueResolver.parseOptionalCount('-1', 'Count')

    def testParseDelimitedValuesNormalizesDeduplicatesAndSkipsBlank(self):
        values = _TestValueResolver.parseDelimitedValues(
            ' Alpha@example.com,\nalpha@example.com,,Beta@example.com ',
            normalizer=str.lower,
        )

        self.assertEqual(values, ('alpha@example.com', 'beta@example.com'))

    def testParseDelimitedValuesAcceptsSequenceInput(self):
        values = _TestValueResolver.parseDelimitedValues([' one ', 'two', 'one'])
        self.assertEqual(values, ('one', 'two'))

    def testBuildSerializedDelimitedValueUsesCommaJoinByDefault(self):
        value = _TestValueResolver.buildSerializedDelimitedValue('one, two, one')
        self.assertEqual(value, 'one,two')

    def testBuildSerializedDelimitedValueSupportsCustomSerializer(self):
        value = _TestValueResolver.buildSerializedDelimitedValue(
            'One, two',
            normalizer=str.lower,
            serializer='|'.join,
        )
        self.assertEqual(value, 'one|two')

    def testBuildSerializedDelimitedValueReturnsConfiguredEmptyValue(self):
        value = _TestValueResolver.buildSerializedDelimitedValue('', emptyValue='EMPTY')
        self.assertEqual(value, 'EMPTY')

    def testIsLikelyValidEmailAcceptsReasonableAddress(self):
        self.assertTrue(_TestValueResolver.isLikelyValidEmail('user.name+tag@example.com'))

    def testIsLikelyValidEmailRejectsMalformedAddress(self):
        self.assertFalse(_TestValueResolver.isLikelyValidEmail('bad..email@example.com'))
        self.assertFalse(_TestValueResolver.isLikelyValidEmail('missing-domain@'))

    def testValidateEmailValuesAllowsEmptyWithoutMessage(self):
        _TestValueResolver.validateEmailValues(())

    def testValidateEmailValuesRaisesEmptyMessage(self):
        with self.assertRaisesRegex(ValueError, 'Email is required'):
            _TestValueResolver.validateEmailValues((), emptyMessage='Email is required')

    def testValidateEmailValuesRaisesInvalidMessage(self):
        with self.assertRaisesRegex(ValueError, 'Bad email'):
            _TestValueResolver.validateEmailValues(('bad-email',), invalidMessage='Bad email')


class FormDataMixinTest(unittest.TestCase):

    def testBuildFormDataUpdateParsesConfiguredFields(self):
        updates = _TestFormState.buildFormDataUpdate({
            'name': '  Alice  ',
            'nickname': '   ',
            'enabled': '1',
            'count': '3',
            'aliases': 'one, two, one',
        })

        self.assertEqual(updates['name'], 'Alice')
        self.assertIsNone(updates['nickname'])
        self.assertTrue(updates['enabled'])
        self.assertEqual(updates['count'], 3)
        self.assertEqual(updates['aliases'], 'one,two')
        self.assertEqual(updates['upperName'], 'ALICE')

    def testBuildFormDataUpdateUsesFallbackFormKey(self):
        updates = _TestFormState.buildFormDataUpdate({
            'name': 'Bob',
            'alias': 'solo',
        })

        self.assertEqual(updates['aliases'], 'solo')

    def testBuildFormDataUpdateSkipsMissingFields(self):
        updates = _TestFormState.buildFormDataUpdate({'name': 'Carol'})

        self.assertEqual(updates, {
            'name': 'Carol',
            'upperName': 'CAROL',
        })

    def testApplyFormUpdatesStateInPlace(self):
        state = _TestFormState()
        state.applyForm({
            'name': '  Delta  ',
            'enabled': '1',
            'count': '5',
            'aliases': 'x,y',
        })

        self.assertEqual(state.name, 'Delta')
        self.assertTrue(state.enabled)
        self.assertEqual(state.count, 5)
        self.assertEqual(state.aliases, 'x,y')
        self.assertEqual(state.upperName, 'DELTA')

    def testBuildFormDataUpdateCanRestrictParsedFields(self):
        updates = _TestFormState.buildFormDataUpdate({
            'name': 'After',
            'count': '9',
        }, fieldNames=('count',))

        self.assertEqual(updates, {'count': 9})

    def testGetFieldRefsExposesDataclassFields(self):
        refs = FormDataMixin.getFieldRefs(_TestFormState)
        self.assertEqual(refs.name.name, 'name')
        self.assertEqual(refs.aliases.name, 'aliases')


class _RouterHost(PathResolverMixin):
    """Minimal PathResolverMixin host for unit-testing route resolution in
    isolation -- no socket, no session, no other mixins."""


class PathResolverMixinTest(unittest.TestCase):
    """Unit tests for PathResolverMixin: exact-string routes, regex fallback,
    and Django-style named-group capture (a matched regex's named groups are
    bound as keyword arguments on the returned handler)."""

    def _makeHost(self):
        return _RouterHost()

    def testExactStringRouteResolves(self):
        host = self._makeHost()
        handler = lambda: 'ok'
        host.mapGETRoute('/status', handler)

        self.assertIs(host._resolveGETHandler('/status'), handler)

    def testUnknownPathResolvesToNone(self):
        host = self._makeHost()
        host.mapGETRoute('/status', lambda: 'ok')

        self.assertIsNone(host._resolveGETHandler('/nope'))

    def testExactStringTakesPriorityOverOverlappingRegex(self):
        host = self._makeHost()
        exactHandler = lambda: 'exact'
        regexHandler = lambda assetPath: f'regex:{assetPath}'
        host.mapGETRoute('/assets/exact', exactHandler)
        host.mapGETRoute(re.compile(r'^/assets/(?P<assetPath>.+)$'), regexHandler)

        self.assertIs(host._resolveGETHandler('/assets/exact'), exactHandler)

    def testRegexWithoutNamedGroupsReturnsHandlerUnwrapped(self):
        # No capture groups -- identity is preserved, same as a plain string route.
        host = self._makeHost()
        handler = lambda: 'static'
        pattern = re.compile(r'^/static(?:/.+)?$')
        host.mapGETRoute(pattern, handler)

        self.assertIs(host._resolveGETHandler('/static/js/app.js'), handler)

    def testNamedGroupIsBoundAsHandlerKeywordArgument(self):
        host = self._makeHost()
        received = {}

        def handleAsset(assetPath):
            received['assetPath'] = assetPath
            return assetPath

        host.mapGETRoute(re.compile(r'^/assets/(?P<assetPath>.+)$'), handleAsset)

        resolved = host._resolveGETHandler('/assets/css/app.css')
        self.assertEqual(resolved(), 'css/app.css')
        self.assertEqual(received['assetPath'], 'css/app.css')

    def testMultipleNamedGroupsAreAllBound(self):
        host = self._makeHost()

        def handleShareFile(shareId, fileName):
            return (shareId, fileName)

        host.mapGETRoute(
            re.compile(r'^/shares/(?P<shareId>[^/]+)/files/(?P<fileName>.+)$'),
            handleShareFile,
        )

        resolved = host._resolveGETHandler('/shares/abc123/files/report.pdf')
        self.assertEqual(resolved(), ('abc123', 'report.pdf'))

    def testCapturedKwargsCoexistWithCallerPositionalArgs(self):
        # Mirrors how DownloadHandler calls GET handlers: handler(args), where
        # args is the parsed query string -- captured path segments must not
        # break that positional call convention.
        host = self._makeHost()

        def handleAsset(queryArgs, assetPath):
            return (queryArgs, assetPath)

        host.mapGETRoute(re.compile(r'^/assets/(?P<assetPath>.+)$'), handleAsset)

        resolved = host._resolveGETHandler('/assets/img/logo.png')
        self.assertEqual(resolved({'v': ['2']}), ({'v': ['2']}, 'img/logo.png'))

    def testHeadGetPostRoutesResolveIndependently(self):
        host = self._makeHost()
        getHandler = lambda: 'get'
        headHandler = lambda: 'head'
        postHandler = lambda: 'post'

        host.mapGETRoute('/thing', getHandler)
        host.mapHEADRoute('/thing', headHandler)
        host.mapPOSTRoute('/thing', postHandler)

        self.assertIs(host._resolveGETHandler('/thing'), getHandler)
        self.assertIs(host._resolveHEADHandler('/thing'), headHandler)
        self.assertIs(host._resolvePOSTHandler('/thing'), postHandler)

    def testDuplicateRouteRaisesRuntimeError(self):
        host = self._makeHost()
        host.mapGETRoute('/status', lambda: 'first')

        with self.assertRaises(RuntimeError):
            host.mapGETRoute('/status', lambda: 'second')


class _FakeHTTPHandler(HTTPRequestHandlerHelper):
    """Minimal HTTPRequestHandlerHelper host that records what would be sent
    over the wire, for testing response-building logic without a real socket."""

    def __init__(self):
        self.wfile = io.BytesIO()
        self.status = None
        self.reason = None
        self.headersSent = {}

    def send_response(self, code, reason=None):
        self.status = code
        self.reason = reason

    def send_header(self, name, value):
        self.headersSent[name] = value

    def end_headers(self):
        pass

    def body(self) -> bytes:
        return self.wfile.getvalue()


def _decodeChunkedBody(data: bytes) -> bytes:
    """Decode an HTTP/1.1 chunked-transfer-encoded body (as written by
    _writeChunk/_finishChunked) back into its raw payload, for test assertions."""
    result = b''
    pos = 0
    while True:
        crlf = data.index(b'\r\n', pos)
        size = int(data[pos:crlf], 16)
        if size == 0:
            break
        start = crlf + 2
        result += data[start:start + size]
        pos = start + size + 2  # skip payload + trailing CRLF
    return result


class StreamFileTest(unittest.TestCase):
    """Unit tests for HTTPRequestHandlerHelper._streamFile -- Range handling
    (via RangeResolver), 416 responses, and the unknown-size chunked-transfer
    path (via _writeChunk/_finishChunked). No real socket -- headers/body are
    captured in memory via _FakeHTTPHandler."""

    def setUp(self):
        self._tmpDir = tempfile.mkdtemp()
        self.content = bytes(range(256)) * 40  # 10240 bytes, deterministic
        self.path = os.path.join(self._tmpDir, 'stream_test.bin')
        with open(self.path, 'wb') as f:
            f.write(self.content)

    def _makeHandler(self):
        return _FakeHTTPHandler()

    def testFullFileNoRangeHeader(self):
        handler = self._makeHandler()
        handler._streamFile(self.path, len(self.content))

        self.assertEqual(handler.status, 200)
        self.assertEqual(handler.headersSent['Content-Length'], str(len(self.content)))
        self.assertEqual(handler.headersSent['Accept-Ranges'], 'bytes')
        self.assertNotIn('Content-Range', handler.headersSent)
        self.assertEqual(handler.body(), self.content)

    def testBoundedRangeReturnsPartialContent(self):
        handler = self._makeHandler()
        handler._streamFile(self.path, len(self.content), rangeHeader='bytes=100-199')

        self.assertEqual(handler.status, 206)
        self.assertEqual(handler.headersSent['Content-Range'], f'bytes 100-199/{len(self.content)}')
        self.assertEqual(handler.headersSent['Content-Length'], '100')
        self.assertEqual(handler.body(), self.content[100:200])

    def testOpenEndedRangeReturnsTailOfFile(self):
        handler = self._makeHandler()
        tailStart = len(self.content) - 40
        handler._streamFile(self.path, len(self.content), rangeHeader=f'bytes={tailStart}-')

        self.assertEqual(handler.status, 206)
        self.assertEqual(handler.body(), self.content[tailStart:])

    def testMalformedRangeHeaderTreatedAsFullRequest(self):
        # Per RFC 7233, an unparseable Range header is ignored, not rejected --
        # this differs from VFS's pre-refactor behavior (which sent 416), but
        # now matches DownloadHandler's existing RangeResolver-based handling.
        handler = self._makeHandler()
        handler._streamFile(self.path, len(self.content), rangeHeader='garbage')

        self.assertEqual(handler.status, 200)
        self.assertEqual(handler.body(), self.content)

    def testOutOfBoundsRangeReturns416WithContentLengthZero(self):
        # Regression guard: a 416 with no Content-Length leaves a keep-alive
        # client hanging forever waiting for a body that never arrives.
        handler = self._makeHandler()
        handler._streamFile(self.path, len(self.content), rangeHeader='bytes=999999-')

        self.assertEqual(handler.status, 416)
        self.assertEqual(handler.headersSent['Content-Length'], '0')
        self.assertEqual(handler.headersSent['Content-Range'], f'bytes */{len(self.content)}')
        self.assertEqual(handler.body(), b'')

    def testUnknownSizeUsesChunkedTransferEncoding(self):
        handler = self._makeHandler()
        handler._streamFile(self.path, fileSize=None)

        self.assertEqual(handler.status, 200)
        self.assertEqual(handler.headersSent['Transfer-Encoding'], 'chunked')
        self.assertNotIn('Content-Length', handler.headersSent)
        self.assertEqual(_decodeChunkedBody(handler.body()), self.content)

    def testUnknownSizeWithRangeHeaderReturns416(self):
        handler = self._makeHandler()
        handler._streamFile(self.path, fileSize=None, rangeHeader='bytes=0-99')

        self.assertEqual(handler.status, 416)
        self.assertEqual(handler.headersSent['Content-Length'], '0')
        self.assertEqual(handler.body(), b'')

    def testKeepAliveOmittedSendsNoConnectionHeader(self):
        handler = self._makeHandler()
        handler._streamFile(self.path, len(self.content))

        self.assertNotIn('Connection', handler.headersSent)

    def testKeepAliveExplicitSetsConnectionHeader(self):
        handlerAlive = self._makeHandler()
        handlerAlive._streamFile(self.path, len(self.content), keepAlive=True)
        self.assertEqual(handlerAlive.headersSent['Connection'], 'keep-alive')

        handlerClose = self._makeHandler()
        handlerClose._streamFile(self.path, len(self.content), keepAlive=False)
        self.assertEqual(handlerClose.headersSent['Connection'], 'close')


if __name__ == '__main__':
    unittest.main()
