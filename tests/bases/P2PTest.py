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

import logging
import os
import unittest

from types import SimpleNamespace
from unittest import mock

from bases.Download import FFLDownloader
from bases.P2P import P2PConfiguration, isP2PAvailable
from tests.CoreTestBase import FastFileLinkTestBase


@unittest.skipUnless(isP2PAvailable(), 'ffl-p2p extension is not available')
class P2PTest(FastFileLinkTestBase):
    """Verify full FFL shares use the intended direct P2P transport."""

    def testP2PConfigurationEnablesNativeDebugLogging(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch('bases.P2P.logging.getLogger') as getRootLogger:
                getRootLogger.return_value.isEnabledFor.return_value = True
                P2PConfiguration._enableNativeDebugLogging()

            self.assertEqual(os.environ['FFL_P2P_NATIVE_LOGGING_LEVEL'], 'DEBUG')

    def testP2PConfigurationPreservesNativeLoggingOverride(self):
        with mock.patch.dict(os.environ, {
            'FFL_P2P_NATIVE_LOGGING_LEVEL': 'WARNING',
        }, clear=True):
            with mock.patch('bases.P2P.logging.getLogger') as getRootLogger:
                getRootLogger.return_value.isEnabledFor.return_value = True
                P2PConfiguration._enableNativeDebugLogging()

            self.assertEqual(os.environ['FFL_P2P_NATIVE_LOGGING_LEVEL'], 'WARNING')

    def testP2PConfigurationUsesSharedSTUNSettings(self):
        """Native P2P must use Settings' STUN list, not a second hard-coded list."""
        with mock.patch('bases.P2P.SettingsGetter.getInstance') as getSettings:
            getSettings.return_value.getSTUNServerURLs.return_value = [
                'stun:primary.example.test:3478',
                'stun:secondary.example.test:3478',
            ]

            configuration = P2PConfiguration.createICEConfiguration()

        self.assertEqual(
            [server.urls for server in configuration.iceServers],
            ['stun:primary.example.test:3478', 'stun:secondary.example.test:3478'],
        )

    def testDirectP2PDownload(self):
        shareOutput = {}
        shareLink = self._startFastFileLink(
            p2p=True,
            timeout=60,
            captureOutputIn=shareOutput,
        )
        outputPath = os.path.join(self.tempDir, 'p2p-download.bin')
        downloadOutput = {}

        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraEnvVars={
                'DISABLE_WEBRTC': 'True',
                'DISABLE_HTTP_FALLBACK': 'True',
            },
            captureOutputIn=downloadOutput,
        )

        self.assertEqual(outputPath, downloadedPath)
        self._verifyDownloadedFile(downloadedPath)
        outputText = self._updateCapturedOutput(downloadOutput)
        self.assertIn(
            'Using P2P TCP download...', outputText,
            f'Download did not use the direct P2P TCP path:\n{outputText}',
        )
        self.assertIn(
            'P2P TCP', outputText,
            f'Direct P2P TCP progress was not labelled correctly:\n{outputText}',
        )
        self.assertNotIn(
            'HTTP fallback', outputText,
            f'Direct P2P TCP progress was incorrectly labelled as fallback:\n{outputText}',
        )

    def testDirectP2PUDPQUICDownload(self):
        shareOutput = {}
        shareLink = self._startFastFileLink(
            p2p=True,
            timeout=60,
            captureOutputIn=shareOutput,
        )
        outputPath = os.path.join(self.tempDir, 'p2p-udp-quic-download.bin')
        downloadOutput = {}

        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraEnvVars={
                'DISABLE_WEBRTC': 'True',
                'DISABLE_HTTP_FALLBACK': 'True',
                'P2P_TRANSPORT_PREFERENCE': 'udp',
            },
            captureOutputIn=downloadOutput,
        )

        self.assertEqual(outputPath, downloadedPath)
        self._verifyDownloadedFile(downloadedPath)
        outputText = self._updateCapturedOutput(downloadOutput)
        self.assertIn(
            'Using P2P UDP/QUIC download...', outputText,
            f'Download did not use the direct P2P UDP/QUIC path:\n{outputText}',
        )
        shareText = self._updateCapturedOutput(shareOutput)
        self.assertIn(
            'P2P QUIC', shareText,
            f'Share side did not display P2P QUIC progress:\n{shareText}',
        )

    def testDisabledFallbackPreventsHTTPDownload(self):
        context = {
            'urlInfo': SimpleNamespace(isGenericURL=False, supportsWebRTC=True),
        }
        with mock.patch.dict(os.environ, {
            'DISABLE_WEBRTC': 'True',
            'DISABLE_HTTP_FALLBACK': 'True',
        }, clear=False):
            downloader = FFLDownloader(loggerCallback=lambda _text: None)
        try:
            with mock.patch.dict(os.environ, {
                'DISABLE_WEBRTC': 'True',
                'DISABLE_HTTP_FALLBACK': 'True',
            }, clear=False), \
                 mock.patch('bases.P2P.isP2PAvailable', return_value=False), \
                 mock.patch.object(downloader, '_resolveDownloadContext', return_value=context), \
                 mock.patch.object(downloader, '_downloadViaHTTP') as httpDownload:
                with self.assertRaisesRegex(RuntimeError, 'HTTP fallback disabled'):
                    downloader.downloadFile('http://example.test/share', outputPath='output.bin')
                    
                httpDownload.assert_not_called()
        finally:
            downloader.close()


if __name__ == '__main__':
    unittest.main()
