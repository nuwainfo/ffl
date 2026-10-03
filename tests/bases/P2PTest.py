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
import sys
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

    def testP2PQUICFallbackResumesViaHTTPAfterPartialTransfer(self):
        """A QUIC transfer that fails after writing bytes must resume over
        HTTP from that exact offset, without corrupting or duplicating the
        stdout stream.

        Regression test for P2PDownloadMixin.downloadFile(): a QUIC transfer
        failure after the direct transport was already established used to
        be terminal (no WebRTC/HTTP fallback at all), so any real-world QUIC
        instability lost the whole transfer no matter how much had already
        arrived.
        """
        failureAfterBytes = self.fileSizeBytes // 2
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        rawBytes, stderrOutput = self._downloadWithCore(
            shareLink,
            stdoutMode=True,
            extraEnvVars={
                'P2P_TRANSPORT_PREFERENCE': 'udp',
                'P2P_CLI_SIMULATE_QUIC_FAILURE': 'True',
                'P2P_CLI_QUIC_FAILURE_AFTER_BYTES': str(failureAfterBytes),
            },
        )

        outputPath = os.path.join(self.tempDir, 'p2p-quic-fallback-resume.bin')
        with open(outputPath, 'wb') as f:
            f.write(rawBytes)

        self.assertIn(
            'Using P2P UDP/QUIC download...', stderrOutput,
            f'Download did not attempt the direct P2P UDP/QUIC path first:\n{stderrOutput}',
        )
        self.assertIn(
            'HTTP fallback', stderrOutput,
            f'HTTP fallback should follow the QUIC failure:\n{stderrOutput}',
        )
        self.assertNotIn(
            'Attempting WebRTC download...', stderrOutput,
            f'Bytes were already written; only HTTP can safely resume mid-stream:\n{stderrOutput}',
        )
        self._verifyDownloadedFile(outputPath)

    def testP2PQUICFallbackResumesViaHTTPForUnknownSizeStdinStream(self):
        """A QUIC transfer that fails partway through an unknown-size share
        (stdin-streamed, exactly what Deploy.py's service-migrate path
        produces via `borg export-tar | ffl.com -`) must still resume the
        REMAINING bytes over HTTP, not stop as soon as the resume request
        reaches the offset QUIC had already delivered.

        Regression test for the HTTP fallback/resume path when
        urlInfo/fileSize is unknown (-1): it used to treat a successful
        resume response as "download complete" the instant it matched the
        already-downloaded byte count, rather than continuing to read the
        rest of the still-open stream, silently truncating the file.
        """
        failureAfterBytes = self.fileSizeBytes // 2
        shareLink = self._startFastFileLink(
            p2p=True,
            timeout=60,
            stdinInputPath=self.testFilePath,
            stdinFileName='p2p-fallback-unknown-size.bin',
        )

        rawBytes, stderrOutput = self._downloadWithCore(
            shareLink,
            stdoutMode=True,
            extraEnvVars={
                'P2P_TRANSPORT_PREFERENCE': 'udp',
                'P2P_CLI_SIMULATE_QUIC_FAILURE': 'True',
                'P2P_CLI_QUIC_FAILURE_AFTER_BYTES': str(failureAfterBytes),
            },
        )

        outputPath = os.path.join(self.tempDir, 'p2p-quic-fallback-unknown-size.bin')
        with open(outputPath, 'wb') as f:
            f.write(rawBytes)

        self.assertIn(
            'Using P2P UDP/QUIC download...', stderrOutput,
            f'Download did not attempt the direct P2P UDP/QUIC path first:\n{stderrOutput}',
        )
        self.assertIn(
            'HTTP fallback', stderrOutput,
            f'HTTP fallback should follow the QUIC failure:\n{stderrOutput}',
        )
        self._verifyDownloadedFile(outputPath)

    def testP2PQUICFallbackResumesEncryptedStdinStreamWhoseTailArrivesLate(self):
        """An end-to-end-encrypted stdin stream whose QUIC transfer fails partway,
        while the producer is still working on the rest, must resume over HTTP and
        decrypt every chunk, including the short last one.

        This is a Deploy.py service migration (`borg export-tar | ffl.com -`,
        `--e2ee --stdin-cache off`) that hit a QUIC stall: the receiver authenticated
        the first 3 chunks, the HTTP fallback resumed at chunk 3 (the short tail,
        produced only later), and failed with "decryptAESGCM failed", which left a
        truncated file.
        """
        chunkSize = 256 * 1024 # the default E2EE chunk size (the manifest's chunkSize)
        headSize = 3 * chunkSize
        sourcePath = os.path.join(self.tempDir, 'slow-producer-source.bin')
        self.generateRandomFile(sourcePath, headSize + 199089)

        # Writes the head at once, then the short tail only after a pause, as a producer that is slow
        # at the end of its output does.
        producerScript = '\n'.join([
            'import sys, time',
            'data = open(sys.argv[1], "rb").read()',
            'head = int(sys.argv[2])',
            'sys.stdout.buffer.write(data[:head]); sys.stdout.buffer.flush()',
            'time.sleep(float(sys.argv[3]))',
            'sys.stdout.buffer.write(data[head:]); sys.stdout.buffer.flush()',
        ])
        shareLink = self._startFastFileLink(
            p2p=True,
            timeout=60,
            stdinProducerArgs=[sys.executable, '-c', producerScript, sourcePath, str(headSize), '2'],
            stdinFileName='p2p-fallback-late-tail.bin',
            extraArgs=['--e2ee', '--stdin-cache', 'off', '--max-downloads', '1'],
        )

        rawBytes, stderrOutput = self._downloadWithCore(
            shareLink,
            stdoutMode=True,
            extraEnvVars={
                'P2P_TRANSPORT_PREFERENCE': 'udp',
                'P2P_CLI_SIMULATE_QUIC_FAILURE': 'True',
                'P2P_CLI_QUIC_FAILURE_AFTER_BYTES': str(headSize),
                # The transport stalls until the producer has finished, then times out, as the real one did.
                'P2P_CLI_QUIC_FAILURE_DELAY_SECONDS': '6',
            },
        )

        self.assertIn(
            'HTTP fallback', stderrOutput,
            f'HTTP fallback should follow the QUIC failure:\n{stderrOutput}',
        )
        self.assertNotIn(
            'decryptAESGCM failed', stderrOutput,
            f'The resumed chunks must decrypt like the first ones:\n{stderrOutput}',
        )
        with open(sourcePath, 'rb') as source:
            self.assertEqual(
                source.read(), rawBytes,
                f'The resumed download differs from the produced stream:\n{stderrOutput}',
            )

    def testP2PQUICFallbackFailsLoudlyPastStdinHandoffWindow(self):
        """A QUIC transfer that fails partway through an unknown-size, stdin
        -streamed share (`--stdin-cache off`, exactly what Deploy.py's
        service-migrate path produces via `borg export-tar | ffl.com -`),
        after the already-delivered prefix has aged out of the source's
        bounded in-memory handoff window (StdinHandoffWindow,
        READER_STDIN_HANDOFF_WINDOW_MB), genuinely cannot be resumed: that
        prefix is gone and stdin cannot be re-read from the start. The
        client must fail loudly with a diagnosable error on stderr.

        Regression test for two bugs that combined to make this failure mode
        silently produce a truncated file with zero diagnostic information
        instead:
        1. bases/Utils.sendException() unconditionally printed the fatal
           error via flushPrint() (stdout). In `--stdout` mode stdout *is*
           the raw file-content stream being piped into e.g. `tar xzvf -`,
           so the error text was silently interleaved into/truncating that
           binary stream instead of ever reaching stderr -- exactly what
           happened on the real Devpi migrate this regression-tests.
        2. Download.py's HTTP fallback trusted "the response stream ended"
           as "transfer complete" for unknown-size downloads, with no size
           or checksum cross-check available to catch a short read (see the
           companion tests for the cases where resume legitimately works).
        Fixing (1) turns this from an undiagnosable silent truncation into a
        loud, correctly-failing download -- which is what this test asserts.
        """
        # Use a dedicated, reliably-oversized source file rather than
        # self.testFilePath: this test needs the file to be comfortably
        # bigger than the 1 MiB handoff window regardless of whatever
        # TEST_FILE_SIZE the rest of the suite is running with.
        windowExceedingFilePath = os.path.join(self.tempDir, 'p2p-fallback-past-window-source.bin')
        windowExceedingFileSize = 8 * 1024 * 1024
        self.generateRandomFile(windowExceedingFilePath, windowExceedingFileSize)

        # Fail almost immediately (not at the file's midpoint): local-loopback
        # QUIC is fast enough to deliver an entire multi-MB file in a single
        # receive-loop pass, so a midpoint threshold can be crossed only
        # after the transfer already finished, defeating the repro. A small
        # absolute threshold guarantees a large, still-pending tail.
        failureAfterBytes = 100_000
        shareLink = self._startFastFileLink(
            p2p=True,
            timeout=60,
            stdinInputPath=windowExceedingFilePath,
            stdinFileName='p2p-fallback-past-window.bin',
            extraArgs=['--stdin-cache', 'off', '--e2ee'],
            extraEnvVars={'READER_STDIN_HANDOFF_WINDOW_MB': '1'},
        )

        with self.assertRaises(AssertionError) as failure:
            self._downloadWithCore(
                shareLink,
                stdoutMode=True,
                extraEnvVars={
                    'P2P_TRANSPORT_PREFERENCE': 'udp',
                    'P2P_CLI_SIMULATE_QUIC_FAILURE': 'True',
                    'P2P_CLI_QUIC_FAILURE_AFTER_BYTES': str(failureAfterBytes),
                },
            )

        errorText = str(failure.exception)
        self.assertIn(
            'Using P2P UDP/QUIC download...', errorText,
            f'Download did not attempt the direct P2P UDP/QUIC path first:\n{errorText}',
        )
        self.assertIn(
            'Download failed', errorText,
            f'The fatal error must reach stderr, not vanish into the stdout '
            f'data stream:\n{errorText}',
        )
        self.assertIn(
            '410', errorText,
            f'Expected the server to reject the out-of-window resume '
            f'(410 Gone), surfaced to the user:\n{errorText}',
        )

    def testP2PQUICFallbackTriesWebRTCBeforeAnyBytesWritten(self):
        """A QUIC transfer that fails before writing any bytes is as safe to
        retry as any other connection-establishment failure, so it should
        still try WebRTC before falling back to HTTP.
        """
        shareLink = self._startFastFileLink(p2p=True, timeout=60)

        rawBytes, stderrOutput = self._downloadWithCore(
            shareLink,
            stdoutMode=True,
            extraEnvVars={
                'P2P_TRANSPORT_PREFERENCE': 'udp',
                'P2P_CLI_SIMULATE_QUIC_FAILURE': 'True',
                'P2P_CLI_QUIC_FAILURE_AFTER_BYTES': '0',
            },
        )

        outputPath = os.path.join(self.tempDir, 'p2p-quic-fallback-webrtc.bin')
        with open(outputPath, 'wb') as f:
            f.write(rawBytes)

        self.assertIn(
            'Using P2P UDP/QUIC download...', stderrOutput,
            f'Download did not attempt the direct P2P UDP/QUIC path first:\n{stderrOutput}',
        )
        self.assertIn(
            'Attempting WebRTC download...', stderrOutput,
            f'No bytes were written yet, so WebRTC should be tried next:\n{stderrOutput}',
        )
        self._verifyDownloadedFile(outputPath)

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


@unittest.skipUnless(isP2PAvailable(), 'ffl-p2p extension is not available')
class P2PQUICMaxDownloadsRaceTest(FastFileLinkTestBase):
    """Regression test: the server must not tear the share session down (on
    reaching --max-downloads) before the client's own post-transfer work --
    E2EE tag fetch and checksum verification, both of which run over the
    HTTPS control plane strictly *after* the raw QUIC byte stream reports
    clean close -- has actually finished.

    This is tunnel-agnostic: it races QUICFileSender.__call__'s
    doAfterDownload() against the client's follow-up HTTPS calls regardless
    of which tunnel (bore or web) carries the control plane, so this test
    deliberately leaves --preferred-tunnel at its default rather than forcing
    either one.
    """

    def __init__(self, methodName='runTest'):
        # Small and fast enough that the raw QUIC transfer finishes near
        # instantly, maximizing the chance of losing the race pre-fix.
        super().__init__(methodName, fileSizeBytes=4096)

    def testE2EEStdinShareSurvivesMaxDownloadsShutdownRaceOverQUIC(self):
        shareOutput = {}
        shareLink = self._startFastFileLink(
            p2p=True,
            stdinInputPath=self.testFilePath,
            extraArgs=['--e2ee', '--stdin-cache', 'off', '--max-downloads', '1'],
            timeout=60,
            captureOutputIn=shareOutput,
        )

        outputPath = os.path.join(self.tempDir, 'quic-race-download.bin')
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


if __name__ == '__main__':
    unittest.main()
