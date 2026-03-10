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

import hashlib
import os
import unittest
from urllib.parse import urlparse

import requests

from ..CoreTestBase import FastFileLinkTestBase, LOCAL_TEST_SERVER_URL
from ..BrowserTestBase import BrowserTestBase


class ChecksumAssertionsMixin:
    def _getDownloadUrl(self, shareLink):
        return shareLink.rstrip('/') + '/download'


class ChecksumTest(ChecksumAssertionsMixin, FastFileLinkTestBase):
    """Functional tests for transfer checksum endpoint and behavior."""

    def testChecksumScriptEndpointAvailable(self):
        """Checksum script should be available as shared dependency for SW and DownloadManager."""
        shareLink = self._startFastFileLink(p2p=True)

        checksumScriptResponse = requests.get(
            shareLink.rstrip('/') + '/static/js/Checksum.js',
            timeout=30
        )
        self.assertEqual(checksumScriptResponse.status_code, 200)
        self.assertIn('FFLChecksum', checksumScriptResponse.text)
        self.assertIn('createBLAKE2b', checksumScriptResponse.text)

    def testChecksumEndpointBeforeAndAfterHttpDownload(self):
        """Checksum endpoint should be not-ready before transfer and ready after full HTTP transfer."""
        shareLink = self._startFastFileLink(p2p=True)

        beforeData = self._fetchChecksumData(shareLink, requireReady=False)
        self.assertFalse(beforeData.get('ready'), "Checksum should be unavailable before any full transfer")
        self.assertEqual(beforeData.get('algorithm'), 'blake2b')

        downloadedPath = self._getDownloadedFilePath("checksum_http.bin")
        transferChecksum = self.downloadFileWithRequests(shareLink, downloadedPath)
        self._verifyDownloadedFile(downloadedPath, shareLink=shareLink, transferChecksum=transferChecksum)

        afterData = self._fetchChecksumData(shareLink)
        self.assertTrue(afterData.get('ready'), "Checksum should be ready after full transfer")
        self.assertEqual(afterData.get('algorithm'), 'blake2b')
        self.assertEqual(afterData.get('transport'), 'http')
        self.assertEqual(afterData.get('e2ee'), False)
        self.assertEqual(afterData.get('size'), os.path.getsize(downloadedPath))

        expectedChecksum = self._calculateBlake2b(downloadedPath)
        self.assertEqual(afterData.get('checksum'), expectedChecksum)

    def testChecksumNotReadyAfterRangeDownload(self):
        """Range/partial transfer should not publish final checksum."""
        shareLink = self._startFastFileLink(p2p=True)

        partialPath = self._getDownloadedFilePath("checksum_partial.bin")
        downloadUrl = self._getDownloadUrl(shareLink)
        with requests.get(downloadUrl, headers={'Range': 'bytes=0-1023'}, stream=True, timeout=60) as response:
            self.assertEqual(response.status_code, 206, f"Expected 206, got {response.status_code}")
            self.assertIn('Content-Range', response.headers)
            with open(partialPath, 'wb') as outputFile:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        outputFile.write(chunk)

        checksumData = self._fetchChecksumData(shareLink, requireReady=False)
        self.assertFalse(checksumData.get('ready'), "Partial transfer should not mark checksum as ready")
        self.assertEqual(checksumData.get('algorithm'), 'blake2b')

    def testChecksumMatchesCiphertextWhenE2EEEnabled(self):
        """With --e2ee, checksum should represent encrypted transport bytes."""
        shareLink = self._startFastFileLink(p2p=True, extraArgs=["--e2ee"])

        ciphertextPath = self._getDownloadedFilePath("checksum_e2ee_cipher.bin")
        transferChecksum = self.downloadFileWithRequests(shareLink, ciphertextPath)
        self._verifyDownloadedFile(
            ciphertextPath,
            shareLink=shareLink,
            transferChecksum=transferChecksum,
            verifyOriginalContent=False
        )

        ciphertextSize = os.path.getsize(ciphertextPath)
        self.assertEqual(
            ciphertextSize,
            self.originalFileSize,
            "Encrypted transport payload size should match plaintext size in current E2EE mode"
        )

        with open(ciphertextPath, 'rb') as ciphertextFile:
            ciphertextHash = hashlib.sha256(ciphertextFile.read()).hexdigest()
        self.assertNotEqual(
            ciphertextHash,
            self.originalFileHash,
            "Ciphertext hash should differ from original plaintext hash"
        )

        checksumData = self._fetchChecksumData(shareLink)
        self.assertTrue(checksumData.get('ready'))
        self.assertEqual(checksumData.get('algorithm'), 'blake2b')
        self.assertEqual(checksumData.get('transport'), 'http')
        self.assertEqual(checksumData.get('e2ee'), True)

        expectedChecksum = self._calculateBlake2b(ciphertextPath)
        self.assertEqual(checksumData.get('checksum'), expectedChecksum)

    def testChecksumVerifiedByFFLDownloader(self):
        """Functional test: Core.py downloader should verify checksum after transfer."""
        shareLink = self._startFastFileLink(p2p=True)

        outputCapture = {}
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=self._getDownloadedFilePath("checksum_cli_downloader.bin"),
            captureOutputIn=outputCapture
        )
        self._verifyDownloadedFile(downloadedPath, shareLink=shareLink)

        outputText = self._updateCapturedOutput(outputCapture)
        self.assertIn("Checksum verified", outputText, "CLI downloader should report checksum verification")

        checksumData = self._fetchChecksumData(shareLink)
        self.assertTrue(checksumData.get('ready'))
        self.assertIn(checksumData.get('transport'), ('webrtc', 'http'))
        self.assertEqual(checksumData.get('size'), os.path.getsize(downloadedPath))

        expectedChecksum = self._calculateBlake2b(downloadedPath)
        self.assertEqual(checksumData.get('checksum'), expectedChecksum)

    def testUploadEndSendsChecksumAndAlgorithm(self):
        """Functional test: upload/end should include checksum metadata from uploader."""
        testServerProcess = None
        try:
            shareLink, testServerProcess = self._startFastFileLink(p2p=False, useTestServer=True)
            uid = [segment for segment in urlparse(shareLink).path.split('/') if segment][-1]

            checksumResponse = requests.get(
                f'{LOCAL_TEST_SERVER_URL}/{uid}/checksum',
                timeout=30
            )
            self.assertEqual(checksumResponse.status_code, 200)
            checksumData = checksumResponse.json()

            self.assertTrue(checksumData.get('ready'))
            self.assertEqual(checksumData.get('algorithm'), 'blake2b')
            self.assertEqual(checksumData.get('transport'), 'upload')
            self.assertTrue(checksumData.get('verified'))

            expectedChecksum = self._calculateBlake2b(self.testFilePath)
            self.assertEqual(checksumData.get('checksum'), expectedChecksum)
            self.assertEqual(checksumData.get('calculated'), expectedChecksum)
        finally:
            self._stopTestServer(testServerProcess)


class ChecksumBrowserTest(ChecksumAssertionsMixin, BrowserTestBase):
    """Browser functional test for checksum behavior (WebRTC path)."""

    def testChecksumAfterBrowserWebRTCDownloadWithChrome(self):
        outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, output=False, captureOutputIn=outputCapture)

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        try:
            downloadedPath = self._downloadWithBrowser(
                driver,
                shareLink,
                self.chromeDownloadDir,
                "testfile.bin",
                disableFallback=True
            )
            self._verifyDownloadedFile(downloadedPath, shareLink=shareLink)

            outputText = self._updateCapturedOutput(outputCapture)
            self.assertTrue(len(outputText) > 0, "Expected non-empty server output")

            checksumData = self._fetchChecksumData(shareLink)
            self.assertTrue(checksumData.get('ready'))
            self.assertEqual(checksumData.get('algorithm'), 'blake2b')
            self.assertIn(checksumData.get('transport'), ('webrtc', 'http'))
            self.assertEqual(checksumData.get('e2ee'), False)

            expectedChecksum = self._calculateBlake2b(downloadedPath)
            self.assertEqual(checksumData.get('checksum'), expectedChecksum)
            self.assertEqual(checksumData.get('size'), os.path.getsize(downloadedPath))
        finally:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == '__main__':
    unittest.main()
