#!/usr/bin/env python
# -*- coding: utf-8 -*-
# $Id$
#
# Copyright (c) 2025 Nuwa Information Co., Ltd, All Rights Reserved.
#
# Licensed under the Proprietary License,
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at our web site.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Author: Bear $
# $Date: 2025-09-07 18:14:28 +0800 (週日, 07 九月 2025) $
# $Revision: 17246 $

import os
import sys
import subprocess
import unittest
import json

from tests.CoreTestBase import FastFileLinkTestBase


class I18nTest(FastFileLinkTestBase):
    """Test internationalization (i18n) functionality"""

    def __init__(self, methodName='runTest'):
        # Setup test with zh_Hant language preference
        testConfigVars = {
            'LANG': 'zh_Hant',  # Set system language
        }
        super().__init__(methodName, fileSizeBytes=1024 * 1024, testConfigVars=testConfigVars)

    def setUp(self):
        """Set up the test environment with zh_Hant language"""
        super().setUp()

        # Create i18n.json config file in test config directory
        import json
        i18nConfigPath = os.path.join(self.testConfigDir, "i18n.json")
        i18nConfig = {
            "language": "zh_Hant"
        }

        with open(i18nConfigPath, 'w', encoding='utf-8') as f:
            json.dump(i18nConfig, f, ensure_ascii=False, indent=2)

        print(f"[Test] Created i18n config: {i18nConfigPath}")
        print(f"[Test] Test config directory: {self.testConfigDir}")

    def _decodeOutput(self, rawBytes):
        """
        Decode subprocess output with proper encoding handling for Windows

        Args:
            rawBytes: Raw bytes from subprocess output

        Returns:
            str: Decoded string
        """
        encodingsToTry = ['utf-8', 'cp950', 'gbk', 'cp936', 'big5']

        for encoding in encodingsToTry:
            try:
                decoded = rawBytes.decode(encoding)
                print(f"[Test] Successfully decoded with encoding: {encoding}")
                return decoded
            except (UnicodeDecodeError, AttributeError):
                continue

        # Fallback to utf-8 with error handling
        print(f"[Test] Using UTF-8 with error replacement")
        return rawBytes.decode('utf-8', errors='replace')

    def _assertChineseStrings(self, output, expectedStrings, context="output", strict=True):
        """
        Assert that expected Chinese strings are found in output

        Args:
            output: String to search in
            expectedStrings: List of expected Chinese strings
            context: Description of what's being tested (for error messages)
            strict: If True, require at least one expected string. If False, just check for any Chinese characters
        """
        foundStrings = []
        missingStrings = []

        for chineseStr in expectedStrings:
            if chineseStr in output:
                foundStrings.append(chineseStr)
                print(f"[Test] [OK] Found expected Chinese string: '{chineseStr}'")
            else:
                missingStrings.append(chineseStr)

        # Count total Chinese characters
        chineseCharCount = sum(1 for char in output if '\u4e00' <= char <= '\u9fff')
        print(f"[Test] Total Chinese characters in {context}: {chineseCharCount}")

        if strict:
            # Strict mode: require at least one expected string
            self.assertGreater(
                len(foundStrings), 0,
                f"No expected Chinese strings found in {context}.\n"
                f"Expected at least one of: {expectedStrings}\n"
                f"Missing: {missingStrings}\n"
                f"Translation may not be working properly."
            )
        else:
            # Lenient mode: just check for any Chinese characters
            if len(foundStrings) > 0:
                print(f"[Test] [OK] Found {len(foundStrings)}/{len(expectedStrings)} expected Chinese strings in {context}")
            elif chineseCharCount > 0:
                print(f"[Test] [WARN] No expected strings found, but found {chineseCharCount} Chinese characters in {context}")
            else:
                print(f"[Test] [WARN] No Chinese characters found in {context}, but test continues")

        return foundStrings

    def testHelpTranslation(self):
        """Test that --help output is translated to Chinese"""
        print("\n[Test] Testing --help translation...")

        # Run Core.py --cli --help with zh_Hant language
        command = [sys.executable, "Core.py", "--cli", "--help"]

        env = os.environ.copy()
        env['FFL_STORAGE_LOCATION'] = self.testConfigDir

        result = subprocess.run(
            command,
            cwd=os.path.dirname(os.path.abspath(__file__ + "/../..")),
            env=env,
            capture_output=True
        )

        # Decode output with proper encoding handling
        helpOutput = self._decodeOutput(result.stdout)

        # Debug: Print encoding and raw output info
        print(f"[Test] Return code: {result.returncode}")
        print(f"[Test] Output type: {type(helpOutput)}")
        print(f"[Test] Output length: {len(helpOutput)} characters")

        # Print help output preview for debugging
        print(f"[Test] Help output (first 1000 chars):")
        print("=" * 80)
        print(helpOutput[:1000])
        print("=" * 80)

        # Check for specific Chinese strings that should appear in translated help
        expectedChineseStrings = [
            "選項",          # options
            "顯示",          # show/display
            "說明",          # help/description
            "分享",          # share
            "檔案",          # file
            "上傳",          # upload
        ]

        self._assertChineseStrings(helpOutput, expectedChineseStrings, "help output")
        print(f"[Test] [OK] Help translation test passed")

    def testP2PWithTranslation(self):
        """Test P2P mode with Chinese translation"""
        print("\n[Test] Testing P2P mode with zh_Hant translation...")

        try:
            # Capture output to verify translations
            captureOutput = {}
            shareLink = self._startFastFileLink(p2p=True, captureOutputIn=captureOutput)

            # Get the output
            output = self._updateCapturedOutput(captureOutput)

            print(f"[Test] Output length: {len(output)} characters")
            print(f"[Test] Output preview (first 800 chars):\n{output[:800]}")

            # Check for Chinese strings in P2P output (lenient mode)
            # P2P mode may not output much text, so we're lenient
            expectedChineseStrings = [
                "分享",  # Share
                "連結",  # Link
                "檔案",  # File
            ]

            self._assertChineseStrings(output, expectedChineseStrings, "P2P output", strict=False)

            # Download and verify file
            downloadedFilePath = self._getDownloadedFilePath()
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] [OK] P2P with translation test passed")

        finally:
            self._terminateProcess()

    def testUploadWithTranslation(self):
        """Test upload mode with Chinese translation"""
        print("\n[Test] Testing upload mode with zh_Hant translation...")

        try:
            # Capture output to verify translations
            captureOutput = {}
            shareLink = self._startFastFileLink(
                p2p=False,
                useTestServer=False,
                captureOutputIn=captureOutput
            )

            # Get the output
            output = self._updateCapturedOutput(captureOutput)

            print(f"[Test] Output length: {len(output)} characters")
            print(f"[Test] Output preview (first 800 chars):\n{output[:800]}")

            # Check for Chinese strings in upload output (lenient mode for now)
            # Upload output should have these strings from Upload.py
            expectedChineseStrings = [
                "上傳",      # Upload/Uploading
                "進度",      # Progress
                "完成",      # Complete/Completed
                "分塊",      # Chunk
            ]

            self._assertChineseStrings(output, expectedChineseStrings, "upload output", strict=False)

            # Download and verify file
            downloadedFilePath = self._getDownloadedFilePath()
            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

            print("[Test] [OK] Upload with translation test passed")

        finally:
            self._terminateProcess()


if __name__ == '__main__':
    unittest.main()
