#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
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

import os
import unittest

import tracemalloc

tracemalloc.start()

from .CoreTestBase import FastFileLinkTestBase


# ---------------------------
# Core CLI Test Class
# ---------------------------
class CoreCliTest(FastFileLinkTestBase):
    """Core test class for FastFileLink basic functionality"""

    def __init__(self, methodName='runTest'):
        # Read TEST_FILE_SIZE environment variable (in MB)
        testFileSizeMB = os.environ.get('TEST_FILE_SIZE')

        # Prepare kwargs for parent constructor
        kwargs = {}

        if testFileSizeMB:
            try:
                fileSizeBytes = int(float(testFileSizeMB) * 1024 * 1024) # Convert MB to bytes
                kwargs['fileSizeBytes'] = fileSizeBytes
                print(
                    f"[Test] Using custom file size from TEST_FILE_SIZE: {testFileSizeMB} MB ({fileSizeBytes:,} bytes)"
                )
            except (ValueError, TypeError):
                print(f"[Test] Invalid TEST_FILE_SIZE value '{testFileSizeMB}', using default file size")
                # Don't add fileSizeBytes to kwargs, let parent use its default

        # Call parent constructor with or without custom file size
        super().__init__(methodName, **kwargs)

    def _testCliWithJsonOutput(self, p2p=True):
        """Test CLI mode with JSON output using requests"""
        try:
            shareLink = self._startFastFileLink(p2p)#, output=True, showOutput=True) 
            downloadedFilePath = self._getDownloadedFilePath()

            self.downloadFileWithRequests(shareLink, downloadedFilePath)
            self._verifyDownloadedFile(downloadedFilePath)

        finally:
            self._terminateProcess()

    # Public test methods
    def testCliByP2P(self):
        """Test core CLI functionality with P2P mode"""
        self._testCliWithJsonOutput(p2p=True)

    def testCliByServer(self):
        """Test core CLI functionality with Server mode"""
        self._testCliWithJsonOutput(p2p=False)


if __name__ == '__main__':
    unittest.main()
