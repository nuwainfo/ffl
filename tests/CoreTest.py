#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

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
