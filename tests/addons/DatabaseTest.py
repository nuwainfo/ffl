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

"""End-to-end coverage for the optional Database addon."""

import json
import os
import sqlite3
import time

from addons.Database import DatabaseDaemonClient
from bases.Daemon import DaemonClient

from tests.CoreTestBase import FastFileLinkTestBase, LOCAL_TEST_SERVER_URL
from tests.bases.DaemonTest import DaemonLifecycleMixin


class DatabaseTest(DaemonLifecycleMixin, FastFileLinkTestBase):
    """Verify a real background share becomes local history through addon events."""

    DEFAULT_FILE_SIZE = 256 * 1024

    def _waitForHistoryShare(self, shareId):
        deadline = time.time() + 15
        databaseClient = DatabaseDaemonClient()
        while time.time() < deadline:
            historyShares = databaseClient.listHistoryShares(limit=20)
            matchingShares = [share for share in historyShares if share['id'] == shareId]
            if matchingShares:
                return matchingShares[0]

            time.sleep(0.2)

        self.fail(f'Share {shareId} was not recorded in Database addon history.')

    def testBackgroundShareIsPersistedAndExposedByDaemonAndCLI(self):
        shareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])
        activeShare = next(
            share for share in DaemonClient().listShares()
            if share['link'] == shareLink
        )
        shareId = activeShare['id']

        self.assertTrue(DaemonClient().stopShare(shareId))
        historyShare = self._waitForHistoryShare(shareId)

        self.assertEqual(historyShare['name'], 'testfile.bin')
        self.assertEqual(historyShare['shareMode'], 'p2p')
        self.assertEqual(historyShare['status'], 'stopped')
        self.assertEqual(historyShare['link'], shareLink)
        self.assertIsNotNone(historyShare['createdAt'])
        self.assertIsNotNone(historyShare['startedAt'])
        self.assertIsNotNone(historyShare['availableAt'])
        self.assertIsNotNone(historyShare['stoppedAt'])

        historyDetail = DatabaseDaemonClient().getHistoryShare(shareId)
        self.assertEqual(historyDetail, historyShare)
        self._waitForCoreProcessExit(timeout=30)

        secondFilePath = os.path.join(self.tempDir, 'archive-second.bin')
        self.generateRandomFile(secondFilePath, 1024)
        with self._usingTestFile(secondFilePath):
            secondShareLink = self._startFastFileLink(p2p=True, extraArgs=['--background'])

        secondShare = next(
            share for share in DaemonClient().listShares()
            if share['link'] == secondShareLink
        )
        self.assertTrue(DaemonClient().stopShare(secondShare['id']))
        self._waitForHistoryShare(secondShare['id'])

        historySharesByName = DatabaseDaemonClient().listHistoryShares(sortField='name', descending=False)
        self.assertEqual(
            [share['name'] for share in historySharesByName[:2]],
            ['archive-second.bin', 'testfile.bin'],
        )
        self.assertEqual(len(DatabaseDaemonClient().listHistoryShares(limit=1)), 1)
        self._waitForCoreProcessExit(timeout=30)

        output, returnCode = self._runPatchedCoreCommand(['--cli', 'shares', 'history'])
        self.assertEqual(returnCode, 0, output)
        self.assertIn(shareId, output)
        self.assertIn('testfile.bin', output)

        databasePath = os.path.join(self.testConfigDir, 'ffl.db')
        self.assertTrue(os.path.exists(databasePath))
        connection = sqlite3.connect(databasePath)
        try:
            tableNames = {
                row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            shareColumns = {row[1] for row in connection.execute('PRAGMA table_info(shares)')}
        finally:
            connection.close()

        self.assertTrue({'schemaMigrations', 'shares', 'shareEvents'}.issubset(tableNames))
        self.assertTrue({'createdAt', 'availableAt', 'stoppedAt', 'downloadCount'}.issubset(shareColumns))

    def testBackgroundUploadIsPersistedAfterRemoteVerification(self):
        self._stopDaemon()
        self._provisionLocalTestServerCredential()
        self._testServerProcesses.append(self._startTestServer())
        self._daemonEnvOverrides = {'FILESHARE_TEST': LOCAL_TEST_SERVER_URL}
        self._startDaemon()

        shareLink = self._startFastFileLink(p2p=False, extraArgs=['--background'])
        activeShare = next(
            share for share in DaemonClient().listShares()
            if share['link'] == shareLink
        )
        historyShare = self._waitForHistoryShare(activeShare['id'])

        self.assertEqual(historyShare['shareMode'], 'server')
        self.assertEqual(historyShare['status'], 'completed')
        self.assertEqual(historyShare['link'], shareLink)
        self.assertIsNotNone(historyShare['createdAt'])
        self.assertIsNotNone(historyShare['startedAt'])
        self.assertIsNotNone(historyShare['availableAt'])
        self.assertIsNotNone(historyShare['completedAt'])
