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
"""Event-driven runtime for the optional local share database."""

import os

from datetime import datetime, timezone

from peewee import SqliteDatabase

from bases.Kernel import FFLEvent, Singleton, StorageLocator, getLogger

from addons.impl.database.DatabaseMigrator import DatabaseMigrator
from addons.impl.database.migrations import MIGRATIONS
from addons.impl.database.Models import databaseProxy
from addons.impl.database.ShareStore import SQLiteShareStore

logger = getLogger(__name__)


class DatabaseRuntime(Singleton):
    DATABASE_FILE_NAME = 'ffl.db'

    @classmethod
    def buildDatabasePath(cls):
        storageDirectory = StorageLocator.getInstance().ensureStorageDir()
        return os.path.join(storageDirectory, cls.DATABASE_FILE_NAME)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc)

    def initialize(self, databasePath=None):
        self._databasePath = databasePath or self.buildDatabasePath()        
        self._database = SqliteDatabase(
            self._databasePath,
            pragmas={
                'foreign_keys': 1,
                'journal_mode': 'wal',
            },
            timeout=10,
        )
        
        databaseProxy.initialize(self._database)
        DatabaseMigrator(self._database, MIGRATIONS).migrate()
        
        self._shareStore = SQLiteShareStore()

    @property
    def shareStore(self):
        return self._shareStore

    def close(self, **kwargs):
        if not self._database.is_closed():
            self._database.close()

    def subscribe(self):
        FFLEvent.shareCreated.subscribe(self._onShareCreated)
        FFLEvent.shareStarted.subscribe(self._onShareStarted)
        FFLEvent.shareAvailable.subscribe(self._onShareAvailable)
        FFLEvent.shareCompleted.subscribe(self._onShareCompleted)
        FFLEvent.shareStopped.subscribe(self._onShareStopped)
        FFLEvent.shareFailed.subscribe(self._onShareFailed)
        FFLEvent.daemonStopped.subscribe(self.close)

    def _persistEvent(self, callback, **eventData):
        try:
            callback(**eventData)
        except Exception:
            logger.exception('Unable to persist share lifecycle event')

    def _onShareCreated(self, **eventData):
        self._persistEvent(self._recordShareCreated, **eventData)

    def _onShareStarted(self, **eventData):
        self._persistEvent(self._recordShareStarted, **eventData)

    def _onShareAvailable(self, **eventData):
        self._persistEvent(self._recordShareAvailable, **eventData)

    def _onShareCompleted(self, **eventData):
        self._persistEvent(self._recordShareCompleted, **eventData)

    def _onShareStopped(self, **eventData):
        self._persistEvent(self._recordShareStopped, **eventData)

    def _onShareFailed(self, **eventData):
        self._persistEvent(self._recordShareFailed, **eventData)

    def _recordShareCreated(self, uid, name, fileSize, shareMode, occurredAt, **kwargs):
        self._shareStore.createShare(uid, name, fileSize, shareMode, occurredAt)

    def _recordShareStarted(self, uid, occurredAt=None, **kwargs):
        self._shareStore.markStarted(uid, occurredAt or self._now())

    def _recordShareAvailable(self, uid, name, fileSize, shareMode, link, occurredAt, **kwargs):
        self._shareStore.markAvailable(
            uid,
            name,
            fileSize,
            shareMode,
            link,
            occurredAt,
        )

    def _recordShareCompleted(self, uid, occurredAt=None, **kwargs):
        self._shareStore.markCompleted(uid, occurredAt or self._now())

    def _recordShareStopped(self, uid, downloads=0, occurredAt=None, **kwargs):
        self._shareStore.markStopped(uid, occurredAt or self._now(), downloads)

    def _recordShareFailed(self, uid, error, occurredAt=None, **kwargs):
        self._shareStore.markFailed(uid, occurredAt or self._now(), str(error))
