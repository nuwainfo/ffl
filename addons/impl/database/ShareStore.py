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
"""Share persistence boundary and SQLite implementation for the Database addon."""

import json

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Optional

from peewee import fn

from bases.Kernel import getLogger
from bases.Share import ShareStatus
from bases.Utils import DataclassDictMixin
from addons.impl.database.Models import Share, ShareEvent

logger = getLogger(__name__)


class ShareEventType(IntEnum):
    CREATED = 1
    STARTED = 2
    AVAILABLE = 3
    COMPLETED = 4
    STOPPED = 5
    FAILED = 6


@dataclass(frozen=True)
class StoredShare(DataclassDictMixin):
    id: str
    name: str
    fileSize: int
    shareMode: str
    status: ShareStatus
    link: Optional[str]
    downloadCount: int
    createdAt: datetime
    startedAt: Optional[datetime]
    availableAt: Optional[datetime]
    completedAt: Optional[datetime]
    stoppedAt: Optional[datetime]
    failedAt: Optional[datetime]
    failureMessage: Optional[str]
    updatedAt: datetime

    @classmethod
    def fromModel(cls, share):
        return cls.fromDict(
            share.toDict(),
            id=share.uid,
            status=ShareStatus(share.status),
        )

    @property
    def endedAt(self):
        return self.stoppedAt or self.failedAt or self.completedAt

class ShareStore(ABC):
    
    @abstractmethod
    def createShare(self, shareUID, name, fileSize, shareMode, occurredAt):
        raise NotImplementedError

    @abstractmethod
    def markStarted(self, shareUID, occurredAt):
        raise NotImplementedError

    @abstractmethod
    def markAvailable(self, shareUID, name, fileSize, shareMode, link, occurredAt):
        raise NotImplementedError

    @abstractmethod
    def markCompleted(self, shareUID, occurredAt):
        raise NotImplementedError

    @abstractmethod
    def markStopped(self, shareUID, occurredAt, downloadCount):
        raise NotImplementedError

    @abstractmethod
    def markFailed(self, shareUID, occurredAt, failureMessage):
        raise NotImplementedError

    @abstractmethod
    def getHistoryShare(self, shareUID):
        raise NotImplementedError

    @abstractmethod
    def listHistoryShares(self, offset, limit, sortField, descending):
        raise NotImplementedError


class SQLiteShareStore(ShareStore):
    
    _SORT_FIELDS = {
        'endedAt': fn.COALESCE(Share.stoppedAt, Share.failedAt, Share.completedAt),
        'name': Share.name,
        'id': Share.uid,
        'fileSize': Share.fileSize,
        'downloadCount': Share.downloadCount,
    }

    @staticmethod
    def _serializeDetails(details):
        return json.dumps(details, ensure_ascii=False) if details else None

    def _appendEvent(self, share, eventType, occurredAt, details=None):
        ShareEvent.create(
            share=share,
            eventType=eventType,
            occurredAt=occurredAt,
            detailsJson=self._serializeDetails(details),
        )

    @staticmethod
    def _requireShare(shareUID):
        share = Share.get_or_none(Share.uid == shareUID)
        if share is not None:
            return share

        raise RuntimeError(f'Database share is missing for {shareUID}.')

    @staticmethod
    def _isHistoryShare(share):
        return (
            share.status in (ShareStatus.STOPPED.value, ShareStatus.CRASHED.value) or
            share.status == ShareStatus.COMPLETED.value
        )

    def createShare(self, shareUID, name, fileSize, shareMode, occurredAt):
        if Share.get_or_none(Share.uid == shareUID) is not None:
            return

        with Share._meta.database.atomic():
            share = Share.create(
                uid=shareUID,
                name=name,
                fileSize=fileSize or 0,
                shareMode=shareMode,
                status=ShareStatus.CREATING.value,
                createdAt=occurredAt,
                updatedAt=occurredAt,
            )
            
            self._appendEvent(share, ShareEventType.CREATED, occurredAt)

    def markStarted(self, shareUID, occurredAt):
        self._updateShare(
            shareUID,
            ShareEventType.STARTED,
            occurredAt,
            status=ShareStatus.CREATING.value,
            startedAt=occurredAt,
        )

    def markAvailable(self, shareUID, name, fileSize, shareMode, link, occurredAt):
        self._updateShare(
            shareUID,
            ShareEventType.AVAILABLE,
            occurredAt,
            status=ShareStatus.ONLINE.value,
            name=name,
            fileSize=fileSize or 0,
            shareMode=shareMode,
            link=link,
            availableAt=occurredAt,
        )

    def markCompleted(self, shareUID, occurredAt):
        self._updateShare(
            shareUID,
            ShareEventType.COMPLETED,
            occurredAt,
            status=ShareStatus.COMPLETED.value,
            completedAt=occurredAt,
        )

    def markStopped(self, shareUID, occurredAt, downloadCount):
        self._updateShare(
            shareUID,
            ShareEventType.STOPPED,
            occurredAt,
            status=ShareStatus.STOPPED.value,
            downloadCount=downloadCount or 0,
            stoppedAt=occurredAt,
        )

    def markFailed(self, shareUID, occurredAt, failureMessage):
        self._updateShare(
            shareUID,
            ShareEventType.FAILED,
            occurredAt,
            status=ShareStatus.CRASHED.value,
            failedAt=occurredAt,
            failureMessage=failureMessage,
        )

    def getHistoryShare(self, shareUID):
        share = Share.get_or_none(Share.uid == shareUID)
        if share is None or not self._isHistoryShare(share):
            return None

        return StoredShare.fromModel(share)

    def listHistoryShares(self, offset=0, limit=None, sortField='endedAt', descending=True):
        if sortField not in self._SORT_FIELDS:
            raise ValueError(f'Unsupported share-history sort field: {sortField}')

        query = Share.select().where(
            (Share.status.in_((ShareStatus.STOPPED.value, ShareStatus.CRASHED.value))) |
            (Share.status == ShareStatus.COMPLETED.value)
        )
        orderField = self._SORT_FIELDS[sortField]
        query = query.order_by(orderField.desc() if descending else orderField.asc()).offset(offset)
        if limit is not None:
            query = query.limit(limit)

        return [StoredShare.fromModel(share) for share in query]

    def _updateShare(self, shareUID, eventType, occurredAt, **updates):
        with Share._meta.database.atomic():
            share = self._requireShare(shareUID)
            Share.update(updatedAt=occurredAt, **updates).where(Share.id == share.id).execute()
            self._appendEvent(share, eventType, occurredAt)
