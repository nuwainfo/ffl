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

import datetime
import hashlib
import threading

from dataclasses import dataclass

DEFAULT_CHECKSUM_ALGORITHM = 'blake2b'


@dataclass(frozen=True)
class ChecksumRecord:
    algorithm: str
    checksum: str
    encoding: str
    size: int
    transport: str
    e2ee: bool
    updatedAt: str


class TransferChecksumSession:
    def __init__(self, store, transport: str, e2ee: bool):
        self.store = store
        self.transport = transport
        self.e2ee = e2ee
        self.hasher = hashlib.blake2b()
        self.size = 0
        self.closed = False

    @property
    def isClosed(self):
        return self.closed

    def update(self, data: bytes):
        if self.closed:
            raise RuntimeError('Checksum session already closed')

        if not data:
            return

        self.hasher.update(data)
        self.size += len(data)

    def commit(self):
        if self.closed:
            raise RuntimeError('Checksum session already closed')

        checksum = self.hasher.hexdigest()
        record = ChecksumRecord(
            algorithm=DEFAULT_CHECKSUM_ALGORITHM,
            checksum=checksum,
            encoding='hex',
            size=self.size,
            transport=self.transport,
            e2ee=self.e2ee,
            updatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

        self.store.setLatestRecord(record)
        self.closed = True
        return record

    def abort(self):
        self.closed = True


class TransferChecksumStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.latestRecord = None

    def begin(self, transport: str, e2ee: bool = False):
        return TransferChecksumSession(self, transport=transport, e2ee=e2ee)

    def setLatestRecord(self, record: ChecksumRecord):
        with self.lock:
            self.latestRecord = record

    def getResponseData(self):
        with self.lock:
            record = self.latestRecord

        if not record:
            return {'ready': False}

        return {
            'ready': True,
            'algorithm': record.algorithm,
            'checksum': record.checksum,
            'encoding': record.encoding,
            'size': record.size,
            'transport': record.transport,
            'e2ee': record.e2ee,
            'updatedAt': record.updatedAt
        }
