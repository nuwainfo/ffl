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
"""Peewee models owned by the optional Database addon."""

from datetime import datetime

from peewee import AutoField, CharField, DatabaseProxy, DateTimeField, ForeignKeyField, IntegerField, Model, TextField

from bases.Kernel import UIDGenerator


databaseProxy = DatabaseProxy()


class DatabaseModel(Model):
    
    class Meta:
        database = databaseProxy

    @staticmethod
    def _decodeFieldValue(field, value):
        if isinstance(field, DateTimeField) and isinstance(value, str):
            return datetime.fromisoformat(value)

        return value

    def toDict(self):
        return {
            fieldName: self._decodeFieldValue(self._meta.fields[fieldName], value)
            for fieldName, value in self.__data__.items()
        }


class SchemaMigration(DatabaseModel):
    version = IntegerField(primary_key=True)
    appliedAt = DateTimeField()

    class Meta:
        table_name = 'SchemaMigrations'


class Share(DatabaseModel):
    id = AutoField()
    uid = CharField(max_length=UIDGenerator.UID_LEN, unique=True, index=True)
    name = CharField(max_length=255)
    fileSize = IntegerField()
    shareMode = CharField(max_length=16)
    status = IntegerField()
    link = CharField(max_length=2048, null=True)
    downloadCount = IntegerField(default=0)
    createdAt = DateTimeField()
    startedAt = DateTimeField(null=True)
    availableAt = DateTimeField(null=True)
    completedAt = DateTimeField(null=True)
    stoppedAt = DateTimeField(null=True)
    failedAt = DateTimeField(null=True)
    failureMessage = TextField(null=True)
    updatedAt = DateTimeField()

    class Meta:
        table_name = 'Shares'


class ShareEvent(DatabaseModel):
    id = AutoField()
    share = ForeignKeyField(Share, backref='events', column_name='shareId', on_delete='CASCADE')
    eventType = IntegerField()
    occurredAt = DateTimeField()
    detailsJson = TextField(null=True)

    class Meta:
        table_name = 'ShareEvents'
