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
"""Optional local SQLite history for share lifecycle events."""

import re

from urllib.parse import parse_qs, urlsplit

from bases.Daemon import DaemonClient
from bases.Kernel import FFLEvent
from bases.Utils import flushPrint, formatSize

from addons import _
from addons.impl.database.DatabaseRuntime import DatabaseRuntime


class DatabaseDaemonClient(DaemonClient):
    
    HISTORY_PATH = '/database/shares'

    def getHistoryShare(self, shareId):
        return self.getJSON(f'{self.HISTORY_PATH}/{shareId}')['share']

    def listHistoryShares(self, offset=0, limit=None, sortField='endedAt', descending=True):
        query = f'?offset={offset}&sort={sortField}&descending={int(descending)}'
        if limit is not None:
            query += f'&limit={limit}'

        return self.getJSON(f'{self.HISTORY_PATH}{query}')['shares']


class DatabaseHistoryCLI:
    
    @staticmethod
    def _formatEndedAt(share):
        endedAt = share.endedAt
        return endedAt.astimezone().strftime('%Y-%m-%d %H:%M:%S') if endedAt else '-'

    def __init__(self, shareStore):
        self._shareStore = shareStore

    def handle(self, args):
        shares = self._shareStore.listHistoryShares(offset=0, limit=None, sortField='endedAt', descending=True)
        if not shares:
            flushPrint(_('No share history yet.'))
            return 0

        flushPrint(_('Ended\tName\tShare ID\tSize\tDownloads'))
        for share in shares:
            flushPrint(
                f'{self._formatEndedAt(share)}\t{share.name}\t{share.id}\t'
                f'{formatSize(share.fileSize)}\t{share.downloadCount}'
            )
        return 0


class DatabaseDaemonEndpoints:
    
    @staticmethod
    def _readListOptions(handler):
        queryValues = parse_qs(urlsplit(handler.path).query)
        
        offset = max(0, int(queryValues.get('offset', ['0'])[0]))
        limitText = queryValues.get('limit', [None])[0]
        limit = max(1, int(limitText)) if limitText is not None else None
        sortField = queryValues.get('sort', ['endedAt'])[0]
        descending = queryValues.get('descending', ['1'])[0] == '1'
        
        return offset, limit, sortField, descending

    def __init__(self, shareStore):
        self._shareStore = shareStore

    def register(self, handler):
        handler.mapGETRoute('/database/shares', lambda: self._handleListShares(handler))
        handler.mapGETRoute(
            re.compile(r'^/database/shares/(?P<shareId>[^/]+)$'),
            lambda shareId: self._handleGetShare(handler, shareId),
        )

    def _handleGetShare(self, handler, shareId):
        share = self._shareStore.getHistoryShare(shareId)
        if share is None:
            handler._sendJSON(404, {'error': 'not found'})
            return

        handler._sendJSON(200, {'share': share.toDict()})

    def _handleListShares(self, handler):
        offset, limit, sortField, descending = self._readListOptions(handler)
        shares = self._shareStore.listHistoryShares(offset, limit, sortField, descending)
        
        handler._sendJSON(200, {'shares': [share.toDict() for share in shares]})


def load():
    """Register persistence, daemon endpoints, and the optional CLI history command."""
    runtime = DatabaseRuntime.getInstance()
    endpointRegistrar = DatabaseDaemonEndpoints(runtime.shareStore)
    historyCLI = DatabaseHistoryCLI(runtime.shareStore)

    def registerHistoryCommand(subparsers=None, globalsParent=None, **kwargs):
        if subparsers is None:
            return

        subparsers.add_parser(
            'history',
            help=_('List local share history'),
            parents=[globalsParent] if globalsParent else [],
            exit_on_error=False,
        )

    def handleHistoryCommand(args, argPolicy, **kwargs):
        if getattr(args, 'command', None) != 'shares' or getattr(args, 'sharesAction', None) != 'history':
            return

        argPolicy['exitCode'] = historyCLI.handle(args)

    def registerDaemonEndpoints(handler, **kwargs):
        endpointRegistrar.register(handler)

    runtime.subscribe()
    
    FFLEvent.cliArgumentsSharesActionsRegister.subscribe(registerHistoryCommand)
    FFLEvent.cliArgumentsStore.subscribe(handleHistoryCommand)
    
    FFLEvent.daemonEndpointsRegister.subscribe(registerDaemonEndpoints)
