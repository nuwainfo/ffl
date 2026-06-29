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

import time

from enum import IntEnum

from bases.Kernel import getLogger

logger = getLogger(__name__)


class ShareStatus(IntEnum):
    CREATING = 1
    ONLINE = 2
    COMPLETED = 3
    STOPPED = 4
    CRASHED = 5


class ShareSession:
    """All state for one file-sharing session inside a MultiShareServer.

    The server and tunnel are shared across sessions; each session owns its
    reader, config, WebRTC manager, E2EE manager, and all download stores.
    """

    def __init__(self, uid, filePaths, createdAt, domain=None, reader=None,
                 config=None, status=None, link=None):
        self.uid = uid
        self.filePaths = filePaths
        self.createdAt = createdAt
        self.status = status or ShareStatus.CREATING
        self.link = link
        self.error = None
        self.shareData = None
        self.domain = domain
        self.reader = reader
        self.config = config
        
        # Initialized by MultiShareServer.addSession()
        self.webRTC = None
        self.e2eeManager = None
        self.checksumStore = None
        self.downloadSessionStore = None
        self.authRateLimiter = None
        self.downloadProgressStore = None
        self.logicalDownloadRequestStore = None
        self.httpDownloadCompletionStore = None
        self.downloadCount = 0
        self.startTime = time.time()
        self.lastError = None
        self._debugUserAgentSessions = set()

    def asDict(self):
        return {
            'id': self.uid,
            'file_paths': self.filePaths,
            'status': self.status.name.lower(),
            'link': self.link,
            'created_at': self.createdAt,
            'downloads': self.downloadCount,
            'error': self.error,
            'worker_data': self.shareData,
        }

    def stop(self):
        if self.webRTC:
            try:
                self.webRTC.closeWebRTC()
            except Exception as e:
                logger.debug(f"Error closing WebRTC for {self.uid}: {e}")
                
        if self.status not in (ShareStatus.COMPLETED, ShareStatus.CRASHED):
            self.status = ShareStatus.STOPPED


class ShareManager:
    """Abstract base class for managing multiple concurrent ShareSessions."""

    def addShare(self, filePaths, extraArgs=None):
        raise NotImplementedError

    def stopShare(self, uid):
        raise NotImplementedError

    def listShares(self):
        raise NotImplementedError

    def getShare(self, uid):
        raise NotImplementedError

    def pollSessions(self):
        """Periodic status update hook called by the daemon monitor thread."""
        pass

    def shutdown(self):
        raise NotImplementedError


