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

import hashlib
import os
import secrets
import threading
import time

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from bases.Auth import RecipientAuth
from bases.Kernel import getLogger

logger = getLogger(__name__)


class ShareStatus(IntEnum):
    CREATING = 1
    ONLINE = 2
    COMPLETED = 3
    STOPPED = 4
    CRASHED = 5


class AuthRateLimiter:
    """Brute-force protection for all credential verification (pickup code, pubkey, email OTP).

    Tracks failure counts per credential type independently so that failures in one
    type do not consume the budget of another (e.g. 2 pickup failures + 3 OTP failures
    locks neither). Each type gets its own MAX_FAILURES budget and lockout timer.

    Locks for LOCKOUT_DURATION seconds after MAX_FAILURES consecutive failures of the same type.
    Resets on a successful verification of that type. Tracks globally per server instance.
    """

    MAX_FAILURES = 5
    LOCKOUT_DURATION = 300 # 5 minutes

    def __init__(self):
        self._state = {} # authType -> {'failures': int, 'lockedUntil': float}
        self._lock = threading.Lock()

    def _stateFor(self, authType: str) -> dict:
        """Return (creating if needed) the state dict for authType. Must be called under lock."""
        if authType not in self._state:
            self._state[authType] = {'failures': 0, 'lockedUntil': 0.0}
        return self._state[authType]

    def isLocked(self, authType: str) -> bool:
        with self._lock:
            return time.time() < self._stateFor(authType)['lockedUntil']

    def recordFailure(self, authType: str):
        with self._lock:
            state = self._stateFor(authType)
            state['failures'] += 1
            if state['failures'] >= self.MAX_FAILURES:
                state['lockedUntil'] = time.time() + self.LOCKOUT_DURATION
                state['failures'] = 0

    def recordSuccess(self, authType: str):
        with self._lock:
            self._state[authType] = {'failures': 0, 'lockedUntil': 0.0}


class DownloadSessionStore:
    """Thread-safe in-memory store for download session cookies.

    Lifecycle:
    - POST /auth exchanges X-FFL-* credentials for a session cookie (dlk).
    - Once claimed, the credentials cannot be used again to create a new session.
    - The existing session cookie (dlk) remains valid until expiry and supports Range requests.
    """

    SESSION_TTL = 600 # seconds

    def __init__(self):
        self._sessions = {} # dlk_hash -> expires_at
        self._claimed = False
        self._lock = threading.Lock()

    def create(self) -> str:
        """Generate and store a new session token. Raises RuntimeError if already claimed."""
        with self._lock:
            if self._claimed:
                raise RuntimeError("Download session already claimed")

            dlk = secrets.token_urlsafe(32)
            dlkHash = hashlib.sha256(dlk.encode()).hexdigest()
            self._sessions[dlkHash] = time.time() + self.SESSION_TTL
            self._claimed = True
            return dlk

    def validate(self, dlk: str) -> bool:
        """Return True if dlk is a valid, unexpired session token."""
        dlkHash = hashlib.sha256(dlk.encode()).hexdigest()
        with self._lock:
            expiresAt = self._sessions.get(dlkHash)
            if expiresAt is None:
                return False

            if time.time() > expiresAt:
                del self._sessions[dlkHash]
                return False

            return True


class DownloadRecordStore:
    """Thread-safe downloadId keyed record store.

    Subclasses own the record schema and behavior; this base only centralizes
    the shared lock/map lifecycle.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._downloads = {}

    def _putRecord(self, downloadId, record):
        with self._lock:
            self._downloads[downloadId] = record

    def unregister(self, downloadId):
        with self._lock:
            self._downloads.pop(downloadId, None)


class DownloadProgressStore(DownloadRecordStore):
    """Thread-safe per-download progress tracker for server-side stall detection.

    Each active HTTP download registers here.  The /status poll checks for
    downloads that have stopped making progress and reports them to /diagnosis
    via the public tunnel URL so the relay can also log the event.
    """

    STALL_THRESHOLD_SECONDS = int(os.getenv('STALL_DETECTION_SECONDS', '60'))

    def register(self, downloadId, total):
        now = time.time()
        self._putRecord(
            downloadId, {
                'downloadId': downloadId,
                'written': 0,
                'total': total,
                'lastUpdateTime': now,
                'startTime': now,
                'stallReported': False,
            }
        )

    def update(self, downloadId, written):
        with self._lock:
            entry = self._downloads.get(downloadId)
            if entry:
                entry['written'] = written
                entry['lastUpdateTime'] = time.time()
                entry['stallReported'] = False # reset on any progress

    def getStalledDownloads(self):
        """Return snapshots of downloads with no progress for STALL_THRESHOLD_SECONDS."""
        now = time.time()
        stalled = []
        with self._lock:
            for entry in self._downloads.values():
                if not entry['stallReported']:
                    if now - entry['lastUpdateTime'] >= self.STALL_THRESHOLD_SECONDS:
                        stalled.append(dict(entry))

        return stalled

    def markStallReported(self, downloadId):
        with self._lock:
            entry = self._downloads.get(downloadId)
            if entry:
                entry['stallReported'] = True


class HTTPDownloadCompletionStore(DownloadRecordStore):
    """Thread-safe ACK tracker for HTTP relay download completion.

    The browser may legitimately send duplicate POST /complete requests when we
    add a Service Worker-side ACK as a reliability backstop while keeping the
    existing page-side ACK path. The server should treat the first ACK as the
    authoritative completion signal and quietly ignore duplicates.
    """

    def register(self, downloadId):
        self._putRecord(downloadId, {
            'event': threading.Event(),
            'acknowledged': False,
        })

    def wait(self, downloadId, timeout):
        with self._lock:
            entry = self._downloads.get(downloadId)
            event = entry['event'] if entry else None

        if not event:
            return False

        return event.wait(timeout=timeout)

    def acknowledge(self, downloadId):
        """Mark downloadId as acknowledged.

        Returns:
            str: One of:
                - 'accepted': first valid ACK for this downloadId
                - 'duplicate': ACK already processed earlier
                - 'unknown': downloadId is not being tracked
        """
        with self._lock:
            entry = self._downloads.get(downloadId)
            if not entry:
                return 'unknown'

            if entry['acknowledged']:
                return 'duplicate'

            entry['acknowledged'] = True
            entry['event'].set()
            return 'accepted'


@dataclass
class LogicalDownloadRequest:
    logicalDl: str
    requestId: str
    rangeStart: int
    rangeEnd: Optional[int]
    startedAt: float
    superseded: bool = False


class LogicalDownloadRequestStore:
    """Track active logical download requests and supersede overlapping older ones.

    Browser/native retry behaviour may open a new /download request using the same
    logical dl identifier before the earlier request has fully drained. We keep
    the newer request and mark overlapping older ones as superseded so they can
    stop sending duplicate data at the next safe checkpoint.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._requests = {} # logicalDl -> requestId -> LogicalDownloadRequest

    def _getRequestsFor(self, logicalDl):
        if logicalDl not in self._requests:
            self._requests[logicalDl] = {}

        return self._requests[logicalDl]

    @staticmethod
    def _rangesOverlap(start1, end1, start2, end2):
        normalizedEnd1 = float('inf') if end1 is None else end1
        normalizedEnd2 = float('inf') if end2 is None else end2
        return start1 <= normalizedEnd2 and start2 <= normalizedEnd1

    def register(self, logicalDl, requestId, rangeStart, rangeEnd):
        supersededRequestIds = []

        with self._lock:
            requestsForDl = self._getRequestsFor(logicalDl)
            for entry in requestsForDl.values():
                if self._rangesOverlap(rangeStart, rangeEnd, entry.rangeStart, entry.rangeEnd):
                    entry.superseded = True
                    supersededRequestIds.append(entry.requestId)

            requestsForDl[requestId] = LogicalDownloadRequest(
                logicalDl=logicalDl,
                requestId=requestId,
                rangeStart=rangeStart,
                rangeEnd=rangeEnd,
                startedAt=time.time(),
            )

        return supersededRequestIds

    def isSuperseded(self, logicalDl, requestId):
        with self._lock:
            entry = self._requests.get(logicalDl, {}).get(requestId)
            return bool(entry and entry.superseded)

    def unregister(self, logicalDl, requestId):
        with self._lock:
            requestsForDl = self._requests.get(logicalDl)
            if not requestsForDl:
                return

            requestsForDl.pop(requestId, None)
            if not requestsForDl:
                self._requests.pop(logicalDl, None)


class SupersededDownloadError(ConnectionAbortedError):
    """Raised when a newer overlapping logical download request replaces this one."""


@dataclass
class ServerConfig:
    """Configuration for Server instance"""

    maxDownloads: int = 0 # Maximum number of downloads (0 = unlimited)
    timeout: int = 0 # Server timeout in seconds (0 = no timeout)
    authUser: Optional[str] = None # HTTP Basic auth username
    authPassword: Optional[str] = None # HTTP Basic auth password
    defaultWebRTC: bool = True # Enable WebRTC support by default
    e2eeEnabled: bool = False # Enable end-to-end encryption
    torEnabled: bool = False # Tor privacy mode enabled.
    recipientAuth: Optional[RecipientAuth] = None # Recipient authentication (e.g. pickup code)
    receipt: Optional[str] = None # Receipt email(s); '' means account email
    receiptConfirm: Optional[str] = None # Receipt confirm message; '' means default message


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
        self.eventHub = None
        self.downloadCount = 0
        self.startTime = time.time()
        self.lastError = None
        self._debugUserAgentSessions = set()

    def asDict(self):
        return {
            'id': self.uid,
            'filePaths': self.filePaths,
            'status': self.status.name.lower(),
            'link': self.link,
            'createdAt': self.createdAt,
            'downloads': self.downloadCount,
            'error': self.error,
            'workerData': self.shareData,
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

    def addShare(self, filePaths, config=None):
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

