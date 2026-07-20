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
"""
Daemon architecture for managing multiple concurrent file shares.

Architecture (Phase 2 — in-process workers):
    ffl daemon          → DaemonServer starts InProcessShareManager
                           ↓ writes
                        daemon.json  (pid, port, token, started_at)
                           ↓ serves
                        DaemonServer (local REST API on 127.0.0.1:<random-port>)
                           ↓ manages via InProcessShareManager
                        ShareSession threads (one per share, in-process)
                           each running: Server + TunnelRunner in a daemon thread

    ffl share --background  → DaemonClient → POST /shares → daemon adds in-process session
    ffl shares list         → DaemonClient → GET  /shares → returns active shares
"""

import datetime
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser

from abc import ABC, abstractmethod
from functools import partial

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

import requests

import segno

from bases.HTTP import HTTPRequestHandlerHelper, PathResolverMixin
from bases.Hook import HookEventForwarder
from bases.I18n import _
from bases.Kernel import StorageLocator, getLogger
from bases.Kernel import FFLEvent
from bases.Runtime import MultiShareServerRuntime, SingleShareRuntime
from bases.Server import createServer
from bases.Session import ServerSession, ShareManager, UploadSession
from bases.Share import (
    ShareExecutionContext,
    ShareReporter,
    ShareRequest,
    ShareResult,
    ShareSession,
    ShareStatus,
    createShareRequest,
    generateUID,
    processSharing,
)
from bases.Settings import SettingsGetter, ShareMode
from bases.Utils import DataclassDictMixin, ProcessHelper, ProxyConfig, flushPrint, getAvailablePort

logger = getLogger(__name__)


@dataclass
class ShareRecord(DataclassDictMixin):
    """Client-side record returned from the daemon REST API."""
    id: str
    filePaths: list
    status: ShareStatus
    link: Optional[str]
    port: Optional[int]
    createdAt: str
    downloads: int
    shareResult: Optional[dict]
    shareRequest: dict

class DaemonStateFile:
    """Manages daemon.json lockfile in FFL_STORAGE_LOCATION."""

    STATE_FILENAME = 'daemon.json'

    @property
    def path(self):
        # When FFL_STORAGE_LOCATION is set (e.g. in tests), always use it directly
        # rather than letting StorageLocator fall through to the home directory,
        # which would find stale daemon.json files from previous runs.
        envStorage = os.environ.get('FFL_STORAGE_LOCATION')
        if envStorage:
            return os.path.join(envStorage, self.STATE_FILENAME)

        return StorageLocator.getInstance().findStorage(self.STATE_FILENAME)

    def save(self, port: int, token: str, pid: int):
        path = self.path

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(
                {
                    'pid': pid,
                    'port': port,
                    'token': token,
                    'startedAt': datetime.datetime.now().isoformat()
                },
                f,
                indent=2,
            )

    def load(self) -> Optional[dict]:
        path = self.path
        if not os.path.exists(path):
            return None

        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.info(f"Daemon state file disappeared while loading {path}")
            return None
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read daemon state file {path}: {e}")
            return None

    def clear(self):
        path = self.path

        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError as e:
                logger.warning(f"Failed to remove daemon state file: {e}")

    def isRunning(self) -> bool:
        state = self.load()
        if not state:
            return False

        pid = state.get('pid')
        if not pid:
            return False

        return ProcessHelper.isAlive(pid)


class DaemonSharedRuntime(MultiShareServerRuntime):

    def __init__(self):
        self._lock = threading.RLock()
        self._server = None
        self._serverThread = None
        self._tunnelRunner = None
        self._domain = None
        self._tunnelLink = None
        self._port = None
        self._proxyConfig = None
        self._fallbackRuntime = SingleShareRuntime()

    def _canReuseInfrastructure(self, proxyConfig):
        return (
            self._server is not None and self._serverThread is not None and self._serverThread.is_alive() and
            self._proxyConfig == proxyConfig
        )

    def _startSharedInfrastructure(self, size, session, context):
        self.shutdown()

        port = getAvailablePort(None)
        tunnelRunner = self.createTunnel(size, context)
        domain, tunnelLink = self.startTunnel(tunnelRunner, port, context)

        session.port = port
        session.domain = domain
        server = createServer(session, autoShutdown=False)

        serverThread = threading.Thread(target=server.serve_forever, daemon=True, name='daemon-shared-server')
        serverThread.start()

        self._server = server
        self._serverThread = serverThread
        self._tunnelRunner = tunnelRunner

        self._domain = domain
        self._tunnelLink = tunnelLink
        self._port = session.port
        self._proxyConfig = context.proxyConfig

    def runServerShare(self, args, context, *, reader, size, uid, torDetected, uploadProcessor):

        if uploadProcessor:
            # Pull upload needs its own local server. SingleShareRuntime replaces
            # context.session with ServerSession while this daemon keeps its
            # UploadSession lifecycle record in _sessions.
            return self._fallbackRuntime.runServerShare(
                args,
                context,
                reader=reader,
                size=size,
                uid=uid,
                torDetected=torDetected,
                uploadProcessor=uploadProcessor
            )

        reporter = context.reporter
        output = reporter.output
        exitCode, session = self.prepareServerSession(
            args, context, reader=reader, uid=uid, link='', torDetected=torDetected, uploadProcessor=uploadProcessor
        )
        if session is None:
            return exitCode

        recipientAuth = session.config.recipientAuth
        authUser = session.config.authUser
        authPassword = session.config.authPassword

        with self._lock:
            if not self._canReuseInfrastructure(context.proxyConfig):
                self._startSharedInfrastructure(size=size, session=session, context=context)
            else:
                session.port = self._port
                session.domain = self._domain
                self._server.addSession(session)

            server = self._server
            tunnelLink = self._tunnelLink
            context.session = session

        reporter.notifyServerCreated(server, uid=uid)
        self.outputAuthenticationInfo(reporter, authPassword, authUser, recipientAuth)

        link = f"{tunnelLink}{uid}"
        shareResult = self.emitP2PShareLink(
            args,
            context,
            uid=uid,
            link=link,
            reader=reader,
            size=size,
            tunnelType=self._tunnelRunner.getTunnelType(),
            recipientAuth=recipientAuth
        )
        session.link = link
        session.status = ShareStatus.ONLINE

        if output and self._serverThread and not self._serverThread.is_alive():
            raise RuntimeError('Daemon shared server thread is not running')

        return 0

    def shutdown(self):
        with self._lock:
            server = self._server
            serverThread = self._serverThread
            tunnelRunner = self._tunnelRunner

            self._server = None
            self._serverThread = None
            self._tunnelRunner = None
            self._domain = None
            self._tunnelLink = None
            self._port = None
            self._proxyConfig = None

        if server:
            try:
                server.shutdown()
                server.server_close()
            except Exception as e:
                logger.debug(f"Failed to shut down shared daemon server: {e}")

        if serverThread and serverThread.is_alive():
            serverThread.join(timeout=5)

        if tunnelRunner:
            try:
                tunnelRunner.stop()
            except Exception as e:
                logger.debug(f"Failed to stop shared daemon tunnel: {e}")


class InProcessShareManager(ShareManager):
    """Manage daemon-owned share workers while reusing the canonical Share.py flow."""

    @dataclass
    class ShareWorker:
        session: ShareSession
        shareRequest: ShareRequest
        context: ShareExecutionContext
        result: Optional[ShareResult] = None
        encryptionKey: Optional[str] = None
        server: Any = None
        vfsServer: Any = None
        exitCode: Optional[int] = None
        thread: Optional[threading.Thread] = None
        doneEvent: threading.Event = field(default_factory=threading.Event)
        messages: list = field(default_factory=list)

    def __init__(self):
        self._settingsGetter = SettingsGetter.getInstance()
        self._featureManager = self._settingsGetter.getFeatureManager()
        self._runtime = DaemonSharedRuntime()
        self._sessions = {}
        self._workers = {}
        self._lock = threading.Lock()

    def addShare(self, filePaths, config, proxyConfig=None):
        normalizedFile = filePaths[0] if len(filePaths) == 1 else filePaths
        uid = config.get('uid') or generateUID(self._featureManager)

        shareRequest = createShareRequest(config, file=normalizedFile, uid=uid)
        sessionClass = UploadSession if shareRequest.upload else ServerSession
        session = sessionClass(id=uid, filePaths=filePaths, createdAt=datetime.datetime.now().isoformat())

        reporter = ShareReporter(
            outputCallback=partial(self._handleOutput, uid),
            exceptionCallback=partial(self._handleException, uid),
            shareLinkCallback=self._handleShareLinkCreated,
            encryptionKeyCallback=partial(self._handleEncryptionKeyAvailable, uid),
            serverCreatedCallback=lambda server,
            uid=None: self._handleServerCreated(uid or session.uid, server),
            vfsServerCreatedCallback=lambda vfsServer,
            link=None,
            uid=None: self._handleVFSCreated(uid or session.uid, vfsServer, link),
        )
        context = ShareExecutionContext(
            reporter=reporter,
            runtime=self._runtime,
            session=session,
            allowUserInteraction=False,
            proxyConfig=proxyConfig,
        )
        worker = self.ShareWorker(session=session, shareRequest=shareRequest, context=context)

        with self._lock:
            self._sessions[uid] = session
            self._workers[uid] = worker

        worker.thread = threading.Thread(
            target=self._runShareWorker, args=(worker,), daemon=True, name=f'daemon-share-{uid}'
        )
        worker.thread.start()

        return session

    def _runShareWorker(self, worker):
        try:
            worker.exitCode = processSharing(worker.shareRequest, worker.context)
        except Exception as e:
            logger.exception(f"Share worker {worker.session.uid} crashed: {e}")
            worker.exitCode = 1

            with self._lock:
                session = worker.session
                if session.status not in (ShareStatus.STOPPED, ShareStatus.COMPLETED):
                    session.status = ShareStatus.CRASHED
                    session.error = str(e)
        finally:
            with self._lock:
                session = worker.session
                if session.status not in (ShareStatus.STOPPED, ShareStatus.CRASHED):
                    if worker.exitCode == 0:
                        if (
                            session.status == ShareStatus.ONLINE and worker.result and
                            worker.result.uploadMode == ShareMode.P2P
                        ):
                            pass
                        else:
                            session.status = ShareStatus.COMPLETED if session.link else ShareStatus.STOPPED
                    else:
                        session.status = ShareStatus.CRASHED
                        if not session.error:
                            session.error = _('Share worker exited with code {exitCode}').format(
                                exitCode=worker.exitCode
                            )

            worker.doneEvent.set()

    def _handleOutput(self, uid, text):
        message = (text or '').strip()
        if not message:
            return

        logger.info(f"[daemon share {uid}] {message}")
        with self._lock:
            worker = self._workers.get(uid)
            if worker:
                worker.messages.append(message)

    def _handleEncryptionKeyAvailable(self, uid, encryptionKey):
        with self._lock:
            self._workers[uid].encryptionKey = encryptionKey

    def _handleException(self, uid, e, action=None, errorPrefix="Oops, something went wrong"):
        parts = []

        if errorPrefix and e:
            parts.append(f'{errorPrefix}: {e}')
        elif e:
            parts.append(str(e))
        elif errorPrefix:
            parts.append(str(errorPrefix))
        else:
            pass

        if action:
            parts.append(str(action))

        message = '\n'.join(parts) if parts else None

        with self._lock:
            session = self._sessions.get(uid)
            worker = self._workers.get(uid)
            if session and message and not session.error:
                session.error = message

            if worker and message:
                worker.messages.append(message)

        if e:
            logger.exception(e)
        elif message:
            logger.error(message)
        else:
            pass

    def _handleServerCreated(self, uid, server):
        with self._lock:
            worker = self._workers.get(uid)
            session = self._sessions.get(uid)
            serverSession = server.getSession(uid)

            if serverSession and session:
                if isinstance(session, UploadSession):
                    session.port = session.port or serverSession.port
                else:
                    serverSession.createdAt = session.createdAt
                    serverSession.status = session.status
                    serverSession.link = session.link
                    serverSession.port = session.port or serverSession.port
                    serverSession.downloads = session.downloads
                    serverSession.error = session.error

                    self._sessions[uid] = serverSession
                    session = serverSession

            if worker:
                worker.server = server
                if serverSession:
                    worker.session = serverSession
                    worker.context.session = serverSession

            stopRequested = session.status == ShareStatus.STOPPED if session else False

        if stopRequested:
            try:
                server.removeSession(uid)
            except Exception as e:
                logger.debug(f"Failed to stop server for {uid}: {e}")

    def _handleVFSCreated(self, uid, vfsServer, link):
        with self._lock:
            worker = self._workers.get(uid)
            session = self._sessions.get(uid)
            if worker:
                worker.vfsServer = vfsServer

            stopRequested = session.status == ShareStatus.STOPPED if session else False

        if stopRequested:
            try:
                vfsServer.stop()
            except Exception as e:
                logger.debug(f"Failed to stop VFS server for {uid}: {e}")

    def _handleShareLinkCreated(self, shareResult, uid=None, reader=None):
        with self._lock:
            session = self._sessions.get(uid)
            worker = self._workers.get(uid)
            if session is None:
                return

            session.link = shareResult.link
            worker.result = shareResult

            if not worker or not worker.context.isStopRequested():
                session.status = ShareStatus.ONLINE

        logger.info(f"Share {uid} link ready: {shareResult.link}")

    def pollSessions(self):
        pass

    def stopShare(self, uid):
        with self._lock:
            session = self._sessions.get(uid)
            worker = self._workers.get(uid)

            if session is None:
                return False

            session.status = ShareStatus.STOPPED
            if worker:
                worker.context.stopEvent.set()

            link = session.link
            downloads = session.downloadCount
            filePaths = list(session.filePaths)
            shareResult = worker.result

        if worker and worker.server:
            try:
                worker.server.removeSession(uid)
            except Exception as e:
                logger.debug(f"Error stopping share server {uid}: {e}")
        elif worker and worker.vfsServer:
            try:
                worker.vfsServer.stop()
            except Exception as e:
                logger.debug(f"Error stopping VFS share {uid}: {e}")
        else:
            session.stop()

        FFLEvent.shareStopped.trigger(
            uid=uid,
            status=ShareStatus.STOPPED,
            link=link,
            downloads=downloads,
            filePaths=filePaths,
            shareResult=shareResult,
        )
        return True

    def listShares(self):
        with self._lock:
            return [session for session in self._sessions.values() if self._shouldExposeSession(session)]

    def getShare(self, uid):
        with self._lock:
            return self._sessions.get(uid)

    def _shouldExposeSession(self, session):
        if session.status in (ShareStatus.STOPPED, ShareStatus.CRASHED):
            return False

        if session.status != ShareStatus.COMPLETED:
            return True

        worker = self._workers[session.uid]
        return worker.result and worker.result.uploadMode == ShareMode.SERVER and bool(session.link)

    def getShareResult(self, uid):
        with self._lock:
            return self._workers[uid].result

    def getEncryptionKey(self, uid):
        with self._lock:
            return self._workers[uid].encryptionKey

    def getShareRequest(self, uid):
        with self._lock:
            return self._workers[uid].shareRequest

    def shutdown(self):
        with self._lock:
            shareIds = list(self._sessions.keys())

        for uid in shareIds:
            self.stopShare(uid)

        self._runtime.shutdown()


class DaemonAPIHandler(PathResolverMixin, HTTPRequestHandlerHelper, BaseHTTPRequestHandler):
    """Handles local REST API requests for the daemon."""

    def __init__(self, *args, **kwargs):
        self.mapGETRoute('/shares', self._handleListShares)
        self.mapGETRoute(re.compile(r'^/shares/(?P<shareId>.+)$'), self._handleGetShare)

        self.mapPOSTRoute('/hook', self._handleSetHook)
        self.mapPOSTRoute('/shares', self._handleCreateShare)
        self.mapPOSTRoute('/shutdown', self._handleShutdown)
        self.mapPOSTRoute(re.compile(r'^/shares/(?P<shareId>.+)/stop$'), self._handleStopShare)

        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        logger.debug(f"DaemonAPI: {format % args}")

    def _requireAuth(self) -> bool:
        token = self.headers.get('X-Daemon-Token', '')
        if token != self.server.token:
            self._sendJSON(403, {'error': 'forbidden'})
            return False

        return True

    def do_GET(self):
        path = self.path.rstrip('/')

        if path == '/health':
            self._handleHealth()
            return

        if not self._requireAuth():
            return

        handler = self._resolveGETHandler(path)
        if handler:
            handler()
            return

        self._sendJSON(404, {'error': 'not found'})

    def do_POST(self):
        path = self.path.rstrip('/')

        if not self._requireAuth():
            return

        handler = self._resolvePOSTHandler(path)
        if handler:
            handler()
            return

        self._sendJSON(404, {'error': 'not found'})

    def _handleHealth(self):
        self._sendJSON(200, {'status': 'ok', 'pid': os.getpid()})

    def _handleListShares(self):
        sessions = self.server.shareManager.listShares()
        self._sendJSON(200, {'shares': [self._getShareData(session) for session in sessions]})

    def _handleGetShare(self, shareId):
        session = self.server.shareManager.getShare(shareId)
        if session is None:
            self._sendJSON(404, {'error': 'not found'})
            return

        self._sendJSON(200, self._getShareData(session))

    def _getShareData(self, session):
        shareData = session.toDict()
        shareResult = self.server.shareManager.getShareResult(session.uid)
        if shareResult:
            shareData['shareResult'] = shareResult.toDict()
            encryptionKey = self.server.shareManager.getEncryptionKey(session.uid)
            if encryptionKey:
                shareData['shareResult']['encryptionKey'] = encryptionKey
        else:
            shareData['shareResult'] = None
            
        shareData['shareRequest'] = self.server.shareManager.getShareRequest(session.uid).toDict()
        
        return shareData

    def _handleCreateShare(self):
        data = self._readJSONBody()
        filePaths = data['filePaths']
        config = data['config']
        proxyConfig = data.get('proxyConfig')

        session = self.server.shareManager.addShare(filePaths, config, proxyConfig=proxyConfig)
        self._sendJSON(201, self._getShareData(session))

    def _handleSetHook(self):
        data = self._readJSONBody()
        hookURL = data.get('hook') or ''

        if not isinstance(hookURL, str):
            self._sendJSON(400, {'error': 'invalid hook'})
            return

        self.server.setHook(hookURL.strip())
        self._sendJSON(200, {'ok': True})

    def _handleStopShare(self, shareId):
        success = self.server.shareManager.stopShare(shareId)
        if not success:
            self._sendJSON(404, {'error': 'not found'})
            return

        self._sendJSON(200, {'ok': True})

    def _handleShutdown(self):
        self._sendJSON(200, {'ok': True})
        threading.Thread(target=self.server.stop, daemon=True).start()


class DaemonServer(ThreadingHTTPServer):
    """Local HTTP server that exposes the daemon REST API and manages in-process share sessions."""

    MONITOR_INTERVAL = 1.0

    def __init__(self):
        super().__init__(('127.0.0.1', 0), DaemonAPIHandler)
        self.shareManager = InProcessShareManager()
        self.token = secrets.token_hex(16)
        self._stateFile = DaemonStateFile()
        self._hookURL = None
        self._monitorThread = None
        self._running = False

    def start(self):
        self._running = True
        port = self.server_address[1]

        self._stateFile.save(port, self.token, os.getpid())

        self._monitorThread = threading.Thread(target=self._monitorLoop, daemon=True, name='daemon-monitor')
        self._monitorThread.start()

        flushPrint(_('Daemon started (PID: {pid}, port: {port})').format(pid=os.getpid(), port=port))
        logger.info(f"Daemon API listening on port {port}")

        try:
            self.serve_forever()
        finally:
            self._cleanup()

    def _monitorLoop(self):
        while self._running:
            try:
                self.shareManager.pollSessions()
            except Exception as e:
                logger.warning(f"Monitor loop error: {e}")

            time.sleep(self.MONITOR_INTERVAL)

    def stop(self):
        if not self._running:
            return

        self._running = False
        self.shareManager.shutdown()
        self._stateFile.clear()

        threading.Thread(target=self.shutdown, daemon=True).start()

    def setHook(self, hookURL: str):
        self._hookURL = hookURL or None
        hookEventForwarder = HookEventForwarder.getInstance()
        hookEventForwarder.configure(self._hookURL)

    def _cleanup(self):
        if self._hookURL:
            hookEventForwarder = HookEventForwarder.getInstance()
            hookEventForwarder.clear()

        self._stateFile.clear()


class DaemonClient:
    """HTTP client that reads daemon.json and calls the daemon REST API."""

    HEALTH_TIMEOUT = 3
    API_TIMEOUT = 10
    STATUS_POLL_INTERVAL = 0.5
    CREATE_SHARE_TIMEOUT = 120

    def __init__(self):
        self._stateFile = DaemonStateFile()

    @property
    def _state(self) -> dict:
        state = self._stateFile.load()
        if not state:
            raise RuntimeError(_('Daemon is not running'))

        return state

    def buildURL(self, path: str) -> str:
        return f"http://127.0.0.1:{self._state['port']}{path}"

    @property
    def _headers(self) -> dict:
        return {'X-Daemon-Token': self._state['token'], 'Content-Type': 'application/json'}

    @classmethod
    def isRunning(cls) -> bool:
        stateFile = DaemonStateFile()
        if not stateFile.isRunning():
            return False

        state = stateFile.load()
        if not state:
            return False

        try:
            response = requests.get(f"http://127.0.0.1:{state['port']}/health", timeout=cls.HEALTH_TIMEOUT)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Daemon health check failed: {e}")
            return False

    def createShare(self, filePaths, config, proxyConfig=None) -> ShareRecord:
        data = {'filePaths': filePaths, 'config': config, 'proxyConfig': proxyConfig}
        response = requests.post(self.buildURL('/shares'), json=data, headers=self._headers, timeout=self.API_TIMEOUT)
        response.raise_for_status()

        return self._parseRecord(response.json())

    def waitForLink(self, shareId: str, timeout: float = CREATE_SHARE_TIMEOUT) -> Optional[dict]:
        """Poll GET /shares/{id} until link is available, then return the full share dict."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            response = requests.get(
                self.buildURL(f'/shares/{shareId}'),
                headers=self._headers,
                timeout=self.API_TIMEOUT,
            )
            if response.status_code != 200:
                return None

            shareData = response.json()
            status = DaemonClient._parseShareStatus(shareData['status'])
            if shareData['link'] and status in (ShareStatus.ONLINE, ShareStatus.COMPLETED):
                return shareData

            if status in (ShareStatus.CRASHED, ShareStatus.STOPPED):
                return None

            time.sleep(self.STATUS_POLL_INTERVAL)

        return None

    def listShares(self) -> list:
        response = requests.get(self.buildURL('/shares'), headers=self._headers, timeout=self.API_TIMEOUT)
        response.raise_for_status()

        return response.json()['shares']

    def getShare(self, shareId: str) -> Optional[dict]:
        response = requests.get(
            self.buildURL(f'/shares/{shareId}'),
            headers=self._headers,
            timeout=self.API_TIMEOUT,
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return response.json()

    def stopShare(self, shareId: str) -> bool:
        response = requests.post(
            self.buildURL(f'/shares/{shareId}/stop'), headers=self._headers, timeout=self.API_TIMEOUT
        )
        return response.status_code == 200

    def stopDaemon(self) -> bool:
        try:
            response = requests.post(self.buildURL('/shutdown'), headers=self._headers, timeout=self.API_TIMEOUT)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Daemon shutdown request failed: {e}")
            return False

    def setHook(self, hookURL: str) -> bool:
        response = requests.post(
            self.buildURL('/hook'), json={'hook': hookURL}, headers=self._headers, timeout=self.API_TIMEOUT
        )
        return response.status_code == 200

    def _parseRecord(self, data: dict) -> ShareRecord:
        return ShareRecord(
            id=data['id'],
            filePaths=data['filePaths'],
            status=DaemonClient._parseShareStatus(data['status']),
            link=data['link'],
            port=data['port'],
            createdAt=data['createdAt'],
            downloads=data['downloads'],
            shareResult=data['shareResult'],
            shareRequest=data['shareRequest'],
        )

    @staticmethod
    def _parseShareStatus(value: str) -> ShareStatus:
        return ShareStatus[value.upper()]


class DaemonManager(ABC):
    """Starts and stops the local daemon API without knowing its host process."""

    STARTUP_TIMEOUT = 15
    POLL_INTERVAL = 0.1

    @property
    @abstractmethod
    def ownsDaemon(self):
        """Whether this manager started the daemon that is currently running."""

    @abstractmethod
    def start(self, hookURL=None):
        """Ensure the daemon API is running and return whether this manager started it."""

    @abstractmethod
    def stop(self):
        """Stop the daemon owned by this manager."""

    @classmethod
    def _waitUntil(cls, predicate, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True

            time.sleep(cls.POLL_INTERVAL)

        return False

    @classmethod
    def _waitForDaemonRunning(cls):
        return cls._waitUntil(DaemonClient.isRunning, cls.STARTUP_TIMEOUT)

    @classmethod
    def _waitForDaemonStopped(cls, timeout=10):
        return cls._waitUntil(lambda: not DaemonClient.isRunning(), timeout)

    def _setRunningDaemonHook(self, hookURL):
        if not hookURL:
            return

        if not DaemonClient().setHook(hookURL):
            raise RuntimeError(_('Failed to configure daemon event hook'))


class InProcessDaemonManager(DaemonManager):
    """Runs DaemonServer in the GUI process while preserving its REST API."""

    def __init__(self):
        self._server = None
        self._serverThread = None

    @property
    def ownsDaemon(self):
        return self._server is not None

    def start(self, hookURL=None):
        if DaemonClient.isRunning():
            self._setRunningDaemonHook(hookURL)
            return False

        self._server = DaemonServer()
        self._server.setHook(hookURL)
        
        self._serverThread = threading.Thread(
            target=self._server.start,
            daemon=True,
            name='in-process-daemon',
        )
        self._serverThread.start()

        if self._waitForDaemonRunning():
            return True

        self.stop()
        raise RuntimeError(_('Daemon failed to start within {timeout} seconds').format(timeout=self.STARTUP_TIMEOUT))

    def stop(self):
        if not self.ownsDaemon:
            return

        server = self._server
        serverThread = self._serverThread
        self._server = None
        self._serverThread = None

        server.stop()
        serverThread.join(timeout=self.STARTUP_TIMEOUT)
        server.server_close()


class ProcessDaemonManager(DaemonManager):
    """CLI-level daemon lifecycle management backed by a detached process."""

    def __init__(self):
        self._daemonPID = None

    @property
    def ownsDaemon(self):
        state = DaemonStateFile().load()
        return state is not None and state['pid'] == self._daemonPID

    def start(self, hookURL=None):
        if DaemonClient.isRunning():
            self._setRunningDaemonHook(hookURL)
            return False

        extraGlobalArgs = ['--hook', hookURL] if hookURL else []
        cmd = self._buildDaemonCommand(extraGlobalArgs=extraGlobalArgs)
        self._spawnDetachedDaemonProcess(cmd)

        if not self._waitForDaemonRunning():
            raise RuntimeError(_('Daemon failed to start within {timeout} seconds').format(timeout=self.STARTUP_TIMEOUT))

        self._daemonPID = DaemonStateFile().load()['pid']
        return True

    def stop(self):
        if not self.ownsDaemon:
            return

        if not DaemonClient().stopDaemon():
            raise RuntimeError(_('Failed to send stop command to daemon'))

        if not self._waitForDaemonStopped():
            raise RuntimeError(_('Daemon may not have stopped cleanly'))

        if not self._waitForDaemonProcessStopped():
            raise RuntimeError(_('Daemon process may not have stopped cleanly'))

    def _waitForDaemonProcessStopped(self):
        return self._waitUntil(lambda: not ProcessHelper.isAlive(self._daemonPID), self.STARTUP_TIMEOUT)

    @classmethod
    def stopRunningDaemon(cls, force=False):
        if not DaemonClient.isRunning():
            return True

        client = DaemonClient()
        if client.stopDaemon() and cls._waitForDaemonStopped():
            return True

        if force:
            cls._forceKillDaemon()
            return True

        return False

    @classmethod
    def handleCLICommand(cls, args) -> int:
        if args.daemonRunServer:
            # Internal: this branch runs inside the background subprocess spawned by _startDaemon().
            # Users never call --start directly (it is argparse.SUPPRESS); _startDaemon() passes it
            # when launching the daemon OS process so that process becomes the HTTP server loop.
            server = DaemonServer()
            server.start()
            return 0

        if args.daemonStop:
            return cls._stopDaemon(force=args.force)

        if args.daemonStatus:
            return cls._showStatus()

        # User-facing default: launch the daemon subprocess and wait for it to be ready.
        return cls._startDaemon()

    @classmethod
    def _resolveShareLink(cls, client, shareId) -> Optional[str]:
        """Look up a share's link, printing a CLI error and returning None if unavailable."""
        share = client.getShare(shareId) if shareId else None
        if not share:
            flushPrint(_('Error: Share {id} not found').format(id=shareId))
            return None

        link = share.get('link')
        if not link:
            flushPrint(_('Error: Share {id} has no link yet').format(id=shareId))
            return None

        return link

    @classmethod
    def handleSharesCLICommand(cls, args) -> int:
        sharesAction = args.sharesAction or 'list'
        shareId = getattr(args, 'id', None)
        stopAll = getattr(args, 'all', False)

        if not DaemonClient.isRunning():
            flushPrint(_('Error: Daemon is not running. Start it with: ffl daemon'))
            return 1

        client = DaemonClient()

        if sharesAction == 'list':
            shares = client.listShares()
            if not shares:
                flushPrint(_('No active shares'))
                return 0

            flushPrint(_('Active shares:'))

            for share in shares:
                link = share.get('link') or _('(no link yet)')
                flushPrint(f"  {share['id']}  {share['status']:<12}  {link}")

            return 0

        if sharesAction == 'stop':
            if stopAll:
                stopped = 0
                attempts = 0
                while attempts < 20:
                    shares = client.listShares()
                    if not shares:
                        break

                    for share in shares:
                        if client.stopShare(share['id']):
                            stopped += 1

                    time.sleep(0.1)
                    attempts += 1

                if stopped == 0:
                    flushPrint(_('No active shares'))
                    return 0

                flushPrint(_('Stopped {count} share(s)').format(count=stopped))
                return 0

            if not shareId:
                flushPrint(_('Error: Share ID required'))
                return 1

            if client.stopShare(shareId):
                flushPrint(_('Share {id} stopped').format(id=shareId))
                return 0

            flushPrint(_('Error: Share {id} not found').format(id=shareId))
            return 1

        if sharesAction == 'open':
            link = cls._resolveShareLink(client, shareId)
            if not link:
                return 1

            webbrowser.open(link)

            flushPrint(_('Opened share {id}').format(id=shareId))
            flushPrint(link)

            return 0

        if sharesAction == 'qr':
            link = cls._resolveShareLink(client, shareId)
            if not link:
                return 1

            try:
                segno.make(link).terminal(compact=True)
            except UnicodeEncodeError:
                flushPrint(_('QR code could not be rendered in this terminal encoding.'))

            flushPrint(link)
            return 0

        flushPrint(_('Unknown shares action: {action}').format(action=sharesAction))
        return 1

    @classmethod
    def handleBackgroundShare(cls, args, shareConfig: dict, proxyConfig: ProxyConfig = None) -> int:
        """Route a share to the daemon, wait for link, write JSON output, and exit."""
        if not DaemonClient.isRunning():
            if args.background:
                result = cls._startDaemon()
                if result != 0:
                    return result
            else:
                return 1

        filePaths = args.file if isinstance(args.file, list) else [args.file]

        client = DaemonClient()
        share = client.createShare(filePaths, shareConfig, proxyConfig=proxyConfig)

        flushPrint(_('Waiting for share link...'))
        shareData = client.waitForLink(share.id)

        if not shareData:
            flushPrint(_('Error: Failed to get share link from daemon'))
            return 1

        link = shareData.get('link')
        shareId = shareData.get('id')
        flushPrint(f'{link}\n')
        flushPrint(_('Share ID: {id} (managed by daemon)').format(id=shareId))

        return 0

    @classmethod
    def _startDaemon(cls) -> int:
        manager = cls()
        if DaemonClient.isRunning():
            state = DaemonStateFile().load()
            flushPrint(_('Daemon already running (PID: {pid}, port: {port})').format(
                pid=state.get('pid'), port=state.get('port')
            ))
            return 0

        try:
            manager.start()
        except Exception as e:
            flushPrint(_('Error: Failed to start daemon: {error}').format(error=e))
            return 1

        state = DaemonStateFile().load()
        flushPrint(_('Daemon started (PID: {pid}, port: {port})').format(
            pid=state['pid'], port=state['port']
        ))
        return 0

    @staticmethod
    def _spawnDetachedDaemonProcess(cmd):
        if sys.platform == 'win32':
            creationFlags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            daemonProcess = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationFlags
            )
        else:
            daemonProcess = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
            )

        daemonProcess.returncode = 0

    @staticmethod
    def _buildDaemonCommand(extraGlobalArgs=None):
        settingsGetter = SettingsGetter.getInstance()
        extraGlobalArgs = extraGlobalArgs or []

        if settingsGetter.isRunOnDevelopment():
            baseDir = settingsGetter.baseDir or os.path.normcase(
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            )
            corePath = os.path.normcase(os.path.abspath(os.path.join(baseDir, 'FFL.py')))

            if not os.path.isfile(corePath):
                raise RuntimeError(_('Unable to locate FFL.py for daemon startup.'))

            pythonExe = os.path.normcase(os.path.abspath(sys.executable))
            return [pythonExe, corePath, '--cli', *extraGlobalArgs, 'daemon', '--start']

        # EXE_PATH may refer to the outer NSIS launcher. A PyInstaller daemon
        # must run the actual executable so its CLI arguments are kept. PyApp
        # still needs its wrapper because sys.executable is an extracted Python.
        executable = sys.executable if getattr(sys, 'frozen', False) else settingsGetter.exePath
        exePath = os.path.normcase(os.path.abspath(executable))
        if not os.path.isfile(exePath):
            raise RuntimeError(_('Executable not found for daemon startup: {path}').format(path=exePath))

        return [exePath, '--cli', *extraGlobalArgs, 'daemon', '--start']

    @classmethod
    def _stopDaemon(cls, force=False) -> int:
        if not DaemonClient.isRunning():
            flushPrint(_('Daemon is not running'))
            return 0

        if cls.stopRunningDaemon(force=force):
            flushPrint(_('Daemon stopped'))
            return 0

        flushPrint(_('Warning: Daemon may not have stopped cleanly'))
        return 1

    @staticmethod
    def _forceKillDaemon() -> int:
        state = DaemonStateFile().load()
        if not state:
            return 0

        pid = state.get('pid')
        if pid:
            try:
                ProcessHelper.kill(pid)
            except Exception as e:
                logger.warning(f"Force kill daemon failed: {e}")

        DaemonStateFile().clear()
        flushPrint(_('Daemon forcefully stopped'))

        return 0

    @classmethod
    def _showStatus(cls) -> int:
        if not DaemonClient.isRunning():
            flushPrint(_('Daemon is not running'))
            return 0

        state = DaemonStateFile().load()
        flushPrint(_('Daemon is running'))
        flushPrint(_('  PID:     {pid}').format(pid=state.get('pid')))
        flushPrint(_('  Port:    {port}').format(port=state.get('port')))
        flushPrint(_('  Started: {started}').format(started=state.get('startedAt')))

        try:
            client = DaemonClient()
            shares = client.listShares()
            flushPrint(_('  Active shares: {count}').format(count=len(shares)))
        except Exception as e:
            logger.debug(f"Could not fetch active shares for status display: {e}")

        return 0
