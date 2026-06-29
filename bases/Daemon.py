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
import secrets
import subprocess
import sys
import threading
import time
import webbrowser

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

import requests
import segno

from bases.Kernel import getLogger, StorageLocator, UIDGenerator
from bases.Readers import SourceReader
from bases.Server import MultiShareServer, DownloadHandler, ServerConfig
from bases.Session import ShareStatus, ShareSession, ShareManager
from bases.Settings import SettingsGetter
from bases.Tunnel import TunnelRunner
from bases.Utils import flushPrint, getAvailablePort, ProcessHelper
from bases.I18n import _

logger = getLogger(__name__)



@dataclass
class ShareRecord:
    """Client-side record returned from the daemon REST API."""
    id: str
    filePaths: list
    pid: Optional[int]
    status: ShareStatus
    link: Optional[str]
    createdAt: str
    downloads: int
    workerData: Optional[dict]

    def asDict(self):
        return {
            'id': self.id,
            'file_paths': self.filePaths,
            'pid': self.pid,
            'status': self.status,
            'link': self.link,
            'created_at': self.createdAt,
            'downloads': self.downloads,
            'worker_data': self.workerData,
        }


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
            json.dump({
                'pid': pid,
                'port': port,
                'token': token,
                'started_at': datetime.datetime.now().isoformat(),
            }, f, indent=2)

    def load(self) -> Optional[dict]:
        path = self.path
        if not os.path.exists(path):
            return None
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
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


class InProcessShareManager(ShareManager):
    """Manages ShareSessions inside one MultiShareServer + one TunnelRunner.

    The first addShare() starts the HTTP server and tunnel in a background
    thread. Subsequent calls add sessions immediately if the tunnel is ready,
    or leave them in CREATING state until the tunnel thread activates them.
    """

    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()
        self._server = None
        self._tunnelRunner = None
        self._tunnelLink = None
        self._domain = None
        self._tunnelStarted = False

    def addShare(self, filePaths, extraArgs=None):
        extraArgs = extraArgs or []
        filePath = filePaths[0] if len(filePaths) == 1 else filePaths
        reader = SourceReader.build(filePath)

        config = ServerConfig(
            maxDownloads=self._parseIntArg(extraArgs, '--max-downloads', 0),
            timeout=self._parseIntArg(extraArgs, '--timeout', 0),
            e2eeEnabled='--e2ee' in extraArgs,
        )

        uid = UIDGenerator().generate()
        session = ShareSession(
            uid=uid,
            filePaths=filePaths,
            createdAt=datetime.datetime.now().isoformat(),
            reader=reader,
            config=config,
        )

        with self._lock:
            self._sessions[uid] = session

            if self._tunnelLink:
                tunnelType = self._tunnelRunner.getTunnelType() if self._tunnelRunner else 'unknown'
                self._activateSession(session, tunnelType)
            elif not self._tunnelStarted:
                self._tunnelStarted = True
                port = getAvailablePort()
                
                self._server = MultiShareServer(('127.0.0.1', port), DownloadHandler, autoShutdown=False)
                threading.Thread(
                    target=self._server.serve_forever,
                    daemon=True,
                    name='multi-share-server',
                ).start()
                
                threading.Thread(
                    target=self._startTunnel,
                    args=(port, reader.size),
                    daemon=True,
                    name='tunnel-starter',
                ).start()                
            else: # tunnel starting — session waits in CREATING until _startTunnel activates it
                pass

        return session

    def _startTunnel(self, port, fileSize):
        try:
            tunnelRunner = TunnelRunner(fileSize)
            domain, tunnelLink = tunnelRunner.start(port)
            tunnelType = tunnelRunner.getTunnelType()

            with self._lock:
                self._tunnelRunner = tunnelRunner
                self._tunnelLink = tunnelLink
                self._domain = domain
                for session in self._sessions.values():
                    if session.status == ShareStatus.CREATING:
                        self._activateSession(session, tunnelType)

        except Exception as e:
            logger.exception(f"Failed to start tunnel: {e}")
            with self._lock:
                for session in self._sessions.values():
                    if session.status == ShareStatus.CREATING:
                        session.status = ShareStatus.CRASHED
                        session.error = str(e)

    def _activateSession(self, session, tunnelType):
        """Called under _lock. Assigns link, adds session to server."""
        session.domain = self._domain
        session.link = f"{self._tunnelLink}{session.uid}"
        filePath = session.filePaths[0] if len(session.filePaths) == 1 else session.filePaths
        
        session.shareData = self._buildShareData(
            session.link, filePath, session.reader.size or 0,
            tunnelType, session.config.e2eeEnabled,
        )
        self._server.addSession(session)
        
        session.status = ShareStatus.ONLINE
        logger.info(f"Share {session.uid} online: {session.link}")

    def pollSessions(self):
        pass

    def stopShare(self, uid):
        with self._lock:
            session = self._sessions.get(uid)
            
        if session is None:
            return False
            
        if self._server:
            self._server.removeSession(uid)
        else:
            session.stop()
            
        session.status = ShareStatus.STOPPED
        return True

    def listShares(self):
        with self._lock:
            return [
                session for session in self._sessions.values()
                if session.status not in (ShareStatus.STOPPED, ShareStatus.COMPLETED, ShareStatus.CRASHED)
            ]

    def getShare(self, uid):
        with self._lock:
            return self._sessions.get(uid)

    def shutdown(self):
        if self._server:
            try:
                self._server.shutdown()
            except Exception as e:
                logger.debug(f"Error shutting down multi-share server: {e}")
                
        if self._tunnelRunner:
            try:
                self._tunnelRunner.stop()
            except Exception as e:
                logger.debug(f"Error stopping tunnel runner: {e}")

    @staticmethod
    def _parseIntArg(args, flag, default):
        if flag not in args:
            return default
            
        idx = args.index(flag)
        if idx + 1 >= len(args):
            return default
            
        try:
            return int(args[idx + 1])
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid value for {flag}: {args[idx + 1]!r}: {e}")
            return default

    @staticmethod
    def _buildShareData(link, filePath, fileSize, tunnelType, e2eeEnabled):
        displayPath = filePath if isinstance(filePath, str) else (str(filePath[0]) if filePath else '')        
        return {
            'link': link,
            'file': displayPath,
            'file_size': fileSize,
            'user': InProcessShareManager._getUserInfo(),
            'tunnel_type': tunnelType,
            'e2ee': e2eeEnabled,
        }

    @staticmethod
    def _getUserInfo():
        try:
            featureManager = SettingsGetter.getInstance().getFeatureManager()
            user = featureManager.user
            return {
                'user': user.name,
                'email': user.email,
                'level': user.level,
                'points': user.points,
                'serial_number': user.serialNumber,
            }
        except Exception as e:
            logger.debug(f"Could not retrieve user info: {e}")
            return None


class DaemonAPIHandler(BaseHTTPRequestHandler):
    """Handles local REST API requests for the daemon."""

    def __init__(self, *args, **kwargs):
        self.getPathMap = {
            '/shares': self._handleListShares,
        }
        self.postPathMap = {
            '/shares': self._handleCreateShare,
            '/shutdown': self._handleShutdown,
        }
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        logger.debug(f"DaemonAPI: {format % args}")

    def _sendJSON(self, status: int, data: dict):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _requireAuth(self) -> bool:
        token = self.headers.get('X-Daemon-Token', '')
        if token != self.server.token:
            self._sendJSON(403, {'error': 'forbidden'})
            return False
            
        return True

    def _readJSON(self) -> dict:
        contentLength = int(self.headers.get('Content-Length', '0'))
        if contentLength == 0:
            return {}
            
        body = self.rfile.read(contentLength)
        return json.loads(body.decode('utf-8'))

    def do_GET(self):
        path = self.path.rstrip('/')

        if path == '/health':
            self._handleHealth()
            return

        if not self._requireAuth():
            return

        handler = self.getPathMap.get(path)
        if handler:
            handler()
            return

        if path.startswith('/shares/'):
            self._handleGetShare(path[len('/shares/'):])
            return

        self._sendJSON(404, {'error': 'not found'})

    def do_POST(self):
        path = self.path.rstrip('/')

        if not self._requireAuth():
            return

        handler = self.postPathMap.get(path)
        if handler:
            handler()
            return

        if path.startswith('/shares/') and path.endswith('/stop'):
            self._handleStopShare(path[len('/shares/'):-len('/stop')])
            return

        self._sendJSON(404, {'error': 'not found'})

    def _handleHealth(self):
        self._sendJSON(200, {'status': 'ok', 'pid': os.getpid()})

    def _handleListShares(self):
        sessions = self.server.shareManager.listShares()
        self._sendJSON(200, {'shares': [s.asDict() for s in sessions]})

    def _handleGetShare(self, shareId):
        session = self.server.shareManager.getShare(shareId)
        if session is None:
            self._sendJSON(404, {'error': 'not found'})
            return
            
        self._sendJSON(200, session.asDict())

    def _handleCreateShare(self):
        data = self._readJSON()
        filePaths = data.get('file_paths', [])
        extraArgs = data.get('extra_args', [])
        
        session = self.server.shareManager.addShare(filePaths, extraArgs)
        self._sendJSON(201, session.asDict())

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
        self._monitorThread = None
        self._running = False

    def start(self):
        self._running = True
        port = self.server_address[1]

        self._stateFile.save(port, self.token, os.getpid())

        self._monitorThread = threading.Thread(
            target=self._monitorLoop, daemon=True, name='daemon-monitor'
        )
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
        self._running = False
        self.shareManager.shutdown()        
        self._stateFile.clear()
        
        threading.Thread(target=self.shutdown, daemon=True).start()

    def _cleanup(self):
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
            response = requests.get(
                f"http://127.0.0.1:{state['port']}/health", timeout=cls.HEALTH_TIMEOUT
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Daemon health check failed: {e}")
            return False

    def createShare(self, filePaths, extraArgs=None) -> ShareRecord:
        if not isinstance(filePaths, list):
            filePaths = [filePaths]
            
        data = {'file_paths': filePaths, 'extra_args': extraArgs or []}
        response = requests.post(
            self.buildURL('/shares'), json=data, headers=self._headers, timeout=self.API_TIMEOUT
        )
        response.raise_for_status()
        
        return self._parseRecord(response.json())

    def waitForLink(self, shareId: str, timeout: float = CREATE_SHARE_TIMEOUT) -> Optional[dict]:
        """Poll GET /shares/{id} until ONLINE, then return the full share dict."""
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
            status = DaemonClient._parseShareStatus(shareData.get('status', ''))
            if status == ShareStatus.ONLINE and shareData.get('link'):
                return shareData
                
            if status in (ShareStatus.CRASHED, ShareStatus.STOPPED):
                return None
                
            time.sleep(self.STATUS_POLL_INTERVAL)
            
        return None

    def listShares(self) -> list:
        response = requests.get(self.buildURL('/shares'), headers=self._headers, timeout=self.API_TIMEOUT)
        response.raise_for_status()
        
        return response.json().get('shares', [])

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
            response = requests.post(
                self.buildURL('/shutdown'), headers=self._headers, timeout=self.API_TIMEOUT
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Daemon shutdown request failed: {e}")
            return False

    def _parseRecord(self, data: dict) -> ShareRecord:
        return ShareRecord(
            id=data.get('id', ''),
            filePaths=data.get('file_paths', []),
            pid=data.get('pid'),
            status=DaemonClient._parseShareStatus(data.get('status', '')),
            link=data.get('link'),
            createdAt=data.get('created_at', ''),
            downloads=data.get('downloads', 0),
            workerData=data.get('worker_data'),
        )

    @staticmethod
    def _parseShareStatus(value: str) -> ShareStatus:
        try:
            return ShareStatus[value.upper()]
        except (KeyError, AttributeError) as e:
            logger.warning(f"Unknown share status {value!r}, defaulting to CREATING: {e}")
            return ShareStatus.CREATING


class DaemonManager:
    """CLI-level daemon lifecycle management."""

    STARTUP_TIMEOUT = 15

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
            share = client.getShare(shareId) if shareId else None
            
            if not share:
                flushPrint(_('Error: Share {id} not found').format(id=shareId))
                return 1
                
            link = share.get('link')
            if not link:
                flushPrint(_('Error: Share {id} has no link yet').format(id=shareId))
                return 1
                
            webbrowser.open(link)
            
            flushPrint(_('Opened share {id}').format(id=shareId))
            flushPrint(link)
            
            return 0

        if sharesAction == 'qr':
            share = client.getShare(shareId) if shareId else None

            if not share:
                flushPrint(_('Error: Share {id} not found').format(id=shareId))
                return 1

            link = share.get('link')
            if not link:
                flushPrint(_('Error: Share {id} has no link yet').format(id=shareId))
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
    def handleBackgroundShare(cls, args) -> int:
        """Route a share to the daemon, wait for link, write JSON output, and exit."""
        if not DaemonClient.isRunning():
            if args.background:
                result = cls._startDaemon()
                if result != 0:
                    return result
            else:
                return 1

        filePaths = args.file if isinstance(args.file, list) else [args.file]

        extraArgs = []
        if args.maxDownloads:
            extraArgs.extend(['--max-downloads', str(args.maxDownloads)])
            
        if args.timeout:
            extraArgs.extend(['--timeout', str(args.timeout)])
            
        if args.e2ee:
            extraArgs.append('--e2ee')
            
        if args.authPassword:
            extraArgs.extend(['--auth-password', args.authPassword])
            if args.authUser:
                extraArgs.extend(['--auth-user', args.authUser])
                
        if args.fileName:
            extraArgs.extend(['--name', args.fileName])

        client = DaemonClient()
        share = client.createShare(filePaths, extraArgs)

        flushPrint(_('Waiting for share link...'))
        shareData = client.waitForLink(share.id)

        if not shareData:
            flushPrint(_('Error: Failed to get share link from daemon'))
            return 1

        link = shareData.get('link')
        shareId = shareData.get('id')
        flushPrint(f'{link}\n')
        flushPrint(_('Share ID: {id} (managed by daemon)').format(id=shareId))

        jsonOutput = getattr(args, 'json', None)
        if jsonOutput:
            workerData = shareData.get('worker_data')
            if workerData:
                try:
                    with open(jsonOutput, 'w', encoding='utf-8') as f:
                        json.dump(workerData, f, indent=2)
                except Exception as e:
                    flushPrint(_('Warning: Failed to write JSON output: {error}').format(error=e))

        return 0

    @classmethod
    def _startDaemon(cls) -> int:
        if DaemonClient.isRunning():
            state = DaemonStateFile().load()
            flushPrint(_('Daemon already running (PID: {pid}, port: {port})').format(
                pid=state.get('pid'), port=state.get('port')
            ))
            return 0

        corePath = os.path.abspath(sys.argv[0])
        cmd = [sys.executable, corePath, '--cli', 'daemon', '--start']

        if sys.platform == 'win32':
            creationFlags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationFlags
            )
        else:
            subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
            )

        stateFile = DaemonStateFile()
        deadline = time.time() + cls.STARTUP_TIMEOUT
        while time.time() < deadline:
            if DaemonClient.isRunning():
                state = stateFile.load()
                flushPrint(_('Daemon started (PID: {pid}, port: {port})').format(
                    pid=state.get('pid'), port=state.get('port')
                ))
                return 0
            time.sleep(0.5)

        flushPrint(
            _('Error: Daemon failed to start within {timeout} seconds').format(timeout=cls.STARTUP_TIMEOUT)
        )
        return 1

    @classmethod
    def _stopDaemon(cls, force=False) -> int:
        if not DaemonClient.isRunning():
            flushPrint(_('Daemon is not running'))
            return 0

        client = DaemonClient()
        if not client.stopDaemon():
            flushPrint(_('Error: Failed to send stop command to daemon'))
            if force:
                return cls._forceKillDaemon()
                
            return 1

        deadline = time.time() + 10
        while time.time() < deadline:
            if not DaemonClient.isRunning():
                flushPrint(_('Daemon stopped'))
                return 0
                
            time.sleep(0.5)

        if force:
            return cls._forceKillDaemon()

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
        flushPrint(_('  Started: {started}').format(started=state.get('started_at')))

        try:
            client = DaemonClient()
            shares = client.listShares()
            flushPrint(_('  Active shares: {count}').format(count=len(shares)))
        except Exception as e:
            logger.debug(f"Could not fetch active shares for status display: {e}")

        return 0
