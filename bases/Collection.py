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

"""Append-only delivery collections and folder-watch publishing."""

import json
import os
import threading
import time

from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from bases.Auth import AuthMixin, HTTPAuth
from bases.Kernel import getLogger
from bases.Runtime import SingleShareRuntime
from bases.Server import createServer
from bases.Session import ServerConfig, ServerSession, createSession
from bases.Settings import ShareMode
from bases.Share import ShareExecutionContext, ShareReporter, ShareResult, ShareStatus, createShareRequest, processSharing
from bases.Tunnel import createTunnelRunner
from bases.Utils import getAvailablePort
from bases.WebRTC import DummyWebRTCManager

logger = getLogger(__name__)


class Collection:
    """Thread-safe append-only manifest for immutable share deliveries."""

    def __init__(self, uid, authUser=None, authPassword=None):
        self.uid = uid
        self.auth = HTTPAuth(user=authUser, password=authPassword)
        self._items = []
        self._lock = threading.Lock()

    def append(self, uid, name, link):
        with self._lock:
            item = {
                'seq': len(self._items) + 1,
                'uid': uid,
                'name': name,
                'link': link,
                'createdAt': datetime.now(timezone.utc).isoformat(),
            }
            self._items.append(item)
            
            return item

    def manifest(self):
        with self._lock:
            return {
                'type': 'ffl.collection',
                'version': 1,
                'revision': len(self._items),
                'items': list(self._items),
            }


class CollectionHandler(AuthMixin, BaseHTTPRequestHandler):
    """Serves a collection manifest at its UID and UID/download endpoints."""

    protocol_version = 'HTTP/1.1'

    @property
    def auth(self):
        return self.server.collection.auth

    def _getCollection(self):
        path = self.path.split('?', 1)[0].strip('/')
        parts = path.split('/', 1)
        
        if not parts or parts[0] != self.server.collectionUID:
            return None
            
        if len(parts) == 2 and parts[1] != 'download':
            return None
            
        return self.server.collection

    def _serveManifest(self, includeBody):
        collection = self._getCollection()
        if collection is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
            
        if not self.handleAuthentication():
            return

        manifest = collection.manifest()
        body = json.dumps(manifest, ensure_ascii=False).encode('utf-8')
        
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'application/vnd.fastfilelink.collection+json; charset=utf-8')
        self.send_header('X-FFL-Resource-Type', 'collection')
        self.send_header('X-FFL-Collection-Revision', str(manifest['revision']))
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()        
        self.close_connection = True
        
        if includeBody:
            self.wfile.write(body)

    def do_HEAD(self):
        self._serveManifest(includeBody=False)

    def do_GET(self):
        self._serveManifest(includeBody=True)

    def log_message(self, format, *args):
        logger.debug(format, *args)


class CollectionServer:
    """Keeps the stable collection endpoint online while child shares run normally."""

    def __init__(self, collection, proxyConfig):
        self.collection = collection
        self.proxyConfig = proxyConfig
        self.server = None
        self.thread = None
        self.tunnelRunner = None
        self.link = None

    def start(self):
        port = getAvailablePort(None)
        
        # Tunnel selection expects a positive payload size even though a collection
        # only serves small manifests.
        self.tunnelRunner = createTunnelRunner(1, proxyConfig=self.proxyConfig)
        self.tunnelRunner.__enter__()
        domain, tunnelLink = self.tunnelRunner.start(port, uid=self.collection.uid)
        
        session = ServerSession(
            id=self.collection.uid,
            filePaths=[],
            createdAt=datetime.now(timezone.utc).isoformat(),
            port=port,
            domain=domain,
            config=ServerConfig(defaultWebRTC=False),
            handlerClass=CollectionHandler,
            webRTCManagerClass=DummyWebRTCManager,
        )
        self.server = createServer(session)
        self.server.collection = self.collection
        self.server.collectionUID = self.collection.uid
        
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name='collection-server')
        self.thread.start()
        
        self.link = f'{tunnelLink}{self.collection.uid}'
        return self.link

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            
        if self.tunnelRunner:
            self.tunnelRunner.__exit__(None, None, None)


class FolderWatchPublisher:
    """Publishes each newly created, stable direct child folder once."""

    POLL_SECONDS = 1

    def __init__(self, shareRequest, reporter, proxyConfig, collection, runtime=None):
        self.shareRequest = shareRequest
        self.reporter = reporter
        self.proxyConfig = proxyConfig
        self.collection = collection
        self.runtime = runtime or SingleShareRuntime()
        self.root = os.path.abspath(shareRequest.file)
        
        self._publishedPaths = set()
        self._pendingFingerprints = {}
        self._deliveryContexts = []
        self._lock = threading.Lock()

    def _listChildFolders(self):
        return [entry.path for entry in os.scandir(self.root) if entry.is_dir()]

    def _fingerprint(self, path):
        entries = []
        for currentRoot, _dirNames, fileNames in os.walk(path):
            for fileName in sorted(fileNames):
                filePath = os.path.join(currentRoot, fileName)
                stat = os.stat(filePath)
                entries.append((os.path.relpath(filePath, path), stat.st_size, stat.st_mtime_ns))
                
        return tuple(entries)

    def _publish(self, path):
        name = os.path.basename(path)
        self.reporter.output(f'Publishing delivery: {name}')
        request = createShareRequest(self.shareRequest, file=path, watch=False, json=None)
        originalCallback = self.reporter.shareLinkCallback

        def appendShare(shareResult, **_eventData):
            self.collection.append(shareResult.link.rsplit('/', 1)[-1], name, shareResult.link)
            self.reporter.output(f'Shared {name}: {shareResult.link}')
            if originalCallback:
                originalCallback(shareResult=shareResult)

        childReporter = ShareReporter(
            outputCallback=self.reporter.outputCallback,
            exceptionCallback=self.reporter.exceptionCallback,
            shareLinkCallback=appendShare,
            encryptionKeyCallback=self.reporter.encryptionKeyCallback,
        )
        context = ShareExecutionContext(
            reporter=childReporter,
            session=createSession(request),
            runtime=self.runtime,
            proxyConfig=self.proxyConfig,
        )
        with self._lock:
            self._deliveryContexts.append(context)

        def run():
            processSharing(request, context)

        thread = threading.Thread(target=run, daemon=True, name=f'watch-share-{name}')
        thread.start()

    def scanOnce(self, now=None):
        now = time.monotonic() if now is None else now
        for path in self._listChildFolders():
            if path in self._publishedPaths:
                continue
                
            fingerprint = self._fingerprint(path)
            previous = self._pendingFingerprints.get(path)
            if previous is None or previous[0] != fingerprint:
                self._pendingFingerprints[path] = (fingerprint, now)
                continue
                
            if now - previous[1] < self.shareRequest.watchSettle:
                continue
                
            self._publishedPaths.add(path)
            self._pendingFingerprints.pop(path, None)
            self._publish(path)

    def initialize(self):
        if not os.path.isdir(self.root):
            raise ValueError('--watch can only be used with a folder')
            
        if self.shareRequest.watchSettle < 1:
            raise ValueError('--watch-settle must be at least 1 second')

        existingPaths = self._listChildFolders()
        self._publishedPaths.update(existingPaths)
        if existingPaths:
            self.reporter.output(
                f'Warning: ignoring {len(existingPaths)} existing delivery folder(s); only newly created folders publish.'
            )
        
        self.reporter.output(f'Watching {self.root} for new delivery folders...')

    def run(self, stopEvent=None):
        self.initialize()
        while stopEvent is None or not stopEvent.is_set():
            self.scanOnce()
            if stopEvent:
                stopEvent.wait(self.POLL_SECONDS)
            else:
                time.sleep(self.POLL_SECONDS)

    def stop(self):
        """Stop child deliveries without tearing down a daemon's shared runtime."""
        with self._lock:
            deliveryContexts = list(self._deliveryContexts)

        for context in deliveryContexts:
            context.stopEvent.set()
            context.session.stop()

            # DaemonSharedRuntime holds the HTTP server for every child delivery.
            # Remove only this delivery's session; the shared infrastructure stays
            # available for unrelated daemon shares.
            server = getattr(context.runtime, '_server', None)
            if server:
                try:
                    server.removeSession(context.session.uid)
                except Exception as e:
                    logger.debug('Failed to remove watch delivery session %s: %s', context.session.uid, e)


def processWatchSharing(shareRequest, context):
    """Publish a stable collection endpoint and watch it until the context stops.

    The function deliberately uses ``context.runtime`` for child deliveries.  In
    daemon mode that is DaemonSharedRuntime, so deliveries participate in the
    daemon's shared server/tunnel lifecycle instead of spawning detached shares.
    """
    if isinstance(shareRequest.file, list):
        if len(shareRequest.file) != 1:
            raise ValueError('--watch requires exactly one folder')
            
        shareRequest.file = shareRequest.file[0]
        
    if not os.path.isdir(shareRequest.file):
        raise ValueError('--watch can only be used with a folder')
        
    if shareRequest.upload:
        raise ValueError('--watch does not support --upload; each delivery is a normal immutable share')

    collection = Collection(
        context.session.uid,
        authUser=shareRequest.authUser,
        authPassword=shareRequest.authPassword,
    )

    collectionServer = CollectionServer(collection, context.proxyConfig)
    
    publisher = None
    contentName = os.path.basename(os.path.abspath(shareRequest.file))
    context.reporter.notifyShareCreated(context.session.uid, contentName, 0, ShareMode.P2P)
    context.reporter.notifyShareStarted(context.session.uid)
    
    try:
        collectionLink = collectionServer.start()
        result = ShareResult(
            file=shareRequest.file,
            contentName=contentName,
            fileSize=0,
            uploadMode=ShareMode.P2P,
            tunnelType=collectionServer.tunnelRunner.getTunnelType(),
            link=collectionLink,
            e2ee=False,
        )
        context.session.link = collectionLink
        context.session.status = ShareStatus.ONLINE
        context.reporter.output(f'Collection URL: {collectionLink}')
        context.reporter.notifyShareLinkCreated(result, uid=context.session.uid)
        context.reporter.notifyShareAvailable(context.session.uid, result)

        # Do not propagate child links through the parent callback: the daemon
        # share record must keep pointing at the stable collection URL.
        deliveryReporter = ShareReporter(
            outputCallback=context.reporter.outputCallback,
            exceptionCallback=context.reporter.exceptionCallback,
            encryptionKeyCallback=context.reporter.encryptionKeyCallback,
        )
    
        publisher = FolderWatchPublisher(
            shareRequest,
            deliveryReporter,
            context.proxyConfig,
            collection,
            runtime=context.runtime,
        )
        publisher.run(stopEvent=context.stopEvent)
        
        return 0
    except Exception as e:
        context.reporter.notifyShareFailed(context.session.uid, str(e))
        raise
    finally:
        if publisher:
            publisher.stop()
            
        collectionServer.close()
