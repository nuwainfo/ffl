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
import os
import threading

from abc import ABC, abstractmethod
from functools import partial

from bases.Auth import RecipientAuth
from bases.I18n import _
from bases.Kernel import getLogger
from bases.Server import DownloadHandler, createServer
from bases.Session import ServerConfig, ServerSession, UploadSession
from bases.Settings import SettingsGetter, ShareMode
from bases.Share import (
    RuntimeProtocol,
    ShareExecutionContext,
    ShareRequest,
    generateUID,
)
from bases.Tunnel import createTunnelRunner
from bases.Utils import copy2Clipboard, getAvailablePort
from bases.WebRTC import DummyWebRTCManager, WebRTCManager

logger = getLogger(__name__)


def removeSplash():
    try:
        if '_PYI_SPLASH_IPC' in os.environ:
            import pyi_splash # type: ignore # pylint: disable=import-error

            pyi_splash.close()
            os.environ.pop('_PYI_SPLASH_IPC', None)
    except Exception as e:
        logger.warning(f'Unable to close splash: {e}')


class AbstractRuntime(RuntimeProtocol, ABC):

    def run(self, shareRequest: ShareRequest, context: ShareExecutionContext, *, reader, size, torDetected: bool):
        args = shareRequest
        settingsGetter = SettingsGetter.getInstance()
        featureManager = settingsGetter.getFeatureManager()

        uid = args.uid
        if uid is None:
            uid = generateUID(featureManager)

        if context.session is None:
            sessionClass = UploadSession if args.upload else ServerSession
            context.session = sessionClass(
                id=uid,
                filePaths=args.file if isinstance(args.file, list) else [args.file],
                createdAt=datetime.datetime.now().isoformat(),
            )

        uploadProcessor = None
        if args.upload:
            from addons.Upload import processUpload

            uploadProcessor = processUpload(args, reader, context)
            if uploadProcessor.isDone():
                return uploadProcessor.exitCode

            uid = uploadProcessor.uid

        if context.isStopRequested():
            return 0

        # If we reach here, we need to start local server (either P2P or Pull upload)
        if not uid:
            uid = generateUID(featureManager)
            context.session.uid = uid

        return self.runServerShare(
            args, context, reader=reader, size=size, uid=uid, torDetected=torDetected, uploadProcessor=uploadProcessor
        )

    @abstractmethod
    def runServerShare(self, args, context, *, reader, size, uid, torDetected, uploadProcessor):
        raise NotImplementedError

    def prepareServerSession(self, args, context, *, reader, uid, link, torDetected, uploadProcessor):
        reporter = context.reporter
        output = reporter.output

        settingsGetter = SettingsGetter.getInstance()
        featureManager = settingsGetter.getFeatureManager()

        # Determine recipient auth mode (P2P only; pull-upload uses server-side auth)
        recipientAuth = RecipientAuth.createFromArgs(args.toDict())

        # Determine handler class and setup link
        try:
            handlerClass = self.prepareBaseHandlerClass(
                context,
                uploadProcessor=uploadProcessor,
                link=link,
                uid=uid,
            )
        except RuntimeError as uploadError:
            output(_('Upload failed: {error}').format(error=str(uploadError)))
            reporter.sendException(str(uploadError))
            return 1, None

        if uploadProcessor and uploadProcessor.isDone():
            return uploadProcessor.exitCode, None

        # Get enhanced handlers from FeatureManager if Features addon is available
        webRTCManagerClass = WebRTCManager
        if settingsGetter.hasFeaturesSupport():
            handlerClass = featureManager.getDownloadHandlerClass(handlerClass)
            webRTCManagerClass = featureManager.getWebRTCManagerClass(webRTCManagerClass, forceRelay=args.forceRelay)
        else:
            if torDetected:
                # Tor mode without Features addon: use DummyWebRTCManager to totally block WebRTC
                webRTCManagerClass = DummyWebRTCManager

        authPassword = args.authPassword or os.getenv('FFL_AUTH_PASSWORD')
        authUser = args.authUser if authPassword else None

        # WebRTC default state: disabled by --force-relay flag
        defaultWebRTC = not args.forceRelay

        # Create server configuration
        serverConfig = ServerConfig(
            maxDownloads=args.maxDownloads,
            timeout=args.timeout,
            authUser=authUser,
            authPassword=authPassword,
            defaultWebRTC=defaultWebRTC,
            e2eeEnabled=args.e2ee,
            torEnabled=torDetected,
            recipientAuth=recipientAuth,
        )

        return 0, ServerSession(
            id=uid,
            filePaths=list(context.session.filePaths),
            createdAt=context.session.createdAt,
            reader=reader,
            config=serverConfig,
            handlerClass=handlerClass,
            webRTCManagerClass=webRTCManagerClass,
        )

    def prepareBaseHandlerClass(self, context, *, uploadProcessor, link, uid):
        if not uploadProcessor:
            # P2P mode
            return DownloadHandler

        return uploadProcessor.prepareServerHandlerClass(link, uid)

    def emitP2PShareLink(self, args, context, *, uid, link, reader, size, tunnelType, recipientAuth, copyLink=True):
        settingsGetter = SettingsGetter.getInstance()
        featureManager = settingsGetter.getFeatureManager()

        output = context.reporter.output

        output(_("Please share the link below with the person you'd like to share the file with."))
        output(f'{link}\n')
        if copyLink and not args.disableClipboard:
            copy2Clipboard(f'{link}')

        shareResult = context.createShareResult(
            file=args.file,
            contentName=reader.contentName,
            fileSize=size,
            uploadMode=ShareMode.P2P,
            tunnelType=tunnelType,
            link=link,
            e2ee=args.e2ee,
            recipientAuth=recipientAuth,
            user=featureManager.user,
        )

        context.reporter.notifyShareLinkCreated(shareResult, uid=uid, reader=reader)

        output(_('Please keep the application running so the recipient can download the file.'))
        if settingsGetter.isCLIMode():
            output(_('Press Ctrl+C to terminate the program when done.\n'))
        else:
            output('')

        return shareResult

    def emitUploadShareLink(self, args, context, *, uid, link, reader, size, tunnelType, recipientAuth):
        settingsGetter = SettingsGetter.getInstance()
        featureManager = settingsGetter.getFeatureManager()

        shareResult = context.createShareResult(
            file=args.file,
            contentName=reader.contentName,
            fileSize=size,
            uploadMode=ShareMode.SERVER,
            tunnelType=tunnelType,
            link=link,
            e2ee=args.e2ee,
            recipientAuth=recipientAuth,
            user=featureManager.user,
        )

        context.reporter.notifyShareLinkCreated(shareResult, uid=uid, reader=reader)
        return shareResult

    def outputAuthenticationInfo(self, reporter, authPassword, authUser, recipientAuth):
        output = reporter.output

        # Show auth info if enabled (password enables auth)
        if authPassword:
            output(_('Authentication enabled - Username: {authUser}\n').format(authUser=authUser))

        if recipientAuth.isEnabled():
            if recipientAuth.requiresPickup():
                output(_('Pickup code: {code}\n').format(code=recipientAuth.pickupCode))


class MultiShareServerRuntime(AbstractRuntime):

    def createTunnel(self, size, context):
        reporter = context.reporter
        return createTunnelRunner(
            size,
            proxyConfig=context.proxyConfig,
            onTunnelError=partial(
                reporter.sendException,
                errorPrefix=_('Unable to create tunnel by your tunnel configuration.')
            ),
        )

    def startTunnel(self, tunnelRunner, port, context):
        output = context.reporter.output
        tunnelType = tunnelRunner.getTunnelType()
        if tunnelType != "default":
            output(_('Using tunnel: {tunnelType}').format(tunnelType=tunnelType))

        # Show proxy status for tunnel connections
        proxyInfo = tunnelRunner.getProxyInfo()
        if proxyInfo:
            output(_('Establishing tunnel connection via proxy {proxyInfo}...\n').format(proxyInfo=proxyInfo))
        else:
            output(_('Establishing tunnel connection...\n'))

        domain, tunnelLink = tunnelRunner.start(port)
        return domain, tunnelLink


class SingleShareRuntime(MultiShareServerRuntime):

    def runServerShare(self, args, context, *, reader, size, uid, torDetected, uploadProcessor):
        reporter = context.reporter
        output = reporter.output

        userPort = args.port
        port = getAvailablePort(userPort)

        tunnelRunner = self.createTunnel(size, context)
        with tunnelRunner:
            domain, tunnelLink = self.startTunnel(tunnelRunner, port, context)
            tunnelType = tunnelRunner.getTunnelType()
            link = f"{tunnelLink}{uid}"

            if context.isStopRequested():
                return 0

            exitCode, serverSession = self.prepareServerSession(
                args,
                context,
                reader=reader,
                uid=uid,
                link=link,
                torDetected=torDetected,
                uploadProcessor=uploadProcessor
            )
            if serverSession is None:
                return exitCode

            serverSession.port = port
            serverSession.domain = domain

            context.session = serverSession

            recipientAuth = serverSession.config.recipientAuth
            authUser = serverSession.config.authUser
            authPassword = serverSession.config.authPassword

            if not uploadProcessor:
                if context.isStopRequested():
                    return 0

                self.emitP2PShareLink(
                    args,
                    context,
                    uid=uid,
                    link=link,
                    reader=reader,
                    size=size,
                    tunnelType=tunnelType,
                    recipientAuth=recipientAuth,
                )

            self.outputAuthenticationInfo(reporter, authPassword, authUser, recipientAuth)

            # Create server with enhanced handler and WebRTC manager
            # Reader provides file and directory information
            server = createServer(serverSession)

            reporter.notifyServerCreated(server, uid=uid)

            threading.Thread(target=server.serve_forever, daemon=True, name='http-server').start()
            try:
                while not server._doneEvent.wait(timeout=0.5):
                    if context.isStopRequested():
                        break
            finally:
                server.shutdown()

            if context.isStopRequested():
                return 0

            if server.error:
                logger.error("Server encountered an error during file sharing")
                raise ChildProcessError()

            # If we used pull upload, publish the link after server ends
            if uploadProcessor:
                if context.isStopRequested():
                    return 0

                hostedLink = uploadProcessor.publish()
                if not hostedLink: # !?
                    reporter.sendException(_('Unable to get uploaded link'))
                    return 1

                self.emitUploadShareLink(
                    args,
                    context,
                    uid=uid,
                    link=hostedLink,
                    reader=reader,
                    size=size,
                    tunnelType=tunnelType,
                    recipientAuth=recipientAuth
                )

            # Default success return for normal P2P completion
            return 0
