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

import os
import threading

from dataclasses import dataclass, field
from functools import partial
from typing import Any, Callable, Optional

import segno

from bases.Auth import RecipientAuth
from bases.Download import FFLDownloader
from bases.FileSystems import ExcludeFilter
from bases.I18n import _
from bases.Kernel import FFLEvent, UIDGenerator, getLogger
from bases.Progress import Progress
from bases.Readers import SourceReader, SourceReaderProgressReporter
from bases.Server import DownloadHandler, createServer
from bases.Session import ServerConfig
from bases.Settings import DEFAULT_AUTH_USER_NAME, DEFAULT_UPLOAD_DURATION, SettingsGetter
from bases.Tor import verifyTorProxy
from bases.Tunnel import createTunnelRunner
from bases.VFS import processVFS
from bases.Utils import (
    DataclassDictMixin,
    ProxyConfig,
    copy2Clipboard,
    flushPrint,
    formatSize,
    getAvailablePort,
    sendException,
    writeShareJsonOutput,
)
from bases.WebRTC import DummyWebRTCManager, WebRTCManager

logger = getLogger(__name__)


@dataclass
class ShareRequest(DataclassDictMixin):
    
    file: Any = field(default=None, metadata={
        'cli': {
            'flags': ('file',),
            'options': {
                'metavar': 'FILE_OR_FOLDER',
                'help': lambda context: _(
                    "File(s) or folder to share. Use '-' for stdin, '@filelist.txt' to read paths "
                    "from a file. Multiple files can be specified: file1 file2 file3"
                ),
                'nargs': '*',
            },
        },
    })

    fileName: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--name', '-n'),
            'options': {
                'metavar': 'FILENAME',
                'help': lambda context: _(
                    "Specify custom download filename (default: original filename for files, "
                    "folder.zip for folders, stdin-YYYYMMDD-HHMMSS.bin for stdin)"
                ),
            },
        },
    })
    
    exclude: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--exclude',),
            'options': {
                'metavar': 'PATTERNS',
                'help': lambda context: _(
                    "Comma-separated patterns to exclude files/folders by name "
                    "(e.g. '*.log,.svn,__pycache__'). Prefix with 're:' for regex "
                    "(e.g. 're:\\.tmp$'). Applies at any depth."
                ),
            },
        },
    })
    
    json: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--json',),
            'options': {
                'metavar': 'JSON_FILE',
                'help': lambda context: _("Output link and settings to a JSON file"),
            },
        },
    })
    
    upload: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--upload',),
            'options': {
                'help': lambda context: _(
                    "Upload file to FastFileLink server to share it "
                    "(Share duration after upload). Default: {default}"
                ).format(default=DEFAULT_UPLOAD_DURATION),
                'choices': lambda context: context['uploadChoices'],
                'nargs': '?',
                'const': lambda context: context['uploadConst'],
            },
        },
    })
    
    resume: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--resume',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _(
                    "Resume a previously interrupted upload (requires previous upload session to exist)"
                ),
            },
        },
    })
    
    pause: Optional[int] = field(default=None, metadata={
        'cli': {
            'flags': ('--pause',),
            'options': {
                'type': 'int',
                'metavar': 'PERCENTAGE',
                'help': lambda context: _("Pause upload at specified percentage (1-99, requires --upload)"),
            },
        },
    })
    
    yes: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--yes',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _("Automatically answer yes to upload confirmation prompts"),
            },
        },
    })
    
    legacyLink: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--legacy-link',),
            'options': {
                'metavar': 'URL',
                'help': lambda context: _("Legacy P2P share link to recover after this server upload completes"),
            },
        },
    })
    
    maxDownloads: int = field(default=0, metadata={
        'cli': {
            'flags': ('--max-downloads',),
            'options': {
                'type': 'maxDownloads',
                'help': lambda context: _(
                    "Maximum number of downloads before the server automatically shuts down "
                    "(P2P mode only). 0 means unlimited."
                ),
            },
        },
    })
    
    timeout: int = field(default=0, metadata={
        'cli': {
            'flags': ('--timeout',),
            'options': {
                'type': 'timeout',
                'help': lambda context: _(
                    "Timeout in seconds before the server automatically shuts down (P2P mode only). "
                    "0 means no timeout."
                ),
            },
        },
    })
    
    port: Optional[int] = field(default=None, metadata={
        'cli': {
            'flags': ('--port',),
            'options': {
                'type': 'port',
                'metavar': 'PORT',
                'help': lambda context: _(
                    "Port number for local server (1024-65535, default: auto-detect available port)"
                ),
            },
        },
    })
    
    authUser: str = field(default=DEFAULT_AUTH_USER_NAME, metadata={
        'cli': {
            'flags': ('--auth-user',),
            'options': {
                'metavar': 'USERNAME',
                'help': lambda context: _(
                    "Username for HTTP Basic Authentication (default: '{default}')"
                ).format(default=DEFAULT_AUTH_USER_NAME),
            },
        },
    })
    
    authPassword: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--auth-password',),
            'options': {
                'metavar': 'PASSWORD',
                'help': lambda context: _("Password for HTTP Basic Authentication (enables auth protection)"),
            },
        },
    })
    
    recipientAuth: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--recipient-auth',),
            'options': {
                'choices': ['pickup', 'pubkey', 'pubkey+pickup', 'email'],
                'help': lambda context: _("Enable recipient verification before download"),
                'metavar': 'MODE',
            },
        },
    })
    
    pickupCode: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--pickup-code',),
            'options': {
                'help': lambda context: _("Custom 6-digit pickup code for recipient verification"),
                'metavar': 'CODE',
            },
        },
    })
    
    recipientPublicKey: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--recipient-public-key',),
            'options': {
                'help': lambda context: _("Recipient public key (.fflpub) file path for pubkey verification"),
                'metavar': 'FILE',
            },
        },
    })
    
    recipientEmail: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--recipient-email',),
            'options': {
                'help': lambda context: _("Recipient email address(es) for email verification (comma-separated)"),
                'metavar': 'EMAILS',
            },
        },
    })
    
    recipientOTPAPIBase: Optional[str] = field(default=None, metadata={
        'cli': {
            'flags': ('--recipient-otp-api-base',),
            'options': {
                'help': lambda context: _(
                    "Base URL for OTP email API (e.g. https://myserver.com/api). "
                    "Required for --recipient-auth email"
                ),
                'metavar': 'URL',
            },
        },
    })
    
    forceRelay: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--force-relay',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _(
                    "Force relayed P2P mode, disable direct WebRTC connections "
                    "(can be overridden by ?webrtc=on URL parameter)"
                ),
            },
        },
    })
    
    e2ee: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--e2ee',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _("Enable end-to-end encryption for file sharing (both HTTP and WebRTC)"),
            },
        },
    })
    
    invite: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--invite',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _("Open invite page in browser with the sharing link"),
            },
        },
    })
    
    qr: Any = field(default=False, metadata={
        'cli': {
            'flags': ('--qr',),
            'options': {
                'nargs': '?',
                'const': True,
                'metavar': 'FILE',
                'help': lambda context: _("Display QR code in terminal (default) or save to FILE (e.g., qr.png)"),
            },
        },
    })
    
    disableClipboard: Optional[bool] = field(default=None, metadata={
        'cli': {
            'flags': ('--disable-clipboard',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _(
                    "Disable automatically copying the share link to the clipboard "
                    "(default: enabled in CLI mode, disabled in GUI mode)"
                ),
            },
        },
    })
    
    vfs: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--vfs',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _(
                    "Start VFS server and provide vfs:// URI instead of HTTPS link "
                    "(P2P mode only, works with --port)"
                ),
            },
        },
    })
    
    stdinCache: str = field(default='on', metadata={
        'cli': {
            'flags': ('--stdin-cache',),
            'options': {
                'choices': ['on', 'off'],
                'help': lambda context: _(
                    "Enable or disable stdin caching ('off' means a second read raises an error)"
                ),
            },
        },
    })
    
    background: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--background',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _("Submit share to background daemon (auto-starts daemon if needed)"),
            },
        },
    })
    
    foreground: bool = field(default=False, metadata={
        'cli': {
            'flags': ('--foreground',),
            'options': {
                'action': 'store_true',
                'help': lambda context: _("Run share in foreground even if a daemon is running"),
            },
        },
    })
    
    uploadConfirmed: bool = False
    
    uid: Optional[str] = None
    extraOptions: dict = field(default_factory=dict)

    @classmethod
    def fromObject(cls, source, **overrides):
        data = source if isinstance(source, dict) else vars(source)
        return cls.fromDict(data, **overrides)

    @classmethod
    def fromDict(cls, data, **overrides):
        return super().fromDict(data, extraField='extraOptions', **overrides)

    def toDict(self):
        data = super().toDict()
        extraOptions = data.pop('extraOptions', {})
        data.update(extraOptions)
        return data

    def __getattr__(self, name):
        try:
            return self.extraOptions[name]
        except KeyError as e:
            raise AttributeError(name) from e


@dataclass
class ShareReporter:
    outputCallback: Callable[[str], None]
    exceptionCallback: Optional[Callable[..., None]] = None
    shareLinkCallback: Optional[Callable[..., None]] = None
    serverCreatedCallback: Optional[Callable[..., None]] = None
    vfsServerCreatedCallback: Optional[Callable[..., None]] = None

    def output(self, text: str):
        self.outputCallback(text)

    def shareLinkCreated(self, **kwargs):
        if self.shareLinkCallback:
            self.shareLinkCallback(**kwargs)

    def serverCreated(self, server, uid=None):
        if self.serverCreatedCallback:
            self.serverCreatedCallback(server=server, uid=uid)

    def vfsServerCreated(self, vfsServer, link=None, uid=None):
        if self.vfsServerCreatedCallback:
            self.vfsServerCreatedCallback(vfsServer=vfsServer, link=link, uid=uid)

    def sendException(self, e, action=None, errorPrefix="Oops, something went wrong"):
        if self.exceptionCallback:
            self.exceptionCallback(e, action=action, errorPrefix=errorPrefix)
            return

        if e and errorPrefix:
            self.output(f'{errorPrefix}: {e}')
        elif e:
            self.output(f'{e}')
        else:
            logger.error(f'Incorrect argument: {errorPrefix=} {e=}')

        if action:
            self.output(action)
        else:
            self.output(_('Please try again or try later.'))

        settingsGetter = SettingsGetter.getInstance()
        supportURL = settingsGetter.getSupportURL()
        
        self.output(_('\nIf you still get the same problem, please contact us at {supportURL}.').format(
            supportURL=supportURL))
        self.output(_('We will fix the problem as soon as possible.\n'))
        logger.exception(e)


@dataclass
class ShareExecutionContext:
    reporter: ShareReporter
    interactionHandler: Any = None
    allowUserInteraction: bool = True
    proxyConfig: Optional[ProxyConfig] = None


class ScanFolderProgressReporter(SourceReaderProgressReporter):
    """Render SourceReader preprocessing progress for CLI and GUI modes."""

    @staticmethod
    def create(path):
        """Create a reader preprocessing reporter only for folder-like inputs."""
        if path == "-":
            return None

        if isinstance(path, list):
            return ScanFolderProgressReporter(useBar=SettingsGetter.getInstance().isCLIMode())

        if isinstance(path, str) and not path.startswith("vfs://") and os.path.isdir(path):
            return ScanFolderProgressReporter(useBar=SettingsGetter.getInstance().isCLIMode())

        return None

    def __init__(self, useBar: bool):
        self._progress = Progress(
            totalSize=None,
            sizeFormatter=lambda value: f"{int(value):,}",
            loggerCallback=lambda text: None,
            useBar=useBar,
            description=_('Scanning folder'),
            unit='entry',
            unitScale=False,
            leave=False
        )
        self._useBar = useBar
        self._started = False
        self._count = 0
        self._guiLabel = _('Scanning folder. Calculating size may take some time...')

    def start(self, operation: str, total=None, unit: str = "items") -> None:
        self._started = True
        self._count = 0
        if not self._useBar:
            flushPrint(self._guiLabel)

    def advance(self, amount: int = 1, processedBytes=None) -> None:
        if not self._started:
            return

        self._count += amount
        extraText = ""
        if processedBytes is not None and processedBytes > 0:
            extraText = _('Scanned {size}').format(size=formatSize(processedBytes))

        self._progress.update(self._count, extraText=extraText)

    def finish(self) -> None:
        if not self._started:
            return

        self._started = False
        if self._useBar:
            self._progress.finishBar(complete=False)

def onShareLinkCreate(args, link, filePath, fileSize, tunnelType, e2ee, reader,
                      reporter, recipientAuth=None, **kwargs):
    """Handle share link creation - invite, QR code, and JSON writing"""
    output = reporter.output
    featureManager = SettingsGetter.getInstance().getFeatureManager()

    # Handle --invite flag
    if args.invite:
        output(_('Opening invite page in browser...'))
        featureManager.invite(link)

    # Handle --qr flag
    if args.qr:
        try:
            qr = segno.make(link)

            # Check if args.qr is a file path (string) or True (terminal display)
            if isinstance(args.qr, str):
                # Save QR code to file
                qr.save(args.qr, scale=5)
                output(_('QR code saved to: {filePath}').format(filePath=args.qr))
            else:
                # Display in terminal
                output(_('\nQR Code:\n'))
                qr.terminal(compact=True)
                output('')
        except Exception as e:
            output(_('Error generating QR code: {error}').format(error=e))
            # It's ok only not generate QR code.

    # Handle --json flag
    if args.json:
        user = featureManager.user

        # Get content name (VFS mode has reader=None, use basename)
        contentName = reader.contentName if reader else os.path.basename(filePath)
        pickupCode = recipientAuth.pickupCode if recipientAuth and recipientAuth.requiresPickup() else None
        pubkeyEnabled = recipientAuth.requiresPubkey() if recipientAuth else False

        try:
            writeShareJsonOutput(
                args.json,
                filePath=filePath,
                contentName=contentName,
                fileSize=fileSize,
                uploadMode="server" if args.upload else "p2p",
                tunnelType=tunnelType,
                link=link,
                e2ee=e2ee,
                pickupCode=pickupCode,
                pubkeyEnabled=pubkeyEnabled,
                userName=user.name,
                email=user.email,
                level=user.level,
                points=user.points,
                serialNumber=user.serialNumber,
            )
            output(_('Sharing information saved to {jsonFile}').format(jsonFile=args.json))
        except Exception as e:
            output(_('Failed to write JSON file: {error}').format(error=e))
            reporter.sendException(e)


def generateUID(featureManager):
    # Get UIDGenerator from FeatureManager
    uidGeneratorClass = UIDGenerator
    settingsGetter = SettingsGetter.getInstance()
    if settingsGetter.hasFeaturesSupport():
        uidGeneratorClass = featureManager.getUIDGeneratorClass(uidGeneratorClass)

    uidGenerator = uidGeneratorClass()
    return uidGenerator.generate()


def createShareRequest(source, settingsGetter=None, **overrides):
    settingsGetter = settingsGetter or SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()
    
    shareRequestClass = featureManager.getShareRequestClass(ShareRequest)    
    return shareRequestClass.fromObject(source, **overrides)


def processSharing(shareRequest: ShareRequest, context: ShareExecutionContext):
    """
    Process the file sharing request with the given arguments

    Args:
        shareRequest: Normalized share request
        context: Share execution context

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    args = shareRequest
    reporter = context.reporter
    proxyConfig = context.proxyConfig
    output = reporter.output
    settingsGetter = SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()
    cliMode = settingsGetter.isCLIMode()

    if not args.file:
        output(_('Error: Please select a file or folder to share'))
        return 1

    # Subscribe handler for share link creation with bound args
    handler = partial(onShareLinkCreate, args, reporter=reporter)
    FFLEvent.shareLinkCreate.subscribe(handler)

    try:
        if args.upload:
            if not settingsGetter.hasUploadSupport():
                output(_('Error: Upload functionality requires Upload addon (addons/Upload.py)'))
                return 1

            # Use FeatureManager to check upload permission
            if not featureManager.allowUpload():
                output(featureManager.getUploadUnavailableMessage())
                return 1

        # registered or for testing
        if not featureManager.isRegisteredUser():
            reporter.sendException(_('User email address has been lost'))
            return 1

        # Handle VFS mode (--vfs): Start VFSServer instead of tunnelRunner
        if args.vfs:
            return processVFS(args, reporter=reporter)

        if not cliMode:
            output(_('If a firewall notification appears, please allow the application to connect.\n'))

        # Hint user about folder content change detection for strict mode
        isShareableLocalPath = isinstance(args.file, str) and args.file != "-" and not args.file.startswith("vfs://")
        if isShareableLocalPath and os.path.isdir(args.file):
            output(_('📁 Sharing folder as ZIP - please keep folder contents unchanged during transfer\n'))

        # Get size using Reader abstraction (supports both files and folders)
        # Reader will use its own default if args.fileName is None
        excludeFilter = ExcludeFilter(args.exclude) if args.exclude else None
        progressReporter = ScanFolderProgressReporter.create(args.file)
        reader = SourceReader.build(
            args.file,
            fileName=args.fileName,
            excludeFilter=excludeFilter,
            progressReporter=progressReporter,
            stdinCache=(args.stdinCache != 'off')
        )
        size = reader.size # None means unknown size (e.g., stdin)

        # Show E2EE status if enabled (first line, before establishing tunnel)
        e2eeEnabled = args.e2ee
        if e2eeEnabled:
            output(_('🔐 End-to-end encryption enabled\n'))

        # Detect if Tor proxy is being used (robust verification)
        torDetected = False
        if proxyConfig:
            try:
                if verifyTorProxy(proxyConfig, skipExitListCheck=True):
                    torDetected = True
                    args.forceRelay = True
                    logger.info(
                        f"Tor proxy verified ({proxyConfig['host']}:{proxyConfig['port']}) - "
                        f"enabling --force-relay for strict WebRTC blocking"
                    )
            except RuntimeError as e:
                logger.debug(f"Tor verification failed: {e}")

        # Notify user if Tor privacy mode is active
        if torDetected:
            output(_("🧅 Tor Privacy Mode Active"))

        uploadProcessor = None
        uid = args.uid
        if args.upload:
            from addons.Upload import processUpload
            
            uploadProcessor = processUpload(args, reader, context)
            if uploadProcessor.isDone():
                return uploadProcessor.exitCode
                
            uid = uploadProcessor.uid

        # If we reach here, we need to start local server (either P2P or Pull upload)
        if uid is None:
            uid = generateUID(featureManager)

        userPort = args.port
        port = getAvailablePort(userPort)

        with createTunnelRunner(
            size,
            proxyConfig=proxyConfig,
            onTunnelError=partial(
                reporter.sendException,
                errorPrefix=_('Unable to create tunnel by your tunnel configuration.')
            ),
        ) as tunnelRunner:
            tunnelType = tunnelRunner.getTunnelType()
            if tunnelType != "default":
                output(_('Using tunnel: {tunnelType}').format(tunnelType=tunnelType))

            # Show proxy status for tunnel connections
            proxyInfo = tunnelRunner.getProxyInfo()
            if proxyInfo:
                output(_('Establishing tunnel connection via proxy {proxyInfo}...\n').format(
                    proxyInfo=proxyInfo))
            else:
                output(_('Establishing tunnel connection...\n'))

            domain, tunnelLink = tunnelRunner.start(port)
            link = f"{tunnelLink}{uid}"

            # Determine recipient auth mode (P2P only; pull-upload uses server-side auth)
            recipientAuth = RecipientAuth.createFromArgs(args.toDict())

            # Determine handler class and setup link
            if uploadProcessor:
                try:
                    handlerClass = uploadProcessor.getDownloadHandlerClass(link, uid)
                except RuntimeError as uploadError:
                    output(_('Upload failed: {error}').format(error=str(uploadError)))
                    reporter.sendException(str(uploadError))
                    return 1
            else:
                # P2P mode
                handlerClass = DownloadHandler

                output(_("Please share the link below with the person you'd like to share the file with."))
                output(f'{link}\n')
                if not args.disableClipboard:
                    copy2Clipboard(f'{link}')

                shareLinkData = {
                    'uid': uid,
                    'link': link,
                    'filePath': args.file,
                    'contentName': reader.contentName,
                    'fileSize': size,
                    'tunnelType': tunnelType,
                    'e2ee': e2eeEnabled,
                    'reader': reader,
                    'recipientAuth': recipientAuth,
                    'upload': args.upload,
                }
                FFLEvent.shareLinkCreate.trigger(**shareLinkData)
                reporter.shareLinkCreated(**shareLinkData)

                output(_('Please keep the application running so the recipient can download the file.'))
                if cliMode:
                    output(_('Press Ctrl+C to terminate the program when done.\n'))
                else:
                    output('')

            try:
                # Get maxDownloads and timeout values
                maxDownloads = args.maxDownloads
                timeout = args.timeout

                # Get enhanced handlers from FeatureManager if Features addon is available
                webRTCManagerClass = WebRTCManager
                if settingsGetter.hasFeaturesSupport():
                    handlerClass = featureManager.getDownloadHandlerClass(handlerClass)
                    webRTCManagerClass = featureManager.getWebRTCManagerClass(
                        webRTCManagerClass, forceRelay=args.forceRelay
                    )
                else:
                    if torDetected:
                        # Tor mode without Features addon: use DummyWebRTCManager to totally block WebRTC
                        webRTCManagerClass = DummyWebRTCManager

                authPassword = args.authPassword or os.getenv('FFL_AUTH_PASSWORD')
                authUser = args.authUser if authPassword else None
                # Show auth info if enabled (password enables auth)
                if authPassword:
                    output(_('Authentication enabled - Username: {authUser}\n').format(authUser=authUser))

                if recipientAuth.isEnabled():
                    if recipientAuth.requiresPickup():
                        output(_('Pickup code: {code}\n').format(code=recipientAuth.pickupCode))

                # WebRTC default state: disabled by --force-relay flag
                defaultWebRTC = not args.forceRelay

                # Create server configuration
                serverConfig = ServerConfig(
                    maxDownloads=maxDownloads,
                    timeout=timeout,
                    authUser=authUser,
                    authPassword=authPassword,
                    defaultWebRTC=defaultWebRTC,
                    e2eeEnabled=e2eeEnabled,
                    torEnabled=torDetected,
                    recipientAuth=recipientAuth,
                )

                # Create server with enhanced handler and WebRTC manager
                # Reader provides file and directory information
                server = createServer(reader, port, uid, domain, handlerClass, webRTCManagerClass, serverConfig)
                reporter.serverCreated(server, uid=uid)

                threading.Thread(target=server.serve_forever, daemon=True, name='http-server').start()
                try:
                    server._doneEvent.wait()
                finally:
                    server.shutdown()

                if server.error:
                    logger.error("Server encountered an error during file sharing")
                    raise ChildProcessError()

            except KeyboardInterrupt:
                output(_('\nExiting on user request (Ctrl+C)...'))

                # Trigger applicationInterrupted event
                FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')

                # Clean exit without stack trace - context manager will handle cleanup
                return 0
            except Exception as e:
                raise e

            # If we used pull upload, publish the link after server ends
            if uploadProcessor:
                link = uploadProcessor.publish()
                if not link: # !?
                    reporter.sendException(_('Unable to get uploaded link'))
                    return 1

                shareLinkData = {
                    'uid': uid,
                    'link': link,
                    'filePath': args.file,
                    'contentName': reader.contentName,
                    'fileSize': size,
                    'tunnelType': tunnelType,
                    'e2ee': e2eeEnabled,
                    'reader': reader,
                    'recipientAuth': recipientAuth,
                    'upload': args.upload,
                }
                FFLEvent.shareLinkCreate.trigger(**shareLinkData)
                reporter.shareLinkCreated(**shareLinkData)
                return 0

    except KeyboardInterrupt:
        output(_('\nExiting on user request (Ctrl+C)...'))
        FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')
        # Ensure clean exit
        return 0
    finally:
        FFLEvent.shareLinkCreate.unsubscribe(handler)

    # Default success return for normal P2P completion
    return 0
