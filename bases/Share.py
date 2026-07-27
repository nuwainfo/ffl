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

import json
import os
import threading

import segno

from dataclasses import InitVar, dataclass, field, fields
from enum import IntEnum
from typing import Any, Callable, Optional, Protocol
from datetime import datetime, timezone

from bases.FileSystems import ExcludeFilter
from bases.Kernel import FFLEvent, UIDGenerator, getLogger
from bases.Progress import Progress
from bases.Readers import SourceReader, SourceReaderProgressReporter
from bases.Settings import (
    AbstractUser,
    DEFAULT_AUTH_USER_NAME,
    DEFAULT_UPLOAD_DURATION,
    SettingsGetter,
    ShareMode,
)
from bases.Tor import verifyTorProxy
from bases.VFS import processVFS
from bases.Utils import (
    DataclassDictMixin,
    ProxyConfig,
    flushPrint,
    formatSize,
)
from bases.I18n import _

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


class ShareStatus(IntEnum):
    CREATING = 1
    ONLINE = 2
    COMPLETED = 3
    STOPPED = 4
    CRASHED = 5
    PAUSED = 6


@dataclass
class ShareSession(DataclassDictMixin):
    """All state for one share lifecycle, independent of any specific server implementation."""

    id: str
    filePaths: list
    createdAt: str
    status: ShareStatus = ShareStatus.CREATING
    link: Optional[str] = None
    port: Optional[int] = None
    downloads: int = 0
    error: Optional[str] = None
    pauseSupported: bool = False

    @classmethod
    def getSerializableFields(cls):
        return fields(ShareSession)

    @classmethod
    def generateUID(cls):
        # Get UIDGenerator from FeatureManager
        uidGeneratorClass = UIDGenerator
        settingsGetter = SettingsGetter.getInstance()
        if settingsGetter.hasFeaturesSupport():
            uidGeneratorClass = settingsGetter.getFeatureManager().getUIDGeneratorClass(uidGeneratorClass)

        return uidGeneratorClass().generate()
        
    @classmethod
    def create(cls, filePaths, sessionClass=None):
        sessionClass = sessionClass or cls
        return sessionClass(
            id=sessionClass.generateUID(),
            filePaths=filePaths if isinstance(filePaths, list) else [filePaths],
            createdAt=datetime.now().isoformat(),
        )

    @property
    def uid(self):
        return self.id

    @uid.setter
    def uid(self, value):
        self.id = value

    @property
    def downloadCount(self):
        return self.downloads

    @downloadCount.setter
    def downloadCount(self, value):
        self.downloads = value

    def stop(self):
        if self.status not in (ShareStatus.COMPLETED, ShareStatus.CRASHED):
            self.status = ShareStatus.STOPPED


@dataclass
class ShareReporter:
    outputCallback: Callable[[str], None]
    exceptionCallback: Optional[Callable[..., None]] = None
    shareLinkCallback: Optional[Callable[..., None]] = None
    encryptionKeyCallback: Optional[Callable[..., None]] = None
    serverCreatedCallback: Optional[Callable[..., None]] = None
    vfsServerCreatedCallback: Optional[Callable[..., None]] = None

    def output(self, text: str):
        self.outputCallback(text)

    def notifyShareCreated(self, uid, name, fileSize, shareMode):
        FFLEvent.shareCreated.trigger(
            uid=uid,
            name=name,
            fileSize=fileSize or 0,
            shareMode=shareMode,
            occurredAt=datetime.now(timezone.utc),
        )

    def notifyShareStarted(self, uid):
        FFLEvent.shareStarted.trigger(uid=uid, occurredAt=datetime.now(timezone.utc))

    def notifyShareAvailable(self, uid, shareResult):
        FFLEvent.shareAvailable.trigger(
            uid=uid,
            name=shareResult.contentName,
            fileSize=shareResult.fileSize or 0,
            shareMode=shareResult.uploadMode,
            link=shareResult.link,
            occurredAt=datetime.now(timezone.utc),
        )

    def notifyShareCompleted(self, uid):
        FFLEvent.shareCompleted.trigger(uid=uid, occurredAt=datetime.now(timezone.utc))

    def notifyShareStopped(self, uid, downloads=0):
        FFLEvent.shareStopped.trigger(
            uid=uid,
            downloads=downloads,
            occurredAt=datetime.now(timezone.utc),
        )

    def notifyShareFailed(self, uid, error):
        FFLEvent.shareFailed.trigger(
            uid=uid,
            error=str(error),
            occurredAt=datetime.now(timezone.utc),
        )

    def notifyEncryptionKeyAvailable(self, encryptionKey):
        if not self.encryptionKeyCallback:
            return False

        self.encryptionKeyCallback(encryptionKey=encryptionKey)
        return True

    def notifyShareLinkCreated(self, shareResult, uid=None, reader=None):
        shareResultData = shareResult.toDict()
        shareResultData['filePath'] = shareResultData['file']
        FFLEvent.shareLinkCreate.trigger(
            uid=uid,
            reader=reader,
            upload=(shareResultData['uploadMode'] == ShareMode.SERVER),
            **shareResultData,
        )

        if self.shareLinkCallback:
            self.shareLinkCallback(shareResult=shareResult, uid=uid, reader=reader)

    def notifyServerCreated(self, server, uid=None):
        session = server.getSession(uid) if uid else server.getDefaultSession()
        configData = session.config.toDict()
        configData['authEnabled'] = configData.pop('authPassword') is not None
        configData['webrtcEnabled'] = configData.pop('defaultWebRTC')

        FFLEvent.serverStarting.trigger(
            uid=session.uid,
            port=server.server_address[1],
            domain=session.domain,
            **configData,
        )

        if self.serverCreatedCallback:
            self.serverCreatedCallback(server=server)

    def notifyVFSServerCreated(self, vfsServer, link=None, uid=None):
        FFLEvent.serverStarting.trigger(
            uid=uid,
            port=vfsServer.actualPort,
            domain=vfsServer.host,
            maxDownloads=0,
            timeout=0,
            authEnabled=bool(vfsServer.authPassword),
            e2eeEnabled=False,
            torEnabled=False,
            webrtcEnabled=False,
            link=link,
            tunnelType='vfs',
        )

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
class ShareResult(DataclassDictMixin):
    file: str
    contentName: str
    fileSize: Optional[int]
    uploadMode: str
    tunnelType: Optional[str]
    link: str
    e2ee: bool
    pickupCode: Optional[str] = None
    pubkeyEnabled: bool = False
    user: Optional[AbstractUser] = None
    recipientAuth: InitVar[Any] = None

    def __post_init__(self, recipientAuth):
        if self.fileSize is None:
            self.fileSize = -1

        if not self.tunnelType:
            self.tunnelType = "default"

        if recipientAuth:
            if self.pickupCode is None and recipientAuth.requiresPickup():
                self.pickupCode = recipientAuth.pickupCode

            if not self.pubkeyEnabled:
                self.pubkeyEnabled = recipientAuth.requiresPubkey()


class RuntimeProtocol(Protocol):

    def run(self, shareRequest: ShareRequest, context, *, reader, size, torDetected: bool):
        raise NotImplementedError


@dataclass
class ShareExecutionContext:
    reporter: ShareReporter
    session: ShareSession
    runtime: Optional[RuntimeProtocol] = None
    interactionHandler: Any = None
    result: Optional[ShareResult] = None
    allowUserInteraction: bool = True
    proxyConfig: Optional[ProxyConfig] = None
    stopEvent: threading.Event = field(default_factory=threading.Event)
    pauseEvent: threading.Event = field(default_factory=threading.Event)
    paused: bool = False

    def isStopRequested(self):
        return self.stopEvent.is_set()

    def requestPause(self):
        self.pauseEvent.set()

    def isPauseRequested(self):
        return self.pauseEvent.is_set()

    def markPaused(self):
        self.paused = True

    def resetForResume(self):
        self.stopEvent.clear()
        self.pauseEvent.clear()
        self.paused = False
        self.result = None

    def createShareResult(self, *args, **kwargs):
        self.result = ShareResult(*args, **kwargs)
        return self.result


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

    def handleShareLinkCreated(**eventData):
        if context.session and eventData.get('uid') != context.session.uid:
            return

        shareResult = context.result
        link = shareResult.link

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
                    # Display QR code in terminal
                    output(_('\nQR Code:\n'))
                    qr.terminal(compact=True)
                    output('')
            except Exception as e:
                output(_('Error generating QR code: {error}').format(error=e))
                # It's ok only not generate QR code.

        # Handle --json flag
        if args.json:
            try:
                # Write to a temp file and rename into place so readers polling
                # for the file's existence never observe a truncated/empty file.
                tempJsonPath = f'{args.json}.tmp{os.getpid()}'
                with open(tempJsonPath, 'w', encoding='utf-8') as fileHandle:
                    json.dump(shareResult.toDict(snakeKey=True), fileHandle, indent=2)
                    
                os.replace(tempJsonPath, args.json)

                output(_('Sharing information saved to {jsonFile}').format(jsonFile=args.json))
            except Exception as e:
                output(_('Failed to write JSON file: {error}').format(error=e))
                reporter.sendException(e)

    if not args.file:
        output(_('Error: Please select a file or folder to share'))
        return 1

    # Subscribe handler for share link creation with bound args
    FFLEvent.shareLinkCreate.subscribe(handleShareLinkCreated)
    try:
        if args.upload:
            if not settingsGetter.hasUploadSupport():
                output(_('Error: Upload functionality requires Upload addon (addons/Upload.py)'))
                return 1

            # Use FeatureManager to check upload permission
            if not featureManager.allowUpload():
                output(featureManager.getUploadUnavailableMessage())
                return 1

        if context.isStopRequested():
            return 0

        # registered or for testing
        if not featureManager.isRegisteredUser():
            reporter.sendException(_('User email address has been lost'))
            return 1

        # Handle VFS mode (--vfs): Start VFSServer instead of tunnelRunner
        if args.vfs:
            return processVFS(args, context)

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

        if context.isStopRequested():
            return 0

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

        if context.isStopRequested():
            return 0

        return context.runtime.run(shareRequest, context, reader=reader, size=size, torDetected=torDetected)

    except KeyboardInterrupt:
        output(_('\nExiting on user request (Ctrl+C)...'))
        FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')
        # Ensure clean exit
        return 0
    finally:
        FFLEvent.shareLinkCreate.unsubscribe(handleShareLinkCreated)
