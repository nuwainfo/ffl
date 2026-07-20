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

import argparse
import json
import os
import logging
import logging.config
import platform

from dataclasses import MISSING, fields

from bases.Kernel import (
    LOG_LEVEL_MAPPING, PUBLIC_VERSION, getLogger, FFLEvent, configureGlobalLogLevel, AddonsManager, StorageLocator
)
from bases.Settings import DEFAULT_AUTH_USER_NAME, DEFAULT_UPLOAD_DURATION, SettingsGetter
from bases.Utils import flushPrint, checkVersionCompatibility, getEnv, parseProxyString, setupProxyEnvironment
from bases.Hook import HookEventForwarder
from bases.Daemon import ProcessDaemonManager
from bases.Upgrade import performUpgrade
from bases.Auth import PICKUP_CODE_LENGTH, PUBKEY_PUBLIC_EXT, PUBKEY_PRIVATE_EXT, RecipientAuth
from bases.Share import ShareRequest
from bases.crypto import CryptoInterface
from bases.I18n import _

logger = getLogger(__name__)


def loadEnvFile():
    """
    Load environment variables from .env file using StorageLocator.
    Searches for .env file in standard locations and sets variables in os.environ.
    Only sets variables that are not already defined in os.environ.
    """
    storageLocator = StorageLocator.getInstance()
    envFilePath = storageLocator.findConfig('.env')

    if not os.path.exists(envFilePath):
        return

    try:
        flushPrint(_('Loading .env file from: {envFilePath}').format(envFilePath=envFilePath))
        loadedCount = 0

        with open(envFilePath, 'r', encoding='utf-8') as f:
            for lineNum, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE format
                if '=' not in line:
                    flushPrint(_('Warning: .env line {lineNum}: Invalid format (missing =): {line}').format(
                        lineNum=lineNum, line=line
                    ))
                    continue

                key, _sep, value = line.partition('=')
                key = key.strip()
                value = value.strip()

                if not key:
                    flushPrint(_('Warning: .env line {lineNum}: Empty key').format(lineNum=lineNum))
                    continue

                # Remove quotes if present (both single and double)
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                # Only set if not already in environment (environment takes precedence)
                if key not in os.environ:
                    os.environ[key] = value
                    loadedCount += 1
                else:
                    logger.debug(f'.env: Skipped {key} (already set in environment)')

        flushPrint(_('Loaded {loadedCount} environment variables from .env').format(loadedCount=loadedCount))

    except Exception as e:
        flushPrint(_('Error: Unexpected error loading .env file: {error}').format(error=e))
        logger.error(f'Unexpected error loading .env file: {e}', exc_info=True)


def configureLogging(logLevel):
    """Configure logging level for the application using Kernel's centralized configuration or config file

    Priority order:
    1. logLevel parameter (from --log-level CLI argument)
    2. FFL_LOGGING_LEVEL environment variable
    3. Default to None (no configuration change)

    Both logLevel and FFL_LOGGING_LEVEL can be:
    - A logging level name (DEBUG, INFO, WARNING, ERROR)
    - A path to a logging configuration JSON file
    """

    def suppressNoisyLogger():
        logging.getLogger('urllib3').setLevel(logging.INFO)
        logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)
        logging.getLogger('sentry_sdk').setLevel(logging.INFO)
        logging.getLogger('asyncio').setLevel(logging.ERROR)

    # Priority: CLI argument > environment variable > None (no change)
    if logLevel is None:
        logLevel = getEnv('FFL_LOGGING_LEVEL', None)

    # If still None, skip configuration (keep existing behavior)
    if logLevel is None:
        suppressNoisyLogger()
        return None

    # Check if logLevel is a file path
    if os.path.isfile(logLevel):
        try:
            # Load logging configuration from JSON file
            with open(logLevel, 'r') as configFile:
                configDict = json.load(configFile)

            # Apply the dictionary configuration
            logging.config.dictConfig(configDict)
            logger.info(f"Logging configured from file: {logLevel}")
            suppressNoisyLogger()
            return logLevel

        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            flushPrint(_('Failed to load logging config from {logLevel}: {error}').format(logLevel=logLevel, error=e))
            flushPrint(_('Falling back to default logging level configuration'))

    # Map string levels to logging constants for standard level names
    levelMapping = LOG_LEVEL_MAPPING

    # Check if it's a standard logging level
    if logLevel.upper() in levelMapping:
        level = levelMapping[logLevel.upper()]
        # Use Kernel's centralized logging configuration
        configureGlobalLogLevel(level)
        logger.info(f"Logging level set to {logLevel}")
    else:
        logger.warning(f"Invalid logging level '{logLevel}', using WARNING as default")
        configureGlobalLogLevel(logging.WARNING)

    # Suppress noisy third-party loggers even in DEBUG mode
    suppressNoisyLogger()

    return logLevel


def showVersion():
    """Display version information and enabled addons"""
    flushPrint(_('FastFileLink v{version}').format(version=PUBLIC_VERSION))
    flushPrint("")

    # Check version compatibility with server
    serverIsNewer, isCompatible, serverVersion, minimumVersion = checkVersionCompatibility()

    if serverIsNewer and isCompatible:
        flushPrint(_('🔄 Update available!'))
        flushPrint(_('   Your version: {version}').format(version=PUBLIC_VERSION))
        flushPrint(_('   Latest version: {serverVersion}').format(serverVersion=serverVersion))
        flushPrint(_('   Consider updating for the latest features and improvements.'))
        flushPrint("")

    if not isCompatible:
        flushPrint(_('⚠️ VERSION INCOMPATIBLE!'))
        flushPrint(_('   Your version: {version}').format(version=PUBLIC_VERSION))
        flushPrint(_('   Server Minimum required: {minimumVersion}').format(minimumVersion=minimumVersion))
        flushPrint(_('   Latest version: {serverVersion}').format(serverVersion=serverVersion))
        flushPrint(_('   Please update to continue using the service.'))
        flushPrint("")

    # Get addons manager and show enabled addons
    addonsManager = AddonsManager.getInstance()
    enabledAddons = addonsManager.getEnabledAddons()
    failedAddons = {name: (error, excClass) for name, error, excClass in addonsManager.getFailedAddons()}

    if enabledAddons:
        flushPrint(_('Enabled addons:'))
        for addon in enabledAddons:
            if addonsManager.isAddonLoaded(addon):
                status = _('[OK] Loaded')
            elif addon in failedAddons:
                error, excClass = failedAddons[addon]
                # Don't show ModuleNotFoundError failures (addon doesn't exist)
                if excClass is not None and issubclass(excClass, ModuleNotFoundError):
                    continue

                status = _('[FAIL] Failed to load')
            else:
                # Addon was neither loaded nor failed (shouldn't happen, but handle it)
                status = _('[UNKNOWN] Not loaded')

            flushPrint(f"  {addon:<12} {status}")
    else:
        flushPrint(_('No addons available'))

    flushPrint("")
    uname = platform.uname()
    flushPrint(_('Architecture: {system} {release} {machine} - {version} ({processor})').format(
        system=uname.system, release=uname.release, machine=uname.machine,
        version=uname.version, processor=uname.processor
    ))

    # Get dynamic support URL based on GUI support and user level
    settingsGetter = SettingsGetter.getInstance()
    supportURL = settingsGetter.getSupportURL()
    flushPrint(_('Support: {supportURL}').format(supportURL=supportURL))


class ShareCLIArgumentAdapter:
    """Build and extract share CLI arguments from ShareRequest metadata."""

    CLI_METADATA_KEY = 'cli'
    
    RECIPIENT_AUTH_FIELDS = (
        'recipientAuth',
        'pickupCode',
        'recipientPublicKey',
        'recipientEmail',
        'recipientOTPAPIBase',
    )

    VALIDATOR_NAMES = {'int', 'port', 'timeout', 'maxDownloads'}

    @classmethod
    def _buildContext(cls, featureManager):
        uploadChoices = list(featureManager.getUploadRetentionTimes().keys())
        
        return {
            'uploadChoices': uploadChoices if uploadChoices else ['unavailable'],
            'uploadConst': DEFAULT_UPLOAD_DURATION if uploadChoices else 'unavailable',
        }

    @classmethod
    def _createPositiveValidator(cls, fieldName):
        def validatePositive(valueStr):
            try:
                value = int(valueStr)
                if value < 0:
                    raise argparse.ArgumentTypeError(f"{fieldName} {value} cannot be negative")
                    
                return value
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid {fieldName.lower()} value: {valueStr}")

        return validatePositive

    @classmethod
    def _createPortValidator(cls):
        def validatePort(portStr):
            try:
                port = int(portStr)
                if not (1024 <= port <= 65535):
                    raise argparse.ArgumentTypeError(f"Port {port} is out of valid range (1024-65535)")
                    
                return port
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {portStr}")

        return validatePort

    @classmethod
    def _getValidator(cls, validatorName):
        validators = {
            'int': int,
            'port': cls._createPortValidator(),
            'timeout': cls._createPositiveValidator("Timeout"),
            'maxDownloads': cls._createPositiveValidator("Max downloads"),
        }
    
        return validators[validatorName]

    @classmethod
    def _iterShareFields(cls, shareRequestClass, fieldNames=None):
        for dataclassField in fields(shareRequestClass):
            if fieldNames and dataclassField.name not in fieldNames:
                continue

            cliMetadata = dataclassField.metadata.get(cls.CLI_METADATA_KEY)
            if cliMetadata:
                yield dataclassField, cliMetadata

    @classmethod
    def _resolveOptionValue(cls, value, context):
        if callable(value):
            return value(context)

        if isinstance(value, str) and value in cls.VALIDATOR_NAMES:
            return cls._getValidator(value)

        return value

    @classmethod
    def _buildArgumentOptions(cls, dataclassField, cliMetadata, context):
        flags = cliMetadata['flags']
        options = {
            key: cls._resolveOptionValue(value, context)
            for key, value in cliMetadata['options'].items()
        }

        if dataclassField.default is not MISSING:
            options.setdefault('default', dataclassField.default)
        elif dataclassField.default_factory is not MISSING:
            options.setdefault('default', dataclassField.default_factory())
        else:
            pass

        if flags and flags[0].startswith('-'):
            options.setdefault('dest', dataclassField.name)

        return flags, options

    @classmethod
    def addShareArguments(cls, parser, featureManager):
        shareGroup = parser.add_argument_group('share')
        context = cls._buildContext(featureManager)
        shareRequestClass = featureManager.getShareRequestClass(ShareRequest)

        for dataclassField, cliMetadata in cls._iterShareFields(shareRequestClass):
            flags, options = cls._buildArgumentOptions(dataclassField, cliMetadata, context)
            shareGroup.add_argument(*flags, **options)

        FFLEvent.cliArgumentsShareOptionsRegister.trigger(parser=shareGroup)
        return shareGroup

    @classmethod
    def addRecipientAuthArguments(cls, parser):
        for dataclassField, cliMetadata in cls._iterShareFields(ShareRequest, fieldNames=cls.RECIPIENT_AUTH_FIELDS):
            flags, options = cls._buildArgumentOptions(dataclassField, cliMetadata, context={})
            parser.add_argument(*flags, **options)

    @classmethod
    def getShareActionGroup(cls, shareSubparser):
        for group in shareSubparser._action_groups:
            if group.title == 'share':
                return group

        raise RuntimeError('Share action group not found')

    @classmethod
    def createDaemonShareConfig(cls, args, shareSubparser):
        shareGroup = cls.getShareActionGroup(shareSubparser)
        shareDests = {
            action.dest
            for action in shareGroup._group_actions
            if action.dest and action.dest != argparse.SUPPRESS
        }
    
        argsDict = vars(args)
        config = {dest: argsDict[dest] for dest in shareDests if dest in argsDict}
        
        if 'uploadConfirmed' in argsDict:
            config['uploadConfirmed'] = argsDict['uploadConfirmed']
            
        return config

    @classmethod
    def serializeShareRequest(cls, shareRequest):
        argv = []

        for dataclassField, cliMetadata in cls._iterShareFields(type(shareRequest)):
            value = getattr(shareRequest, dataclassField.name)
            argv.extend(cls._serializeFieldValue(dataclassField, cliMetadata, value))

        return argv

    @classmethod
    def _serializeFieldValue(cls, dataclassField, cliMetadata, value):
        flags = cliMetadata['flags']
        options = cliMetadata['options']

        if not flags:
            return []

        if not flags[0].startswith('-'):
            if value is None:
                return []

            if isinstance(value, (list, tuple)):
                return [str(item) for item in value]

            return [str(value)]

        if options.get('action') == 'store_true':
            return [flags[0]] if value else []

        if value is None:
            return []

        defaultValue = cls._getDefaultValue(dataclassField)
        if defaultValue is not MISSING and value == defaultValue:
            return []

        if 'const' in options and value == options['const']:
            return [flags[0]]

        return [flags[0], str(value)]

    @staticmethod
    def _getDefaultValue(dataclassField):
        if dataclassField.default is not MISSING:
            return dataclassField.default

        if dataclassField.default_factory is not MISSING:
            return dataclassField.default_factory()

        return MISSING


def configureCLIParser():
    """Configure the parser for CLI mode with multi-phase command support using global parent approach

    Returns:
        tuple: (parser, globals_parent, command_names, shareSubparser)
    """
    # Get settings for configuration - import here to avoid circular dependency
    settingsGetter = SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()

    # Validator for log level
    def validateLogLevel(logLevel):
        """Validate log level for argparse"""
        # Allow file paths (they'll be validated later)
        if os.path.exists(logLevel):
            return logLevel

        # Validate log level names
        validLevels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if logLevel.upper() not in validLevels:
            raise argparse.ArgumentTypeError(
                _("Invalid log level '{logLevel}'. Valid levels are: {validLevels}").format(
                    logLevel=logLevel, validLevels=', '.join(validLevels)
                )
            )
        return logLevel.upper()

    # === 1) Global parameters in a parent parser ===
    globalsParent = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    globalsParent.add_argument("--version", action="store_true", help=_("Show version information and enabled addons"))
    globalsParent.add_argument("--cli", action="store_true", help=_("Run in CLI mode without GUI (optional)"))

    globalsParent.add_argument(
        "--log-level",
        type=validateLogLevel,
        help=_(
            "Set logging level (DEBUG, INFO, WARNING, ERROR) or path to logging config JSON file (default: WARNING)"
        ),
        metavar="LEVEL_OR_FILE",
        dest="logLevel"
    )
    globalsParent.add_argument(
        "--proxy",
        help=_(
            "Proxy server for all outbound connections. "
            "Formats: [user:pass@]host:port (defaults to SOCKS5), "
            "socks5[h]://[user:pass@]host:port, http[s]://[user:pass@]host:port. "
            "SOCKS5 proxies work for both tunnel and HTTP requests. "
            "HTTP proxies only work for HTTP requests (not tunnel)"
        ),
        metavar="PROXY",
        dest="proxy"
    )
    globalsParent.add_argument(
        "--hook",
        help=_(
            "Webhook URL for forwarding events to parent process or external service. "
            "Format: http://[user:pass@]host:port/path (e.g., http://app:token@127.0.0.1:12345/events). "
            "Auth credentials are optional but recommended."
        ),
        metavar="WEBHOOK_URL",
        dest="hook"
    )

    # Allow addons to register additional global options
    FFLEvent.cliArgumentsGlobalOptionsRegister.trigger(parser=globalsParent)

    # === 2) Main parser + subparsers; all inherit from globalsParent ===
    parser = argparse.ArgumentParser(
        description=_("FastFileLink makes file sharing fast, simple, and secure."),
        parents=[globalsParent],
        exit_on_error=False,
    )

    # Let addons register their commands
    commandRegistry = {}
    FFLEvent.cliArgumentsCommandsRegister.trigger(parser=parser, commandRegistry=commandRegistry)

    subparsers = parser.add_subparsers(dest='command', help=_('Available commands'))

    # Default 'share' command for file sharing
    shareSubparser = subparsers.add_parser(
        'share',
        help=_('Share a file (default command)'),
        parents=[globalsParent],
        exit_on_error=False
    )
    ShareCLIArgumentAdapter.addShareArguments(shareSubparser, featureManager)

    # Download command for receiving files
    downloadSubparser = subparsers.add_parser(
        'download',
        help=_('Download a file from FastFileLink URL'),
        parents=[globalsParent],
        exit_on_error=False
    )
    downloadSubparser.add_argument(
        "url",
        metavar="URL",
        help=_("FastFileLink URL to download from")
    )
    downloadSubparser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help=_("Output file path (default: use filename from server)")
    )
    downloadSubparser.add_argument(
        "--resume",
        action="store_true",
        help=_("Resume incomplete download (like curl -C), otherwise overwrite existing file")
    )
    downloadSubparser.add_argument(
        "--auth-user",
        help=_("Username for HTTP Basic Authentication (default: '{default}')").format(
            default=DEFAULT_AUTH_USER_NAME),
        metavar="USERNAME",
        default=DEFAULT_AUTH_USER_NAME,
        dest="authUser"
    )
    downloadSubparser.add_argument(
        "--auth-password",
        help=_("Password for HTTP Basic Authentication"),
        metavar="PASSWORD",
        dest="authPassword"
    )
    downloadSubparser.add_argument(
        "--recipient-auth",
        choices=['pickup', 'pubkey', 'pubkey+pickup'],
        default=None,
        help=_("Recipient verification mode when downloading a protected file"),
        dest="recipientAuth"
    )
    downloadSubparser.add_argument(
        "--pickup-code",
        help=_("Pickup code to present when downloading (use with --recipient-auth pickup or pubkey+pickup)"),
        metavar="CODE",
        dest="pickupCode"
    )
    downloadSubparser.add_argument(
        "--recipient-private-key",
        help=_(
            "Path to recipient's RSA private key file ({ext}) for pubkey auth"
        ).format(ext=PUBKEY_PRIVATE_EXT),
        metavar="FILE",
        dest="recipientPrivateKey"
    )
    downloadSubparser.add_argument(
        "--stdout",
        action="store_true",
        default=False,
        help=_("Write downloaded content to stdout instead of a file (useful for piping, e.g. | tar -xf -)"),
        dest="stdout"
    )

    # Upgrade command for self-updating
    upgradeSubparser = subparsers.add_parser(
        'upgrade',
        help=_('Upgrade to latest version or specified version'),
        parents=[globalsParent],
        exit_on_error=False
    )
    upgradeSubparser.add_argument(
        "target",
        nargs='?',
        help=_("Target binary path to upgrade (for development mode), or version (e.g., v3.7.5)")
    )
    upgradeSubparser.add_argument(
        "version",
        nargs='?',
        help=_("Target version when binary path is specified (default: latest)")
    )

    # Keypair generation command
    keygenSubparser = subparsers.add_parser(
        'keygen',
        help=_('Generate an RSA-2048 keypair for --recipient-auth pubkey'),
        parents=[globalsParent],
        exit_on_error=False
    )
    keygenSubparser.add_argument(
        "--name",
        default="recipient",
        help=_("Base name for keypair files (default: recipient → recipient{pub} + recipient{priv})").format(
            pub=PUBKEY_PUBLIC_EXT, priv=PUBKEY_PRIVATE_EXT),
        metavar="NAME",
        dest="keypairName"
    )
    keygenSubparser.add_argument(
        "--share",
        action="store_true",
        default=False,
        help=_(
            "Share the generated private key immediately after generation "
            "(private key can only be downloaded once, then auto-deleted; "
            "recommended: add --recipient-auth pickup or --recipient-auth pubkey)"
        ),
        dest="keypairShare"
    )
    keygenSubparser.add_argument(
        "--json",
        metavar="JSON_FILE",
        help=_("Output link and settings to a JSON file (use with --share)"),
    )

    ShareCLIArgumentAdapter.addRecipientAuthArguments(keygenSubparser)

    # Daemon management command
    daemonSubparser = subparsers.add_parser(
        'daemon',
        help=_('Manage background daemon for multi-session sharing'),
        parents=[globalsParent],
        exit_on_error=False
    )
    daemonSubparser.add_argument(
        '--stop',
        action='store_true',
        default=False,
        help=_('Stop the daemon and all managed shares'),
        dest='daemonStop'
    )
    daemonSubparser.add_argument(
        '--status',
        action='store_true',
        default=False,
        help=_('Show daemon status'),
        dest='daemonStatus'
    )
    daemonSubparser.add_argument(
        '--force',
        action='store_true',
        default=False,
        help=_('Force stop the daemon (use with --stop)'),
        dest='force'
    )
    # Internal flag: ProcessDaemonManager._startDaemon() passes --start when spawning the background
    # daemon subprocess so that subprocess enters the server loop (DaemonServer().start()).
    # Hidden from --help because users should never call this directly.
    daemonSubparser.add_argument(
        '--start',
        action='store_true',
        default=False,
        help=argparse.SUPPRESS,
        dest='daemonRunServer'
    )

    # Shares management command
    sharesSubparser = subparsers.add_parser(
        'shares',
        help=_('Manage daemon-managed shares'),
        parents=[globalsParent],
        exit_on_error=False
    )
    sharesActions = sharesSubparser.add_subparsers(dest='sharesAction')
    sharesActions.add_parser('list', help=_('List active managed shares'), parents=[globalsParent], exit_on_error=False)
    sharesStopParser = sharesActions.add_parser(
        'stop', help=_('Stop a specific share'), parents=[globalsParent], exit_on_error=False
    )
    sharesStopParser.add_argument('id', metavar='ID', nargs='?', help=_('Share ID to stop'))
    sharesStopParser.add_argument(
        '--all',
        action='store_true',
        help=_('Stop all managed shares'),
        dest='all'
    )
    sharesOpenParser = sharesActions.add_parser(
        'open', help=_('Open a share link in the browser'), parents=[globalsParent], exit_on_error=False
    )
    sharesOpenParser.add_argument('id', metavar='ID', help=_('Share ID to open'))
    sharesQrParser = sharesActions.add_parser(
        'qr', help=_('Show the share QR code in the terminal'), parents=[globalsParent], exit_on_error=False
    )
    sharesQrParser.add_argument('id', metavar='ID', help=_('Share ID to render as QR'))

    # Let addons create their command parsers (same pattern - inherit globalsParent)
    for cmdName, cmdConfig in commandRegistry.items():
        cmdParser = subparsers.add_parser(cmdName, help=cmdConfig['help'], parents=[globalsParent], exit_on_error=False)
        cmdConfig['setupFunction'](cmdParser)

    # Collect all valid subcommand names (including core commands)
    commandNames = {'share', 'download', 'upgrade', 'keygen', 'daemon', 'shares', *commandRegistry.keys()}
    return parser, globalsParent, commandNames, shareSubparser


def handleHookArgument(hook, result=None):
    if not hook:
        return result

    hookEventForwarder = HookEventForwarder.getInstance()
    hookEventForwarder.configure(hook)
    return result


def handleProxyArgument(proxy, result):
    if not proxy:
        return result

    proxyConfig = parseProxyString(proxy)
    if not proxyConfig:
        flushPrint(_('Error: Invalid proxy format: {proxy}').format(proxy=proxy))
        result['exitCode'] = 1
        return result

    # Setup HTTP_PROXY/HTTPS_PROXY for requests library
    setupProxyEnvironment(proxyConfig)

    # Store proxyConfig to pass to tunnel creation flow
    result['proxyConfig'] = proxyConfig
    return result


def processGlobalArguments(globalArgs):
    """
    Process global arguments before command processing.
    This handles global options that affect the entire application or cause early exits.

    Args:
        globalArgs: Parsed global arguments from globalsParent parser

    Returns:
        dict: Returns dict with 'exitCode' (int or None) and 'proxyConfig' (dict or None)
    """
    result = {'exitCode': None, 'proxyConfig': None}

    # Configure logging level (checks --log-level argument and FFL_LOGGING_LEVEL env var)
    configureLogging(globalArgs.logLevel)

    # Initialize hook client if --hook was specified
    handleHookArgument(globalArgs.hook, result)

    # Handle --proxy option
    handleProxyArgument(globalArgs.proxy, result)

    # Let addons handle global options (like --enable-reporting)
    argPolicy = {'exitCode': None}
    FFLEvent.cliArgumentsGlobalOptionsStore.trigger(args=globalArgs, argPolicy=argPolicy)

    if argPolicy['exitCode'] is not None:
        result['exitCode'] = argPolicy['exitCode']
        return result

    # Handle --version early exit
    if globalArgs.version:
        showVersion()
        result['exitCode'] = 0
        return result

    return result


def _handleKeygenCommand(args, shareSubparser):
    """Generate RSA-2048 keypair files for --recipient-auth pubkey."""
    name = args.keypairName
    privPath = f"{name}{PUBKEY_PRIVATE_EXT}"
    pubPath = f"{name}{PUBKEY_PUBLIC_EXT}"

    cryptoInterface = CryptoInterface()
    privKey, pubKey = cryptoInterface.generateRSAKeyPair()
    privPem = cryptoInterface.serializeRSAPrivateKeyPKCS8(privKey)
    pubPem = cryptoInterface.serializeRSAPublicKey(pubKey)

    with open(privPath, 'w', encoding='utf-8') as f:
        f.write(privPem)
    with open(pubPath, 'w', encoding='utf-8') as f:
        f.write(pubPem)

    flushPrint(_('Generated RSA-2048 keypair:'))
    flushPrint(_('  Private key : {path}').format(path=privPath))
    flushPrint(_('  Public key  : {path}  ← share with sender').format(path=pubPath))

    if not args.keypairShare:
        flushPrint(_('Share the public key file with the sender who will use:'))
        flushPrint(_('  ffl share file.bin --recipient-auth pubkey --recipient-public-key {pub}').format(pub=pubPath))
        return 0

    # --share mode: fill all share arg defaults from shareSubparser, then overlay
    # keypair-specific values and force constraints. This way new share args
    # automatically get their correct defaults without manual maintenance here.
    keypairJson = args.json
    keypairRecipientAuth = args.recipientAuth
    keypairPickupCode = args.pickupCode
    keypairRecipientPublicKey = args.recipientPublicKey
    keypairRecipientEmail = args.recipientEmail
    keypairRecipientOTPAPIBase = args.recipientOTPAPIBase

    shareArgs = shareSubparser.parse_args([privPath])
    args.__dict__.update(vars(shareArgs))

    # parse_args() called directly on the child subparser (above) never sets
    # 'command' -- that dest is populated by the parent parser's subparsers
    # action during normal dispatch, which this bypasses. Without this, the
    # caller's `if args.command == 'share'` check never fires and the process
    # exits after printing the banner without ever starting the share.
    args.command = 'share'
    args.maxDownloads = 1  # forced: private key is one-time use
    args.json = keypairJson
    args.recipientAuth = keypairRecipientAuth
    args.pickupCode = keypairPickupCode
    args.recipientPublicKey = keypairRecipientPublicKey
    args.recipientEmail = keypairRecipientEmail
    args.recipientOTPAPIBase = keypairRecipientOTPAPIBase

    # Validate share arguments now that defaults are set
    validationResult = validateShareArguments(args)
    if validationResult is not None:
        return validationResult

    # Delete private key file from disk after successful download
    def deletePrivKeyAfterDownload(**kwargs):
        try:
            os.remove(privPath)
            flushPrint(_('Private key deleted: {path}').format(path=privPath))
        except OSError as e:
            logger.warning(f"Failed to delete private key {privPath}: {e}")

    FFLEvent.downloadCompleted.subscribe(deletePrivKeyAfterDownload)
    FFLEvent.webrtcTransferCompleted.subscribe(deletePrivKeyAfterDownload)

    flushPrint(_('Sharing private key (download once, then auto-deleted).'))
    if not args.recipientAuth:
        flushPrint(_('Tip: use --recipient-auth pickup or --recipient-auth pubkey to restrict who can download.\n'))
    else:
        flushPrint('')
    return None  # hand off to processSharing


def processArgumentsAndCommands(args, shareSubparser=None, proxyConfig=None):
    """
    Process parsed arguments and handle command execution through addons.
    This handles all commands except 'share' (which is handled by processFileSharing).
    Used primarily in CLI mode.

    Returns:
        int or None: Exit code if command was handled, None if should continue to processFileSharing
    """
    # Handle core upgrade command
    command = getattr(args, 'command', None)

    if command == 'keygen':
        return _handleKeygenCommand(args, shareSubparser)

    if command == 'upgrade':
        # Parse arguments: support both "upgrade <version>" and "upgrade <binary_path> <version>"
        target = args.target
        version = args.version

        # Determine if target is a binary path or a version
        targetBinary = None
        targetVersion = None

        if target:
            # Check if target looks like a file path (contains path separators)
            if '/' in target or '\\' in target or os.path.exists(target):
                # target is a binary path
                targetBinary = target
                targetVersion = version if version and version != 'latest' else None
            else:
                # target is a version string
                targetVersion = target if target != 'latest' else None

        success = performUpgrade(targetVersion=targetVersion, targetBinary=targetBinary, force=False)
        return 0 if success else 1

    # Let addons store or handle their own arguments
    argPolicy = {'exitCode': None}
    FFLEvent.cliArgumentsStore.trigger(args=args, argPolicy=argPolicy)

    if argPolicy['exitCode'] is not None:
        return argPolicy['exitCode']

    if command == 'daemon':
        return ProcessDaemonManager.handleCLICommand(args)

    if command == 'shares':
        return ProcessDaemonManager.handleSharesCLICommand(args)

    # Validate share arguments for:
    # - CLI mode: when command is 'share'
    # - GUI mode: when command attribute doesn't exist (GUI doesn't use subcommands)
    if command == 'share' or command is None:
        return validateShareArguments(args)

    return None


def preprocessArguments(argv, commandNames, shareSubparser, globalsParent):
    """
    Preprocess command-line arguments before final parsing.

    Handles:
    - Auto-insertion of 'share' or 'download' command based on first argument
    - Auto-insertion of default duration for --upload when followed by file path

    Args:
        argv: Command-line argument list (sys.argv[1:])
        commandNames: Set of valid command names
        shareSubparser: Parser for share command (to get --upload action config)
        globalsParent: Global arguments parser (to identify global options)

    Returns:
        list: Preprocessed argv ready for final parsing
    """
    # Make a copy to avoid modifying the original
    argv = argv.copy()

    # Build set of global option strings from globalsParent parser
    globalOptions = set()
    globalOptionsWithValues = set() # Options that take a value

    for action in globalsParent._actions:
        if action.option_strings: # Skip positional arguments
            for opt in action.option_strings:
                globalOptions.add(opt)
                # Check if this option takes a value (not a store_true/store_false action)
                if action.nargs is not None or action.const is None:
                    if not isinstance(action, argparse._StoreConstAction):
                        globalOptionsWithValues.add(opt)

    # Phase 2: Auto-insert 'share' or 'download' based on first argument
    # Find where command arguments start (after global arguments)
    globalArgCount = 0
    i = 0
    while i < len(argv):
        arg = argv[i]

        # Check if it's a global option (--option or --option=value format)
        if '=' in arg:
            # --option=value format
            optName = arg.split('=', 1)[0]
            if optName in globalOptions:
                globalArgCount = i + 1
                i += 1
                continue

        # Check if it's a global option
        if arg in globalOptions:
            globalArgCount = i + 1
            # Check if this option takes a value
            if arg in globalOptionsWithValues:
                # Skip the value too
                if i + 1 < len(argv) and not argv[i + 1].startswith('-'):
                    globalArgCount = i + 2
                    i += 2
                    continue
            i += 1
            continue

        # First non-global argument found
        break

    if globalArgCount < len(argv) and argv[globalArgCount] not in commandNames:
        firstArg = argv[globalArgCount]

        # Check if first argument is a URL (FastFileLink or generic HTTP URL)
        if firstArg.startswith('https://') or firstArg.startswith('http://'):
            # Auto-insert 'download' command for any HTTP(S) URL
            argv.insert(globalArgCount, 'download')
            logger.debug(f"Auto-inserted 'download' command before URL")
        else:
            # Auto-insert 'share' command for file paths (existing behavior)
            argv.insert(globalArgCount, 'share')
            logger.debug(f"Auto-inserted 'share' command before file path")

    # Phase 2.5: Fix --upload argument when followed by file path instead of duration
    # If --upload is followed by a value that looks like a file/folder path, insert default duration
    if '--upload' in argv:
        uploadIdx = argv.index('--upload')
        # Check if there's a next argument and it's not a valid duration choice
        if uploadIdx + 1 < len(argv):
            nextArg = argv[uploadIdx + 1]

            # Get valid durations and default from the share subparser's --upload action
            uploadAction = next((action for action in shareSubparser._actions if '--upload' in action.option_strings),
                                None)

            validDurations = set(uploadAction.choices) if uploadAction and uploadAction.choices else set()
            defaultDuration = uploadAction.const if uploadAction else DEFAULT_UPLOAD_DURATION

            # If next arg is not a valid duration and doesn't look like another flag, insert default duration
            if nextArg not in validDurations and not nextArg.startswith('-'):
                # Insert default duration after --upload
                argv.insert(uploadIdx + 1, defaultDuration)
                logger.debug(f"Auto-inserted default duration '{defaultDuration}' for --upload before file argument")

    return argv


def _expandFileList(fileListPath: str):
    """
    Read paths from a filelist file, return list of absolute paths.
    Returns None and prints an error message on failure.
    """
    if not os.path.exists(fileListPath):
        flushPrint(_('Error: file list not found: {path}').format(path=fileListPath))
        return None

    baseDir = os.path.dirname(os.path.abspath(fileListPath))
    paths = []
    with open(fileListPath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if not os.path.isabs(line):
                line = os.path.join(baseDir, line)
            paths.append(line)

    if not paths:
        flushPrint(_('Error: file list is empty: {path}').format(path=fileListPath))
        return None

    logger.debug(f"Expanded file list: {fileListPath} → {len(paths)} paths")
    return paths


def _normalizeAndValidateSharePathList(paths):
    """Normalize share paths and fail fast if any entry does not exist."""
    normalizedPathPairs = [(path, os.path.abspath(path)) for path in paths]
    missingPathPairs = [
        (originalPath, normalizedPath)
        for originalPath, normalizedPath in normalizedPathPairs if not os.path.exists(normalizedPath)
    ]

    if missingPathPairs:
        for originalPath, normalizedPath in missingPathPairs:
            logger.debug(
                "Missing share path during CLI validation: originalPath=%r normalizedPath=%r cwd=%r",
                originalPath, normalizedPath, os.getcwd()
            )
            flushPrint(_('Error: file not found: {path}').format(path=normalizedPath))

        return None

    return [normalizedPath for _originalPath, normalizedPath in normalizedPathPairs]


def validateShareArguments(args):
    """
    Validate arguments specifically for the share command.
    Used by GUI mode which only supports share command.

    Returns:
        int or None: Exit code if validation fails, None if validation passes
    """
    # Get settings for validation
    settingsGetter = SettingsGetter.getInstance()

    # --disable-clipboard defaults to None (not explicitly set) so the actual
    # default can depend on mode: CLI usage copies the link automatically
    # (convenient for pasting elsewhere); GUI mode already has an explicit
    # "Copy Link" button, so auto-copy there would just clobber whatever the
    # user has on their clipboard -- default it off instead.
    if args.disableClipboard is None:
        args.disableClipboard = not settingsGetter.isCLIMode()

    # Normalize file argument: list (from nargs='*') → None / str / list[str]
    #   0 items  → None
    #   1 item, starts with '@' → expand filelist → list[str]
    #   1 item, normal path    → str  (unchanged, single-file fast path)
    #   2+ items               → list[str] of absolute paths
    files = args.file if isinstance(args.file, list) else ([args.file] if args.file else [])
    if len(files) == 0:
        args.file = None
    elif len(files) == 1:
        singlePath = files[0]
        
        if singlePath.startswith('@'):
            expanded = _expandFileList(singlePath[1:])
            if expanded is None:
                return 1

            args.file = _normalizeAndValidateSharePathList(expanded)
            if args.file is None:
                return 1
        elif singlePath == "-" or singlePath.startswith("vfs://"):
            args.file = singlePath  # str
        else:
            normalizedPaths = _normalizeAndValidateSharePathList([singlePath])
            if normalizedPaths is None:
                return 1
                
            args.file = normalizedPaths[0]  # str
    else:
        args.file = _normalizeAndValidateSharePathList(files)
        if args.file is None:
            return 1

    # Check if --upload was used without Upload addon
    if args.upload and not settingsGetter.hasUploadSupport():
        flushPrint(_('Error: --upload option requires Upload addon (addons/Upload.py)'))
        flushPrint(_('Please install the Upload addon (use Standard/Plus version) or use P2P mode without --upload'))
        return 1

    # Validate --pause argument
    if args.pause is not None:
        # --pause requires --upload
        if not args.upload:
            flushPrint(_('Error: --pause requires --upload'))
            flushPrint(_('Use: --upload <duration> --pause <percentage>'))
            return 1

        # Validate percentage range
        if not (1 <= args.pause <= 99):
            flushPrint(_('Error: --pause percentage must be between 1 and 99'))
            return 1

    # Validate --resume argument
    if args.resume:
        # --resume requires --upload
        if not args.upload:
            flushPrint(_('Error: --resume flag can only be used with --upload'))
            return 1

    if args.legacyLink and not args.upload:
        flushPrint(_('Error: --legacy-link requires --upload'))
        flushPrint(_('Use: --upload <duration> --legacy-link <old-share-url>'))
        return 1

    # Validate conflicting --pause and --resume flags
    if args.pause is not None and args.resume:
        flushPrint(_('Error: --pause and --resume cannot be used together'))
        flushPrint(_('Use --pause to pause a new upload, or --resume to continue a paused upload'))
        return 1

    # Validate auth arguments - password is required to enable auth
    # Check if user provided --auth-user but no --auth-password (CLI or env var)
    # We check if authUser is not the default value 'ffl' AND authPassword is not set
    authPasswordProvided = args.authPassword is not None or os.getenv('FFL_AUTH_PASSWORD')
    if args.authUser != DEFAULT_AUTH_USER_NAME and not authPasswordProvided:
        flushPrint(_('Error: --auth-user requires --auth-password'))
        flushPrint(_(
            'Use --auth-password to enable authentication '
            '(username defaults to \'{defaultUser}\' if not specified)'
        ).format(defaultUser=DEFAULT_AUTH_USER_NAME))
        return 1

    originalRecipientAuth = args.recipientAuth

    if args.pickupCode:
        if not args.pickupCode.isdigit() or len(args.pickupCode) != PICKUP_CODE_LENGTH:
            flushPrint(_('Error: --pickup-code must be exactly {n} digits').format(n=PICKUP_CODE_LENGTH))
            return 1
            
        # Auto-infer --recipient-auth pickup when --pickup-code is provided without a mode
        if args.recipientAuth is None:
            args.recipientAuth = 'pickup'

    recipientPublicKey = args.recipientPublicKey

    # Auto-infer --recipient-auth pubkey/pubkey+pickup when --recipient-public-key is provided
    if recipientPublicKey and originalRecipientAuth is None:
        args.recipientAuth = 'pubkey+pickup' if args.pickupCode else 'pubkey'

    # Auto-infer --recipient-auth email when --recipient-email is provided
    if args.recipientEmail and args.recipientAuth != 'email':
        args.recipientAuth = 'email'

    # Validate email auth options
    recipientEmails = RecipientAuth.parseRecipientValues(args.recipientEmail, normalizer=RecipientAuth.normalizeEmail)
    if args.recipientAuth == 'email' and not recipientEmails:
        flushPrint(_('Error: --recipient-email is required with --recipient-auth email'))
        flushPrint(_('Use: --recipient-auth email --recipient-email user@example.com'))
        return 1

    if args.recipientAuth == 'email' and not args.recipientOTPAPIBase:
        flushPrint(_('Error: --recipient-auth email requires an OTP API server'))
        flushPrint(_('Use --recipient-otp-api-base to specify one'))
        return 1
        
    # Validate pubkey auth options
    pubkeyMode = args.recipientAuth in ('pubkey', 'pubkey+pickup')
    recipientPublicKeys = RecipientAuth.parseRecipientValues(recipientPublicKey)
    if pubkeyMode and not recipientPublicKey:
        flushPrint(_('Error: --recipient-public-key is required with --recipient-auth {mode}').format(
            mode=args.recipientAuth))
        flushPrint(_('Use --recipient-public-key {name}{ext}').format(
            name='alice', ext=PUBKEY_PUBLIC_EXT))
        return 1
        
    if recipientPublicKey and not pubkeyMode:
        flushPrint(_('Error: --recipient-public-key requires --recipient-auth pubkey or pubkey+pickup'))
        return 1

    for publicKeyPath in recipientPublicKeys:
        if not os.path.exists(publicKeyPath):
            flushPrint(_('Error: public key file not found: {path}').format(path=publicKeyPath))
            return 1

    # Validate --vfs argument
    if args.vfs:
        # --vfs cannot be used with --upload
        if args.upload:
            flushPrint(_('Error: --vfs cannot be used with --upload'))
            flushPrint(_('VFS mode is only for P2P sharing. Remove --upload to use --vfs'))
            return 1

        # --vfs requires a single file or folder (not stdin or multiple paths)
        if isinstance(args.file, list):
            flushPrint(_('Error: --vfs does not support multiple files'))
            flushPrint(_('Please specify a single file or folder path for VFS mode'))
            return 1

        if args.file == "-":
            flushPrint(_('Error: --vfs does not support stdin input'))
            flushPrint(_('Please specify a file or folder path instead of "-"'))
            return 1

    return None # Validation passed
