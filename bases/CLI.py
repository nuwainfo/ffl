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

from bases.Kernel import (
    LOG_LEVEL_MAPPING, PUBLIC_VERSION, getLogger, FFLEvent, configureGlobalLogLevel, AddonsManager, StorageLocator
)
from bases.Settings import DEFAULT_AUTH_USER_NAME, DEFAULT_UPLOAD_DURATION, SettingsGetter
from bases.Utils import flushPrint, checkVersionCompatibility, getEnv, parseProxyString, setupProxyEnvironment
from bases.Hook import HookClient, HookFileWriter
from bases.Upgrade import performUpgrade
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


def configureCLIParser():
    """Configure the parser for CLI mode with multi-phase command support using global parent approach

    Returns:
        tuple: (parser, globals_parent, command_names, shareSubparser)
    """
    # Get settings for configuration - import here to avoid circular dependency
    settingsGetter = SettingsGetter.getInstance()
    featureManager = settingsGetter.getFeatureManager()

    def _configureShareParser(parser):
        """Configure parser for file sharing (share command)"""

        # Argument validators.
        def validatePositive(valueStr, fieldName):
            """Validate positive integer values for argparse"""
            try:
                value = int(valueStr)
                if value < 0:
                    raise argparse.ArgumentTypeError(f"{fieldName} {value} cannot be negative")
                return value
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid {fieldName.lower()} value: {valueStr}")

        def validatePort(portStr):
            """Validate port number for argparse"""
            try:
                port = int(portStr)
                if not (1024 <= port <= 65535):
                    raise argparse.ArgumentTypeError(f"Port {port} is out of valid range (1024-65535)")
                return port
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {portStr}")

        def validateTimeout(timeoutStr):
            """Validate timeout value for argparse"""
            return validatePositive(timeoutStr, "Timeout")

        def validateMaxDownloads(maxDownloadsStr):
            """Validate max downloads value for argparse"""
            return validatePositive(maxDownloadsStr, "Max downloads")

        parser.add_argument(
            "file",
            metavar="FILE_OR_FOLDER",
            help=_("Choose a file or folder you want to share (use '-' for stdin)"),
            nargs='?'
        )
        parser.add_argument(
            "--name", "-n",
            metavar="FILENAME",
            help=_("Specify custom download filename (default: original filename for files, "
                   "folder.zip for folders, stdin-YYYYMMDD-HHMMSS.bin for stdin)"),
            dest="fileName"
        )

        # Upload mode - optional parameter (always available, but requires Upload addon)
        # Use FeatureManager to filter retention times or fallback to default
        times = list(featureManager.getUploadRetentionTimes().keys())
        parser.add_argument("--json", metavar="JSON_FILE", help=_("Output link and settings to a JSON file"))
        parser.add_argument(
            "--upload",
            help=_("Upload file to FastFileLink server to share it "
                   "(Share duration after upload). Default: {default}").format(
                default=DEFAULT_UPLOAD_DURATION
            ),
            choices=times if times else ['unavailable'],
            nargs='?',
            const=DEFAULT_UPLOAD_DURATION if times else 'unavailable',
            default=None,
        )
        parser.add_argument(
            "--resume",
            action="store_true",
            default=False,
            help=_("Resume a previously interrupted upload (requires previous upload session to exist)")
        )
        parser.add_argument(
            "--pause",
            type=int,
            metavar="PERCENTAGE",
            help=_("Pause upload at specified percentage (1-99, requires --upload)")
        )
        parser.add_argument(
            "--max-downloads",
            type=validateMaxDownloads,
            default=0,
            help=_(
                "Maximum number of downloads before the server automatically shuts down (P2P mode only)."
                " 0 means unlimited."
            ),
            dest="maxDownloads"
        )
        parser.add_argument(
            "--timeout",
            type=validateTimeout,
            default=0,
            help=_("Timeout in seconds before the server automatically shuts down (P2P mode only). 0 means no timeout.")
        )
        parser.add_argument(
            "--port",
            type=validatePort,
            help=_("Port number for local server (1024-65535, default: auto-detect available port)"),
            metavar="PORT"
        )
        parser.add_argument(
            "--auth-user",
            help=_("Username for HTTP Basic Authentication (default: '{default}')").format(
                default=DEFAULT_AUTH_USER_NAME),
            metavar="USERNAME",
            default=DEFAULT_AUTH_USER_NAME,
            dest="authUser"
        )
        parser.add_argument(
            "--auth-password",
            help=_("Password for HTTP Basic Authentication (enables auth protection)"),
            metavar="PASSWORD",
            dest="authPassword"
        )
        parser.add_argument(
            "--force-relay",
            action="store_true",
            default=False,
            help=_(
                "Force relayed P2P mode, disable direct WebRTC connections "
                "(can be overridden by ?webrtc=on URL parameter)"
            ),
            dest="forceRelay"
        )
        parser.add_argument(
            "--e2ee",
            action="store_true",
            default=False,
            help=_("Enable end-to-end encryption for file sharing (both HTTP and WebRTC)"),
            dest="e2ee"
        )
        parser.add_argument(
            "--invite",
            action="store_true",
            default=False,
            help=_("Open invite page in browser with the sharing link"),
            dest="invite"
        )
        parser.add_argument(
            "--qr",
            nargs='?',
            const=True,
            default=False,
            metavar="FILE",
            help=_("Display QR code in terminal (default) or save to FILE (e.g., qr.png)"),
            dest="qr"
        )
        parser.add_argument(
            "--vfs",
            action="store_true",
            default=False,
            help=_("Start VFS server and provide vfs:// URI instead of HTTPS link (P2P mode only, works with --port)"),
            dest="vfs"
        )

        # Allow addons to register additional arguments for share command
        FFLEvent.cliArgumentsShareOptionsRegister.trigger(parser=parser)

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
    _configureShareParser(shareSubparser)

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

    # Let addons create their command parsers (same pattern - inherit globalsParent)
    for cmdName, cmdConfig in commandRegistry.items():
        cmdParser = subparsers.add_parser(cmdName, help=cmdConfig['help'], parents=[globalsParent], exit_on_error=False)
        cmdConfig['setupFunction'](cmdParser)

    # Collect all valid subcommand names (including core commands)
    commandNames = {'share', 'download', 'upgrade', *commandRegistry.keys()}
    return parser, globalsParent, commandNames, shareSubparser


def handleHookArgument(hook, result=None):
    if not hook:
        return result

    jsonl = False
    sender = None

    if hook.startswith('http://') or hook.startswith('https://'):
        sender = HookClient(hook)
    else:
        sender = HookFileWriter(hook)
        jsonl = True

    logger.info(f"Hook client initialized: {hook}")

    def forwardEventToHook(eventName, **eventData):
        sender.sendEvent(eventName, eventData)

    FFLEvent.all.subscribe(forwardEventToHook)

    if jsonl:
        # HookFileWriter requires close on shutdown or interrupt (Ctrl+C)
        closeHandler = lambda *args, **kwargs: sender.close()
        FFLEvent.applicationShutdown.subscribe(closeHandler)
        FFLEvent.applicationInterrupted.subscribe(closeHandler)

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


def processArgumentsAndCommands(args):
    """
    Process parsed arguments and handle command execution through addons.
    This handles all commands except 'share' (which is handled by processFileSharing).
    Used primarily in CLI mode.

    Returns:
        int or None: Exit code if command was handled, None if should continue to processFileSharing
    """
    # Handle core upgrade command
    command = getattr(args, 'command', None)
    if command == 'upgrade':
        # Parse arguments: support both "upgrade <version>" and "upgrade <binary_path> <version>"
        target = getattr(args, 'target', None)
        version = getattr(args, 'version', None)

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


def validateShareArguments(args):
    """
    Validate arguments specifically for the share command.
    Used by GUI mode which only supports share command.

    Returns:
        int or None: Exit code if validation fails, None if validation passes
    """
    # Get settings for validation
    settingsGetter = SettingsGetter.getInstance()

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

    # Validate --vfs argument
    if args.vfs:
        # --vfs cannot be used with --upload
        if args.upload:
            flushPrint(_('Error: --vfs cannot be used with --upload'))
            flushPrint(_('VFS mode is only for P2P sharing. Remove --upload to use --vfs'))
            return 1

        # --vfs requires a file or folder (not stdin)
        if args.file == "-":
            flushPrint(_('Error: --vfs does not support stdin input'))
            flushPrint(_('Please specify a file or folder path instead of "-"'))
            return 1

    return None # Validation passed
