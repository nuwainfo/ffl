#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 Nuwa Information Co., Ltd, All Rights Reserved.
#
# Licensed under the Proprietary License,
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at our web site.
#
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import os
import logging
import logging.config
import platform

from bases.Kernel import PUBLIC_VERSION, getLogger, FFLEvent, configureGlobalLogLevel, AddonsManager
from bases.Settings import DEFAULT_AUTH_USER_NAME, SUPPORT_URL, SettingsGetter
from bases.Utils import flushPrint, checkVersionCompatibility

logger = getLogger(__name__)


def configureLogging(logLevel):
    """Configure logging level for the application using Kernel's centralized configuration or config file"""

    def suppressNoisyLogger():
        logging.getLogger('urllib3').setLevel(logging.INFO)
        logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)
        logging.getLogger('sentry_sdk').setLevel(logging.INFO)

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
            return

        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            flushPrint(f"Failed to load logging config from {logLevel}: {e}")
            flushPrint("Falling back to default logging level configuration")

    # Map string levels to logging constants for standard level names
    levelMapping = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR}

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


def showVersion():
    """Display version information and enabled addons"""
    flushPrint(f"FastFileLink v{PUBLIC_VERSION}")
    flushPrint("")

    # Check version compatibility with server
    serverIsNewer, isCompatible, serverVersion, minimumVersion = checkVersionCompatibility()

    if serverIsNewer and isCompatible:
        flushPrint("🔄 Update available!")
        flushPrint(f"   Your version: {PUBLIC_VERSION}")
        flushPrint(f"   Latest version: {serverVersion}")
        flushPrint("   Consider updating for the latest features and improvements.")
        flushPrint("")

    if not isCompatible:
        flushPrint("⚠️ VERSION INCOMPATIBLE!")
        flushPrint(f"   Your version: {PUBLIC_VERSION}")
        flushPrint(f"   Server Minimum required: {minimumVersion}")
        flushPrint(f"   Latest version: {serverVersion}")
        flushPrint("   Please update to continue using the service.")
        flushPrint("")

    # Get addons manager and show enabled addons
    addonsManager = AddonsManager.getInstance()
    enabledAddons = addonsManager.getEnabledAddons()

    if enabledAddons:
        flushPrint("Enabled addons:")
        for addon in enabledAddons:
            status = "[OK] Loaded" if addonsManager.isAddonLoaded(addon) else "[FAIL] Failed to load"
            flushPrint(f"  {addon:<12} {status}")
    else:
        flushPrint("No addons available")

    flushPrint("")
    uname = platform.uname()
    flushPrint(f"Architecture: {uname.system} {uname.release} {uname.machine} - {uname.version} ({uname.processor})")
    flushPrint(f"Support: {SUPPORT_URL}")


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

        parser.add_argument("file", metavar="File", help="Choose a file you want to share", nargs='?')

        # Upload mode - optional parameter (always available, but requires Upload addon)
        # Use FeatureManager to filter retention times or fallback to default
        times = list(featureManager.getUploadRetentionTimes().keys())
        parser.add_argument("--json", metavar="JSON_FILE", help="Output link and settings to a JSON file")
        parser.add_argument(
            "--upload",
            help="Upload file to FastFileLink server to share it (Share duration after upload). Default: 6 hours",
            choices=times if times else ['unavailable'],
            nargs='?',
            const='6 hours' if times else 'unavailable',
            default=None,
        )
        parser.add_argument(
            "--max-downloads",
            type=validateMaxDownloads,
            default=0,
            help=(
                "Maximum number of downloads before the server automatically shuts down (P2P mode only)."
                " 0 means unlimited."
            ),
            dest="maxDownloads"
        )
        parser.add_argument(
            "--timeout",
            type=validateTimeout,
            default=0,
            help="Timeout in seconds before the server automatically shuts down (P2P mode only). 0 means no timeout."
        )
        parser.add_argument(
            "--port",
            type=validatePort,
            help="Port number for local server (1024-65535, default: auto-detect available port)",
            metavar="PORT"
        )
        parser.add_argument(
            "--auth-user",
            help=f"Username for HTTP Basic Authentication (default: '{DEFAULT_AUTH_USER_NAME}')",
            metavar="USERNAME",
            default=DEFAULT_AUTH_USER_NAME,
            dest="authUser"
        )
        parser.add_argument(
            "--auth-password",
            help="Password for HTTP Basic Authentication (enables auth protection)",
            metavar="PASSWORD",
            dest="authPassword"
        )
        parser.add_argument(
            "--force-relay",
            action="store_true",
            default=False,
            help=
            "Force relayed P2P mode, disable direct WebRTC connections (can be overridden by ?webrtc=on URL parameter)",
            dest="forceRelay"
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
                f"Invalid log level '{logLevel}'. Valid levels are: {', '.join(validLevels)}"
            )
        return logLevel.upper()

    # === 1) Global parameters in a parent parser ===
    globalsParent = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    globalsParent.add_argument("--version", action="store_true", help="Show version information and enabled addons")
    globalsParent.add_argument("--cli", action="store_true", help="Run in CLI mode without GUI (optional)")
    globalsParent.add_argument(
        "--log-level",
        type=validateLogLevel,
        help="Set logging level (DEBUG, INFO, WARNING, ERROR) or path to logging config JSON file (default: WARNING)",
        metavar="LEVEL_OR_FILE",
        dest="logLevel"
    )

    # === 2) Main parser + subparsers; all inherit from globalsParent ===
    parser = argparse.ArgumentParser(
        description="FastFileLink makes file sharing fast, simple, and secure.",
        parents=[globalsParent],
        exit_on_error=False,
    )

    # Let addons register their commands
    commandRegistry = {}
    FFLEvent.cliArgumentsCommandsRegister.trigger(parser=parser, commandRegistry=commandRegistry)

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Default 'share' command for file sharing
    shareSubparser = subparsers.add_parser(
        'share', help='Share a file (default command)', parents=[globalsParent], exit_on_error=False
    )
    _configureShareParser(shareSubparser)

    # Let addons create their command parsers (same pattern - inherit globalsParent)
    for cmdName, cmdConfig in commandRegistry.items():
        cmdParser = subparsers.add_parser(cmdName, help=cmdConfig['help'], parents=[globalsParent], exit_on_error=False)
        cmdConfig['setupFunction'](cmdParser)

    # Collect all valid subcommand names (including 'share')
    commandNames = {'share', *commandRegistry.keys()}
    return parser, globalsParent, commandNames, shareSubparser


def processArgumentsAndCommands(args):
    """
    Process parsed arguments and handle command execution through addons.
    This handles all commands except 'share' (which is handled by processFileSharing).
    Used primarily in CLI mode.
    
    Returns:
        int or None: Exit code if command was handled, None if should continue to processFileSharing
    """
    # Let addons store or handle their own arguments
    argPolicy = {'exitCode': None}
    FFLEvent.cliArgumentsStore.trigger(args=args, argPolicy=argPolicy)

    if argPolicy['exitCode'] is not None:
        return argPolicy['exitCode']

    return validateShareArguments(args)


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
    if hasattr(args, 'upload') and args.upload and not settingsGetter.hasUploadSupport():
        flushPrint("Error: --upload option requires Upload addon (addons/Upload.py)")
        flushPrint("Please install the Upload addon (use Standard/Plus version) or use P2P mode without --upload")
        return 1

    # Validate auth arguments - password is required to enable auth
    if hasattr(args, 'authPassword'):
        # Check if user provided --auth-user but no --auth-password
        # We check if authUser is not the default value 'ffl' AND authPassword is None
        if args.authUser != DEFAULT_AUTH_USER_NAME and args.authPassword is None:
            flushPrint("Error: --auth-user requires --auth-password")
            flushPrint(
                f"Use --auth-password to enable authentication (username defaults to '{DEFAULT_AUTH_USER_NAME}' if not specified)"
            )
            return 1

    return None # Validation passed
