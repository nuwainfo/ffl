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

import platform
import sys
import os
import argparse
import signal
import atexit
import time
import threading

if 'Cosmopolitan' in platform.version():
    if sys.prefix not in sys.path:
        sys.path.insert(0, sys.prefix)

if os.getenv('PYAPP'):
    BASE_DIR = os.path.dirname(__file__)
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)

# This line must be the first to ensure all stubs working.
import bases.Stub # isort:skip

import requests
import certifi
import segno

from functools import partial
from bases.crypto import CryptoInterface 

from bases.Kernel import FFLEvent 
from bases.Settings import DEFAULT_STATIC_ROOT, ExecutionMode, SettingsGetter 
from bases.Auth import PUBKEY_PRIVATE_EXT, PUBKEY_PUBLIC_EXT, RecipientAuth 
from bases.Download import FFLDownloader 
from bases.FileSystems import ExcludeFilter
from bases.Readers import FolderChangedException, SourceReader
from bases.Tunnel import TunnelUnavailableError
from bases.Share import ShareExecutionContext, ShareReporter, createShareRequest, processSharing
from bases.Daemon import DaemonClient, DaemonManager
from bases.CLI import (  
    ShareCLIArgumentAdapter, configureCLIParser, loadEnvFile, preprocessArguments, processArgumentsAndCommands,
    processGlobalArguments
) 
from bases.Utils import (  
    flushPrint, getLogger, sendException, validateCompatibleWithServer
) 
from bases.I18n import _ # isort:skip

logger = getLogger(__name__)


def setupGracefulShutdown():
    """Setup signal handlers for graceful shutdown on multiple Ctrl+C and cleanup on exit"""
    context = {'shutdownInProgress': False, 'shutdownEventTriggered': False}

    def triggerShutdownEvent():
        """Trigger application shutdown event for cleanup (called on exit)"""
        if not context['shutdownEventTriggered']:
            context['shutdownEventTriggered'] = True
            try:
                FFLEvent.applicationShutdown.trigger()
            except Exception as e:
                # Fail silently - don't prevent exit
                logger.debug(f'Shutdown event trigger error: {str(e)}')

    def signalHandler(signum, frame):
        if context['shutdownInProgress']:
            # Second Ctrl+C - force immediate exit without cleanup messages
            os._exit(0)
        else:
            # First Ctrl+C - set flag and raise KeyboardInterrupt normally
            context['shutdownInProgress'] = True
            raise KeyboardInterrupt()

    # Register signal handler for SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, signalHandler)

    # Register shutdown event trigger on exit
    atexit.register(triggerShutdownEvent)


def detectExecutionEnvironment():
    """
    Detect the current execution environment (Python script, PyInstaller, PyApp, Cosmopolitan).

    Returns:
        tuple: (ExecutionMode, baseDir, exePath) where:
            - ExecutionMode: The detected execution mode
            - baseDir: Base directory for the application
            - exePath: Path to the actual executable (wrapper for PyApp, sys.executable for others)
    """
    baseDir = os.path.dirname(os.path.abspath(__file__))
    exePath = sys.executable # Default to sys.executable

    # Execute in PyInstaller .exe
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # NSIS sets EXE_PATH environment variable
        exePath = os.getenv('EXE_PATH', sys.executable)
        return ExecutionMode.EXECUTABLE, sys._MEIPASS, exePath

    # Execute in PyApp exe
    elif os.getenv('PYAPP'):
        # PyApp extracts and runs the code, so sys.executable points to the extracted Python
        exePath = os.getenv('PYAPP', sys.executable)
        return ExecutionMode.EXECUTABLE, baseDir, exePath

    # Execute in Cosmopolitan libc
    elif os.__file__.startswith('/zip') or 'Cosmopolitan' in platform.version():
        # Check if running from zip
        if bases.Stub.__file__.startswith('/zip'):
            baseDir = '/zip'
        return ExecutionMode.COSMOPOLITAN_LIBC, baseDir, exePath

    # Pure Python execution
    else:
        # Go up one level from bases/ to get project root
        return ExecutionMode.PURE_PYTHON, baseDir, exePath


def setupSettings(logger):

    # Load .env file early (before any configuration or addon loading)
    loadEnvFile()

    # Detect execution environment (PyInstaller, PyApp, Cosmopolitan, or pure Python)
    exeMode, baseDir, exePath = detectExecutionEnvironment()

    if platform.system().lower() != 'windows':
        os.environ["SSL_CERT_FILE"] = certifi.where()

    staticRoot = os.path.join(baseDir, DEFAULT_STATIC_ROOT)

    return SettingsGetter(
        exeMode=exeMode,
        baseDir=baseDir,
        staticRoot=staticRoot,
        platform=platform.system(),
        exePath=exePath,
    )


# Initialize SettingsGetter
settingsGetter = setupSettings(logger)
featureManager = settingsGetter.getFeatureManager()

# Setup graceful shutdown handling
setupGracefulShutdown()


def processDownload(args):

    downloader = None
    try:
        # Setup credentials if provided
        credentials = None
        if args.authPassword:
            credentials = (args.authUser, args.authPassword)

        logCallback = (lambda text: print(text, file=sys.stderr, flush=True)) if args.stdout else flushPrint

        # Create downloader and download file
        downloader = FFLDownloader(loggerCallback=logCallback)
        outputPath = downloader.downloadFile(
            args.url,
            "-" if args.stdout else args.output,
            credentials,
            resume=args.resume,
            pickupCode=args.pickupCode,
            recipientPrivateKey=args.recipientPrivateKey
        )

        logger.debug(f"File downloaded successfully: {outputPath}")

        if args.stdout:
            logCallback(_('Download complete'))
        else:
            logCallback(_('Downloaded: {outputPath}').format(outputPath=outputPath))

        return 0

    except Exception as e:
        # Check if this is a FolderChangedException
        if isinstance(e, FolderChangedException):
            # Add user-facing guidance to server error message
            serverMsg = str(e)
            clientMsg = _(
                '{serverMsg}\n\n'
                'The shared folder contents changed during the transfer.\n'
                'Please contact the person who shared the file and ask them to share it again.'
            ).format(serverMsg=serverMsg)
            sendException(logger, clientMsg)
            return 1
        else:
            sendException(logger, _('Download failed: {error}').format(error=e))
            return 1
    finally:
        # Clean up downloader resources
        if downloader:
            downloader.close()


# CLI mode implementation
def runCLIMain():
    """Run the program in CLI mode using two-phase parsing"""
    parser, globalsParent, commandNames, shareSubparser = configureCLIParser()

    argv = sys.argv[1:]

    # Handle special cases first (maintain original UX)
    if argv == ['--cli'] or len(argv) == 0:
        parser.print_help()
        return 0

    # Phase 1: Use globalsParent to separate global args from the rest
    # This lets argparse handle all global argument validation (including --log-level missing values)
    try:
        globalArgs, rest = globalsParent.parse_known_args(argv)
    except argparse.ArgumentError as e:
        # Global argument error - let argparse report it properly
        parser.error(str(e))

    # Process global arguments (handles --log-level, --enable-reporting, --version, --proxy, etc.)
    globalResult = processGlobalArguments(globalArgs)
    if globalResult['exitCode'] is not None:
        return globalResult['exitCode']

    # Extract proxyConfig from global arguments processing
    proxyConfig = globalResult['proxyConfig']

    if not rest:
        # No subcommand or remaining arguments -> show help
        parser.print_help()
        return 0

    # Phase 2: Preprocess arguments (auto-insert commands, fix --upload)
    argv = preprocessArguments(argv, commandNames, shareSubparser, globalsParent)

    # Phase 3: Final parsing with subcommand determined
    try:
        args, unknownArgs = parser.parse_known_args(argv)
    except argparse.ArgumentError as e:
        parser.error(str(e))

    # Collect any extra positional arguments (files after optional args like --json)
    # and append them to args.file for multi-file sharing support
    if unknownArgs:
        extraFiles = [a for a in unknownArgs if not a.startswith('-')]
        unrecognizedFlags = [a for a in unknownArgs if a.startswith('-')]
        if unrecognizedFlags:
            parser.error(f"unrecognized arguments: {' '.join(unrecognizedFlags)}")
            
        if extraFiles and args.command == 'share':
            existingFiles = args.file if isinstance(args.file, list) else ([args.file] if args.file else [])
            args.file = existingFiles + extraFiles

    # Ensure we have a command after parsing
    if args.command is None:
        parser.print_help()
        return 0

    # Handle download command
    if args.command == 'download':
        return processDownload(args)

    # Special validation for share command - must have file argument
    if args.command == 'share' and not args.file:
        parser.print_help()
        return 0

    # Process arguments and handle non-share commands
    commandResult = processArgumentsAndCommands(args, shareSubparser=shareSubparser, proxyConfig=proxyConfig)
    if commandResult is not None:
        return commandResult

    # Start prefetch immediately so tunnels API + token + SSL warm + TCP pre-connect
    # all run concurrently with the version check network round-trip.
    if settingsGetter.hasFeaturesSupport():
        featureManager.startTunnelPrefetch(proxyConfig=proxyConfig)

    if not validateCompatibleWithServer():
        return 1
    
    if args.command == 'share':
        shareRequest = createShareRequest(args)
        shareReporter = ShareReporter(
            outputCallback=flushPrint,
            exceptionCallback=partial(sendException, logger),
        )
        shareContext = ShareExecutionContext(
            reporter=shareReporter,
            proxyConfig=proxyConfig,
        )

        # If share control by daemon.
        if (not args.foreground and (args.background or DaemonClient.isRunning())):
            if args.upload and not args.yes:
                from addons.Upload import prepareUpload

                excludeFilter = ExcludeFilter(shareRequest.exclude) if shareRequest.exclude else None
                reader = SourceReader.build(
                    shareRequest.file,
                    fileName=shareRequest.fileName,
                    excludeFilter=excludeFilter,
                    stdinCache=(shareRequest.stdinCache != 'off')
                )
                confirmationExitCode = prepareUpload(shareRequest, reader, shareContext).exitCode
                if confirmationExitCode is not None:
                    return confirmationExitCode

                args.uploadConfirmed = True

            shareConfig = ShareCLIArgumentAdapter.createDaemonShareConfig(args, shareSubparser)
            return DaemonManager.handleBackgroundShare(args, shareConfig, proxyConfig=proxyConfig)
        else:
            return processSharing(shareRequest, shareContext)

    return None


# GUI mode implementation - delegated to addons.GUI plugin
def runGUIMain():
    """Run the program in GUI mode using addons.GUI plugin"""
    try:
        import addons.GUI
        return addons.GUI.runGUIMain()
    except ImportError:
        flushPrint(_('GUI support not available. Install required dependencies or use CLI mode.'))
        return 1


# Choose the appropriate main function based on CLI mode detection
def main():
    """The main entry point that chooses between CLI and GUI modes"""

    # Raise exception when user is not registered
    if not featureManager.isRegisteredUser():
        # Handle differently depending on mode
        if settingsGetter.isCLIMode():
            print(_('Error: App has not been registered'))
            raise requests.exceptions.ConnectionError()
        else: # Must be GUI.
            import addons.GUI
            addons.GUI.showErrorDialog(_('App has not been registered'))
            if os.getenv("GUI_DEBUG") != "True":
                raise requests.exceptions.ConnectionError()

    try:
        if settingsGetter.isCLIMode():
            return runCLIMain()
        else:
            return runGUIMain()
    except KeyboardInterrupt:
        flushPrint(_('\nExiting on user request (Ctrl+C)...'))
        FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')
        return 0 # Return success code for clean exit


if __name__ == '__main__':
    try:
        exitCode = main()
        sys.exit(exitCode or 0)
    except KeyboardInterrupt:
        flushPrint(_('\nExiting on user request (Ctrl+C)...'))
        FFLEvent.applicationInterrupted.trigger(reason='user-interrupt')
        sys.exit(0) # Exit with success code
    except TunnelUnavailableError as e:
        sendException(
            logger, _(
                'Tunnel server temporarily unavailable. '
                'See https://github.com/nuwainfo/ffl#3--using-tunnels for alternative tunnels.'
            )
        )
        sys.exit(1)
    except (requests.exceptions.ConnectionError, ConnectionError) as e:
        sendException(logger, _('Failed to connect server'))
        sys.exit(1)
    except requests.exceptions.JSONDecodeError as e:
        sendException(logger, _('Server return error'))
        sys.exit(1)
    except PermissionError as e:
        sys.exit(1)
    except Exception as e:
        sendException(logger, e)
        sys.exit(1)
