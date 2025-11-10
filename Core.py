#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2024-2025 FastFileLink contributors
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

from bases.Kernel import UIDGenerator, getLogger, PUBLIC_VERSION
from bases.Server import createServer, DownloadHandler
from bases.Tunnel import TunnelRunner
from bases.WebRTC import WebRTCManager, WebRTCDownloader
from bases.Settings import (DEFAULT_STATIC_ROOT, ExecutionMode, SettingsGetter)
from bases.CLI import configureCLIParser, configureLogging, processArgumentsAndCommands, showVersion, loadEnvFile
from bases.Utils import (
    copy2Clipboard, flushPrint, getLogger, getAvailablePort, sendException, getJSONWriter, validateCompatibleWithServer
)
from bases.Reader import SourceReader

logger = getLogger(__name__)


def setupGracefulShutdown():
    """Setup signal handlers for graceful shutdown on multiple Ctrl+C"""
    context = {'shutdownInProgress': False}

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


def setupSettings(logger):

    # Load .env file early (before any configuration or addon loading)
    loadEnvFile()

    exeMode = ExecutionMode.PURE_PYTHON
    baseDir = os.path.dirname(__file__)
    staticRoot = DEFAULT_STATIC_ROOT

    # execute in .exe
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        exeMode = ExecutionMode.EXECUTABLE
        baseDir = sys._MEIPASS
    # execute in pyapp exe.
    elif os.getenv('PYAPP'):
        exeMode = ExecutionMode.EXECUTABLE
    # execute in cosmo libc
    elif os.__file__.startswith('/zip') or 'Cosmopolitan' in platform.version():
        exeMode = ExecutionMode.COSMOPOLITAN_LIBC
        if bases.Stub.__file__.startswith('/zip'):
            baseDir = '/zip'
    else:
        exeMode = ExecutionMode.PURE_PYTHON

    if platform.system().lower() != 'windows':
        os.environ["SSL_CERT_FILE"] = certifi.where()

    staticRoot = os.path.join(baseDir, DEFAULT_STATIC_ROOT)

    return SettingsGetter(
        exeMode=exeMode,
        baseDir=baseDir,
        staticRoot=staticRoot,
        platform=platform.system(),
    )


# Initialize SettingsGetter
settingsGetter = setupSettings(logger)
featureManager = settingsGetter.getFeatureManager()

# Setup graceful shutdown handling
setupGracefulShutdown()


def isCLIMode():
    """Check if we should run in CLI mode (backward compatibility)"""
    return settingsGetter.isCLIMode()


# Main business logic - shared between CLI and GUI modes
def processFileSharing(args):
    """
    Process the file sharing request with the given arguments
    
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    # Argument predicates.
    if not os.path.exists(args.file):
        flushPrint(f'"{args.file}" does not exist!')
        return 1

    try:

        if args.upload:
            if not settingsGetter.hasUploadSupport():
                flushPrint('Error: Upload functionality requires Upload addon (addons/Upload.py)')
                return 1

            # Use FeatureManager to check upload permission
            if not featureManager.allowUpload():
                flushPrint(featureManager.getUploadUnavailableMessage())
                return 1

        # registered or for testing
        if featureManager.isRegisteredUser():

            if not isCLIMode():
                flushPrint('If a firewall notification appears, please allow the application to connect.\n')

            # Get size using Reader abstraction (supports both files and folders)
            reader = SourceReader.build(args.file)
            size = reader.size if reader.size is not None else 0
            directory, file = os.path.split(args.file)

            # Hint user about folder content change detection for strict mode
            if os.path.isdir(args.file):
                flushPrint('📁 Sharing folder as ZIP - please keep folder contents unchanged during transfer\n')

            # Get UIDGenerator from FeatureManager
            uidGeneratorClass = UIDGenerator
            if settingsGetter.hasFeaturesSupport():
                uidGeneratorClass = featureManager.getUIDGeneratorClass(uidGeneratorClass)

            uidGenerator = uidGeneratorClass()
            generateUid = lambda: uidGenerator.generate()
            uid = generateUid()

            # Show E2EE status if enabled (first line, before establishing tunnel)
            e2eeEnabled = args.e2ee if hasattr(args, 'e2ee') else False
            if e2eeEnabled:
                flushPrint('🔐 End-to-end encryption enabled\n')

            uploadMethod = None
            if args.upload:
                from addons.Upload import (
                    createUploadStrategy, UploadPredicate, UploadResult, PauseUploadError, ResumeNotSupportedError,
                    PauseNotSupportedError, E2EENotSupportedError, UploadParameterMismatchError, ResumeValidationError
                )

                # Inform GUI users about upload resumability
                if not isCLIMode():
                    flushPrint('You can stop the upload at any time and resume it later.\n')

                class UploadAbortResult(UploadResult):

                    def __init__(self, exitCode=0, *args, **kws):
                        super().__init__(*args, **kws)
                        self.exitCode = exitCode

                def doUpload(uploadMethod, uid, link=None, resume=False):
                    uploadResult = None
                    try:
                        if resume:
                            # Resume mode: use resume() instead of tell()
                            response = uploadMethod.resume(args.file, args.upload, reader=reader)
                        else:
                            # Normal mode: pass reader to tell() to avoid rebuilding
                            response = uploadMethod.tell(uid, args.file, args.upload, link=link, reader=reader)

                        if response['success']:
                            # Pass pause percentage if specified
                            pausePercentage = args.pause
                            uploadResult = uploadMethod.execute(response, args.file, pausePercentage=pausePercentage)
                        else:
                            message = response['message']
                            sendException(logger, message, errorPrefix="Server temporarily cannot process this file")
                    except PauseUploadError as e:
                        # Handle pause like Ctrl+C - print message and re-raise for elegant exit
                        flushPrint(
                            f"Upload paused at {e.percentage:.1f}% ({e.completedChunks}/{e.totalChunks} "
                            f"chunks completed)"
                        )
                        flushPrint('Use --resume to continue upload')
                        return UploadAbortResult(exitCode=0)
                    except ResumeNotSupportedError as e:
                        # Handle resume not supported by upload strategy (e.g., PullUpload)
                        sendException(
                            logger, (
                                'Resume is only available for direct upload mode (without external tunnels).\n'
                                'Please restart the upload without --resume to upload the file normally.'
                            ),
                            errorPrefix=None
                        )
                        return UploadAbortResult(exitCode=1)
                    except PauseNotSupportedError as e:
                        # Handle pause not supported by upload strategy (e.g., PullUpload)
                        sendException(
                            logger, (
                                'Pause functionality is only available for direct upload mode '
                                '(without external tunnels).\n'
                                'Please restart the upload without --pause to upload the file normally.'
                            ),
                            errorPrefix=None
                        )
                        return UploadAbortResult(exitCode=1)
                    except E2EENotSupportedError as e:
                        # Handle E2EE not supported by upload strategy (e.g., PullUpload)
                        sendException(
                            logger, (
                                'End-to-end encryption is only available for direct upload mode '
                                '(without external tunnels).\n'
                                'Please restart the upload without --e2ee to upload the file normally.'
                            ),
                            errorPrefix=None
                        )
                        return UploadAbortResult(exitCode=1)
                    except UploadParameterMismatchError as e:
                        # Handle parameter mismatch during resume
                        sendException(
                            logger, (
                                f'Cannot resume: {e.parameter} mismatch.\n'
                                f'Original upload used "{e.originalValue}" but "{e.requestedValue}" was requested.\n'
                                'Please use the same parameters as the original upload.'
                            ),
                            errorPrefix=None
                        )
                        return UploadAbortResult(exitCode=1)
                    except ResumeValidationError as e:
                        # Handle resume validation failures (file changed, expired, corrupted)
                        sendException(logger, e, action=e.action, errorPrefix=None)
                        return UploadAbortResult(exitCode=1)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        sendException(logger, e, errorPrefix="Server temporarily cannot process this file")
                        return UploadAbortResult(exitCode=1)

                    return uploadResult

                # Create upload strategy (only if Upload addon is available)
                user = featureManager.user
                uploadMethod = createUploadStrategy(user.serialNumber, e2eeEnabled=e2eeEnabled)

                # Check upload predicate
                predicateResult = uploadMethod.predicate(file, size, user.points, args.upload)
                if not predicateResult.canUpload:
                    if predicateResult.type == UploadPredicate.INVALIDATE_POINTS:
                        flushPrint(
                            'Your user points are not enough. Please top up on our website (https://fastfilelink.com/).'
                        )
                        logger.error(f'User {user.email} points not enough.')
                    else:
                        flushPrint(predicateResult.message or 'Upload not allowed.')
                        sendException(logger, predicateResult.message or 'Upload predicate failed.')
                    return 1

            while uploadMethod:
                if uploadMethod.requireServer():
                    break

                # Try upload with current strategy
                uploadResult = doUpload(uploadMethod, uid, resume=args.resume)

                if uploadResult and isinstance(uploadResult, UploadAbortResult):
                    return uploadResult.exitCode

                if uploadResult and uploadResult.success:
                    uploadMethod.publish(uploadResult)

                    writeJSON = getJSONWriter(args, size, uploadResult.link, e2ee=e2eeEnabled)
                    if writeJSON:
                        writeJSON()
                    return 0
                else:
                    # Try fallback strategy if available
                    uploadMethod = uploadMethod.createFallbackStrategy()
                    noRetry = os.environ.get('UPLOAD_NO_RETRY') == 'True'

                    # Resume can't retry, it only can be done with original upload method.
                    # TODO: We can design a ResumeUploadMismatchError to make sure using right method to resume.
                    if uploadMethod and not noRetry and not args.resume:
                        # Regenerate UID to retry.
                        uid = generateUid()

                        flushPrint('Retrying...\n')
                    else:
                        sendException(logger, uploadResult.message if uploadResult else 'Upload failed')
                        return 1

            # If we reach here, we need to start local server (either P2P or Pull upload)
            userPort = args.port
            port = getAvailablePort(userPort)

            # Get enhanced TunnelRunner from FeatureManager if Features or Tunnels addon is available
            tunnelRunnerClass = TunnelRunner
            if settingsGetter.hasFeaturesSupport():
                tunnelRunnerClass = featureManager.getTunnelRunnerClass(tunnelRunnerClass)
            if settingsGetter.hasTunnelsSupport():
                try:
                    from addons.Tunnels import TunnelRunnerProvider
                    provider = TunnelRunnerProvider()
                    tunnelRunnerClass = provider.getTunnelRunnerClass(tunnelRunnerClass)
                except Exception as e:
                    sendException(logger, 'Unable to create tunnel by your tunnel configuration.')

            with tunnelRunnerClass(size) as tunnelRunner:
                tunnelType = tunnelRunner.getTunnelType()
                if tunnelType != "default":
                    flushPrint(f'Using tunnel: {tunnelType}')

                flushPrint('Establishing tunnel connection...\n')

                domain, tunnelLink = tunnelRunner.start(port)
                link = f"{tunnelLink}{uid}"

                # Determine handler class and setup link
                if uploadMethod:
                    uploadResult = doUpload(uploadMethod, uid, link, resume=args.resume)

                    if uploadResult and isinstance(uploadResult, UploadAbortResult):
                        return uploadResult.exitCode

                    if uploadResult and uploadResult.success:
                        handlerClass = uploadResult.requestHandler
                    else:
                        flushPrint(f'Upload failed: {uploadResult.message if uploadResult else "Unknown error"}')
                        sendException(logger, uploadResult.message if uploadResult else 'Upload failed')
                        return 1
                else:
                    # P2P mode
                    handlerClass = DownloadHandler

                    flushPrint("Please share the link below with the person you'd like to share the file with.")
                    flushPrint(f'{link}\n')
                    copy2Clipboard(f'{link}')

                    # Show auth info if enabled (password enables auth)
                    authPassword = args.authPassword
                    if authPassword:
                        authUser = args.authUser
                        flushPrint(f'Authentication enabled - Username: {authUser}\n')

                    flushPrint('Please keep the application running so the recipient can download the file.')
                    if isCLIMode():
                        flushPrint('Press Ctrl+C to terminate the program when done.\n')
                    else:
                        flushPrint('')

                    writeJSON = getJSONWriter(args, size, link, tunnelType, e2ee=e2eeEnabled)
                    if writeJSON:
                        writeJSON() # P2P mode, write before start server.

                try:
                    # Get maxDownloads and timeout values
                    maxDownloads = args.maxDownloads
                    timeout = args.timeout

                    # Get enhanced handlers from FeatureManager if Features addon is available
                    webRTCManagerClass = WebRTCManager
                    if settingsGetter.hasFeaturesSupport():
                        handlerClass = featureManager.getDownloadHandlerClass(handlerClass)
                        webRTCManagerClass = featureManager.getWebRTCManagerClass(webRTCManagerClass)

                    # Get auth credentials from args - password enables auth
                    authPassword = args.authPassword
                    authUser = args.authUser if authPassword else None

                    # Get force-relay setting from args
                    enableWebRTC = not args.forceRelay

                    # Check --force-relay feature restriction for free users with default tunnel
                    if not enableWebRTC:
                        if featureManager.user.isFreeUser() and 'fastfilelink.com' in domain:
                            flushPrint(
                                "Error: The --force-relay option with the default tunnel requires a logged in"
                                " user (Standard or Plus plan)."
                            )
                            flushPrint("")
                            flushPrint("As a free user, you can enable this feature by providing an external tunnel:")
                            flushPrint("  ffl MyFile --force-relay --preferred-tunnel <external tunnel>")
                            flushPrint("")
                            flushPrint("Alternatively, consider upgrading your plan for unrestricted access.")
                            return 1

                    # Create server with enhanced handler and WebRTC manager
                    server = createServer(
                        port, directory, file, uid, domain, handlerClass, webRTCManagerClass, maxDownloads, timeout,
                        authUser, authPassword, enableWebRTC, e2eeEnabled
                    )
                    server.start()
                except KeyboardInterrupt:
                    flushPrint('\nExiting on user request (Ctrl+C)...')
                    # Clean exit without stack trace - context manager will handle cleanup
                    return 0
                except Exception as e:
                    raise e

                # If we used pull upload, publish the link after server ends
                if uploadMethod and uploadResult and uploadResult.success:
                    uploadMethod.publish(uploadResult)

                    writeJSON = getJSONWriter(args, size, uploadResult.link, tunnelType, e2ee=e2eeEnabled)
                    if writeJSON:
                        writeJSON()
                    return 0
        else:
            sendException(logger, 'User email address has been lost')
            return 1

    except KeyboardInterrupt:
        flushPrint('\nExiting on user request (Ctrl+C)...')
        # Ensure clean exit
        return 0

    # Default success return for normal P2P completion
    return 0


def processDownload(args):
    """
    Process download command using WebRTCDownloader

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    downloader = None
    try:
        # Setup credentials if provided
        credentials = None
        if args.authPassword:
            credentials = (args.authUser, args.authPassword)

        # Create downloader and download file
        downloader = WebRTCDownloader(loggerCallback=flushPrint)
        resume = args.resume if hasattr(args, 'resume') else False
        outputPath = downloader.downloadFile(args.url, args.output, credentials, resume=resume)

        # Don't print success message - progress bar already shows completion
        logger.debug(f"File downloaded successfully: {outputPath}")
        # Print file path for test framework to parse
        flushPrint(f"Downloaded: {outputPath}")
        return 0

    except Exception as e:
        # Check if this is a FolderChangedException
        from bases.Reader import FolderChangedException
        if isinstance(e, FolderChangedException):
            # Add user-facing guidance to server error message
            serverMsg = str(e)
            clientMsg = (
                f"{serverMsg}\n\nThe shared folder contents changed during the transfer.\n"
                f"Please contact the person who shared the file and ask them to share it again."
            )
            sendException(logger, clientMsg)
            return 1
        else:
            sendException(logger, f"Download failed: {e}")
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

    # Configure logging level if specified (from global args)
    if hasattr(globalArgs, 'logLevel') and globalArgs.logLevel:
        configureLogging(globalArgs.logLevel)

    # Handle --version early exit (from global args)
    if globalArgs.version:
        showVersion()
        return 0

    if not rest:
        # No subcommand or remaining arguments -> show help
        parser.print_help()
        return 0

    # Phase 2: Auto-insert 'share' or 'download' based on first argument
    if rest[0] not in commandNames:
        prefixLen = len(argv) - len(rest) # Length of global arguments prefix

        # Check if first argument is a URL (FastFileLink or generic HTTP URL)
        if rest[0].startswith('https://') or rest[0].startswith('http://'):
            # Auto-insert 'download' command for any HTTP(S) URL
            argv = argv[:prefixLen] + ['download'] + rest
        else:
            # Auto-insert 'share' command for file paths (existing behavior)
            argv = argv[:prefixLen] + ['share'] + rest

    # Phase 3: Final parsing with subcommand determined
    try:
        args = parser.parse_args(argv)
    except argparse.ArgumentError as e:
        parser.error(str(e))

    # Ensure we have a command after parsing
    if args.command is None:
        parser.print_help()
        return 0

    # Handle download command
    if args.command == 'download':
        return processDownload(args)

    # Special validation for share command - must have file argument
    if args.command == 'share' and args.file is None:
        parser.print_help()
        return 0

    # Process arguments and handle non-share commands
    commandResult = processArgumentsAndCommands(args)
    if commandResult is not None:
        return commandResult

    if not validateCompatibleWithServer():
        return 1

    return processFileSharing(args)


# GUI mode implementation - delegated to addons.GUI plugin
def runGUIMain():
    """Run the program in GUI mode using addons.GUI plugin"""
    try:
        import addons.GUI
        return addons.GUI.runGUIMain(processFileSharing)
    except ImportError:
        flushPrint("GUI support not available. Install required dependencies or use CLI mode.")
        return 1


# Choose the appropriate main function based on CLI mode detection
def main():
    """The main entry point that chooses between CLI and GUI modes"""

    # Raise exception when user is not registered
    if not featureManager.isRegisteredUser():
        # Handle differently depending on mode
        if isCLIMode():
            print("Error: App has not been registered")
            raise requests.exceptions.ConnectionError()
        else: # Must be GUI.
            import addons.GUI
            addons.GUI.showErrorDialog("App has not been registered")
            if os.getenv("GUI_DEBUG") != "True":
                raise requests.exceptions.ConnectionError()

    try:
        if isCLIMode():
            return runCLIMain()
        else:
            return runGUIMain()
    except KeyboardInterrupt:
        flushPrint('\nExiting on user request (Ctrl+C)...')
        return 0 # Return success code for clean exit


if __name__ == '__main__':
    try:
        exitCode = main()
        sys.exit(exitCode or 0)
    except KeyboardInterrupt:
        flushPrint('\nExiting on user request (Ctrl+C)...')
        sys.exit(0) # Exit with success code
    except (requests.exceptions.ConnectionError, ConnectionError) as e:
        sendException(logger, 'Failed to connect server')
        sys.exit(1)
    except requests.exceptions.JSONDecodeError as e:
        sendException(logger, 'Server return error')
        sys.exit(1)
    except PermissionError as e:
        sys.exit(1)
    except Exception as e:
        sendException(logger, e)
        sys.exit(1)
