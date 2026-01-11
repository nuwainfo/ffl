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
import json
import atexit

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

from bases.Kernel import UIDGenerator, getLogger, FFLEvent
from bases.Server import createServer, DownloadHandler, ServerConfig
from bases.Tunnel import TunnelRunner, TunnelUnavailableError
from bases.WebRTC import DummyWebRTCManager, WebRTCManager, WebRTCDownloader
from bases.Settings import DEFAULT_STATIC_ROOT, SettingsGetter, ExecutionMode
from bases.CLI import (
    configureCLIParser, processGlobalArguments, processArgumentsAndCommands, loadEnvFile, preprocessArguments
)
from bases.Utils import (
    copy2Clipboard, flushPrint, getLogger, getAvailablePort, sendException, validateCompatibleWithServer, ProxyConfig
)
from bases.Reader import SourceReader
from bases.Tor import verifyTorProxy
from bases.I18n import _

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


def isCLIMode():
    """Check if we should run in CLI mode (backward compatibility)"""
    return settingsGetter.isCLIMode()


def onShareLinkCreate(args, link, filePath, fileSize, tunnelType, e2ee, reader, **kwargs):
    """Handle share link creation - invite, QR code, and JSON writing"""
    # Handle --invite flag
    if args.invite:
        flushPrint(_('Opening invite page in browser...'))
        featureManager.invite(link)

    # Handle --qr flag
    if args.qr:
        try:
            qr = segno.make(link)

            # Check if args.qr is a file path (string) or True (terminal display)
            if isinstance(args.qr, str):
                # Save QR code to file
                qr.save(args.qr, scale=5)
                flushPrint(_('QR code saved to: {filePath}').format(filePath=args.qr))
            else:
                # Display in terminal
                flushPrint(_('\nQR Code:\n'))
                qr.terminal(compact=True)
                flushPrint('')
        except Exception as e:
            flushPrint(_('Error generating QR code: {error}').format(error=e))
            # It's ok only not generate QR code.

    # Handle --json flag
    if args.json:
        user = featureManager.user
        outputData = {
            "file": filePath,
            "content_name": reader.contentName, # Download filename (may be custom via --name)
            "file_size": fileSize if fileSize is not None else -1, # -1 indicates unknown size
            "upload_mode": "server" if args.upload else "p2p",
            "tunnel_type": tunnelType or "default",
            "link": link,
            "e2ee": e2ee,
            "user": {
                "user": user.name,
                "email": user.email,
                "level": user.level,
                "points": user.points,
                "serial_number": user.serialNumber
            }
        }

        try:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(outputData, f, indent=2)
            flushPrint(_('Sharing information saved to {jsonFile}').format(jsonFile=args.json))
        except Exception as e:
            flushPrint(_('Failed to write JSON file: {error}').format(error=e))
            sendException(logger, e)


# Main business logic - shared between CLI and GUI modes
def processFileSharing(args, proxyConfig: ProxyConfig = None):
    """
    Process the file sharing request with the given arguments

    Args:
        args: Parsed command-line arguments
        proxyConfig: Optional proxy configuration dict from parseProxyString()

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    # Argument predicates.
    # Allow "-" for stdin, otherwise check file existence
    if args.file != "-" and not os.path.exists(args.file):
        flushPrint(_('{file} does not exist!').format(file=f'"{args.file}"'))
        return 1

    # Subscribe handler for share link creation with bound args
    handler = partial(onShareLinkCreate, args)
    FFLEvent.shareLinkCreate.subscribe(handler)

    try:
        if args.upload:
            if not settingsGetter.hasUploadSupport():
                flushPrint(_('Error: Upload functionality requires Upload addon (addons/Upload.py)'))
                return 1

            # Use FeatureManager to check upload permission
            if not featureManager.allowUpload():
                flushPrint(featureManager.getUploadUnavailableMessage())
                return 1

        # registered or for testing
        if featureManager.isRegisteredUser():

            if not isCLIMode():
                flushPrint(_('If a firewall notification appears, please allow the application to connect.\n'))

            # Get size using Reader abstraction (supports both files and folders)
            # Reader will use its own default if args.fileName is None
            reader = SourceReader.build(args.file, fileName=args.fileName)
            size = reader.size # None means unknown size (e.g., stdin)

            # Hint user about folder content change detection for strict mode
            if args.file != "-" and os.path.isdir(args.file):
                flushPrint(_('📁 Sharing folder as ZIP - please keep folder contents unchanged during transfer\n'))

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
                flushPrint(_('🔐 End-to-end encryption enabled\n'))

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
                flushPrint(_("🧅 Tor Privacy Mode Active"))

            uploadMethod = None
            if args.upload:
                from addons.Upload import (
                    createUploadStrategy, UploadPredicate, UploadResult, PauseUploadError, ResumeNotSupportedError,
                    PauseNotSupportedError, E2EENotSupportedError, UploadParameterMismatchError, ResumeValidationError
                )

                # Inform GUI users about upload resumability
                if not isCLIMode():
                    flushPrint(_('You can stop the upload at any time and resume it later.\n'))

                class UploadAbortResult(UploadResult):

                    def __init__(self, exitCode=0, *args, **kws):
                        super().__init__(*args, **kws)
                        self.exitCode = exitCode

                def doUpload(uploadMethod, uid, link=None, resume=False):
                    uploadResult = None
                    try:
                        if resume:
                            # Resume mode: use resume() instead of tell()
                            response = uploadMethod.resume(
                                args.file, args.upload, reader=reader, fileName=args.fileName
                            )
                        else:
                            # Normal mode: pass reader to tell() to avoid rebuilding
                            response = uploadMethod.tell(
                                uid, args.file, args.upload, link=link, reader=reader, fileName=args.fileName
                            )

                        if response['success']:
                            # Pass pause percentage if specified
                            pausePercentage = args.pause
                            uploadResult = uploadMethod.execute(response, args.file, pausePercentage=pausePercentage)
                        else:
                            message = response['message']
                            sendException(logger, message, errorPrefix="Server temporarily cannot process this file")
                    except PauseUploadError as e:
                        # Handle pause like Ctrl+C - print message and re-raise for elegant exit
                        flushPrint(_(
                            'Upload paused at {percentage:.1f}% ({completedChunks}/{totalChunks} chunks completed)'
                        ).format(percentage=e.percentage, completedChunks=e.completedChunks, totalChunks=e.totalChunks))
                        flushPrint(_('Use --resume to continue upload'))
                        return UploadAbortResult(exitCode=0)
                    except ResumeNotSupportedError as e:
                        # Handle resume not supported by upload strategy (e.g., PullUpload)
                        sendException(
                            logger, _(
                                'Resume is only available for direct upload mode (without external tunnels).\n'
                                'Please restart the upload without --resume to upload the file normally.'
                            ),
                            errorPrefix=None
                        )
                        return UploadAbortResult(exitCode=1)
                    except PauseNotSupportedError as e:
                        # Handle pause not supported by upload strategy (e.g., PullUpload)
                        sendException(
                            logger, _(
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
                            logger, _(
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
                            logger, _(
                                'Cannot resume: {parameter} mismatch.\n'
                                'Original upload used "{originalValue}" but "{requestedValue}" was requested.\n'
                                'Please use the same parameters as the original upload.'
                            ).format(parameter=e.parameter, originalValue=e.originalValue,
                                     requestedValue=e.requestedValue),
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
                predicateResult = uploadMethod.predicate(reader.file, size, user.points, args.upload)
                if not predicateResult.canUpload:
                    if predicateResult.type == UploadPredicate.INVALIDATE_POINTS:
                        flushPrint(_(
                            'Your user points are not enough. Please top up on our website (https://fastfilelink.com/).'
                        ))
                        logger.error(f'User {user.email} points not enough.')
                    else:
                        flushPrint(predicateResult.message or _('Upload not allowed.'))
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
                    FFLEvent.shareLinkCreate.trigger(
                        link=uploadResult.link,
                        filePath=args.file,
                        fileSize=size,
                        tunnelType=None,
                        e2ee=e2eeEnabled,
                        reader=reader
                    )
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

                        flushPrint(_('Retrying...\n'))
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
                    sendException(logger, _('Unable to create tunnel by your tunnel configuration.'))

            # Use proxyConfig passed from global arguments processing
            with tunnelRunnerClass(size, proxyConfig=proxyConfig) as tunnelRunner:
                tunnelType = tunnelRunner.getTunnelType()
                if tunnelType != "default":
                    flushPrint(_('Using tunnel: {tunnelType}').format(tunnelType=tunnelType))

                # Show proxy status for tunnel connections
                proxyInfo = tunnelRunner.getProxyInfo()
                if proxyInfo:
                    flushPrint(_('Establishing tunnel connection via proxy {proxyInfo}...\n').format(
                        proxyInfo=proxyInfo))
                else:
                    flushPrint(_('Establishing tunnel connection...\n'))

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
                        flushPrint(_('Upload failed: {error}').format(
                            error=uploadResult.message if uploadResult else _('Unknown error')
                        ))
                        sendException(logger, uploadResult.message if uploadResult else 'Upload failed')
                        return 1
                else:
                    # P2P mode
                    handlerClass = DownloadHandler

                    flushPrint(_("Please share the link below with the person you'd like to share the file with."))
                    flushPrint(f'{link}\n')
                    copy2Clipboard(f'{link}')

                    # Trigger share link create event for GUI and other subscribers
                    FFLEvent.shareLinkCreate.trigger(
                        link=link,
                        filePath=args.file,
                        fileSize=size,
                        tunnelType=tunnelType,
                        e2ee=e2eeEnabled,
                        reader=reader
                    )

                    # Show auth info if enabled (password enables auth)
                    authPassword = args.authPassword
                    if authPassword:
                        authUser = args.authUser
                        flushPrint(_('Authentication enabled - Username: {authUser}\n').format(authUser=authUser))

                    flushPrint(_('Please keep the application running so the recipient can download the file.'))
                    if isCLIMode():
                        flushPrint(_('Press Ctrl+C to terminate the program when done.\n'))
                    else:
                        flushPrint('')

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

                    # Get auth credentials from args - password enables auth
                    authPassword = args.authPassword
                    authUser = args.authUser if authPassword else None

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
                    )

                    # Create server with enhanced handler and WebRTC manager
                    # Reader provides file and directory information
                    server = createServer(reader, port, uid, domain, handlerClass, webRTCManagerClass, serverConfig)
                    server.start()
                except KeyboardInterrupt:
                    flushPrint(_('\nExiting on user request (Ctrl+C)...'))
                    # Clean exit without stack trace - context manager will handle cleanup
                    return 0
                except Exception as e:
                    raise e

                # If we used pull upload, publish the link after server ends
                if uploadMethod and uploadResult and uploadResult.success:
                    uploadMethod.publish(uploadResult)
                    FFLEvent.shareLinkCreate.trigger(
                        link=uploadResult.link,
                        filePath=args.file,
                        fileSize=size,
                        tunnelType=tunnelType,
                        e2ee=e2eeEnabled,
                        reader=reader
                    )
                    return 0
        else:
            sendException(logger, _('User email address has been lost'))
            return 1

    except KeyboardInterrupt:
        flushPrint(_('\nExiting on user request (Ctrl+C)...'))
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
        flushPrint(_('Downloaded: {outputPath}').format(outputPath=outputPath))
        return 0

    except Exception as e:
        # Check if this is a FolderChangedException
        from bases.Reader import FolderChangedException
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

    return processFileSharing(args, proxyConfig=proxyConfig)


# GUI mode implementation - delegated to addons.GUI plugin
def runGUIMain():
    """Run the program in GUI mode using addons.GUI plugin"""
    try:
        import addons.GUI
        return addons.GUI.runGUIMain(processFileSharing)
    except ImportError:
        flushPrint(_('GUI support not available. Install required dependencies or use CLI mode.'))
        return 1


# Choose the appropriate main function based on CLI mode detection
def main():
    """The main entry point that chooses between CLI and GUI modes"""

    # Raise exception when user is not registered
    if not featureManager.isRegisteredUser():
        # Handle differently depending on mode
        if isCLIMode():
            print(_('Error: App has not been registered'))
            raise requests.exceptions.ConnectionError()
        else: # Must be GUI.
            import addons.GUI
            addons.GUI.showErrorDialog(_('App has not been registered'))
            if os.getenv("GUI_DEBUG") != "True":
                raise requests.exceptions.ConnectionError()

    try:
        if isCLIMode():
            return runCLIMain()
        else:
            return runGUIMain()
    except KeyboardInterrupt:
        flushPrint(_('\nExiting on user request (Ctrl+C)...'))
        return 0 # Return success code for clean exit


if __name__ == '__main__':
    try:
        exitCode = main()
        sys.exit(exitCode or 0)
    except KeyboardInterrupt:
        flushPrint(_('\nExiting on user request (Ctrl+C)...'))
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
