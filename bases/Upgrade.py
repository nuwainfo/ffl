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
"""
Upgrade module for FastFileLink CLI

Handles automatic upgrading of the CLI binary by downloading and executing
the official install scripts from the GitHub repository.
"""

import os
import subprocess
import tempfile
import logging
import tempfile
import shutil
import re
import platform

from pathlib import Path
from typing import Optional

import requests

from bases.Kernel import PUBLIC_VERSION, getLogger, AddonsManager
from bases.Settings import SettingsGetter
from bases.Utils import flushPrint, sendException, compareVersions
from bases.I18n import _

logger = getLogger(__name__)

REPO_OWNER = "nuwainfo"
REPO_NAME = "ffl"
INSTALL_SCRIPT_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/refs/heads/main/dist"


class UpgradeError(Exception):
    """Base exception for upgrade-related errors"""
    pass


def detectAPEVariant() -> str:
    """
    Detect APE variant (ffl.com or fflo.com) based on available addons

    Returns:
        "fflo.com" if API addon is not loaded (lite version)
        "ffl.com" if API addon is loaded (full version)
    """
    addonsManager = AddonsManager.getInstance()

    # Check if API addon is loaded
    if 'API' in addonsManager.loadedAddons:
        logger.debug('API addon is loaded, detected ffl.com variant')
        return "ffl.com"
    else:
        logger.debug('API addon is not loaded, detected fflo.com variant')
        return "fflo.com"


def detectGlibcVersion(binaryPath: Path) -> Optional[str]:
    """
    Detect the glibc version requirement from a Linux ELF binary

    Returns:
        Glibc version string (e.g., "2.28", "2.39") or None if unable to detect
    """
    import lief

    def detectGlibcByFileSize(path: Path) -> str:
        """Fallback: detect glibc version by file size heuristic"""
        fileSizeMB = path.stat().st_size / (1024 * 1024)
        if fileSizeMB > 100:
            logger.debug(f'File size {fileSizeMB:.1f}MB > 100MB, assuming glibc 2.28')
            return "2.28"
        else:
            logger.debug(f'File size {fileSizeMB:.1f}MB <= 100MB, assuming glibc 2.39')
            return "2.39"

    try:
        binary = lief.parse(str(binaryPath))
        if not binary or not isinstance(binary, lief.ELF.Binary):
            logger.debug(f'{binaryPath} is not an ELF binary')
            return None

        # Check if binary is dynamically linked (has imported libraries)
        isDynamic = hasattr(binary, 'libraries') and list(binary.libraries)

        if not isDynamic:
            # Static binary - can't detect glibc from symbols, use file size heuristic
            return detectGlibcByFileSize(binaryPath)

        # Find maximum GLIBC version requirement from dynamic symbols
        maxGlibcVersion = None

        for symbolVersionReq in binary.symbols_version_requirement:
            if 'libc.so' in symbolVersionReq.name:
                for aux in symbolVersionReq.auxiliary_symbols:
                    if aux.name.startswith('GLIBC_'):
                        versionStr = aux.name.replace('GLIBC_', '')
                        try:
                            parts = versionStr.split('.')
                            if len(parts) >= 2:
                                major, minor = int(parts[0]), int(parts[1])
                                if maxGlibcVersion is None or (major, minor) > maxGlibcVersion:
                                    maxGlibcVersion = (major, minor)
                        except (ValueError, IndexError):
                            continue

        if maxGlibcVersion:
            versionStr = f"{maxGlibcVersion[0]}.{maxGlibcVersion[1]}"
            logger.debug(f'Detected glibc version requirement: {versionStr}')
            return versionStr

        logger.debug(f'Could not detect glibc version from dynamic symbols')
        return None

    except Exception as e:
        logger.debug(f'Error detecting glibc version from {binaryPath}: {e}')
        return detectGlibcByFileSize(binaryPath)


def detectDarwinArch(binaryPath: Path) -> Optional[str]:
    """
    Detect the architecture from a macOS Mach-O binary

    Returns:
        Architecture string ("x86_64", "arm64") or None if unable to detect
    """
    import lief

    try:
        binary = lief.parse(str(binaryPath))
        if not binary or not isinstance(binary, lief.MachO.Binary):
            logger.debug(f'{binaryPath} is not a Mach-O binary')
            return None

        # Get CPU type from Mach-O header
        cpuType = binary.header.cpu_type
        cpuName = cpuType.name

        # Map LIEF CPU types to architecture strings
        if cpuName == 'X86_64':
            arch = "x86_64"
        elif cpuName == 'ARM64':
            arch = "arm64"
        else:
            logger.debug(f'Unknown CPU type: {cpuType}')
            return None

        logger.debug(f'Detected macOS architecture: {arch}')
        return arch

    except Exception as e:
        logger.debug(f'Error detecting architecture from {binaryPath}: {e}')
        return None


def getLatestVersionFromGitHub() -> Optional[str]:
    """
    Get the latest release version from GitHub by following redirect
    (avoids API rate limits)

    Returns:
        Version string (e.g., "3.7.6") or None if unable to determine
    """
    url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest"

    try:
        # Follow redirect to get final URL with version tag
        response = requests.head(url, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # Extract version from redirected URL
        # Expected format: https://github.com/nuwainfo/ffl/releases/tag/v3.7.6
        finalUrl = response.url
        if '/releases/tag/' in finalUrl:
            tagName = finalUrl.split('/releases/tag/')[-1]

            # Remove 'v' prefix if present (e.g., "v3.7.6" -> "3.7.6")
            if tagName.startswith('v'):
                version = tagName[1:]
            else:
                version = tagName

            logger.debug(f'Latest GitHub release: {tagName} (normalized: {version})')
            return version if version else None
        else:
            logger.warning(f'Unexpected redirect URL format: {finalUrl}')
            return None

    except requests.RequestException as e:
        logger.warning(f'Failed to fetch latest version from GitHub: {e}')
        return None


def downloadInstallScript(osType: str) -> Path:
    """Download the appropriate install script for the OS"""
    if osType == "windows":
        scriptName = "install.ps1"
    else:
        scriptName = "install.sh"

    url = f"{INSTALL_SCRIPT_BASE_URL}/{scriptName}"

    try:
        flushPrint(_("Downloading install script from: {url}").format(url=url))
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Save to temporary file
        tmpDir = Path(tempfile.gettempdir())
        scriptPath = tmpDir / scriptName

        with open(scriptPath, 'wb') as f:
            f.write(response.content)

        # Make executable on Unix-like systems
        if osType != "windows":
            scriptPath.chmod(0o755)

        flushPrint(_("Install script downloaded successfully"))
        flushPrint("")
        return scriptPath

    except requests.RequestException as e:
        raise UpgradeError(_("Failed to download install script: {error}").format(error=e))


def executeInstallScript(scriptPath: Path, targetVersion: str, osType: str, targetBinary: Optional[str] = None) -> bool:
    """Execute the install script with the specified version"""

    # Get SettingsGetter instance (needed for both development and normal modes)
    settingsGetter = SettingsGetter.getInstance()

    try:
        # Get target executable path (either specified or current)
        if targetBinary:
            currentExecutable = Path(targetBinary).resolve()
        else:
            currentExecutable = Path(settingsGetter.exePath).resolve()

        # Use a temporary target to avoid "cannot overwrite with itself" error
        # Install script will download to temp location, we'll move it after
        tempTarget = Path(tempfile.gettempdir()) / f"ffl_upgrade_{os.getpid()}{currentExecutable.suffix}"

        # Prepare environment variables
        env = os.environ.copy()
        env["FFL_VERSION"] = targetVersion
        env["FFL_TARGET"] = str(tempTarget) # Install to temp location first
        env["FFL_UPGRADE"] = "true" # Signal to install script that this is an upgrade

        # Remove SSL-related environment variables that may point to APE's internal zip filesystem
        # This ensures the install script can use system certificates
        sslVarsToRemove = ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE']
        for varName in sslVarsToRemove:
            env.pop(varName, None)

        flushPrint(_("Target executable: {path}").format(path=currentExecutable))

        # Backup existing file if it exists (copy, not move, since it might be running)
        backupPath = None
        if currentExecutable.exists():
            backupPath = currentExecutable.with_suffix(currentExecutable.suffix + '.old')
            try:
                shutil.copy2(currentExecutable, backupPath)
                logger.debug(f'Backed up {currentExecutable} to {backupPath}')
            except OSError as e:
                logger.warning(f'Could not backup target file: {e}')
                backupPath = None

        # Handle FFL_UPGRADE_VARIANT (development mode: REQUIRED when targetBinary specified)
        upgradeVariant = os.getenv('FFL_UPGRADE_VARIANT')

        if targetBinary:
            # Development mode: upgrading another binary requires explicit variant specification
            if not upgradeVariant:
                flushPrint(_("Error: FFL_UPGRADE_VARIANT is required when upgrading a different binary"))
                flushPrint("")
                flushPrint(_("Supported formats:"))
                flushPrint(_("  APE variants: ffl.com, fflo.com"))
                flushPrint(_("  Windows: windows"))
                flushPrint(_("  Linux: linux-2.39, linux-2.28 (glibc version)"))
                flushPrint(_("  macOS: darwin"))
                flushPrint("")
                flushPrint(_("Example: FFL_UPGRADE_VARIANT=ffl.com python Core.py --cli upgrade {path}").format(path=targetBinary))
                return False

            flushPrint(_("Using FFL_UPGRADE_VARIANT: {variant}").format(variant=upgradeVariant))

            # Parse variant and set environment variables
            variantLower = upgradeVariant.lower()

            if variantLower in ('ffl.com', 'fflo.com'):
                # APE variant - explicit APE file specified
                env["FFL_VARIANT"] = "com"
                env["FFL_APE"] = variantLower
                flushPrint(_("Upgrading to APE variant ({ape})").format(ape=variantLower))

            elif variantLower == 'windows':
                # Windows native (install script will detect architecture)
                env["FFL_VARIANT"] = "native"
                flushPrint(_("Upgrading to Windows native variant"))

            elif variantLower.startswith('linux'):
                # Linux native with glibc version (e.g., linux-2.39, linux-glibc-2.39)
                env["FFL_VARIANT"] = "native"
                # Extract glibc version if specified (e.g., "2.39" from "linux-2.39" or "linux-glibc-2.39")
                versionMatch = re.search(r'(\d+\.\d+)', variantLower)
                if versionMatch:
                    glibcVersion = versionMatch.group(1)
                    env["FFL_GLIBC"] = glibcVersion
                    flushPrint(_("Upgrading to Linux native variant (glibc {version})").format(version=glibcVersion))
                else:
                    # No version specified, let install script auto-detect
                    flushPrint(_("Upgrading to Linux native variant (glibc auto-detect)"))

            elif variantLower in ('darwin', 'macos'):
                # macOS native (install script will detect architecture)
                env["FFL_VARIANT"] = "native"
                flushPrint(_("Upgrading to macOS native variant"))

            else:
                flushPrint(_("Error: Unknown variant '{variant}'").format(variant=upgradeVariant))
                flushPrint(_("Supported formats: ffl.com, fflo.com, windows, linux-2.39, linux-2.28, darwin"))
                return False

        else:
            # Normal mode: upgrading current binary - auto-detect from running environment
            if settingsGetter.isRunOnCosmopolitanLibc():
                env["FFL_VARIANT"] = "com"
                # Detect specific APE variant based on available addons
                apeVariant = detectAPEVariant()
                env["FFL_APE"] = apeVariant
                flushPrint(_("Detected APE variant ({variant}), will replace with same variant").format(variant=apeVariant))
            else:
                # Native variant - detect platform-specific details
                env["FFL_VARIANT"] = "native"

                if settingsGetter.isLinux():
                    # Detect glibc version from current binary
                    glibcVersion = detectGlibcVersion(currentExecutable)
                    if not glibcVersion:
                        raise UpgradeError(_("Failed to detect glibc version from binary"))
                    env["FFL_GLIBC"] = glibcVersion
                    flushPrint(_("Detected native variant with glibc {version}").format(version=glibcVersion))
                elif settingsGetter.isDarwin():
                    # Detect architecture from current binary
                    arch = detectDarwinArch(currentExecutable)
                    if not arch:
                        raise UpgradeError(_("Failed to detect architecture from binary"))
                    env["FFL_ARCH"] = arch
                    flushPrint(_("Detected macOS native variant ({arch})").format(arch=arch))
                else:
                    # Other Unix - install script will auto-detect
                    flushPrint(_("Detected native variant, will replace with same variant"))

        flushPrint("")

        # Execute install script based on OS type
        flushPrint(_("Executing install script..."))
        flushPrint("")

        # Prepare command based on OS
        if osType == "windows":
            powershell = "powershell.exe"
            if settingsGetter.isRunOnCosmopolitanLibc():
                powershell = os.path.join(
                    os.path.expandvars('$SYSTEMROOT'), f"System32/WindowsPowerShell/v1.0/{powershell}"
                )

            command = [powershell, "-ExecutionPolicy", "Bypass", "-File", str(scriptPath)]
        else:
            command = ["bash", str(scriptPath)]

        logger.debug(f'Run command: {command=}, {os.getcwd()=}')

        # Execute and stream output
        process = subprocess.Popen(
            command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        # Stream output in real-time
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                if line:
                    flushPrint(line.rstrip())

        returncode = process.wait()

        if returncode != 0:
            raise UpgradeError(_("Install script failed with exit code {code}").format(code=returncode))

        return True

    except subprocess.SubprocessError as e:
        raise UpgradeError(_("Failed to execute install script: {error}").format(error=e))
    except Exception as e:
        raise UpgradeError(_("Unexpected error during installation: {error}").format(error=e))
    finally:
        # Initialize tempOldPath for cleanup tracking
        tempOldPath = None

        # Helper function to restore backup
        def restoreBackup():
            if backupPath and backupPath.exists():
                try:
                    shutil.copy2(backupPath, currentExecutable)
                    logger.debug(f'Restored backup from {backupPath}')
                except OSError as e:
                    logger.error(f'Could not restore backup file: {e}')

        # Helper function to cleanup files
        def cleanupFile(filePath, successMsg, errorMsg, errorLevel='debug'):
            if filePath and filePath.exists():
                try:
                    filePath.unlink()
                    logger.debug(successMsg)
                except OSError as e:
                    logFunc = logger.warning if errorLevel == 'warning' else logger.debug
                    logFunc(f'{errorMsg}: {e}')

        # Move temp file to target location if it exists
        if tempTarget.exists():
            try:
                # Try to rename current executable out of the way first
                # This works on Unix/Linux even for running executables
                # On Windows, it only works if the executable is not running (development mode)
                if currentExecutable.exists():
                    tempOldPath = currentExecutable.with_suffix(currentExecutable.suffix + '.tmp')
                    try:
                        currentExecutable.rename(tempOldPath)
                        logger.debug(f'Renamed {currentExecutable} to {tempOldPath}')
                    except OSError as e:
                        logger.debug(f'Could not rename current executable (might be running): {e}')
                        tempOldPath = None
                else:
                    tempOldPath = None

                # Move new binary into place
                shutil.move(str(tempTarget), str(currentExecutable))
                logger.debug(f'Moved {tempTarget} to {currentExecutable}')

                # Clean up the temporarily renamed old file
                if tempOldPath and tempOldPath.exists():
                    cleanupFile(
                        tempOldPath,
                        f'Deleted old executable {tempOldPath}',
                        'Could not delete old executable',
                        errorLevel='debug'
                    )

                # Clean up backup
                cleanupFile(
                    backupPath,
                    f'Deleted backup file {backupPath}',
                    'Could not delete backup file',
                    errorLevel='warning'
                )
            except OSError as e:
                logger.error(f'Failed to move upgrade file: {e}')
                restoreBackup()
        else:
            # Upgrade failed - restore backup
            restoreBackup()

        # Clean up temp file if it still exists
        cleanupFile(tempTarget, f'Cleaned up temp file {tempTarget}', 'Could not delete temp file')

        # Clean up .tmp file if it still exists (in case move failed)
        if tempOldPath:
            cleanupFile(
                tempOldPath,
                f'Cleaned up temp old file {tempOldPath}',
                'Could not delete temp old file',
                errorLevel='warning'
            )


def performUpgrade(
    targetVersion: Optional[str] = None,
    targetBinary: Optional[str] = None,
    force: bool = False,
    osType=None,
) -> bool:
    """
    Perform upgrade of FastFileLink CLI by downloading and executing install scripts

    Args:
        targetVersion: Version to upgrade to (e.g., "v3.7.5"). If None, uses latest.
        targetBinary: Target binary path to upgrade (for development mode). If None, upgrades current executable.
        force: Force upgrade even if already on latest version

    Returns:
        True if upgrade was successful, False otherwise
    """
    flushPrint(_("Current version: v{version}").format(version=PUBLIC_VERSION))
    flushPrint("")

    # Get SettingsGetter instance
    settingsGetter = SettingsGetter.getInstance()

    # Development mode: allow upgrading other binaries
    if targetBinary:
        flushPrint(_("Development mode: upgrading target binary {path}").format(path=targetBinary))
        flushPrint("")
    else:
        # Check if running from source
        if settingsGetter.isRunOnDevelopment():
            flushPrint(_("Cannot upgrade when running from Python source"))
            flushPrint(_("Tip: Use 'upgrade <binary_path>' to upgrade a specific binary in development mode"))
            return False

    # Check latest version from GitHub
    latestVersion = getLatestVersionFromGitHub()

    if not latestVersion:
        if not targetVersion:
            sendException(logger, Exception(_("Could not determine latest version from GitHub")))
            return False
        logger.warning(_("Could not check latest version from GitHub, proceeding with specified version"))
    else:
        flushPrint(_("Latest version available: {version}").format(version=latestVersion))
        flushPrint("")

        # Compare versions if not forcing upgrade
        if not force:
            comparison = compareVersions(PUBLIC_VERSION, latestVersion)
            if comparison >= 0:
                # Current version is same or newer than latest
                if comparison == 0:
                    flushPrint(_("✓ You are already running the latest version!"))
                else:
                    flushPrint(_(
                        "✓ You are running a newer version ({current}) than the latest release ({latest})!"
                    ).format(current=PUBLIC_VERSION, latest=latestVersion))
                return False

    # Determine target version
    if targetVersion is None:
        if latestVersion:
            targetVersion = f"v{latestVersion}"
        else:
            sendException(logger, Exception(_("Could not determine target version from GitHub")))
            return False

    flushPrint(_("Upgrading to {version}...").format(version=targetVersion))
    flushPrint("")

    # Detect platform
    if osType is None:
        if settingsGetter.isWindows():
            osType = "windows"
        elif settingsGetter.isLinux():
            osType = "linux"
        elif settingsGetter.isDarwin():
            osType = "darwin"
        else:
            sendException(logger, UpgradeError(_(f"Unsupported operating system: {platform.system()=}")))
            return False

    flushPrint(_("Platform: {os}").format(os=osType))
    flushPrint("")

    # Download install script
    try:
        scriptPath = downloadInstallScript(osType)
    except UpgradeError as e:
        sendException(logger, e)
        return False

    # Execute install script
    success = False
    try:
        success = executeInstallScript(scriptPath, targetVersion, osType, targetBinary)

        if success:
            flushPrint("")
            flushPrint(_("✓ Successfully upgraded to {version}!").format(version=targetVersion))
            flushPrint("")
            return True
        else:
            return False

    except UpgradeError as e:
        sendException(logger, e)
        return False
    finally:
        # Handle both Logger and LoggerAdapter
        underlyingLogger = getattr(logger, 'logger', logger)
        if underlyingLogger.getEffectiveLevel() == logging.DEBUG and not success:
            logger.debug(f'Install script execute failed, keep script in {scriptPath}')
        else:
            # Clean up script file
            try:
                if scriptPath and scriptPath.exists():
                    scriptPath.unlink()
            except Exception as e:
                logger.debug(f'Unable to delete install script {e}')
