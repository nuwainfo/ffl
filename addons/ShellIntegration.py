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
import plistlib
import shutil
import stat
import subprocess
import sys
import textwrap

from pathlib import Path

from addons import _
from bases.Kernel import FFLEvent, getLogger
from bases.Settings import SettingsGetter
from bases.Utils import StoreHelper, flushPrint

logger = getLogger(__name__)

MODE_WINDOWS = "windows-explorer"
MODE_MACOS = "macos-services"
MODE_LINUX = "linux-open-with"

_WINDOWS_REG_PATH = r"Software\Classes\AllFilesystemObjects\shell\FastFileLink.Share"
_WINDOWS_MENU_TEXT = _("Share with FastFileLink")
_WINDOWS_MULTI_SELECT_MODEL = "Single"

# Cascading submenu items: (registry-key-name, label, extra-cli-args, icon-path)
# The key names are prefixed with a sort-order digit so Windows displays them
# in the intended order.  Icon paths use REG_EXPAND_SZ so %SystemRoot% expands
# at read time; negative indices address icons from the end of the DLL table.
_WINDOWS_SUBMENU_ITEMS = [
    ('01_Share',       _('Share'),                                    [],                                    r'%SystemRoot%\System32\shell32.dll,264'),
    ('02_OneTime',     _('Share  —  One Download Only'),             ['--max-downloads', '1'],              r'%SystemRoot%\System32\shell32.dll,262'),
    ('03_E2EE',        _('Share Encrypted'),                         ['--e2ee'],                            r'%SystemRoot%\System32\imageres.dll,54'),
    ('04_E2EEOneTime', _('Share Encrypted  —  One Download Only'),   ['--e2ee', '--max-downloads', '1'],    r'%SystemRoot%\System32\imageres.dll,73'),
]

_LINUX_LAUNCHER_DIR = "fastfilelink"
# Each action gets its own desktop file ({base}.desktop) and wrapper script ({base}).
_LINUX_DESKTOP_ACTIONS = [
    ('fastfilelink-share',               _('FastFileLink Share'),                       []),
    ('fastfilelink-share-once',          _('FastFileLink Share Once'),                 ['--max-downloads', '1']),
    ('fastfilelink-share-encrypted',     _('FastFileLink Share Encrypted'),            ['--e2ee']),
    ('fastfilelink-share-encrypted-once', _('FastFileLink Share Encrypted Once'),      ['--e2ee', '--max-downloads', '1']),
]

_MAC_SERVICES_DIR = "Services"
# Each action gets its own Automator workflow bundle appearing in the Services menu.
# Metadata for status-detection is stored in the first bundle.
_MAC_SERVICE_BUNDLES = [
    ('FastFileLink Share.workflow',                []),
    ('FastFileLink Share Once.workflow',          ['--max-downloads', '1']),
    ('FastFileLink Share Encrypted.workflow',      ['--e2ee']),
    ('FastFileLink Share Encrypted Once.workflow', ['--e2ee', '--max-downloads', '1']),
]
_MAC_METADATA_FILE = "ffl-service-metadata.plist"
_MAC_SCRIPT_FILE = "ffl-context-menu.sh"


class ShellIntegration:
    """Platform-agnostic interface for OS context menu / right-click shell integration."""

    PREFERENCE_DEFAULTS = {
        'shellIntegrationEnabled': False,
        'shellIntegrationIdentity': None,
    }

    @classmethod
    def build(cls, settingsGetter=None):
        """Factory method returning a platform-appropriate integration instance."""
        settingsGetter = settingsGetter or SettingsGetter.getInstance()

        if settingsGetter.isWindows():
            return WindowsIntegration.create(settingsGetter)

        if settingsGetter.isDarwin():
            return MacIntegration.create(settingsGetter)

        if settingsGetter.isLinux():
            return LinuxIntegration.create(settingsGetter)

        return UnsupportedIntegration(_("OS context menu integration is not available on this platform."))

    @property
    def supported(self):
        raise NotImplementedError()

    @property
    def status(self):
        raise NotImplementedError()

    def setEnabled(self, enabled):
        raise NotImplementedError()


class UnsupportedIntegration(ShellIntegration):

    def __init__(self, reason):
        self._reason = reason

    @property
    def supported(self):
        return False

    @property
    def status(self):
        return {
            'supported': False,
            'enabled': False,
            'reason': self._reason,
            'mode': None,
            'identity': None,
        }

    def setEnabled(self, enabled):
        raise RuntimeError(self._reason)


class _BaseIntegration(ShellIntegration):
    """
    Base for platform-specific integrations.

    execPath  — the path used for identity / change-detection (FFL.py in dev mode,
                ffl binary in packaged mode).
    commandArgs — the command prefix written to the OS, without the file argument
                  (e.g. [python, FFL.py, --cli]  or  [ffl.exe]).
    """

    def __init__(self, mode, execPath, commandArgs):
        self._mode = mode
        self._execPath = execPath
        self._commandArgs = commandArgs

    @property
    def supported(self):
        return True

    @property
    def identity(self):
        return {
            'mode': self._mode,
            'target': self._normalizePath(self._execPath),
        }

    def setEnabled(self, enabled):
        if enabled:
            self._enable()
        else:
            self._disable()

        currentStatus = self.status
        if enabled and not currentStatus['enabled']:
            raise RuntimeError(_("FastFileLink could not verify OS context menu registration."))
        return currentStatus

    @property
    def status(self):
        raise NotImplementedError()

    def _enable(self):
        raise NotImplementedError()

    def _disable(self):
        raise NotImplementedError()

    @staticmethod
    def _normalizePath(path):
        if not path:
            return None
        return os.path.normcase(os.path.abspath(path))

    @staticmethod
    def _resolveCommandArgs(settingsGetter):
        """Return (execPath, commandArgs) for OS registration.

        Dev mode  → execPath = FFL.py,    commandArgs = [python, FFL.py, --cli]
        Packaged  → execPath = ffl binary, commandArgs = [ffl binary]
        """
        if settingsGetter.isRunOnDevelopment():
            corePath = os.path.normcase(os.path.abspath(
                os.path.join(settingsGetter.baseDir, 'FFL.py')
            ))
            pythonExe = os.path.normcase(os.path.abspath(sys.executable))
            return corePath, [pythonExe, corePath, '--cli']

        exePath = settingsGetter.exePath or sys.executable
        exePath = os.path.normcase(os.path.abspath(exePath))
        if not os.path.isfile(exePath):
            return None, None
        return exePath, [exePath]

    @staticmethod
    def _writeTextFile(path, content):
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(content)

    @staticmethod
    def _runIfAvailable(binary, args):
        executable = shutil.which(binary)
        if not executable:
            return
        try:
            subprocess.run([executable, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception as e:
            logger.debug(f"Optional command failed: {binary} {args} -> {e}")


class WindowsIntegration(_BaseIntegration):

    def __init__(self, execPath, commandArgs):
        super().__init__(MODE_WINDOWS, execPath, commandArgs)
        import winreg
        self._winreg = winreg

    @classmethod
    def create(cls, settingsGetter):
        try:
            import winreg  # noqa: F401
        except ImportError:
            return UnsupportedIntegration(_("Windows registry support is unavailable in this runtime."))

        if StoreHelper.isWindowsStore():
            return UnsupportedIntegration(_("OS context menu integration is unavailable in Windows Store builds."))

        execPath, commandArgs = cls._resolveCommandArgs(settingsGetter)
        if not execPath:
            return UnsupportedIntegration(_("Unable to locate the FastFileLink executable."))

        return cls(execPath, commandArgs)

    def _buildCommandValue(self, extraArgs=()):
        """Build a registry command string with optional extra args before the file placeholder."""
        parts = [f'"{arg}"' for arg in self._commandArgs]
        parts.extend(f'"{arg}"' for arg in extraArgs)
        parts.append('"%1"')
        return ' '.join(parts)

    @property
    def _commandValue(self):
        """Base 'Share' command value — no extra args."""
        return self._buildCommandValue()

    @property
    def status(self):
        winreg = self._winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINDOWS_REG_PATH) as key:
                subCommands = self._queryRegValue(key, 'SubCommands')

            if subCommands is None:
                # Key exists but has no SubCommands — old single-command format
                return {
                    'supported': True,
                    'enabled': False,
                    'reason': None,
                    'mode': MODE_WINDOWS,
                    'identity': self.identity,
                    'installedCommand': None,
                }

            firstCmdPath = _WINDOWS_REG_PATH + r'\shell\01_Share\command'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, firstCmdPath) as key:
                commandValue = self._queryRegValue(key, None)

            enabled = commandValue == self._commandValue
            return {
                'supported': True,
                'enabled': enabled,
                'reason': None,
                'mode': MODE_WINDOWS,
                'identity': self.identity,
                'installedCommand': commandValue,
            }
        except FileNotFoundError:
            logger.debug(f"Windows shell integration registry key not found: {_WINDOWS_REG_PATH}")
            return {
                'supported': True,
                'enabled': False,
                'reason': None,
                'mode': MODE_WINDOWS,
                'identity': self.identity,
                'installedCommand': None,
            }
        except Exception as e:
            logger.warning(f"Failed to query Windows shell integration: {e}")
            return {
                'supported': True,
                'enabled': False,
                'reason': _("FastFileLink could not read the Windows context menu registration."),
                'mode': MODE_WINDOWS,
                'identity': self.identity,
            }

    def _enable(self):
        winreg = self._winreg

        # Remove any existing installation before creating the new layout.
        # This handles upgrades from the old single-command format cleanly.
        self._deleteRegTree(winreg.HKEY_CURRENT_USER, _WINDOWS_REG_PATH)

        # Parent key — shows the "Share with FastFileLink ▶" cascading menu header.
        # SubCommands = "" tells Windows to look for items under the shell\ subkey.
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _WINDOWS_REG_PATH) as key:
            winreg.SetValueEx(key, None,             0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'MUIVerb',        0, winreg.REG_SZ, _WINDOWS_MENU_TEXT)
            winreg.SetValueEx(key, 'Icon',           0, winreg.REG_SZ, self._commandArgs[0])
            winreg.SetValueEx(key, 'SubCommands',    0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'MultiSelectModel', 0, winreg.REG_SZ, _WINDOWS_MULTI_SELECT_MODEL)

        # Submenu items
        shellBase = _WINDOWS_REG_PATH + r'\shell'
        for keyName, label, extraArgs, iconPath in _WINDOWS_SUBMENU_ITEMS:
            subPath = shellBase + '\\' + keyName
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subPath) as key:
                winreg.SetValueEx(key, None,   0, winreg.REG_SZ,        label)
                winreg.SetValueEx(key, 'Icon', 0, winreg.REG_EXPAND_SZ, iconPath)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subPath + r'\command') as key:
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, self._buildCommandValue(extraArgs))

    def _disable(self):
        winreg = self._winreg
        self._deleteRegTree(winreg.HKEY_CURRENT_USER, _WINDOWS_REG_PATH)

    def _deleteRegTree(self, rootKey, subKey):
        winreg = self._winreg
        try:
            with winreg.OpenKey(rootKey, subKey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                childCount = winreg.QueryInfoKey(key)[0]
                for _i in range(childCount):
                    childName = winreg.EnumKey(key, 0)
                    self._deleteRegTree(rootKey, subKey + '\\' + childName)
        except FileNotFoundError:
            logger.debug(f"Registry key already absent, skipping: {subKey}")
            return
            
        try:
            winreg.DeleteKey(rootKey, subKey)
        except FileNotFoundError:
            logger.debug(f"Registry key already deleted: {subKey}")

    def _queryRegValue(self, key, name):
        try:
            return self._winreg.QueryValueEx(key, name)[0]
        except OSError as e:
            logger.debug(f"Registry value {name!r} not found: {e}")
            return None


class MacIntegration(_BaseIntegration):

    def __init__(self, execPath, commandArgs, isAppBundle=False):
        super().__init__(MODE_MACOS, execPath, commandArgs)
        self._isAppBundle = isAppBundle

    @classmethod
    def create(cls, settingsGetter):
        if StoreHelper.isAppleStore():
            return UnsupportedIntegration(_("OS context menu integration is unavailable in sandboxed macOS builds."))

        if not settingsGetter.isRunOnDevelopment():
            # Packaged mode: use open -a with .app bundle
            bundlePath = cls._findAppBundle(settingsGetter.exePath) or cls._findAppBundle(sys.executable)
            if not bundlePath:
                return UnsupportedIntegration(
                    _("OS context menu integration on macOS requires the packaged .app bundle.")
                )
            execPath = os.path.normcase(os.path.abspath(bundlePath))
            return cls(execPath=execPath, commandArgs=[bundlePath], isAppBundle=True)

        # Dev mode: direct Python invocation, no .app bundle needed
        execPath, commandArgs = cls._resolveCommandArgs(settingsGetter)
        if not execPath:
            return UnsupportedIntegration(_("Unable to locate FFL.py for shell integration."))
        return cls(execPath=execPath, commandArgs=commandArgs, isAppBundle=False)

    @staticmethod
    def _findAppBundle(path):
        if not path:
            return None
        current = Path(path).resolve()
        if current.suffix == '.app':
            return str(current)
        for parent in current.parents:
            if parent.suffix == '.app':
                return str(parent)
        return None

    def _getBundlePaths(self, bundleName):
        servicesDir = os.path.join(os.path.expanduser('~'), 'Library', _MAC_SERVICES_DIR)
        bundlePath = os.path.join(servicesDir, bundleName)
        contentsDir = os.path.join(bundlePath, 'Contents')
        resourcesDir = os.path.join(contentsDir, 'Resources')
        return {
            'bundlePath': bundlePath,
            'contentsDir': contentsDir,
            'resourcesDir': resourcesDir,
            'metadataFile': os.path.join(contentsDir, _MAC_METADATA_FILE),
            'scriptFile': os.path.join(resourcesDir, _MAC_SCRIPT_FILE),
            'documentFile': os.path.join(contentsDir, 'document.wflow'),
            'infoPlist': os.path.join(contentsDir, 'Info.plist'),
        }

    @property
    def status(self):
        # Status is determined by the first bundle's metadata file.
        firstBundleName = _MAC_SERVICE_BUNDLES[0][0]
        paths = self._getBundlePaths(firstBundleName)
        if not os.path.exists(paths['metadataFile']):
            return {
                'supported': True,
                'enabled': False,
                'reason': None,
                'mode': MODE_MACOS,
                'identity': self.identity,
                'servicePath': paths['bundlePath'],
            }
        try:
            with open(paths['metadataFile'], 'rb') as handle:
                metadata = plistlib.load(handle)
            # Support both legacy 'appBundle' key and current 'execPath' key
            storedExecPath = metadata.get('execPath') or metadata.get('appBundle')
            enabled = storedExecPath == self._execPath
            return {
                'supported': True,
                'enabled': enabled,
                'reason': None,
                'mode': MODE_MACOS,
                'identity': self.identity,
                'servicePath': paths['bundlePath'],
            }
        except Exception as e:
            logger.warning(f"Failed to read macOS shell integration metadata: {e}")
            return {
                'supported': True,
                'enabled': False,
                'reason': _("FastFileLink could not read the macOS Services registration."),
                'mode': MODE_MACOS,
                'identity': self.identity,
                'servicePath': paths['bundlePath'],
            }

    def _enable(self):
        if self._isAppBundle:
            baseCmd = f'/usr/bin/open -a "{self._commandArgs[0]}" --args'
        else:
            baseCmd = ' '.join(f'"{a}"' for a in self._commandArgs)

        for bundleIdx, (bundleName, extraArgs) in enumerate(_MAC_SERVICE_BUNDLES):
            paths = self._getBundlePaths(bundleName)
            os.makedirs(paths['resourcesDir'], exist_ok=True)

            extraStr = ' '.join(f'"{a}"' for a in extraArgs)
            scriptBody = f'{baseCmd} {extraStr} "$1"' if extraArgs else f'{baseCmd} "$1"'

            scriptContent = textwrap.dedent(f"""\
                #!/bin/sh
                set -eu
                if [ "$#" -lt 1 ]; then
                  exit 0
                fi
                {scriptBody}
            """)
            self._writeTextFile(paths['scriptFile'], scriptContent)
            os.chmod(
                paths['scriptFile'],
                os.stat(paths['scriptFile']).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

            with open(paths['infoPlist'], 'wb') as handle:
                plistlib.dump(self._buildInfoPlist(bundleName), handle)

            with open(paths['documentFile'], 'wb') as handle:
                plistlib.dump(self._buildWorkflowDocument(paths['scriptFile']), handle)

            # Write metadata only into the first bundle for status detection.
            if bundleIdx == 0:
                with open(paths['metadataFile'], 'wb') as handle:
                    plistlib.dump({'execPath': self._execPath, 'mode': MODE_MACOS}, handle)

    def _disable(self):
        for bundleName, _extraArgs in _MAC_SERVICE_BUNDLES:
            paths = self._getBundlePaths(bundleName)
            if os.path.exists(paths['bundlePath']):
                shutil.rmtree(paths['bundlePath'], ignore_errors=True)

    @staticmethod
    def _buildInfoPlist(bundleName):
        serviceName = bundleName.removesuffix('.workflow')
        bundleId = 'com.fastfilelink.service.' + serviceName.lower().replace(' ', '.')
        return {
            'CFBundleIdentifier': bundleId,
            'CFBundleName': serviceName,
            'CFBundlePackageType': 'BNDL',
            'CFBundleVersion': '1',
        }

    @staticmethod
    def _buildWorkflowDocument(scriptPath):
        command = f'"{scriptPath}" "$@"'
        return {
            'AMApplicationBuild': '554',
            'AMApplicationVersion': '2.10',
            'actions': [{
                'action': {
                    'ActionBundlePath': '/System/Library/Automator/Run Shell Script.action',
                    'ActionName': 'Run Shell Script',
                    'ActionParameters': {
                        'COMMAND_STRING': command,
                        'CheckedForUserDefaultShell': True,
                        'inputMethod': 1,
                        'shell': '/bin/zsh',
                        'source': command,
                    },
                    'AMAccepts': {
                        'Container': 'List',
                        'Optional': False,
                        'Types': ['com.apple.cocoa.path'],
                    },
                    'AMProvides': {
                        'Container': 'List',
                        'Types': ['com.apple.cocoa.path'],
                    },
                    'AMActionVersion': '2.4.1',
                    'AMApplication': 'Automator',
                },
                'isViewVisible': False,
            }],
            'connectors': [],
            'workflowMetaData': {
                'serviceApplicationBundleIdentifier': 'com.apple.finder',
                'serviceInputTypeIdentifier': 'com.apple.Automator.fileSystemObject',
                'serviceOutputTypeIdentifier': 'com.apple.Automator.nothing',
                'serviceProcessesInput': 0,
            },
        }


class LinuxIntegration(_BaseIntegration):

    def __init__(self, execPath, commandArgs):
        super().__init__(MODE_LINUX, execPath, commandArgs)

    @classmethod
    def create(cls, settingsGetter):
        execPath, commandArgs = cls._resolveCommandArgs(settingsGetter)
        if not execPath:
            return UnsupportedIntegration(_("Unable to locate the FastFileLink executable."))
            
        return cls(execPath, commandArgs)

    def _getActionPaths(self, baseName):
        dataHome = os.getenv('XDG_DATA_HOME') or os.path.join(os.path.expanduser('~'), '.local', 'share')
        applicationsDir = os.path.join(dataHome, 'applications')
        launcherDir = os.path.join(dataHome, _LINUX_LAUNCHER_DIR)
        
        return {
            'applicationsDir': applicationsDir,
            'desktopFile': os.path.join(applicationsDir, baseName + '.desktop'),
            'launcherDir': launcherDir,
            'wrapperFile': os.path.join(launcherDir, baseName),
        }

    @property
    def status(self):
        # Status is determined by the first action's files.
        firstBase = _LINUX_DESKTOP_ACTIONS[0][0]
        paths = self._getActionPaths(firstBase)
        enabled = os.path.exists(paths['wrapperFile']) and os.path.exists(paths['desktopFile'])
        
        return {
            'supported': True,
            'enabled': enabled,
            'reason': None,
            'mode': MODE_LINUX,
            'identity': self.identity,
            'desktopFile': paths['desktopFile'],
            'wrapperFile': paths['wrapperFile'],
        }

    def _enable(self):
        firstBase = _LINUX_DESKTOP_ACTIONS[0][0]
        firstPaths = self._getActionPaths(firstBase)
        os.makedirs(firstPaths['applicationsDir'], exist_ok=True)
        os.makedirs(firstPaths['launcherDir'], exist_ok=True)

        baseCmdStr = ' '.join(f'"{a}"' for a in self._commandArgs)
        tryExec = self._escapeDesktopValue(self._commandArgs[0])

        for baseName, displayName, extraArgs in _LINUX_DESKTOP_ACTIONS:
            paths = self._getActionPaths(baseName)

            extraStr = ' '.join(f'"{a}"' for a in extraArgs)
            fullCmd = f'{baseCmdStr} {extraStr}' if extraArgs else baseCmdStr
            wrapperContent = textwrap.dedent(f"""\
                #!/bin/sh
                set -eu
                exec {fullCmd} "$1"
            """)
            desktopContent = textwrap.dedent(f"""\
                [Desktop Entry]
                Type=Application
                Version=1.0
                Name={displayName}
                Comment={_('Open the selected file or folder in FastFileLink')}
                NoDisplay=true
                Terminal=false
                Categories=Utility;
                Exec={self._escapeDesktopExec(paths['wrapperFile'])} %f
                TryExec={tryExec}
                MimeType=inode/directory;application/octet-stream;
                X-FastFileLink-Generated=true
            """)

            self._writeTextFile(paths['wrapperFile'], wrapperContent)
            os.chmod(
                paths['wrapperFile'],
                os.stat(paths['wrapperFile']).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )
            self._writeTextFile(paths['desktopFile'], desktopContent)

        self._runIfAvailable('update-desktop-database', [firstPaths['applicationsDir']])

    def _disable(self):
        sharedPaths = self._getActionPaths(_LINUX_DESKTOP_ACTIONS[0][0])
        for baseName, _displayName, _extraArgs in _LINUX_DESKTOP_ACTIONS:
            paths = self._getActionPaths(baseName)
            for path in (paths['desktopFile'], paths['wrapperFile']):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    logger.debug(f"File already absent, skipping: {path}")
        for directory in (sharedPaths['launcherDir'], sharedPaths['applicationsDir']):
            try:
                os.rmdir(directory)
            except OSError as e:
                logger.debug(f"Could not remove directory {directory}: {e}")

    @staticmethod
    def _escapeDesktopExec(path):
        return path.replace('\\', '\\\\').replace(' ', '\\ ')

    @staticmethod
    def _escapeDesktopValue(value):
        return value.replace('\\', '\\\\').replace('\n', ' ')


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _modeLabel(mode):
    labels = {
        MODE_WINDOWS: _('Windows Explorer (Context Menu)'),
        MODE_MACOS: _('macOS Services (Finder)'),
        MODE_LINUX: _('Linux (Open With)'),
    }
    return labels.get(mode, mode or _('Unknown'))


def _cliStatus(integration):
    status = integration.status
    flushPrint(_('OS Context Menu Integration'))
    
    if not status['supported']:
        flushPrint(_('  Status:   Unavailable'))
        if status.get('reason'):
            flushPrint(_('  Reason:   {reason}').format(reason=status['reason']))
        return
    flushPrint(_('  Platform: {platform}').format(platform=_modeLabel(status['mode'])))
    
    if status['enabled']:
        flushPrint(_('  Status:   Installed'))
    else:
        flushPrint(_('  Status:   Not installed'))
        flushPrint('')
        flushPrint(_("Run 'ffl shell --install' to add FastFileLink to your OS context menu."))


def _cliInstall(integration):
    if not integration.supported:
        flushPrint(_('Error: {reason}').format(reason=integration.status['reason']))
        return 1
        
    try:
        integration.setEnabled(True)
        flushPrint(_('OS context menu integration installed.'))
        flushPrint('')
        _cliStatus(integration)
        return 0
    except RuntimeError as e:
        flushPrint(_('Error: {error}').format(error=e))
        return 1


def _cliUninstall(integration):
    if not integration.supported:
        flushPrint(_('Error: {reason}').format(reason=integration.status['reason']))
        return 1
    try:
        integration.setEnabled(False)
        flushPrint(_('OS context menu integration removed.'))
        return 0
    except RuntimeError as e:
        flushPrint(_('Error: {error}').format(error=e))
        return 1


# ---------------------------------------------------------------------------
# Addon entry point
# ---------------------------------------------------------------------------

def load():
    """Load function called by AddonsManager - register the 'shell' CLI command."""

    def registerShellCommand(parser=None, commandRegistry=None, **kwargs):
        if commandRegistry is None:
            return

        def setupShellParser(subparser):
            group = subparser.add_mutually_exclusive_group()
            group.add_argument(
                '--install',
                action='store_true',
                default=False,
                help=_('Install OS context menu (right-click) integration'),
                dest='shellInstall',
            )
            group.add_argument(
                '--uninstall',
                action='store_true',
                default=False,
                help=_('Remove OS context menu (right-click) integration'),
                dest='shellUninstall',
            )

        commandRegistry['shell'] = {
            'help': _('Manage OS context menu (right-click) integration'),
            'setupFunction': setupShellParser,
        }

    def handleShellCommand(args, argPolicy, **kwargs):
        if getattr(args, 'command', None) != 'shell':
            return

        integration = ShellIntegration.build()

        if getattr(args, 'shellInstall', False):
            exitCode = _cliInstall(integration)
        elif getattr(args, 'shellUninstall', False):
            exitCode = _cliUninstall(integration)
        else:
            _cliStatus(integration)
            exitCode = 0

        argPolicy['exitCode'] = exitCode

    FFLEvent.cliArgumentsCommandsRegister.subscribe(registerShellCommand)
    FFLEvent.cliArgumentsStore.subscribe(handleShellCommand)
