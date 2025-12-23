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
"""
Generic external tunnel provider system supporting Cloudflare Tunnel, ngrok, etc.
"""

import json
import os
import queue
import re
import subprocess
import threading
import time

from typing import Any, Dict, List, Optional, Tuple

from bases.Kernel import getLogger, FFLEvent, StorageLocator
from bases.Tunnel import AsyncTunnelThread
from bases.Settings import SettingsGetter

from addons import _ # I18n for addons domain

logger = getLogger(__name__)


class ExternalTunnelThread(threading.Thread):
    """Sync tunnel thread for external processes like cloudflared"""

    def __init__(self, resultQueue, client):
        self.client = client
        self.resultQueue = resultQueue
        self.e = None
        super().__init__()

    def run(self):
        try:
            # Connect and start listening (sync)
            if self.client.connect():
                tunnelUrl = self.client.getTunnelURL()
                self.resultQueue.put((True, tunnelUrl))
                self.client.listen()
            else:
                logger.error("Failed to connect to the server. Exiting.")
        except Exception as e:
            self.e = e
            self.resultQueue.put((False, None))
            self.kill()

    def kill(self):
        if self.client:
            try:
                self.client.shutdown()
            except Exception as e:
                logger.debug(f"Error during tunnel shutdown: {e}")

            # Force stop if shutdown fails
            if hasattr(self.client, 'stop'):
                self.client.stop()


class StaticURLTunnelClient:
    """Tunnel client for fixed URL configurations (no external command needed)"""

    def __init__(self, config: Dict[str, Any], localPort: int):
        self.config = config
        self.localPort = localPort
        self.running = False
        self.publicUrl = config.get('url', '').replace('{port}', str(localPort))

    def getTunnelURL(self):
        """Get the fixed tunnel URL"""
        return self.publicUrl

    def connect(self) -> bool:
        """'Connect' to fixed URL tunnel (just validate URL)"""
        if not self.publicUrl or not self.publicUrl.startswith(('http://', 'https://')):
            logger.error(f"Invalid fixed URL: {self.publicUrl}")
            return False

        self.running = True
        return True

    def listen(self):
        """Keep tunnel 'alive' - for fixed URLs, this just waits"""
        while self.running:
            time.sleep(1)

    def stop(self):
        """Stop the tunnel"""
        self.running = False

    def shutdown(self):
        """Shutdown tunnel"""
        self.stop()


class ExternalTunnelClient:
    """Generic external tunnel client that manages external tunnel processes"""

    def __init__(self, config: Dict[str, Any], localPort: int):
        self.config = config
        self.localPort = localPort
        self.process = None
        self.running = False
        self.publicUrl = None

    def getTunnelURL(self):
        """Get the tunnel URL"""
        return self.publicUrl

    def connect(self) -> bool:
        """Start external tunnel process and extract public URL"""
        try:
            # Build command from config
            cmd, shell = self._buildCommand()

            # Start process with forced output
            env = os.environ.copy()
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                encoding='utf-8',
                shell=shell,
                env=env,
            )

            # Wait for tunnel URL extraction
            success = self._waitForTunnelUrl()
            if success:
                self.running = True
                return True
            else:
                self._cleanup()
                return False

        except Exception as e:
            self._cleanup()
            raise RuntimeError(f"Failed to start external tunnel: {e}")

    def _buildCommand(self) -> Tuple[List[str], bool]:
        """Build command from configuration"""
        settingsGetter = SettingsGetter.getInstance()

        cmd = [self.config['binary']]
        shell = False
        cmd[0] = settingsGetter.which(cmd[0])

        # Add arguments, replacing placeholders
        for arg in self.config.get('args', []):
            arg = arg.replace('{port}', str(self.localPort))
            arg = arg.replace('{localhost}', '127.0.0.1')
            cmd.append(arg)

        return (cmd, shell)

    def _waitForTunnelUrl(self) -> bool:
        """Wait for tunnel URL to appear in process output"""
        timeout = self.config.get('timeout', 30)
        urlPattern = self.config.get('url_pattern', r'https?://[^\s]+')

        startTime = time.time()
        outputLines = []

        while time.time() - startTime < timeout:
            if self.process.poll() is not None:
                # Process exited
                raise RuntimeError(f"Tunnel process exited with code: {self.process.returncode}")

            try:
                # Read line with timeout
                line = self.process.stdout.readline()
                if line:
                    line = line.strip()
                    outputLines.append(line)

                    # Try to extract URL (handle both plain text and JSON format)
                    matches = re.findall(urlPattern, line)
                    if matches:
                        self.publicUrl = matches[0].rstrip('/')
                        logger.debug(f"Extracted tunnel URL: {self.publicUrl}")
                        return True
                else:
                    # No data available, sleep briefly to avoid busy loop
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error reading tunnel output: {e}")
                break

        logger.error(f"Timeout waiting for tunnel URL. Output: {outputLines}")
        return False

    def listen(self):
        """Keep tunnel alive while process is running"""
        while self.running and self.process and self.process.poll() is None:
            time.sleep(1)

        if self.process and self.process.poll() is not None:
            raise RuntimeError(f"Tunnel process exited with code: {self.process.returncode}")

    def stop(self):
        """Stop the tunnel"""
        self.running = False

    def shutdown(self):
        """Shutdown tunnel process"""
        self.stop()
        self._cleanup()

    def _cleanup(self):
        """Clean up tunnel process"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            except Exception as e:
                logger.error(f"Error cleaning up tunnel process: {e}")
            finally:
                self.process = None


class TunnelRunnerProvider:
    """
    Provider for external tunnel integrations supporting multiple tunnel types
    through configuration files.
    """

    def __init__(self, configPath: Optional[str] = None):
        """
        Initialize TunnelRunnerProvider

        Args:
            configPath: Path to tunnel configuration file
        """
        self.configPath = configPath or self._getDefaultConfigPath()
        self.tunnelConfigs = {}
        self._loadTunnelConfigs()

    def _getDefaultConfigPath(self, prefer=StorageLocator.Location.CURRENT) -> str:
        """Get default configuration path using StorageLocator"""
        storageLocator = StorageLocator.getInstance()
        return storageLocator.findConfig('tunnels.json', prefer=prefer)

    def _loadTunnelConfigs(self):
        """Load tunnel configurations from file"""

        def _load():
            if os.path.exists(self.configPath):
                with open(self.configPath, 'r') as f:
                    data = json.load(f)
                    self.tunnelConfigs = data.get('tunnels', {})
                    logger.info(f"Loaded {len(self.tunnelConfigs)} tunnel configurations")
                return True
            else:
                return False

        try:
            loaded = _load()
            if not loaded:
                # Try to create default config file
                self.configPath = self._createDefaultConfig(
                    self._getDefaultConfigPath(prefer=StorageLocator.Location.HOME)
                )
                _load()
        except Exception as e:
            logger.error(f"Failed to load tunnel configs: {e}")
            self.tunnelConfigs = {}

    def _createDefaultConfig(self, configPath=None):
        """Create default configuration file with simple tunnel examples"""
        defaultConfig = {
            "tunnels": {
                "cloudflare": {
                    "name": "Cloudflare Tunnel",
                    "binary": "cloudflared",
                    "args": ["tunnel", "--url", "http://127.0.0.1:{port}"],
                    "url_pattern": "https://[^\\s]+\\.trycloudflare\\.com",
                    "timeout": 30,
                    "enabled": True
                },
                "cloudflare-fixed": {
                    "name": "Cloudflare Fixed Domain",
                    "url": "https://my-tunnel.example.com",
                    "enabled": False,
                    "_comment": "Example of fixed URL tunnel, just specify the URL. Enable and set your own domain."
                },
                "ngrok": {
                    "name": "ngrok",
                    "binary": "ngrok",
                    "args": ["http", "{port}", "--log", "stdout"],
                    "url_pattern": "https://[^\\s]+\\.ngrok[^\\s]*",
                    "timeout": 30,
                    "enabled": True
                },
                "localtunnel": {
                    "name": "LocalTunnel",
                    "binary": "lt",
                    "args": ["--port", "{port}"],
                    "url_pattern": "https://[^\\s]+\\.loca\\.lt",
                    "timeout": 30,
                    "enabled": True
                },
                "loophole": {
                    "name": "loophole",
                    "binary": "loophole",
                    "args": ["http", "{port}"],
                    "url_pattern": "https://[^\\s]+\\.loophole\\.site",
                    "timeout": 30,
                    "enabled": True
                },
                "devtunnel": {
                    "name": "Dev Tunnel",
                    "binary": "devtunnel",
                    "args": ["host", "-p", "{port}"],
                    "url_pattern": "https://[^\\s]+\\.asse\\.devtunnels\\.ms",
                    "timeout": 30,
                    "enabled": True
                },
                "bore": {
                    "name": "bore",
                    "binary": "bore",
                    "args": ["local", "{port}", "--to", "bore.pub"],
                    "url_pattern": "bore\\.pub:\\d+",
                    "timeout": 30,
                    "enabled": True
                }
            },
            "settings": {
                "preferred_tunnel": "cloudflare",
                "fallback_order": ["cloudflare", "ngrok", "localtunnel", "loophole", "devtunnel", "bore", "default"]
            }
        }

        if not configPath:
            configPath = self.configPath

        try:
            # Save the default config using helper method
            self._saveConfig(defaultConfig, configPath)

            logger.debug(f"Created default tunnel config at: {configPath}")

            # Load the config we just created
            self.tunnelConfigs = defaultConfig.get('tunnels', {})
            return configPath
        except Exception as e:
            # If creation fails, it's okay - user might not have permission
            # or doesn't want the program to create files
            logger.debug(f"Could not create default config file: {e}")
            self.tunnelConfigs = {}
            return None

    def getAvailableTunnels(self, includeDefault=False) -> List[str]:
        """Get list of available/enabled tunnels with existing binaries or fixed URLs"""
        settingsGetter = SettingsGetter.getInstance()

        availableTunnels = []
        for name, config in self.tunnelConfigs.items():
            if not config.get('enabled', False):
                continue

            # Check if it's a fixed URL tunnel (has 'url' field)
            if config.get('url'):
                # Fixed URL tunnel - always available if URL is valid
                url = config.get('url', '')
                if url and (url.startswith(('http://', 'https://')) or '{port}' in url):
                    availableTunnels.append(name)
                else:
                    logger.debug(f"Tunnel '{name}' disabled: invalid fixed URL '{url}'")
                continue

            # Check if binary exists for external command tunnels
            binary = config.get('binary')
            whichBinary = settingsGetter.which(binary)

            if binary and not whichBinary:
                logger.debug(f"Tunnel '{name}' disabled: binary '{binary}' not found in PATH")
                continue

            availableTunnels.append(name)

        if includeDefault:
            availableTunnels.append('default')

        return availableTunnels

    def getTunnelConfig(self, tunnelName: str) -> Optional[Dict[str, Any]]:
        """Get configuration for specific tunnel"""
        return self.tunnelConfigs.get(tunnelName)

    def getTunnelRunnerClass(self, baseTunnelRunnerClass):
        """Create enhanced TunnelRunner that supports external tunnels"""

        provider = self # Reference for closure

        class ExternalTunnelRunner(baseTunnelRunnerClass):
            """TunnelRunner with external tunnel support"""

            def __init__(self, fileSize, proxyConfig=None):
                super().__init__(fileSize, proxyConfig=proxyConfig)
                self.preferredTunnel = self._getPreferredTunnel()

            def getTunnelType(self):
                """Get the type/name of tunnel being used"""
                if self.preferredTunnel:
                    config = provider.getTunnelConfig(self.preferredTunnel)
                    if config:
                        return config.get('name', self.preferredTunnel)
                    return self.preferredTunnel
                return super().getTunnelType()

            def _getPreferredTunnel(self) -> Optional[str]:
                """Get preferred external tunnel if available"""
                settings = provider._getSettings()
                preferred = settings.get('preferred_tunnel', 'default')

                # If preferred is 'default', use builtin Bore tunnel
                if preferred == 'default':
                    return None

                # Check if preferred tunnel is available
                availableTunnels = provider.getAvailableTunnels()
                if preferred in availableTunnels:
                    logger.debug(f"Using preferred tunnel: {preferred}")
                    return preferred

                # Try fallback order
                fallbackOrder = settings.get('fallback_order', [])
                for tunnelName in fallbackOrder:
                    if tunnelName == 'default':
                        return None # Use builtin
                    if tunnelName in availableTunnels:
                        logger.debug(f"Using fallback tunnel: {tunnelName} (preferred '{preferred}' not available)")
                        return tunnelName

                # Use first available or None for builtin
                if availableTunnels:
                    logger.debug(
                        f"Using first available tunnel: {availableTunnels[0]} (preferred '{preferred}' not available)"
                    )
                    return availableTunnels[0]
                else:
                    logger.debug(
                        f"No external tunnels available, falling back to builtin "
                        f"(preferred '{preferred}' not available)"
                    )
                    return None

            def createClient(self, port, **kwargs):
                """Override to support external tunnels"""

                # Try external tunnel first if available
                if self.preferredTunnel:
                    try:
                        return self._createExternalClient(port)
                    except Exception as e:
                        logger.warning(f"External tunnel {self.preferredTunnel} failed: {e}")

                # Fallback to parent's method (builtin or Features enhancement)
                return super().createClient(port, **kwargs)

            def _createExternalClient(self, port):
                """Create external tunnel client"""
                config = provider.getTunnelConfig(self.preferredTunnel)
                if not config:
                    raise ValueError(f"No config found for tunnel: {self.preferredTunnel}")

                # Check if it's a fixed URL tunnel
                if config.get('url'):
                    return StaticURLTunnelClient(config, port)
                else:
                    return ExternalTunnelClient(config, port)

            def createTunnelThread(self, client):
                """Create tunnel thread - use ExternalTunnelThread for external clients"""
                resultQueue = queue.Queue()
                if isinstance(client, (ExternalTunnelClient, StaticURLTunnelClient)):
                    tunnelThread = ExternalTunnelThread(resultQueue, client)
                else:
                    # For BoreClient or other async clients, use AsyncTunnelThread
                    tunnelThread = AsyncTunnelThread(resultQueue, client)
                return tunnelThread, resultQueue

        return ExternalTunnelRunner

    def _ensureConfigDirectory(self, configPath: str):
        """Ensure the directory for config path exists"""
        configDir = os.path.dirname(configPath)
        if configDir:
            os.makedirs(configDir, exist_ok=True)

    def _loadConfig(self, configPath: str = None) -> Dict[str, Any]:
        """Load configuration from file or return empty dict"""
        if configPath is None:
            configPath = self.configPath

        if os.path.exists(configPath):
            try:
                with open(configPath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config from {configPath}: {e}")
        return {}

    def _saveConfig(self, config: Dict[str, Any], configPath: str = None):
        """Save configuration to file with proper error handling"""
        if configPath is None:
            configPath = self.configPath

        try:
            self._ensureConfigDirectory(configPath)
            with open(configPath, 'w') as f:
                json.dump(config, f, indent=2)
            logger.debug(f"Successfully saved config to {configPath}")
        except Exception as e:
            logger.error(f"Failed to save config to {configPath}: {e}")
            raise

    def _getSettings(self) -> Dict[str, Any]:
        """Get tunnel settings from config"""
        config = self._loadConfig()
        return config.get('settings', {})

    def _setPreferredTunnel(self, tunnelName: str):
        """Set preferred tunnel in config"""
        try:
            # Load existing config or create new one
            config = self._loadConfig()

            # Ensure settings section exists
            if 'settings' not in config:
                config['settings'] = {}

            # Set preferred tunnel
            config['settings']['preferred_tunnel'] = tunnelName

            # Save config
            self._saveConfig(config)

            logger.info(f"Set preferred tunnel to '{tunnelName}' in {self.configPath}")

        except Exception as e:
            logger.error(f"Failed to set preferred tunnel: {e}")
            raise

    def registerCLIArguments(self, parser=None, **kwargs):
        """Register tunnel-specific CLI arguments"""
        # Get available tunnel providers
        availableTunnels = self.getAvailableTunnels(includeDefault=True)

        parser.add_argument(
            "--preferred-tunnel",
            choices=availableTunnels,
            help=_("Set preferred tunnel for future runs. Available: {tunnels}").format(
                tunnels=', '.join(availableTunnels)
            ),
            dest="preferredTunnel"
        )

    def handlePreferredTunnelSetting(self, args=None, **kwargs):
        """Handle the --preferred-tunnel argument if provided"""
        if hasattr(args, 'preferredTunnel') and args.preferredTunnel:
            self._setPreferredTunnel(args.preferredTunnel)


# Factory function for integration with Features.py
def createTunnelRunnerProvider(configPath: Optional[str] = None) -> TunnelRunnerProvider:
    """Create TunnelRunnerProvider instance"""
    return TunnelRunnerProvider(configPath)


def load():
    """Load function called by AddonsManager - register for CLI argument events"""
    provider = TunnelRunnerProvider()

    FFLEvent.cliArgumentsShareOptionsRegister.subscribe(provider.registerCLIArguments)
    FFLEvent.cliArgumentsStore.subscribe(provider.handlePreferredTunnelSetting)
