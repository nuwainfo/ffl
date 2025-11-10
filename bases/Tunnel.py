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

import asyncio
import queue
import threading
import urllib.parse
import os

import requests

from bases.Bore import BoreClient
from bases.Kernel import getLogger

BUILTIN_TUNNEL = os.getenv('BUILTIN_TUNNEL', '33.fastfilelink.com')
TUNNEL_TOKEN_SERVER_URL = os.getenv('TUNNEL_TOKEN_SERVER_URL', 'https://fastfilelink.com')

logger = getLogger(__name__)


def fetchTunnelToken():
    """Fetch tunnel authentication token from token server"""
    serverURL = os.getenv(
        'TUNNEL_TOKEN_SERVER_URL', TUNNEL_TOKEN_SERVER_URL
    ) # Fetch again to make sure its final value.

    try:
        response = requests.get(f"{serverURL}/api/tunnel/token", timeout=10)
        response.raise_for_status()
        tokenData = response.json()
        token = tokenData.get('token')
        expiresIn = tokenData.get('expires_in', 300)

        logger.info(f"Retrieved tunnel token, expires in {expiresIn} seconds")
        logger.debug(f"Token: {token}")

        return token
    except Exception as e:
        logger.error(f"Failed to fetch tunnel token from {TUNNEL_TOKEN_SERVER_URL}: {e}")
        raise ConnectionError(f'Cannot fetch tunnel token: {e}')


class AsyncTunnelThread(threading.Thread):
    """Async tunnel thread for async clients like BoreClient"""

    def __init__(self, resultQueue, client):
        self.client = client
        self.resultQueue = resultQueue
        self.e = None
        self.loop = asyncio.new_event_loop()
        super().__init__()

    def run(self):
        try:
            # Cannot use asyncio.run & loop.add_signal_handler because
            # the error of "set_wakeup_fd only works in main thread of the main interpreter"
            self.loop.run_until_complete(self.main())
        except Exception as e:
            self.e = e
            self.resultQueue.put((False, None))
            self.kill()

    async def main(self):
        # Connect and start listening
        if await self.client.connect():
            try:
                tunnelUrl = self.client.getTunnelURL()
                self.resultQueue.put((True, tunnelUrl))
                await self.client.listen()
            except Exception as e:
                logger.exception(e)
                await self.client.shutdown()
        else:
            logger.error("Failed to connect to the server. Exiting.")
            raise ConnectionError(f'Failed to connect to tunnel server.')

    def kill(self):
        if self.client:
            try:
                # Use proper shutdown method that handles task cancellation
                future = asyncio.run_coroutine_threadsafe(self.client.shutdown(), self.loop)
                future.result(timeout=2) # Wait up to 2 seconds for shutdown
            except Exception as e:
                logger.debug(f"Error during tunnel shutdown: {e}")


class TunnelRunner:
    """
    Tunnel management class that handles tunnel creation, running, and cleanup.
    Designed specifically for Core.py usage pattern.
    """

    def __init__(self, fileSize):
        """
        Initialize TunnelRunner
        
        Args:
            fileSize: Size of file being shared (for tunnel optimization)
        """
        self.fileSize = fileSize
        self.tunnelThread = None
        self.lock = threading.Lock()

    def getTunnelType(self):
        """
        Get the type/name of tunnel being used
        
        Returns:
            str: Name of the tunnel type (e.g., "default", "Cloudflare", etc.)
        """
        return "default"

    def createClient(self, port, **kwargs):
        """
        Create BoreClient instance with given parameters
        
        Args:
            port: Local port to tunnel
            
        Returns:
            BoreClient: Configured client instance
        """

        # Get tunnel configuration
        # Use builtin tunnel domain
        domain = BUILTIN_TUNNEL

        # Validate builtin tunnel reachable
        try:
            reachable = requests.get(f"https://{domain}/", timeout=5).text is not None
        except Exception as e:
            logger.error(f"Failed to verify tunnel server reachability: {e}")
            raise ConnectionError('Cannot connect to any FastFileLink server.')

        if not reachable:
            raise ConnectionError('Cannot connect to any FastFileLink server.')

        # Fetch authentication token from token server
        secret = fetchTunnelToken()

        return BoreClient(
            localhost='127.0.0.1',
            localPort=port,
            remoteHost=domain,
            remotePort=0,
            secret=secret,
            verbose=False,
            debug=False,
            useHttps=True,
            **kwargs
        )

    def createTunnelThread(self, client):
        """
        Create tunnel thread with client
        
        Args:
            client: BoreClient instance (async)
            
        Returns:
            AsyncTunnelThread: Thread instance ready to start
        """
        resultQueue = queue.Queue()
        tunnelThread = AsyncTunnelThread(resultQueue, client)
        return tunnelThread, resultQueue

    def start(self, port):
        """
        Start tunnel connection
        
        Args:
            port: Local port to tunnel
            
        Returns:
            tuple: (domain: str, link: str)
            
        Raises:
            ConnectionError: When tunnel connection fails
        """
        with self.lock:
            if self.tunnelThread:
                raise RuntimeError("Tunnel already started")

        try:
            # Create client and tunnel thread
            client = self.createClient(port)
            self.tunnelThread, resultQueue = self.createTunnelThread(client)
            self.tunnelThread.start()

            # Wait for connection result
            try:
                success, tunnelUrl = resultQueue.get(timeout=120)
                if not success:
                    ex = None
                    if hasattr(self.tunnelThread, 'e') and self.tunnelThread.e:
                        ex = self.tunnelThread.e

                    self._cleanup()

                    if ex:
                        raise ex
                    else:
                        raise ConnectionError("Tunnel connection failed")

                # tunnelUrl is now the complete URL from getTunnelURL()
                link = tunnelUrl if tunnelUrl.endswith('/') else tunnelUrl + "/"

                # Extract domain from URL
                parsed = urllib.parse.urlparse(link)
                domain = parsed.netloc

                logger.info(f"Tunnel connected: {link}")
                return domain, link

            except queue.Empty:
                self._cleanup()
                raise ConnectionError('Tunnel server timeout.')

        except Exception as e:
            self._cleanup()
            raise e

    def stop(self):
        """Stop tunnel connection and cleanup"""
        self._cleanup()

    def _cleanup(self):
        """Internal cleanup method"""
        with self.lock:
            if self.tunnelThread:
                try:
                    self.tunnelThread.kill()
                    self.tunnelThread.join(timeout=5)
                    if self.tunnelThread.is_alive():
                        logger.warning("Tunnel thread did not terminate cleanly")
                except Exception as e:
                    logger.error(f"Error during tunnel cleanup: {e}")
                finally:
                    self.tunnelThread = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, excType, excValue, traceback):
        """Context manager exit with automatic cleanup"""
        self.stop()
        return False
