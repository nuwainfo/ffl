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
Tor detection and verification utilities.

This module provides robust Tor proxy detection using multiple verification methods:
1. Port availability check (fast preflight)
2. check.torproject.org page parsing
3. Exit IP verification against Tor exit list
4. Onionoo API relay lookup
"""

import re
import socket

from typing import Optional

import requests

from bases.Kernel import getLogger
from bases.Utils import ProxyConfig, parseProxyString, setupProxyEnvironment

logger = getLogger(__name__)

# Tor verification endpoints
CHECK_TOR_HTML = "https://check.torproject.org/"
CHECK_TOR_EXIT_ADDRESSES = "https://check.torproject.org/exit-addresses"
IPIFY_JSON = "https://api.ipify.org?format=json"
ONIONOO_SEARCH = "https://onionoo.torproject.org/details?search="

# Common Tor SOCKS5 ports
TOR_BROWSER_PORT = 9150 # Tor Browser Bundle default
TOR_SERVICE_PORT = 9050 # Tor standalone service default


def isPortOpen(host: str, port: int, timeout: float = 0.8) -> bool:
    """
    Fast preflight check: verify something is listening on host:port.

    Args:
        host: Hostname or IP address
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        bool: True if port is open and accepting connections
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def isTorPort(proxyConfig: ProxyConfig) -> bool:
    """
    Quick heuristic check if proxy configuration looks like Tor (naive detection).

    Checks if:
    - Proxy type is SOCKS5
    - Host is localhost (127.0.0.1 or localhost)
    - Port is common Tor port (9150 or 9050)

    Note: This is a heuristic only - not a proof of Tor. Use verifyTorProxy() for robust verification.

    Args:
        proxyConfig: Proxy configuration from parseProxyString()

    Returns:
        bool: True if configuration looks like common Tor setup
    """
    if proxyConfig['type'] != 'socks5':
        return False

    host = proxyConfig['host']
    port = proxyConfig['port']

    if host not in ['127.0.0.1', 'localhost']:
        return False

    if port not in [TOR_BROWSER_PORT, TOR_SERVICE_PORT]:
        return False

    return True


def makeRequestsProxies(proxyUrl: str) -> dict:
    """
    Convert proxy URL to requests library proxy dict format.

    Args:
        proxyUrl: Proxy URL (e.g., 'socks5h://127.0.0.1:9150')

    Returns:
        dict: Proxy configuration for requests library
    """
    return {"http": proxyUrl, "https": proxyUrl}


def fetchText(url: str, proxies: dict, timeout: float = 10.0) -> Optional[str]:
    """
    Fetch URL content as text through proxy.

    Args:
        url: URL to fetch
        proxies: Proxy configuration dict (requests format)
        timeout: Request timeout in seconds

    Returns:
        str: Response text if successful
        None: If request fails
    """
    try:
        response = requests.get(url, proxies=proxies, timeout=timeout)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.debug(f"Failed to fetch {url}: {e}")
        return None


def fetchJson(url: str, proxies: dict, timeout: float = 10.0) -> Optional[dict]:
    """
    Fetch URL content as JSON through proxy.

    Args:
        url: URL to fetch
        proxies: Proxy configuration dict (requests format)
        timeout: Request timeout in seconds

    Returns:
        dict: Parsed JSON response if successful
        None: If request fails or JSON parsing fails
    """
    try:
        response = requests.get(url, proxies=proxies, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.debug(f"Failed to fetch JSON from {url}: {e}")
        return None


def checkViaCheckPage(proxies: dict) -> Optional[bool]:
    """
    Detect Tor by parsing check.torproject.org HTML page.

    This is the most reliable method - the official Tor check page explicitly
    indicates if the connection is using Tor.

    Args:
        proxies: Proxy configuration dict (requests format)

    Returns:
        True: Page indicates connection is using Tor
        False: Page indicates connection is NOT using Tor
        None: Page unreachable or parsing uncertain
    """
    html = fetchText(CHECK_TOR_HTML, proxies, timeout=30.0)
    if not html:
        return None

    # Check for positive Tor indicator
    # Pattern: "Congratulations. This browser is configured to use Tor."
    if re.search(r"Congratulations.*use Tor", html, re.IGNORECASE | re.DOTALL):
        logger.debug("check.torproject.org confirms Tor usage")
        return True

    # Check for negative Tor indicator
    # Pattern: "Sorry. You are not using Tor."
    if re.search(r"Sorry.*not using Tor", html, re.IGNORECASE | re.DOTALL):
        logger.debug("check.torproject.org indicates NOT using Tor")
        return False

    # Page content unrecognized - could be captive portal, error, etc.
    logger.debug("check.torproject.org page content unrecognized")
    return None


def getExitIp(proxies: dict) -> Optional[str]:
    """
    Get exit IP address as seen by external services when using proxy.

    Args:
        proxies: Proxy configuration dict (requests format)

    Returns:
        str: Public IP address if successful
        None: If request fails
    """
    data = fetchJson(IPIFY_JSON, proxies, timeout=10.0)
    if not data:
        return None

    ip = data.get("ip")
    if isinstance(ip, str) and ip:
        return ip

    return None


def checkIpInExitList(ip: str, proxies: Optional[dict] = None) -> Optional[bool]:
    """
    Check if IP address is in Tor exit node list.

    Downloads the official Tor exit-addresses list and checks if the given IP
    is listed as a Tor exit node.

    Args:
        ip: IP address to check
        proxies: Optional proxy configuration (default: fetch list directly)

    Returns:
        True: IP is listed as Tor exit node
        False: IP is NOT in the exit list
        None: Could not fetch or parse exit list
    """
    try:
        response = requests.get(CHECK_TOR_EXIT_ADDRESSES, proxies=proxies, timeout=15.0)
        response.raise_for_status()
        text = response.text
    except Exception as e:
        logger.debug(f"Failed to fetch Tor exit list: {e}")
        return None

    # Lines look like: "ExitAddress 1.2.3.4 2026-01-01 00:00:00"
    pattern = re.compile(rf"^ExitAddress\s+{re.escape(ip)}\s+", re.MULTILINE)
    return bool(pattern.search(text))


def checkViaOnionoo(ip: str) -> Optional[bool]:
    """
    Check if IP is a known Tor relay using Onionoo API.

    The Onionoo API provides details about Tor relays. Note that not all relays
    are exit nodes, so this is supplementary evidence.

    Args:
        ip: IP address to check

    Returns:
        True: IP found in Tor relay database
        False: IP not found in relay database
        None: API request failed
    """
    url = ONIONOO_SEARCH + ip
    data = fetchJson(url, {}, timeout=12.0)

    if not data:
        return None

    relays = data.get("relays") or []
    return len(relays) > 0


def verifyTorProxy(proxyConfig: ProxyConfig, skipExitListCheck: bool = False) -> bool:
    """
    Robustly verify if proxy is actually a Tor proxy using multiple methods.

    Verification steps (in order):
    1. Port availability check (preflight)
    2. check.torproject.org page parsing (most reliable)
    3. Exit IP verification against Tor exit list (if not skipped)
    4. Onionoo API relay lookup (supplementary)

    Args:
        proxyConfig: Proxy configuration from parseProxyString()
        skipExitListCheck: Skip exit list check (faster but less thorough)

    Returns:
        bool: True if proxy is verified as Tor, False otherwise

    Raises:
        RuntimeError: If proxy port is not listening
    """
    # Extract host and port
    host = proxyConfig['host']
    port = proxyConfig['port']
    proxyUrl = proxyConfig['url']

    # Preflight: Verify port is actually listening (for localhost proxies)
    if host in ['127.0.0.1', 'localhost']:
        if not isPortOpen(host, port):
            raise RuntimeError(
                f"Proxy port is not listening: {host}:{port}. "
                f"Did you start Tor Browser / tor daemon?"
            )

    # Prepare requests proxy configuration
    proxies = makeRequestsProxies(proxyUrl)

    # Step 1: Check via check.torproject.org (most reliable)
    pageResult = checkViaCheckPage(proxies)
    if pageResult is True:
        logger.debug(f"Tor verified via check.torproject.org: {proxyUrl}")
        return True

    if pageResult is False:
        logger.debug(f"check.torproject.org indicates NOT Tor: {proxyUrl}")
        return False

    # Page check was inconclusive - continue with IP-based verification
    logger.debug("check.torproject.org check inconclusive, trying IP verification")

    # Step 2: Get exit IP through proxy
    exitIp = getExitIp(proxies)
    if not exitIp:
        logger.debug(f"Could not fetch exit IP through proxy. ")
        return False

    logger.debug(f"Exit IP through proxy: {exitIp}")

    # Step 3: Check if exit IP is in Tor exit list (unless skipped)
    if not skipExitListCheck:
        exitListResult = checkIpInExitList(exitIp, proxies=None)
        if exitListResult is True:
            logger.debug(f"Exit IP {exitIp} verified in Tor exit list")
            return True

        if exitListResult is False:
            logger.debug(f"Exit IP {exitIp} not in Tor exit list (could be non-exit relay)")
        else:
            logger.debug("Could not fetch Tor exit list")

    # Step 4: Fallback to Onionoo API check (supplementary)
    onionooResult = checkViaOnionoo(exitIp)
    if onionooResult is True:
        logger.debug(f"Exit IP {exitIp} found in Tor relay database (Onionoo)")
        return True

    # All verification methods failed or were inconclusive
    logger.debug(f"Could not verify proxy as Tor: {proxyUrl}")
    return False


def detectTorProxy(checkPorts: Optional[list] = None) -> Optional[str]:
    """
    Detect if Tor is running on common ports by checking port availability.

    This is a fast heuristic check - use verifyTorProxy() for robust verification.

    Args:
        checkPorts: List of ports to check (default: [9150, 9050])

    Returns:
        str: Proxy URL if Tor detected (e.g., 'socks5://127.0.0.1:9150')
        None: If Tor not detected on any port
    """
    if checkPorts is None:
        checkPorts = [TOR_BROWSER_PORT, TOR_SERVICE_PORT]

    for port in checkPorts:
        if isPortOpen('127.0.0.1', port):
            logger.debug(f"Detected open port on 127.0.0.1:{port}")
            return f"socks5://127.0.0.1:{port}"

    return None


def setupTorProxy(verify: bool = False) -> tuple[Optional[ProxyConfig], Optional[str]]:
    """
    Detect, verify, and setup Tor proxy configuration.

    This is a convenience function that combines detectTorProxy(), parseProxyString(),
    verifyTorProxy(), and setupProxyEnvironment() into a single call.

    Args:
        verify: If True, performs full Tor verification using verifyTorProxy()
                If False, only detects and parses the proxy (faster)

    Returns:
        tuple: (proxyConfig, proxyUrl) if successful, (None, None) otherwise
    """
    # Detect Tor on common ports
    torProxyUrl = detectTorProxy()
    if not torProxyUrl:
        return None, None

    # Parse proxy string
    proxyConfig = parseProxyString(torProxyUrl)
    if not proxyConfig:
        logger.warning(f"Failed to parse Tor proxy string: {torProxyUrl}")
        return None, None

    # Verify if requested
    if verify:
        try:
            if not verifyTorProxy(proxyConfig, skipExitListCheck=True):
                logger.warning(f"Tor verification failed for proxy: {torProxyUrl}")
                return None, None
        except RuntimeError as e:
            logger.warning(f"Tor verification error: {e}")
            return None, None

    # Setup proxy environment variables
    setupProxyEnvironment(proxyConfig)
    logger.debug(f"Tor proxy configured: {torProxyUrl}")

    return proxyConfig, torProxyUrl
