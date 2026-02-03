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
CorePatched.py - A wrapper around Core.py that optionally injects network instability simulation
for FastFileLink upload operations. When no instability parameters are provided, it behaves exactly like Core.py.
"""

import os
import sys
import random
import argparse
import importlib.util
import re
import logging
import tempfile
import datetime

import requests
import requests_mock

# Import original Core module
CORE_BASE_PATH = os.path.join(os.path.dirname(__file__), '..')
CORE_PATH = os.path.join(CORE_BASE_PATH, 'Core.py')
spec = importlib.util.spec_from_file_location("Core", CORE_PATH)
Core = importlib.util.module_from_spec(spec)

sys.path.insert(0, CORE_BASE_PATH)

# Setup logger for network simulation
logger = logging.getLogger('CorePatched')


def setupLogger(logLevel='INFO'):
    """Setup logger with specified level"""
    # Convert string level to logging constant
    numericLevel = getattr(logging, logLevel.upper(), logging.INFO)

    # Clear any existing handlers
    logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler()
    handler.setLevel(numericLevel)

    # Create formatter
    formatter = logging.Formatter('[%(name)s] %(message)s')
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)
    logger.setLevel(numericLevel)

    return logger


class FastFileLinkApiSimulator:
    """Simulates network instability for FastFileLink API operations using requests-mock"""

    def __init__(self, failureRate=0.0, maxConsecutiveFailures=1):
        """
        Initialize FastFileLink API instability simulator

        Args:
            failureRate (float): Probability of failure (0.0 to 1.0)
            maxConsecutiveFailures (int): Maximum consecutive failures allowed
        """
        self.failureRate = failureRate
        self.maxConsecutiveFailures = maxConsecutiveFailures
        self.consecutiveFailures = 0
        self.requestCount = 0
        self.totalFailures = 0
        self.mocker = None

        # FastFileLink API URL patterns (based on Upload.py)
        self.apiPatterns = [
            r'.*/upload/valid.*', # Server validation endpoint  
            r'.*/upload/end.*', # Upload end endpoint
            r'.*/upload/commit.*', # Upload commit endpoint
            r'.*/upload(?:/.*)?$', # Main upload endpoints (including dynamic ones)
        ]

        # Critical endpoints that should only fail with network exceptions
        self.criticalEndpoints = [
            r'.*/upload/end.*', # Upload end endpoint
            r'.*/upload/commit.*', # Upload commit endpoint
        ]

        # Excluded endpoints that should never fail (essential for test initialization)
        self.excludedEndpoints = [
            r'.*/upload\?.*', # Upload initialization endpoint (upload?uid=...)
            r'.*/api/upload\?.*', # API upload initialization endpoint
        ]

        if failureRate > 0:
            logger.info(f"FastFileLink API instability simulator initialized")
            logger.info(f"Failure rate: {failureRate * 100:.1f}%, Max consecutive failures: {maxConsecutiveFailures}")
            logger.debug(f"Monitoring API patterns: {self.apiPatterns}")
            logger.debug(f"Critical endpoints (network errors only): {self.criticalEndpoints}")
            logger.debug(f"Excluded endpoints (never fail): {self.excludedEndpoints}")

    def shouldSimulateFailure(self):
        """Determine if current request should fail"""
        if self.failureRate == 0:
            return False

        return (random.random() < self.failureRate and self.consecutiveFailures < self.maxConsecutiveFailures)

    def isExcludedEndpoint(self, url):
        """Check if the URL is an excluded endpoint that should never fail"""
        for pattern in self.excludedEndpoints:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def isCriticalEndpoint(self, url):
        """Check if the URL is a critical endpoint that should only have network failures"""
        for pattern in self.criticalEndpoints:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def isUploadRelatedRequest(self, request, method):
        """Check if the request is upload-related and should be simulated"""
        # Only simulate failures for upload-related methods
        if method.upper() not in ['POST', 'PUT', 'PATCH', 'GET']:
            return False

        # Check if URL is excluded from simulation
        url = request.url
        if self.isExcludedEndpoint(url):
            return False

        # Check if URL matches any of our FastFileLink API patterns
        for pattern in self.apiPatterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    def getFailureTypeForUrl(self, url):
        """Get appropriate failure type based on the URL"""
        # For critical endpoints (commit/end), only use network exceptions
        if self.isCriticalEndpoint(url):
            networkFailureTypes = [
                (requests.exceptions.Timeout, "Simulated network timeout for critical API"),
                (requests.exceptions.ConnectionError, "Simulated connection error for critical API"),
            ]
            return random.choice(networkFailureTypes)

        # For other upload endpoints, can include HTTP errors
        elif 'upload' in url.lower():
            # Upload endpoints - network issues and HTTP errors
            failureTypes = [(requests.exceptions.Timeout, "Simulated upload timeout"),
                            (requests.exceptions.ConnectionError, "Simulated connection error during upload"),
                            (requests.exceptions.HTTPError, "Simulated HTTP error during upload")]
            return random.choice(failureTypes)

        # For other endpoints
        elif 'points' in url.lower():
            # Points/cost checking - server errors
            failureTypes = [(requests.exceptions.HTTPError, "Simulated points API error"),
                            (requests.exceptions.ConnectionError, "Simulated connection error to points API")]
            return random.choice(failureTypes)

        else:
            # General API failures
            failureTypes = [(requests.exceptions.Timeout, "Simulated API timeout"),
                            (requests.exceptions.ConnectionError, "Simulated API connection error"),
                            (requests.exceptions.HTTPError, "Simulated API HTTP error")]
            return random.choice(failureTypes)

    def setupMocker(self):
        """Set up requests-mock mocker with FastFileLink API failure simulation"""
        if self.failureRate == 0:
            return None

        # Create mocker with real_http=True so non-mocked requests pass through
        self.mocker = requests_mock.Mocker(real_http=True)

        # Register a single matcher using ANY method and ANY URL with additional_matcher
        self.mocker.register_uri(
            requests_mock.ANY,
            requests_mock.ANY,
            additional_matcher=self.createAdditionalMatcher(),
            text=self.createFailureResponse # This will be called when matcher returns True
        )

        logger.debug(f"requests-mock setup completed for FastFileLink API simulation")
        return self.mocker

    def createAdditionalMatcher(self):
        """Create additional matcher that decides whether to simulate failure"""

        def additionalMatcher(request):
            self.requestCount += 1

            # Check if this is an excluded endpoint
            if self.isExcludedEndpoint(request.url):
                logger.debug(
                    f"{request.method} request {self.requestCount} to {request.url} - EXCLUDED from failure simulation"
                )
                return False

            # Check if this is an upload-related request that should be simulated
            isUploadRequest = self.isUploadRelatedRequest(request, request.method)

            if isUploadRequest and self.shouldSimulateFailure():
                self.consecutiveFailures += 1
                self.totalFailures += 1

                # Special logging for critical endpoints
                if self.isCriticalEndpoint(request.url):
                    logger.info(
                        f"Simulating NETWORK FAILURE on CRITICAL {request.method} API request {self.requestCount} "
                        f"to {request.url} (consecutive: {self.consecutiveFailures}, total failures: {self.totalFailures})"
                    )
                else:
                    logger.info(
                        f"Simulating {request.method} API failure on request {self.requestCount} "
                        f"to {request.url} (consecutive: {self.consecutiveFailures}, total failures: {self.totalFailures})"
                    )

                # Return True to match this request and trigger the failure response
                return True
            else:
                if isUploadRequest:
                    self.consecutiveFailures = 0
                    logger.debug(
                        f"{request.method} API request {self.requestCount} to {request.url} - no failure simulation"
                    )

                # Return False to not match this request, allowing real_http to handle it
                return False

        return additionalMatcher

    def createFailureResponse(self, request, context):
        """Create failure response by raising appropriate exception"""
        # Choose failure type based on the endpoint
        failureType = self.getFailureTypeForUrl(request.url)
        exception, message = failureType

        logger.debug(f"Raising {exception.__name__}: {message}")

        # Create a more realistic exception with proper attributes
        if exception == requests.exceptions.HTTPError:
            # Create a mock response object for HTTPError
            mockResponse = requests.Response()
            mockResponse.status_code = random.choice([500, 502, 503, 504])
            mockResponse.reason = "Simulated Server Error"
            mockResponse._content = message.encode('utf-8')

            # Create HTTPError with the mock response
            httpError = requests.exceptions.HTTPError(message)
            httpError.response = mockResponse
            raise httpError
        else:
            # For other exceptions, raise directly
            raise exception(message)

    def startMocking(self):
        """Start the mocking context"""
        if self.mocker:
            self.mocker.start()
            logger.debug(f"FastFileLink API instability mocking started")

    def stopMocking(self):
        """Stop the mocking context"""
        if self.mocker:
            self.mocker.stop()
            logger.debug(f"FastFileLink API instability mocking stopped")
            if self.totalFailures > 0:
                logger.info(
                    f"Final stats - Total API requests: {self.requestCount}, Total failures: {self.totalFailures}"
                )


def parseInstabilityArgs():
    """Parse network instability arguments from command line"""
    parser = argparse.ArgumentParser(add_help=False) # Don't interfere with Core.py's help
    parser.add_argument(
        '--network-failure-rate',
        type=float,
        default=0.0,
        help='Network failure rate for FastFileLink API (0.0 to 1.0, default: 0.0 for no instability)'
    )
    parser.add_argument(
        '--max-consecutive-failures', type=int, default=1, help='Maximum consecutive API failures (default: 1)'
    )
    parser.add_argument(
        '--sim-log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Log level for network simulation output (default: INFO)'
    )

    # Parse only known args, leave the rest for Core.py
    knownArgs, remainingArgs = parser.parse_known_args()

    # Update sys.argv to remove our custom arguments
    sys.argv = [sys.argv[0]] + remainingArgs

    return knownArgs.network_failure_rate, knownArgs.max_consecutive_failures, knownArgs.sim_log_level


def writeDebugLog(message):
    """Write debug message to both stdout and a debug file"""

    if os.getenv("FFL_CORE_PATCHED_DEBUG") != "True":
        return

    try:
        print(message)
        sys.stdout.flush()
    except Exception as e:
        logger.debug(f"Unable to print and flush: {e}")

    try:
        # Also write to debug file to bypass buffering issues
        debug_file = os.path.join(tempfile.gettempdir(), "corepatched_debug.log")
        with open(debug_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
            f.flush()
    except Exception as e:
        print(f"[DEBUG_ERROR] Failed to write debug log: {e}")


def main():
    """Main entry point that optionally applies FastFileLink API instability simulation"""
    writeDebugLog(f"[CorePatched] Starting with args: {sys.argv}")
    writeDebugLog(f"[CorePatched] Python version: {sys.version}")
    writeDebugLog(f"[CorePatched] Working directory: {os.getcwd()}")
    writeDebugLog(f"[CorePatched] CORE_PATH: {CORE_PATH}")
    writeDebugLog(f"[CorePatched] Core module exists: {os.path.exists(CORE_PATH)}")

    try:
        failureRate, maxConsecutiveFailures, simLogLevel = parseInstabilityArgs()
        writeDebugLog(
            f"[CorePatched] Parsed args - failure_rate: {failureRate}, max_failures: {maxConsecutiveFailures}, sim_log_level: {simLogLevel}"
        )

        # Setup logger with specified level
        setupLogger(simLogLevel)
        writeDebugLog(f"[CorePatched] Logger setup complete")

        simulator = FastFileLinkApiSimulator(failureRate, maxConsecutiveFailures)
        mocker = simulator.setupMocker()
        writeDebugLog(f"[CorePatched] Simulator setup complete, mocker active: {mocker is not None}")
    except Exception as e:
        writeDebugLog(f"[CorePatched] Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        raise

    try:
        # Start mocking if needed
        if mocker:
            simulator.startMocking()
            writeDebugLog(f"[CorePatched] Network mocking started")

        # Load and execute the original Core module
        try:
            writeDebugLog(f"[CorePatched] Loading Core module from: {CORE_PATH}")
            spec.loader.exec_module(Core)
            writeDebugLog(f"[CorePatched] Core module loaded successfully")
        except Exception as moduleError:
            writeDebugLog(f"[CorePatched] Failed to load Core module: {moduleError}")
            import traceback
            traceback.print_exc()
            raise

        # Run the main function if it exists
        if hasattr(Core, 'main'):
            writeDebugLog(f"[CorePatched] Calling Core.main()")
            writeDebugLog(f"[CorePatched] sys.argv before Core.main(): {sys.argv}")

            Core.main()
            writeDebugLog(f"[CorePatched] Core.main() completed")
        else:
            writeDebugLog(f"[CorePatched] Error: Core module does not have a 'main' function")
            raise AttributeError("Core module missing 'main' function")

    except Exception as e:
        if simulator.failureRate > 0:
            logger.error(f"Error during execution with API instability: {e}")
        else:
            writeDebugLog(f"[CorePatched] Error during execution: {e}")
            import traceback
            traceback.print_exc()
        raise
    finally:
        # Stop mocking
        simulator.stopMocking()
        writeDebugLog(f"[CorePatched] Cleanup completed")


if __name__ == '__main__':
    main()
