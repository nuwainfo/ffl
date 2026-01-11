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
Tests for bases/Upgrade.py

Tests upgrade functionality with different variants and verifies
that the downloaded binaries match the requested variant.
"""

import os
import sys
import unittest
import tempfile
import subprocess
import shutil
import platform

from pathlib import Path

from bases.Upgrade import performUpgrade, detectGlibcVersion, detectDarwinArch, detectAPEVariant


class UpgradeTest(unittest.TestCase):
    """Test upgrade functionality with different variants"""

    def setUp(self):
        """Set up test environment"""
        self.tempDir = tempfile.mkdtemp()
        self.testBinary = Path(self.tempDir) / "ffl_test"

    def tearDown(self):
        """Clean up test files"""
        if Path(self.tempDir).exists():
            shutil.rmtree(self.tempDir)

    def _createEmptyBinary(self):
        """Create an empty file to serve as upgrade target"""
        self.testBinary.touch()
        self.testBinary.chmod(0o755)

    def _testUpgrade(self, variant, expectedCheck):
        """
        Test upgrade with a specific variant

        Args:
            variant: FFL_UPGRADE_VARIANT value (e.g., "ffl.com", "linux-2.39")
            expectedCheck: Function to verify the downloaded binary
                          Should return (bool, str) - (success, error_message)

        Note: Runs upgrade from tests/fixtures to avoid APE binaries importing
        current codebase modules during download/installation.
        """
        # Create target binary in fixtures directory to avoid import conflicts
        fixturesDir = Path(__file__).parent.parent / 'fixtures'
        fixturesDir.mkdir(exist_ok=True)

        # Determine appropriate filename extension for the variant
        if variant in ('ffl.com', 'fflo.com'):
            # APE variants need .com extension
            testBinaryName = self.testBinary.name if self.testBinary.name.endswith(
                '.com'
            ) else f"{self.testBinary.name}.com"
        elif variant == 'windows':
            # Windows native needs .exe extension
            testBinaryName = self.testBinary.name if self.testBinary.name.endswith(
                '.exe'
            ) else f"{self.testBinary.name}.exe"
        else:
            # Linux/macOS native: no extension
            testBinaryName = self.testBinary.name

        testBinary = fixturesDir / testBinaryName
        testBinary.touch()

        # Set variant environment variable
        os.environ["FFL_UPGRADE_VARIANT"] = variant

        osType = platform.system().lower()

        try:
            # Change to fixtures directory before upgrade to avoid import conflicts
            originalCwd = os.getcwd()
            os.chdir(str(fixturesDir))

            try:
                # Perform upgrade (force=True to allow downgrade for testing)
                # In Jenkins, settingsGetter initialized without platform, so we pass osType to force using current os.
                success = performUpgrade(targetBinary=str(testBinary), force=True, osType=osType)
                self.assertTrue(success, f"Upgrade failed for variant: {variant}")
            finally:
                # Restore original working directory
                os.chdir(originalCwd)
                # Update self.testBinary to point to the actual location
                self.testBinary = testBinary

            # Verify the downloaded binary (should preserve exact filename)
            self.assertTrue(self.testBinary.exists(), f"Binary not found after upgrade: {self.testBinary}")

            # Check if binary is correct variant
            checkSuccess, errorMsg = expectedCheck(self.testBinary)
            self.assertTrue(checkSuccess, f"Variant check failed for {variant}: {errorMsg}")

        finally:
            # Clean up environment variable
            if "FFL_UPGRADE_VARIANT" in os.environ:
                del os.environ["FFL_UPGRADE_VARIANT"]

            # Clean up test files in fixtures
            if testBinary.exists():
                testBinary.unlink()

    def _checkAPEVariant(self, expectedVariant):
        """
        Create a check function for APE variants

        Runs the binary with --version to check loaded addons.
        Both ffl.com and fflo.com should have Tunnels addon loaded.
        Only ffl.com (full) should have API addon loaded.
        fflo.com (lite) should NOT have API addon loaded.
        """

        def check(binaryPath):
            try:
                # Run binary with --version (already in fixtures directory)
                # When shell=True, command must be a string, not a list
                result = subprocess.run(
                    f'"{binaryPath}" --version',
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(binaryPath.parent),
                    shell=True # THIS IS REQUIRED FOR APE.
                )
                output = result.stdout + result.stderr

                # Check if Tunnels addon is loaded (required for both variants)
                hasTunnelsAddon = 'Tunnels' in output and '[OK] Loaded' in output.split('Tunnels')[1].split('\n')[
                    0] if 'Tunnels' in output else False

                if not hasTunnelsAddon:
                    return False, f"Expected Tunnels addon to be loaded in both variants, but not found in: {output}"

                # Check if API addon is loaded successfully
                # Look for "API          [OK] Loaded" pattern in output
                hasAPIAddon = 'API' in output and '[OK] Loaded' in output.split('API')[1].split('\n')[
                    0] if 'API' in output else False

                if expectedVariant == "ffl.com":
                    # Full version should have API addon loaded
                    if hasAPIAddon:
                        return True, None
                    return False, f"Expected ffl.com (with API addon loaded), but API addon not loaded in: {output}"
                elif expectedVariant == "fflo.com":
                    # Lite version should NOT have API addon loaded
                    if not hasAPIAddon:
                        return True, None
                    return False, f"Expected fflo.com (without API addon), but API addon loaded in: {output}"
                return False, f"Unknown APE variant: {expectedVariant}"
            except Exception as e:
                return False, f"Failed to run binary --version: {e}"

        return check

    def _checkGlibcVersion(self, expectedVersion):
        """Create a check function for Linux glibc variants"""

        def check(binaryPath):
            try:
                detectedVersion = detectGlibcVersion(binaryPath)
                if detectedVersion == expectedVersion:
                    return True, None
                return False, f"Expected glibc {expectedVersion}, detected: {detectedVersion}"
            except Exception as e:
                return False, f"Failed to detect glibc version: {e}"

        return check

    def _checkDarwinArch(self, expectedArch):
        """Create a check function for macOS architecture variants"""

        def check(binaryPath):
            try:
                detectedArch = detectDarwinArch(binaryPath)
                if detectedArch == expectedArch:
                    return True, None
                return False, f"Expected arch {expectedArch}, detected: {detectedArch}"
            except Exception as e:
                return False, f"Failed to detect architecture: {e}"

        return check

    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    def testUpgradeWindowsNative(self):
        """Test upgrading to Windows native variant"""

        # For Windows, we can't easily verify the binary type without dependencies
        # Just verify it downloads successfully
        def check(binaryPath):
            # Check file size is reasonable (> 1MB for a real binary)
            size = binaryPath.stat().st_size
            if size > 1024 * 1024:
                return True, None
            return False, f"Binary too small: {size} bytes"

        self._testUpgrade("windows", check)

    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    def testUpgradeFflComOnWindows(self):
        """Test upgrading to ffl.com APE variant on Windows"""
        self._testUpgrade("ffl.com", self._checkAPEVariant("ffl.com"))

    @unittest.skipIf(sys.platform != 'win32', "Windows-only test")
    def testUpgradeFfloComOnWindows(self):
        """Test upgrading to fflo.com APE variant on Windows"""
        self._testUpgrade("fflo.com", self._checkAPEVariant("fflo.com"))

    @unittest.skipIf(sys.platform != 'linux', "Linux-only test")
    def testUpgradeLinuxGlibc239(self):
        """Test upgrading to Linux native variant with glibc 2.39"""
        self._testUpgrade("linux-2.39", self._checkGlibcVersion("2.39"))

    @unittest.skipIf(sys.platform != 'linux', "Linux-only test")
    def testUpgradeLinuxGlibc228(self):
        """Test upgrading to Linux native variant with glibc 2.28"""
        self._testUpgrade("linux-2.28", self._checkGlibcVersion("2.28"))

    @unittest.skipIf(sys.platform != 'linux', "Linux-only test")
    def testUpgradeFflComOnLinux(self):
        """Test upgrading to ffl.com APE variant on Linux"""
        self._testUpgrade("ffl.com", self._checkAPEVariant("ffl.com"))

    @unittest.skipIf(sys.platform != 'linux', "Linux-only test")
    def testUpgradeFfloComOnLinux(self):
        """Test upgrading to fflo.com APE variant on Linux"""
        self._testUpgrade("fflo.com", self._checkAPEVariant("fflo.com"))

    @unittest.skipIf(sys.platform != 'darwin', "macOS-only test")
    def testUpgradeDarwinX8664(self):
        """Test upgrading to macOS x86_64 variant"""

        # Note: This will download based on current system arch
        # We can only test if it downloads successfully
        def check(binaryPath):
            try:
                arch = detectDarwinArch(binaryPath)
                if arch in ("x86_64", "arm64"):
                    return True, None
                return False, f"Unexpected arch: {arch}"
            except Exception as e:
                return False, f"Failed to detect architecture: {e}"

        self._testUpgrade("darwin", check)

    @unittest.skipIf(sys.platform != 'darwin', "macOS-only test")
    def testUpgradeFflComOnDarwin(self):
        """Test upgrading to ffl.com APE variant on macOS"""
        self._testUpgrade("ffl.com", self._checkAPEVariant("ffl.com"))

    @unittest.skipIf(sys.platform != 'darwin', "macOS-only test")
    def testUpgradeFfloComOnDarwin(self):
        """Test upgrading to fflo.com APE variant on macOS"""
        self._testUpgrade("fflo.com", self._checkAPEVariant("fflo.com"))


if __name__ == '__main__':
    unittest.main()
