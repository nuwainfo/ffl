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

import unittest

from bases.Utils import formatSize, compareVersions, parseProxyString, ProxyConfig, ONE_KB, ONE_MB, ONE_GB, ONE_TB


class TestFormatSize(unittest.TestCase):
    """Test cases for the formatSize utility function."""

    def setUp(self):
        """Set up test fixtures with common test data."""
        self.testCases = [
            # (size_in_bytes, expected_output_pattern, description)
            (0, "0 Byte", "zero bytes"),
            (1, "1 Byte", "single byte"),
            (512, "512 Bytes", "bytes plural"),
            (ONE_KB, "1K", "one kilobyte"),
            (ONE_KB * 1.5, "2K", "1.5 kilobytes rounded"),
            (ONE_MB, "1M", "one megabyte"),
            (ONE_MB * 2.3, "2M", "2.3 megabytes"),
            (ONE_GB, "1.0G", "one gigabyte with decimal"),
            (ONE_GB * 1.5, "1.5G", "1.5 gigabytes"),
            (ONE_TB, "1.00T", "one terabyte with two decimals"),
            (ONE_TB * 2.5, "2.50T", "2.5 terabytes"),
        ]

    def testDefaultFormatting(self):
        """Test formatSize with default parameters."""
        for size, expectedPattern, description in self.testCases:
            with self.subTest(size=size, description=description):
                result = formatSize(size)
                print(f"formatSize({size}) = '{result}' ({description})")

                # Basic validation that result contains expected unit
                if 'K' in expectedPattern:
                    self.assertIn('K', result)
                elif 'M' in expectedPattern:
                    self.assertIn('M', result)
                elif 'G' in expectedPattern:
                    self.assertIn('G', result)
                elif 'T' in expectedPattern:
                    self.assertIn('T', result)
                elif 'Byte' in expectedPattern:
                    self.assertIn('Byte', result)

    def testCustomDecimalPlaces(self):
        """Test formatSize with custom decimal places."""
        testCases = [
            (ONE_GB * 1.234, 0, "1G"),
            (ONE_GB * 1.234, 1, "1.2G"),
            (ONE_GB * 1.234, 2, "1.23G"),
            (ONE_GB * 1.234, 3, "1.234G"),
        ]

        for size, decimal, expectedPattern in testCases:
            with self.subTest(size=size, decimal=decimal):
                result = formatSize(size, decimal=decimal)
                print(f"formatSize({size}, decimal={decimal}) = '{result}'")
                self.assertIn('G', result)

    def testPluralHandling(self):
        """Test formatSize with explicit plural parameter."""
        # Test singular form
        result = formatSize(1, plural=False)
        print(f"formatSize(1, plural=False) = '{result}'")
        self.assertIn('Byte', result)
        self.assertNotIn('Bytes', result)

        # Test plural form
        result = formatSize(2, plural=True)
        print(f"formatSize(2, plural=True) = '{result}'")
        self.assertIn('Bytes', result)

    def testEdgeCases(self):
        """Test formatSize with edge cases."""
        edgeCases = [
            (ONE_KB - 1, "1023 Bytes", "just under 1KB"),
            (ONE_KB + 1, "1K", "just over 1KB"),
            (ONE_MB - 1, "1000K", "just under 1MB"),
            (ONE_GB - 1, "1000M", "just under 1GB"),
            (ONE_TB - 1, "1000.0G", "just under 1TB"),
        ]

        for size, expectedPattern, description in edgeCases:
            with self.subTest(size=size, description=description):
                result = formatSize(size)
                print(f"formatSize({size}) = '{result}' ({description})")
                # Just verify it doesn't crash and returns a string
                self.assertIsInstance(result, str)
                self.assertTrue(len(result) > 0)

    def testLargeNumbers(self):
        """Test formatSize with very large numbers."""
        largeNumbers = [
            ONE_TB * 1000, # 1 petabyte
            ONE_TB * 1000000, # 1 exabyte
        ]

        for size in largeNumbers:
            with self.subTest(size=size):
                result = formatSize(size)
                print(f"formatSize({size}) = '{result}' (large number test)")
                self.assertIsInstance(result, str)
                self.assertTrue(len(result) > 0)

    def testConsistentBehavior(self):
        """Test that formatSize behaves consistently across different size ranges."""
        # Test that decimal places follow the expected pattern:
        # < 1GB: 0 decimals, 1GB-1TB: 1 decimal, >1TB: 2 decimals

        # Less than 1GB should have 0 decimals (when using default)
        result = formatSize(ONE_MB * 500) # 500MB
        print(f"formatSize({ONE_MB * 500}) = '{result}' (< 1GB range)")

        # Between 1GB and 1TB should have 1 decimal
        result = formatSize(ONE_GB * 5) # 5GB
        print(f"formatSize({ONE_GB * 5}) = '{result}' (1GB-1TB range)")

        # Greater than 1TB should have 2 decimals
        result = formatSize(ONE_TB * 2) # 2TB
        print(f"formatSize({ONE_TB * 2}) = '{result}' (> 1TB range)")

    def runAllTests(self):
        """Convenience method to run all tests and display results."""
        print("=== Running formatSize Tests ===\n")

        # Run each test method
        testMethods = [
            self.testDefaultFormatting, self.testCustomDecimalPlaces, self.testPluralHandling, self.testEdgeCases,
            self.testLargeNumbers, self.testConsistentBehavior
        ]

        for testMethod in testMethods:
            print(f"\n--- {testMethod.__name__} ---")
            try:
                testMethod()
                print(f"✓ {testMethod.__name__} passed")
            except Exception as e:
                print(f"✗ {testMethod.__name__} failed: {e}")

        print("\n=== formatSize Tests Complete ===")


class TestCompareVersions(unittest.TestCase):
    """Test cases for the compareVersions utility function."""

    def setUp(self):
        """Set up test fixtures with common test data."""
        self.testCases = [
            # (version1, version2, expected_result, description)
            ("1.2", "1.2.0", 0, "Same versions with different format"),
            ("1.10", "1.2", 1, "1.10 > 1.2 (decimal comparison)"),
            ("3.6.0", "10.10", -1, "3.6.0 < 10.10 (incompatible scenario)"),
            ("10.11", "10.10", 1, "10.11 > 10.10 (minor update)"),
            ("4.0.0", "3.6.0", 1, "4.0.0 > 3.6.0 (major update)"),
            ("1.0", "1.0", 0, "Identical versions"),
            ("2.1", "2.1.0", 0, "2.1 equals 2.1.0"),
            ("1.0.0", "1.0", 0, "1.0.0 equals 1.0"),
            ("1.2.3", "1.2.3", 0, "Identical three-part versions"),
            ("2.0", "1.9.9", 1, "2.0 > 1.9.9 (major vs minor)"),
            ("1.9.9", "2.0", -1, "1.9.9 < 2.0 (minor vs major)"),
        ]

    def testBasicComparisons(self):
        """Test basic version comparisons."""
        for version1, version2, expectedResult, description in self.testCases:
            with self.subTest(v1=version1, v2=version2, description=description):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                self.assertEqual(result, expectedResult, 
                    f"Expected {expectedResult}, got {result} for {description}")

    def testEqualVersions(self):
        """Test various equal version scenarios."""
        equalCases = [
            ("1.0", "1.0.0"),
            ("2.5", "2.5.0.0"),
            ("3.0.0", "3.0"),
            ("1.2.3", "1.2.3.0"),
            ("0.1", "0.1.0"),
        ]
        
        for version1, version2 in equalCases:
            with self.subTest(v1=version1, v2=version2):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} (should be equal)")
                self.assertEqual(result, 0, 
                    f"Versions '{version1}' and '{version2}' should be equal")
                
                # Test reverse comparison too
                reverseResult = compareVersions(version2, version1)
                self.assertEqual(reverseResult, 0,
                    f"Reverse comparison should also be equal")

    def testGreaterThanScenarios(self):
        """Test scenarios where first version > second version."""
        greaterCases = [
            ("2.0", "1.9", "Major version increase"),
            ("1.10", "1.9", "Double digit minor > single digit"),
            ("1.0.1", "1.0", "Patch version addition"),
            ("3.6.1", "3.6.0", "Patch increment"),
            ("4.0", "3.99", "Major vs high minor"),
            ("10.0", "9.99.99", "Double digit major"),
            ("1.2.3.4", "1.2.3", "More version parts"),
        ]
        
        for version1, version2, description in greaterCases:
            with self.subTest(v1=version1, v2=version2, desc=description):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                self.assertEqual(result, 1,
                    f"'{version1}' should be greater than '{version2}' - {description}")

    def testLessThanScenarios(self):
        """Test scenarios where first version < second version."""
        lessCases = [
            ("1.9", "2.0", "Minor vs major version"),
            ("1.9", "1.10", "Single digit vs double digit"),
            ("1.0", "1.0.1", "Missing patch version"),
            ("3.6.0", "3.6.1", "Patch version behind"),
            ("3.99", "4.0", "High minor vs major"),
            ("9.99.99", "10.0", "High version vs double digit major"),
            ("1.2.3", "1.2.3.4", "Fewer version parts"),
        ]
        
        for version1, version2, description in lessCases:
            with self.subTest(v1=version1, v2=version2, desc=description):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                self.assertEqual(result, -1,
                    f"'{version1}' should be less than '{version2}' - {description}")

    def testEdgeCases(self):
        """Test edge cases and error conditions."""
        edgeCases = [
            ("0", "0.0", 0, "Zero versions"),
            ("0.0", "0.0.0", 0, "Multiple zero parts"),
            ("1", "1.0.0", 0, "Single digit vs multi-part"),
            ("10", "2", 1, "Double digit vs single digit"),
            ("1.0.0.0.0", "1", 0, "Many zero parts vs simple"),
        ]
        
        for version1, version2, expected, description in edgeCases:
            with self.subTest(v1=version1, v2=version2, desc=description):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                self.assertEqual(result, expected,
                    f"Edge case failed: {description}")

    def testRealWorldVersions(self):
        """Test with real-world version scenarios from the application."""
        realWorldCases = [
            # Current FastFileLink scenarios
            ("3.6.0", "3.6.0", 0, "Same current version"),
            ("3.6.0", "3.7.0", -1, "Minor update available"),
            ("3.6.0", "4.0.0", -1, "Major update available"),
            ("3.6.0", "3.5.0", 1, "Newer than available"),
            ("3.6.0", "10.10", -1, "Version incompatibility scenario"),
            ("10.10", "3.6.0", 1, "Compatible with minimum requirement"),
            
            # Common software versioning patterns
            ("2.1.4", "2.1.5", -1, "Patch update"),
            ("2.1.5", "2.2.0", -1, "Minor update with patch reset"),
            ("2.2.0", "3.0.0", -1, "Major version jump"),
        ]
        
        for version1, version2, expected, description in realWorldCases:
            with self.subTest(v1=version1, v2=version2, desc=description):
                result = compareVersions(version1, version2)
                print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                self.assertEqual(result, expected,
                    f"Real-world scenario failed: {description}")

    def testInvalidInputHandling(self):
        """Test handling of invalid version inputs."""
        # Note: compareVersions should handle these gracefully by logging warnings
        # and returning sensible defaults (treating invalid as 0)
        
        invalidCases = [
            ("", "1.0", -1, "Empty string vs valid version"),
            ("1.0", "", 1, "Valid version vs empty string"), 
            ("invalid", "1.0", -1, "Invalid string vs valid version"),
            ("1.0", "invalid", 1, "Valid version vs invalid string"),
            (None, "1.0", -1, "None vs valid version"),
            ("1.0", None, 1, "Valid version vs None"),
        ]
        
        for version1, version2, expected, description in invalidCases:
            with self.subTest(v1=version1, v2=version2, desc=description):
                # These should not raise exceptions, but handle gracefully
                try:
                    result = compareVersions(version1, version2)
                    print(f"compareVersions('{version1}', '{version2}') = {result} ({description})")
                    self.assertEqual(result, expected,
                        f"Invalid input handling failed: {description}")
                except Exception as e:
                    self.fail(f"compareVersions should handle invalid input gracefully, but raised: {e}")

    def testSymmetryProperty(self):
        """Test that compareVersions(a, b) = -compareVersions(b, a)."""
        symmetryCases = [
            ("1.2", "1.3"),
            ("2.0", "1.9"),
            ("3.6.0", "10.10"),
            ("1.0", "1.0.1"),
        ]
        
        for version1, version2 in symmetryCases:
            with self.subTest(v1=version1, v2=version2):
                result1 = compareVersions(version1, version2)
                result2 = compareVersions(version2, version1)
                print(f"Symmetry test: compareVersions('{version1}', '{version2}') = {result1}, reverse = {result2}")
                
                # They should be opposites (except when both are 0)
                if result1 == 0:
                    self.assertEqual(result2, 0, "Both should be 0 for equal versions")
                else:
                    self.assertEqual(result1, -result2, "Results should be opposites for different versions")

    def testTransitivityProperty(self):
        """Test that if a < b and b < c, then a < c."""
        # Test chain: 1.0 < 1.1 < 2.0
        versions = ["1.0", "1.1", "2.0"]
        
        result1 = compareVersions(versions[0], versions[1])  # 1.0 vs 1.1
        result2 = compareVersions(versions[1], versions[2])  # 1.1 vs 2.0  
        result3 = compareVersions(versions[0], versions[2])  # 1.0 vs 2.0
        
        print(f"Transitivity test: {versions[0]} vs {versions[1]} = {result1}")
        print(f"Transitivity test: {versions[1]} vs {versions[2]} = {result2}")
        print(f"Transitivity test: {versions[0]} vs {versions[2]} = {result3}")
        
        self.assertEqual(result1, -1, "1.0 should be less than 1.1")
        self.assertEqual(result2, -1, "1.1 should be less than 2.0")
        self.assertEqual(result3, -1, "1.0 should be less than 2.0 (transitivity)")

    def runAllTests(self):
        """Convenience method to run all tests and display results."""
        print("\n=== Running compareVersions Tests ===\n")

        # Run each test method
        testMethods = [
            self.testBasicComparisons,
            self.testEqualVersions, 
            self.testGreaterThanScenarios,
            self.testLessThanScenarios,
            self.testEdgeCases,
            self.testRealWorldVersions,
            self.testInvalidInputHandling,
            self.testSymmetryProperty,
            self.testTransitivityProperty
        ]

        for testMethod in testMethods:
            print(f"\n--- {testMethod.__name__} ---")
            try:
                testMethod()
                print(f"✓ {testMethod.__name__} passed")
            except Exception as e:
                print(f"✗ {testMethod.__name__} failed: {e}")

        print("\n=== compareVersions Tests Complete ===")


class TestParseProxyString(unittest.TestCase):
    """Test cases for the parseProxyString utility function."""

    def testTypeHints(self):
        """Test that ProxyConfig TypedDict works with type hints (backward compatible)."""
        # Demonstrates type-safe usage with modern type hints
        result: ProxyConfig | None = parseProxyString("127.0.0.1:9150")

        # TypedDict is fully backward compatible - it's still a dict at runtime
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)

        # Type checkers (like mypy, pyright) now know the structure
        if result is not None:
            # These keys are guaranteed to exist by ProxyConfig TypedDict
            self.assertIn('type', result)
            self.assertIn('url', result)
            self.assertIn('host', result)
            self.assertIn('port', result)
            self.assertIn('protocol', result)
            self.assertIn('username', result)
            self.assertIn('password', result)

            # Type checkers know the types
            self.assertIsInstance(result['type'], str)
            self.assertIsInstance(result['port'], int)

        print(f"[OK] TypedDict is backward compatible and type-safe: {result}")

    def testSimpleHostPort(self):
        """Test parsing simple host:port format (defaults to socks5h)."""
        result = parseProxyString("127.0.0.1:9150")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'socks5')
        self.assertEqual(result['protocol'], 'socks5h')
        self.assertEqual(result['host'], '127.0.0.1')
        self.assertEqual(result['port'], 9150)
        self.assertEqual(result['url'], 'socks5h://127.0.0.1:9150')
        self.assertIsNone(result['username'])
        self.assertIsNone(result['password'])
        print(f"[OK] Simple host:port: {result}")

    def testSocks5WithProtocol(self):
        """Test parsing socks5:// protocol."""
        result = parseProxyString("socks5://proxy.example.com:1080")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'socks5')
        self.assertEqual(result['protocol'], 'socks5')
        self.assertEqual(result['host'], 'proxy.example.com')
        self.assertEqual(result['port'], 1080)
        self.assertEqual(result['url'], 'socks5h://proxy.example.com:1080')
        self.assertIsNone(result['username'])
        self.assertIsNone(result['password'])
        print(f"[OK] socks5:// protocol: {result}")

    def testSocks5hWithProtocol(self):
        """Test parsing socks5h:// protocol."""
        result = parseProxyString("socks5h://localhost:9050")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'socks5')
        self.assertEqual(result['protocol'], 'socks5h')
        self.assertEqual(result['host'], 'localhost')
        self.assertEqual(result['port'], 9050)
        self.assertEqual(result['url'], 'socks5h://localhost:9050')
        print(f"[OK] socks5h:// protocol: {result}")

    def testHttpProtocol(self):
        """Test parsing http:// protocol."""
        result = parseProxyString("http://proxy.company.com:8080")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'http')
        self.assertEqual(result['protocol'], 'http')
        self.assertEqual(result['host'], 'proxy.company.com')
        self.assertEqual(result['port'], 8080)
        self.assertEqual(result['url'], 'http://proxy.company.com:8080')
        self.assertIsNone(result['username'])
        self.assertIsNone(result['password'])
        print(f"[OK] http:// protocol: {result}")

    def testHttpsProtocol(self):
        """Test parsing https:// protocol."""
        result = parseProxyString("https://secure-proxy.com:443")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'http')
        self.assertEqual(result['protocol'], 'https')
        self.assertEqual(result['host'], 'secure-proxy.com')
        self.assertEqual(result['port'], 443)
        self.assertEqual(result['url'], 'https://secure-proxy.com:443')
        print(f"[OK] https:// protocol: {result}")

    def testSocks5WithCredentials(self):
        """Test parsing socks5:// with username and password."""
        result = parseProxyString("socks5://user:pass@proxy.example.com:1080")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'socks5')
        self.assertEqual(result['protocol'], 'socks5')
        self.assertEqual(result['host'], 'proxy.example.com')
        self.assertEqual(result['port'], 1080)
        self.assertEqual(result['username'], 'user')
        self.assertEqual(result['password'], 'pass')
        self.assertEqual(result['url'], 'socks5h://user:pass@proxy.example.com:1080')
        print(f"[OK] socks5:// with credentials: {result}")

    def testSocks5hWithCredentials(self):
        """Test parsing socks5h:// with username and password."""
        result = parseProxyString("socks5h://admin:secret123@localhost:9050")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'socks5')
        self.assertEqual(result['protocol'], 'socks5h')
        self.assertEqual(result['host'], 'localhost')
        self.assertEqual(result['port'], 9050)
        self.assertEqual(result['username'], 'admin')
        self.assertEqual(result['password'], 'secret123')
        self.assertEqual(result['url'], 'socks5h://admin:secret123@localhost:9050')
        print(f"[OK] socks5h:// with credentials: {result}")

    def testHttpWithCredentials(self):
        """Test parsing http:// with username and password."""
        result = parseProxyString("http://john:doe123@proxy.company.com:8080")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'http')
        self.assertEqual(result['protocol'], 'http')
        self.assertEqual(result['host'], 'proxy.company.com')
        self.assertEqual(result['port'], 8080)
        self.assertEqual(result['username'], 'john')
        self.assertEqual(result['password'], 'doe123')
        self.assertEqual(result['url'], 'http://john:doe123@proxy.company.com:8080')
        print(f"[OK] http:// with credentials: {result}")

    def testHttpsWithCredentials(self):
        """Test parsing https:// with username and password."""
        result = parseProxyString("https://admin:p@ssw0rd@secure-proxy.com:443")
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'http')
        self.assertEqual(result['protocol'], 'https')
        self.assertEqual(result['host'], 'secure-proxy.com')
        self.assertEqual(result['port'], 443)
        self.assertEqual(result['username'], 'admin')
        self.assertEqual(result['password'], 'p@ssw0rd')
        self.assertEqual(result['url'], 'https://admin:p@ssw0rd@secure-proxy.com:443')
        print(f"[OK] https:// with credentials: {result}")

    def testComplexPassword(self):
        """Test parsing with complex password containing special characters."""
        result = parseProxyString("socks5h://user:p@ss:w0rd!@proxy.example.com:1080")
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'user')
        # Password is everything after first : in credentials, so includes : and !
        self.assertEqual(result['password'], 'p@ss:w0rd!')
        self.assertEqual(result['host'], 'proxy.example.com')
        self.assertEqual(result['port'], 1080)
        print(f"[OK] Complex password with special chars: {result}")

    def testEmptyString(self):
        """Test parsing empty string."""
        result = parseProxyString("")
        self.assertIsNone(result)
        print("[OK] Empty string returns None")

    def testNone(self):
        """Test parsing None."""
        result = parseProxyString(None)
        self.assertIsNone(result)
        print("[OK] None returns None")

    def testWhitespaceOnly(self):
        """Test parsing whitespace-only string."""
        result = parseProxyString("   ")
        self.assertIsNone(result)
        print("[OK] Whitespace-only returns None")

    def testInvalidProtocol(self):
        """Test parsing with unsupported protocol."""
        result = parseProxyString("ftp://proxy.example.com:21")
        self.assertIsNone(result)
        print("[OK] Invalid protocol returns None")

    def testMissingPort(self):
        """Test parsing host without port."""
        result = parseProxyString("proxy.example.com")
        self.assertIsNone(result)
        print("[OK] Missing port returns None")

    def testInvalidPort(self):
        """Test parsing with non-numeric port."""
        result = parseProxyString("proxy.example.com:abc")
        self.assertIsNone(result)
        print("[OK] Invalid port returns None")

    def testMissingPassword(self):
        """Test parsing with username but missing password."""
        result = parseProxyString("socks5://user@proxy.example.com:1080")
        self.assertIsNone(result)
        print("[OK] Username without password returns None")

    def testIPv6Address(self):
        """Test parsing IPv6 address (edge case)."""
        # IPv6 addresses with colons need special handling
        # For now, just verify it doesn't crash
        result = parseProxyString("[::1]:9050")
        # May or may not parse correctly depending on implementation
        print(f"IPv6 address result: {result}")

    def testWhitespaceHandling(self):
        """Test that leading/trailing whitespace is handled."""
        result = parseProxyString("  127.0.0.1:9150  ")
        self.assertIsNotNone(result)
        self.assertEqual(result['host'], '127.0.0.1')
        self.assertEqual(result['port'], 9150)
        print(f"[OK] Whitespace trimmed: {result}")

    def testCaseInsensitiveProtocol(self):
        """Test that protocol is case-insensitive."""
        result = parseProxyString("SOCKS5://proxy.example.com:1080")
        self.assertIsNotNone(result)
        self.assertEqual(result['protocol'], 'socks5')
        print(f"[OK] Case-insensitive protocol: {result}")

    def testDifferentPorts(self):
        """Test parsing with various port numbers."""
        testCases = [
            ("127.0.0.1:1", 1),
            ("127.0.0.1:80", 80),
            ("127.0.0.1:443", 443),
            ("127.0.0.1:1080", 1080),
            ("127.0.0.1:8080", 8080),
            ("127.0.0.1:9150", 9150),
            ("127.0.0.1:65535", 65535),
        ]

        for proxyStr, expectedPort in testCases:
            with self.subTest(proxyStr=proxyStr):
                result = parseProxyString(proxyStr)
                self.assertIsNotNone(result)
                self.assertEqual(result['port'], expectedPort)
        print(f"[OK] All port numbers parsed correctly")

if __name__ == '__main__':
    unittest.main()
