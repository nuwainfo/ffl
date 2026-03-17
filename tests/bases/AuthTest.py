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

import base64
import email as email_lib
import imaplib
import json
import os
import re
import subprocess
import sys
import time
import unittest

import requests
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from bases.crypto import CryptoInterface

from ..BrowserTestBase import BrowserTestBase
from ..CoreTestBase import FastFileLinkTestBase, IMAPTestMixin

_EMAIL_AUTH_VARS = ('FFL_TEST_EMAIL', 'FFL_TEST_IMAP_HOST', 'FFL_TEST_IMAP_PASSWORD')
SKIP_EMAIL_AUTH_TEST = not all(v in os.environ for v in _EMAIL_AUTH_VARS)
SKIP_EMAIL_RECIPIENT_TEST = 'FFL_TEST_EMAIL' not in os.environ


def _decryptRsaChallenge(encryptedChallengeB64, privKeyPath):
    """Decrypt an RSA-OAEP challenge and return the plaintext as base64."""
    challengeCiphertext = base64.b64decode(encryptedChallengeB64)
    with open(privKeyPath, 'r', encoding='utf-8') as f:
        privKeyPem = f.read()
    return base64.b64encode(CryptoInterface().decryptRSAOAEP(privKeyPem, challengeCiphertext)).decode()


def _resolveProofFromChecksumData(checksumData, privKeyPath):
    encryptedChallenges = checksumData.get('encrypted_challenges') or []

    seenChallenges = set()
    for challengeValue in encryptedChallenges:
        if not challengeValue or challengeValue in seenChallenges:
            continue

        seenChallenges.add(challengeValue)
        try:
            return _decryptRsaChallenge(challengeValue, privKeyPath)
        except Exception:
            pass

    raise AssertionError("encrypted_challenges not found or private key does not match any published challenge")


class AuthTest(FastFileLinkTestBase):
    """Functional tests for --recipient-auth pickup and --pickup-code."""

    def _startAndGetShareInfo(self, extraArgs):
        """Start the server and return (shareLink, shareInfo dict)."""
        self.outputCapture = {}
        shareLink = self._startFastFileLink(p2p=True, extraArgs=extraArgs, captureOutputIn=self.outputCapture)
        with open(self.jsonOutputPath, 'r') as f:
            shareInfo = json.load(f)
        return shareLink, shareInfo

    def _buildDownloadUrl(self, shareLink):
        """Build the direct download URL."""
        return shareLink.rstrip('/') + '/download'

    def _buildAuthUrl(self, shareLink):
        """Build the POST /auth URL from a share link."""
        return shareLink.rstrip('/') + '/auth'

    def _makeAuthHeaders(self, code=None, proof=None):
        """Build X-FFL-Pickup / X-FFL-Proof request headers."""
        headers = {}
        if code is not None:
            headers['X-FFL-Pickup'] = code
        if proof is not None:
            headers['X-FFL-Proof'] = proof
        return headers

    def _runCommandAndGetOutput(self, extraArgs):
        """Run CLI command, capture output, return text (same pattern as CLITest)."""
        outputCapture = {}
        try:
            self._startFastFileLink(p2p=True, extraArgs=extraArgs, captureOutputIn=outputCapture)
        except Exception as e:
            print(f"[Test] Process terminated early (expected for output-only tests): {e}")

        if self.coreProcess and self.coreProcess.poll() is None:
            try:
                startTime = time.time()
                while time.time() - startTime < 15:
                    if self.coreProcess.poll() is not None:
                        break
                    time.sleep(0.5)
            except Exception:
                pass
            if self.coreProcess.poll() is None:
                self.coreProcess.terminate()
                try:
                    self.coreProcess.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.coreProcess.kill()
                    self.coreProcess.wait()

        return self._updateCapturedOutput(outputCapture)

    def _resolveProofForDownload(self, shareLink, privKeyPath):
        """Fetch /checksum JSON, decrypt encrypted_challenges with privKeyPath, return base64 proof."""
        checksumUrl = shareLink.rstrip('/') + '/checksum'
        response = requests.get(checksumUrl, timeout=15)
        response.raise_for_status()
        data = response.json()
        return _resolveProofFromChecksumData(data, privKeyPath)

    def testPickupCodeCSPRNGGenerated(self):
        """No --pickup-code → JSON has a 6-digit numeric code in pickup_code."""
        extraArgs = ["--recipient-auth", "pickup", "--timeout", "10"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        pickupCode = shareInfo.get("pickup_code")
        self.assertIsNotNone(pickupCode, "JSON should contain 'pickup_code'")
        self.assertIsInstance(pickupCode, str, "pickup_code should be a string")
        self.assertEqual(len(pickupCode), 6, f"pickup_code should be 6 digits, got: {pickupCode!r}")
        self.assertTrue(pickupCode.isdigit(), f"pickup_code should be all digits, got: {pickupCode!r}")
        print(f"[Test] PASS: CSPRNG-generated pickup code is valid 6-digit string: {pickupCode}")

    def testPickupCodeImpliesRecipientAuth(self):
        """--pickup-code alone (no --recipient-auth) → implicitly enables pickup auth."""
        customCode = "246813"
        extraArgs = ["--pickup-code", customCode, "--timeout", "10"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        pickupCode = shareInfo.get("pickup_code")
        self.assertEqual(pickupCode, customCode, f"Expected pickup_code '{customCode}', got: {pickupCode!r}")
        print(f"[Test] PASS: --pickup-code alone implicitly enables pickup auth: {pickupCode}")

    def testRecipientPublicKeyImpliesRecipientAuth(self):
        """--recipient-public-key alone (no --recipient-auth) ??implicitly enables pubkey auth."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_pubkey_implied')
        extraArgs = ["--recipient-public-key", pubKeyPath, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        self.assertTrue(shareInfo.get("pubkey_enabled"), "JSON should have pubkey_enabled=True")
        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("pubkey_implied_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers=self._makeAuthHeaders(proof=proof))
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print("[Test] PASS: --recipient-public-key alone implicitly enables pubkey auth")

    def testRecipientPublicKeyAndPickupCodeImplyCombinedRecipientAuth(self):
        """--recipient-public-key + --pickup-code (no --recipient-auth) ??implicitly enables pubkey+pickup."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_pubkey_pickup_implied')
        pickupCode = "246810"
        extraArgs = ["--recipient-public-key", pubKeyPath, "--pickup-code", pickupCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        self.assertTrue(shareInfo.get("pubkey_enabled"), "JSON should have pubkey_enabled=True")
        self.assertEqual(shareInfo.get("pickup_code"), pickupCode, "JSON should contain pickup_code")
        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("pubkey_pickup_implied_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl,
            downloadedFilePath,
            headers=self._makeAuthHeaders(proof=proof, code=pickupCode),
        )
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print("[Test] PASS: --recipient-public-key with --pickup-code implicitly enables pubkey+pickup auth")

    def testWebRTCPickupCodeAllows(self):
        """WebRTC download with correct pickup code → file downloaded and integrity verified."""
        correctCode = "741852"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        outputPath = self._getDownloadedFilePath("webrtc_pickup_download.bin")
        print(f"[Test] Downloading via WebRTC with correct code: {correctCode}")
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraArgs=["--pickup-code", correctCode]
        )
        self._verifyDownloadedFile(downloadedPath)
        print(f"[Test] PASS: WebRTC download with correct pickup code succeeded")

    def testWebRTCPickupCodeBlocksWrongCode(self):
        """WebRTC download with wrong pickup code → download fails."""
        correctCode = "369258"
        wrongCode = "000000"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        outputPath = self._getDownloadedFilePath("webrtc_blocked_download.bin")
        print(f"[Test] Attempting WebRTC download with wrong code: {wrongCode}")
        with self.assertRaises(AssertionError):
            self._downloadWithCore(
                shareLink,
                outputPath=outputPath,
                extraArgs=["--pickup-code", wrongCode]
            )
        print(f"[Test] PASS: WebRTC download with wrong pickup code was rejected")

    def testWebRTCHTTPFallbackPickupCode(self):
        """WebRTC ICE failure → HTTP fallback with correct pickup code → file downloaded."""
        correctCode = "159753"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        outputPath = self._getDownloadedFilePath("webrtc_fallback_pickup_download.bin")
        print(f"[Test] Downloading via HTTP fallback (simulated ICE failure) with correct code: {correctCode}")
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraArgs=["--pickup-code", correctCode],
            extraEnvVars={"WEBRTC_CLI_SIMULATE_ICE_FAILURE": "True"}
        )
        self._verifyDownloadedFile(downloadedPath)
        print(f"[Test] PASS: HTTP fallback download with correct pickup code succeeded")

    # -----------------------------------------------------------------------
    # Pubkey auth tests
    # -----------------------------------------------------------------------

    def testPubkeyKeypairGenerated(self):
        """CLI keypair subcommand creates .fflkey (PKCS#8) and .fflpub (SPKI) files."""
        privKeyPath, pubKeyPath = self._generateKeypair('keypair_test')
        with open(privKeyPath, 'r', encoding='utf-8') as f:
            privContent = f.read()
        with open(pubKeyPath, 'r', encoding='utf-8') as f:
            pubContent = f.read()
        self.assertIn('-----BEGIN PRIVATE KEY-----', privContent,
                      "Private key file should use PKCS#8 PEM header (Web Crypto API compatible)")
        self.assertIn('-----BEGIN PUBLIC KEY-----', pubContent,
                      "Public key file should use SPKI PEM header")
        print(f"[Test] PASS: keypair generated with correct PKCS#8/SPKI PEM headers")

    def testPubkeyBlocksNoProof(self):
        """GET /download without X-FFL-Proof header → 401 Unauthorized."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_no_proof')
        extraArgs = ["--recipient-auth", "pubkey", "--recipient-public-key", pubKeyPath, "--timeout", "15"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        downloadUrl = self._buildDownloadUrl(shareLink)
        response = requests.get(downloadUrl, timeout=10)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 without proof header, got {response.status_code}")
        print(f"[Test] PASS: Missing proof correctly rejected with 401")

    def testPubkeyAllowsCorrectKey(self):
        """GET /download with X-FFL-Proof header (correct) → 200, file integrity verified."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_allow')
        extraArgs = ["--recipient-auth", "pubkey", "--recipient-public-key", pubKeyPath, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("pubkey_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers=self._makeAuthHeaders(proof=proof))
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: Correct pubkey proof allowed download with intact file")

    def testPubkeyAllowsAnyConfiguredRecipientKey(self):
        """GET /download with a proof derived from any configured public key ??200."""
        firstPrivKeyPath, firstPubKeyPath = self._generateKeypair('alice_multi_pubkey')
        secondPrivKeyPath, secondPubKeyPath = self._generateKeypair('bob_multi_pubkey')
        extraArgs = [
            "--recipient-auth", "pubkey",
            "--recipient-public-key", f"{firstPubKeyPath},{secondPubKeyPath}",
            "--timeout", "30"
        ]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        proof = self._resolveProofForDownload(shareLink, secondPrivKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("pubkey_multi_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers=self._makeAuthHeaders(proof=proof))
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: Second configured pubkey recipient downloaded successfully")

    def testWebRTCPubkeyAllowsCorrectKey(self):
        """CLI download with --recipient-private-key → WebRTC resolves proof, file downloaded."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_webrtc')
        extraArgs = ["--recipient-auth", "pubkey", "--recipient-public-key", pubKeyPath, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        outputPath = self._getDownloadedFilePath("webrtc_pubkey_download.bin")
        print(f"[Test] Downloading via WebRTC with --recipient-private-key {privKeyPath}")
        downloadedPath = self._downloadWithCore(
            shareLink,
            outputPath=outputPath,
            extraArgs=["--recipient-private-key", privKeyPath]
        )
        self._verifyDownloadedFile(downloadedPath)
        print(f"[Test] PASS: WebRTC download with correct private key succeeded")

    def testWebRTCPubkeyBlocksWrongKey(self):
        """CLI download with wrong --recipient-private-key → RSA failure, exit non-zero."""
        correctPrivKeyPath, correctPubKeyPath = self._generateKeypair('alice_webrtc_correct')
        wrongPrivKeyPath, wrongPubKeyPath = self._generateKeypair('bob_webrtc_wrong')
        extraArgs = ["--recipient-auth", "pubkey", "--recipient-public-key", correctPubKeyPath, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        outputPath = self._getDownloadedFilePath("webrtc_pubkey_blocked.bin")
        print(f"[Test] Attempting download with wrong private key (expecting failure)")
        with self.assertRaises(AssertionError):
            self._downloadWithCore(
                shareLink,
                outputPath=outputPath,
                extraArgs=["--recipient-private-key", wrongPrivKeyPath]
            )
        print(f"[Test] PASS: Download with wrong private key correctly rejected")

    def testPubkeyPlusPickupCombined(self):
        """pubkey+pickup: correct key AND correct code (via headers) → 200, file integrity verified."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_combined')
        correctCode = "123456"
        extraArgs = [
            "--recipient-auth", "pubkey+pickup",
            "--recipient-public-key", pubKeyPath,
            "--pickup-code", correctCode,
            "--timeout", "30"
        ]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        self.assertTrue(shareInfo.get("pubkey_enabled"), "JSON should have pubkey_enabled=True")
        self.assertEqual(shareInfo.get("pickup_code"), correctCode, "JSON should contain pickup_code")
        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("combined_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath,
            headers=self._makeAuthHeaders(code=correctCode, proof=proof))
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: pubkey+pickup correct combo allowed download")

    def testPubkeyPlusPickupWrongCode(self):
        """pubkey+pickup: correct key but wrong code (via header) → 401 Unauthorized."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_wrong_code')
        correctCode = "654321"
        wrongCode = "000000"
        extraArgs = [
            "--recipient-auth", "pubkey+pickup",
            "--recipient-public-key", pubKeyPath,
            "--pickup-code", correctCode,
            "--timeout", "15"
        ]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        downloadUrl = self._buildDownloadUrl(shareLink)
        response = requests.get(
            downloadUrl, headers=self._makeAuthHeaders(code=wrongCode, proof=proof), timeout=10)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 with correct proof but wrong pickup code, got {response.status_code}")
        print(f"[Test] PASS: Correct proof with wrong pickup code rejected with 401")

    def testPubkeyPlusPickupNoProofNoCode(self):
        """pubkey+pickup: request with no headers at all → 401."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_no_both')
        extraArgs = [
            "--recipient-auth", "pubkey+pickup",
            "--recipient-public-key", pubKeyPath,
            "--pickup-code", "777888",
            "--timeout", "15"
        ]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)
        downloadUrl = self._buildDownloadUrl(shareLink)
        response = requests.get(downloadUrl, timeout=10)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 with no credentials at all, got {response.status_code}")
        print(f"[Test] PASS: No proof and no code correctly rejected with 401")

    # -----------------------------------------------------------------------
    # POST /auth → cookie session tests
    # -----------------------------------------------------------------------

    def testCookieSessionBlocksWrongCode(self):
        """POST /auth with wrong X-FFL-Pickup → 401."""
        correctCode = "333444"
        wrongCode = "000000"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "15"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        authUrl = self._buildAuthUrl(shareLink)
        response = requests.post(authUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 from /auth with wrong code, got {response.status_code}")
        print(f"[Test] PASS: POST /auth with wrong code returns 401")

    def testCookieSessionAllowsDownload(self):
        """POST /auth → cookie → GET /download (cookie only, no header) → 200, file intact."""
        correctCode = "555666"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        session = requests.Session()
        authUrl = self._buildAuthUrl(shareLink)
        authResp = session.post(authUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(authResp.status_code, 204, f"Expected 204 from /auth, got {authResp.status_code}")

        # Download using only the cookie — no X-FFL-* headers
        downloadUrl = self._buildDownloadUrl(shareLink)
        print(f"[Test] GET {downloadUrl} with cookie only (no auth headers)")
        downloadedFilePath = self._getDownloadedFilePath("cookie_download.bin")
        with session.get(downloadUrl, stream=True, timeout=30) as response:
            self.assertEqual(response.status_code, 200,
                             f"Expected 200 with cookie session, got {response.status_code}")
            with open(downloadedFilePath, 'wb') as f:
                for chunk in response.iter_content(65536):
                    f.write(chunk)
        self._verifyDownloadedFile(downloadedFilePath)
        print(f"[Test] PASS: Cookie session allowed download with intact file")

    def testCookieSessionRangeResume(self):
        """Cookie session supports multiple Range requests (same session, not single-use)."""
        correctCode = "777888"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        session = requests.Session()
        authUrl = self._buildAuthUrl(shareLink)
        authResp = session.post(authUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(authResp.status_code, 204, f"Expected 204 from /auth, got {authResp.status_code}")

        downloadUrl = self._buildDownloadUrl(shareLink)
        # First Range request
        r1 = session.get(downloadUrl, headers={'Range': 'bytes=0-1023'}, timeout=10)
        self.assertIn(r1.status_code, (200, 206), f"First Range request got {r1.status_code}")
        # Second Range request — same session, cookie still valid
        r2 = session.get(downloadUrl, headers={'Range': 'bytes=0-1023'}, timeout=10)
        self.assertIn(r2.status_code, (200, 206), f"Second Range request got {r2.status_code}")
        print(f"[Test] PASS: Cookie session supports multiple Range requests")

    def testCookieSessionClaimed(self):
        """POST /auth stays valid for the same session, while a new client is still rejected."""
        correctCode = "999000"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "15"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        authUrl = self._buildAuthUrl(shareLink)
        session = requests.Session()

        r1 = session.post(authUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(r1.status_code, 204, f"First /auth should succeed, got {r1.status_code}")

        r2 = session.post(authUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(r2.status_code, 204,
                         f"Second /auth in same session should remain valid, got {r2.status_code}")

        r3 = requests.post(authUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(r3.status_code, 401,
                         f"Fresh client should still fail after claim, got {r3.status_code}")

        downloadUrl = self._buildDownloadUrl(shareLink)
        r4 = session.get(downloadUrl, timeout=10)
        self.assertEqual(r4.status_code, 200,
                         f"Expected 200 for download after repeated same-session auth, got {r4.status_code}")

        r5 = session.get(downloadUrl, timeout=10)
        self.assertEqual(r5.status_code, 200,
                         f"Expected 200 for repeat download in same session, got {r5.status_code}")
        print(f"[Test] PASS: Same-session POST /auth remains reusable, new client is still blocked")

    def testCookiePubkeySession(self):
        """POST /auth with X-FFL-Proof → cookie → GET /download (cookie only) → 200."""
        privKeyPath, pubKeyPath = self._generateKeypair('alice_cookie')
        extraArgs = ["--recipient-auth", "pubkey", "--recipient-public-key", pubKeyPath, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        proof = self._resolveProofForDownload(shareLink, privKeyPath)
        session = requests.Session()
        authUrl = self._buildAuthUrl(shareLink)
        authResp = session.post(authUrl, headers=self._makeAuthHeaders(proof=proof), timeout=10)
        self.assertEqual(authResp.status_code, 204, f"Expected 204 from /auth, got {authResp.status_code}")

        downloadUrl = self._buildDownloadUrl(shareLink)
        downloadedFilePath = self._getDownloadedFilePath("cookie_pubkey_download.bin")
        with session.get(downloadUrl, stream=True, timeout=30) as response:
            self.assertEqual(response.status_code, 200,
                             f"Expected 200 with pubkey cookie session, got {response.status_code}")
            with open(downloadedFilePath, 'wb') as f:
                for chunk in response.iter_content(65536):
                    f.write(chunk)
        self._verifyDownloadedFile(downloadedFilePath)
        print(f"[Test] PASS: Pubkey cookie session allowed download with intact file")

    def testAuthRateLimitLocks(self):
        """5 consecutive wrong pickup codes → 6th attempt returns 429 Too Many Requests."""
        correctCode = "424242"
        wrongCode = "000000"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        downloadUrl = self._buildDownloadUrl(shareLink)
        for i in range(5):
            response = requests.get(
                downloadUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)
            self.assertEqual(response.status_code, 401,
                             f"Attempt {i + 1}: expected 401, got {response.status_code}")

        print(f"[Test] 5 failed attempts recorded, expecting 429 on next request")
        response = requests.get(
            downloadUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)
        self.assertEqual(response.status_code, 429,
                         f"Expected 429 after 5 failures, got {response.status_code}")
        self.assertIn('Retry-After', response.headers, "Expected Retry-After header in 429 response")
        print(f"[Test] PASS: Rate limiter locked after 5 failures, returned 429")

    def testAuthRateLimitResetsOnSuccess(self):
        """Correct code after failures resets the counter — subsequent wrong codes start fresh."""
        correctCode = "848484"
        wrongCode = "000000"
        extraArgs = ["--recipient-auth", "pickup", "--pickup-code", correctCode, "--timeout", "30"]
        shareLink, shareInfo = self._startAndGetShareInfo(extraArgs)

        downloadUrl = self._buildDownloadUrl(shareLink)
        # 4 failures
        for i in range(4):
            requests.get(downloadUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)

        # Correct code resets counter
        response = requests.get(
            downloadUrl, headers=self._makeAuthHeaders(code=correctCode), timeout=10)
        self.assertEqual(response.status_code, 200,
                         f"Expected 200 with correct code, got {response.status_code}")
        print(f"[Test] Correct code accepted and counter reset")

        # 5 more failures to trigger lockout again
        for i in range(5):
            requests.get(downloadUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)

        response = requests.get(downloadUrl, headers=self._makeAuthHeaders(code=wrongCode), timeout=10)
        self.assertEqual(response.status_code, 429,
                         f"Expected 429 after 5 new failures, got {response.status_code}")
        print(f"[Test] PASS: Counter reset on success; 5 new failures trigger lockout again")


class KeypairShareTest(FastFileLinkTestBase):
    """Functional tests for `keypair --share`."""

    def testKeypairSharePickupDownloadsAndDeletes(self):
        """keypair --share --recipient-auth pickup: correct code downloads private key; file deleted after."""
        pickupCode = "357159"
        basePath = os.path.join(self.tempDir, 'kp_share')
        privKeyPath = f"{basePath}.fflkey"
        pubKeyPath = f"{basePath}.fflpub"

        projectRoot = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'

        self._procLogFile = open(self.procLogPath, 'w', encoding='utf-8', errors='replace')
        self.coreProcess = subprocess.Popen(
            [
                sys.executable, 'Core.py', '--cli', 'keygen',
                '--name', basePath, '--share',
                '--recipient-auth', 'pickup', '--pickup-code', pickupCode,
                '--json', self.jsonOutputPath,
            ],
            cwd=projectRoot,
            stdout=self._procLogFile,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )

        # Wait for JSON (server is up and link is ready)
        startTime = time.time()
        while time.time() - startTime < 60:
            if os.path.exists(self.jsonOutputPath):
                break
            if self.coreProcess.poll() is not None:
                self._procLogFile.flush()
                with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as f:
                    output = f.read()
                raise AssertionError(
                    f"keypair --share exited early (code {self.coreProcess.returncode}):\n{output}"
                )
            time.sleep(0.5)

        with open(self.jsonOutputPath, 'r') as f:
            shareInfo = json.load(f)

        shareLink = shareInfo['link']
        downloadUrl = shareLink.rstrip('/') + '/download'

        self.assertTrue(os.path.exists(privKeyPath), "Private key must exist before download")
        self.assertEqual(shareInfo.get('pickup_code'), pickupCode, "JSON must expose pickup_code")

        # Download with correct pickup code
        downloadedPath = self._getDownloadedFilePath('privkey.fflkey')
        with requests.get(
            downloadUrl, headers={'X-FFL-Pickup': pickupCode}, stream=True, timeout=30
        ) as response:
            self.assertEqual(response.status_code, 200,
                             f"Expected 200 with correct pickup code, got {response.status_code}")
            with open(downloadedPath, 'wb') as f:
                for chunk in response.iter_content(65536):
                    f.write(chunk)

        # Verify downloaded content is a PKCS#8 private key
        with open(downloadedPath, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('-----BEGIN PRIVATE KEY-----', content,
                      "Downloaded file should be a PKCS#8 private key")

        # Wait for server to exit (maxDownloads=1 reached) and verify cleanup
        startTime = time.time()
        while time.time() - startTime < 30:
            if self.coreProcess.poll() is not None:
                break
            time.sleep(0.5)
        self.assertIsNotNone(self.coreProcess.poll(), "Server should have exited after 1 download")

        self.assertFalse(os.path.exists(privKeyPath),
                         f".fflkey should be deleted after download: {privKeyPath}")
        self.assertTrue(os.path.exists(pubKeyPath),
                        f".fflpub should remain on disk: {pubKeyPath}")
        print(f"[Test] PASS: private key downloaded with pickup code, then auto-deleted")


class _UploadAuthMixin:
    """Shared helpers for upload-mode auth tests (AuthUploadTest and AuthUploadBrowserTest)."""

    def _startUploadAndGetInfo(self, extraArgs):
        """Upload file and return (shareLink, shareInfo dict)."""
        shareLink = self._startFastFileLink(
            p2p=False,
            extraArgs=extraArgs,
        )
        with open(self.jsonOutputPath, 'r') as f:
            shareInfo = json.load(f)
        return shareLink, shareInfo

    def _buildDownloadUrl(self, shareLink):
        """Build download URL, stripping any query params from the share link."""
        return shareLink.split('?')[0].rstrip('/') + '/download'

    def _waitForAuthActive(self, downloadUrl, timeout=90):
        """Poll download URL until Caddy enforces auth (no credentials → 401).

        Uses GET (not HEAD) because Caddy's templates directive only evaluates
        template bodies for GET requests; HEAD requests bypass template evaluation
        and return 200 from file_server directly.
        """
        startTime = time.time()
        while time.time() - startTime < timeout:
            try:
                with requests.get(downloadUrl, timeout=3, allow_redirects=False, stream=True) as response:
                    if response.status_code == 401:
                        return
            except Exception:
                pass
            time.sleep(1)
        raise AssertionError(f"Auth did not become active at {downloadUrl} within {timeout}s")


class AuthUploadTest(_UploadAuthMixin, FastFileLinkTestBase):
    """Functional tests for --recipient-auth pickup with --upload."""

    def __init__(self, methodName='runTest'):
        # Small file for fast upload/download
        super().__init__(methodName, fileSizeBytes=512 * 1024)

    def _resolveProofForUpload(self, shareLink, privKeyPath):
        """Poll /checksum until encrypted_challenges is available, decrypt, return base64 proof."""
        checksumUrl = shareLink.split('?')[0].rstrip('/') + '/checksum'
        startTime = time.time()
        while time.time() - startTime < 90:
            try:
                response = requests.get(checksumUrl, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('encrypted_challenges'):
                        return _resolveProofFromChecksumData(data, privKeyPath)
            except Exception:
                pass
            time.sleep(1)
        raise AssertionError(f"encrypted_challenges not available at {checksumUrl} within 90s")

    def _startUploadWithPubkeyAndWait(self, keypairName):
        """Generate keypair, upload with pubkey auth, wait for Caddy to enforce it.

        Returns (privKeyPath, shareLink, downloadUrl).
        """
        privKeyPath, pubKeyPath = self._generateKeypair(keypairName)
        shareLink, shareInfo = self._startUploadAndGetInfo([
            "--recipient-auth", "pubkey",
            "--recipient-public-key", pubKeyPath,
        ])
        downloadUrl = self._buildDownloadUrl(shareLink)
        self._waitForAuthActive(downloadUrl)
        return privKeyPath, shareLink, downloadUrl

    def testUploadPickupCodeCSPRNGGenerated(self):
        """--upload with --recipient-auth pickup (no --pickup-code) → JSON has 6-digit code."""
        shareLink, shareInfo = self._startUploadAndGetInfo(
            ["--recipient-auth", "pickup"]
        )
        pickupCode = shareInfo.get("pickup_code")
        self.assertIsNotNone(pickupCode, "JSON should contain 'pickup_code'")
        self.assertEqual(len(pickupCode), 6, f"pickup_code should be 6 digits, got: {pickupCode!r}")
        self.assertTrue(pickupCode.isdigit(), f"pickup_code should be all digits, got: {pickupCode!r}")
        print(f"[Test] PASS: Upload CSPRNG pickup code is valid 6-digit string: {pickupCode}")

    def testUploadPickupCodeBlocksNoCode(self):
        """Caddy /download without ?code= → 401 Unauthorized."""
        code = "135792"
        shareLink, shareInfo = self._startUploadAndGetInfo(
            ["--recipient-auth", "pickup", "--pickup-code", code]
        )
        downloadUrl = self._buildDownloadUrl(shareLink)
        self._waitForAuthActive(downloadUrl)
        response = requests.get(downloadUrl, timeout=10, allow_redirects=False)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 without ?code=, got {response.status_code}")
        print("[Test] PASS: Upload download without code returns 401")

    def testUploadPickupCodeBlocksWrongCode(self):
        """Caddy /download with wrong X-FFL-Pickup header → 401 Unauthorized."""
        code = "246800"
        shareLink, shareInfo = self._startUploadAndGetInfo(
            ["--recipient-auth", "pickup", "--pickup-code", code]
        )
        downloadUrl = self._buildDownloadUrl(shareLink)
        self._waitForAuthActive(downloadUrl)
        response = requests.get(downloadUrl, headers={'X-FFL-Pickup': '000000'}, timeout=10, allow_redirects=False)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 with wrong X-FFL-Pickup header, got {response.status_code}")
        print("[Test] PASS: Upload download with wrong X-FFL-Pickup header returns 401")

    def testUploadPickupCodeAllowsCorrectCode(self):
        """Caddy /download with correct X-FFL-Pickup header → 200, file integrity verified."""
        code = "135780"
        shareLink, shareInfo = self._startUploadAndGetInfo(
            ["--recipient-auth", "pickup", "--pickup-code", code]
        )
        downloadUrl = self._buildDownloadUrl(shareLink)
        self._waitForAuthActive(downloadUrl)
        downloadedFilePath = self._getDownloadedFilePath("upload_pickup_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers={'X-FFL-Pickup': code})
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: Upload download with correct X-FFL-Pickup header succeeds with intact file")

    # -----------------------------------------------------------------------
    # Pubkey auth upload tests
    # -----------------------------------------------------------------------

    def testUploadPubkeyBlocksNoProof(self):
        """Caddy /download without X-FFL-Proof → 401 Unauthorized."""
        privKeyPath, shareLink, downloadUrl = self._startUploadWithPubkeyAndWait('upload_pubkey_block')
        response = requests.get(downloadUrl, timeout=10, allow_redirects=False)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 without X-FFL-Proof, got {response.status_code}")
        print("[Test] PASS: Upload pubkey download without proof returns 401")

    def testUploadPubkeyAllowsCorrectProof(self):
        """Caddy /download with correct X-FFL-Proof header → 200, file integrity verified."""
        privKeyPath, shareLink, downloadUrl = self._startUploadWithPubkeyAndWait('upload_pubkey_allow')
        proof = self._resolveProofForUpload(shareLink, privKeyPath)
        downloadedFilePath = self._getDownloadedFilePath("upload_pubkey_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers={'X-FFL-Proof': proof})
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: Upload pubkey download with correct proof succeeds with intact file")

    def testUploadPubkeyAllowsAnyConfiguredRecipientKey(self):
        """Caddy /download accepts a proof from any configured recipient public key."""
        firstPrivKeyPath, firstPubKeyPath = self._generateKeypair('upload_pubkey_multi_alice')
        secondPrivKeyPath, secondPubKeyPath = self._generateKeypair('upload_pubkey_multi_bob')
        shareLink, shareInfo = self._startUploadAndGetInfo([
            '--recipient-auth', 'pubkey',
            '--recipient-public-key', f'{firstPubKeyPath},{secondPubKeyPath}',
        ])
        downloadUrl = self._buildDownloadUrl(shareLink)
        self._waitForAuthActive(downloadUrl)
        proof = self._resolveProofForUpload(shareLink, secondPrivKeyPath)
        downloadedFilePath = self._getDownloadedFilePath("upload_pubkey_multi_download.bin")
        transferChecksum = self.downloadFileWithRequests(
            downloadUrl, downloadedFilePath, headers={'X-FFL-Proof': proof})
        self._verifyDownloadedFile(downloadedFilePath, transferChecksum=transferChecksum)
        print(f"[Test] PASS: Upload pubkey download succeeded with second configured key")

    def testUploadPubkeyBlocksWrongProof(self):
        """Caddy /download with wrong X-FFL-Proof → 401 Unauthorized."""
        privKeyPath, shareLink, downloadUrl = self._startUploadWithPubkeyAndWait('upload_pubkey_wrong')
        wrongProof = base64.b64encode(b'wrong' * 6).decode()
        response = requests.get(downloadUrl, headers={'X-FFL-Proof': wrongProof}, timeout=10, allow_redirects=False)
        self.assertEqual(response.status_code, 401,
                         f"Expected 401 with wrong X-FFL-Proof, got {response.status_code}")
        print("[Test] PASS: Upload pubkey download with wrong proof returns 401")

    def _waitForPageReady(self, shareLink, timeout=90):
        """Poll shareLink until the HTML page is served (200 with HTML content).

        Must send a browser User-Agent: CaddyIndex.tpl redirects non-browser clients
        (no 'Mozilla' in UA) directly to /{uid}/download (the binary file).
        requests auto-decompresses Content-Encoding: gzip responses.
        """
        startTime = time.time()
        while time.time() - startTime < timeout:
            try:
                response = requests.get(
                    shareLink, timeout=5, allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; ffl-test)'}
                )
                if response.status_code == 200 and len(response.content) > 100:
                    return response.text
            except Exception:
                pass
            time.sleep(1)
        raise AssertionError(f"Page not available at {shareLink} within {timeout}s")

    @unittest.skipIf(SKIP_EMAIL_RECIPIENT_TEST, 'FFL_TEST_EMAIL env var not set')
    def testUploadEmailGateRenderedInHTML(self):
        """--upload with --recipient-auth email → FileDownloading.html contains EMAIL_REQUIRED=true.

        This test verifies the full data chain: Core.py → Upload header → Django API →
        CaddyPublisher → FileDownloading.html template rendering.
        Without the fix in PushUpload.execute() (passing recipientEmail to end()),
        the header is never sent to EndUploadFile, EMAIL_REQUIRED renders as false,
        and the gate is never shown.
        """
        recipientEmail = os.environ['FFL_TEST_EMAIL']
        shareLink, shareInfo = self._startUploadAndGetInfo([
            '--recipient-auth', 'email',
            '--recipient-email', recipientEmail,
        ])

        print(f'[Test] Uploaded, share link: {shareLink}')
        htmlContent = self._waitForPageReady(shareLink)

        self.assertIn('EMAIL_REQUIRED = true', htmlContent,
                      'EMAIL_REQUIRED should be true in FileDownloading.html — '
                      'check that recipientEmail is passed to end() in PushUpload.execute()')
        self.assertIn(f'RECIPIENT_EMAILS = ["{recipientEmail}"]', htmlContent,
                      f'RECIPIENT_EMAILS should contain "{recipientEmail}" in FileDownloading.html')
        print(f'[Test] PASS: EMAIL_REQUIRED=true and RECIPIENT_EMAILS rendered correctly in HTML')


class _GateBrowserMixin:
    """Mixin for auth gate browser tests — provides _openAndWaitForGate."""

    def _openAndWaitForGate(self, driver, url, gateId='pickupGate'):
        """Navigate to url, wait for page ready, then wait for gateId to be CSS-visible.

        Uses a JS getComputedStyle check rather than Selenium's is_displayed() because
        headless Chrome on Linux can report elements as not displayed even when the inline
        style explicitly sets display:block (e.g. when a sibling contains a file input).
        """
        driver.get(url)
        WebDriverWait(driver, 10).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        try:
            WebDriverWait(driver, 15).until(
                lambda d: d.execute_script(
                    "const el = document.getElementById(arguments[0]);"
                    "if (!el) return false;"
                    "const s = window.getComputedStyle(el);"
                    "return s.display !== 'none' && s.visibility !== 'hidden'"
                    "       && parseFloat(s.opacity || '1') > 0;",
                    gateId
                )
            )
        except Exception:
            try:
                for entry in driver.get_log('browser'):
                    print(f"[Browser] {entry['level']}: {entry['message']}")
            except Exception:
                pass
            raise

class _EmailBrowserMixin:
    """Mixin for email OTP gate browser tests."""

    OTP_ERROR_ELEMENT_ID = 'unlock-error-message'

    def _openEmailGate(self, driver, shareLink, recipientEmail=None):
        """Open email gate, assert display state, and set email input when multi-recipient UI is shown."""
        self._openAndWaitForGate(driver, shareLink, gateId='emailGate')
        downloadBlock = driver.find_element(By.ID, 'downloadBlock')
        self.assertEqual(downloadBlock.get_attribute('style'), 'display: none;',
                         'downloadBlock should be hidden while email gate is shown')
        if recipientEmail is None:
            emailDisplay = WebDriverWait(driver, 10).until(
                lambda d: d.find_element(By.ID, 'email-address-display') if d.find_element(By.ID, 'email-address-display').text else None
            )
            self.assertEqual(emailDisplay.text, self.TEST_EMAIL,
                             f'Email display mismatch: {emailDisplay.text!r}')
            return

        emailInput = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, 'email-address-input'))
        )
        emailInput.clear()
        emailInput.send_keys(recipientEmail)

    def _requestEmailOTP(self, driver, gateWaitTimeout=15):
        """Click Send Code and wait for OTP input section to appear."""
        sendBtn = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, 'email-send-btn'))
        )
        sendBtn.click()
        WebDriverWait(driver, gateWaitTimeout).until(
            EC.visibility_of_element_located((By.ID, 'email-otp-section'))
        )

    def _openEmailGateAndRequestOTP(self, driver, shareLink):
        """Open email gate, assert display state, click Send Code, wait for OTP input section."""
        self._openEmailGate(driver, shareLink)
        self._requestEmailOTP(driver)

    def _submitOTPAndVerifyAccepted(self, driver, otp, gateWaitTimeout=15):
        """Enter otp, submit, assert gate disappears without error."""
        driver.find_element(By.ID, 'email-otp-input').send_keys(otp)
        driver.find_element(By.ID, 'unlock-btn').click()
        errorElId = self.OTP_ERROR_ELEMENT_ID

        def gateResolved(d):
            gateGone = not d.find_element(By.ID, 'emailGate').is_displayed()
            errorEl = d.find_element(By.ID, errorElId)
            return gateGone or (errorEl.is_displayed() and bool(errorEl.text.strip()))

        WebDriverWait(driver, gateWaitTimeout).until(gateResolved)
        errorEl = driver.find_element(By.ID, errorElId)
        self.assertFalse(
            errorEl.is_displayed() and bool(errorEl.text.strip()),
            f'OTP authentication rejected by server: {errorEl.text!r}'
        )

    def _submitWrongOTPAndVerifyRejected(self, driver, wrongOTP='000000', errorWaitTimeout=10):
        """Enter wrong OTP, submit, assert error shown and gate remains visible."""
        driver.find_element(By.ID, 'email-otp-input').send_keys(wrongOTP)
        driver.find_element(By.ID, 'unlock-btn').click()
        WebDriverWait(driver, errorWaitTimeout).until(
            EC.visibility_of_element_located((By.ID, self.OTP_ERROR_ELEMENT_ID))
        )
        self.assertTrue(
            driver.find_element(By.ID, 'emailGate').is_displayed(),
            'emailGate should remain visible after wrong OTP'
        )


class AuthUploadBrowserTest(_UploadAuthMixin, _GateBrowserMixin, BrowserTestBase):
    """Browser tests for pickup code UI on the Caddy-served FileDownloading.html page."""

    def __init__(self, methodName='runTest'):
        # 512 KB — fast upload and browser download
        super().__init__(methodName, fileSizeBytes=512 * 1024)

    def _startUploadPickupBrowserTest(self, code, browser='chrome'):
        """Upload file with pickup auth, wait for Caddy to enforce it, return (shareLink, driver, downloadDir)."""
        shareLink, shareInfo = self._startUploadAndGetInfo(
            ["--recipient-auth", "pickup", "--pickup-code", code]
        )
        self._waitForAuthActive(self._buildDownloadUrl(shareLink))
        if browser == 'firefox':
            downloadDir = self.firefoxDownloadDir
            driver = self._setupFirefoxDriver(downloadDir)
        else:
            downloadDir = self.chromeDownloadDir
            driver = self._setupChromeDriver(downloadDir)
        self.activeDrivers.append(driver)
        return shareLink, driver, downloadDir

    def testBrowserUploadPickupCodeRequired(self):
        """Upload: browser shows pickup gate, download does not auto-start."""
        shareLink, driver, downloadDir = self._startUploadPickupBrowserTest("482952")
        try:
            print(f"[Test] Navigating to Caddy download page: {shareLink}")
            self._openAndWaitForGate(driver, shareLink)
            print(f"[Test] Pickup gate visible on FileDownloading.html")

            # Download block must be hidden
            downloadBlock = driver.find_element(By.ID, 'downloadBlock')
            self.assertEqual(downloadBlock.get_attribute('style'), 'display: none;',
                             "downloadBlock should be hidden when pickup gate is shown")
            print(f"[Test] PASS: Pickup gate shown, download correctly blocked")
        finally:
            self._terminateProcess()

    def testBrowserUploadPickupCodeWrongCodeRejected(self):
        """Upload: wrong pickup code → error message shown, gate remains."""
        shareLink, driver, downloadDir = self._startUploadPickupBrowserTest("617294")
        try:
            self._openAndWaitForGate(driver, shareLink)

            codeInput = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, 'pickup-code-input'))
            )
            codeInput.send_keys("000000")
            driver.find_element(By.ID, 'unlock-btn').click()
            print(f"[Test] Submitted wrong pickup code: 000000")

            # Error message should appear
            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, 'pickup-error-message'))
            )
            # Gate should still be visible
            self.assertTrue(
                driver.find_element(By.ID, 'pickupGate').is_displayed(),
                "pickupGate should remain visible after wrong code"
            )
            print(f"[Test] PASS: Wrong pickup code shows error, gate remains")
        finally:
            self._terminateProcess()

    def testBrowserUploadPickupCodeAllows(self):
        """Upload: correct pickup code → download completes, file integrity verified."""
        code = "617295"
        shareLink, driver, downloadDir = self._startUploadPickupBrowserTest(code, browser='firefox')
        try:
            print(f"[Test] Navigating to Caddy download page: {shareLink}")
            self._openAndWaitForGate(driver, shareLink)

            codeInput = driver.find_element(By.ID, 'pickup-code-input')
            codeInput.send_keys(code)
            driver.find_element(By.ID, 'unlock-btn').click()
            print(f"[Test] Submitted correct pickup code: {code}")

            # Gate should disappear
            WebDriverWait(driver, 10).until(
                EC.invisibility_of_element_located((By.ID, 'pickupGate'))
            )

            downloadedFile = self._waitForDownload(downloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)
            print(f"[Test] PASS: Correct pickup code in browser allowed full upload download")
        finally:
            self._terminateProcess()


class AuthBrowserTest(_GateBrowserMixin, BrowserTestBase):
    """Browser tests for pickup code UI.

    Set STATIC_SERVER env var so the browser loads locally-built static/index.html and its JS.
    """

    def __init__(self, methodName='runTest'):
        # 1 MB keeps the download under USE_BLOB_THRESHOLD (10 MB) → Blob path, no StreamSaver needed
        super().__init__(methodName, fileSizeBytes=1 * 1024 * 1024)

    def testBrowserPickupCodeRequired(self):
        """Browser: share with pickup code → code input block shown, download does not auto-start."""
        correctCode = "482951"
        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=["--pickup-code", correctCode, "--timeout", "30"]
        )

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)

        try:
            print(f"[Test] Navigating to share link: {shareLink}")
            self._openAndWaitForGate(driver, shareLink)
            print(f"[Test] Pickup code block is visible")

            # Download must NOT have auto-started — progress bar stays at 0
            progressValue = driver.find_element(By.ID, 'downloadProgress').get_attribute('value')
            self.assertEqual(progressValue, '0',
                             f"Progress should be 0 when pickup code not entered, got {progressValue}")

            print(f"[Test] PASS: Pickup code block shown, download correctly blocked")
        finally:
            self._terminateProcess()

    def testBrowserPickupCodeAllows(self):
        """Browser: enter correct pickup code → download completes, file integrity verified."""
        correctCode = "617293"
        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=["--pickup-code", correctCode, "--timeout", "60"]
        )

        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)

        try:
            print(f"[Test] Navigating to share link: {shareLink}")
            self._openAndWaitForGate(driver, shareLink)

            # Enter the correct code and submit
            codeInput = driver.find_element(By.ID, 'pickup-code-input')
            codeInput.send_keys(correctCode)
            driver.find_element(By.ID, 'unlock-btn').click()
            print(f"[Test] Submitted pickup code: {correctCode}")

            # Pickup code block should now be hidden
            WebDriverWait(driver, 5).until(
                EC.invisibility_of_element_located((By.ID, 'pickupGate'))
            )

            # Wait for the browser to finish downloading the file
            downloadedFile = self._waitForDownload(self.chromeDownloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)

            print(f"[Test] PASS: Correct pickup code in browser allowed full download")
        finally:
            self._terminateProcess()

    def testBrowserCombinedNativeLink(self):
        """Browser: pubkey+pickup with ?native=true → triggerNativeDownloadLink path, file integrity verified.

        WebRTC is disabled so the HTTP fallback fires and triggerNativeDownloadLink is used,
        which requires the ffl_dlk session cookie set by authEndpoint (cannot send custom headers via <a href>).
        """
        correctCode = "248135"
        privKeyPath, pubKeyPath = self._generateKeypair('alice_native')

        # Set up Chrome before starting the FFL process so the driver's cold-start time
        # (undetected_chromedriver can be slow on first run) does not consume the server's
        # absolute 60-second timeout, which would cause a 502 when Chrome finally navigates.
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        if 'JENKINS_HOME' in os.environ:
            self._injectPerformanceTimelineMonitor(driver)

        shareLink = self._startFastFileLink(
            p2p=True,
            extraArgs=[
                "--recipient-auth", "pubkey+pickup",
                "--recipient-public-key", pubKeyPath,
                "--pickup-code", correctCode,
                "--timeout", "60"
            ],
            extraEnvVars={"DISABLE_WEBRTC": "True"}
        )

        try:
            pageUrl = shareLink + '?native=true'
            print(f"[Test] Navigating to: {pageUrl}")
            self._openAndWaitForGate(driver, pageUrl)
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script(
                    "const el = document.getElementById('pubkeyGate');"
                    "if (!el) return false;"
                    "const s = window.getComputedStyle(el);"
                    "return s.display !== 'none' && s.visibility !== 'hidden'"
                    "       && parseFloat(s.opacity || '1') > 0;"
                )
            )
            print(f"[Test] Both pickup and pubkey gates visible")

            # Enter pickup code
            driver.find_element(By.ID, 'pickup-code-input').send_keys(correctCode)

            # Upload private key file — make visible first so send_keys works reliably
            driver.execute_script("document.getElementById('pubkey-file-input').style.display = 'block'")
            driver.find_element(By.ID, 'pubkey-file-input').send_keys(privKeyPath)
            print(f"[Test] Private key file selected: {privKeyPath}")

            # Submit
            driver.find_element(By.ID, 'unlock-btn').click()
            print(f"[Test] Clicked unlock")

            # Capture browser console for diagnostics
            time.sleep(2)
            for entry in driver.get_log('browser'):
                print(f"[Browser] {entry['level']}: {entry['message']}")

            # Gates should disappear after successful auth
            WebDriverWait(driver, 30).until(
                EC.invisibility_of_element_located((By.ID, 'authGateContainer'))
            )

            # Wait for native download (triggerNativeDownloadLink fires <a download>)
            downloadedFile = self._waitForDownload(self.chromeDownloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)

            print(f"[Test] PASS: pubkey+pickup with ?native=true completed download via native link")
        finally:
            # Always print the FFL process log so we can diagnose crashes
            if self._procLogFile and self.procLogPath:
                try:
                    self._procLogFile.flush()
                    with open(self.procLogPath, 'r', encoding='utf-8', errors='replace') as f:
                        procLog = f.read()
                    print(f"[Test] FFL process log:\n{procLog}")
                except Exception as e:
                    print(f"[Test] Could not read process log: {e}")
            if self.coreProcess:
                print(f"[Test] FFL process exit code: {self.coreProcess.poll()}")
            self._terminateProcess()


@unittest.skipIf(SKIP_EMAIL_AUTH_TEST, 'FFL_TEST_EMAIL, FFL_TEST_IMAP_HOST, FFL_TEST_IMAP_PASSWORD env vars not set')
class EmailAuthBrowserTest(IMAPTestMixin, _EmailBrowserMixin, _GateBrowserMixin, BrowserTestBase):
    """Browser tests for --recipient-auth email gate (P2P).

    Shares a file with email OTP auth, navigates to the page in a browser,
    clicks "Send Code", fetches the OTP from the test IMAP inbox, enters it,
    and verifies that the download completes successfully.

    Required env vars:
      FFL_TEST_EMAIL         — recipient email address used for OTP
      FFL_TEST_IMAP_HOST     — IMAP server hostname
      FFL_TEST_IMAP_PASSWORD — IMAP account password
    Optional env vars:
      FFL_TEST_IMAP_PORT     — IMAP port (default: 993)
    """

    def __init__(self, methodName='runTest'):
        super().__init__(methodName, fileSizeBytes=512 * 1024)

    def setUp(self):
        super().setUp()
        self.TEST_EMAIL = os.environ['FFL_TEST_EMAIL']
        self.IMAP_EMAIL = self.TEST_EMAIL
        self.IMAP_HOST = os.environ['FFL_TEST_IMAP_HOST']
        self.IMAP_PORT = int(os.environ.get('FFL_TEST_IMAP_PORT', '993'))
        self.IMAP_PASSWORD = os.environ['FFL_TEST_IMAP_PASSWORD']

    def _startEmailShare(self, timeout='120', recipientEmail=None):
        """Start P2P share with email auth, return shareLink."""
        return self._startFastFileLink(
            p2p=True,
            extraArgs=['--recipient-auth', 'email', '--recipient-email', recipientEmail or self.TEST_EMAIL,
                       '--timeout', timeout],
        )

    def testBrowserEmailGateShownAndDownloadWorks(self):
        """Email auth: gate shown → Send Code → IMAP fetch OTP → enter → download completes."""
        self._deleteTestEmails()
        shareLink = self._startEmailShare(timeout='120')
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)
        try:
            print(f'[Test] Navigating to share link: {shareLink}')
            self._openEmailGateAndRequestOTP(driver, shareLink)
            print('[Test] OTP input section appeared')
            otp = self._fetchOTPFromEmail(timeout=90)
            print(f'[Test] Received OTP via IMAP: {otp}')
            print('[Test] Submitted OTP, waiting for gate to disappear or error to appear')
            self._submitOTPAndVerifyAccepted(driver, otp)
            downloadedFile = self._waitForDownload(self.chromeDownloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)
            print('[Test] PASS: Email OTP gate allowed full download, file integrity verified')
        finally:
            self._terminateProcess()

    def testBrowserEmailGateWrongOTPRejected(self):
        """Email auth: wrong OTP → error message shown, gate remains."""
        self._deleteTestEmails()
        shareLink = self._startEmailShare(timeout='60')
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)
        try:
            self._openEmailGateAndRequestOTP(driver, shareLink)
            self._fetchOTPFromEmail(timeout=60)  # Consume the email to keep IMAP clean for subsequent tests
            print('[Test] Submitted wrong OTP: 000000')
            self._submitWrongOTPAndVerifyRejected(driver)
            print('[Test] PASS: Wrong OTP shows error, gate remains visible')
        finally:
            self._terminateProcess()

    def testBrowserEmailGateRejectsUnlistedAddressThenAllowsListedAddress(self):
        """Email auth with multiple recipients: reject unlisted address, then allow a listed address."""
        self._deleteTestEmails()
        shareLink = self._startEmailShare(
            timeout='120',
            recipientEmail=f'{self.TEST_EMAIL},someoneelse@example.com'
        )
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)
        try:
            self._openEmailGate(driver, shareLink, recipientEmail='intruder@example.com')
            driver.find_element(By.ID, 'email-send-btn').click()
            errorEl = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, 'email-error-message'))
            )
            self.assertIn('not allowed', errorEl.text.lower())
            self.assertFalse(
                driver.find_element(By.ID, 'email-otp-section').is_displayed(),
                'OTP section should stay hidden for an unlisted email address'
            )

            self._openEmailGate(driver, shareLink, recipientEmail=self.TEST_EMAIL)
            self._requestEmailOTP(driver)
            otp = self._fetchOTPFromEmail(timeout=90)
            self._submitOTPAndVerifyAccepted(driver, otp)
            downloadedFile = self._waitForDownload(self.chromeDownloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)
            print('[Test] PASS: Multi-email allowlist rejected unlisted address and allowed listed address')
        finally:
            self._terminateProcess()


@unittest.skipIf(SKIP_EMAIL_AUTH_TEST, 'FFL_TEST_EMAIL, FFL_TEST_IMAP_HOST, FFL_TEST_IMAP_PASSWORD env vars not set')
class EmailAuthUploadBrowserTest(_UploadAuthMixin, EmailAuthBrowserTest):
    """Browser tests for --recipient-auth email with --upload (Caddy FileDownloading.html)."""

    OTP_ERROR_ELEMENT_ID = 'email-error-message'

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    def _startUploadEmailShare(self, recipientEmail=None):
        """Upload file with email auth, return (shareLink, shareInfo)."""
        return self._startUploadAndGetInfo([
            '--recipient-auth', 'email',
            '--recipient-email', recipientEmail or self.TEST_EMAIL,
        ])

    def testBrowserUploadEmailGateShownAndDownloadWorks(self):
        """Upload email auth: email gate shown, correct OTP → download completes."""
        self._deleteTestEmails()
        shareLink, shareInfo = self._startUploadEmailShare()
        downloadDir = self.firefoxDownloadDir
        driver = self._setupFirefoxDriver(downloadDir)
        self.activeDrivers.append(driver)
        try:
            print(f'[Test] Navigating to Caddy download page: {shareLink}')
            self._openEmailGateAndRequestOTP(driver, shareLink)
            print('[Test] OTP input section appeared')
            otp = self._fetchOTPFromEmail(timeout=90)
            print(f'[Test] Received OTP via IMAP: {otp}')
            print('[Test] Submitted OTP, waiting for gate to resolve')
            self._submitOTPAndVerifyAccepted(driver, otp, gateWaitTimeout=20)
            downloadedFile = self._waitForDownload(downloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)
            print('[Test] PASS: Upload email OTP gate allowed full download, file integrity verified')
        finally:
            self._terminateProcess()

    def testBrowserEmailGateWrongOTPRejected(self):
        """Upload email auth: wrong OTP → error message shown, gate remains."""
        self._deleteTestEmails()
        shareLink, shareInfo = self._startUploadEmailShare()
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)
        try:
            self._openEmailGateAndRequestOTP(driver, shareLink)
            self._fetchOTPFromEmail(timeout=60)  # Consume the email to keep IMAP clean for subsequent tests
            print('[Test] Submitted wrong OTP: 000000')
            self._submitWrongOTPAndVerifyRejected(driver, errorWaitTimeout=15)
            print('[Test] PASS: Wrong OTP shows error, gate remains visible')
        finally:
            self._terminateProcess()

    def testBrowserUploadEmailGateRejectsUnlistedAddressThenAllowsListedAddress(self):
        """Upload email auth with multiple recipients: reject unlisted address, then allow a listed address."""
        self._deleteTestEmails()
        shareLink, shareInfo = self._startUploadEmailShare(
            recipientEmail=f'{self.TEST_EMAIL},someoneelse@example.com'
        )
        driver = self._setupChromeDriver(self.chromeDownloadDir)
        self.activeDrivers.append(driver)
        try:
            self._openEmailGate(driver, shareLink, recipientEmail='intruder@example.com')
            driver.find_element(By.ID, 'email-send-btn').click()
            errorEl = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, 'email-error-message'))
            )
            self.assertIn('not allowed', errorEl.text.lower())
            self.assertFalse(
                driver.find_element(By.ID, 'email-otp-section').is_displayed(),
                'OTP section should stay hidden for an unlisted email address'
            )

            self._openEmailGate(driver, shareLink, recipientEmail=self.TEST_EMAIL)
            self._requestEmailOTP(driver)
            otp = self._fetchOTPFromEmail(timeout=90)
            self._submitOTPAndVerifyAccepted(driver, otp, gateWaitTimeout=20)
            downloadedFile = self._waitForDownload(self.chromeDownloadDir, 'testfile.bin', driver=driver)
            self._verifyDownloadedFile(downloadedFile)
            print('[Test] PASS: Upload multi-email allowlist rejected unlisted address and allowed listed address')
        finally:
            self._terminateProcess()
