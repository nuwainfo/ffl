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
import datetime
import secrets

from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import Callable, Optional, Tuple

from bases.crypto import CryptoInterface
from bases.Kernel import getLogger, FFLEvent

logger = getLogger(__name__)

PICKUP_CODE_LENGTH = 6

PUBKEY_PUBLIC_EXT = '.fflpub'
PUBKEY_PRIVATE_EXT = '.fflkey'


@dataclass
class HTTPAuth:
    """HTTP Basic Authentication credentials."""
    user: Optional[str] = None
    password: Optional[str] = None

    def isEnabled(self) -> bool:
        """Check if authentication is enabled (password is required)."""
        return bool(self.password)


class AuthMixin:
    """
    A mixin to handle Basic Authentication for BaseHTTPRequestHandler.
    Provides authentication functionality for protecting HTTP resources.

    Child classes must implement:
        @property
        def auth(self) -> HTTPAuth:
            return HTTPAuth(user=..., password=...)
    """
    REALM = 'FastFileLink Protected Resource'

    def handleAuthentication(self):
        """
        Checks the 'Authorization' header and validates user credentials.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        # Skip auth if not configured (password is required to enable auth)
        if not self.auth.isEnabled():
            return True

        authHeader = self.headers.get('Authorization')

        if not authHeader or not authHeader.startswith('Basic '):
            logger.warning("Authentication challenge sent: No or invalid auth header")
            self.sendAuthChallenge()
            return False

        try:
            # Decode credentials from Base64
            encodedCredentials = authHeader.split(' ')[1]
            decodedBytes = base64.b64decode(encodedCredentials)
            credentials = decodedBytes.decode('utf-8')
            username, password = credentials.split(':', 1)

            # Verify credentials against auth property
            if username == self.auth.user and password == self.auth.password:
                logger.info(f"Authentication successful for user: '{username}'")

                # Trigger authSuccess event
                FFLEvent.authSuccess.trigger(
                    username=username,
                    timestamp=datetime.datetime.now().isoformat(),
                    clientIp=self.client_address[0] if self.client_address else None
                )

                return True
            else:
                logger.warning(f"Authentication failed: Invalid credentials for user '{username}'")

                # Trigger authFailed event
                FFLEvent.authFailed.trigger(
                    username=username,
                    clientIp=self.client_address[0] if self.client_address else None,
                    timestamp=datetime.datetime.now().isoformat()
                )

                self.sendAuthChallenge()
                return False
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            logger.error(f"Error decoding credentials: {e}")
            self.sendAuthChallenge()
            return False

    def sendAuthChallenge(self):
        """
        Sends a 401 Unauthorized response to the client, prompting for credentials.
        """
        # Trigger authRequired event
        FFLEvent.authRequired.trigger(realm=self.REALM, timestamp=datetime.datetime.now().isoformat())

        html = b'<h1>401 Unauthorized</h1><p>Authentication required to access this resource.</p>'

        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', f'Basic realm="{self.REALM}"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()

        self.wfile.write(html)


class RecipientAuthMode(Enum):
    NONE = 'none'
    PICKUP = 'pickup'
    PUBKEY = 'pubkey'
    PUBKEY_PICKUP = 'pubkey+pickup'
    EMAIL = 'email'


@dataclass
class RecipientAuth:
    mode: RecipientAuthMode = RecipientAuthMode.NONE
    pickupCode: Optional[str] = None
    publicKeyPems: Tuple[str, ...] = ()
    challenges: Tuple[bytes, ...] = ()
    challengeCiphertexts: Tuple[bytes, ...] = ()
    recipientEmails: Tuple[str, ...] = ()
    otpRequestUrl: Optional[str] = None        # FFL API URL: POST {email, link} sends OTP
    otpVerifyUrl: Optional[str] = None         # FFL API URL: POST {email, otp, link} verificationToken

    @classmethod
    def parseRecipientValues(
        cls,
        rawValue: Optional[str],
        normalizer: Optional[Callable[[str], str]] = None,
    ) -> Tuple[str, ...]:
        if not rawValue:
            return ()

        values = []
        seenValues = set()

        for rawPart in rawValue.split(','):
            value = rawPart.strip()
            if not value:
                continue

            normalizedValue = normalizer(value) if normalizer else value
            if normalizedValue in seenValues:
                continue

            seenValues.add(normalizedValue)
            values.append(normalizedValue)

        return tuple(values)

    @classmethod
    def normalizeEmail(cls, email: str) -> str:
        return email.strip().lower()

    @classmethod
    def serializeRecipientValues(cls, values: Tuple[str, ...]) -> Optional[str]:
        if not values:
            return None
        return ','.join(values)

    @classmethod
    def create(cls, mode: Optional[str], publicKeyPath: Optional[str] = None, pickupCode: Optional[str] = None,
               recipientEmail: Optional[str] = None, otpRequestUrl: Optional[str] = None,
               otpVerifyUrl: Optional[str] = None) -> 'RecipientAuth':
        """Factory: construct a RecipientAuth from explicit configuration values."""
        if mode == 'email':
            recipientEmails = cls.parseRecipientValues(recipientEmail, normalizer=cls.normalizeEmail)
            return cls(
                mode=RecipientAuthMode.EMAIL,
                recipientEmails=recipientEmails,
                otpRequestUrl=otpRequestUrl,
                otpVerifyUrl=otpVerifyUrl,
            )

        if mode in ('pubkey', 'pubkey+pickup'):
            crypto = CryptoInterface()
            publicKeyPaths = cls.parseRecipientValues(publicKeyPath)
            publicKeyPems = []
            challenges = []
            challengeCiphertexts = []

            for path in publicKeyPaths:
                with open(path, 'r', encoding='utf-8') as f:
                    publicKeyPem = f.read()

                publicKey = crypto.loadRSAPublicKeyFromPEM(publicKeyPem)
                challenge = cls.generateChallenge()
                challengeCiphertext = crypto.encryptRSAOAEP(publicKey, challenge)
                publicKeyPems.append(publicKeyPem)
                challenges.append(challenge)
                challengeCiphertexts.append(challengeCiphertext)

            authMode = RecipientAuthMode.PUBKEY if mode == 'pubkey' else RecipientAuthMode.PUBKEY_PICKUP
            resolvedPickupCode = pickupCode or (cls.generatePickupCode() if authMode == RecipientAuthMode.PUBKEY_PICKUP else None)

            return cls(
                mode=authMode,
                pickupCode=resolvedPickupCode,
                publicKeyPems=tuple(publicKeyPems),
                challenges=tuple(challenges),
                challengeCiphertexts=tuple(challengeCiphertexts),
            )

        if mode == 'pickup':
            return cls(mode=RecipientAuthMode.PICKUP, pickupCode=pickupCode or cls.generatePickupCode())

        return cls()

    @classmethod
    def createFromArgs(cls, config: dict) -> 'RecipientAuth':
        """Create from a flat dict of share args (Namespace vars or daemon config dict)."""
        otpAPIBase = config.get('recipientOTPAPIBase')
        return cls.create(
            mode=config.get('recipientAuth'),
            publicKeyPath=config.get('recipientPublicKey'),
            pickupCode=config.get('pickupCode'),
            recipientEmail=config.get('recipientEmail'),
            otpRequestUrl=f"{otpAPIBase.rstrip('/')}/otp/email/request/" if otpAPIBase else None,
            otpVerifyUrl=f"{otpAPIBase.rstrip('/')}/otp/email/verify/" if otpAPIBase else None,
        )

    @classmethod
    def generatePickupCode(cls) -> str:
        """Generate a cryptographically secure 6-digit pickup code (zero-padded)."""
        return f"{secrets.randbelow(10 ** PICKUP_CODE_LENGTH):0{PICKUP_CODE_LENGTH}d}"

    @classmethod
    def generateChallenge(cls) -> bytes:
        """Generate a cryptographically secure 32-byte challenge."""
        return secrets.token_bytes(32)

    def isEnabled(self) -> bool:
        return self.mode != RecipientAuthMode.NONE

    def requiresPickup(self) -> bool:
        return self.mode in (RecipientAuthMode.PICKUP, RecipientAuthMode.PUBKEY_PICKUP)

    def requiresPubkey(self) -> bool:
        return self.mode in (RecipientAuthMode.PUBKEY, RecipientAuthMode.PUBKEY_PICKUP)

    def requiresEmail(self) -> bool:
        return self.mode == RecipientAuthMode.EMAIL

    def hasMultipleRecipientEmails(self) -> bool:
        return len(self.recipientEmails) > 1

    def getRecipientEmailPayload(self) -> Optional[str]:
        return self.serializeRecipientValues(self.recipientEmails)

    def getPrimaryRecipientEmail(self) -> Optional[str]:
        if not self.recipientEmails:
            return None
        return self.recipientEmails[0]

    def getPublicKeyPayload(self) -> Optional[str]:
        return self.serializeRecipientValues(self.publicKeyPems)

    def getChallenges(self) -> Tuple[bytes, ...]:
        return self.challenges

    def getChallengeCiphertexts(self) -> Tuple[bytes, ...]:
        return self.challengeCiphertexts

    def isAllowedEmail(self, email: Optional[str]) -> bool:
        if not self.requiresEmail():
            return True

        normalizedEmail = self.normalizeEmail(email or '')
        if not normalizedEmail:
            return False

        return normalizedEmail in {self.normalizeEmail(allowedEmail) for allowedEmail in self.recipientEmails}

    def verify(self, code: Optional[str] = None, proof: Optional[str] = None) -> bool:
        """Return True if all required credentials are valid. No-op when not enabled."""
        if not self.isEnabled():
            return True

        if self.requiresPickup():
            if not (code and code == self.pickupCode):
                return False

        if self.requiresPubkey():
            if not self._verifyProof(proof):
                return False

        return True

    def verifyCode(self, code: Optional[str]) -> bool:
        """Verify only the pickup code, ignoring other auth requirements."""
        if not self.requiresPickup():
            return True
        return bool(code and code == self.pickupCode)

    def verifyProof(self, proof: Optional[str]) -> bool:
        """Verify only the pubkey proof, ignoring other auth requirements."""
        if not self.requiresPubkey():
            return True
        return self._verifyProof(proof)

    def _verifyProof(self, proof: Optional[str]) -> bool:
        """Verify base64-encoded decrypted challenge matches any stored challenge."""
        challengeValues = self.getChallenges()
        if not proof or not challengeValues:
            return False

        try:
            proofBytes = base64.b64decode(proof)
            return any(secrets.compare_digest(proofBytes, challengeValue) for challengeValue in challengeValues)
        except Exception:
            return False
