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
import secrets

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from bases.crypto import CryptoInterface

PICKUP_CODE_LENGTH = 6

PUBKEY_PUBLIC_EXT = '.fflpub'
PUBKEY_PRIVATE_EXT = '.fflkey'


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
    publicKeyPem: Optional[str] = None         # Recipient's RSA public key PEM (SPKI)
    challenge: Optional[bytes] = None          # 32-byte server-generated challenge
    challengeCiphertext: Optional[bytes] = None  # RSA-OAEP(challenge) embedded in HTML
    recipientEmail: Optional[str] = None       # Email address for OTP auth
    otpRequestUrl: Optional[str] = None        # FFL API URL: POST {email, link} → sends OTP
    otpVerifyUrl: Optional[str] = None         # FFL API URL: POST {email, otp, link} → verificationToken

    @classmethod
    def create(cls, mode: Optional[str], publicKeyPath: Optional[str] = None, pickupCode: Optional[str] = None,
               recipientEmail: Optional[str] = None, otpRequestUrl: Optional[str] = None,
               otpVerifyUrl: Optional[str] = None) -> 'RecipientAuth':
        """Factory: construct a RecipientAuth from explicit configuration values."""
        if mode == 'email':
            return cls(
                mode=RecipientAuthMode.EMAIL,
                recipientEmail=recipientEmail,
                otpRequestUrl=otpRequestUrl,
                otpVerifyUrl=otpVerifyUrl,
            )

        if mode in ('pubkey', 'pubkey+pickup'):
            with open(publicKeyPath, 'r', encoding='utf-8') as f:
                publicKeyPem = f.read()
                
            crypto = CryptoInterface()
            publicKey = crypto.loadRSAPublicKeyFromPEM(publicKeyPem)
            challenge = cls.generateChallenge()
            challengeCiphertext = crypto.encryptRSAOAEP(publicKey, challenge)

            authMode = RecipientAuthMode.PUBKEY if mode == 'pubkey' else RecipientAuthMode.PUBKEY_PICKUP
            resolvedPickupCode = pickupCode or (cls.generatePickupCode() if authMode == RecipientAuthMode.PUBKEY_PICKUP else None)

            return cls(
                mode=authMode,
                pickupCode=resolvedPickupCode,
                publicKeyPem=publicKeyPem,
                challenge=challenge,
                challengeCiphertext=challengeCiphertext,
            )

        if mode == 'pickup':
            return cls(mode=RecipientAuthMode.PICKUP, pickupCode=pickupCode or cls.generatePickupCode())

        return cls()

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
        """Verify base64-encoded decrypted challenge matches stored challenge."""
        if not proof or not self.challenge:
            return False
            
        try:
            proofBytes = base64.b64decode(proof)
            return secrets.compare_digest(proofBytes, self.challenge)
        except Exception:
            return False


