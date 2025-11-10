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

from abc import ABC, abstractmethod

from bases.Kernel import classForName, getLogger

logger = getLogger(__name__)


class CryptoBackend(ABC):
    """Abstract base class for cryptographic backends"""

    @abstractmethod
    def getName(self):
        """Get backend name"""
        pass

    @abstractmethod
    def generateKeyPair(self):
        """Generate Ed25519 key pair, returns (privateKeyB64, publicKeyB64)"""
        pass

    @abstractmethod
    def signMessage(self, message, privateKeyB64):
        """Sign message with private key, returns signatureB64"""
        pass

    @abstractmethod
    def verifySignature(self, message, signatureB64, publicKeyB64):
        """Verify signature with public key, returns boolean"""
        pass

    @abstractmethod
    def encryptData(self, data, keyB64):
        """Encrypt data with key, returns encryptedB64"""
        pass

    @abstractmethod
    def decryptData(self, encryptedB64, keyB64):
        """Decrypt data with key, returns decrypted data"""
        pass

    @abstractmethod
    def verifyVoucher(self, sessionToken, serverPublicKey, voucher, endorsementPublicKey):
        """Verify voucher using endorsement public key, returns boolean"""
        pass

    @abstractmethod
    def encryptWithPublicKey(self, data, publicKeyB64, devicePrivateKeyB64=None):
        """Encrypt data using ECIES with public key, returns base64 string"""
        pass

    @abstractmethod
    def deriveKey(self, keyMaterial, length=32, info=b'', salt=None):
        """Derive key using HKDF, returns bytes"""
        pass

    @abstractmethod
    def encryptAESGCM(self, keyOrCipher, plaintext, nonce=None, aad=None):
        """Encrypt with AES-GCM, returns (nonce, ciphertext+tag) tuple"""
        pass

    @abstractmethod
    def decryptAESGCM(self, keyOrCipher, nonce, ciphertextWithTag, aad=None):
        """Decrypt with AES-GCM, returns plaintext"""
        pass

    @abstractmethod
    def derivePublicKeyFromPrivate(self, privateKeyB64: str) -> str:
        """Derive public key from private key"""
        pass

    @abstractmethod
    def loadRSAPublicKeyFromPEM(self, pemString):
        """Load RSA public key from PEM format string"""
        pass

    @abstractmethod
    def encryptRSAOAEP(self, publicKey, plaintext):
        """Encrypt data with RSA-OAEP, returns ciphertext bytes"""
        pass

    @abstractmethod
    def createAESGCM(self, key):
        """Create a reusable AES-GCM cipher object"""
        pass

    @abstractmethod
    def generateRSAKeyPair(self, keySize=2048):
        """Generate RSA key pair, returns (privateKey, publicKey)"""
        pass

    @abstractmethod
    def serializeRSAPublicKey(self, publicKey):
        """Serialize RSA public key to PEM format string"""
        pass

    @abstractmethod
    def decryptRSAOAEP(self, privateKey, ciphertext):
        """Decrypt data with RSA-OAEP, returns plaintext bytes"""
        pass


class CryptoInterface:
    """Main crypto interface with automatic backend selection"""

    def __init__(self, preferredBackend=None):
        self.backend = self._initializeBackend(preferredBackend)

    def _initializeBackend(self, preferredBackend='auto'):
        """Initialize crypto backend with fallback priority"""
        backendList = ['cryptography', 'mbedTLS']

        # If specific backend requested, try that first
        if preferredBackend is None:
            if preferredBackend in backendList:
                try:
                    return preferredBackend()
                except ImportError as e:
                    logger.warning(f"[CRYPTO] Requested backend '{preferredBackend}' not available: {e}")

        # Auto selection or fallback - try backends in priority order
        for backendName in backendList:
            try:
                backendModule = f'{backendName[0].upper()}{backendName[1:]}'
                backendClass = classForName(f'bases.crypto.{backendModule}.{backendModule}Backend')
                return backendClass()
            except ImportError as e:
                logger.debug(f"Failed to load crypto backend {backendName}: {e}")
                continue

        # This should not happen if cryptography or mbedtls is available
        raise RuntimeError("No crypto backend available - please install 'cryptography' or 'python-mbedtls'")

    def getBackendName(self):
        """Get current backend name"""
        return self.backend.getName()

    def __getattr__(self, name):
        # Delegate any undefined method to backend
        return getattr(self.backend, name)
