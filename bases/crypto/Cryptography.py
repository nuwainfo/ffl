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

import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec, padding as asymPadding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from bases.Kernel import getLogger
from bases.crypto import CryptoBackend

logger = getLogger(__name__)


class CryptographyBackend(CryptoBackend):
    """Cryptography library backend implementation"""

    def __init__(self):
        self.ec = ec
        self.serialization = serialization
        self.hashes = hashes
        self.Cipher = Cipher
        self.algorithms = algorithms
        self.modes = modes
        self.HKDF = HKDF
        self.AESGCM = AESGCM

    def getName(self):
        return "cryptography"

    def generateKeyPair(self):
        """Generate ECDSA P-384 key pair using cryptography"""
        privateKey = self.ec.generate_private_key(self.ec.SECP384R1())

        # Export private key in DER format
        privateKeyBytes = privateKey.private_bytes(
            encoding=self.serialization.Encoding.DER,
            format=self.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self.serialization.NoEncryption()
        )

        # Export public key in DER format
        publicKey = privateKey.public_key()
        publicKeyBytes = publicKey.public_bytes(
            encoding=self.serialization.Encoding.DER, format=self.serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return (base64.b64encode(privateKeyBytes).decode(), base64.b64encode(publicKeyBytes).decode())

    def signMessage(self, message, privateKeyB64):
        """Sign message using ECDSA P-384 with cryptography"""
        privateKeyBytes = base64.b64decode(privateKeyB64)
        privateKey = self.serialization.load_der_private_key(privateKeyBytes, password=None)
        signature = privateKey.sign(message.encode(), self.ec.ECDSA(self.hashes.SHA256()))
        return base64.b64encode(signature).decode()

    def verifySignature(self, message, signatureB64, publicKeyB64):
        """Verify ECDSA P-384 signature with cryptography"""
        publicKeyBytes = base64.b64decode(publicKeyB64)
        publicKey = self.serialization.load_der_public_key(publicKeyBytes)
        signature = base64.b64decode(signatureB64)
        try:
            publicKey.verify(signature, message.encode(), self.ec.ECDSA(self.hashes.SHA256()))
        except InvalidSignature as e:
            logger.error(f'verifySignature failed: {e}')
            return False
        return True

    def encryptData(self, data, keyB64):
        """Encrypt data using AES-256-CBC"""
        key = base64.b64decode(keyB64)[:32] # Use first 32 bytes for AES-256
        iv = os.urandom(16)

        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad data to 16-byte boundary
        dataBytes = data.encode() if isinstance(data, str) else data
        padding = 16 - (len(dataBytes) % 16)
        paddedData = dataBytes + bytes([padding] * padding)

        encrypted = encryptor.update(paddedData) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()

    def decryptData(self, encryptedB64, keyB64):
        """Decrypt data using AES-256-CBC"""
        key = base64.b64decode(keyB64)[:32]
        data = base64.b64decode(encryptedB64)
        iv = data[:16]
        encrypted = data[16:]

        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        padding = decrypted[-1]
        return decrypted[:-padding].decode()

    def verifyVoucher(self, sessionToken, serverPublicKey, voucher, endorsementPublicKey):
        """Verify voucher using endorsement public key with cryptography"""
        # Step 1: Combine PASETO token string + server public key string
        combinedString = sessionToken + serverPublicKey

        # Step 2: Calculate SHA256 hash of combined string
        combinedHash = hashlib.sha256(combinedString.encode()).digest()

        # Step 3: Load endorsement public key
        endorsementKeyBytes = base64.b64decode(endorsementPublicKey)
        endorsementPubKey = self.serialization.load_der_public_key(endorsementKeyBytes)

        # Step 4: Decode and verify voucher signature
        voucherSignature = base64.b64decode(voucher)
        endorsementPubKey.verify(voucherSignature, combinedHash, self.ec.ECDSA(self.hashes.SHA256()))

        return True

    def encryptWithPublicKey(self, data, publicKeyB64, devicePrivateKeyB64=None):
        """Encrypt data using ECIES with ephemeral key (matching MbedTLS approach)"""
        # Load server public key
        publicKeyBytes = base64.b64decode(publicKeyB64)
        serverPublicKey = self.serialization.load_der_public_key(publicKeyBytes)

        # Generate ephemeral key pair for ECIES (like MbedTLS backend)
        ephemeralPrivateKey = self.ec.generate_private_key(self.ec.SECP384R1())
        ephemeralPublicKey = ephemeralPrivateKey.public_key()

        # Export ephemeral public key in DER format
        ephemeralPublicDer = ephemeralPublicKey.public_bytes(
            encoding=self.serialization.Encoding.DER, format=self.serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Perform ECDH: ephemeralPrivate * serverPublic
        sharedSecret = ephemeralPrivateKey.exchange(self.ec.ECDH(), serverPublicKey)

        # Derive encryption key using shared deriveKey method (DRY)
        encryptionKey = self.deriveKey(sharedSecret, length=32, info=b'ecies-encryption')
        if not encryptionKey:
            raise RuntimeError("Failed to derive encryption key")

        # Encrypt data using shared encryptAESGCM method (DRY)
        nonce = os.urandom(12) # 96-bit nonce for GCM

        result = self.encryptAESGCM(encryptionKey, data, nonce)
        if not result:
            raise RuntimeError("Cryptography AES-GCM encryption failed")

        nonceUsed, ciphertext = result

        # Format: ephemeralPublic + nonce + ciphertext (ECIES format)
        encryptedData = ephemeralPublicDer + nonceUsed + ciphertext

        return base64.b64encode(encryptedData).decode()

    def deriveKey(self, keyMaterial, length=32, info=b'', salt=None):
        """Derive key using HKDF with SHA-256"""
        if isinstance(keyMaterial, str):
            keyMaterial = keyMaterial.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')

        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=length, salt=salt, info=info)
        return hkdf.derive(keyMaterial)

    def encryptAESGCM(self, keyOrCipher, plaintext, nonce=None, aad=None):
        """Encrypt with AES-GCM, returns (nonce, ciphertext+tag) tuple"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Accept either a key (bytes) or pre-created cipher object (AESGCM instance)
        if isinstance(keyOrCipher, self.AESGCM):
            aesgcm = keyOrCipher
        else:
            aesgcm = self.AESGCM(keyOrCipher)

        if nonce is None:
            nonce = os.urandom(12)  # 96-bit nonce for GCM

        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return (nonce, ciphertext)

    def decryptAESGCM(self, keyOrCipher, nonce, ciphertextWithTag, aad=None):
        """Decrypt with AES-GCM, returns plaintext"""
        # Accept either a key (bytes) or pre-created cipher object (AESGCM instance)
        if isinstance(keyOrCipher, self.AESGCM):
            aesgcm = keyOrCipher
        else:
            aesgcm = self.AESGCM(keyOrCipher)

        plaintext = aesgcm.decrypt(nonce, ciphertextWithTag, aad)
        return plaintext

    def derivePublicKeyFromPrivate(self, privateKeyB64: str) -> str:
        """Derive public key from private key"""
        # Decode base64 string to DER bytes
        privateKeyDer = base64.b64decode(privateKeyB64)

        # Load private key from DER (PKCS#8 format)
        privateKey = serialization.load_der_private_key(privateKeyDer, password=None, backend=default_backend())

        # Derive the corresponding public key
        publicKey = privateKey.public_key()

        # Serialize public key to DER (SubjectPublicKeyInfo format)
        publicKeyDer = publicKey.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encode DER bytes to base64 string
        publicKeyB64 = base64.b64encode(publicKeyDer).decode('utf-8')
        return publicKeyB64

    def loadRSAPublicKeyFromPEM(self, pemString):
        """Load RSA public key from PEM format string"""
        pemBytes = pemString.encode() if isinstance(pemString, str) else pemString
        publicKey = self.serialization.load_pem_public_key(pemBytes, backend=default_backend())
        return publicKey

    def encryptRSAOAEP(self, publicKey, plaintext):
        """Encrypt data with RSA-OAEP"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        ciphertext = publicKey.encrypt(
            plaintext,
            asymPadding.OAEP(
                mgf=asymPadding.MGF1(algorithm=self.hashes.SHA256()),
                algorithm=self.hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def createAESGCM(self, key):
        """Create a reusable AES-GCM cipher object"""
        return self.AESGCM(key)

    def generateRSAKeyPair(self, keySize=2048):
        """Generate RSA key pair"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=keySize,
            backend=default_backend()
        )
        publicKey = privateKey.public_key()
        return (privateKey, publicKey)

    def serializeRSAPublicKey(self, publicKey):
        """Serialize RSA public key to PEM format string"""
        pemBytes = publicKey.public_bytes(
            encoding=self.serialization.Encoding.PEM,
            format=self.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pemBytes.decode('utf-8')

    def decryptRSAOAEP(self, privateKey, ciphertext):
        """Decrypt data with RSA-OAEP"""
        plaintext = privateKey.decrypt(
            ciphertext,
            asymPadding.OAEP(
                mgf=asymPadding.MGF1(algorithm=self.hashes.SHA256()),
                algorithm=self.hashes.SHA256(),
                label=None
            )
        )
        return plaintext
