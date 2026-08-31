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
import hashlib

from ffl_mbedtls import CryptoEngine, RSAPrivateKey, RSAPublicKey

from bases.crypto import CryptoBackend


_RSAPublicKey = RSAPublicKey
_RSAPrivateKey = RSAPrivateKey


class MbedTLSBackend(CryptoBackend):
    """FastFileLink crypto backend backed by ffl_mbedtls."""

    @staticmethod
    def _extractKeyMaterial(keyOrCipher):
        if isinstance(keyOrCipher, bytes):
            return keyOrCipher
            
        if isinstance(keyOrCipher, (bytearray, memoryview)):
            return bytes(keyOrCipher)

        if isinstance(keyOrCipher, dict):
            if "key" not in keyOrCipher:
                raise TypeError("cipher dict must contain a 'key' entry")
                
            return bytes(keyOrCipher["key"])

        key = getattr(keyOrCipher, "key", None)
        if key is not None:
            return bytes(key)

        privateKey = getattr(keyOrCipher, "_key", None)
        if privateKey is not None:
            return bytes(privateKey)

        raise TypeError("unsupported AES key container")

    def __init__(self):
        self.crypto = CryptoEngine()

    def getName(self):
        return "ffl-mbedtls"

    def generateKeyPair(self):
        privateKeyDER, publicKeyDER = self.crypto.generateP384KeyPair()
        return (
            base64.b64encode(privateKeyDER).decode(),
            base64.b64encode(publicKeyDER).decode(),
        )

    def signMessage(self, message, privateKeyB64):
        messageBytes = message.encode()
        privateKeyDER = base64.b64decode(privateKeyB64)
        signature = self.crypto.signSHA256(messageBytes, privateKeyDER)
        return base64.b64encode(signature).decode()

    def verifySignature(self, message, signatureB64, publicKeyB64):
        messageBytes = message.encode()
        signature = base64.b64decode(signatureB64)
        publicKeyDER = base64.b64decode(publicKeyB64)
        return self.crypto.verifySHA256(
            messageBytes,
            signature,
            publicKeyDER,
        )

    def encryptData(self, data, keyB64):
        key = base64.b64decode(keyB64)[:32]
        iv = self.crypto.randomBytes(16)
        dataBytes = data.encode() if isinstance(data, str) else bytes(data)
        ciphertext = self.crypto.encryptAESCBC(key, dataBytes, iv)
        return base64.b64encode(iv + ciphertext).decode()

    def decryptData(self, encryptedB64, keyB64):
        encrypted = base64.b64decode(encryptedB64)
        if len(encrypted) < 32:
            raise ValueError("encrypted data is too short")

        key = base64.b64decode(keyB64)[:32]
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        return self.crypto.decryptAESCBC(key, ciphertext, iv)

    def verifyVoucher(
        self,
        sessionToken,
        serverPublicKey,
        voucher,
        endorsementPublicKey,
    ):
        combinedString = sessionToken + serverPublicKey
        combinedHash = hashlib.sha256(combinedString.encode()).digest()
        voucherSignature = base64.b64decode(voucher)
        endorsementPublicKeyDER = base64.b64decode(endorsementPublicKey)

        # Preserve the existing protocol: the ECDSA helper hashes this
        # pre-hash once more with SHA-256 before verification.
        return self.crypto.verifySHA256(
            combinedHash,
            voucherSignature,
            endorsementPublicKeyDER,
        )

    def encryptWithPublicKey(
        self,
        data,
        publicKeyB64,
        devicePrivateKeyB64=None,
    ):
        publicKeyDER = base64.b64decode(publicKeyB64)
        devicePrivateKeyDER, devicePublicKeyDER = (
            self.crypto.generateP384KeyPair()
        )
        sharedSecret = self.crypto.deriveP384SharedSecret(
            devicePrivateKeyDER,
            publicKeyDER,
        )
        encryptionKey = self.deriveKey(
            sharedSecret,
            length=32,
            info=b"ecies-encryption",
        )
        nonce = self.crypto.randomBytes(12)
        dataBytes = data.encode() if isinstance(data, str) else bytes(data)
        ciphertextWithTag = self.crypto.encryptAESGCM(
            encryptionKey,
            dataBytes,
            nonce,
        )
        encryptedData = devicePublicKeyDER + nonce + ciphertextWithTag
        return base64.b64encode(encryptedData).decode()

    def deriveKey(self, keyMaterial, length=32, info=b"", salt=None):
        if isinstance(keyMaterial, str):
            keyMaterial = keyMaterial.encode("utf-8")
            
        if isinstance(info, str):
            info = info.encode("utf-8")
            
        if isinstance(salt, str):
            salt = salt.encode("utf-8")

        return self.crypto.deriveHKDFSHA256(
            bytes(keyMaterial),
            length=length,
            info=bytes(info),
            salt=None if salt is None else bytes(salt),
        )

    def encryptAESGCM(self, keyOrCipher, plaintext, nonce=None, aad=None):
        key = self._extractKeyMaterial(keyOrCipher)
        plaintextBytes = (
            plaintext.encode("utf-8")
            if isinstance(plaintext, str)
            else bytes(plaintext)
        )
        nonceBytes = self.crypto.randomBytes(12) if nonce is None else bytes(nonce)
        aadBytes = b"" if aad is None else bytes(aad)
        ciphertextWithTag = self.crypto.encryptAESGCM(
            key,
            plaintextBytes,
            nonceBytes,
            aadBytes,
        )
        return (nonceBytes, ciphertextWithTag)

    def decryptAESGCM(
        self,
        keyOrCipher,
        nonce,
        ciphertextWithTag,
        aad=None,
    ):
        if len(ciphertextWithTag) < 16:
            raise ValueError("Ciphertext too short for GCM tag")

        key = self._extractKeyMaterial(keyOrCipher)
        aadBytes = b"" if aad is None else bytes(aad)
        return self.crypto.decryptAESGCM(
            key,
            bytes(nonce),
            bytes(ciphertextWithTag),
            aadBytes,
        )

    def derivePublicKeyFromPrivate(self, privateKeyB64):
        privateKeyDER = base64.b64decode(privateKeyB64)
        publicKeyDER = self.crypto.deriveP384PublicKey(privateKeyDER)
        return base64.b64encode(publicKeyDER).decode()

    def loadRSAPublicKeyFromPEM(self, pemString):
        return self.crypto.loadRSAPublicKey(pemString)

    def encryptRSAOAEP(self, publicKey, plaintext):
        plaintextBytes = (
            plaintext.encode("utf-8")
            if isinstance(plaintext, str)
            else bytes(plaintext)
        )
        return self.crypto.encryptRSAOAEP(publicKey, plaintextBytes)

    def createAESGCM(self, key):
        return bytes(key)

    def generateRSAKeyPair(self, keySize=2048):
        return self.crypto.generateRSAKeyPair(keySize)

    def serializeRSAPublicKey(self, publicKey):
        return self.crypto.serializeRSAPublicKey(publicKey)

    def decryptRSAOAEP(self, privateKey, ciphertext):
        return self.crypto.decryptRSAOAEP(privateKey, bytes(ciphertext))

    def serializeRSAPrivateKeyPKCS8(self, privateKey):
        return self.crypto.serializeRSAPrivateKeyPKCS8(privateKey)
