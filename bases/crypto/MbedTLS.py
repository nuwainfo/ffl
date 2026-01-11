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
import os

import mbedtls

try:
    import mbedtls.hkdf as hkdf
except ImportError: # Cosmopolitan
    import _mbedtls_hkdf as hkdf # type: ignore

import mbedtls.hmac as hmac

from dataclasses import dataclass
from typing import Callable, Tuple

from mbedtls import pk
from mbedtls import hashlib as mbedtls_hashlib
from mbedtls import cipher

from bases.Kernel import getLogger
from bases.crypto import CryptoBackend

logger = getLogger(__name__)

_OAEP_HASH = hashlib.sha256


@dataclass
class _RSAPublicKey:
    n: int
    e: int
    pem: str

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass
class _RSAPrivateKey:
    n: int
    e: int
    d: int
    pem: str

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def toPublic(self) -> _RSAPublicKey:
        return _RSAPublicKey(self.n, self.e, self.pem)


class MbedTLSBackend(CryptoBackend):
    """Python-mbedtls backend implementation"""

    def __init__(self):
        self.mbedtls = mbedtls
        self.pk = pk
        self.mbedtls_hashlib = mbedtls_hashlib
        self.cipher = cipher

    def getName(self):
        return "python-mbedtls"

    def generateKeyPair(self):
        """Generate ECDSA P-384 key pair using mbedtls"""
        # Generate ECDSA key with P-384 curve using mbedtls
        key = self.pk.ECC(curve=b'secp384r1')
        key.generate()

        # Export keys in DER format for compatibility with cryptography
        privateKeyDer = key.export_key(format="DER")
        publicKeyDer = key.export_public_key(format="DER")

        return (base64.b64encode(privateKeyDer).decode(), base64.b64encode(publicKeyDer).decode())

    def signMessage(self, message, privateKeyB64):
        """Sign message using ECDSA P-384 with mbedtls"""
        messageBytes = message.encode()

        # Reconstruct key object from base64 private key
        privateKeyDer = base64.b64decode(privateKeyB64)
        key = self.pk.ECC.from_buffer(privateKeyDer)
        signature = key.sign(messageBytes, self.mbedtls_hashlib.sha256)

        return base64.b64encode(signature).decode()

    def verifySignature(self, message, signatureB64, publicKeyB64):
        """Verify ECDSA P-384 signature with mbedtls"""
        signature = base64.b64decode(signatureB64)
        messageBytes = message.encode()

        # Reconstruct key object from base64 public key
        publicKeyDer = base64.b64decode(publicKeyB64)
        key = self.pk.ECC.from_buffer(publicKeyDer)
        # verify() returns boolean
        return key.verify(messageBytes, signature, self.mbedtls_hashlib.sha256)

    def encryptData(self, data, keyB64):
        """Encrypt data using mbedtls AES"""
        # Use mbedtls cipher for AES encryption
        key = base64.b64decode(keyB64)[:32]
        iv = os.urandom(16)

        # Initialize AES cipher
        aes = self.cipher.AES()
        aes.set_key(key)

        # Pad data
        dataBytes = data.encode() if isinstance(data, str) else data
        padding = 16 - (len(dataBytes) % 16)
        paddedData = dataBytes + bytes([padding] * padding)

        # Encrypt in CBC mode
        encrypted = b""
        for i in range(0, len(paddedData), 16):
            block = paddedData[i:i + 16]
            if i == 0:
                encrypted += aes.encrypt(bytes(a ^ b for a, b in zip(block, iv)))
            else:
                encrypted += aes.encrypt(bytes(a ^ b for a, b in zip(block, encrypted[-16:])))

        return base64.b64encode(iv + encrypted).decode()

    def decryptData(self, encryptedB64, keyB64):
        """Decrypt data using mbedtls AES"""
        raise NotImplementedError('Mbedtls backend not support AES descrypt yet.')

    def verifyVoucher(self, sessionToken, serverPublicKey, voucher, endorsementPublicKey):
        """Verify voucher using endorsement public key with mbedtls"""
        # Step 1: Combine PASETO token string + server public key string
        combinedString = sessionToken + serverPublicKey

        # Step 2: Calculate SHA256 hash of combined string
        combinedHash = hashlib.sha256(combinedString.encode()).digest()

        # Step 3: Load endorsement public key
        endorsementKeyBytes = base64.b64decode(endorsementPublicKey)
        verifyKey = self.pk.ECC.from_buffer(endorsementKeyBytes)

        # Step 4: Decode and verify voucher signature
        voucherSignature = base64.b64decode(voucher)

        # MbedTLS verify() always returns boolean according to pk.pyx
        return verifyKey.verify(combinedHash, voucherSignature, self.mbedtls_hashlib.sha256)

    def encryptWithPublicKey(self, data, publicKeyB64, devicePrivateKeyB64=None):
        """Encrypt data using pure MbedTLS ECDH (matching ecdh_cs.py approach)"""
        # Load server public key from base64 DER
        publicKeyBytes = base64.b64decode(publicKeyB64)

        # Generate ephemeral device key pair using MbedTLS (like ecdh_cs.py)
        deviceKey = self.pk.ECC(curve=b'secp384r1')
        deviceKey.generate()
        devicePublicDer = deviceKey.export_public_key('DER')

        # Perform ECDH using MbedTLS (exact same as ecdh_cs.py)
        # This is the final corrected client-side ECDH logic from working solution

        # 1. Load server public key into an ECC object
        serverPubKey = self.pk.ECC.from_buffer(publicKeyBytes)

        # 2. Create an empty ECDHClient context
        clientECDH = self.pk.ECDHClient(self.pk.ECC(curve=b'secp384r1'))

        # 3. Manually set the private and peer public keys
        clientECDH.private_key = deviceKey.export_key("NUM")
        clientECDH.peers_public_key = serverPubKey.export_public_key("POINT")

        # 4. Generate the client's public key from its private key
        clientECDH.generate_public_key()

        # 5. Generate the shared secret
        deviceSharedSecret = clientECDH.generate_secret()

        # Convert the shared secret (an MPI) to bytes
        # For P-384, the shared secret is the 48-byte x-coordinate of the resulting point
        bitLength = deviceSharedSecret.bit_length()
        byteLength = (bitLength + 7) // 8
        tempBytes = deviceSharedSecret.to_bytes(byteLength, 'big')

        if len(tempBytes) > 48:
            sharedSecret = tempBytes[-48:]
        elif len(tempBytes) < 48:
            sharedSecret = b'\x00' * (48 - len(tempBytes)) + tempBytes
        else:
            sharedSecret = tempBytes

        # Derive encryption key using MbedTLS HKDF (matching server ECIES)
        encryptionKey = self.deriveKey(sharedSecret, length=32, info=b'ecies-encryption')
        if not encryptionKey:
            raise RuntimeError(f"[ERROR] Failed to derive encryption key")

        # Encrypt data using pure MbedTLS AES-GCM
        nonce = os.urandom(12) # 96-bit nonce for GCM

        result = self.encryptAESGCM(encryptionKey, data, nonce)
        if not result:
            raise RuntimeError(f"[ERROR] MbedTLS AES-GCM encryption failed")

        nonceUsed, ciphertextWithTag = result # ciphertext includes tag

        # Format: devicePublic + nonce + ciphertext + tag (ECIES format like ecdh_cs.py)
        encryptedData = devicePublicDer + nonceUsed + ciphertextWithTag

        return base64.b64encode(encryptedData).decode()

    def deriveKey(self, keyMaterial, length=32, info=b'', salt=None):
        """Derive key using HKDF with mbedtls"""
        if isinstance(keyMaterial, str):
            keyMaterial = keyMaterial.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')

        # Use proper HKDF implementation from mbedtls
        digestmod = lambda key: hmac.new(key, digestmod='sha256')
        derivedKey = hkdf.hkdf(keyMaterial, length, info, salt, digestmod)

        return derivedKey

    def encryptAESGCM(self, keyOrCipher, plaintext, nonce=None, aad=None):
        """Encrypt with AES-GCM, returns (nonce, ciphertext+tag) tuple"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Accept either a key (bytes) or reusable cipher container
        key = self._extractKeyMaterial(keyOrCipher)

        if nonce is None:
            nonce = os.urandom(12)  # 96-bit nonce for GCM

        # Use pure mbedtls AES-GCM with proper API
        # This returns (ciphertext, tag) tuple as documented in source tests
        adata = aad if aad is not None else b''
        aesCipher = cipher.AES.new(key, cipher.MODE_GCM, nonce, adata)

        # mbedtls encrypt() returns (ciphertext, tag) tuple
        ciphertext, tag = aesCipher.encrypt(plaintext)

        # Combine ciphertext and tag for compatibility with our interface
        combined = ciphertext + tag
        return (nonce, combined)

    def decryptAESGCM(self, keyOrCipher, nonce, ciphertextWithTag, aad=None):
        """Decrypt with AES-GCM, returns plaintext"""
        # Split ciphertext and tag (tag is last 16 bytes)
        if len(ciphertextWithTag) < 16:
            raise ValueError("Ciphertext too short for GCM tag")

        tag = ciphertextWithTag[-16:]
        actualCiphertext = ciphertextWithTag[:-16]

        key = self._extractKeyMaterial(keyOrCipher)

        # Use pure mbedtls AES-GCM with proper API
        adata = aad if aad is not None else b''
        aesCipher = cipher.AES.new(key, cipher.MODE_GCM, nonce, adata)

        # mbedtls decrypt() expects separate ciphertext and tag
        plaintext = aesCipher.decrypt(actualCiphertext, tag)

        return plaintext

    def _extractKeyMaterial(self, keyOrCipher):
        """Extract raw key bytes from supported inputs"""
        if isinstance(keyOrCipher, (bytes, bytearray, memoryview)):
            return bytes(keyOrCipher)

        # Some callers may pass a dict or object with 'key' attribute
        if isinstance(keyOrCipher, dict) and 'key' in keyOrCipher:
            return keyOrCipher['key']

        keyAttr = getattr(keyOrCipher, 'key', None)
        if keyAttr is not None:
            return keyAttr

        privateKeyAttr = getattr(keyOrCipher, '_key', None)
        if privateKeyAttr is not None:
            return privateKeyAttr

        return keyOrCipher

    def derivePublicKeyFromPrivate(self, privateKeyB64: str) -> str:
        # TODO: Not used yet, because only used in embed envelop data, but mbedtls backend only used in Cosmo (CLI).
        raise NotImplementedError('Mbedtls backend not support derivePublicKeyFromPrivate yet.')

    def loadRSAPublicKeyFromPEM(self, pemString):
        """Parse RSA public key from PEM without cryptography"""
        pemInput = pemString.decode('utf-8') if isinstance(pemString, bytes) else pemString
        return self._parsePublicKeyPem(pemInput)

    def encryptRSAOAEP(self, publicKey, plaintext):
        """Encrypt data with RSA-OAEP using python-mbedtls"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        key = self._ensurePublicKey(publicKey)
        return self._rsaOaepEncrypt(plaintext, key)

    def createAESGCM(self, key):
        """Create a reusable AES-GCM cipher object"""
        # MbedTLS requires creating new cipher for each operation
        # Return the key and we'll create cipher on-demand in encryptAESGCM
        return key

    def generateRSAKeyPair(self, keySize=2048):
        """Generate RSA key pair using python-mbedtls"""
        rsaKey = self.pk.RSA()
        rsaKey.generate(key_size=keySize, exponent=65537)
        privatePem = rsaKey.export_key("PEM")
        publicPem = rsaKey.export_public_key("PEM")
        privateKey = self._parsePrivateKeyPem(privatePem)
        publicKey = self._parsePublicKeyPem(publicPem)
        return (privateKey, publicKey)

    def serializeRSAPublicKey(self, publicKey):
        """Serialize RSA public key to PEM format string"""
        key = self._ensurePublicKey(publicKey)
        return key.pem

    def decryptRSAOAEP(self, privateKey, ciphertext):
        """Decrypt data with RSA-OAEP"""
        key = self._ensurePrivateKey(privateKey)
        return self._rsaOaepDecrypt(ciphertext, key)

    # ------------------------------------------------------------------ #
    # Internal RSA helpers                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _pemToDer(pem: str) -> bytes:
        lines = [
            line.strip()
            for line in pem.strip().splitlines()
            if line and not line.startswith("-----")
        ]
        return base64.b64decode("".join(lines))

    @staticmethod
    def _readLength(buffer: bytes, offset: int) -> Tuple[int, int]:
        first = buffer[offset]
        offset += 1
        if first & 0x80:
            num = first & 0x7F
            length = int.from_bytes(buffer[offset:offset + num], "big")
            offset += num
        else:
            length = first
        return length, offset

    @classmethod
    def _readElement(cls, buffer: bytes, offset: int):
        tag = buffer[offset]
        offset += 1
        length, offset = cls._readLength(buffer, offset)
        value = buffer[offset:offset + length]
        return tag, value, offset + length

    @classmethod
    def _parsePublicKeyPem(cls, pem: str) -> _RSAPublicKey:
        der = cls._pemToDer(pem)
        tag, value, _ = cls._readElement(der, 0)
        if tag != 0x30:
            raise ValueError("Invalid RSA public key structure")
        tag0, part0, offset = cls._readElement(value, 0)
        if tag0 == 0x02:
            n = int.from_bytes(part0, "big")
            tag1, exponent, _ = cls._readElement(value, offset)
            if tag1 != 0x02:
                raise ValueError("Invalid RSA public exponent")
            e = int.from_bytes(exponent, "big")
        else:
            tag1, bitstring, _ = cls._readElement(value, offset)
            if tag1 != 0x03 or not bitstring:
                raise ValueError("Invalid RSA public key bit string")
            rsa_der = bitstring[1:]
            tag2, rsa_seq, _ = cls._readElement(rsa_der, 0)
            if tag2 != 0x30:
                raise ValueError("Invalid RSA public key sequence")
            tag3, modulus, inner_offset = cls._readElement(rsa_seq, 0)
            tag4, exponent, _ = cls._readElement(rsa_seq, inner_offset)
            if tag3 != 0x02 or tag4 != 0x02:
                raise ValueError("Invalid RSA public key components")
            n = int.from_bytes(modulus, "big")
            e = int.from_bytes(exponent, "big")
        return _RSAPublicKey(n=n, e=e, pem=pem)

    @classmethod
    def _parsePrivateKeyPem(cls, pem: str) -> _RSAPrivateKey:
        der = cls._pemToDer(pem)
        tag, value, _ = cls._readElement(der, 0)
        if tag != 0x30:
            raise ValueError("Invalid RSA private key structure")
        tag0, version, offset = cls._readElement(value, 0)
        if tag0 != 0x02 or len(version) > 1:
            # Assume PKCS#8 (version, algorithm identifier, octet string)
            tagAlg, _, offset = cls._readElement(value, offset)
            if tagAlg != 0x30:
                raise ValueError("Invalid PKCS#8 algorithm identifier")
            tagOctet, octets, _ = cls._readElement(value, offset)
            if tagOctet != 0x04:
                raise ValueError("Invalid PKCS#8 private key payload")
            return cls._parsePrivateKeyDer(octets, pem)
        return cls._parsePrivateKeyDer(value, pem, offset)

    @classmethod
    def _parsePrivateKeyDer(cls, data: bytes, pem: str, offset: int = 0) -> _RSAPrivateKey:
        if offset == 0:
            _, _, offset = cls._readElement(data, 0)
        tagN, modulus, offset = cls._readElement(data, offset)
        tagE, publicExp, offset = cls._readElement(data, offset)
        tagD, privateExp, _ = cls._readElement(data, offset)
        if tagN != 0x02 or tagE != 0x02 or tagD != 0x02:
            raise ValueError("Invalid RSA key integers")
        n = int.from_bytes(modulus, "big")
        e = int.from_bytes(publicExp, "big")
        d = int.from_bytes(privateExp, "big")
        return _RSAPrivateKey(n=n, e=e, d=d, pem=pem)

    @staticmethod
    def _maskGeneration(seed: bytes, length: int, hashCtor: Callable[[], "hashlib._Hash"]) -> bytes:
        counter = 0
        mask = bytearray()
        while len(mask) < length:
            block = hashCtor(seed + counter.to_bytes(4, "big")).digest()
            mask.extend(block)
            counter += 1
        return bytes(mask[:length])

    @classmethod
    def _rsaOaepEncrypt(cls, message: bytes, publicKey: _RSAPublicKey,
                        label: bytes = b"", hashCtor: Callable[[], "hashlib._Hash"] = _OAEP_HASH) -> bytes:
        keyLength = publicKey.size_bytes
        hashLength = hashCtor().digest_size
        if len(message) > keyLength - 2 * hashLength - 2:
            raise ValueError("Message too long for RSA OAEP")
        labelHash = hashCtor(label).digest()
        padding = b"\x00" * (keyLength - len(message) - 2 * hashLength - 2)
        dataBlock = labelHash + padding + b"\x01" + message
        seed = os.urandom(hashLength)
        dataBlockMask = cls._maskGeneration(seed, keyLength - hashLength - 1, hashCtor)
        maskedDataBlock = bytes(a ^ b for a, b in zip(dataBlock, dataBlockMask))
        seedMask = cls._maskGeneration(maskedDataBlock, hashLength, hashCtor)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        encoded = b"\x00" + maskedSeed + maskedDataBlock
        messageInt = int.from_bytes(encoded, "big")
        cipherInt = pow(messageInt, publicKey.e, publicKey.n)
        return cipherInt.to_bytes(keyLength, "big")

    @classmethod
    def _rsaOaepDecrypt(cls, ciphertext: bytes, privateKey: _RSAPrivateKey,
                        label: bytes = b"", hashCtor: Callable[[], "hashlib._Hash"] = _OAEP_HASH) -> bytes:
        keyLength = privateKey.size_bytes
        hashLength = hashCtor().digest_size
        if len(ciphertext) != keyLength or keyLength < 2 * hashLength + 2:
            raise ValueError("Ciphertext has invalid length")
        cipherInt = int.from_bytes(ciphertext, "big")
        messageInt = pow(cipherInt, privateKey.d, privateKey.n)
        encoded = messageInt.to_bytes(keyLength, "big")
        if encoded[0] != 0x00:
            raise ValueError("Decryption failed")
        maskedSeed = encoded[1:1 + hashLength]
        maskedDataBlock = encoded[1 + hashLength:]
        seedMask = cls._maskGeneration(maskedDataBlock, hashLength, hashCtor)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
        dataBlockMask = cls._maskGeneration(seed, keyLength - hashLength - 1, hashCtor)
        dataBlock = bytes(a ^ b for a, b in zip(maskedDataBlock, dataBlockMask))
        labelHash = hashCtor(label).digest()
        if dataBlock[:hashLength] != labelHash:
            raise ValueError("Label hash mismatch")
        separatorIndex = dataBlock.find(b"\x01", hashLength)
        if separatorIndex == -1:
            raise ValueError("Invalid OAEP padding")
        return dataBlock[separatorIndex + 1:]

    def _ensurePublicKey(self, key) -> _RSAPublicKey:
        if isinstance(key, _RSAPublicKey):
            return key
        if isinstance(key, _RSAPrivateKey):
            return key.toPublic()
        if isinstance(key, (str, bytes)):
            return self.loadRSAPublicKeyFromPEM(key)
        raise TypeError("Unsupported RSA public key type")

    def _ensurePrivateKey(self, key) -> _RSAPrivateKey:
        if isinstance(key, _RSAPrivateKey):
            return key
        if isinstance(key, (str, bytes)):
            pem = key.decode("utf-8") if isinstance(key, bytes) else key
            return self._parsePrivateKeyPem(pem)
        raise TypeError("Unsupported RSA private key type")
