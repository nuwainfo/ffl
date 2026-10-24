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

import hashlib
import os
import socket
import ssl
import tempfile

from bases.crypto import CryptoInterface
from bases.Kernel import getLogger
from bases.Utils import getEnv

logger = getLogger(__name__)


class DirectTLSIdentity:
    """A share server's self-signed TLS identity for downloaders that connect
    to its port directly (P2P TCP) instead of through the tunnel.

    The same port keeps serving plain HTTP to the tunnel, which connects
    locally; a connection is TLS when its first byte opens a TLS handshake
    record. No CA can vouch for an ad-hoc LAN or port-mapped address, so
    downloaders pin sha256Fingerprint, obtained over the share link's own
    control plane, instead of verifying a certificate chain or hostname.
    """

    COMMON_NAME = 'FastFileLink direct'
    TLS_HANDSHAKE_RECORD = b'\x16'
    PROBE_TIMEOUT_SECONDS = getEnv('DIRECT_TLS_PROBE_TIMEOUT_SECONDS', 10)

    def __init__(self, certificatePEM, privateKeyPEM):
        self.sha256Fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificatePEM)).hexdigest()
        self._context = self._createServerContext(certificatePEM, privateKeyPEM)

    @staticmethod
    def _createServerContext(certificatePEM, privateKeyPEM):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # ssl only loads a certificate chain from files; the private directory
        # and its key file are removed as soon as the context holds them.
        with tempfile.TemporaryDirectory() as directory:
            certificatePath = os.path.join(directory, 'certificate.pem')
            privateKeyPath = os.path.join(directory, 'privateKey.pem')
            for path, pem in ((certificatePath, certificatePEM), (privateKeyPath, privateKeyPEM)):
                with open(path, 'w', encoding='ascii') as pemFile:
                    pemFile.write(pem)

            context.load_cert_chain(certificatePath, privateKeyPath)

        return context

    @classmethod
    def create(cls):
        """Issue a fresh identity, or return None when the crypto backend
        cannot issue certificates (direct TCP then stays plain HTTP)."""
        crypto = CryptoInterface()
        if not crypto.canIssueCertificates:
            logger.info(f'Direct TLS unavailable: crypto backend {crypto.getBackendName()} cannot issue certificates')
            return None

        return cls(*crypto.generateSelfSignedCertificate(cls.COMMON_NAME))

    @classmethod
    def isHandshake(cls, connection):
        return connection.recv(1, socket.MSG_PEEK) == cls.TLS_HANDSHAKE_RECORD

    def wrap(self, connection):
        return self._context.wrap_socket(connection, server_side=True)

    def accept(self, connection):
        """Return the connection to serve: TLS-wrapped when it opens with a
        handshake, otherwise as is.

        Only the first-byte peek and the TLS handshake run under
        PROBE_TIMEOUT_SECONDS, so a client that stalls before either cannot
        hold a worker thread; the served connection keeps its own timeout.
        Raises TimeoutError when the probe deadline passes.
        """
        servingTimeout = connection.gettimeout()
        connection.settimeout(self.PROBE_TIMEOUT_SECONDS)
        if not self.isHandshake(connection):
            connection.settimeout(servingTimeout)
            return connection

        tlsConnection = self.wrap(connection)
        tlsConnection.settimeout(servingTimeout)
        return tlsConnection
