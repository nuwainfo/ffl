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

"""FFL-side direct P2P download glue with TCP/HTTPS and UDP/QUIC paths.

This file is based on the newer P2P.py supplied with the integration request.
It intentionally keeps FFL policy (metadata, output paths, resume, E2EE,
checksum and fallback) in FFL while delegating ICE/QUIC transport mechanics to
ffl-p2p.
"""

import contextlib
import datetime
import logging
import os
import sys
import time
import uuid

from dataclasses import dataclass, replace

from bases.Checksum import DEFAULT_CHECKSUM_ALGORITHM
from bases.E2EE import CryptoHelper
from bases.I18n import _
from bases.Kernel import FFLEvent, Throttler, getLogger
from bases.Progress import Progress
from bases.Settings import SettingsGetter, TRANSFER_CHUNK_SIZE, TransferTransport
from bases.Utils import flushPrint, formatSize, getEnv

logger = getLogger(__name__)

try:
    from ffl_p2p import (
        ICEConfiguration, ICEServer, P2PAnswer, P2PConnectivityTimeout,
        P2PConnector, P2PPublisher, QUICFileClient, QUICFileServer,
    )
except ImportError:
    ICEConfiguration = ICEServer = P2PAnswer = P2PConnectivityTimeout = None
    P2PConnector = P2PPublisher = QUICFileClient = QUICFileServer = None


def isP2PAvailable():
    return P2PConnector is not None and not getEnv('DISABLE_P2P', False)


class P2PConfiguration:
    """Build ffl-p2p's STUN-only configuration from shared ICE settings."""

    @classmethod
    def createICEConfiguration(cls):
        if not isP2PAvailable():
            return None

        cls._enableNativeDebugLogging()
        
        stunURLs = SettingsGetter.getInstance().getSTUNServerURLs()
        return ICEConfiguration(iceServers=[ICEServer(urls=url) for url in stunURLs])

    @staticmethod
    def _enableNativeDebugLogging():
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            os.environ.setdefault('FFL_P2P_NATIVE_LOGGING_LEVEL', 'DEBUG')


class QUICFileSender:
    """Map FFL reader, E2EE, checksum, and progress state onto a QUIC stream."""

    @dataclass
    class _TransferState:
        downloadId: str
        startedAt: float
        progress: Progress | None = None

    def __init__(self, session, server=None, timeout=600):
        self.session = session
        self.server = server
        self.timeout = timeout

    def _fileInfo(self):
        reader = self.session.reader
        return reader.contentName, reader.size, reader

    def _createProgress(self, size, offset):
        settingsGetter = SettingsGetter.getInstance()
        
        progress = Progress(
            size,
            sizeFormatter=formatSize,
            loggerCallback=flushPrint,
            useBar=settingsGetter.isCLIMode(),
            description=_('P2P QUIC'),
        )
    
        if offset > 0:
            progress.update(offset)
            
        return progress

    def _iterWireChunks(self, offset, transferState):
        name, size, reader = self._fileInfo()
        if offset < 0 or (size is not None and offset > size):
            raise ValueError('invalid QUIC resume offset')
            
        if offset > 0 and not getattr(reader, 'supportsRange', False):
            raise RuntimeError('this source cannot resume a QUIC transfer')

        encryptor = None
        if self.session.config.e2eeEnabled:
            chunkSize = self.session.e2eeManager.chunkSize
            readStart, _discardLeading = CryptoHelper.alignChunkStart(offset, chunkSize)
            startChunkIndex = readStart // chunkSize
            encryptor = self.session.e2eeManager.createEncryptor(
                fileName=name,
                fileSize=size,
                startChunkIndex=startChunkIndex,
                saveTags=True,
            )
            plaintextReader = encryptor.buildReader(reader)
        else:
            chunkSize = TRANSFER_CHUNK_SIZE
            readStart = offset
            plaintextReader = reader

        checksumSession = self.session.checksumStore.begin(
            transport='quic', e2ee=bool(encryptor)
        )
        
        shouldCommitChecksum = offset == 0
        completed = False
        plainEnd = readStart
        progressThrottler = Throttler(interval=1.0)

        try:
            for plainData in plaintextReader.iterChunks(chunkSize, start=readStart):
                if not plainData:
                    continue
                    
                plainEnd += len(plainData)
                wireData = encryptor.encryptChunk(plainData) if encryptor else plainData
                checksumSession.update(wireData)

                logicalTransferred = max(offset, plainEnd)
                if size is not None:
                    logicalTransferred = min(logicalTransferred, size)
                    
                self.session.downloadProgressStore.update(
                    transferState.downloadId, logicalTransferred
                )
            
                transferState.progress.update(
                    logicalTransferred, extraText=_('P2P QUIC')
                )

                if progressThrottler.shouldTrigger():
                    now = time.time()
                    duration = now - transferState.startedAt
                    speed = int(max(0, logicalTransferred - offset) / duration) if duration > 0 else 0
                    percentage = (logicalTransferred * 100.0 / size) if size and size > 0 else 0
                    
                    FFLEvent.downloadProgress.trigger(
                        shareId=self.session.uid,
                        downloadId=transferState.downloadId,
                        bytesTransferred=logicalTransferred,
                        totalBytes=size,
                        percentage=percentage,
                        speed=speed,
                        connectionType=TransferTransport.P2P_QUIC.value,
                        elapsedTime=duration,
                        estimatedRemaining=((size - logicalTransferred) / speed)
                        if (speed > 0 and size) else None,
                    )

                yield wireData

            completed = True
            if shouldCommitChecksum:
                checksumSession.commit()
        finally:
            if not completed or not shouldCommitChecksum:
                if not checksumSession.isClosed:
                    checksumSession.abort()

    def __call__(self, udpTransport):
        name, size, _reader = self._fileInfo()
        transferState = self._TransferState(str(uuid.uuid4()), time.time())
        completed = False

        self.session.downloadProgressStore.register(transferState.downloadId, size)
        quicServer = QUICFileServer(udpTransport)

        try:
            def chunks(offset):
                transferState.progress = self._createProgress(size, offset)
                
                FFLEvent.downloadStarted.trigger(
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    shareId=self.session.uid,
                    downloadId=transferState.downloadId,
                    connectionType=TransferTransport.P2P_QUIC.value,
                    clientInfo={'transport': 'ice-udp/quic'},
                    resumeOffset=offset,
                    fileSize=size,
                    fileName=name,
                )
                
                yield from self._iterWireChunks(offset, transferState)

            result = quicServer.serve(chunks, timeout=self.timeout, closeTimeout=15)
            offset = result['offset']
            duration = time.time() - transferState.startedAt
            bytesTransferred = max(0, (size - offset)) if size is not None else 0
            averageSpeed = int(bytesTransferred / duration) if duration > 0 else 0

            if not result['cleanClose']:
                raise ConnectionError('QUIC stream did not close cleanly')

            if transferState.progress is not None:
                transferState.progress.update(
                    size if size is not None else transferState.progress.transferred,
                    forceLog=True,
                    extraText=_('P2P QUIC'),
                    forceFinish=True,
                )
            completed = True

            FFLEvent.downloadCompleted.trigger(
                shareId=self.session.uid,
                downloadId=transferState.downloadId,
                bytesTransferred=bytesTransferred,
                duration=duration,
                averageSpeed=averageSpeed,
                connectionType=TransferTransport.P2P_QUIC.value,
                clientInfo={'transport': 'ice-udp/quic'},
            )

            if self.server is not None:
                self.server.doAfterDownload(self.session.uid)

            flushPrint(_(
                'Finish transfer {sizeDisplay} for [#{downloadId}], '
                'please wait for the recipient to finish downloading before you close the application..\n'
            ).format(
                sizeDisplay=formatSize(
                    transferState.progress.transferred
                    if transferState.progress else bytesTransferred
                ),
                downloadId=transferState.downloadId[:5],
            ))
                
            return result
        except Exception as error:
            FFLEvent.downloadFailed.trigger(
                shareId=self.session.uid,
                downloadId=transferState.downloadId,
                reason='p2p-quic-failed',
                error=str(error),
                connectionType=TransferTransport.P2P_QUIC.value,
            )
        
            raise
        finally:
            if transferState.progress is not None:
                transferState.progress.finishBar(complete=completed)
                
            quicServer.close()
            
            self.session.downloadProgressStore.unregister(transferState.downloadId)


class P2PDownloadMixin:
    """Try direct P2P once; TCP reuses HTTP, UDP carries bulk data over QUIC."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.p2pTimeout = getEnv('P2P_CONNECT_TIMEOUT', 1.5)
        self.p2pQUICReadTimeout = getEnv('P2P_QUIC_READ_TIMEOUT', 600)
        self.p2pTransportPreference = getEnv('P2P_TRANSPORT_PREFERENCE', 'auto')
        
        if self.p2pTransportPreference not in {'auto', 'tcp', 'udp'}:
            raise ValueError("P2P_TRANSPORT_PREFERENCE must be 'auto', 'tcp', or 'udp'")

    def _downloadViaQUIC(
        self,
        connection,
        urlInfo,
        outputPath,
        credentials,
        resume,
        e2eeContext,
        pickupCode,
        proof,
        checksumAlgorithm=DEFAULT_CHECKSUM_ALGORITHM,
    ):
        """Receive one FFL file over the already-selected ICE/UDP transport.

        HTTPS remains the authenticated control plane for metadata, E2EE tag
        retrieval and checksum publication.  Only the bulk byte stream moves to
        QUIC.  For E2EE the QUIC payload deliberately uses the same ciphertext
        semantics as HTTP: the sender saves per-chunk tags and the existing
        HTTPStreamDecryptor fetches/verifies them over the control plane.  This
        also preserves the existing unaligned-resume behavior.
        """
        self._notifyTransport(TransferTransport.P2P_QUIC.value)
        
        authExtra = {}
        if pickupCode:
            authExtra['X-FFL-Pickup'] = pickupCode
        if proof:
            authExtra['X-FFL-Proof'] = proof
            
        headers = self._makeHeaders(credentials, authExtra if authExtra else None)

        # Metadata/auth stay on the original public HTTPS URL.  Do not perform
        # HEAD against the direct UDP path; it is intentionally not HTTP/3.
        fileSize, fileName, _metadataHeaders = self._getRemoteMetadata(
            urlInfo.baseURL, headers, isGenericURL=False
        )
        finalOutputPath = self._resolveOutputPath(outputPath, fileName)
        resumePosition = self._handleResumeLogic(finalOutputPath, fileSize, resume)
        verifyChecksum = self._shouldVerifyChecksum(urlInfo, resumePosition)

        if self._isPositiveSize(fileSize) and resumePosition >= fileSize:
            return self._finishAlreadyComplete(fileSize, resumePosition, finalOutputPath)

        if resumePosition > 0 and self._isPositiveSize(fileSize):
            self.loggerCallback(_("Resuming download from {resumePos} / {totalSize}").format(
                resumePos=formatSize(resumePosition), totalSize=formatSize(fileSize)
            ))

        progress = self._ensureProgress(fileSize, _("P2P QUIC download"), resumePosition)
        checksumState = self._createTransferChecksumState(verifyChecksum, checksumAlgorithm)
        client = QUICFileClient(connection.transport)
        totalDownloaded = resumePosition

        # The HTTP decryptor is intentional: QUIC transports the exact same
        # encrypted chunk payload as HTTP, while tag fetching remains HTTPS.
        streamDecryptor = (
            self.e2eeClient.createHTTPDecryptor(e2eeContext, resumePosition)
            if e2eeContext else None
        )

        mode = 'ab' if resumePosition > 0 else 'wb'
        outputContext = (
            contextlib.nullcontext(sys.stdout.buffer)
            if finalOutputPath == '-'
            else open(finalOutputPath, mode)
        )

        try:
            with outputContext as output:
                for wireData in client.iterDownload(
                    offset=resumePosition,
                    timeout=self.p2pQUICReadTimeout,
                ):
                    if not wireData:
                        continue
                        
                    self._updateTransferChecksumState(checksumState, wireData)
                    
                    data = streamDecryptor.processChunk(wireData) if streamDecryptor else wireData
                    if data:
                        output.write(data)
                        totalDownloaded += len(data)
                        progress.update(totalDownloaded, extraText='P2P QUIC')

                if streamDecryptor:
                    tail = streamDecryptor.flush()
                    if tail:
                        output.write(tail)
                        totalDownloaded += len(tail)
                        progress.update(totalDownloaded, extraText='P2P QUIC')

            # Match the HTTP completion lifecycle: close/flush the output, check
            # final size, and verify the control-plane checksum before telling
            # the sender it may tear down the share session.
            finalSize = totalDownloaded if finalOutputPath == '-' else os.path.getsize(finalOutputPath)
            if self._isPositiveSize(fileSize) and finalSize != fileSize:
                raise RuntimeError(f'QUIC download incomplete: {finalSize} != {fileSize} bytes')

            progress.update(finalSize, forceLog=True, extraText='P2P QUIC')
            self._finishProgress()

            if verifyChecksum:
                self._verifyTransferChecksum(
                    urlInfo.baseURL,
                    self._createAuthHeaders(credentials),
                    checksumState,
                    'quic',
                )

            logger.debug(f'P2P QUIC download completed: {finalOutputPath}')
            return finalOutputPath
        except Exception as error:
            self._finishProgress(complete=False)
            raise
        finally:
            client.close()

    def downloadFile(self, url, outputPath=None, resume=False, downloadAuth=None):
        self._validateOutputPath(outputPath)
        credentials, pickupCode, recipientPrivateKey, encryptionKey = self._getDownloadAuthValues(downloadAuth)

        ctx = self._resolveDownloadContext(url, credentials, recipientPrivateKey, encryptionKey)
        urlInfo = ctx['urlInfo']

        webRTCDebugEnabled = (
            self.debugSimulateIceFailure or self.debugSimulateStall or
            self.debugSimulateDropBeforeFirstPayload or self.debugSimulateConnectionHang
        )

        canUseP2P = (
            isP2PAvailable() and not webRTCDebugEnabled and
            not urlInfo.isGenericURL and urlInfo.supportsWebRTC
        )

        skipWebRTC = False
        if canUseP2P:
            headers = self._createAuthHeaders(credentials)
            if pickupCode:
                headers['X-FFL-Pickup'] = pickupCode
            if ctx['proof']:
                headers['X-FFL-Proof'] = ctx['proof']

            connection = None
            try:
                self.loggerCallback(self._STATUS_CONNECTING)
                self.loggerCallback('Attempting P2P download...')

                # Connection-establishment failures may fall back. Once UDP/QUIC
                # is selected, a transfer failure is terminal: switching transport
                # after bytes may already have been written can corrupt stdout and
                # also hides the original QUIC failure we need to diagnose.
                try:
                    connection = P2PConnector(
                        configuration=P2PConfiguration.createICEConfiguration()
                    ).connect(
                        urlInfo.baseURL,
                        preference=self.p2pTransportPreference,
                        timeout=self.p2pTimeout,
                        headers=headers,
                    )
                except InterruptedError:
                    raise
                except P2PConnectivityTimeout as error:
                    # Every direct UDP ICE candidate pair failed to connect. Skip
                    # another ICE attempt via WebRTC and go straight to HTTP.
                    logger.warning(
                        f'P2P direct UDP connectivity timed out, skipping WebRTC fallback: {error}'
                    )
                    skipWebRTC = True
                except Exception as error:
                    logger.warning(f'P2P direct connection unavailable, falling back: {error}')
                else:
                    if connection and connection.transportName == 'tcp':
                        directURL = connection.transport.baseURL
                        directURLInfo = replace(urlInfo, baseURL=directURL)

                        self.loggerCallback('Using P2P TCP download...')
                        try:
                            return self._downloadViaHTTP(
                                directURL, outputPath, credentials, None, resume,
                                e2eeContext=ctx['e2eeContext'], urlInfo=directURLInfo,
                                pickupCode=pickupCode, proof=ctx['proof'],
                                checksumAlgorithm=ctx['checksumAlgorithm'],
                                progressLabel=_('P2P TCP'),
                                transport=TransferTransport.P2P_TCP.value,
                            )
                        except InterruptedError:
                            raise
                        except Exception as error:
                            # Preserve the existing TCP-direct fallback policy.
                            logger.warning(
                                f'P2P direct TCP download unavailable, falling back: {error}'
                            )

                    if connection and connection.transportName == 'udp':
                        self.loggerCallback('Using P2P UDP/QUIC download...')
                        try:
                            return self._downloadViaQUIC(
                                connection,
                                urlInfo,
                                outputPath,
                                credentials,
                                resume,
                                ctx['e2eeContext'],
                                pickupCode,
                                ctx['proof'],
                                ctx['checksumAlgorithm'],
                            )
                        except InterruptedError:
                            raise
                        except Exception as error:
                            logger.exception(
                                'P2P UDP/QUIC transfer failed after the direct transport '
                                'was established; refusing WebRTC fallback (%s): %s',
                                type(error).__name__,
                                error,
                            )
                            raise
            finally:
                if connection:
                    # Preserve a real transfer exception if connection cleanup also
                    # fails while that exception is already propagating.
                    preservingError = sys.exc_info()[0] is not None
                    try:
                        connection.close()
                    except Exception:
                        if preservingError:
                            logger.exception(
                                'P2P connection cleanup failed while preserving an earlier error'
                            )
                        else:
                            raise

        return self._downloadWithResolvedContext(
            url, outputPath, credentials, resume, pickupCode, ctx, skipWebRTC=skipWebRTC
        )
