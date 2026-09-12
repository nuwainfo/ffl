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

import json
import re
import sys
import threading
import tempfile
import time
import unittest
import zipfile
import os

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

from bases.Collection import Collection, CollectionHandler, FolderWatchPublisher
from bases.Daemon import DaemonClient, InProcessDaemonManager
from bases.Download import CollectionDownloadFollower
from bases.Share import ShareReporter, ShareRequest
from bases.Server import MultiShareServer

from ..CoreTestBase import FastFileLinkTestBase, LOCAL_TEST_SERVER_URL
from .DaemonTest import DaemonLifecycleMixin


class CollectionTest(unittest.TestCase):
    def setUp(self):
        self.collection = Collection('META123')
        self.server = MultiShareServer(('127.0.0.1', 0), CollectionHandler)
        self.server.collection = self.collection
        self.server.collectionUID = self.collection.uid
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}/META123'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def testManifestIsAppendOnlyAndAvailableAtDownloadEndpoint(self):
        first = self.collection.append('AAA', 'Rough-v1', 'https://example.test/AAA')
        second = self.collection.append('BBB', 'Final', 'https://example.test/BBB')

        response = requests.get(f'{self.url}/download', timeout=5)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-FFL-Resource-Type'], 'collection')
        self.assertEqual(response.headers['X-FFL-Collection-Revision'], '2')
        manifest = response.json()
        self.assertEqual(manifest['type'], 'ffl.collection')
        self.assertEqual(manifest['revision'], 2)
        self.assertEqual(manifest['items'], [first, second])

    def testHeadAdvertisesCollectionWithoutBody(self):
        response = requests.head(self.url, timeout=5)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-FFL-Resource-Type'], 'collection')
        self.assertEqual(response.content, b'')

    def testManifestHonorsBasicAuthentication(self):
        self.collection.auth.user = 'manifest-user'
        self.collection.auth.password = 'manifest-secret'

        denied = requests.get(self.url, timeout=5)
        allowed = requests.get(self.url, timeout=5, auth=('manifest-user', 'manifest-secret'))

        self.assertEqual(denied.status_code, 401)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers['X-FFL-Resource-Type'], 'collection')

    def testCollectionDownloadCheckpointRecordsOnlyCompletedItems(self):
        manifestResponse = MagicMock()
        manifestResponse.headers = {'X-FFL-Resource-Type': 'collection'}
        manifestResponse.json.return_value = {
            'revision': 1,
            'items': [{'seq': 1, 'uid': 'AAA', 'name': 'Delivery-A', 'link': 'https://example.test/AAA'}],
        }
        args = SimpleNamespace(
            url='https://example.test/META123', output=None, resume=False,
            authUser='ffl', authPassword=None, pickupCode=None, recipientPrivateKey=None, follow=False,
        )
        with tempfile.TemporaryDirectory() as directory, patch('bases.Download.os.getcwd', return_value=directory), \
                patch('bases.Download.requests.get', return_value=manifestResponse), \
                patch('bases.Download.FFLDownloader') as downloaderClass:
            downloader = downloaderClass.return_value
            CollectionDownloadFollower(args, lambda _text: None).run()

            downloader.downloadFile.assert_called_once()
            with open(f'{directory}/.ffl-state', 'r', encoding='utf-8') as fileHandle:
                self.assertEqual(json.load(fileHandle), {'https://example.test/META123': 1})

    def testWatchIgnoresExistingFoldersAndPublishesNewStableFolderOnce(self):
        with tempfile.TemporaryDirectory() as root:
            existingPath = os.path.join(root, 'already-there')
            os.makedirs(existingPath)
            output = []
            request = SimpleNamespace(file=root, watchSettle=2)
            publisher = FolderWatchPublisher(
                request, ShareReporter(outputCallback=output.append), None, Collection('META123')
            )
            publisher.initialize()
            newPath = os.path.join(root, 'new-delivery')
            os.makedirs(newPath)
            with open(os.path.join(newPath, 'final.txt'), 'w', encoding='utf-8') as fileHandle:
                fileHandle.write('ready')
                
            publishedPaths = []
            publisher._publish = publishedPaths.append

            publisher.scanOnce(now=10)
            publisher.scanOnce(now=11)
            publisher.scanOnce(now=12)
            publisher.scanOnce(now=20)

            self.assertEqual(publishedPaths, [newPath])
            self.assertTrue(any('ignoring 1 existing' in line for line in output))

    def testWatchDeliveryRetainsShareSecurityOptions(self):
        with tempfile.TemporaryDirectory() as root:
            deliveryPath = os.path.join(root, 'new-delivery')
            os.makedirs(deliveryPath)
            request = ShareRequest(
                file=root,
                watch=True,
                e2ee=True,
                authUser='delivery-user',
                authPassword='delivery-secret',
                recipientAuth='pickup',
                pickupCode='123456',
            )
            publisher = FolderWatchPublisher(
                request, ShareReporter(outputCallback=lambda _text: None), None, Collection('META123')
            )

            with patch('bases.Collection.processSharing') as processSharing:
                publisher._publish(deliveryPath)
                deadline = time.monotonic() + 2
                while not processSharing.called and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(processSharing.called, 'delivery share was not started')

            deliveryRequest = processSharing.call_args.args[0]
            self.assertFalse(deliveryRequest.watch)
            self.assertTrue(deliveryRequest.e2ee)
            self.assertEqual(deliveryRequest.authUser, 'delivery-user')
            self.assertEqual(deliveryRequest.authPassword, 'delivery-secret')
            self.assertEqual(deliveryRequest.recipientAuth, 'pickup')
            self.assertEqual(deliveryRequest.pickupCode, '123456')

    def testFollowDownloadsOnlyNewSequenceAfterInitialManifest(self):
        args = SimpleNamespace(
            url='https://example.test/META123', output=None, resume=False,
            authUser='ffl', authPassword=None, pickupCode=None, recipientPrivateKey=None, follow=True,
        )
        first = {'seq': 1, 'uid': 'AAA', 'name': 'First', 'link': 'https://example.test/AAA'}
        second = {'seq': 2, 'uid': 'BBB', 'name': 'Second', 'link': 'https://example.test/BBB'}
        with tempfile.TemporaryDirectory() as directory, patch('bases.Download.os.getcwd', return_value=directory), \
                patch('bases.Download.time.sleep', side_effect=[None, KeyboardInterrupt]):
            follower = CollectionDownloadFollower(args, lambda _text: None)
            follower._fetchManifest = MagicMock(side_effect=[{'items': [first]}, {'items': [first, second]}])
            follower._downloadItem = MagicMock(side_effect=[f'{directory}/first', f'{directory}/second'])

            with self.assertRaises(KeyboardInterrupt):
                follower.run()

            self.assertEqual(follower._downloadItem.call_args_list[0].args, (first,))
            self.assertEqual(follower._downloadItem.call_args_list[1].args, (second,))
            self.assertEqual(follower.state['https://example.test/META123'], 2)


class CollectionDaemonTest(DaemonLifecycleMixin, FastFileLinkTestBase):
    """Daemon-hosted watch/collection publish-and-download, end to end."""

    def testDaemonWatchPublishesCollectionAndDownloadsDelivery(self):
        """A daemon-owned watch returns a stable collection URL, publishes a
        new folder through the daemon runtime, and the collection downloader can
        retrieve its immutable ZIP delivery end to end with its Basic Auth
        policy applied to both the manifest and its deliveries."""
        watchRoot = os.path.join(self.tempDir, 'daemon-watch-root')
        os.makedirs(os.path.join(watchRoot, 'already-there'))

        authUser = 'collection-user'
        authPassword = 'collection-secret'

        output, returnCode = self._runPatchedCoreCommand([
            '--cli', 'share', watchRoot, '--watch', '--watch-settle', '1', '--background',
            '--auth-user', authUser, '--auth-password', authPassword,
        ], timeout=30)

        self.assertEqual(returnCode, 0, f'daemon watch creation failed: {output}')

        collectionMatch = re.search(r'https?://\S+', output)
        self.assertIsNotNone(collectionMatch, f'No collection URL in daemon output: {output}')

        collectionLink = collectionMatch.group(0)
        shareIdMatch = re.search(r'Share ID: ([^\s]+)', output)
        self.assertIsNotNone(shareIdMatch, f'No daemon share ID in output: {output}')
        watchShareId = shareIdMatch.group(1)

        share = DaemonClient().getShare(watchShareId)
        self.assertTrue(share['shareRequest']['watch'])
        self.assertEqual(share['link'], collectionLink)
        self.assertEqual(requests.get(collectionLink, timeout=5).status_code, 401)

        deliveryPath = os.path.join(watchRoot, 'delivery-001')
        os.makedirs(deliveryPath)
        with open(os.path.join(deliveryPath, 'done.txt'), 'w', encoding='utf-8') as deliveryFile:
            deliveryFile.write('published by the daemon watch')

        deadline = time.time() + 30
        manifest = None
        while time.time() < deadline:
            response = requests.get(collectionLink, timeout=5, auth=(authUser, authPassword))
            if response.ok:
                manifest = response.json()
                if manifest['items']:
                    break

            time.sleep(0.5)

        self.assertIsNotNone(manifest, 'Collection manifest was never available')
        self.assertEqual(len(manifest['items']), 1, manifest)
        self.assertEqual(manifest['items'][0]['name'], 'delivery-001')

        outputDirectory = os.path.join(self.tempDir, 'daemon-watch-download')
        os.makedirs(outputDirectory)
        downloadOutput, downloadReturnCode = self._runPatchedCoreCommand([
            '--cli', 'download', collectionLink, '--output', outputDirectory,
            '--auth-user', authUser, '--auth-password', authPassword,
        ], timeout=120)
        self.assertEqual(downloadReturnCode, 0, f'collection download failed: {downloadOutput}')

        zipPath = os.path.join(outputDirectory, 'delivery-001.zip')
        self.assertTrue(os.path.isfile(zipPath), f'Delivery ZIP was not downloaded: {downloadOutput}')
        with zipfile.ZipFile(zipPath) as deliveryZip:
            doneEntry = next(name for name in deliveryZip.namelist() if name.endswith('/done.txt'))
            self.assertEqual(deliveryZip.read(doneEntry).decode('utf-8'), 'published by the daemon watch')

        self.assertTrue(DaemonClient().stopShare(watchShareId))


class InProcessCollectionDaemonTest(CollectionDaemonTest):
    """Run the same daemon watch/collection test against an in-process-hosted daemon."""

    daemonManagerClass = InProcessDaemonManager


class CollectionDownloadTest(FastFileLinkTestBase):
    """Non-daemon watch/collection download integration tests (real CLI processes,
    local test server)."""

    def __init__(self, methodName='runTest'):
        # Use a smaller file size for faster setup; these tests share folders, not
        # the base class's single generated file.
        super().__init__(methodName, fileSizeBytes=512 * 1024)

    def testWatchPublishesNewFolderAndFollowDownloadsZip(self):
        """A watch collection ignores pre-existing folders and delivers a new folder to --follow."""
        self._provisionLocalTestServerCredential()

        testServer = self._startTestServer()
        self._registerManagedTestServer(testServer)

        watchRoot = os.path.join(self.tempDir, 'watch_root')
        existingFolder = os.path.join(watchRoot, 'already_there')
        os.makedirs(existingFolder)
        with open(os.path.join(existingFolder, 'old.txt'), 'w', encoding='utf-8') as fileHandle:
            fileHandle.write('must not be published')

        watchLogPath = os.path.join(self.tempDir, 'watch.log')
        followLogPath = os.path.join(self.tempDir, 'follow.log')
        receiveDirectory = os.path.join(self.tempDir, 'received')
        os.makedirs(receiveDirectory)
        coreScript = os.path.join(os.path.dirname(__file__), '..', 'CorePatched.py')
        watchProcess = None
        followProcess = None

        try:
            with open(watchLogPath, 'w', encoding='utf-8', buffering=1) as watchLog:
                watchProcess = self._runCoreCommand(
                    ['share', watchRoot, '--watch', '--watch-settle', '1', '--disable-clipboard'],
                    commandPrefix=[sys.executable, coreScript, '--cli'],
                    extraEnvVars={'FILESHARE_TEST': LOCAL_TEST_SERVER_URL, 'PYTHONUNBUFFERED': '1'},
                    outputTarget=watchLog,
                    wait=False,
                )
                collectionURL = self._waitForText(
                    watchLogPath, r'Collection URL: (\S+)', timeout=60, process=watchProcess
                ).group(1)

                manifest = requests.get(collectionURL, timeout=10).json()
                self.assertEqual(manifest['items'], [])
                with open(watchLogPath, 'r', encoding='utf-8') as fileHandle:
                    self.assertIn('ignoring 1 existing delivery folder', fileHandle.read())

                with open(followLogPath, 'w', encoding='utf-8', buffering=1) as followLog:
                    followProcess = self._runCoreCommand(
                        ['--cli', 'download', collectionURL, '--follow', '--output', receiveDirectory],
                        extraEnvVars={'FILESHARE_TEST': LOCAL_TEST_SERVER_URL, 'PYTHONUNBUFFERED': '1'},
                        outputTarget=followLog,
                        wait=False,
                    )
                    newFolder = os.path.join(watchRoot, 'new_delivery')
                    os.makedirs(newFolder)

                    with open(os.path.join(newFolder, 'final.txt'), 'w', encoding='utf-8') as fileHandle:
                        fileHandle.write('new immutable delivery')

                    self._waitForText(followLogPath, r'Downloaded: .*new_delivery\.zip', timeout=90)

            downloadedZip = os.path.join(receiveDirectory, 'new_delivery.zip')
            self._verifyZipFile(downloadedZip, newFolder)
            statePath = os.path.join(receiveDirectory, '.ffl-state')
            self.assertTrue(os.path.exists(statePath))
        finally:
            if followProcess:
                self._stopTestProcess(followProcess)

            if watchProcess:
                self._stopTestProcess(watchProcess)

            self._unregisterManagedTestServer(testServer)
            self._stopTestServer(testServer)

    def testCollectionDownloadsCurrentFolderDelivery(self):
        """Without --follow, the CLI downloads the current immutable folder delivery and exits."""
        folderPath = self._createTestFolder()
        originalFilePath = self.testFilePath
        originalFileSize = self.originalFileSize
        self.testFilePath = folderPath
        self.originalFileSize = -1

        try:
            shareLink = self._startFastFileLink(p2p=True, timeout=60, useTestServer=True)
        finally:
            self.testFilePath = originalFilePath
            self.originalFileSize = originalFileSize

        collection = Collection('collection-download-test')
        collection.append('delivery-one', 'Delivery One', shareLink)

        server = MultiShareServer(('127.0.0.1', 0), CollectionHandler)
        server.collection = collection
        server.collectionUID = collection.uid

        serverThread = threading.Thread(target=server.serve_forever, daemon=True)
        serverThread.start()

        collectionURL = f'http://127.0.0.1:{server.server_address[1]}/{collection.uid}'
        outputCapture = {}
        outputDirectory = os.path.join(self.tempDir, 'collection_downloads')
        os.makedirs(outputDirectory)

        try:
            downloadedPath = self._downloadWithCore(
                collectionURL, outputPath=outputDirectory, captureOutputIn=outputCapture, timeout=20
            )
            self.assertTrue(os.path.exists(downloadedPath))
            self._verifyZipFile(downloadedPath, folderPath)

            with open(os.path.join(outputDirectory, '.ffl-state'), 'r', encoding='utf-8') as fileHandle:
                self.assertEqual(json.load(fileHandle)[collectionURL], 1)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
