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

import concurrent.futures
import os
import shutil
import tempfile
import threading
import unittest

from bases.Tunnel import fetchTunnelToken # isort:skip
from tests.CoreTestBase import FastFileLinkTestBase


class TunnelsIntegrationTest(unittest.TestCase):

    def testAllTunnelServers(self):
        servers = FastFileLinkTestBase.getBuiltinTunnels()

        print(f"\n[Test] Total servers to test: {len(servers)}\n")

        results = []
        lock = threading.Lock()

        def runOne(i, tunnel):
            host = tunnel["domain"]
            tempDir = tempfile.mkdtemp()
            port = 9000 + i

            try:
                # Fetch token dynamically for each test
                print(f"[Test] Fetching token for {host}...")
                try:
                    secret = fetchTunnelToken(domain=host)
                except Exception as e:
                    isJenkins = 'JENKINS_HOME' in os.environ
                    isRateLimited = '429' in str(e)
                    if isJenkins and isRateLimited:
                        print(
                            f"[⚠️  WARN] {host} - Token fetch returned 429 on Jenkins "
                            f"(Jenkins itself may be on this server). "
                            f"Falling back to fastfilelink.com token."
                        )
                        try:
                            secret = fetchTunnelToken(domain='fastfilelink.com')
                        except Exception as fallbackE:
                            with lock:
                                print(f"[❌ FAIL] {host} - Fallback token fetch also failed: {fallbackE}")
                                results.append((host, False))
                            return
                    else:
                        with lock:
                            print(f"[❌ FAIL] {host} - Token fetch failed: {e}")
                            results.append((host, False))
                        return
                    
                from tests.bases.BoreTest import BoreHttpsTest # isort:skip                 
                
                testCase = BoreHttpsTest(
                    methodName='testUseHttpsTunnel', remoteHost=host, secret=secret, tempDir=tempDir, port=port
                )
                result = unittest.TestResult()
                testCase.run(result)

                with lock:
                    if result.failures or result.errors:
                        print(f"[❌ FAIL] {host}")

                        for test_case, traceback_str in result.failures + result.errors:
                            print(f"\n[TestCase] {test_case.id()}")
                            print("[Traceback]")
                            print(traceback_str)

                        results.append((host, False))
                    else:
                        print(f"[✅ OK] {host}")
                        results.append((host, True))

            finally:
                shutil.rmtree(tempDir, ignore_errors=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(runOne, i, tunnel) for i, tunnel in enumerate(servers)]
            concurrent.futures.wait(futures)

        failed = [host for host, ok in results if not ok]
        if failed:
            self.fail(f"{len(failed)} tunnel server(s) failed: {failed}")

        self.assertTrue(len(failed) == 0)


if __name__ == '__main__':
    unittest.main()
