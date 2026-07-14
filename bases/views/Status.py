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
import os
import threading
import time
from http import HTTPStatus

import requests

from bases.Kernel import getLogger
from bases.views import BaseController, BaseView, HTTPResult

logger = getLogger(__name__)


class StatusController(BaseController):
    """Status-polling and stall-diagnosis decisions for one ShareSession."""

    def getStatus(self, publicBaseUrl: str) -> HTTPResult:
        """GET /status — error notifications and server-side stall detection.

        Each poll checks all active HTTP downloads for stalls. When one is found,
        /diagnosis is called via the public tunnel URL so the tunnel/relay also
        records the event. The call is fired in a daemon thread so it never delays
        the /status response.
        """
        uid = self.session.uid

        for info in self.session.downloadProgressStore.getStalledDownloads():
            self.session.downloadProgressStore.markStallReported(info['downloadId'])

            downloadId = info['downloadId']
            written = info['written']
            total = info['total']
            stallMs = int((time.time() - info['lastUpdateTime']) * 1000)

            if written == 0:
                phase = 'first-byte'
            elif total and total > 0 and written / total >= 0.95:
                phase = 'tail'
            else:
                phase = 'mid-stream'

            percent = f'{written / total * 100:.2f}' if total and total > 0 else 'unknown'
            diagnosisUrl = f'{publicBaseUrl}/{uid}/diagnosis'
            params = {
                'type': 'http',
                'phase': phase,
                'delivered': str(written),
                'total': str(total) if total is not None else '?',
                'stall_ms': str(stallMs),
                'percent': percent,
                'probe_status': 'server-side',
                'range_ok': '?',
                'has_auth': '?',
                'browser': '?',
                'ff_pass': '?',
                'e2ee': str(self.session.config.e2eeEnabled).lower(),
                'resume': '?',
                'dl': downloadId,
                'source': 'server',
            }

            logger.warning(
                f"[Status] Server-side stall | dl={downloadId[:8]} phase={phase}"
                f" written={written}/{total} stall={stallMs}ms → {diagnosisUrl}"
            )

            def fire(url=diagnosisUrl, p=params):
                try:
                    requests.get(url, params=p, timeout=10)
                except Exception as exc:
                    logger.debug(f"[Status] /diagnosis call failed: {exc}")

            threading.Thread(target=fire, daemon=True).start()

        status = {'error': self.session.lastError if self.session.lastError else None}
        return self._buildJSONResult(status, headers={'Cache-Control': 'no-cache'})

    def recordDiagnosis(self, args, userAgent: str) -> HTTPResult:
        """GET /diagnosis — stall diagnosis reports from the Service Worker or server-side stall detection.

        The SW sends this when it detects no data has flowed for stallMs milliseconds.
        /status also fires this when it detects a server-side stall (source=server).
        Fields logged here help identify recurring stall patterns (browser, position, probe result, etc.).

        When FFL_DIAGNOSIS_LOG is set, each report is appended as a JSON line to that
        file. This is used by tests to verify that /diagnosis was called with the
        correct parameters.
        """

        def first(key, default=''):
            values = args.get(key)
            return values[0] if values else default

        transportType = first('type', 'unknown')
        phase = first('phase', 'unknown')
        delivered = first('delivered', '?')
        total = first('total', '?')
        stallMs = first('stall_ms', '?')
        percent = first('percent', '?')
        probeStatus = first('probe_status', '?')
        rangeOk = first('range_ok', '?')
        hasAuth = first('has_auth', '?')
        browser = first('browser', '?')
        ffPass = first('ff_pass', '?')
        e2ee = first('e2ee', '?')
        resume = first('resume', '?')
        downloadId = first('dl', '?')
        source = first('source', 'sw')

        dlShort = downloadId[:8] if len(downloadId) >= 8 else downloadId

        logger.warning(
            f"[Diagnosis] Stall | type={transportType} phase={phase}"
            f" delivered={delivered}/{total} ({percent}%)"
            f" stall={stallMs}ms probe={probeStatus} range_ok={rangeOk}"
            f" browser={browser} has_auth={hasAuth} ff_pass={ffPass} e2ee={e2ee} resume={resume}"
            f" source={source} dl={dlShort} ua={userAgent}"
        )

        diagLogPath = os.getenv('FFL_DIAGNOSIS_LOG', '')
        if diagLogPath:
            record = {
                'type': transportType,
                'phase': phase,
                'delivered': delivered,
                'total': total,
                'stall_ms': stallMs,
                'percent': percent,
                'probe_status': probeStatus,
                'range_ok': rangeOk,
                'has_auth': hasAuth,
                'browser': browser,
                'ff_pass': ffPass,
                'e2ee': e2ee,
                'resume': resume,
                'dl': downloadId,
                'source': source,
            }
            try:
                with open(diagLogPath, 'a', encoding='utf-8') as diagLog:
                    diagLog.write(json.dumps(record) + '\n')
                    diagLog.flush()
            except Exception as exc:
                logger.debug(f"[Diagnosis] Failed to write to FFL_DIAGNOSIS_LOG: {exc}")

        return HTTPResult(status=HTTPStatus.OK, body=b'ok')


class StatusView(BaseView):
    """Mounts GET /status, GET /diagnosis."""

    controller = StatusController

    def mount(self, mapHEADRoute, mapGETRoute, mapPOSTRoute):
        self._registerRoute(mapGETRoute, '/status', self.handleStatus)
        self._registerRoute(mapGETRoute, '/diagnosis', self.handleDiagnosis)

    def handleStatus(self, args, *, controller):
        # Resolve public base URL once from this request's headers.
        # Tunnel URLs always use HTTPS and contain dots; localhost/bare-IP is HTTP.
        # parse_request() re-parses self.headers from the socket for every HTTP
        # request (even when this handler instance is reused across an HTTP/1.1
        # keep-alive connection), so headers already carry the current client's
        # Host / X-Forwarded-Proto — no extra context needed.
        host = self.headers.get('Host', '')
        scheme = self.headers.get('X-Forwarded-Proto', '')
        if not scheme:
            scheme = 'https' if (host and '.' in host and 'localhost' not in host) else 'http'

        publicBaseUrl = f'{scheme}://{host}' if host else f'http://localhost:{self.server.server_address[1]}'

        result = controller.getStatus(publicBaseUrl)
        self.sendHTTPResult(result)

    def handleDiagnosis(self, args, *, controller):
        userAgent = self.headers.get('User-Agent', 'unknown')
        result = controller.recordDiagnosis(args, userAgent)
        self.sendHTTPResult(result)
