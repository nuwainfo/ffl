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

import datetime
import json
import queue
import threading

from collections import deque
from http import HTTPStatus

from bases.Kernel import getLogger

logger = getLogger(__name__)


class EventHub:
    """Thread-safe pub/sub hub backing a replayable Server-Sent Events stream."""

    REPLAY_LOG_SIZE = 500

    def __init__(self):
        self._lock = threading.Lock()
        self._seq = 0
        self._subscribers = set()
        self._log = deque(maxlen=self.REPLAY_LOG_SIZE)

    def _appendToLog(self, topic, payload):
        with self._lock:
            self._seq += 1
            event = {
                'seq': self._seq,
                'topic': topic,
                'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'payload': payload,
            }
            self._log.append(event)
            return event

    def record(self, topic, payload):
        """Append an event to the replay log without broadcasting it."""
        return self._appendToLog(topic, payload)

    def publish(self, topic, payload):
        """Broadcast an event to all current subscribers and record it for replay."""
        event = self._appendToLog(topic, payload)

        with self._lock:
            subscribers = list(self._subscribers)

        for subscriberQueue in subscribers:
            subscriberQueue.put(event)

        return event

    def subscribe(self):
        """Register a new connection. Returns the Queue it should read events from."""
        subscriberQueue = queue.Queue()
        with self._lock:
            self._subscribers.add(subscriberQueue)

        return subscriberQueue

    def unsubscribe(self, subscriberQueue):
        with self._lock:
            self._subscribers.discard(subscriberQueue)

    def replayAfter(self, lastSeq):
        """Return buffered events with seq > lastSeq, for a Last-Event-ID reconnect."""
        with self._lock:
            return [event for event in self._log if event['seq'] > lastSeq]


class SSEMixin:

    @property
    def sseEventHub(self):
        raise NotImplementedError

    @property
    def initialSSEEvents(self):
        return []

    @property
    def sseEventName(self):
        return 'ffl'

    @property
    def sseHeartbeatTimeoutSeconds(self):
        return 15

    @property
    def sseLogger(self):
        return logger

    @property
    def sseDisconnectLogMessage(self):
        return 'Client disconnected from SSE event channel'

    @property
    def sseErrorLogPrefix(self):
        return 'Event channel error'

    def buildSSEEventName(self, event):
        return self.sseEventName

    def buildSSEData(self, event):
        body = json.dumps(event, ensure_ascii=False)
        return body

    def buildSSEFrame(self, event):
        eventName = self.buildSSEEventName(event)
        data = str(self.buildSSEData(event))
        dataLines = ''.join(f'data: {line}\n' for line in data.splitlines() or [''])
        
        return f"id: {event['seq']}\nevent: {eventName}\n{dataLines}\n".encode('utf-8')

    def _writeSSEEvent(self, event):
        self.wfile.write(self.buildSSEFrame(event))
        self.wfile.flush()

    def _handleEvents(self, routeContext=None):
        eventHub = self.sseEventHub

        try:
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache, no-transform')
            self.send_header('X-Accel-Buffering', 'no')
            self.end_headers()

            subscriberQueue = eventHub.subscribe()
            try:
                lastEventId = self.headers.get('Last-Event-ID')
                if lastEventId is not None:
                    try:
                        backlog = eventHub.replayAfter(int(lastEventId))
                    except ValueError:
                        backlog = []

                    for event in backlog:
                        self._writeSSEEvent(event)
                else:
                    for event in self.initialSSEEvents:
                        self._writeSSEEvent(event)

                while True:
                    try:
                        event = subscriberQueue.get(timeout=self.sseHeartbeatTimeoutSeconds)
                        self._writeSSEEvent(event)
                    except queue.Empty:
                        self.wfile.write(b': heartbeat\n\n')
                        self.wfile.flush()
            finally:
                eventHub.unsubscribe(subscriberQueue)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.sseLogger.debug(self.sseDisconnectLogMessage)
        except Exception as e:
            self.sseLogger.exception(f'{self.sseErrorLogPrefix}: {e}')
